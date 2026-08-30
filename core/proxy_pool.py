# core/proxy_pool.py
"""Пул прокси: кого выбрать под следующий запрос и когда перестать его брать.

Вынесено из NetworkValidator, потому что это самостоятельная задача со своим
состоянием и своими правилами, и правил этих набралось на несколько сотен
строк. Валидации от пула нужен один ответ — «дай прокси под такой-то домен», —
а всё остальное про здоровье, нагрузку, страну и бан к проверке ящиков
отношения не имеет.

Три вещи, которые здесь устроены неочевидно и объяснены на местах:

* Лимит одновременных соединений считается на пару «почтовый сервер + наш
  выходной IP», а не на сервер: нагрузку считает почтовик, и считает он её
  по адресу отправителя.
* Перегруженный выходной IP ИСКЛЮЧАЕТСЯ из выбора, а не просто опускается в
  ранге: репутация адреса тратится безвозвратно.
* Прокси банится за сбои на РАЗНЫХ серверах. Три таймаута на одном туго
  отвечающем MX означают, что мёртв сервер, а не прокси.

Примесь, а не отдельный объект: методы читают то же состояние, что заводит
NetworkValidator.__init__, и разрывать это состояние надвое значило бы
плодить проксирующие вызовы без единой выгоды.
"""
import random
import threading
import time

from core.proxy_probe import profile_proxies
from core.proxy_transport import build_proxy_dict
from core.mail_constants import PROXY_MAX_CONSECUTIVE_FAILS

UNKNOWN_LATENCY_MS = 10 ** 9

# За сколько секунд жалоба сервера теряет половину веса.
#
# 421 значит «сейчас слишком часто», а не «слишком часто навсегда». Две
# минуты выбраны по тому, как ведут себя крупные почтовики: окно их счётчика
# сравнимо с этим, и через пару минут спокойной работы прежние жалобы уже
# ничего не говорят о текущем состоянии.
MX_ERROR_HALF_LIFE_SEC = 120.0

# Ниже этого значения затухший счётчик считается нулём.
MX_ERROR_FLOOR = 0.5


class ProxyPoolMixin:
    """Выбор прокси, учёт нагрузки, здоровье и бан. Состояние — в NetworkValidator."""

    def proxy_slot(self, proxy):
        """Семафор конкретного прокси. Держит число соединений в пределах лимита."""
        if not proxy:
            return None
        with self._proxy_sem_lock:
            slot = self._proxy_semaphores.get(proxy)
            if slot is None:
                slot = threading.Semaphore(self._max_concurrent_per_proxy)
                self._proxy_semaphores[proxy] = slot
            return slot

    def set_proxy_concurrency(self, limit):
        """Сколько соединений разрешено держать через один прокси одновременно.

        Уже созданные семафоры не пересоздаём: менять лимит под работающими
        потоками значит выпустить больше, чем разрешено, ровно один раз.
        """
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            return self._max_concurrent_per_proxy
        self._max_concurrent_per_proxy = max(1, min(limit, 64))
        return self._max_concurrent_per_proxy

    def note_ip_use(self, proxy, count=1):
        """Отмечает обращение через выходной IP этого прокси."""
        exit_ip = (self._proxy_profiles.get(proxy) or {}).get("exit_ip")
        key = exit_ip or proxy
        with self._ip_load_lock:
            self._ip_load[key] = self._ip_load.get(key, 0) + int(count)
            return self._ip_load[key]

    def ip_load(self, proxy):
        """Сколько обращений уже ушло через выходной IP этого прокси."""
        exit_ip = (self._proxy_profiles.get(proxy) or {}).get("exit_ip")
        key = exit_ip or proxy
        with self._ip_load_lock:
            return self._ip_load.get(key, 0)

    def overloaded_ips(self):
        """Выходные IP, перешагнувшие мягкий потолок суточной нагрузки."""
        with self._ip_load_lock:
            return {ip: n for ip, n in self._ip_load.items()
                    if n >= self._ip_load_soft_cap}

    def _get_mx_semaphore(self, mx_host: str, proxy=None) -> threading.Semaphore:
        """Семафор на пару «почтовый сервер + наш выходной IP».

        ПОЧЕМУ НЕ ПРОСТО НА MX. Лимит существует, чтобы не бить в один сервер
        слишком часто С ОДНОГО АДРЕСА — считает нагрузку именно почтовик, и
        считает он её по IP отправителя. Общий лимит на MX означал, что вся
        база на одном домене (а база из одних только Gmail — обычное дело)
        обрабатывалась ПЯТЬЮ соединениями, сколько бы прокси и потоков ни
        было. Ползунок «Потоки 300» при этом ничего не менял: 78 адресов по
        30 секунд каждый, по пять за раз — это восемь минут тишины, которые
        и выглядят как зависание.

        Теперь у каждого выходного IP свой счёт к этому серверу. Нагрузка на
        один адрес осталась прежней, а суммарная пропускная способность
        растёт вместе с числом РАЗНЫХ выходных адресов — то есть ровно так,
        как её видит сам почтовик.
        """
        exit_ip = ""
        if proxy:
            exit_ip = (self._proxy_profiles.get(proxy) or {}).get("exit_ip") or str(proxy)
        mx_key = f"{mx_host.lower()}|{exit_ip}"

        # Сервер, который давно не жалуется, получает свой поток обратно.
        # Раньше сужение было односторонним: потолок падал до одного
        # соединения и таким оставался до конца прогона.
        if (mx_key in self._mx_narrowed
                and self._decayed_mx_errors(mx_host) < 3):
            with self._mx_error_lock:
                self._mx_narrowed.pop(mx_key, None)
            with self._mx_sem_lock:
                self._mx_semaphores[mx_key] = threading.Semaphore(
                    self._max_concurrent_per_mx)
                return self._mx_semaphores[mx_key]

        with self._mx_sem_lock:
            if mx_key not in self._mx_semaphores:
                self._mx_semaphores[mx_key] = threading.Semaphore(self._max_concurrent_per_mx)
            return self._mx_semaphores[mx_key]

    def _decayed_mx_errors(self, mx_host):
        """Сколько жалоб этого сервера ещё «в силе» с учётом давности."""
        if not isinstance(mx_host, str) or not mx_host:
            return 0.0
        key = mx_host.lower()
        with self._mx_error_lock:
            count = self._mx_error_counts.get(key, 0)
            last = self._mx_error_seen.get(key)
        if not count:
            return 0.0
        if not last:
            return float(count)
        elapsed = max(0.0, time.time() - last)
        decayed = count * (0.5 ** (elapsed / MX_ERROR_HALF_LIFE_SEC))
        return decayed if decayed >= MX_ERROR_FLOOR else 0.0

    def _record_mx_error(self, mx_host: str, proxy=None):
        """Записывает 421 и при накоплении сужает поток к ЭТОЙ паре сервер+IP.

        Счётчик жалоб ведётся по серверу: 421 означает «слишком часто», и
        это свойство сервера, а не конкретного адреса. А вот сужать надо тот
        самый семафор, который используется при отправке, — то есть ключ
        обязан совпадать с ключом _get_mx_semaphore. Раньше здесь стоял
        ключ только по MX; после перехода на пару «сервер + выходной IP»
        снижение создавало бы новый семафор, которого никто не читает, и
        адаптивное торможение молча перестало бы работать.
        """
        mx_key = mx_host.lower()
        with self._mx_error_lock:
            self._mx_error_counts[mx_key] = self._mx_error_counts.get(mx_key, 0) + 1
            errors = self._mx_error_counts[mx_key]
            self._mx_error_seen[mx_key] = time.time()

        limit = 2 if errors == 3 else (1 if errors == 6 else None)
        if limit is None:
            return

        exit_ip = ""
        if proxy:
            exit_ip = (self._proxy_profiles.get(proxy) or {}).get("exit_ip") or str(proxy)
        pair = f"{mx_key}|{exit_ip}"
        with self._mx_sem_lock:
            self._mx_semaphores[pair] = threading.Semaphore(limit)
        # Помечаем пару как суженную, чтобы потом было что вернуть обратно.
        with self._mx_error_lock:
            self._mx_narrowed[pair] = limit

    def set_ptr_proxies(self, ptr_proxies):
        """Задаёт подмножество прокси, у которых есть обратный DNS (FCrDNS).

        Только через них можно проверять Yahoo/AOL/Verizon — остальные они
        отшивают на MAIL FROM ошибкой 5.7.25, не дойдя до проверки адреса.
        """
        if isinstance(ptr_proxies, (str, bytes)) or not hasattr(ptr_proxies, "__iter__"):
            ptr_proxies = []
        with self._proxy_score_lock:
            self._ptr_proxies = set(ptr_proxies or [])
            self._profiled = bool(ptr_proxies)

    def set_proxy_profiles(self, profiles):
        """Принимает результат profile_proxies(): выходной IP, PTR, чёрные списки.

        Позволяет выбирать прокси под задачу: Yahoo/AOL требуют PTR,
        Outlook/iCloud/GMX — чистую репутацию IP, остальным сойдёт любой живой.

        PTR хранится ТРЕМЯ состояниями. "Не удалось проверить" — это не то же
        самое, что "PTR нет": такие прокси стоит попробовать на Yahoo, если
        подтверждённых не осталось. Отказ от проверки гарантирует ноль
        результатов, а попытка стоит одного пинга.
        """
        profiles = profiles if isinstance(profiles, dict) else {}
        self._proxy_profiles = dict(profiles)
        with self._proxy_score_lock:
            # Факт профилирования храним отдельно от его результатов: если у ВСЕХ
            # прокси PTR точно отсутствует, все три множества окажутся пустыми,
            # и по ним нельзя отличить "профилировали, PTR ни у кого нет" от
            # "не профилировали вовсе". А это разные случаи: в первом Yahoo
            # проверять нечем, во втором ограничений нет.
            self._profiled = bool(profiles)
            self._ptr_proxies = {p for p, v in profiles.items() if v.get("has_ptr") is True}
            self._ptr_unknown = {p for p, v in profiles.items() if v.get("has_ptr") is None}

            # Измеренная задержка идёт в выбор прокси, а не только в лог.
            self._proxy_latency = {
                p: v.get("latency_ms") for p, v in profiles.items()
                if isinstance(v.get("latency_ms"), (int, float))
            }

            # "Грязный" = непригодный для провайдеров, чувствительных к репутации.
            # Три независимых признака, и прямая проба среди них ГЛАВНАЯ: замерено,
            # что Microsoft отвергает IP, которого нет ни в одном чёрном списке —
            # у него своя база репутации, и DNSBL её предсказывает лишь частично.
            self._dirty_proxies = {
                p for p, v in profiles.items()
                if v.get("in_dnsbl")                 # числится в чёрных списках
                or v.get("outlook_ok") is False      # Microsoft отверг напрямую
                or v.get("rdns_dirty")               # имя в PTR выдаёт прокси/VPN
            }

            # Прямые пробы Yahoo и iCloud. Раньше их пригодность выводилась —
            # у Yahoo из PTR, у iCloud из чёрных списков. Теперь она измерена,
            # и измеренное сильнее выведенного: прокси, которого Yahoo отверг
            # на MAIL FROM, в пул Yahoo не попадает, даже если PTR у него есть.
            self._yahoo_ok = {p for p, v in profiles.items() if v.get("yahoo_ok") is True}
            self._yahoo_bad = {p for p, v in profiles.items() if v.get("yahoo_ok") is False}
            self._icloud_bad = {p for p, v in profiles.items() if v.get("icloud_ok") is False}
            self._dirty_proxies |= self._icloud_bad

    def refresh_proxy_profiles(self, timeout=10, workers=30):
        """Переснимает профиль живых прокси и возвращает, что изменилось.

        Зачем: у ротирующегося прокси выходной IP меняется по ходу прогона, а
        профиль снимается один раз на старте. Маршрутизация продолжает считать,
        что у прокси есть PTR, когда его уже нет, и Yahoo уходит в пустоту.

        Тяжёлую пробу Microsoft не повторяем — репутация IP меняется медленно,
        а вот сам IP и его обратный DNS проверить надо. Прежние значения
        outlook_ok переносим из старого профиля.
        """
        with self._proxy_score_lock:
            alive = [p for p in self.proxies if p not in self._proxy_banned]
        if not alive:
            return {"checked": 0, "ip_changed": 0, "ptr_lost": 0, "ptr_gained": 0}

        previous = dict(self._proxy_profiles)
        fresh = profile_proxies(alive, timeout=timeout, workers=workers,
                                probe_outlook=False)
        if not fresh:
            return {"checked": 0, "ip_changed": 0, "ptr_lost": 0, "ptr_gained": 0}

        ip_changed = ptr_lost = ptr_gained = 0
        merged = dict(previous)
        for proxy, info in fresh.items():
            old = previous.get(proxy, {})
            if old.get("exit_ip") and info.get("exit_ip") and old["exit_ip"] != info["exit_ip"]:
                ip_changed += 1
            if old.get("has_ptr") is True and info.get("has_ptr") is False:
                ptr_lost += 1
            if old.get("has_ptr") is not True and info.get("has_ptr") is True:
                ptr_gained += 1
            # Репутацию у Microsoft заново не спрашивали — берём прежнюю
            if info.get("outlook_ok") is None and old.get("outlook_ok") is not None:
                info["outlook_ok"] = old["outlook_ok"]
                info["outlook_reason"] = old.get("outlook_reason")
            merged[proxy] = info

        self.set_proxy_profiles(merged)
        return {"checked": len(fresh), "ip_changed": ip_changed,
                "ptr_lost": ptr_lost, "ptr_gained": ptr_gained}

    def has_ptr_proxies(self):
        """True, если есть чем проверять Yahoo/AOL: подтверждённый PTR либо непроверенный."""
        with self._proxy_score_lock:
            return bool((self._ptr_proxies | self._ptr_unknown) - self._proxy_banned)

    def has_clean_proxies(self):
        with self._proxy_score_lock:
            alive = {p for p in self.proxies if p not in self._proxy_banned}
            return bool(alive - self._dirty_proxies)

    def _dns_proxy(self):
        """Прокси для DNS-запроса. Контракт описан в ProxiedResolver.resolve().

        Когда прокси заданы, но живых не осталось, возвращаем пустую строку, а не
        None: молча уйти на 8.8.8.8 напрямую — значит раскрыть реальный IP там,
        где пользователь этого не ждёт. Ровно та же логика, что у SMTP.
        """
        if not self._proxy_dns or not self.proxies:
            return None
        return self._pick_best_proxy() or ""

    def _proxy_country(self, proxy):
        """Двухбуквенный код страны выходного IP или пусто."""
        return ((self._proxy_profiles.get(proxy) or {}).get("asn_country") or "").upper()

    def _choose_from(self, candidates, want_country=""):
        """Берёт случайный из топа.

        Порядок: сначала health score, потом совпадение страны с доменом
        получателя, потом скорость, потом нагрузка на выходной IP.

        Про страну. Почтовики смотрят, откуда пришло письмо: проверять
        немецкий домен через бразильский адрес — лишний повод для отказа.
        Совпадение стоит ниже health score осознанно: мёртвый прокси из
        нужной страны бесполезнее живого из соседней.

        Про нагрузку. Считается по ВЫХОДНОМУ IP: десять прокси с общим
        выходом жгут репутацию одного адреса, и при прочих равных выбор
        уходит на менее нагруженный.
        """
        if not candidates or not hasattr(candidates, "__iter__"):
            return None
        want = (want_country or "").upper()

        def primary(proxy):
            """Ключи, по которым уступать нельзя: здоровье и страна."""
            return (-self._proxy_scores.get(proxy, 0),
                    0 if (want and self._proxy_country(proxy) == want) else 1)

        def secondary(proxy):
            """Ключи, по которым разброс допустим: скорость и нагрузка."""
            return (self._proxy_latency.get(proxy) or UNKNOWN_LATENCY_MS,
                    self.ip_load(proxy))

        candidates = list(candidates)
        if not candidates:
            return None

        # Перегруженный выходной адрес ИСКЛЮЧАЕТСЯ из выбора, а не просто
        # оказывается ниже в ранге. Раньше нагрузка была лишь одним из ключей
        # сортировки, и когда все прочие ключи равны, тот же самый выжженный
        # адрес продолжал получать запросы. Репутация IP тратится безвозвратно,
        # поэтому здесь именно отсев.
        #
        # Если свободных не осталось совсем, работаем перегруженными: полная
        # остановка проверки хуже, чем продолжение с предупреждением.
        rested = [p for p in candidates if self.ip_load(p) < self._ip_load_soft_cap]
        if rested:
            candidates = rested

        # Случайность нужна, чтобы не бить одним прокси в один сервер, но она
        # не имеет права отменять предпочтение. Раньше здесь брались первые
        # пять по рангу и выбирался случайный из них — и на пуле из двух
        # прокси «первые пять» это ВЕСЬ пул, то есть ранжирование не работало
        # вовсе: прокси нужной страны выигрывал сортировку и тут же проигрывал
        # монетке. Теперь разброс идёт ТОЛЬКО среди равных по здоровью и стране.
        best = min(primary(p) for p in candidates)
        equals = [p for p in candidates if primary(p) == best]

        equals.sort(key=secondary)

        # Отсечение по трети остаётся жёстким: заведомо медленные прокси не
        # должны получать шанс вообще, иначе прогон растягивается на них же.
        top = equals[:max(5, len(equals) // 3)]

        # А вот ВНУТРИ среза раньше стоял равновероятный выбор, и на маленьком
        # пуле это обнуляло ранжирование: «первые пять» из двух прокси — оба,
        # то есть быстрый ненагруженный решался монеткой наравне с медленным
        # перегруженным. Вес по месту в ранге чинит именно это, не трогая
        # отсечение: лучший берётся чаще, но разброс внутри среза сохраняется.
        weights = [1.0 / (rank + 1) for rank in range(len(top))]
        return random.choices(top, weights=weights, k=1)[0]

    def _pick_best_proxy(self, need_ptr=False, need_clean=False, want_country=""):
        """Выбирает живой прокси с наивысшим health score (п.8).

        need_ptr=True  — только прокси с обратным DNS (для Yahoo/AOL/Verizon).
                         Если таких нет, возвращает None: идти без PTR бессмысленно.
        need_ptr=False — предпочитает прокси БЕЗ PTR, чтобы не расходовать
                         дефицитные PTR-прокси там, где они не нужны.
                         Если остались только PTR-прокси, берёт их.

        Возвращает None, если прокси не заданы вообще ИЛИ все забанены.
        Вызывающий код обязан различать эти случаи через has_proxies_configured().
        """
        if not self.proxies:
            return None
        with self._proxy_score_lock:
            # Забаненные прокси не воскрешаем — они выбыли навсегда
            alive = [p for p in self.proxies if p not in self._proxy_banned]
            if not alive:
                return None

            # Профилирование не проводилось — разделения нет, берём из общего пула.
            # ВАЖНО: проверяем именно факт профилирования, а не пустоту _ptr_proxies.
            # Раньше стояло "if not self._ptr_proxies", и когда подтверждённых PTR
            # не находилось, вся логика need_ptr обходилась: для Yahoo выбирался
            # прокси с ТОЧНО отсутствующим PTR — гарантированный холостой ход.
            if not self._profiled:
                return self._choose_from(alive, want_country)

            with_ptr = [p for p in alive if p in self._ptr_proxies]
            without_ptr = [p for p in alive if p not in self._ptr_proxies]

            if need_ptr:
                # Сначала подтверждённые PTR; если таких нет — пробуем те, что
                # проверить не удалось. Прокси с ТОЧНО отсутствующим PTR не берём
                # никогда: Yahoo отошьёт их на MAIL FROM, это гарантированный холостой ход.
                pool = with_ptr or [p for p in alive if p in self._ptr_unknown]
                # Прямая проба перевешивает вывод по PTR в обе стороны:
                # подтверждённо принятые идут первыми, подтверждённо
                # отвергнутые выбывают, даже если PTR у них в порядке.
                if self._yahoo_ok:
                    measured = [p for p in pool if p in self._yahoo_ok]
                    extra = [p for p in alive
                             if p in self._yahoo_ok and p not in pool]
                    pool = measured + extra or pool
                if self._yahoo_bad:
                    pool = [p for p in pool if p not in self._yahoo_bad] or pool
                if need_clean:
                    pool = [p for p in pool if p not in self._dirty_proxies] or pool
                return self._choose_from(pool, want_country) if pool else None

            # Бережём PTR-прокси: для обычных доменов они не нужны
            pool = without_ptr or with_ptr
            if need_clean:
                # Outlook/iCloud/GMX режут по репутации — берём только чистые.
                # Если чистых не осталось, идём грязными: лучше попытка, чем ничего.
                pool = [p for p in pool if p not in self._dirty_proxies] or pool
            return self._choose_from(pool, want_country)

    def has_proxies_configured(self):
        """True, если пользователь загрузил прокси (независимо от того, живы ли они)."""
        return bool(self.proxies)

    def get_live_proxy_count(self):
        with self._proxy_score_lock:
            return len([p for p in self.proxies if p not in self._proxy_banned])

    def all_proxies_dead(self):
        return bool(self.proxies) and self.get_live_proxy_count() == 0

    def _mx_delay(self, mx_host):
        """Пауза перед запросом к MX. Растёт с числом полученных от него 421.

        Раньше пауза была фиксированной (0.1–0.4 с), и весь «back-off» сводился
        к разовому понижению параллельности 5 → 2 → 1. Но сервер, ответивший
        421, просит именно ПОДОЖДАТЬ. Теперь мы отступаем и по времени:
        экспоненциально, с потолком в 8 секунд, чтобы не подвесить прогон.
        """
        base = random.uniform(0.1, 0.4)
        if not isinstance(mx_host, str) or not mx_host:
            return base
        # Счёт берётся С УЧЁТОМ ДАВНОСТИ: сервер, замолчавший десять минут
        # назад, не должен тормозить нас так же, как жалующийся сейчас.
        errors = self._decayed_mx_errors(mx_host)
        if not errors:
            return base
        return min(base * (2 ** min(errors, 5)), 8.0)

    def _update_proxy_score(self, proxy, success: bool, mx_record=None):
        """Обновляет health score прокси и банит его после N сбоев подряд (п.8).

        ВАЖНО про бан. Считать сбои только по прокси нельзя: наблюдалось, как
        рабочий прокси получил три таймаута подряд на ОДНОМ тугом MX и вылетел
        из ротации навсегда — а с ним встала и проверка DNS, которая тоже идёт
        через прокси. Три сбоя на одном сервере означают, что мёртв сервер;
        мёртвым прокси считается тот, кто сыпется на РАЗНЫХ серверах.
        """
        if not proxy:
            return
        with self._proxy_score_lock:
            if proxy not in self._proxy_scores:
                self._proxy_scores[proxy] = 0
                self._proxy_consecutive_fails[proxy] = 0
            if success:
                self._proxy_scores[proxy] += 1
                self._proxy_consecutive_fails[proxy] = 0  # Ожил — счётчик подряд сбрасываем
                self._proxy_fail_hosts.pop(proxy, None)
                return

            self._proxy_scores[proxy] -= 3  # Штраф за неудачу в 3 раза больше
            self._proxy_consecutive_fails[proxy] = self._proxy_consecutive_fails.get(proxy, 0) + 1

            hosts = self._proxy_fail_hosts.setdefault(proxy, set())
            if isinstance(mx_record, str) and mx_record:
                hosts.add(mx_record.lower())

            if self._proxy_consecutive_fails[proxy] < PROXY_MAX_CONSECUTIVE_FAILS:
                return

            # Сбои неизвестно на чём (сам прокси не поднялся) — банить можно.
            # Сбои, все до одного пришедшиеся на один сервер, — вина сервера.
            if not hosts or len(hosts) >= 2:
                self._proxy_banned.add(proxy)

    def _note_latency(self, proxy, millis):
        """Обновляет задержку прокси по живому замеру.

        Сглаживание, а не замена: одиночный всплеск бывает у любого прокси, и
        выкидывать из-за него рабочий адрес не за что. Вес новому замеру дан
        небольшой, поэтому решает устойчивая тенденция, а не отдельный случай.
        """
        if not proxy or not isinstance(millis, (int, float)) or millis < 0:
            return
        with self._proxy_score_lock:
            previous = self._proxy_latency.get(proxy)
            if isinstance(previous, (int, float)):
                self._proxy_latency[proxy] = int(previous * 0.7 + millis * 0.3)
            else:
                self._proxy_latency[proxy] = int(millis)
