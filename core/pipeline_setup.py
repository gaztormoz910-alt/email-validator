# -*- coding: utf-8 -*-
"""Подготовка прогона: сеть, кэш, списки, отбор и профилирование прокси.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. `setup` и профилирование прокси — это всё, что
происходит ДО первого адреса: создаётся валидатор, поднимается кэш,
докачиваются чёрные списки, отбираются живые прокси и снимается их профиль.
Ни одна из этих строк не участвует в разборе конкретного адреса, но лежали
они посреди файла, где разбирается каждый.

ПОЧЕМУ ПРИМЕСЬ. Всё состояние заводится в `ValidationPipeline.__init__` и
остаётся там же. Примесь работает с тем же объектом: файл поделён,
поведение — нет.
"""
import os
import threading
from core.cache import ResultCache
from core.filters import SpamFilter
from core.github_parser import BlacklistDownloader
from core.network import NetworkValidator
from core.ai_engine import EmailAI
from core.provider import extend_free_domains
from core.paths import data_path

__all__ = ["PipelineSetupMixin"]


class PipelineSetupMixin:
    def _домен_принимает_почту(self, domain):
        """True / False / None — принимает ли домен почту.

        Обёртка над get_mx_records, сохраняющая три состояния. Различие между
        «записей нет» и «спросить не удалось» здесь решает, подменим мы адрес
        владельца или нет, поэтому схлопывать их нельзя ни в коем случае.

        Своей памяти не заводит намеренно: get_mx_records уже кэширует ответ
        на прогон, а вторая копия кэша разошлась бы с первой.
        """
        if not domain or getattr(self, "network", None) is None:
            return None
        try:
            записи = self.network.get_mx_records(domain)
        except Exception:
            return None
        if записи is None:
            return None
        return bool(записи)

    def _http_proxies(self):
        """Прокси для HTTP-проверок (Gravatar, RDAP, HEAD).

        Возвращает None, если прокси не заданы — тогда идём напрямую, как раньше.
        Если заданы, все HTTP-каналы идут через них: иначе реальный IP утекает
        и на gravatar.com, и в WHOIS, и на сайт самой проверяемой компании.
        """
        try:
            if self.network and self.network.has_proxies_configured():
                from core.network import build_proxy_dict
                proxy = self.network._pick_best_proxy()
                if proxy:
                    return build_proxy_dict(proxy)
        except Exception:
            pass
        return None
    def _start_profile_refresher(self, timeout, workers, interval=600):
        """Фоновое обновление профиля прокси раз в interval секунд."""
        self._refresh_stop = threading.Event()

        def loop():
            while not self._refresh_stop.wait(interval):
                if not self.is_running or not self.network:
                    return
                try:
                    stats = self.network.refresh_proxy_profiles(
                        timeout=timeout, workers=workers)
                except Exception:
                    continue
                if not stats.get("checked"):
                    continue
                if stats["ip_changed"] or stats["ptr_lost"] or stats["ptr_gained"]:
                    self.callbacks['on_log'](
                        f"[PROXY] Профиль обновлён: сменили IP — {stats['ip_changed']}, "
                        f"потеряли PTR — {stats['ptr_lost']}, "
                        f"получили PTR — {stats['ptr_gained']}.", "info")

        self._refresh_thread = threading.Thread(target=loop, daemon=True)
        self._refresh_thread.start()
    def _stop_profile_refresher(self):
        stop = getattr(self, "_refresh_stop", None)
        if stop is not None:
            stop.set()
    def _profile_live_proxies(self, live_proxies, timeout, threads):
        """Профиль пула: реальный выходной IP, обратный DNS, чёрные списки.

        Выходной IP спрашиваем у самого Gmail (он сообщает его в ответе на
        EHLO) — стороннего сервиса не нужно. Проверять надо именно ЕГО:
        адрес подключения к прокси совпадает с выходным не всегда.

        Живёт отдельным методом не ради красоты. Внутри блок обёрнут в
        `except Exception` — то есть ЛЮБАЯ поломка здесь превращается в одну
        строку лога и молчаливую потерю всего профиля пула. Пока блок сидел
        внутри setup(), проверить его отдельно было нечем, и он падал
        каждый прогон, ничего об этом не сообщая по существу.

        Требует УЖЕ созданный self.network: профили с прошлого запуска
        спрашиваются у него.
        """
        # Профилируем прокси: реальный выходной IP, обратный DNS, чёрные списки.
        # Выходной IP спрашиваем у самого Gmail (он сообщает его в ответе на
        # EHLO) — стороннего сервиса не нужно. Проверять надо именно ЕГО:
        # адрес подключения к прокси совпадает с выходным не всегда.
        proxy_profiles = {}
        if live_proxies:
            try:
                from core.network import profile_proxies
                self.callbacks['on_log'](
                    f"[INFO] Профилирование {len(live_proxies)} прокси "
                    "(выходной IP, PTR, чёрные списки)...", "info")

                def on_prof(done, total, ptr_n, bl_n):
                    self.callbacks['on_log'](
                        f"[PROXY] Профиль... {done}/{total} | с PTR: {ptr_n} | в списках: {bl_n}", "info")

                # Профили, снятые в прошлый раз, подставляются сразу.
                #
                # Снятие — это выходной IP через EHLO у Gmail, обратный
                # DNS, семь чёрных списков и три прямые пробы почтовиков
                # НА КАЖДЫЙ прокси. На пуле в несколько сотен — минуты
                # простоя перед каждой работой, а выходной адрес за сутки
                # обычно не меняется. Заново снимаем только тех, кого не
                # помним; фоновое обновление всё равно идёт раз в десять
                # минут и поправит то, что успело устареть.
                remembered = self.network.recall_proxy_profiles(live_proxies)
                fresh_needed = [p for p in live_proxies if p not in remembered]
                if remembered:
                    self.callbacks['on_log'](
                        "[PROXY] Из прошлого запуска помню профиль %d прокси "
                        "из %d — заново проверяю только остальных."
                        % (len(remembered), len(live_proxies)), "info")

                # Потоки берём из ползунка: раньше здесь было жёсткое 30, и
                # список в несколько тысяч прокси профилировался часами.
                proxy_profiles = dict(remembered)
                if fresh_needed:
                    proxy_profiles.update(profile_proxies(
                        fresh_needed, timeout=timeout, workers=threads,
                        progress_callback=on_prof))

                vals = list(proxy_profiles.values())
                ptr_n = sum(1 for v in vals if v["has_ptr"] is True)
                bl_n = sum(1 for v in vals if v["in_dnsbl"])
                known_ip = sum(1 for v in vals if v["exit_ip"])
                dirty_n = sum(1 for v in vals if v.get("rdns_dirty"))
                outlook_n = sum(1 for v in vals if v.get("outlook_ok") is True)
                clean_n = len(live_proxies) - bl_n

                lats = sorted(v["latency_ms"] for v in vals if v.get("latency_ms"))
                if lats:
                    median = lats[len(lats) // 2]
                    self.callbacks['on_log'](
                        f"[INFO] Скорость прокси: медиана {median} мс, "
                        f"быстрейший {lats[0]} мс, медленнейший {lats[-1]} мс.", "info")

                self.callbacks['on_log'](
                    f"[INFO] Профиль готов: выходной IP определён у {known_ip} из "
                    f"{len(live_proxies)}, с PTR — {ptr_n}, в чёрных списках — {bl_n}.", "info")

                if outlook_n is not None:
                    self.callbacks['on_log'](
                        f"[INFO] Microsoft реально принял {outlook_n} прокси из "
                        f"{len(live_proxies)} (проверено пробой до MAIL FROM, "
                        "а не по спискам).", "info")
                if dirty_n:
                    self.callbacks['on_log'](
                        f"[DEAD] У {dirty_n} прокси имя в PTR выдаёт прокси/VPN/динамику "
                        "(proxy, vpn, tor, pool...). Почтовики такие штрафуют даже "
                        "при валидном обратном DNS.", "dead")

                if ptr_n:
                    self.callbacks['on_log'](
                        f"[INFO] Yahoo/AOL пойдут через {ptr_n} прокси с PTR.", "info")
                else:
                    self.callbacks['on_log'](
                        "[DEAD] Обратного DNS (PTR) нет ни у одного прокси — Yahoo, AOL "
                        "и Verizon проверить не получится. Остальные домены проверятся.", "dead")

                if clean_n:
                    self.callbacks['on_log'](
                        f"[INFO] Outlook/iCloud/GMX пойдут через {clean_n} прокси "
                        "с чистой репутацией.", "info")
                else:
                    self.callbacks['on_log'](
                        "[DEAD] ВСЕ прокси числятся в чёрных списках — Outlook, iCloud "
                        "и GMX будут молчать. Нужны прокси с чистым IP.", "dead")

                # Структурная сводка для окна. Всё перечисленное выше уже
                # уходило строками лога, но лог прокручивается и теряется,
                # а решение «хватит ли этих прокси» пользователь принимает
                # именно по этим числам. Считает их core/proxy_profile.py,
                # чтобы панель, лог и CLI не могли разойтись.
                # Готовность — до прогона, а не после.
                #
                # Раньше владелец узнавал, что прокси не годятся, из
                # сплошного «не доказано» через полчаса работы. Причина
                # при этом лежала в одной строке профиля, которую никто
                # не читал. Теперь она произносится вслух и с указанием,
                # что чинить.
                try:
                    from core.proxy_profile import readiness_report
                    ready = readiness_report(proxy_profiles)
                    self.callbacks['on_log'](
                        ("[INFO] Готовность прокси: %s" if ready["ready"]
                         else "[DEAD] Готовность прокси: %s") % ready["verdict"],
                        "info" if ready["ready"] else "dead")
                    for item in ready["providers"]:
                        if not item["ok"]:
                            self.callbacks['on_log'](
                                "[DEAD]    %s — 0 годных прокси: %s"
                                % (item["name"], item["reason"]), "dead")
                except Exception:
                    pass

                if 'on_proxy_profile' in self.callbacks:
                    try:
                        from core.proxy_profile import pool_summary
                        self.callbacks['on_proxy_profile'](pool_summary(proxy_profiles))
                    except Exception:
                        pass
            except Exception as e:
                self.callbacks['on_log'](
                    "[DEAD] Профилирование прокси не удалось: %s: %s. "
                    "Выходной IP, PTR и чёрные списки не узнаны ни у одного "
                    "прокси — Yahoo/AOL и Outlook/iCloud пойдут вслепую."
                    % (type(e).__name__, e), "dead")
        return proxy_profiles
    def setup(self, timeout=5, enable_ai=False, proxies=None, threads=100, use_cache=True):
        # Прогон начинается с чистой сети: донашивать объект от прошлого
        # запуска нельзя — у него внутри старый список прокси.
        self.network = None
        # Гибридный режим: Whitelist + DNS-проверка неизвестных доменов
        self.callbacks['on_log']("[INFO] Подготовка валидатора (гибридный режим: Whitelist + DNS)...", "info")

        # Кэш вердиктов прошлых прогонов. Хранит только доказанное — Valid и
        # Invalid/Bounce; Unknown и Risky не кэшируются никогда, иначе сбой
        # нашей стороны закрепился бы за адресом навсегда.
        self.cache = None
        self._cache_hits = 0
        if use_cache:
            try:
                # Путь из настроек: положив кэш в синхронизируемую папку
                # (OneDrive, сетевой диск), два рабочих места перестают
                # проверять одно и то же по второму разу.
                from core.settings import cache_path
                chosen = cache_path()
                cache = ResultCache(path=chosen)
                if cache.enabled:
                    dropped = cache.purge_expired()
                    self.cache = cache
                    msg = f"[INFO] Кэш вердиктов: {cache.size()} адресов из прошлых прогонов."
                    from core.cache import DEFAULT_CACHE_PATH
                    if chosen != DEFAULT_CACHE_PATH:
                        msg += f" Общий кэш: {chosen}."
                    if dropped:
                        msg += f" Просроченных удалено: {dropped}."
                    self.callbacks['on_log'](msg, "info")
                else:
                    self.callbacks['on_log'](
                        "[DEAD] Кэш вердиктов недоступен (не удалось открыть базу) — "
                        "проверяю всё заново.", "dead")
            except Exception as e:
                self.callbacks['on_log'](
                    f"[DEAD] Кэш вердиктов не включён ({type(e).__name__}).", "dead")
        
        # Обновляем disposable/spam-списки ДО загрузки SpamFilter, чтобы он
        # сразу подхватил свежие данные. Списки переустанавливаются (замена, не
        # накопление), а качаются только если на сервере реально есть новое.
        try:
            self.callbacks['on_log']("[INFO] Проверка обновлений disposable-списков...", "info")
            BlacklistDownloader().download_all(log_callback=self.callbacks['on_log'])
        except Exception as e:
            self.callbacks['on_log'](f"[DEAD] Обновление списков не удалось ({type(e).__name__}), использую локальные.", "dead")

        # Список бесплатных почтовиков. Он НЕ для отбраковки, а для скоринга:
        # без него сотни бесплатных сервисов считаются корпоративными и
        # получают +5, которого не получает gmail.com.
        try:
            free_path = data_path("free_providers.txt")
            if os.path.exists(free_path):
                with open(free_path, "r", encoding="utf-8") as f:
                    added = extend_free_domains(line.strip() for line in f
                                                if line.strip() and not line.startswith("#"))
                if added:
                    self.callbacks['on_log'](
                        f"[INFO] Бесплатных почтовиков добавлено: {added}. "
                        "Скоринг больше не путает их с корпоративными.", "info")
        except Exception:
            pass

        # Подключаем SpamFilter из внешних файлов
        try:
            self.filter = SpamFilter(log_callback=self.callbacks.get('on_log'))
            self.callbacks['on_log'](f"[INFO] SpamFilter загружен ({self.filter.get_count() if hasattr(self.filter, 'get_count') else '?'} доменов).", "info")
            # Сливаем свежие списки во встроенную базу: она захардкожена и сама
            # не обновляется, зато умеет проверять ПОДДОМЕНЫ (foo.mailinator.com),
            # чего SpamFilter не делает — он сверяет только точное имя домена.
            try:
                from core.disposable import extend_disposable_domains, get_disposable_count
                added = extend_disposable_domains(self.filter.blacklist_domains)
                if added:
                    self.callbacks['on_log'](
                        f"[INFO] В базу одноразовых добавлено {added} доменов "
                        f"(всего {get_disposable_count()}), поддомены тоже ловятся.", "info")
            except Exception:
                pass
        except Exception:
            self.filter = None
        
        # Высокий таймаут вместе с повторами через прокси даёт огромное время на
        # один адрес: до 10 попыток * таймаут. Ползунок не трогаем (это осознанная
        # настройка), но предупреждаем, иначе прогон выглядит как зависание.
        if timeout > 30:
            self.callbacks['on_log'](
                f"[DEAD] Таймаут {timeout}с очень большой — прогон будет медленным. "
                "Обычно хватает 10-20с. (Зависнуть на одном адресе валидатор не даст: "
                "есть общий дедлайн, максимум 180с на адрес.)", "dead")

        proxy_profiles = {}
        if proxies:
            from core.network import filter_live_proxies, dedupe_proxies_stream
            # Прокси приходят ЛЕНИВО: на входе может быть и список, и генератор
            # из файла в миллионы строк. Длину заранее не спрашиваем — это
            # прочитало бы весь вход в память ради одного числа.
            #
            # Повторы схлопываются по ходу чтения: один прокси, записанный
            # дважды, проверялся бы дважды и занимал два места в ротации.
            proxies = dedupe_proxies_stream(proxies)
            self.callbacks['on_log'](
                f"[INFO] Тестирование прокси-серверов потоком "
                f"(потоков: {threads}, таймаут: {timeout}с)...", "info")
            # Теперь таймаут строго подчиняется твоему ползунку (никаких ограничений!)
            # Прогресс прокси идёт СВОИМ каналом, а не в полосу проверки почт.
            #
            # Раньше он шёл в on_progress — тот самый, которым потом двигается
            # проверка адресов. Владелец видел «Проверено 16 891 из 19 590»
            # рядом с карточками, где всюду нули, и читал это как почты. А
            # считались прокси, и «из» было не итогом, а «сколько прочитано на
            # сейчас»: разница между числами на девяти снимках подряд ровно
            # 2699 — постоянный отрыв читателя от проверяющего.
            proxy_progress = self.callbacks.get('on_proxy_progress')
            # «Хватит живых» — настройка владельца, по умолчанию выключена.
            # См. core/settings.py: на бесплатных списках перебор всего файла
            # съедает больше времени, чем сама проверка почт.
            try:
                from core.settings import get as setting
                enough = int(setting("proxy_enough", 0) or 0)
            except Exception:
                enough = 0

            live_proxies, total_seen = filter_live_proxies(
                proxies, timeout=timeout, threads=threads,
                progress_callback=proxy_progress,
                log_callback=self.callbacks.get('on_log'),
                enough=max(0, enough))
            # Итог перебора говорится числом И смыслом. «Найдено 54 из 26390»
            # само по себе не отвечает на вопрос, который у владельца в
            # голове: «а проверятся ли теперь мои почты».
            share = (100.0 * len(live_proxies) / total_seen) if total_seen else 0.0
            self.callbacks['on_log'](
                "[INFO] Проверка прокси закончена: живых %d из %d (%.1f%%)."
                % (len(live_proxies), total_seen, share), "info")
            if 'on_proxies_tested' in self.callbacks:
                self.callbacks['on_proxies_tested'](len(live_proxies), total_seen)
            if not live_proxies:
                self.callbacks['on_log'](
                    "[DEAD] Ни один прокси не отвечает на порт 25. Проверять "
                    "почту через них нечем: почтовые серверы слушают именно "
                    "этот порт, а 587 и 465 к проверке ящиков отношения не "
                    "имеют. Вердиктов не будет — ни одного. Возьми прокси с "
                    "открытым портом 25 или подними свой VPS "
                    "(tools/make_vps_proxy.py), либо запусти без прокси и "
                    "проверь хотя бы Gmail и Яндекс.", "dead")
            elif len(live_proxies) < 10:
                self.callbacks['on_log'](
                    "[DEAD] Живых прокси всего %d. На большой базе этого мало: "
                    "почтовик считает нагрузку по адресу отправителя, и с "
                    "нескольких IP он быстро начнёт отвечать «слишком часто» "
                    "или принимать любые адреса подряд." % len(live_proxies),
                    "dead")
            proxies = live_proxies

            # Сеть создаётся ЗДЕСЬ, ДО профилирования, а не после него.
            # Профилирование спрашивает у неё профили, снятые в прошлый раз.
            # Пока объект создавался ниже, этот вызов падал с AttributeError
            # на КАЖДОМ прогоне: в логе оставалась одна строка «не удалось
            # (AttributeError)», а выходной IP, PTR и чёрные списки не
            # узнавались ни у одного прокси. Маршрутизация Yahoo/AOL (нужен
            # PTR) и Outlook/iCloud (нужна чистая репутация) после этого
            # работала вслепую.
            self.network = NetworkValidator(timeout=timeout, proxies=proxies)
            proxy_profiles = self._profile_live_proxies(
                live_proxies, timeout, threads)

        # Прокси не задавали — сеть ещё не создана, создаём здесь.
        if self.network is None:
            self.network = NetworkValidator(timeout=timeout, proxies=proxies)

        # Spamhaus ZEN — крупнейший чёрный список, и до сих пор он молчал.
        # Код опроса был написан и покрыт тестами, но включался только в них:
        # в рабочем прогоне резолвер никто не задавал, и зона не спрашивалась
        # вовсе. Причина не в лени, а в самом Spamhaus: публичные резолверы
        # он не обслуживает и отвечает NXDOMAIN даже на обязательную тестовую
        # запись. Нужен свой — на том же VPS, где стоит прокси.
        resolvers = []
        try:
            from core.settings import spamhaus_resolvers
            resolvers = spamhaus_resolvers()
        except Exception:
            resolvers = []

        if resolvers and self.network:
            if self.network.set_spamhaus_resolver(resolvers):
                self.callbacks['on_log'](
                    f"[INFO] Spamhaus ZEN подключён через {', '.join(resolvers)} — "
                    "санитарный контракт зоны пройден.", "info")
            else:
                # Причина называется словами. «Не прошла контракт» не говорит
                # владельцу, что чинить: отказ резолверу и недоступная сеть
                # лечатся по-разному.
                try:
                    why = self.network.spamhaus_refusal_reason()
                except Exception:
                    why = "зона не прошла санитарный контракт"
                self.callbacks['on_log'](
                    "[DEAD] Spamhaus ZEN не опрашивается через %s: %s "
                    "Проверяю без него — это значит, что крупнейший чёрный "
                    "список молчит, и репутация IP оценивается по семи "
                    "остальным зонам." % (", ".join(resolvers), why), "dead")
        elif not resolvers and self.network:
            # Резолвер не задан — не повод молчать. Зона не обслуживает
            # КРУПНЫЕ публичные резолверы, но в системном списке обычно лежит
            # ещё и резолвер провайдера или Quad9, а их она обслуживает.
            #
            # Замерено на машине владельца: 1.1.1.1 отвечает кодом отказа
            # 127.255.255.254, 8.8.8.8 — NXDOMAIN даже на обязательную
            # тестовую запись, а 9.9.9.9 отвечает правильно. То есть
            # крупнейший чёрный список был доступен всё это время — его просто
            # никто не спросил.
            found = None
            try:
                found = self.network.autodetect_spamhaus_resolver()
            except Exception:
                found = None
            if found:
                self.callbacks['on_log'](
                    "[INFO] Spamhaus ZEN подключён сам через системный "
                    "резолвер %s — санитарный контракт зоны пройден." % found,
                    "info")
            else:
                self.callbacks['on_log'](
                    "[DEAD] Spamhaus ZEN не опрашивается: ни один резолвер из "
                    "системных зона не обслуживает. Крупнейший чёрный список "
                    "сейчас не участвует в оценке — репутация IP считается по "
                    "семи остальным зонам. Свой резолвер указывается в "
                    "data/settings.json полем spamhaus_resolvers; проще всего "
                    "поднять его на том же VPS, где стоит прокси.", "dead")

        # Починка склейки домена теперь применяется только по ответу DNS.
        # Признак «к зоне приклеен мусор» одинаково подходит настоящей
        # склейке (`mail.ruxxx`) и чужому домену (`honda.carpoi`, где после
        # реза выходит правдоподобный `honda.car`). Отличить их строкой
        # нельзя — спрашиваем факт. Без этой строки очистка ведёт себя как
        # раньше, поэтому все её офлайновые проверки остаются в силе.
        if self.cleaner is not None:
            self.cleaner.установить_проверку_домена(self._домен_принимает_почту)

        if proxy_profiles:
            self.network.set_proxy_profiles(proxy_profiles)
            # Профиль протухает: у ротирующегося прокси выходной IP меняется
            # по ходу прогона, и маршрутизация продолжает считать, что PTR
            # на месте. Обновляем в фоне, чтобы не держать воркеры.
            self._start_profile_refresher(timeout=timeout, workers=threads)
        
        if enable_ai:
            self.callbacks['on_log']("[INFO] Прогрев и обучение Нейросети (TensorFlow + NaiveBayes)...", "info")
            self.ai = EmailAI()
            self.ai.train_models()
            self.callbacks['on_log']("[INFO] ИИ успешно обучен и готов к бою!", "info")
