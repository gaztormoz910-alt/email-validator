# -*- coding: utf-8 -*-
"""Пересмотр уже выданного вердикта: канарейка, второе мнение, отзыв из кэша.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. Это единственное место, где программа ЗАБИРАЕТ
назад то, что уже сказала: домен раскрылся как catch-all в середине
прогона, канарейка уличила сервер, второй выход не подтвердил «Годен».
Такие правки обязаны читаться вместе и целиком — разбросанные по большому
файлу, они выглядят как частные случаи, а это один механизм.
"""
from concurrent.futures import ThreadPoolExecutor

from core.canary import canary_address
from core.confirmation import rejects_fake

__all__ = ["VerdictRevisionMixin"]


class VerdictRevisionMixin:
    def _second_opinion_on_valid(self, email, res):
        """Спрашивает адрес вторым выходом. True/False/None — см. сеть.

        Тихо: сбой второго мнения не должен ронять вердикт, полученный
        первым. None здесь означает «сверить не удалось», и первый ответ
        остаётся в силе — иначе наш собственный сбой понижал бы честно
        подтверждённые адреса.
        """
        if self.network is None:
            return None
        mx = res.get("mx_records") or ([res["mx_record"]]
                                       if res.get("mx_record") else [])
        if not mx:
            return None
        try:
            return self.network.confirm_valid_from_other_exit(
                email, list(mx), first_proxy=res.get("proxy"))
        except Exception:
            return None
    def _fly_canary(self, email, res):
        """Пускает канарейку по домену только что подтверждённого адреса.

        Первая проба на пару «выход + домен» — на первом «Годен», дальше —
        через каждые CanaryWatch.REPEAT_EVERY новых: лишняя сессия к чужому
        почтовику — лишний повод попасться ему на глаза, но одной пробы мало,
        защита от перебора включается посреди прогона (core/canary.py).
        """
        watch = getattr(self, "canary", None)
        if watch is None or self.network is None:
            return False
        try:
            domain = email.rsplit("@", 1)[1].lower()
        except Exception:
            return False
        proxy = res.get("proxy")
        exit_ip = self._exit_key(proxy)[0]
        mx = res.get("mx_records") or ([res["mx_record"]]
                                       if res.get("mx_record") else [])
        if mx:
            # Маршрут пары — для завершающей пробы в конце прогона.
            self.__dict__.setdefault("_canary_routes", {})[(exit_ip, domain)] = (proxy, list(mx))
        # Номер этого «Годен» — сейчас, до полёта пробы. _note_valid_exit
        # зовётся ПОСЛЕ _fly_canary (core/settle.py), а проба летит в этом же
        # потоке секундами; перечитанный тогда номер раздут «Годен» других
        # потоков, и адрес, сам пустивший честную пробу, не был ею покрыт
        # (живой прогон 21.11.2026: 11 «Неизвестно» из 40 вместо 2).
        номер = watch.note_valid(exit_ip, domain)
        self.__dict__.setdefault("_valid_numbers", {})[str(email).strip().lower()] = номер
        if not mx:
            # Без MX пробу не пустить — и занимать её нельзя: занятая, но не
            # пущенная проба отодвинула бы следующую на двадцать «Годен».
            return False
        # Номер фиксируется при запуске: «Годен», пришедшие с этой пары, пока
        # проба летит, она не видела и ручаться за них не может.
        covers = watch.claim_probe(exit_ip, domain)
        if covers is None:
            return False
        return self._probe_pair(exit_ip, domain, proxy, mx, covers)

    def _probe_pair(self, exit_ip, domain, proxy, mx, covers=None):
        """Одна канарейка на пару. True — выход уличён.

        Ответ засчитывается ТОЛЬКО если проба реально прошла через этот выход.
        prefer_exit_of — просьба, а не гарантия: выбывший прокси сеть меняет на
        другой, и ответ ЧУЖОГО выхода прежде записывался на этот. Честный чужой
        выход так «ручался» за непроверенный — а при отзыве по выходу ещё и
        сохранял его ложные «Годен».

        covers — номер Valid, за который проба поручится, если выход честен
        (CanaryWatch.claim_probe/claim_now в момент запуска).
        """
        watch = self.canary
        одна_сессия = getattr(self.network, "_do_single_ping", None)
        try:
            if callable(одна_сессия):
                # ОДНА сессия через ровно этот прокси: без перебора выходов и
                # без сверки приговора со вторым MX. Сверка шла другим выходом,
                # и на домене, где врёт сосед, честный «нет такого ящика»
                # превращался в «выходы спорят» без указания выхода — честный
                # выход не мог себя доказать (живой прогон 21.11.2026).
                ответ = одна_сессия(canary_address(domain), list(mx)[0], proxy=proxy)
                ответ = dict(ответ or {}, proxy=proxy)
            else:
                ответ = self.network.stealth_smtp_ping(
                    canary_address(domain), list(mx), prefer_exit_of=proxy)
            статус = ответ.get("status")
        except Exception:
            # Сорвавшаяся проба — это НЕ улика. Молчим: обвинить выход по
            # своему же сбою значит выбросить живые адреса. Занятость снять:
            # иначе пара больше не получила бы ни одной пробы за прогон.
            watch.release(exit_ip, domain, covers)
            return False
        if self._exit_key(ответ.get("proxy"))[0] != exit_ip:
            watch.release(exit_ip, domain, covers)
            return False
        if статус in ("invalid", "risky", "disabled") and not rejects_fake(ответ):
            # Отказ по форме, но не по сути: «550 … try again later», предел
            # получателей на сессию. Сервер отложил решение, а не отверг
            # выдуманный адрес — ручаться за выход этим нельзя. То же правило,
            # что у контрольной пробы (core/confirmation.py, rejects_fake).
            статус = "unknown"
        if not watch.record(exit_ip, domain, статус, covers=covers):
            return False
        # Дальше этот домен обходит пойманный выход (core/proxy_pool.py,
        # _pick_for_domain): каждый следующий «Годен» оттуда ушёл бы в отзыв.
        отметить = getattr(self.network, "mark_exit_caught", None)
        if callable(отметить):
            отметить(exit_ip, domain)

        self.callbacks['on_log'](
            "[DEAD] Канарейка вернулась живой: %s принял заведомо "
            "несуществующий адрес с выхода %s. Все «Годен» по этому домену с "
            "этого выхода НЕДОКАЗУЕМЫ — виноват прокси, не база."
            % (domain, exit_ip or "прямого соединения"), "dead")
        return True

    def _final_canaries(self, trapped):
        """Перед отзывом по выходу: завершающие пробы и переспрос. Число завершающих.

        Только на разоблачённых доменах (тарпитинг или канарейка поймали хоть
        один выход): только там отзыв по выходу решает, что уцелеет.
        Сначала хвост «Годен» после последней пробы покрывается завершающей
        пробой, затем «Годен», которые всё равно ушли бы в «Неизвестно»,
        переспрашиваются честным выходом (_recheck_revoked). «Стоп» — ни
        одной сессии.
        """
        watch = getattr(self, "canary", None)
        if watch is None or self.network is None or self.network.aborted():
            return 0
        домены = set(trapped or []) | set(watch.compromised_domains())
        пущено = self._cover_tails(домены)
        self._recheck_revoked(домены)
        return пущено

    def _cover_tails(self, домены):
        """Завершающая проба на паре, у которой «Годен» есть ПОСЛЕ последней пробы."""
        watch = self.canary
        пущено = 0
        for (exit_ip, domain), (proxy, mx) in list(self.__dict__.get("_canary_routes", {}).items()):
            if domain not in домены or self.network.aborted():
                continue
            if watch.valid_count(exit_ip, domain) <= watch.honest_upto(exit_ip, domain):
                continue
            if watch.is_compromised(exit_ip, domain):
                continue
            # Занять пробу на нынешнем номере, чтобы она ручалась за весь хвост.
            covers = watch.claim_now(exit_ip, domain)
            self._probe_pair(exit_ip, domain, proxy, mx, covers)
            if (watch.honest_upto(exit_ip, domain) < covers
                    and not watch.is_compromised(exit_ip, domain)
                    and not self.network.aborted()):
                # Проба сорвалась (таймаут, обрыв) — не улика и не
                # поручительство. Последний шанс у этих «Годен», поэтому ещё
                # одна попытка: живой прогон 21.11.2026 потерял так 3 адреса,
                # честный выход сказал «Годен», а канарейка не дождалась ответа.
                covers = watch.claim_now(exit_ip, domain)
                self._probe_pair(exit_ip, domain, proxy, mx, covers)
            пущено += 1
        if пущено:
            self.callbacks['on_log'](
                "[INFO] Завершающих канареек: %d — по выходам, у которых были «Годен» "
                "после последней пробы." % пущено, "info")
        return пущено

    def _recheck_revoked(self, домены):
        """Переспросить честным выходом «Годен», которые иначе уйдут в «Неизвестно».

        Это «Годен» с выхода, пойманного на домене, с выхода без профиля или
        без честной пробы после себя. Увод (core/proxy_pool.py) не пускает
        новые адреса через лжеца, но всё, что прошло через него ДО поимки, уже
        выдано. Переспрос — та же лестница, что у основного прохода: ответ
        выхода (мимо уличённых), второе мнение, канарейка. Уцелеет адрес по
        тому же правилу отзыва (_spared_valid): новый выход известен, не
        уличён и проверен честной пробой не раньше этого адреса. Отказ или
        молчание честного выхода «Годен» не возвращают: строка уходит в
        «Неизвестно», как и без переспроса, — приговор по одному переспросу
        не выносится. Возвращает (переспрошено, подтверждено).
        """
        net = self.network
        проверить = getattr(net, "check_email", None)
        if not callable(проверить) or net.aborted():
            return 0, 0
        try:
            лжецы = set(net.tarpit_pairs()) | self.canary.lying_pairs()
        except Exception:
            return 0, 0
        уцелеют = self._spared_valid(домены, лжецы)
        исходные = dict(self.__dict__.get("_valid_original", {}))
        кандидаты = sorted(адрес for адрес in list(self.__dict__.get("_valid_exits", {}))
                           if адрес.rsplit("@", 1)[-1] in домены and адрес not in уцелеют)
        if not кандидаты:
            return 0, 0
        # Опора домена — честный выход, чьи канарейки уже отвечали дальше всех
        # (наибольший honest_upto). Переспрос идёт сначала через него: новый
        # «Годен» на выходе без истории ждал бы завершающей пробы, а она на
        # медленном прокси срывается — и честно подтверждённый адрес уходил в
        # «Неизвестно» (живой прогон 21.11.2026, 3 адреса).
        опора = {}
        for (выход, домен), (прокси, _mx) in list(self.__dict__.get("_canary_routes", {}).items()):
            if домен not in домены or (выход, домен) in лжецы or not self._exit_key(прокси)[1]:
                continue
            честен_до = self.canary.honest_upto(выход, домен)
            if честен_до >= 0 and честен_до > опора.get(домен, (-1, None))[0]:
                опора[домен] = (честен_до, прокси)
        подтверждено = []

        def переспросить(адрес):
            if net.aborted():
                return
            email = исходные.get(адрес, адрес)
            try:
                res = проверить(email, prefer_exit_of=опора.get(
                    адрес.rsplit("@", 1)[-1], (-1, None))[1])
            except Exception:
                return
            if res.get("status") != "valid" or res.get("aborted"):
                return
            if not self._exit_key(res.get("proxy"))[1]:
                return               # «Годен» с неизвестного выхода отзыв не сохранит
            if (getattr(self, "confirm_valid", False)
                    and self._second_opinion_on_valid(email, res) is False):
                return
            self._fly_canary(email, res)
            self._note_valid_exit(email, res)
            подтверждено.append(адрес)

        with ThreadPoolExecutor(max_workers=min(8, len(кандидаты))) as пул:
            list(пул.map(переспросить, кандидаты))
        if подтверждено:
            # Новые «Годен» на честных выходах — под завершающую пробу.
            self._cover_tails(домены)
        self.callbacks['on_log'](
            "[INFO] Переспрошено честным выходом «Годен», которые иначе ушли бы в "
            "«Неизвестно»: %d; снова «Годен» — %d (сохранятся, если их выход прошёл "
            "канарейку)." % (len(кандидаты), len(подтверждено)), "info")
        return len(кандидаты), len(подтверждено)
    def _split_catchall_from_tarpit(self, proven, trapped):
        """Делит «принял выдуманный адрес» на настоящий catch-all и тарпитинг.

        Гигант в списке proven — не catch-all: контрольная проба у него
        помечает домен на весь прогон, но catch-all у gmail.com не бывает по
        устройству — это наш выход под подозрением. Живой прогон 15.11.2026 так
        и написал владельцу про 82 адреса gmail «домен принимает любой адрес»
        и отправил бы его чистить базу вместо смены прокси. Пересмотр в
        «Неизвестно» остаётся (честные и нечестные ответы по времени не
        разделить), меняется названная причина: такие домены уходят в
        тарпитинг. Возвращает (catch-all, тарпитинг).
        """
        net = getattr(self, "network", None)
        гиганты = []
        for d in proven or []:
            try:
                if net is not None and net._is_never_catchall(d):
                    гиганты.append(d)
            except Exception:
                pass
        if not гиганты:
            return list(proven or []), list(trapped or [])
        return ([d for d in proven if d not in гиганты],
                sorted(set(trapped or []) | set(гиганты)))
    def _catchall_disproven(self, domain):
        """Опровергнут ли у домена приём любых адресов — фактом, а не догадкой.

        Да, если это гигант, у которого catch-all не бывает по устройству
        (его враньё — тарпитинг, и ловится оно канарейкой и контролем), или
        если в этом прогоне сервер отверг выдуманный адрес. Не знаем — False:
        отсутствие опровержения не опровержение.
        """
        net = getattr(self, "network", None)
        if net is None:
            return False
        try:
            if net._is_never_catchall(domain):
                return True
            with net.catchall_lock:
                return net.catchall_cache.get(domain) is False
        except Exception:
            return False
    def _forget_cached(self, domains, why):
        """Стирает из кэша вердикты по разоблачённым доменам.

        `_revise` чинит ТЕКУЩИЙ прогон: таблицу и выгрузку. Но вердикт лежит
        ещё и в кэше со сроком в тридцать суток, и следующий запуск достанет
        оттуда тот самый «Годен», не сходив в сеть. Разоблачение действовало
        бы один прогон, а ложный вердикт возвращался бы на месяц — то есть
        владелец получил бы его ровно тогда, когда уже забыл про
        предупреждение.

        Тихо и по одному домену: сбой кэша не имеет права ронять прогон,
        который к этому моменту уже закончен.
        """
        cache = getattr(self, "cache", None)
        if cache is None or not domains:
            return 0
        forgotten = 0
        for domain in domains:
            try:
                forgotten += cache.forget_domain(domain)
            except Exception:
                pass
        if forgotten:
            self.callbacks['on_log'](
                "[INFO] Из кэша убрано вердиктов: %d (%s). Следующий запуск "
                "проверит эти адреса заново, а не достанет старый «Годен»."
                % (forgotten, why), "info")
        return forgotten
    def _exit_key(self, proxy):
        """(ключ выхода, известен ли выход) — тот же ключ, что у канарейки.

        Выход — выходной IP прокси, а не строка подключения: десять прокси
        могут делить один выход. Не профилированный прокси — выход НЕИЗВЕСТЕН,
        и сохранить по нему «Годен» нельзя: он мог делить выход с уличённым.
        """
        if not proxy:
            return "прямое соединение", True
        try:
            ip = self.network.exit_ip_of(proxy) if self.network is not None else ""
        except Exception:
            ip = ""
        return (str(ip).lower(), True) if ip else (str(proxy).lower(), False)

    def _note_valid_exit(self, email, res):
        """Запомнить выход «Годен» этого адреса и его номер на паре.

        Номер — тот, что выдал note_valid в _fly_canary, в момент «Годен».
        Без него (канарейки нет) — сколько Valid насчитано сейчас: при гонке
        потоков это больше настоящего, ошибка в строгую сторону — для
        сохранения нужна честная проба не раньше этого номера.
        """
        выходы = self.__dict__.setdefault("_valid_exits", {})
        key, known = self._exit_key(res.get("proxy"))
        адрес = str(email).strip().lower()
        watch = getattr(self, "canary", None)
        номер = self.__dict__.get("_valid_numbers", {}).pop(адрес, None)
        try:
            if номер is None:
                номер = watch.valid_count(key, адрес.rsplit("@", 1)[-1]) if watch else 0
        except Exception:
            номер = 0
        выходы[адрес] = (key, known, номер)
        # Написание как во входе — для переспроса: локальная часть по RFC 5321
        # может различать регистр, и спрашивать надо тот же адрес.
        self.__dict__.setdefault("_valid_original", {})[адрес] = str(email).strip()

    def _spared_valid(self, domains, liars):
        """Адреса этих доменов, чей «Годен» переживает разоблачение домена.

        Решение владельца 20.11.2026: отзыв по выходу, а не по домену. Защита
        почтовика от перебора включается на конкретный IP, а прежде один
        уличённый выход снимал «Годен» с ВСЕГО домена: на живом прогоне через
        прокси владельца части без пойманного выхода давали 30–32 «Годен» из
        40, части с пойманным — 0–2.

        Сохраняется строго меньшее: выход известен, на этом домене в этом
        прогоне ПРОВЕРЕН канарейкой (отверг выдуманный адрес) ПОСЛЕ этого
        «Годен» — номер честной пробы не меньше номера «Годен» на паре — и не
        пойман ни канарейкой, ни тарпитингом. Всё остальное — неизвестный выход,
        непроверенный выход, «Годен» после последней честной пробы, строка из
        кэша — пересматривается, как раньше.
        """
        watch = getattr(self, "canary", None)
        if watch is None or not hasattr(watch, "honest_upto"):
            return set()
        wanted = {str(d).strip().lower().lstrip("@") for d in domains or []}
        spare = set()
        for email, (key, known, номер) in list(self.__dict__.get("_valid_exits", {}).items()):
            domain = email.rsplit("@", 1)[-1]
            if (domain in wanted and known and (key, domain) not in liars
                    and watch.vouched(key, domain)
                    and watch.honest_upto(key, domain) >= номер):
                spare.add(email)
        return spare

    def _log_spared(self, spared, why):
        """Сказать вслух, сколько «Годен» уцелело при отзыве по выходу."""
        if spared:
            self.callbacks['on_log'](
                "[INFO] Отзыв по выходу (%s): сохранено «Годен» — %d; их выход на "
                "этом домене проверен канарейкой и честно отверг выдуманный адрес."
                % (why, len(spared)), "info")

    def _revise(self, domains, new_status, note, spare=None):
        """Просит поверхность пересмотреть уже показанные строки по домену.

        Канал необязательный: командная строка и API держат свои списки, и
        каждый пересматривает их сам. Отсутствие обработчика не должно ронять
        прогон — но и молчать об этом нельзя, поэтому строка в логе остаётся
        в любом случае (её пишет вызывающий).
        """
        handler = self.callbacks.get('on_revise')
        if handler is None or not domains:
            return 0
        # None доходит до поверхности как None, а не как строка «None».
        # None значит «статус не трогать, только приписать оговорку», и оба
        # обработчика проверяют это условием `if new_status`. Строка «None»
        # это условие проходит: командная строка записывала её в статус, а
        # окно переносило живые адреса в группу «Неясно» со статусом «None».
        # Замерено прогоном 27.09.2026: пять доказанно живых Gmail из
        # test.txt владельца вышли со статусом «None».
        status = None if new_status is None else str(new_status)
        try:
            if spare:
                try:
                    return int(handler(list(domains), status, str(note), set(spare)) or 0)
                except TypeError:
                    # Обработчик о выходах не знает — пересмотр всего домена,
                    # то есть прежнее, более строгое поведение.
                    pass
            return int(handler(list(domains), status, str(note)) or 0)
        except Exception:
            return 0
