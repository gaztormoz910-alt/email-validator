# -*- coding: utf-8 -*-
"""Пересмотр уже выданного вердикта: канарейка, второе мнение, отзыв из кэша.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. Это единственное место, где программа ЗАБИРАЕТ
назад то, что уже сказала: домен раскрылся как catch-all в середине
прогона, канарейка уличила сервер, второй выход не подтвердил «Годен».
Такие правки обязаны читаться вместе и целиком — разбросанные по большому
файлу, они выглядят как частные случаи, а это один механизм.
"""
from core.canary import canary_address

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

        Тихо и не чаще одного раза на пару «выход + домен» за прогон: лишняя
        сессия к чужому почтовику — лишний повод попасться ему на глаза,
        ровно за тем ответом, ради которого мы и пришли.
        """
        watch = getattr(self, "canary", None)
        if watch is None or self.network is None:
            return False
        try:
            domain = email.rsplit("@", 1)[1].lower()
        except Exception:
            return False
        proxy = res.get("proxy")
        try:
            exit_ip = self.network.exit_ip_of(proxy) if proxy else None
        except Exception:
            exit_ip = proxy
        exit_ip = exit_ip or proxy

        watch.note_valid(exit_ip, domain)
        if not watch.should_probe(exit_ip, domain):
            return False

        mx = res.get("mx_records") or ([res["mx_record"]]
                                       if res.get("mx_record") else [])
        if not mx:
            return False
        try:
            ответ = self.network.stealth_smtp_ping(
                canary_address(domain), list(mx), prefer_exit_of=proxy)
            статус = ответ.get("status")
        except Exception:
            # Сорвавшаяся проба — это НЕ улика. Молчим: обвинить выход по
            # своему же сбою значит выбросить живые адреса.
            return False

        if not watch.record(exit_ip, domain, статус):
            return False

        self.callbacks['on_log'](
            "[DEAD] Канарейка вернулась живой: %s принял заведомо "
            "несуществующий адрес с выхода %s. Все «Годен» по этому домену с "
            "этого выхода НЕДОКАЗУЕМЫ — виноват прокси, не база."
            % (domain, exit_ip or "прямого соединения"), "dead")
        return True
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
        """Запомнить, через какой выход получен «Годен» этого адреса."""
        выходы = self.__dict__.setdefault("_valid_exits", {})
        выходы[str(email).strip().lower()] = self._exit_key(res.get("proxy"))

    def _spared_valid(self, domains, liars):
        """Адреса этих доменов, чей «Годен» переживает разоблачение домена.

        Решение владельца 20.11.2026: отзыв по выходу, а не по домену. Защита
        почтовика от перебора включается на конкретный IP, а прежде один
        уличённый выход снимал «Годен» с ВСЕГО домена: на живом прогоне через
        прокси владельца части без пойманного выхода давали 30–32 «Годен» из
        40, части с пойманным — 0–2.

        Сохраняется строго меньшее: выход известен, на этом домене в этом
        прогоне ПРОВЕРЕН канарейкой (отверг выдуманный адрес) и не пойман ни
        канарейкой, ни тарпитингом. Всё остальное — неизвестный выход,
        непроверенный выход, строка из кэша — пересматривается, как раньше.
        """
        watch = getattr(self, "canary", None)
        if watch is None or not hasattr(watch, "vouched"):
            return set()
        wanted = {str(d).strip().lower().lstrip("@") for d in domains or []}
        spare = set()
        for email, (key, known) in list(self.__dict__.get("_valid_exits", {}).items()):
            domain = email.rsplit("@", 1)[-1]
            if (domain in wanted and known and (key, domain) not in liars
                    and watch.vouched(key, domain)):
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
