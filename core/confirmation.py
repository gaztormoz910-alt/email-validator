# -*- coding: utf-8 -*-
"""Когда `250` на адрес — доказательство, а когда нет.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. «Сервер принял адрес» само по себе не значит «ящик
существует»: так же принимает домен, который берёт ЛЮБОЙ адрес (catch-all).
Раньше правило было размазано по SMTP-диалогу и держалось на одном вопросе
— отверг ли сервер выдуманный адрес. Если выдуманный получал ВРЕМЕННЫЙ
отказ (серый список, «слишком много получателей»), вопрос оставался без
ответа, а адрес всё равно уходил в «Годен». Аудит 27.09.2026 воспроизвёл
это на настоящем коде: catch-all за серым списком выдавал «Годен» на
выдуманный адрес (D2), а сервер, не пускающий второй RCPT в сессию, — в
круге перепроверки (D3).

ПРАВИЛО. «Годен» — только когда приём любых адресов ИСКЛЮЧЁН доказательством:
выдуманный адрес получил окончательный отказ «нет такого ящика» — в той же
сессии или в отдельной, — либо домен уже доказанно не catch-all. Иначе —
`unconfirmed`: сервер принял, но доказать, что это не приём всего подряд,
не удалось. Это не «Годен» и не «Мёртв», а «Неясно», и конвейер
переспрашивает такой адрес позже.

У гигантов (gmail.com, Яндекс, Microsoft, Yahoo, iCloud) catch-all не бывает
по устройству, и там правило не применяется: их честность стерегут
контрольная проба раз в 25 адресов и канарейка (core/canary.py).

ПОЧЕМУ ПРИМЕСЬ. Состояние (кэш catch-all, замок, память между запусками)
живёт в NetworkValidator; примесь работает с тем же объектом.
"""
from core.heuristics import is_parked_domain
from core.mail_constants import AOL_DOMAINS, NEEDS_CLEAN_IP_DOMAINS, YAHOO_DOMAINS
from core.smtp_codes import classify_smtp_response, looks_transient

# Причина «не проверено», когда выдуманный адрес принял только наш выход.
# Цикл попыток переспрашивает такой адрес другим выходом сразу; не успел —
# маркер «лжёт выход» в core/pipeline.py (_TRANSIENT_MARKERS) отправляет его
# в круг перепроверки, тоже другим выходом.
LIAR_EXIT_REASON = ("Выход принял и выдуманный адрес, а другой выход его отверг — "
                    "лжёт выход, а не домен; адрес переспрашивается другим выходом")

__all__ = ["AcceptanceMixin", "FORWARDING_MX", "forwarding_service", "rejects_fake"]


# Сервисы, которые НЕ хранят почту, а пересылают её дальше. Домен получателя
# с таким MX своих ящиков не имеет: адрес на нём — только правило пересылки,
# и сервер пересылки отвечает за правило, а не за ящик, куда письмо уйдёт.
# Конечный ящик снаружи не проверяется никак, поэтому `250` здесь — не
# «Годен». ZeroBounce помечает такие адреса как mx_forward (do_not_mail).
#
# Ключ — суффикс имени MX-хоста по границе метки, значение — имя сервиса.
FORWARDING_MX = {
    "improvmx.com": "ImprovMX",
    "mx.cloudflare.net": "Cloudflare Email Routing",
    "forwardemail.net": "Forward Email",
    "pobox.com": "Pobox",
    "porkbun.com": "Porkbun (пересылка)",
}
# У Namecheap пересылка живёт на общем домене с хостингом, поэтому узнаётся
# по имени узла, а не по суффиксу: eforward1…eforward5.registrar-servers.com.
_NAMECHEAP_FORWARD_PREFIX = "eforward"
_NAMECHEAP_FORWARD_SUFFIX = ".registrar-servers.com"


def _suffix_match(host, suffix):
    return host == suffix or host.endswith("." + suffix)


def forwarding_service(mx_records):
    """Имя сервиса пересылки, если почта домена идёт через него, иначе ''."""
    if isinstance(mx_records, str):
        mx_records = [mx_records]
    if not isinstance(mx_records, (list, tuple)):
        return ""
    for record in mx_records:
        if not isinstance(record, str) or not record:
            continue
        host = record.strip().lower().rstrip(".")
        if host.startswith(_NAMECHEAP_FORWARD_PREFIX) and host.endswith(_NAMECHEAP_FORWARD_SUFFIX):
            return "Namecheap (пересылка)"
        for suffix, name in FORWARDING_MX.items():
            if suffix == "porkbun.com":
                # У Porkbun под тем же доменом и их собственная почта;
                # пересылка — только узлы fwd1/fwd2.
                if host in ("fwd1.porkbun.com", "fwd2.porkbun.com"):
                    return name
                continue
            if _suffix_match(host, suffix):
                return name
    return ""


# Какие ответы на ВЫДУМАННЫЙ адрес доказывают, что сервер сверяет
# получателей: «нет такого ящика» (invalid) и голый отказ 5xx без объяснения
# (risky) — сервер отличил настоящий адрес от выдуманного. Отказ по политике,
# временный отказ, обрыв — не доказывают ничего.
_REJECTS_FAKE = ("invalid", "risky", "disabled")

# Отказ из-за ЧИСЛА получателей в сессии («550 5.5.3 Too many recipients»).
# Разбор ответов читает его как голый отказ (risky), но про выдуманный адрес
# он не говорит ничего: так сервер, принимающий любой адрес, отвечает на
# второй RCPT в сессии. Засчитать его как «сервер отверг выдуманный» значило
# бы выдать «Годен» на catch-all домене.
_SESSION_LIMIT_MARKERS = ("too many recipients", "5.5.3", "4.5.3",
                          "recipients per", "one recipient")


def rejects_fake(verdict, message=""):
    """Доказывает ли ответ на выдуманный адрес, что сервер сверяет получателей."""
    if not isinstance(verdict, dict) or verdict.get("status") not in _REJECTS_FAKE:
        return False
    текст = (message.decode("utf-8", "ignore") if isinstance(message, bytes)
             else str(message or "")).lower() + " " + str(verdict.get("reason", "")).lower()
    if any(m in текст for m in _SESSION_LIMIT_MARKERS):
        return False
    # «Под вопросом» бывает и ОТСРОЧКОЙ: «550 … try again later» разбор читает
    # как «временный отказ с постоянным кодом», «4.x.x» при 5xx — как
    # «постоянный код с временным статусом». Сервер не отверг выдуманный адрес,
    # а отложил решение — и про приём любых адресов не сказал ничего
    # (аудит 21.11.2026). Голый отказ 5xx без объяснения по-прежнему отказ.
    if verdict.get("status") == "risky" and (
            "временн" in текст or looks_transient(текст)):
        return False
    return True


class AcceptanceMixin:
    """Доказательство того, что `250` — про ящик. Примешивается к NetworkValidator."""

    def _exit_of(self, proxy):
        """Выход прокси — тот же ключ, что у канарейки (core/verdict_revision.py)."""
        if not proxy:
            return "прямое соединение"
        try:
            ip = self.exit_ip_of(proxy)
        except Exception:
            ip = ""
        return str(ip or proxy).lower()

    def _note_fake_rejected(self, domain, proxy):
        """Выдуманный адрес отвергнут на домене — запомнить, ЧЕРЕЗ КАКОЙ выход.

        Отметка «домен не catch-all» одна на домен, а получена она через
        конкретный выход. Почтовик, включивший защиту от перебора на одном IP,
        отвечает «да» на всё именно ему — и такой выход получал «Годен» потому,
        что домен честно проверил ДРУГОЙ (аудит 21.11.2026). Поэтому «Годен»
        оставляет только отказ, полученный тем же выходом.
        """
        with self.catchall_lock:
            self.catchall_cache.setdefault(domain, False)
            self.__dict__.setdefault("_fake_rejected", set()).add(
                (self._exit_of(proxy), str(domain or "").lower()))

    def _note_exit_lies(self, domain, proxy):
        """Выход пойман на приёме выдуманного адреса: тарпитинг пары «выход + домен».

        Та же отметка, что у гиганта, пойманного контрольной пробой: домен
        обходит этот выход (core/proxy_pool.py, caught_exits_on), а его «Годен»
        по домену в конце прогона отзываются (отзыв по выходу).
        """
        with self.catchall_lock:
            self._tarpit_domains.add(str(domain or "").lower())
            self._tarpit_pairs.add((self._exit_of(proxy), str(domain or "").lower()))

    def _lies_about_fake(self, domain, mx, proxy):
        """Принимает ли этот выход выдуманный адрес прямо сейчас. Одна сессия."""
        if not mx:
            return False
        ответ = (self._probe_recipients([self._control_address(domain)], mx,
                                        proxy=proxy) or [{}])[0]
        return ответ.get("status") == "valid"

    def _fake_rejected_elsewhere(self, domain, proxy, mx):
        """Выдуманный адрес принял только ЭТОТ выход? True — другой выход его отверг.

        Приём выдуманного адреса одним выходом — ещё не catch-all домена:
        почтовик, включивший защиту от перебора на наш IP, отвечает «да» на всё
        именно ему. yandex.com так уходил в catch-all целиком: живой прогон
        21.11.2026 — 6 строк из 300, по эталону 5 из них несуществующие ящики.
        Прежде чем объявить домен, тот же выдуманный адрес спрашивается другим
        выходом. Другого выхода нет или он промолчал — False, прежний вывод.
        """
        if not mx:
            return False
        домен = str(domain or "").lower()
        try:
            другой, _пойманы = self._pick_for_domain(
                домен, домен in YAHOO_DOMAINS or домен in AOL_DOMAINS,
                домен in NEEDS_CLEAN_IP_DOMAINS, "", proxy)
        except Exception:
            return False
        if not другой or self._exit_of(другой) == self._exit_of(proxy):
            return False
        ответ = (self._probe_recipients([self._control_address(домен)], mx,
                                        proxy=другой) or [{}])[0]
        if not rejects_fake(ответ):
            return False
        self._note_fake_rejected(домен, другой)
        return True

    def _fake_rejected_via(self, domain, proxy):
        """Отвергал ли выдуманный адрес на этом домене именно этот выход."""
        with self.catchall_lock:
            return ((self._exit_of(proxy), str(domain or "").lower())
                    in self.__dict__.get("_fake_rejected", set()))

    def _control_address(self, domain):
        """Выдуманный адрес для контрольной пробы — ОДИН на домен за прогон.

        Раньше на каждую пробу собирался новый. Для серого списка это значит,
        что выдуманный адрес ВСЕГДА новый получатель и всегда получает
        «приходите позже», то есть контроль не мог состояться никогда.
        Постоянный адрес проходит выдержку так же, как настоящий, и на
        повторе получает настоящий ответ.
        """
        # Импорт локальный: core/network.py импортирует эту примесь, и импорт
        # на уровне файла замкнул бы круг (так же сделано в core/catchall.py).
        from core.network import control_probe_address
        key = str(domain or "").strip().lower()
        with self.catchall_lock:
            address = self._control_addrs.get(key)
            if address is None:
                address = control_probe_address(key)
                self._control_addrs[key] = address
        return address

    def _mark_catchall(self, domain, reason, proxy=None):
        with self.catchall_lock:
            self.catchall_cache[domain] = True
        # У гигантов приём выдуманного — тарпитинг, а не свойство домена, и в
        # долгую память он не пишется (см. core/catchall.py). Прочие пишутся
        # туда только с надёжного выхода — решает _remember_catchall по proxy.
        if not self._is_never_catchall(domain):
            self._remember_catchall(domain, True, proxy=proxy)
        return {"status": "catchall", "reason": reason}

    def _control_in_session(self, server, domain, result, via_vrfy=False, proxy=None,
                            mx=None):
        """Контрольный вопрос про выдуманный адрес в ТОЙ ЖЕ сессии.

        Спрашивается той же командой, которой получен ответ про настоящий
        адрес: если «принят» пришло от VRFY, то и контроль — VRFY. Раньше
        контроль всегда шёл через RCPT, и отказ по RCPT «подтверждал» ответ
        VRFY — сравнивались две разные команды (аудит, D10).

        Выдуманный принят по RCPT — прежде чем объявить домен catch-all, его же
        спрашивает другой выход (_fake_rejected_elsewhere). Отверг — лжёт наш
        выход: он помечается пойманным, ответ становится «не проверено», и цикл
        попыток (stealth_smtp_ping) переспрашивает адрес другим выходом.
        """
        fake = self._control_address(domain)
        try:
            code, message = (server.verify(fake) if via_vrfy else server.rcpt(fake))
            code = int(code)
        except Exception:
            code, message = None, b""
        if via_vrfy and code == 252:
            code = None                   # «не берусь проверить» — не ответ
        if code is not None and 200 <= code < 300:
            if not via_vrfy and self._fake_rejected_elsewhere(domain, proxy, mx):
                self._note_exit_lies(domain, proxy)
                result.update({"status": "unknown", "reason": LIAR_EXIT_REASON,
                               "exit_caught": True})
                return
            caught = self._mark_catchall(
                domain, "Catch-All: сервер принял и выдуманный адрес в той же сессии",
                proxy=proxy)
            result.update(caught)
            return
        verdict = (classify_smtp_response(code, message) if code is not None
                   else {"status": "unknown", "reason": "контрольная проба сорвалась"})
        if rejects_fake(verdict, message):
            self._note_fake_rejected(domain, proxy)
            result["control_rcpt"] = "rejected"
        else:
            result["control_rcpt"] = "inconclusive"
            result["control_answer"] = verdict.get("reason", "")

    def _prewarm_control(self, server, domain):
        """Запустить выдержку серого списка для контрольного адреса.

        Настоящий адрес получил «приходите позже» — значит и контрольный
        получит то же. Спросить его сейчас, в той же сессии, стоит одного
        пакета, а на повторе оба адреса вернутся одновременно и получат
        настоящие ответы. Ответ здесь не читается.
        """
        try:
            server.rcpt(self._control_address(domain))
        except Exception:
            pass

    def _confirm_acceptance(self, domain, result, mx_records, gateway=""):
        """Решает, остаётся ли `valid` «Годен». Возвращает итоговый результат."""
        if result.get("status") == "catchall" and gateway:
            result["reason"] = f"Catch-All: почтовый шлюз {gateway} принимает любой адрес"
        if result.get("status") != "valid":
            return result

        excluded = result.get("control_rcpt") == "rejected"
        if not excluded and not result.get("via_vrfy"):
            # Отказ выдуманному в этом прогоне — но ТЕМ ЖЕ выходом, что принёс
            # «Годен»: отметка другого выхода про этот выход не говорит ничего.
            excluded = self._fake_rejected_via(domain, result.get("proxy"))
        if not excluded and not result.get("via_vrfy") and mx_records:
            excluded = self._control_in_own_session(domain, result, mx_records)
            if result.get("status") == "catchall":
                if gateway:
                    result["reason"] = (f"Catch-All: почтовый шлюз {gateway} "
                                        "принимает любой адрес")
                return result
        if not excluded:
            answer = result.get("control_answer") or "ответа по существу не было"
            # Ответ VRFY на повторе не изменится: «не берусь проверить» или
            # выключенная команда останутся теми же. Серый список и лимит
            # сессии — изменятся, поэтому такой адрес переспрашивается.
            return self._downgrade(result, (
                "Сервер принял адрес, но исключить приём любых адресов не "
                "удалось: на выдуманный адрес — %s" % answer),
                final=bool(result.get("via_vrfy")))

        # Приём любых адресов исключён. Остаётся вопрос, КОМУ уйдёт письмо.
        parked = is_parked_domain(mx_records)
        if parked:
            return self._downgrade(result, (
                "Почта домена ведёт на сервер парковки или регистратора — "
                "ящика за адресом, скорее всего, нет"), final=True)
        service = forwarding_service(mx_records)
        if service:
            return self._downgrade(result, (
                "Почта домена пересылается через %s — конечный ящик "
                "получателя снаружи не проверяется" % service), final=True)
        if gateway:
            result["reason"] = ("%s [шлюз %s честно отвергает выдуманные адреса]"
                                % (result.get("reason", ""), gateway))
        return result

    def _control_in_own_session(self, domain, result, mx_records):
        """Контроль ОТДЕЛЬНОЙ сессией, если в общей ответа не было.

        Нужен серверу, который не пускает второй RCPT в сессию
        (`452 too many recipients`): так он прячет себя от контроля в той же
        сессии. Здесь выдуманный адрес — ПЕРВЫЙ получатель, и прятаться
        нечем. Идём тем же выходом, что и основная проверка.
        """
        fake = self._control_address(domain)
        proxy = result.get("proxy")
        if proxy is None and self.has_proxies_configured():
            proxy = self._probe_proxy_for(domain)
        answer = (self._probe_recipients([fake], mx_records[0], proxy=proxy) or [{}])[0]
        status = answer.get("status")
        if status == "valid":
            result.update(self._mark_catchall(
                domain, "Catch-All: сервер принял выдуманный адрес отдельной сессией",
                proxy=proxy))
            return False
        if rejects_fake(answer):
            self._note_fake_rejected(domain, proxy)
            if self._exit_of(proxy) != self._exit_of(result.get("proxy")):
                # Проба ушла другим выходом (у основной проверки прокси не было,
                # а в пуле они есть): про выход «Годен» она не говорит ничего.
                return False
            result["control_rcpt"] = "rejected"
            return True
        result["control_answer"] = answer.get("reason") or result.get("control_answer", "")
        return False

    @staticmethod
    def _downgrade(result, why, final=False):
        """`valid` -> `unconfirmed` с причиной. Исходный ответ сохраняется.

        final=True — повтор ответа не изменит (парковка, пересылка, VRFY), и
        конвейер не отправляет такой адрес ждать перепроверки.
        """
        result["accepted_reason"] = result.get("reason", "")
        result["status"] = "unconfirmed"
        result["unconfirmed_final"] = bool(final)
        result["reason"] = "%s | %s" % (result.get("reason", ""), why)
        return result
