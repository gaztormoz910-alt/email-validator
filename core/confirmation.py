# -*- coding: utf-8 -*-
from core.heuristics import is_parked_domain
from core.mail_constants import AOL_DOMAINS, NEEDS_CLEAN_IP_DOMAINS, YAHOO_DOMAINS
from core.smtp_codes import classify_smtp_response, looks_transient

LIAR_EXIT_REASON = ("Выход принял и выдуманный адрес, а другой выход его отверг — "
                    "лжёт выход, а не домен; адрес переспрашивается другим выходом")

__all__ = ["AcceptanceMixin", "FORWARDING_MX", "forwarding_service", "rejects_fake"]


FORWARDING_MX = {
    "improvmx.com": "ImprovMX",
    "mx.cloudflare.net": "Cloudflare Email Routing",
    "forwardemail.net": "Forward Email",
    "pobox.com": "Pobox",
    "porkbun.com": "Porkbun (пересылка)",
}
_NAMECHEAP_FORWARD_PREFIX = "eforward"
_NAMECHEAP_FORWARD_SUFFIX = ".registrar-servers.com"


def _suffix_match(host, suffix):
    return host == suffix or host.endswith("." + suffix)


def forwarding_service(mx_records):
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
                if host in ("fwd1.porkbun.com", "fwd2.porkbun.com"):
                    return name
                continue
            if _suffix_match(host, suffix):
                return name
    return ""


_REJECTS_FAKE = ("invalid", "risky", "disabled")

_SESSION_LIMIT_MARKERS = ("too many recipients", "5.5.3", "4.5.3",
                          "recipients per", "one recipient")


def rejects_fake(verdict, message=""):
    if not isinstance(verdict, dict) or verdict.get("status") not in _REJECTS_FAKE:
        return False
    текст = (message.decode("utf-8", "ignore") if isinstance(message, bytes)
             else str(message or "")).lower() + " " + str(verdict.get("reason", "")).lower()
    if any(m in текст for m in _SESSION_LIMIT_MARKERS):
        return False
    if verdict.get("status") == "risky" and (
            "временн" in текст or looks_transient(текст)):
        return False
    return True


class AcceptanceMixin:

    def _exit_of(self, proxy):
        if not proxy:
            return "прямое соединение"
        try:
            ip = self.exit_ip_of(proxy)
        except Exception:
            ip = ""
        return str(ip or proxy).lower()

    def _note_fake_rejected(self, domain, proxy):
        with self.catchall_lock:
            self.catchall_cache.setdefault(domain, False)
            self.__dict__.setdefault("_fake_rejected", set()).add(
                (self._exit_of(proxy), str(domain or "").lower()))

    def _note_exit_lies(self, domain, proxy):
        with self.catchall_lock:
            self._tarpit_domains.add(str(domain or "").lower())
            self._tarpit_pairs.add((self._exit_of(proxy), str(domain or "").lower()))

    def _lies_about_fake(self, domain, mx, proxy):
        if not mx:
            return False
        ответ = (self._probe_recipients([self._control_address(domain)], mx,
                                        proxy=proxy) or [{}])[0]
        return ответ.get("status") == "valid"

    def _fake_rejected_elsewhere(self, domain, proxy, mx):
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
        with self.catchall_lock:
            return ((self._exit_of(proxy), str(domain or "").lower())
                    in self.__dict__.get("_fake_rejected", set()))

    def _control_address(self, domain):
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
        if not self._is_never_catchall(domain):
            self._remember_catchall(domain, True, proxy=proxy)
        return {"status": "catchall", "reason": reason}

    def _control_in_session(self, server, domain, result, via_vrfy=False, proxy=None,
                            mx=None):
        fake = self._control_address(domain)
        try:
            code, message = (server.verify(fake) if via_vrfy else server.rcpt(fake))
            code = int(code)
        except Exception:
            code, message = None, b""
        if via_vrfy and code == 252:
            code = None
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
        try:
            server.rcpt(self._control_address(domain))
        except Exception:
            pass

    def _confirm_acceptance(self, domain, result, mx_records, gateway=""):
        if result.get("status") == "catchall" and gateway:
            result["reason"] = f"Catch-All: почтовый шлюз {gateway} принимает любой адрес"
        if result.get("status") != "valid":
            return result

        excluded = result.get("control_rcpt") == "rejected"
        if not excluded and not result.get("via_vrfy"):
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
            return self._downgrade(result, (
                "Сервер принял адрес, но исключить приём любых адресов не "
                "удалось: на выдуманный адрес — %s" % answer),
                final=bool(result.get("via_vrfy")))

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
                return False
            result["control_rcpt"] = "rejected"
            return True
        result["control_answer"] = answer.get("reason") or result.get("control_answer", "")
        return False

    @staticmethod
    def _downgrade(result, why, final=False):
        result["accepted_reason"] = result.get("reason", "")
        result["status"] = "unconfirmed"
        result["unconfirmed_final"] = bool(final)
        result["reason"] = "%s | %s" % (result.get("reason", ""), why)
        return result
