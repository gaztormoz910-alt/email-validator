# -*- coding: utf-8 -*-
__all__ = ["BehindGatewayMixin", "m365_hosts_for", "M365_SUFFIX"]

M365_SUFFIX = "mail.protection.outlook.com"


def m365_hosts_for(domain):
    d = str(domain or "").strip().lower().rstrip(".")
    if not d or "." not in d or not d.isascii() or d.startswith("[") or ".." in d:
        return []
    hosts = [d.replace(".", "-") + "." + M365_SUFFIX]
    if "-" in d:
        hosts.append(d.replace("-", "").replace(".", "-") + "." + M365_SUFFIX)
    return hosts


class BehindGatewayMixin:

    def behind_gateway_valid(self):
        with self.catchall_lock:
            return set(self.__dict__.get("_behind_gateway_valid", ()))

    def behind_gateway_domains(self):
        with self.catchall_lock:
            return set(self.__dict__.get("_behind_gateway_domains", ()))

    def _ask_behind_gateway(self, domain, email, result, gateway, original=None):
        if result.get("status") != "catchall" or self.aborted():
            return result
        host = next((h for h in m365_hosts_for(domain)
                     if self.mx_hosts_alive([h]) is True), None)
        if host is None:
            return result
        proxy = None
        if self.has_proxies_configured():
            proxy, _все_пойманы = self._pick_for_domain(domain, False, True, "", None)
            if proxy is None:
                return result
        fake = self._control_address(domain)
        try:
            ответы = self._probe_recipients([email, fake], host, proxy=proxy) or []
        except Exception:
            return result
        if len(ответы) < 2:
            return result
        настоящий, выдуманный = ответы[0] or {}, ответы[1] or {}
        if настоящий.get("status") == "valid" and выдуманный.get("status") == "invalid":
            with self.catchall_lock:
                self.__dict__.setdefault("_behind_gateway_valid", set()).add(
                    str(original or email).strip().lower())
                self.__dict__.setdefault("_behind_gateway_domains", set()).add(
                    str(domain).lower())
            return {"status": "valid",
                    "reason": ("250 Microsoft 365 за шлюзом %s принял адрес и отверг "
                               "выдуманный — ящик есть в каталоге организации"
                               % gateway),
                    "proxy": proxy, "mx_record": host, "mx_records": [host],
                    "behind_gateway": gateway, "control_rcpt": "rejected"}
        if настоящий.get("status") == "invalid" and выдуманный.get("status") == "invalid":
            # Не приговор (см. шапку): только пометка для владельца.
            result["reason"] = ("%s [Microsoft 365 за шлюзом этого ящика не знает — "
                                "это не приговор: ящик может жить на сервере "
                                "организации]" % result.get("reason", ""))
        return result
