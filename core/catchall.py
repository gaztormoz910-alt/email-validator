# -*- coding: utf-8 -*-
from core.mail_constants import AOL_DOMAINS, MICROSOFT_DOMAINS, YAHOO_DOMAINS

__all__ = ["CatchAllMixin"]


class CatchAllMixin:

    def is_catch_all_domain(self, domain, mx_record) -> bool:
        with self.catchall_lock:
            if domain in self.catchall_cache:
                return self.catchall_cache[domain]
            if domain in self._remembered_not_catchall():
                return False

        if self.memory is not None:
            remembered = self.memory.catchall_get(domain)
            if remembered is not None:
                with self.catchall_lock:
                    if remembered:
                        self.catchall_cache[domain] = remembered
                    else:
                        self._remembered_not_catchall()[domain] = True
                return remembered

        from core.network import _generate_random_local
        fakes = [
            f"{_generate_random_local('short')}@{domain}",
            f"{_generate_random_local('short')}@{domain}",
            f"{_generate_random_local('uuid')}@{domain}",
        ]
        probe_proxy = self._probe_proxy_for(domain)
        results = self._probe_recipients(fakes, mx_record, proxy=probe_proxy)

        if any((r or {}).get("status") == "valid" for r in results):
            if self._fake_rejected_elsewhere(domain, probe_proxy, mx_record):
                # Принял только выход пробы, другой выход выдуманный отверг:
                self._note_exit_lies(domain, probe_proxy)
                with self.catchall_lock:
                    self.catchall_cache[domain] = False
                self._remember_catchall(domain, False)
                return False
            with self.catchall_lock:
                self.catchall_cache[domain] = True
            self._remember_catchall(domain, True, proxy=probe_proxy)
            self._note_mx_catchall(mx_record, domain)
            return True

        from core.confirmation import rejects_fake
        for result in results:
            if (result["status"] not in ("unknown", "greylisted", "valid")
                    and not rejects_fake(result)):
                result = dict(result, status="unknown")
            if result["status"] in ("unknown", "greylisted"):
                if self._mx_catchall_suspected(mx_record, domain):
                    return True
                return False
            if result["status"] != "valid":
                self._note_fake_rejected(domain, probe_proxy)
                with self.catchall_lock:
                    self.catchall_cache[domain] = False
                self._remember_catchall(domain, False)
                return False

        with self.catchall_lock:
            self.catchall_cache[domain] = True
        self._remember_catchall(domain, True, proxy=probe_proxy)
        self._note_mx_catchall(mx_record, domain)
        return True
    def _remembered_not_catchall(self):
        store = getattr(self, "_catchall_remembered_false", None)
        if store is None:
            from core.bounded import BoundedCache
            store = self._catchall_remembered_false = BoundedCache()
        return store

    def _note_mx_catchall(self, mx_record, domain):
        host = (mx_record or "").strip().lower().rstrip(".")
        if not host or not domain:
            return
        with self.catchall_lock:
            seen = self._mx_catchall.get(host)
            if seen is None:
                seen = set()
                self._mx_catchall[host] = seen
            seen.add(domain.strip().lower())
    def _mx_catchall_suspected(self, mx_record, domain):
        host = (mx_record or "").strip().lower().rstrip(".")
        if not host:
            return False
        with self.catchall_lock:
            seen = self._mx_catchall.get(host) or set()
            others = {d for d in seen if d != (domain or "").strip().lower()}
        return len(others) >= 2
    NEVER_CATCHALL = frozenset({
        "gmail.com", "googlemail.com", "yandex.ru", "ya.ru",
        "icloud.com", "me.com", "mac.com",
    })
    def _is_never_catchall(self, domain):
        """Гигант, у которого catch-all не бывает: приём выдуманного адреса
        у него означает тарпитинг, а не настройку домена."""
        low = str(domain or "").lower()
        return (low in self.NEVER_CATCHALL or low in YAHOO_DOMAINS
                or low in MICROSOFT_DOMAINS or low in AOL_DOMAINS)
    def _exit_trustworthy(self, proxy):
        if not proxy:
            return True
        try:
            with self._proxy_score_lock:
                if not getattr(self, "_profiled", False):
                    return False
                return (proxy in self._ptr_proxies
                        and proxy not in self._dirty_proxies)
        except Exception:
            return False
    def _remember_catchall(self, domain, is_catchall, proxy=None):
        if self.memory is None:
            return
        if is_catchall and self._is_never_catchall(domain):
            return
        if is_catchall and not self._exit_trustworthy(proxy):
            return
        try:
            self.memory.catchall_put(domain, is_catchall)
        except Exception:
            pass
    TARPIT_RECHECK_EVERY = 25
    def _time_to_recheck(self, domain):
        if not domain:
            return False
        with self._domain_checks_lock:
            seen = self._domain_checks.get(domain, 0)
            self._domain_checks[domain] = seen + 1
        return seen == 0 or seen % self.TARPIT_RECHECK_EVERY == 0
    def proven_catchall_domains(self):
        with self.catchall_lock:
            return sorted(d for d, yes in self.catchall_cache.items() if yes)
    def tarpit_domains(self):
        with self.catchall_lock:
            return sorted(self._tarpit_domains)

    def tarpit_pairs(self):
        with self.catchall_lock:
            return set(getattr(self, "_tarpit_pairs", set()))
