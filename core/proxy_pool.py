import random
import threading
import time

from core.proxy_probe import profile_proxies
from core.proxy_transport import build_proxy_dict
from core.mail_constants import PROXY_MAX_CONSECUTIVE_FAILS

UNKNOWN_LATENCY_MS = 10 ** 9

MX_ERROR_HALF_LIFE_SEC = 120.0

MX_ERROR_FLOOR = 0.5


class ProxyPoolMixin:

    def proxy_slot(self, proxy):
        if not proxy:
            return None
        with self._proxy_sem_lock:
            slot = self._proxy_semaphores.get(proxy)
            if slot is None:
                slot = threading.Semaphore(self._max_concurrent_per_proxy)
                self._proxy_semaphores[proxy] = slot
            return slot

    def set_proxy_concurrency(self, limit):
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            return self._max_concurrent_per_proxy
        self._max_concurrent_per_proxy = max(1, min(limit, 64))
        return self._max_concurrent_per_proxy

    def note_ip_use(self, proxy, count=1):
        exit_ip = (self._proxy_profiles.get(proxy) or {}).get("exit_ip")
        key = exit_ip or proxy
        try:
            count = int(count)
        except (TypeError, ValueError):
            count = 1
        with self._ip_load_lock:
            self._ip_load[key] = self._ip_load.get(key, 0) + count
            total = self._ip_load[key]
        memory = getattr(self, "memory", None)
        if memory is not None and key:
            try:
                remembered = memory.ip_load_add(key, count)
                if remembered > total:
                    with self._ip_load_lock:
                        self._ip_load[key] = remembered
                    total = remembered
            except Exception:
                pass
        return total

    def ip_load(self, proxy):
        exit_ip = (self._proxy_profiles.get(proxy) or {}).get("exit_ip")
        key = exit_ip or proxy
        with self._ip_load_lock:
            if key in self._ip_load:
                return self._ip_load[key]

        memory = getattr(self, "memory", None)
        if memory is None or not key:
            return 0
        try:
            used = int(memory.ip_load_today(key) or 0)
        except Exception:
            return 0
        with self._ip_load_lock:
            self._ip_load.setdefault(key, used)
            return self._ip_load[key]

    def overloaded_ips(self):
        with self._ip_load_lock:
            return {ip: n for ip, n in self._ip_load.items()
                    if n >= self._ip_load_soft_cap}

    def _get_mx_semaphore(self, mx_host: str, proxy=None) -> threading.Semaphore:
        exit_ip = ""
        if proxy:
            exit_ip = (self._proxy_profiles.get(proxy) or {}).get("exit_ip") or str(proxy)
        mx_key = f"{mx_host.lower()}|{exit_ip}"

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
        with self._mx_error_lock:
            self._mx_narrowed[pair] = limit

    def set_ptr_proxies(self, ptr_proxies):
        if isinstance(ptr_proxies, (str, bytes)) or not hasattr(ptr_proxies, "__iter__"):
            ptr_proxies = []
        with self._proxy_score_lock:
            self._ptr_proxies = set(ptr_proxies or [])
            self._profiled = bool(ptr_proxies)

    def set_proxy_profiles(self, profiles):
        profiles = profiles if isinstance(profiles, dict) else {}
        self._proxy_profiles = dict(profiles)
        self._remember_profiles(profiles)
        with self._proxy_score_lock:
            self._profiled = bool(profiles)
            self._ptr_proxies = {p for p, v in profiles.items() if v.get("has_ptr") is True}
            self._ptr_unknown = {p for p, v in profiles.items() if v.get("has_ptr") is None}

            self._proxy_latency = {
                p: v.get("latency_ms") for p, v in profiles.items()
                if isinstance(v.get("latency_ms"), (int, float))
            }

            self._dirty_proxies = {
                p for p, v in profiles.items()
                if v.get("in_dnsbl")
                or v.get("outlook_ok") is False
                or v.get("rdns_dirty")
            }

            self._yahoo_ok = {p for p, v in profiles.items() if v.get("yahoo_ok") is True}
            self._yahoo_bad = {p for p, v in profiles.items() if v.get("yahoo_ok") is False}
            self._icloud_bad = {p for p, v in profiles.items() if v.get("icloud_ok") is False}
            self._dirty_proxies |= self._icloud_bad

    def _remember_profiles(self, profiles):
        memory = getattr(self, "memory", None)
        if memory is None or not profiles:
            return
        try:
            memory.profiles_save(profiles)
        except Exception:
            pass

    def recall_proxy_profiles(self, proxies):
        memory = getattr(self, "memory", None)
        if memory is None:
            return {}
        try:
            return memory.profiles_load(proxies)
        except Exception:
            return {}

    def refresh_proxy_profiles(self, timeout=10, workers=30):
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
            if info.get("outlook_ok") is None and old.get("outlook_ok") is not None:
                info["outlook_ok"] = old["outlook_ok"]
                info["outlook_reason"] = old.get("outlook_reason")
            merged[proxy] = info

        self.set_proxy_profiles(merged)
        return {"checked": len(fresh), "ip_changed": ip_changed,
                "ptr_lost": ptr_lost, "ptr_gained": ptr_gained}

    def has_ptr_proxies(self):
        with self._proxy_score_lock:
            return bool((self._ptr_proxies | self._ptr_unknown) - self._proxy_banned)

    def has_clean_proxies(self):
        with self._proxy_score_lock:
            alive = {p for p in self.proxies if p not in self._proxy_banned}
            return bool(alive - self._dirty_proxies)

    def _dns_proxy(self, exclude=()):
        if not self._proxy_dns or not self.proxies:
            return None
        return self._pick_best_proxy(exclude=exclude) or ""

    def _proxy_country(self, proxy):
        return ((self._proxy_profiles.get(proxy) or {}).get("asn_country") or "").upper()

    def _choose_from(self, candidates, want_country=""):
        if not candidates or not hasattr(candidates, "__iter__"):
            return None
        want = (want_country or "").upper()

        def primary(proxy):
            return (-self._proxy_scores.get(proxy, 0),
                    0 if (want and self._proxy_country(proxy) == want) else 1)

        def secondary(proxy):
            return (self._proxy_latency.get(proxy) or UNKNOWN_LATENCY_MS,
                    self.ip_load(proxy))

        candidates = list(candidates)
        if not candidates:
            return None

        rested = [p for p in candidates if self.ip_load(p) < self._ip_load_soft_cap]
        if rested:
            candidates = rested

        best = min(primary(p) for p in candidates)
        equals = [p for p in candidates if primary(p) == best]

        equals.sort(key=secondary)

        top = equals[:max(5, len(equals) // 3)]

        weights = [1.0 / (rank + 1) for rank in range(len(top))]
        return random.choices(top, weights=weights, k=1)[0]

    def exit_ip_of(self, proxy):
        if not proxy:
            return ""
        return (self._proxy_profiles.get(proxy) or {}).get("exit_ip") or ""

    def take_recent_bans(self):
        with self._proxy_score_lock:
            bans, self._recent_bans = list(self._recent_bans), []
        return bans

    def proxy_still_usable(self, proxy, domain=None):
        if not proxy or not isinstance(proxy, str):
            return None
        with self._proxy_score_lock:
            if proxy in self._proxy_banned or proxy not in self.proxies:
                return None
        if domain and self._exit_key_of(proxy) in self.caught_exits_on(domain):
            return None
        return proxy


    ALL_EXITS_CAUGHT = {
        "status": "unknown",
        "reason": ("Все живые выходы уличены на этом домене: почтовик принимает "
                   "через них любой адрес — проверять бессмысленно; нужен чистый прокси"),
    }

    def _exit_key_of(self, proxy):
        if not proxy:
            return "прямое соединение"
        return str(self.exit_ip_of(proxy) or proxy).lower()

    def mark_exit_caught(self, exit_key, domain):
        with self.catchall_lock:
            self.__dict__.setdefault("_caught_pairs", set()).add(
                (str(exit_key or "прямое соединение").lower(), str(domain or "").lower()))

    def caught_exits_on(self, domain):
        domain = str(domain or "").strip().lower()
        with self.catchall_lock:
            пары = (set(getattr(self, "_tarpit_pairs", ()))
                    | set(self.__dict__.get("_caught_pairs", ())))
        return {выход for выход, домен in пары if домен == domain}

    def _pick_for_domain(self, domain, need_ptr=False, need_clean=False,
                         want_country="", avoid_exit_of=None):
        пойманы = self.caught_exits_on(domain)
        if not self.proxies and "прямое соединение" in пойманы:
            return None, True
        if not пойманы:
            return self._pick_best_proxy(need_ptr=need_ptr, need_clean=need_clean,
                                         want_country=want_country,
                                         avoid_exit_of=avoid_exit_of), False
        не_брать = {p for p in list(self.proxies) if self._exit_key_of(p) in пойманы}
        безымянные = {p for p in list(self.proxies) if not self.exit_ip_of(p)}
        выбор = dict(need_ptr=need_ptr, need_clean=need_clean,
                     want_country=want_country, avoid_exit_of=avoid_exit_of)
        proxy = (self._pick_best_proxy(exclude=не_брать | безымянные, **выбор)
                 or self._pick_best_proxy(exclude=не_брать, **выбор))
        if proxy is not None or not не_брать:
            return proxy, False
        return None, self._pick_best_proxy(**выбор) is not None

    def _pick_best_proxy(self, need_ptr=False, need_clean=False, want_country="",
                         avoid_exit_of=None, exclude=None):
        if not self.proxies:
            return None
        with self._proxy_score_lock:
            alive = [p for p in self.proxies if p not in self._proxy_banned]
            if exclude:
                alive = [p for p in alive if p not in exclude]

            if avoid_exit_of:
                banned_ip = self.exit_ip_of(avoid_exit_of)
                if banned_ip:
                    alive = [p for p in alive if self.exit_ip_of(p) != banned_ip]
                else:
                    alive = [p for p in alive if p != avoid_exit_of]

            if not alive:
                return None

            if not self._profiled:
                return self._choose_from(alive, want_country)

            with_ptr = [p for p in alive if p in self._ptr_proxies]
            without_ptr = [p for p in alive if p not in self._ptr_proxies]

            if need_ptr:
                pool = with_ptr or [p for p in alive if p in self._ptr_unknown]
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

            pool = without_ptr or with_ptr
            if need_clean:
                pool = [p for p in pool if p not in self._dirty_proxies] or pool
            return self._choose_from(pool, want_country)

    def has_proxies_configured(self):
        return bool(self.proxies)

    def get_live_proxy_count(self):
        with self._proxy_score_lock:
            return len([p for p in self.proxies if p not in self._proxy_banned])

    def all_proxies_dead(self):
        return bool(self.proxies) and self.get_live_proxy_count() == 0

    def _mx_delay(self, mx_host):
        base = random.uniform(0.1, 0.4)
        if not isinstance(mx_host, str) or not mx_host:
            return base
        errors = self._decayed_mx_errors(mx_host)
        if not errors:
            return base
        return min(base * (2 ** min(errors, 5)), 8.0)

    def _update_proxy_score(self, proxy, success: bool, mx_record=None):
        if not proxy:
            return
        aborted = getattr(self, "aborted", None)
        if not success and callable(aborted) and aborted():
            return
        with self._proxy_score_lock:
            if proxy not in self._proxy_scores:
                self._proxy_scores[proxy] = 0
                self._proxy_consecutive_fails[proxy] = 0
            if success:
                self._proxy_scores[proxy] += 1
                self._proxy_consecutive_fails[proxy] = 0
                self._proxy_fail_hosts.pop(proxy, None)
                return

            self._proxy_scores[proxy] -= 3
            self._proxy_consecutive_fails[proxy] = self._proxy_consecutive_fails.get(proxy, 0) + 1

            hosts = self._proxy_fail_hosts.setdefault(proxy, set())
            if isinstance(mx_record, str) and mx_record:
                hosts.add(mx_record.lower())

            if self._proxy_consecutive_fails[proxy] < PROXY_MAX_CONSECUTIVE_FAILS:
                return

            if not hosts or len(hosts) >= 2:
                if proxy not in self._proxy_banned:
                    self._proxy_banned.add(proxy)
                    self._recent_bans.append(proxy)

    def _note_latency(self, proxy, millis):
        if not proxy or not isinstance(millis, (int, float)) or millis < 0:
            return
        with self._proxy_score_lock:
            previous = self._proxy_latency.get(proxy)
            if isinstance(previous, (int, float)):
                self._proxy_latency[proxy] = int(previous * 0.7 + millis * 0.3)
            else:
                self._proxy_latency[proxy] = int(millis)
