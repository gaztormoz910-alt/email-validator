import concurrent.futures
import inspect
import ipaddress
import queue
import socket
import threading
import time
from collections import OrderedDict

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename
import socks

from core.proxy_transport import (PROXY_TYPES as _PROXY_TYPES, _parse_proxy,
                                  _proxy_scheme, build_proxy_dict, proxy_socket)

__all__ = ["ProxiedResolver", "DNSUnavailable", "DOH_ENDPOINTS"]

DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
)

UNKNOWN_LATENCY_MS = 10000

DNS_SILENCE_COOLDOWN_SEC = 120.0

SESSIONS_PER_THREAD = 32

LANE_THREADS = 256

_BOTH_TRANSPORTS = frozenset({"doh", "tcp"})


def _chain(exc):
    seen = set()
    stack = [exc]
    while stack:
        error = stack.pop()
        if not isinstance(error, BaseException) or id(error) in seen:
            continue
        seen.add(id(error))
        yield error
        stack.extend((error.__cause__, error.__context__,
                      getattr(error, "reason", None), getattr(error, "socket_err", None),
                      getattr(error, "original_error", None)))
        stack.extend(getattr(error, "args", ()))


def _http_modules():
    import requests
    import urllib3
    return requests, urllib3


def _waited_in_vain(exc):
    requests, urllib3 = _http_modules()
    silence = (TimeoutError, dns.exception.Timeout, socks.ProxyConnectionError,
               requests.exceptions.Timeout, urllib3.exceptions.ReadTimeoutError)
    errors = list(_chain(exc))
    if any(isinstance(error, silence) for error in errors):
        return True
    proxy_error = any(isinstance(error, (requests.exceptions.ProxyError,
                                         urllib3.exceptions.ProxyError)) for error in errors)
    unreachable = any(isinstance(error, urllib3.exceptions.NewConnectionError) for error in errors)
    return proxy_error and unreachable


def _give_up_on(silent, failed_kinds):
    return silent or failed_kinds >= _BOTH_TRANSPORTS


def _accepts_exclude(provider):
    if provider is None:
        return False
    try:
        params = inspect.signature(provider).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == "exclude" or p.kind is p.VAR_KEYWORD for p in params)


class _Lanes:

    def __init__(self, limit):
        self._limit = limit
        self._queue = queue.SimpleQueue()
        self._lock = threading.Lock()
        self._threads = 0
        self._idle = 0
        self._pending = 0

    def submit(self, fn, *args):
        future = concurrent.futures.Future()
        with self._lock:
            self._pending += 1
            spawn = self._pending > self._idle and self._threads < self._limit
            if spawn:
                self._threads += 1
        if spawn:
            try:
                threading.Thread(target=self._work, name="dns-lane", daemon=True).start()
            except Exception as exc:
                with self._lock:
                    self._threads -= 1
                    self._pending -= 1
                future.set_exception(exc)
                return future
        self._queue.put((future, fn, args))
        return future

    def _work(self):
        while True:
            with self._lock:
                self._idle += 1
            future, fn, args = self._queue.get()
            with self._lock:
                self._idle -= 1
                self._pending -= 1
            try:
                if future.set_running_or_notify_cancel():
                    try:
                        future.set_result(fn(*args))
                    except BaseException as exc:
                        future.set_exception(exc)
            finally:
                future = fn = args = None


_LANES = _Lanes(LANE_THREADS)


class _Race:

    def __init__(self):
        self.cond = threading.Condition()
        self.response = None
        self.proxy = None
        self.verified = True
        self.closed = False

    @property
    def answered(self):
        return self.response is not None

    def offer(self, response, proxy, verified=True):
        with self.cond:
            if self.response is None and not self.closed:
                self.response = response
                self.proxy = proxy
                self.verified = verified
            self.cond.notify_all()

    def close(self):
        with self.cond:
            self.closed = True
            self.cond.notify_all()

    def poke(self, _future=None):
        with self.cond:
            self.cond.notify_all()


def _is_local_address(host):
    try:
        address = ipaddress.ip_address(str(host).strip("[]"))
    except ValueError:
        return False
    return (address.is_private or address.is_loopback or address.is_link_local
            or address.is_unspecified or address.is_multicast)


def _has_data(response, rdtype):
    return (response.rcode() == dns.rcode.NOERROR
            and any(rrset.rdtype == rdtype for rrset in response.answer))


def _second_lane_accepts(response, rdtype, kind):
    if _has_data(response, rdtype):
        return True
    return kind == "doh" and response.rcode() in (dns.rcode.NXDOMAIN, dns.rcode.NOERROR)


def _negative_kind(response, rdtype):
    if response.rcode() == dns.rcode.NXDOMAIN:
        return "nx"
    if response.rcode() == dns.rcode.NOERROR and not _has_data(response, rdtype):
        return "nodata"
    return None


class DNSUnavailable(dns.exception.DNSException):
    pass


class UnverifiedNXDOMAIN(dns.resolver.NXDOMAIN):
    pass


class UnverifiedNoAnswer(dns.resolver.NoAnswer):
    pass


class ProxiedResolver:

    def __init__(self, nameservers, timeout, proxy_provider=None, public_doh=True):
        self._plain = dns.resolver.Resolver()
        self._plain.nameservers = list(nameservers)
        self._plain.timeout = timeout
        self._plain.lifetime = timeout
        self.nameservers = self._plain.nameservers
        self.timeout = timeout
        self.lifetime = timeout
        self._proxy_provider = proxy_provider
        self._provider_excludes = _accepts_exclude(proxy_provider)
        self._public_doh = bool(public_doh)
        if proxy_provider is not None:
            _http_modules()
        self._local = threading.local()
        self._silent = {}
        self._silent_lock = threading.Lock()

    def resolve(self, qname, rdtype='A'):
        proxy = self._proxy_provider() if self._proxy_provider else None
        if proxy is None:
            return self._plain.resolve(qname, rdtype)
        if not proxy:
            raise DNSUnavailable("прокси заданы, но живых не осталось")

        rd = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else rdtype
        query = dns.message.make_query(qname, rd)
        attempts = self._attempts()
        deadline = time.monotonic() + len(attempts) * self.timeout
        race = _Race()
        second = None

        def open_second(start):
            nonlocal second
            if second is None and self._provider_excludes:
                second = _LANES.submit(self._second_lane, query, rd, attempts, proxy,
                                       start, deadline, race)
                second.add_done_callback(race.poke)

        try:
            if self._provider_excludes and proxy in self._recently_silent():
                open_second(0)

            failed = set()
            for index, (kind, ask, target) in enumerate(attempts):
                if race.answered:
                    break
                response, silent = self._attempt(ask, target, query, proxy)
                if response is not None:
                    self._forget_silence(proxy)
                    return self._extract(response, rd, verified=(kind == "doh"))
                if silent:
                    self._remember_silence(proxy)
                else:
                    failed.add(kind)
                if _give_up_on(silent, failed):
                    open_second(index + 1)

            if second is not None and not race.answered:
                limit = min(deadline, time.monotonic() + 2 * self.timeout)
                with race.cond:
                    race.cond.wait_for(lambda: race.answered or second.done(),
                                       timeout=max(0.0, limit - time.monotonic()))
            with race.cond:
                found, verified = race.response, race.verified
            if found is not None:
                return self._extract(found, rd, verified=verified)
            raise DNSUnavailable("ни DoH, ни DNS-over-TCP через прокси не ответили")
        finally:
            race.close()

    def _second_lane(self, query, rd, attempts, first_proxy, start, deadline, race):
        tcp = [(kind, ask, target) for kind, ask, target in attempts if kind == "tcp"]
        doh = [(kind, ask, target) for kind, ask, target in attempts if kind == "doh"]
        tried = {first_proxy}
        proxy = self._other_proxy(tried)
        turn = start
        budget = 2 * len(attempts)
        heard_no = None
        while proxy and budget > 0:
            tried.add(proxy)
            plan = [pick[turn % len(pick)] for pick in (tcp, doh) if pick]
            turn += 1
            for kind, ask, target in plan:
                if race.closed or race.answered or time.monotonic() >= deadline or budget <= 0:
                    return
                budget -= 1
                response, silent = self._attempt(ask, target, query, proxy)
                if response is not None and _second_lane_accepts(response, rd, kind):
                    self._forget_silence(proxy)
                    race.offer(response, proxy, verified=(kind == "doh"))
                    return
                no = _negative_kind(response, rd) if response is not None else None
                if no is not None:
                    if heard_no is not None and heard_no[0] == no and heard_no[1] != proxy:
                        self._forget_silence(proxy)
                        race.offer(response, proxy, verified=False)
                        return
                    if heard_no is None:
                        heard_no = (no, proxy)
                    break
                if silent:
                    self._remember_silence(proxy)
                    break
            if race.closed or race.answered:
                return
            proxy = self._other_proxy(tried)

    def resolve_verified(self, qname, rdtype='A', proxies=8):
        if not self._public_doh or self._proxy_provider is None:
            raise DNSUnavailable("DoH без прокси не спрашивается")
        rd = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else rdtype
        query = dns.message.make_query(qname, rd)
        with self._silent_lock:
            очередь = list(self.__dict__.get("_doh_answered", ()))
        опрошены = set()
        for _ in range(max(1, int(proxies))):
            proxy = None
            while очередь and proxy is None:
                кандидат = очередь.pop(0)
                if кандидат not in опрошены:
                    proxy = кандидат
            if proxy is None:
                proxy = (self._other_proxy(опрошены) if self._provider_excludes
                         else (self._proxy_provider() if not опрошены else None))
            if not proxy or proxy in опрошены:
                break
            опрошены.add(proxy)
            for url in DOH_ENDPOINTS:
                response, silent = self._attempt(self._ask_doh, url, query, proxy)
                if response is not None:
                    with self._silent_lock:
                        ответившие = self.__dict__.setdefault("_doh_answered", [])
                        if proxy in ответившие:
                            ответившие.remove(proxy)
                        ответившие.insert(0, proxy)
                    return self._extract(response, rd, verified=True)
                if silent:
                    break
        raise DNSUnavailable("DoH не ответил ни через один из %d прокси" % len(опрошены))

    def _attempts(self):
        doh = [("doh", self._ask_doh, url) for url in DOH_ENDPOINTS] if self._public_doh else []
        return doh + [("tcp", self._ask_tcp, nameserver) for nameserver in self.nameservers]

    def _attempt(self, ask, target, query, proxy):
        try:
            return ask(target, query, proxy), False
        except Exception as exc:
            return None, _waited_in_vain(exc)

    def _other_proxy(self, tried):
        if not self._provider_excludes:
            return None
        avoid = frozenset(tried)
        wider = avoid | self._recently_silent()
        for exclude in ((wider, avoid) if wider != avoid else (avoid,)):
            try:
                other = self._proxy_provider(exclude=exclude)
            except Exception:
                return None
            if other and other not in avoid:
                return other
        return None

    def _recently_silent(self):
        now = time.monotonic()
        with self._silent_lock:
            for proxy in [p for p, until in self._silent.items() if until <= now]:
                del self._silent[proxy]
            return frozenset(self._silent)

    def _remember_silence(self, proxy):
        with self._silent_lock:
            self._silent[proxy] = time.monotonic() + DNS_SILENCE_COOLDOWN_SEC

    def _forget_silence(self, proxy):
        with self._silent_lock:
            self._silent.pop(proxy, None)

    def _session(self, proxy):
        store = getattr(self._local, "sessions", None)
        if store is None:
            store = OrderedDict()
            self._local.sessions = store
        session = store.get(proxy)
        if session is not None:
            store.move_to_end(proxy)
            return session
        import requests
        session = requests.Session()
        session.trust_env = False
        session.headers.update({
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "User-Agent": "Mozilla/5.0",
        })
        session.proxies.update(build_proxy_dict(proxy) or {})
        store[proxy] = session
        while len(store) > SESSIONS_PER_THREAD:
            _, old = store.popitem(last=False)
            try:
                old.close()
            except Exception:
                pass
        return session

    def _ask_doh(self, url, query, proxy):
        if not build_proxy_dict(proxy):
            return None
        resp = self._session(proxy).post(url, data=query.to_wire(), timeout=self.timeout)
        if resp.status_code == 200 and resp.content:
            return dns.message.from_wire(resp.content)
        return None

    def _ask_tcp(self, nameserver, query, proxy):
        if _is_local_address(nameserver):
            return None
        parsed = _parse_proxy(proxy)
        if not parsed:
            return None
        pip, pport, puser, ppass = parsed
        ptype = _PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5)
        sock = proxy_socket(pip)
        try:
            sock.set_proxy(ptype, pip, pport, username=puser, password=ppass)
            sock.settimeout(self.timeout)
            sock.connect((nameserver, 53))
            return dns.query.tcp(query, nameserver, timeout=self.timeout, sock=sock)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    @staticmethod
    def _extract(response, rdtype, verified=True):
        rcode = response.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN if verified else UnverifiedNXDOMAIN
        if rcode != dns.rcode.NOERROR:
            raise DNSUnavailable(f"DNS rcode {dns.rcode.to_text(rcode)}")
        items = []
        for rrset in response.answer:
            if rrset.rdtype == rdtype:
                items.extend(rrset)
        if not items:
            raise dns.resolver.NoAnswer if verified else UnverifiedNoAnswer
        return items


_COUNTRY_TO_CODE = {
    "Германия": "DE", "Франция": "FR", "Италия": "IT", "Испания": "ES",
    "Великобритания": "GB", "Нидерланды": "NL", "Бельгия": "BE",
    "Польша": "PL", "Россия": "RU", "Украина": "UA", "Беларусь": "BY",
    "Казахстан": "KZ", "Швеция": "SE", "Норвегия": "NO", "Дания": "DK",
    "Финляндия": "FI", "США": "US", "Канада": "CA", "Австралия": "AU",
    "Новая Зеландия": "NZ", "Китай": "CN", "Южная Корея": "KR",
    "Япония": "JP", "Индия": "IN", "Бразилия": "BR", "Мексика": "MX",
    "Аргентина": "AR", "Чехия": "CZ", "Словакия": "SK", "Венгрия": "HU",
    "Румыния": "RO", "Болгария": "BG", "Австрия": "AT", "Швейцария": "CH",
    "Португалия": "PT", "Греция": "GR", "Турция": "TR", "Израиль": "IL",
    "Ирландия": "IE", "Эстония": "EE", "Латвия": "LV", "Литва": "LT",
    "ЮАР": "ZA", "ОАЭ": "AE", "Саудовская Аравия": "SA", "Египет": "EG",
    "Марокко": "MA", "Нигерия": "NG", "Кения": "KE", "Вьетнам": "VN",
    "Таиланд": "TH", "Индонезия": "ID", "Малайзия": "MY", "Сингапур": "SG",
    "Филиппины": "PH", "Пакистан": "PK",
}


