import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import socks

import random
import threading

from core.proxy_transport import (PROXY_TYPES as _PROXY_TYPES, SocksSMTP,
                                  build_proxy_dict, _parse_proxy,
                                  _proxy_scheme, exit_ip_from_banner,
                                  EXIT_IP_PROBE_HOST, PROXY_PROBE_TARGETS,
                                  PROBE_GMAIL, PROBE_OUTLOOK, PROBE_YAHOO,
                                  PROBE_ICLOUD)
from core.mail_constants import LEGIT_HELO_NAMES, MAIL_FROM_POOL
from core.hostport import sender_key

__all__ = ["probe_proxy_target", "get_proxy_exit_ip", "dedupe_proxies",
           "dedupe_proxies_stream", "is_dirty_rdns", "profile_proxies",
           "filter_live_proxies", "DIRTY_RDNS_KEYWORDS"]


DIRTY_RDNS_KEYWORDS = ("proxy", "vpn", "tor", "torexit", "exit", "anon",
                       "spam", "abuse", "dynamic", "dyn", "dhcp", "pool",
                       "dial", "dialup", "pppoe", "cable", "dsl")

_DIRTY_RDNS_RE = re.compile(
    r'(?:^|[.\-])(' + "|".join(DIRTY_RDNS_KEYWORDS) + r')(?:[.\-0-9]|$)')


def probe_proxy_target(proxy, host, timeout=10, want_exit_ip=False):
    server = None
    started = time.monotonic()
    try:
        parsed = _parse_proxy(proxy)
        if not parsed:
            return (False, None, None, "неверный формат прокси")
        ip, port, user, password = parsed
        server = SocksSMTP(ip, port, proxy_user=user, proxy_pass=password,
                           timeout=timeout,
                           proxy_type=_PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5))
        server.connect(host, 25)
        latency = int((time.monotonic() - started) * 1000)

        _code, msg = server.ehlo(random.choice(LEGIT_HELO_NAMES))
        text = msg.decode('utf-8', 'ignore') if isinstance(msg, bytes) else str(msg)
        exit_ip = exit_ip_from_banner(text) if want_exit_ip else None

        mail_code, mail_msg = server.mail(random.choice(MAIL_FROM_POOL))
        if mail_code >= 400:
            reason = mail_msg.decode('utf-8', 'ignore') if isinstance(mail_msg, bytes) else str(mail_msg)
            return (False, latency, exit_ip, f"{mail_code} {reason[:60]}")
        return (True, latency, exit_ip, "ok")
    except Exception as e:
        return (False, None, None, type(e).__name__)
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass


def get_proxy_exit_ip(proxy, timeout=10):
    _ok, _lat, exit_ip, _reason = probe_proxy_target(
        proxy, EXIT_IP_PROBE_HOST, timeout=timeout, want_exit_ip=True)
    return exit_ip


def dedupe_proxies(proxies):
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return []
    seen = set()
    result = []
    for p in proxies:
        if not isinstance(p, str):
            continue
        norm = p.strip()
        if not norm:
            continue
        parsed = _parse_proxy(norm)
        key = (_proxy_scheme(norm), parsed) if parsed else norm.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(norm)
    return result


def dedupe_proxies_stream(proxies, max_keys=2_000_000):
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return
    seen = set()
    capped = False
    for raw in proxies:
        if not isinstance(raw, str):
            continue
        norm = raw.strip()
        if not norm:
            continue
        parsed = _parse_proxy(norm)
        key = hash((_proxy_scheme(norm), parsed) if parsed else norm.lower())
        if not capped:
            if key in seen:
                continue
            seen.add(key)
            if len(seen) >= max_keys:
                capped = True
        yield norm


def is_dirty_rdns(hostname):
    if not isinstance(hostname, str) or not hostname:
        return False
    return bool(_DIRTY_RDNS_RE.search(hostname.lower()))


def profile_proxies(proxies, timeout=10, workers=30, progress_callback=None,
                    probe_outlook=True, should_stop=None):
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return {}
    proxies = list(proxies)

    from core.network import NetworkValidator

    validator = NetworkValidator(timeout=timeout, proxy_dns=False)
    result = {}
    done = 0
    lock = threading.Lock()

    def profile_one(proxy):
        empty = {"exit_ip": None, "exit_addr": None, "latency_ms": None, "has_ptr": None,
                 "rdns": None, "rdns_dirty": False, "in_dnsbl": False,
                 "outlook_ok": None, "outlook_reason": None,
                 "asn": None, "asn_country": "", "asn_org": "",
                 "ip_type": "unknown", "yahoo_ok": None, "icloud_ok": None}

        if should_stop is not None and should_stop():
            return proxy, None
        ok, latency, exit_ip, reason = probe_proxy_target(
            proxy, EXIT_IP_PROBE_HOST, timeout=timeout, want_exit_ip=True)
        if not exit_ip:
            empty["latency_ms"] = latency
            empty["outlook_reason"] = reason if not ok else None
            return proxy, empty

        has_ptr = validator.check_fcrdns(exit_ip)
        if has_ptr is None:
            with validator._fcrdns_lock:
                validator._fcrdns_cache.pop(exit_ip, None)
            time.sleep(0.3)
            has_ptr = validator.check_fcrdns(exit_ip)

        rdns = validator.get_ptr_hostname(exit_ip)
        in_dnsbl = validator.check_dnsbl_ip(exit_ip)

        from core.proxy_profile import lookup_ip_meta
        meta = lookup_ip_meta(exit_ip, timeout=timeout,
                              proxies=build_proxy_dict(proxy))

        outlook_ok = None
        outlook_reason = None
        yahoo_ok = None
        icloud_ok = None
        if probe_outlook:
            o_ok, _lat, _ip, o_reason = probe_proxy_target(
                proxy, PROXY_PROBE_TARGETS[PROBE_OUTLOOK][1], timeout=timeout)
            outlook_ok, outlook_reason = o_ok, o_reason

            y_ok, _yl, _yi, _yr = probe_proxy_target(
                proxy, PROXY_PROBE_TARGETS[PROBE_YAHOO][1], timeout=timeout)
            yahoo_ok = y_ok
            i_ok, _il, _ii, _ir = probe_proxy_target(
                proxy, PROXY_PROBE_TARGETS[PROBE_ICLOUD][1], timeout=timeout)
            icloud_ok = i_ok

        return proxy, {"exit_ip": sender_key(exit_ip), "exit_addr": exit_ip,
                       "latency_ms": latency,
                       "has_ptr": has_ptr, "rdns": rdns,
                       "rdns_dirty": is_dirty_rdns(rdns), "in_dnsbl": in_dnsbl,
                       "outlook_ok": outlook_ok, "outlook_reason": outlook_reason,
                       "asn": meta.get("asn"),
                       "asn_country": meta.get("asn_country", ""),
                       "asn_org": meta.get("asn_org", ""),
                       "ip_type": meta.get("ip_type", "unknown"),
                       "yahoo_ok": yahoo_ok, "icloud_ok": icloud_ok}

    try:
        workers = int(workers)
    except (TypeError, ValueError):
        workers = 30
    workers = max(1, min(workers, 300))

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(proxies)))) as pool:
        for proxy, info in pool.map(profile_one, proxies):
            if info is None:
                continue
            result[proxy] = info
            with lock:
                done += 1
                if progress_callback and (done % 50 == 0 or done == len(proxies)):
                    ptr_n = sum(1 for v in result.values() if v["has_ptr"] is True)
                    bl_n = sum(1 for v in result.values() if v["in_dnsbl"])
                    progress_callback(done, len(proxies), ptr_n, bl_n)

    return result


def filter_live_proxies(proxies, timeout, threads=100, progress_callback=None,
                        log_callback=None, enough=0, should_stop=None):
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return [], 0
    from core.async_proxy import run_async_checker

    live_now = {"n": 0}

    def on_prog(c, t, l):
        live_now["n"] = l
        if progress_callback:
            progress_callback(c, t)
        if log_callback:
            if c % 100 == 0 or c == t:
                log_callback(
                    f"[PROXY] Проверено: {c} | Прочитано: {t} | Рабочих: {l}",
                    "info")

    seen = {"total": 0}

    stopped = {"early": False}

    def counted(source):
        for item in source:
            if should_stop is not None and should_stop():
                return
            if enough and live_now["n"] >= enough:
                stopped["early"] = True
                if log_callback:
                    log_callback(
                        "[PROXY] Набрано живых прокси: %d — остальные %s"
                        % (live_now["n"], "не проверяю, как и просили"), "info")
                return
            seen["total"] += 1
            yield item

    live_proxies = run_async_checker(
        proxies=counted(proxies),
        workers=threads,
        timeout=timeout,
        mode="smtp",
        progress_callback=on_prog,
        should_stop=should_stop,
    )

    return live_proxies, seen["total"]
