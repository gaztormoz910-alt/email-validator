# -*- coding: utf-8 -*-
import ipaddress
import socket
from typing import List, Optional, Tuple

__all__ = ["ipv6_literal", "split_proxy_address", "bare_ipv6_ambiguous",
           "sender_key", "has_ipv6_route", "url_host"]


def ipv6_literal(host: object) -> Optional[str]:
    if not isinstance(host, str):
        return None
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    if ":" not in text or "%" in text:
        return None
    try:
        return ipaddress.IPv6Address(text).compressed
    except ValueError:
        return None


def split_proxy_address(text: str) -> Optional[Tuple[str, List[str]]]:
    if not isinstance(text, str):
        return None
    text = text.strip()
    if not text:
        return None
    if text.startswith("["):
        end = text.find("]")
        if end < 0:
            return None
        host = ipv6_literal(text[1:end])
        rest = text[end + 1:]
        if host is None or not rest.startswith(":"):
            return None
        return host, rest[1:].split(":")
    parts = text.split(":")
    if len(parts) <= 4 and "::" not in text:
        return parts[0], parts[1:]
    head, _, port = text.rpartition(":")
    host = ipv6_literal(head)
    if host is not None and ipv6_literal(text) is None:
        return host, [port]
    return None


def bare_ipv6_ambiguous(text: object) -> bool:
    if not isinstance(text, str):
        return False
    value = text.strip()
    for scheme in ("socks5://", "socks4://", "socks://", "https://", "http://"):
        if value.lower().startswith(scheme):
            value = value[len(scheme):]
            break
    if "@" in value:
        value = value.rpartition("@")[2]
    if value.startswith("["):
        return False
    head = value.rpartition(":")[0]
    return ipv6_literal(head) is not None and split_proxy_address(value) is None


def sender_key(ip: object) -> str:
    if not isinstance(ip, str) or not ip:
        return ""
    v6 = ipv6_literal(ip)
    if v6 is None:
        return ip
    return str(ipaddress.IPv6Network(v6 + "/64", strict=False))


def url_host(host: str) -> str:
    v6 = ipv6_literal(host)
    return "[%s]" % v6 if v6 is not None else host


_ROUTE_PROBE = ("2001:4860:4860::8888", 53)


def has_ipv6_route() -> bool:
    if not socket.has_ipv6:
        return False
    probe = None
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        probe.connect(_ROUTE_PROBE)
        return True
    except OSError:
        return False
    finally:
        if probe is not None:
            probe.close()
