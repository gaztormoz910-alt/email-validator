import ipaddress
import re
import smtplib
import socket

import socks

from core.hostport import ipv6_literal, split_proxy_address, url_host

__all__ = ["PROXY_TYPES", "SocksSMTP", "build_proxy_dict", "exit_ip_from_banner",
           "proxy_socket", "_parse_proxy", "_proxy_scheme"]

PROXY_TYPES = {
    "socks5": socks.SOCKS5,
    "socks4": socks.SOCKS4,
    "http": socks.HTTP,
    "https": socks.HTTP,
}


def _proxy_scheme(proxy):
    if isinstance(proxy, str) and "://" in proxy:
        return proxy.split("://", 1)[0].strip().lower()
    return "socks5"


class SocksSMTP(smtplib.SMTP):
    def __init__(self, proxy_ip, proxy_port, proxy_user=None, proxy_pass=None,
                 host='', port=0, local_hostname=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT, proxy_type=None):
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.proxy_user = proxy_user
        self.proxy_pass = proxy_pass
        self.proxy_type = proxy_type if proxy_type is not None else socks.SOCKS5
        super().__init__(host, port, local_hostname, timeout)

    def _get_socket(self, host, port, timeout):
        return socks.create_connection(
            (host, port),
            timeout=timeout,
            proxy_type=self.proxy_type,
            proxy_addr=self.proxy_ip,
            proxy_port=self.proxy_port,
            proxy_username=self.proxy_user,
            proxy_password=self.proxy_pass
        )


def _parse_proxy(proxy):
    try:
        if not isinstance(proxy, str) or not proxy:
            return None

        proxy_clean = proxy.strip()
        for scheme in ("socks5://", "socks4://", "https://", "http://"):
            if proxy_clean.lower().startswith(scheme):
                proxy_clean = proxy_clean[len(scheme):]
                break

        if "@" in proxy_clean:
            creds, _, addr = proxy_clean.rpartition("@")
            split = split_proxy_address(addr)
            if not split or len(split[1]) != 1:
                return None
            user, sep, password = creds.partition(":")
            if not sep:
                return None
            return split[0], int(split[1][0]), user, password

        split = split_proxy_address(proxy_clean)
        if not split:
            return None
        host, rest = split
        if len(rest) == 3:
            return host, int(rest[0]), rest[1], rest[2]
        elif len(rest) == 1:
            return host, int(rest[0]), None, None
        return None
    except Exception:
        return None


def proxy_socket(proxy_host):
    family = socket.AF_INET6 if ipv6_literal(proxy_host) else socket.AF_INET
    return socks.socksocket(family, socket.SOCK_STREAM)


_EXIT_IP_RE = re.compile(r'\[((?:\d{1,3}\.){3}\d{1,3})\]')

_BRACKETED_RE = re.compile(r'\[(?:IPv6:)?([0-9A-Fa-f:.]{2,45})\]')


def exit_ip_from_banner(text):
    if not isinstance(text, str):
        return None
    for match in _BRACKETED_RE.finditer(text):
        try:
            address = ipaddress.ip_address(match.group(1))
        except ValueError:
            continue
        return address.compressed
    return None


EXIT_IP_PROBE_HOST = "gmail-smtp-in.l.google.com"

PROXY_PROBE_TARGETS = [
    ("Gmail", "gmail-smtp-in.l.google.com"),
    ("Outlook", "outlook-com.olc.protection.outlook.com"),
    ("Yahoo", "mta5.am0.yahoodns.net"),
    ("iCloud", "mx01.mail.icloud.com"),
]

PROBE_GMAIL, PROBE_OUTLOOK, PROBE_YAHOO, PROBE_ICLOUD = 0, 1, 2, 3


def build_proxy_dict(proxy):
    parsed = _parse_proxy(proxy)
    if not parsed:
        return None
    ip, port, user, password = parsed
    scheme = _proxy_scheme(proxy)
    kind = {"socks5": "socks5h", "socks4": "socks4a",
            "http": "http", "https": "http"}.get(scheme, "socks5h")
    auth = f"{user}:{password}@" if user and password else ""
    url = f"{kind}://{auth}{url_host(ip)}:{port}"
    return {"http": url, "https": url}


_PROXY_TYPES = PROXY_TYPES
