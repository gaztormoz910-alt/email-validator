# core/whois_client.py
"""WHOIS своими руками — потому что чужой клиент не умеет прокси.

Библиотечный `whois` ходит на 43-й порт голым сокетом, и подменить транспорт
в нём нельзя. Пока прокси заданы, запрос WHOIS либо раскрыл бы настоящий IP
проверяющего, либо (как было раньше) просто пропускался — и возраст домена
брался только из RDAP, который отвечает не по всем зонам.

Здесь тот же протокол сказан вручную: сначала у IANA спрашивается, какой
сервер отвечает за зону, потом у него — сам домен. Оба запроса идут через
прокси, если он задан.
"""
import re
import socket

import socks

from core.proxy_transport import _parse_proxy, _proxy_scheme, PROXY_TYPES as _PROXY_TYPES

__all__ = ["whois_creation_date", "WHOIS_PORT", "WHOIS_IANA",
           "_whois_ask", "_WHOIS_REFER_RE", "_WHOIS_CREATED_RE"]

# Порт 43 — единственный канал, который оставался непроксируемым: библиотека
# whois ходит на него голым сокетом и прокси не умеет. Пока прокси заданы,
# WHOIS просто пропускался, и возраст домена брался только из RDAP. Здесь тот
# же протокол говорится вручную через SOCKS — утечки нет, данные есть.
WHOIS_PORT = 43
CRLF = chr(13) + chr(10)
WHOIS_IANA = "whois.iana.org"
_WHOIS_REFER_RE = re.compile(r'^\s*(?:refer|whois):\s*(\S+)\s*$', re.IGNORECASE | re.MULTILINE)
_WHOIS_CREATED_RE = re.compile(
    r'^\s*(?:Creation Date|Created On|created|registered on|Registration Time)\s*:\s*(\S+)',
    re.IGNORECASE | re.MULTILINE)


def _whois_ask(server, query, proxy=None, timeout=10):
    """Один запрос к WHOIS-серверу. Через прокси, если он задан."""
    sock = None
    try:
        if proxy:
            parsed = _parse_proxy(proxy)
            if not parsed:
                return ""
            pip, pport, puser, ppass = parsed
            sock = socks.socksocket()
            sock.set_proxy(_PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5),
                           pip, pport, username=puser, password=ppass)
        else:
            sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((server, WHOIS_PORT))
        sock.sendall((query + CRLF).encode("utf-8", "ignore"))
        chunks = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            chunks.append(data)
            if sum(len(c) for c in chunks) > 262144:   # ответ WHOIS столько не весит
                break
        return b"".join(chunks).decode("utf-8", "ignore")
    except Exception:
        return ""
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                pass


def whois_creation_date(domain, proxy=None, timeout=10):
    """Дата регистрации домена по WHOIS или пустая строка.

    Сначала спрашивает IANA, какой сервер отвечает за зону, потом сам сервер:
    у каждой зоны он свой, и общего адреса не существует.
    """
    if not isinstance(domain, str) or "." not in domain:
        return ""
    zone = domain.rsplit(".", 1)[-1].lower()

    referral = _WHOIS_REFER_RE.search(_whois_ask(WHOIS_IANA, zone, proxy, timeout))
    if not referral:
        return ""
    body = _whois_ask(referral.group(1), domain, proxy, timeout)
    found = _WHOIS_CREATED_RE.search(body or "")
    return found.group(1) if found else ""
