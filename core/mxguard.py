# -*- coding: utf-8 -*-
import ipaddress
import re
import socket

__all__ = ["is_ip_literal", "resolves_to_private", "filter_mx_hosts",
           "REASON_PRIVATE", "REASON_IP_LITERAL"]

REASON_IP_LITERAL = ("MX-запись указывает прямо на IP-адрес вместо имени "
                     "хоста — это нарушение RFC 2181 §10.3, и подключение по "
                     "ней уходит неизвестно куда")
REASON_PRIVATE = ("MX-хост ведёт на внутренний адрес (localhost, приватная "
                  "сеть или зарезервированный диапазон). Снаружи такая почта "
                  "недоступна, а подключаться туда по указанию чужого домена "
                  "нельзя")

_IPV4 = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def is_ip_literal(host):
    if not host or not isinstance(host, str):
        return False
    сырое = host.strip().strip(".").strip("[]")
    if not сырое:
        return False
    try:
        ipaddress.ip_address(сырое)
        return True
    except ValueError:
        pass
    return bool(_IPV4.match(сырое))


def _адрес_запрещён(текст):
    try:
        адрес = ipaddress.ip_address(текст)
    except ValueError:
        return False
    return (адрес.is_private or адрес.is_loopback or адрес.is_link_local
            or адрес.is_multicast or адрес.is_reserved
            or _ведёт_в_никуда(адрес))


def _ведёт_в_никуда(адрес):
    try:
        return адрес.is_unspecified
    except AttributeError:
        return str(адрес) in ("0.0.0.0", "::")


def resolves_to_private(host, resolve=None):
    if not host or not isinstance(host, str):
        return False
    сырое = host.strip().strip(".")
    if is_ip_literal(сырое):
        return _адрес_запрещён(сырое.strip("[]"))

    получить = resolve or _системный_резолвер
    try:
        адреса = получить(сырое)
    except Exception:
        return False
    if not адреса:
        return False
    return any(_адрес_запрещён(а) for а in адреса)


def _системный_резолвер(host):
    сведения = socket.getaddrinfo(host, None)
    return [запись[4][0] for запись in сведения]


def filter_mx_hosts(hosts, resolve=None):
    годные, отвергнутые = [], []
    for хост in (hosts or []):
        if is_ip_literal(хост):
            отвергнутые.append((хост, REASON_IP_LITERAL))
            continue
        if resolves_to_private(хост, resolve=resolve):
            отвергнутые.append((хост, REASON_PRIVATE))
            continue
        годные.append(хост)
    return годные, отвергнутые
