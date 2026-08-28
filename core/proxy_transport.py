# core/proxy_transport.py
"""Как соединиться через прокси: разбор строки, SOCKS-обёртка над SMTP.

Вынесено из network.py, потому что это транспорт, а не валидация: тем же
кодом пользуются и SMTP-проверка, и WHOIS, и DNS, и HTTP-обогащение. Пока он
лежал внутри сетевого клиента, любой новый потребитель либо импортировал
приватное имя из чужого модуля, либо заводил свою копию разбора — и копии
расходились в том, какие форматы строки они понимают.

Форматов у прокси-строки шесть, и понимать надо все: пул покупается у разных
продавцов, и каждый пишет по-своему.
"""
import re
import smtplib
import socket

import socks

__all__ = ["PROXY_TYPES", "SocksSMTP", "build_proxy_dict",
           "_parse_proxy", "_proxy_scheme"]

# Схема прокси -> тип соединения PySocks. Чекер умеет проверять socks4 и HTTP,
# поэтому и подключаться надо тем же протоколом: иначе прокси проходит проверку
# как рабочий, а при валидации отваливается.
PROXY_TYPES = {
    "socks5": socks.SOCKS5,
    "socks4": socks.SOCKS4,
    "http": socks.HTTP,
    "https": socks.HTTP,
}


def _proxy_scheme(proxy):
    """Возвращает схему прокси ('socks5' по умолчанию, если не указана)."""
    if isinstance(proxy, str) and "://" in proxy:
        return proxy.split("://", 1)[0].strip().lower()
    return "socks5"


class SocksSMTP(smtplib.SMTP):
    """SMTP поверх прокси (SOCKS5 по умолчанию, также SOCKS4 и HTTP CONNECT)."""
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
    """Парсит строку прокси в компоненты. Возвращает (ip, port, user, password) или None.

    Поддерживаемые форматы (с любым префиксом схемы или без него):
        host:port
        host:port:user:pass
        user:pass@host:port      <- этот отдают многие продавцы
    """
    try:
        if not isinstance(proxy, str) or not proxy:
            return None

        proxy_clean = proxy.strip()
        for scheme in ("socks5://", "socks4://", "https://", "http://"):
            if proxy_clean.lower().startswith(scheme):
                proxy_clean = proxy_clean[len(scheme):]
                break

        # Формат с авторизацией через "@": user:pass@host:port
        if "@" in proxy_clean:
            creds, _, addr = proxy_clean.rpartition("@")
            host_parts = addr.split(":")
            if len(host_parts) != 2:
                return None
            user, sep, password = creds.partition(":")
            if not sep:
                return None
            return host_parts[0], int(host_parts[1]), user, password

        parts = proxy_clean.split(":")
        if len(parts) == 4:
            return parts[0], int(parts[1]), parts[2], parts[3]
        elif len(parts) == 2:
            return parts[0], int(parts[1]), None, None
        return None
    except Exception:
        return None


# Gmail в ответе на EHLO сообщает IP, с которого мы к нему пришли:
#   "mx.google.com at your service, [31.192.250.3]"
# Это ТОТ САМЫЙ выходной IP, который видит любой почтовый сервер, — а значит
# именно его надо проверять на PTR и чёрные списки. Раньше проверялся адрес
# подключения к прокси, а он совпадает с выходным не всегда (цепочки, NAT).
_EXIT_IP_RE = re.compile(r'\[((?:\d{1,3}\.){3}\d{1,3})\]')

EXIT_IP_PROBE_HOST = "gmail-smtp-in.l.google.com"

# Цели для проверки прокси. Одного Google мало: прокси может отвечать ему и
# при этом быть заблокированным у Microsoft по репутации IP. DNSBL это
# предсказывает лишь частично — у Microsoft своя база репутации, поэтому
# честнее спросить у него напрямую.
PROXY_PROBE_TARGETS = [
    ("Gmail", "gmail-smtp-in.l.google.com"),
    ("Outlook", "outlook-com.olc.protection.outlook.com"),
    # Yahoo и iCloud добавлены, потому что их пригодность раньше ВЫВОДИЛАСЬ:
    # у Yahoo — из наличия PTR, у iCloud — из чёрных списков. Обе догадки
    # неточны ровно по той же причине, по которой понадобилась прямая проба
    # Microsoft: у каждого из них своя база репутации, и предсказать её
    # чужими сигналами нельзя. Спросить дешевле, чем угадать.
    ("Yahoo", "mta5.am0.yahoodns.net"),
    ("iCloud", "mx01.mail.icloud.com"),
]

# Индексы в PROXY_PROBE_TARGETS — чтобы не привязываться к порядку числами
PROBE_GMAIL, PROBE_OUTLOOK, PROBE_YAHOO, PROBE_ICLOUD = 0, 1, 2, 3

# Имена в PTR, за которые почтовики штрафуют: сервер видит, что письмо идёт
# через прокси/VPN/Tor или с домашнего динамического адреса.
#
# Совпадение ищется ПО ГРАНИЦАМ ярлыка, а не подстрокой. Раньше стояло простое
# `"exit" in hostname`, и под него попадали безобидные имена вроде exitcom.net,
# а слово "hosting" отбраковывало ровно те датацентровые прокси, которые для
# валидации и нужны. "relay" убрано отдельно: mail-relay — нормальное имя

def build_proxy_dict(proxy):
    """Готовит словарь proxies для requests из строки прокси.

    Нужен, чтобы HTTP-проверки (Gravatar, RDAP, HEAD на сайт компании) шли
    через тот же прокси, что и SMTP. Иначе реальный IP пользователя утекал
    сразу по нескольким каналам, а Gravatar ещё и блокировал за объём.
    """
    parsed = _parse_proxy(proxy)
    if not parsed:
        return None
    ip, port, user, password = parsed
    scheme = _proxy_scheme(proxy)
    # requests умеет socks5h/socks4a (DNS резолвится на стороне прокси)
    kind = {"socks5": "socks5h", "socks4": "socks4a",
            "http": "http", "https": "http"}.get(scheme, "socks5h")
    auth = f"{user}:{password}@" if user and password else ""
    url = f"{kind}://{auth}{ip}:{port}"
    return {"http": url, "https": url}



# Прежнее приватное имя: на него ссылается код, переехавший отсюда позже.
_PROXY_TYPES = PROXY_TYPES
