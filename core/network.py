# core/network.py
import dns.resolver
import dns.reversename
import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import smtplib
import socket
import random
import string
import socks
import threading
import re
from concurrent.futures import ThreadPoolExecutor
import time

# Список доменов, известных как трудные для валидации или требующие специальной обработки
YAHOO_DOMAINS = {
    "yahoo.com", "yahoo.co.uk", "yahoo.co.in", "yahoo.fr", "yahoo.de",
    "yahoo.es", "yahoo.it", "yahoo.com.br", "yahoo.com.ar", "yahoo.com.mx",
    "yahoo.com.au", "yahoo.com.sg", "yahoo.com.hk", "yahoo.com.ph",
    "yahoo.gr", "yahoo.ro", "yahoo.hu", "yahoo.se", "yahoo.no", "yahoo.dk",
    "ymail.com", "rocketmail.com"
}

AOL_DOMAINS = {"aol.com", "aim.com", "verizon.net"}

# Провайдеры, которые режут по РЕПУТАЦИИ исходящего IP. Проверено вживую:
# Outlook отвечает "550 5.7.1 Service unavailable, Client host [IP]",
# iCloud — "550 Mail from IP ... rejected", GMX рвёт соединение.
# Через прокси из чёрных списков они молчат, через чистые — отвечают.
NEEDS_CLEAN_IP_DOMAINS = {
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk",
    "hotmail.fr", "hotmail.de", "hotmail.es", "hotmail.it", "live.co.uk",
    "live.fr", "passport.com",
    "icloud.com", "me.com", "mac.com",
    "gmx.com", "gmx.de", "gmx.net", "gmx.at",
}

MICROSOFT_DOMAINS = {
    "outlook.com", "hotmail.com", "hotmail.co.uk", "hotmail.fr", "hotmail.de",
    "hotmail.es", "hotmail.it", "live.com", "live.co.uk", "live.fr",
    "msn.com", "passport.com"
}

# HELO имена, которые выглядят как настоящие почтовые серверы (не как случайное имя ПК)
LEGIT_HELO_NAMES = [
    "mail.outbound-01.net",
    "smtp.delivery-gateway.com",
    "mta01.mailforward.net",
    "relay.outbound-smtp.org",
    "smtp-out.mailhost.net",
    "mx01.emailgateway.net",
]

# Чёрные списки почтовых серверов.
#
# Состав проверен санити-контрактом 2026-08-23: у каждой зоны запрошены
# обязательная тестовая запись 127.0.0.2 (должна числиться) и 127.0.0.1
# (не должна). Отсеяны нерабочие: zen.spamhaus.org отклоняет запросы с
# публичных DNS, cbl.abuseat.org влит в Spamhaus XBL, dnsbl.sorbs.net
# выведен из эксплуатации — все три давали NXDOMAIN даже на 127.0.0.2,
# то есть числились в коде, но не работали.
DNSBL_ZONES = [
    'b.barracudacentral.org',
    'bl.spamcop.net',
    'psbl.surriel.com',
    'truncate.gbudb.net',
    'all.s5h.net',
    'bl.mailspike.net',
    'dnsbl.dronebl.org',
]

# Spamhaus ZEN — крупнейший список, и его отсутствие было заметной дырой.
# Он отклоняет запросы, пришедшие с ПУБЛИЧНЫХ резолверов (8.8.8.8, 1.1.1.1),
# и поэтому раньше давал NXDOMAIN даже на обязательную тестовую запись
# 127.0.0.2 — то есть числился в коде, но не работал, и был убран.
#
# Работает он через СВОЙ резолвер: рекурсивный на том же VPS либо любой
# непубличный, который согласится обслуживать зону. Поэтому Spamhaus вынесен
# отдельно: спрашивается только когда такой резолвер задан, а перед первым
# запросом проверяется санити-контрактом — 127.0.0.2 обязана числиться,
# 127.0.0.1 обязана не числиться. Не прошёл контракт — зона не используется,
# и её молчание НЕ считается чистотой адреса.
SPAMHAUS_ZONE = 'zen.spamhaus.org'

# Обязательные тестовые записи Spamhaus (документированы им самим)
SPAMHAUS_SANITY_LISTED = '2.0.0.127'      # обязана числиться
SPAMHAUS_SANITY_CLEAN = '1.0.0.127'       # обязана НЕ числиться

# Сколько сбоев ПОДРЯД должен дать прокси, чтобы вылететь из ротации навсегда.
# Один-два сбоя бывают случайными (таймаут, занятый MX), три подряд — прокси мёртв.
PROXY_MAX_CONSECUTIVE_FAILS = 3

# Пул правдоподобных адресов для ротации MAIL FROM (п.3.2)
MAIL_FROM_POOL = [
    'check@example.com',       # RFC 2606 — зарезервирован, нет SPF
    'verify@example.net',      # RFC 2606 — зарезервирован, нет SPF
    'test@example.org',        # RFC 2606 — зарезервирован, нет SPF
    'noreply@mail.com',        # Минимальный SPF (~all)
    'check@email.com',         # Минимальный SPF (~all)
    'verify@usa.com',          # Минимальный SPF (~all)
]

# TLD: либо обычные буквы, либо punycode-зона IDN (xn--p1ai для .рф, xn--80asehdb
# для .онлайн). Без второй половины любой интернационализированный домен после
# перевода в punycode не проходил регулярку и получал вердикт «Bad Syntax».
_TLD_PART = r'(?:xn--[a-zA-Z0-9\-]{2,}|[a-zA-Z]{2,})'

# RFC 5322 — строгая проверка синтаксиса email (п.1.3)
_RFC5322_REGEX = re.compile(
    r'^[a-zA-Z0-9]'                # Начинается с буквы или цифры
    r'[a-zA-Z0-9._%+\-]{0,63}'     # Локальная часть: до 64 символов
    r'@'
    r'[a-zA-Z0-9]'                 # Домен начинается с буквы/цифры
    r'[a-zA-Z0-9.\-]{0,251}'       # Тело домена
    r'\.' + _TLD_PART + r'$'       # TLD: буквы либо punycode-зона
)

# Домен отдельно — нужен, когда локальная часть не-ASCII и общей регуляркой
# адрес не проверить.
_DOMAIN_REGEX = re.compile(
    r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,251}\.' + _TLD_PART + r'$'
)

_BAD_SYNTAX_PATTERNS = re.compile(
    r'(\.\.|'           # Двойные точки
    r'\.@|'             # Точка перед @
    r'@\.|'             # Точка после @
    r'\s)'              # Пробелы
)


def to_ascii_domain(domain: str):
    """Переводит домен в punycode. None — домен непереводим (значит, битый).

    почта.рф -> xn--80a1acny.xn--p1ai,  münchen.de -> xn--mnchen-3ya.de
    """
    if not isinstance(domain, str) or not domain:
        return None
    try:
        if domain.isascii():
            return domain
        return domain.encode('idna').decode('ascii')
    except Exception:
        return None


def has_non_ascii_local(email: str) -> bool:
    """True, если локальная часть содержит не-ASCII символы (нужен SMTPUTF8).

    Такой адрес законен по RFC 6531, но `RCPT TO` с ним отправить нельзя:
    smtplib кодирует команду в ASCII. Это повод для `unknown`, а не для `invalid`.
    """
    if not isinstance(email, str) or "@" not in email:
        return False
    return not email.rsplit("@", 1)[0].isascii()


def validate_email_syntax(email: str) -> bool:
    """Проверяет синтаксис email. True — адрес построен корректно.

    Интернационализированные адреса (IDN-домен, не-ASCII локальная часть)
    считаются КОРРЕКТНЫМИ. Раньше их резала ASCII-регулярка, и живой
    ivan@почта.рф получал вердикт `invalid` «Bad Syntax» — ложное захоронение
    лида на ровном месте. Проверяемость таких адресов решается отдельно.
    """
    if not email or not isinstance(email, str):
        return False
    if len(email) > 320:  # RFC максимум: 64 (local) + 1 (@) + 255 (domain)
        return False
    if email.count('@') != 1:
        return False
    if _BAD_SYNTAX_PATTERNS.search(email):
        return False

    local, _, domain = email.partition('@')
    domain_ascii = to_ascii_domain(domain)
    if not domain_ascii:
        return False

    # Не-ASCII локальная часть: общей регуляркой её не проверить, поэтому
    # смотрим только длину и домен. Отбраковывать адрес за это нельзя.
    if not local.isascii():
        return bool(local) and len(local.encode('utf-8')) <= 64 and bool(
            _DOMAIN_REGEX.match(domain_ascii))

    return bool(_RFC5322_REGEX.match(f"{local}@{domain_ascii}"))


# Схема прокси -> тип соединения PySocks. Чекер умеет проверять socks4 и HTTP,
# поэтому и подключаться надо тем же протоколом: иначе прокси проходит проверку
# как рабочий, а при валидации отваливается.
_PROXY_TYPES = {
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
# почтового сервера, а не признак прокси.
DIRTY_RDNS_KEYWORDS = ("proxy", "vpn", "tor", "torexit", "exit", "anon",
                       "spam", "abuse", "dynamic", "dyn", "dhcp", "pool",
                       "dial", "dialup", "pppoe", "cable", "dsl")

_DIRTY_RDNS_RE = re.compile(
    r'(?:^|[.\-])(' + "|".join(DIRTY_RDNS_KEYWORDS) + r')(?:[.\-0-9]|$)')

# Почтовые шлюзы безопасности. Стоят ПЕРЕД корпоративным доменом и принимают
# любой RCPT, фильтруя письмо позже, — то есть домен за таким шлюзом является
# catch-all по конструкции. Проверено на практике: тройная проба выясняет это
# верно, но тратит три подключения и не объясняет причину.
SECURITY_GATEWAY_MX = {
    "pphosted.com": "Proofpoint",
    "ppe-hosted.com": "Proofpoint",
    "pphosted.net": "Proofpoint",
    "mimecast.com": "Mimecast",
    "mimecast.co.za": "Mimecast",
    "mimecast-offshore.com": "Mimecast",
    "iphmx.com": "Cisco IronPort",
    "barracudanetworks.com": "Barracuda",
    "barracuda.com": "Barracuda",
    "messagelabs.com": "Symantec",
    "sophos.com": "Sophos",
    "fortimail.com": "Fortinet",
    "hornetsecurity.com": "Hornetsecurity",
    "antispamcloud.com": "SpamExperts",
    "spamexperts.com": "SpamExperts",
    "mailcontrol.com": "Forcepoint",
    "securence.com": "Securence",
    "spamtitan.com": "SpamTitan",
    "mailanyone.net": "FuseMail",
    "emailfiltering.com": "Email Filtering",
    "mailprotector.com": "Mailprotector",
    "mailguard.com.au": "MailGuard",
    "libraesva.com": "Libraesva",
    "vadesecure.com": "Vade",
    "abusix.com": "Abusix",
}


# Формулировки, по которым видно: отказали не ящику, а нашему исходящему IP.
_IP_REPUTATION_MARKERS = (
    "our ip blocked", "our ip blacklisted", "client host", "reputation",
    "spamhaus", "barracuda", "blacklist", "rbl", "dnsbl", "listed in",
    "service unavailable", "5.7.1", "5.7.606", "poor reputation",
)


# Формулировки, по которым видно: отказ ВРЕМЕННЫЙ, даже если код постоянный.
# Сервер, который в ответе 550 пишет "try again later", противоречит сам себе,
# и верить в этом споре надо тексту, а не коду: цена ошибки — похороненный лид.
_TRANSIENT_TEXT_MARKERS = (
    "temporarily", "temporary", "try again", "try later", "retry",
    "later", "deferred", "defer", "greylist", "grey list", "throttl",
    "too busy", "server busy", "overloaded", "over load", "rate limit",
    "resources temporarily", "not available at this time", "at this time",
    "come back", "in a few", "currently unavailable",
)

# Отрицания, при которых упоминание получателя действительно означает,
# что ящика нет. Без одного из них 550 про «mailbox» ничего не доказывает.
_RECIPIENT_NEGATIONS = (
    "no such", "not exist", "doesn't exist", "does not exist", "unknown",
    "not found", "no longer", "invalid", "rejected", "reject", "disabled",
    "unavailable", "not available", "cannot", "can not", "can't", "refused",
    "denied", "no mailbox", "nonexistent", "non-existent", "not accepted",
    "unrouteable", "unroutable", "undeliverable", "bad ", "illegal",
)


def _looks_transient(reason):
    """True, если текст ответа говорит о временной проблеме, а не о ящике."""
    if not isinstance(reason, str) or not reason:
        return False
    return any(marker in reason.lower() for marker in _TRANSIENT_TEXT_MARKERS)


def _looks_like_ip_reputation(reason):
    """True, если причина отказа — репутация исходящего IP, а не ящик."""
    if not isinstance(reason, str) or not reason:
        return False
    low = reason.lower()
    return any(marker in low for marker in _IP_REPUTATION_MARKERS)


def security_gateway(mx_records):
    """Имя шлюза безопасности, если почта домена идёт через него, иначе None."""
    if not mx_records:
        return None
    if isinstance(mx_records, str):
        records = [mx_records]
    elif hasattr(mx_records, "__iter__") and not isinstance(mx_records, (bytes, dict)):
        records = list(mx_records)
    else:
        return None
    for record in records:
        if not isinstance(record, str):
            continue
        low = record.lower().rstrip(".")
        for host, vendor in SECURITY_GATEWAY_MX.items():
            if low == host or low.endswith("." + host):
                return vendor
    return None


# DKIM-селекторы. Универсального способа их узнать нет — имя выбирает владелец
# домена. Но если известно, на чьей инфраструктуре сидит домен, перебирать все
# два с лишним десятка незачем: у Google селектор гугловский.
_DKIM_BY_MX = (
    (("google", "googlemail"), ['google', '20230601', '20221208', '20210112', '20161025']),
    (("outlook", "microsoft", "protection.outlook"), ['selector1', 'selector2']),
    (("yandex",), ['mx', 'yandex']),
    (("mail.ru",), ['mailru', 'mail']),
    (("protonmail", "proton.me"), ['protonmail', 'protonmail2', 'protonmail3']),
    (("zoho",), ['zoho', 'zmail']),
    (("yahoodns",), ['s2048', 's1024']),
    (("messagingengine", "fastmail"), ['fm1', 'fm2', 'fm3', 'mesmtp']),
    (("amazonaws", "amazonses"), ['amazonses']),
    (("sendgrid",), ['s1', 's2']),
    (("mailgun",), ['mailo', 'smtp', 'k1']),
)

_DKIM_FALLBACK = [
    'google', '20230601', 'selector1', 'selector2', 'mailru', 'mail', 'dkim',
    'default', 'mx', 'yandex', 'protonmail', 'zoho', 'k1', 'k2', 's1', 's2',
    'sig1', 'smtp', 'key1', 'dkim1', '20221208', '20210112', 'zmail',
]


def _dkim_selectors_for(mx_record):
    """Список селекторов под конкретный MX. Без MX — общий перебор."""
    if isinstance(mx_record, str) and mx_record and mx_record != "N/A":
        low = mx_record.lower()
        for hints, selectors in _DKIM_BY_MX:
            if any(hint in low for hint in hints):
                # Плюс два самых частых общих — на случай своей подписи домена
                return selectors + ['default', 'dkim']
    return _DKIM_FALLBACK


def probe_proxy_target(proxy, host, timeout=10, want_exit_ip=False):
    """Полная проба прокси до конкретного почтовика.

    Идём до MAIL FROM, а не до баннера: именно там Microsoft отвечает
    "550 5.7.1 Service unavailable, Client host [IP]", а Yahoo — 5.7.25.
    До этого этапа оба выглядят рабочими.

    Возвращает (ok, latency_ms, exit_ip, reason).
    """
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
        exit_ip = None
        if want_exit_ip:
            m = _EXIT_IP_RE.search(text)
            exit_ip = m.group(1) if m else None

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
    """Возвращает реальный выходной IP прокси или None.

    Спрашиваем у самого почтового сервера — стороннего сервиса не нужно,
    лимитов нет, и ответ гарантированно совпадает с тем, что увидит Yahoo.
    """
    _ok, _lat, exit_ip, _reason = probe_proxy_target(
        proxy, EXIT_IP_PROBE_HOST, timeout=timeout, want_exit_ip=True)
    return exit_ip


def dedupe_proxies(proxies):
    """Убирает повторы, сохраняя порядок.

    Один прокси, записанный дважды (или с разным регистром схемы), проверялся
    бы дважды и занимал два места в ротации.
    """
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
        # Ключ по разобранным частям: socks5://1.2.3.4:1080 и 1.2.3.4:1080 — одно
        key = (_proxy_scheme(norm), parsed) if parsed else norm.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(norm)
    return result


def is_dirty_rdns(hostname):
    """True, если имя из PTR выдаёт прокси/VPN/динамический IP.

    Почтовики штрафуют такие имена даже при валидном FCrDNS: по хосту видно,
    что письмо идёт не с нормального почтового сервера.

    Совпадение по границам ярлыка: pool-71-105.fios.verizon.net — динамика,
    а exitcom.net и hosting-provider.net — обычные хосты, и метить их грязными
    значит выбрасывать годные датацентровые прокси.
    """
    if not isinstance(hostname, str) or not hostname:
        return False
    return bool(_DIRTY_RDNS_RE.search(hostname.lower()))


def profile_proxies(proxies, timeout=10, workers=30, progress_callback=None,
                    probe_outlook=True):
    """Профилирует прокси и говорит, для каких провайдеров он пригоден.

    За один проход выясняем всё, что определяет пригодность:
      * реальный выходной IP (спрашиваем у Gmail — он сообщает его на EHLO)
      * задержку соединения (медленный прокси растягивает прогон)
      * PTR по выходному IP: три состояния, "не проверили" != "нет"
      * имя из PTR: proxy/vpn/tor в нём почтовики штрафуют
      * чёрные списки по выходному IP
      * реальную достижимость Microsoft — у него своя база репутации,
        и DNSBL её предсказывает лишь частично

    Возвращает {proxy: {exit_ip, latency_ms, has_ptr, rdns, rdns_dirty,
                        in_dnsbl, outlook_ok, outlook_reason}}.
    """
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return {}
    proxies = list(proxies)

    # proxy_dns=False осознанно: здесь резолвятся обратные записи САМИХ прокси,
    # данных пользователя в этих запросах нет. Гнать их через проверяемый прокси
    # значило бы ставить качество профиля в зависимость от того, что мы измеряем.
    validator = NetworkValidator(timeout=timeout, proxy_dns=False)
    result = {}
    done = 0
    lock = threading.Lock()

    def profile_one(proxy):
        empty = {"exit_ip": None, "latency_ms": None, "has_ptr": None,
                 "rdns": None, "rdns_dirty": False, "in_dnsbl": False,
                 "outlook_ok": None, "outlook_reason": None,
                 "asn": None, "asn_country": "", "asn_org": "",
                 "ip_type": "unknown", "yahoo_ok": None, "icloud_ok": None}

        ok, latency, exit_ip, reason = probe_proxy_target(
            proxy, EXIT_IP_PROBE_HOST, timeout=timeout, want_exit_ip=True)
        if not exit_ip:
            empty["latency_ms"] = latency
            empty["outlook_reason"] = reason if not ok else None
            return proxy, empty

        # check_fcrdns различает "PTR нет" (False) и "проверить не удалось" (None).
        # Во время профилирования летят сотни параллельных DNS-запросов, и часть
        # ожидаемо отваливается по таймауту. Схлопывать None в False нельзя:
        # хороший прокси с PTR вылетел бы из пула Yahoo из-за случайного сбоя DNS.
        has_ptr = validator.check_fcrdns(exit_ip)
        if has_ptr is None:
            with validator._fcrdns_lock:
                validator._fcrdns_cache.pop(exit_ip, None)   # не кэшируем неудачу
            time.sleep(0.3)
            has_ptr = validator.check_fcrdns(exit_ip)        # вторая попытка

        rdns = validator.get_ptr_hostname(exit_ip)
        in_dnsbl = validator.check_dnsbl_ip(exit_ip)

        # ASN, страна и тип адреса. Датацентровый IP фильтры режут заметно
        # чаще резидентного, а страна нужна, чтобы подбирать прокси под гео
        # домена получателя. Раньше про выходной IP было известно только то,
        # числится ли он в чёрных списках.
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

            # Yahoo и iCloud спрашиваем напрямую. Каждая проба — один SMTP-диалог
            # до MAIL FROM; на старте это окупается тем, что маршрутизация потом
            # не гоняет письма туда, где их точно не примут.
            y_ok, _yl, _yi, _yr = probe_proxy_target(
                proxy, PROXY_PROBE_TARGETS[PROBE_YAHOO][1], timeout=timeout)
            yahoo_ok = y_ok
            i_ok, _il, _ii, _ir = probe_proxy_target(
                proxy, PROXY_PROBE_TARGETS[PROBE_ICLOUD][1], timeout=timeout)
            icloud_ok = i_ok

        return proxy, {"exit_ip": exit_ip, "latency_ms": latency,
                       "has_ptr": has_ptr, "rdns": rdns,
                       "rdns_dirty": is_dirty_rdns(rdns), "in_dnsbl": in_dnsbl,
                       "outlook_ok": outlook_ok, "outlook_reason": outlook_reason,
                       "asn": meta.get("asn"),
                       "asn_country": meta.get("asn_country", ""),
                       "asn_org": meta.get("asn_org", ""),
                       "ip_type": meta.get("ip_type", "unknown"),
                       "yahoo_ok": yahoo_ok, "icloud_ok": icloud_ok}

    # Число потоков приходит из ползунка. Раньше здесь стояло жёсткое 30, и на
    # списке в несколько тысяч прокси профилирование занимало часы: на каждый
    # прокси идут два полных SMTP-диалога плюс DNS. Потолок в 300 — та же
    # аппаратная защита, что и у валидации.
    try:
        workers = int(workers)
    except (TypeError, ValueError):
        workers = 30
    workers = max(1, min(workers, 300))

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(proxies)))) as pool:
        for proxy, info in pool.map(profile_one, proxies):
            result[proxy] = info
            with lock:
                done += 1
                if progress_callback and (done % 50 == 0 or done == len(proxies)):
                    ptr_n = sum(1 for v in result.values() if v["has_ptr"] is True)
                    bl_n = sum(1 for v in result.values() if v["in_dnsbl"])
                    progress_callback(done, len(proxies), ptr_n, bl_n)

    return result


def filter_live_proxies(proxies, timeout, threads=100, progress_callback=None, log_callback=None):
    """Тестирует список прокси и возвращает только рабочие (у которых открыт 25 порт)."""
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return []
    proxies = list(proxies)
    from core.async_proxy import run_async_checker

    def on_prog(c, t, l):
        if progress_callback:
            progress_callback(c, t)
        if log_callback:
            if c % 100 == 0 or c == t:
                log_callback(f"[PROXY] Проверка... {c}/{t} | Найдено рабочих: {l}", "info")

    live_proxies = run_async_checker(
        proxies=proxies,
        workers=threads,
        timeout=timeout,
        mode="smtp",
        progress_callback=on_prog
    )

    return live_proxies


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


# --- DNS через прокси --------------------------------------------------------
#
# Раньше резолвер ходил на 8.8.8.8 напрямую всегда. Это был последний канал, по
# которому реальный IP пользователя уходил наружу: публичный DNS видел и его
# адрес, и ПОЛНЫЙ список доменов проверяемой базы. SMTP, Gravatar, RDAP и HTTP
# уже шли через прокси, а DNS — нет.
#
# Теперь при заданных прокси каждый DNS-запрос идёт через тот же прокси:
#   1. DoH (POST wire-format) через socks5h. Соединение переиспользуется
#      сессией, поэтому 25 DKIM-селекторов на домен не превращаются в 25
#      TLS-рукопожатий.
#   2. Обычный DNS по TCP через SOCKS — если DoH недоступен.
#   3. Отказ. Прямого запроса в обход прокси НЕТ — ради этого всё и делалось.
DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
)

# Задержка для прокси, у которого её не измеряли. Ставим заведомо большую, чтобы
# при равном health score измеренные быстрые шли впереди неизвестных.
UNKNOWN_LATENCY_MS = 10000


class DNSUnavailable(dns.exception.DNSException):
    """DNS спросить не удалось: прокси заданы, но ни один транспорт не ответил.

    Отличать от NXDOMAIN обязательно. «Не смогли проверить» — это не
    «домена не существует»: иначе живой домен уедет в Invalid как мёртвый.
    """


class ProxiedResolver:
    """Резолвер с интерфейсом dns.resolver.Resolver.resolve().

    Без прокси ведёт себя ровно как раньше — обычный резолвер на 8.8.8.8/1.1.1.1.
    С прокси заворачивает запрос в тот же прокси, что и SMTP.
    """

    def __init__(self, nameservers, timeout, proxy_provider=None):
        self._plain = dns.resolver.Resolver()
        self._plain.nameservers = list(nameservers)
        self._plain.timeout = timeout
        self._plain.lifetime = timeout
        self.nameservers = self._plain.nameservers
        self.timeout = timeout
        self.lifetime = timeout
        self._proxy_provider = proxy_provider
        # Сессии requests не потокобезопасны — держим по одной на поток.
        self._local = threading.local()

    def resolve(self, qname, rdtype='A'):
        """Контракт proxy_provider():
            None  — прокси не заданы, идём напрямую (прежнее поведение)
            ""    — прокси заданы, но живых нет: спрашивать нельзя, это утечка
            str   — идём через этот прокси
        """
        proxy = self._proxy_provider() if self._proxy_provider else None
        if proxy is None:
            return self._plain.resolve(qname, rdtype)
        if not proxy:
            raise DNSUnavailable("прокси заданы, но живых не осталось")

        rd = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else rdtype
        query = dns.message.make_query(qname, rd)
        response = self._via_doh(query, proxy)
        if response is None:
            response = self._via_socks_tcp(query, proxy)
        if response is None:
            raise DNSUnavailable("ни DoH, ни DNS-over-TCP через прокси не ответили")
        return self._extract(response, rd)

    def _session(self, proxy):
        store = getattr(self._local, "sessions", None)
        if store is None:
            store = {}
            self._local.sessions = store
        session = store.get(proxy)
        if session is None:
            import requests
            session = requests.Session()
            session.headers.update({
                "Content-Type": "application/dns-message",
                "Accept": "application/dns-message",
                "User-Agent": "Mozilla/5.0",
            })
            proxies = build_proxy_dict(proxy)
            if proxies:
                session.proxies.update(proxies)
            store[proxy] = session
        return session

    def _via_doh(self, query, proxy):
        wire = query.to_wire()
        for url in DOH_ENDPOINTS:
            try:
                resp = self._session(proxy).post(url, data=wire, timeout=self.timeout)
                if resp.status_code == 200 and resp.content:
                    return dns.message.from_wire(resp.content)
            except Exception:
                continue
        return None

    def _via_socks_tcp(self, query, proxy):
        parsed = _parse_proxy(proxy)
        if not parsed:
            return None
        pip, pport, puser, ppass = parsed
        ptype = _PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5)
        for nameserver in self.nameservers:
            sock = None
            try:
                sock = socks.socksocket()
                sock.set_proxy(ptype, pip, pport, username=puser, password=ppass)
                sock.settimeout(self.timeout)
                sock.connect((nameserver, 53))
                # DNS по UDP через SOCKS5 работает не везде, по TCP — везде.
                return dns.query.tcp(query, nameserver, timeout=self.timeout, sock=sock)
            except Exception:
                continue
            finally:
                if sock is not None:
                    try:
                        sock.close()
                    except Exception:
                        pass
        return None

    @staticmethod
    def _extract(response, rdtype):
        """Превращает ответ в список rdata — то же, что отдаёт обычный резолвер."""
        rcode = response.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN
        if rcode != dns.rcode.NOERROR:
            raise DNSUnavailable(f"DNS rcode {dns.rcode.to_text(rcode)}")
        items = []
        for rrset in response.answer:
            if rrset.rdtype == rdtype:
                items.extend(rrset)
        if not items:
            raise dns.resolver.NoAnswer
        return items


# Домен почтовика -> двухбуквенный код страны. Нужен, чтобы сверить страну
# домена получателя со страной выходного IP прокси (RDAP отдаёт именно код).
#
# Своей таблицы стран здесь нет и быть не должно: core/provider.py уже знает
# страну домена по названию, и держать второй список значило бы обречь их на
# расхождение. Здесь только перевод названия в код.
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


def country_code_for_domain(domain):
    """Двухбуквенный код страны домена или пусто, если страна неизвестна.

    Пусто — нормальный и частый исход: у .com и .net страны нет, и подбирать
    прокси по гео для них не по чему. В этом случае выбор идёт как раньше.
    """
    if not isinstance(domain, str) or "." not in domain:
        return ""
    try:
        from core.provider import country_from_domain
    except Exception:
        return ""
    return _COUNTRY_TO_CODE.get(country_from_domain(domain), "")


def _generate_random_local(style="short"):
    """Генерирует случайный локальный-адрес для Catch-All теста.
    style='short' — классический (16 символов), style='uuid' — UUID-подобный (п.4 Catch-All)"""
    if style == "uuid":
        import uuid
        return str(uuid.uuid4()).replace('-', '')[:24]
    chars = string.ascii_lowercase + string.digits
    prefix = ''.join(random.choices(chars, k=12))
    suffix = ''.join(random.choices(string.digits, k=4))
    return f"{prefix}{suffix}"


class NetworkValidator:
    def __init__(self, from_email="check@example.com", timeout=5, proxies=None,
                 proxy_dns=True):
        self.from_email = from_email
        self.timeout = timeout
        self.proxies = proxies if proxies else []
        # Потолок времени на ОДИН адрес, независимо от числа MX и повторов.
        # Держит прогон предсказуемым: без него адрес с тремя MX мог висеть минутами.
        self.address_deadline = max(30, min(180, timeout * 6))

        # Пускать ли DNS через прокси. Выключается только там, где запросы не
        # содержат данных пользователя — например при профилировании самих
        # прокси (обратный DNS их собственных IP).
        self._proxy_dns = bool(proxy_dns)

        # Настройка DNS резолвера. С прокси запросы идут через них, без прокси —
        # напрямую, как раньше.
        self.resolver = ProxiedResolver(
            nameservers=['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1'],
            timeout=self.timeout,
            proxy_provider=self._dns_proxy,
        )

        # Кэш MX-записей
        self.mx_cache = {}
        self.mx_lock = threading.Lock()

        # Кэш Catch-All доменов — чтобы не делать двойной пинг дважды для одного домена
        self.catchall_cache = {}
        self.catchall_lock = threading.Lock()

        # Честен ли сервер домена: принимает ли он обязательный по RFC postmaster@.
        # Спрашивается лениво — только перед тем, как похоронить адрес.
        self._postmaster_cache = {}
        self._postmaster_lock = threading.Lock()

        # Кэш DNS-здоровья (SPF/DMARC/DKIM) — п.2.2+
        self._dns_health_cache = {}
        self._dns_health_lock = threading.Lock()

        # Дополнительные кэши (п.1.2, п.1.3)
        self._dnsbl_cache = {}
        self._dnsbl_lock = threading.Lock()
        self._ptr_cache = {}
        self._ptr_lock = threading.Lock()
        # FCrDNS исходящих IP (наших/прокси) — от него зависит доступ к Yahoo/AOL
        self._fcrdns_cache = {}
        self._fcrdns_lock = threading.Lock()

        # Rate Limiting: семафоры для ограничения одновременных соединений к одному MX (п.3.3)
        self._mx_semaphores = {}
        self._mx_sem_lock = threading.Lock()
        self._max_concurrent_per_mx = 5  # Максимум 5 параллельных соединений к одному MX

        # Адаптивный Rate Limiting: счётчик 421-ошибок по MX (п.5 — adaptive)
        self._mx_error_counts = {}
        self._mx_error_lock = threading.Lock()

        # Proxy Health Scoring (п.8): score каждого прокси
        self._proxy_scores = {}
        self._proxy_score_lock = threading.Lock()

        # Лимит ОДНОВРЕМЕННЫХ соединений через один прокси.
        #
        # Семафор стоял только на MX. При 300 потоках и пяти живых прокси в
        # каждый летело по 60 соединений разом — дешёвый SOCKS5 столько не
        # держит, начинает рвать связь и выглядит мёртвым. Валидатор при этом
        # банил его за «три сбоя подряд», хотя убил его сам.
        self._proxy_semaphores = {}
        self._proxy_sem_lock = threading.Lock()
        self._max_concurrent_per_proxy = 8

        # Суточная нагрузка на ВЫХОДНОЙ IP, а не на строку прокси: десять
        # прокси с общим выходом жгут репутацию одного адреса. Счётчик уводит
        # выбор на менее нагруженный, пока такие есть.
        self._ip_load = {}
        self._ip_load_lock = threading.Lock()
        self._ip_load_soft_cap = 800

        # Свой резолвер для Spamhaus. Пусто — Spamhaus не спрашивается вовсе.
        self._spamhaus_resolver = None
        self._spamhaus_ok = None
        # Задержка до баннера, измеренная профилировщиком. Раньше она только
        # логировалась; теперь при равном health score быстрый прокси идёт первым.
        self._proxy_latency = {}
        # Прокси, севший MAX_CONSECUTIVE_FAILS раз ПОДРЯД, выбывает из ротации навсегда.
        # Иначе мёртвый прокси бесконечно тормозит прогон (10 повторов × таймаут на адрес).
        self._proxy_consecutive_fails = {}
        # На каких MX пришлись сбои текущей серии: три неудачи на одном сервере
        # означают мёртвый сервер, а не мёртвый прокси
        self._proxy_fail_hosts = {}
        self._proxy_banned = set()
        # Полный профиль прокси: нужен, чтобы при переснятии не потерять
        # то, что заново не измеряли (например реакцию Microsoft)
        self._proxy_profiles = {}
        # Прокси с обратным DNS — единственные, через кого проверяется Yahoo/AOL
        self._ptr_proxies = set()
        # PTR проверить не удалось — не путать с "PTR точно нет"
        self._ptr_unknown = set()
        # Профилировались ли прокси вообще (см. set_proxy_profiles)
        self._profiled = False
        # Прокси, чей выходной IP числится в чёрных списках: Outlook, iCloud и GMX
        # такие отшивают по репутации, а Gmail и Yandex — принимают
        self._dirty_proxies = set()
        # Результаты ПРЯМЫХ проб до Yahoo и iCloud (заполняет set_proxy_profiles)
        self._yahoo_ok = set()
        self._yahoo_bad = set()
        self._icloud_bad = set()
        if self.proxies:
            for p in self.proxies:
                self._proxy_scores[p] = 0  # Начальный score = 0
                self._proxy_consecutive_fails[p] = 0

        # Случайный HELO-хост для этой сессии (выглядит как настоящий почтовый сервер)
        self.helo_name = random.choice(LEGIT_HELO_NAMES)

    def proxy_slot(self, proxy):
        """Семафор конкретного прокси. Держит число соединений в пределах лимита."""
        if not proxy:
            return None
        with self._proxy_sem_lock:
            slot = self._proxy_semaphores.get(proxy)
            if slot is None:
                slot = threading.Semaphore(self._max_concurrent_per_proxy)
                self._proxy_semaphores[proxy] = slot
            return slot

    def set_proxy_concurrency(self, limit):
        """Сколько соединений разрешено держать через один прокси одновременно.

        Уже созданные семафоры не пересоздаём: менять лимит под работающими
        потоками значит выпустить больше, чем разрешено, ровно один раз.
        """
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            return self._max_concurrent_per_proxy
        self._max_concurrent_per_proxy = max(1, min(limit, 64))
        return self._max_concurrent_per_proxy

    def note_ip_use(self, proxy, count=1):
        """Отмечает обращение через выходной IP этого прокси."""
        exit_ip = (self._proxy_profiles.get(proxy) or {}).get("exit_ip")
        key = exit_ip or proxy
        with self._ip_load_lock:
            self._ip_load[key] = self._ip_load.get(key, 0) + int(count)
            return self._ip_load[key]

    def ip_load(self, proxy):
        """Сколько обращений уже ушло через выходной IP этого прокси."""
        exit_ip = (self._proxy_profiles.get(proxy) or {}).get("exit_ip")
        key = exit_ip or proxy
        with self._ip_load_lock:
            return self._ip_load.get(key, 0)

    def overloaded_ips(self):
        """Выходные IP, перешагнувшие мягкий потолок суточной нагрузки."""
        with self._ip_load_lock:
            return {ip: n for ip, n in self._ip_load.items()
                    if n >= self._ip_load_soft_cap}

    def set_spamhaus_resolver(self, nameservers):
        """Задаёт СВОЙ резолвер для Spamhaus и проверяет его санити-контрактом.

        Без такого резолвера Spamhaus не спрашивается: с публичного DNS он
        отвечает отказом, а отказ, принятый за чистоту, снял бы штраф с
        реально грязного IP. Возвращает True, если зона прошла контракт.
        """
        if not nameservers:
            self._spamhaus_resolver = None
            self._spamhaus_ok = None
            return False

        resolver = ProxiedResolver(
            nameservers=list(nameservers), timeout=self.timeout,
            proxy_provider=self._dns_proxy)

        def listed(reversed_ip):
            """True — числится, False — точно не числится, None — не спросили.

            NXDOMAIN и пустой ответ — это ОТВЕТ зоны «такого IP в списке нет»,
            а не сбой. Схлопывать их в None нельзя: тогда контрольная чистая
            запись никогда не даёт False, и санити-контракт не проходит даже
            у полностью исправного резолвера — то есть Spamhaus не включается
            вообще. Сбоем считается только то, что помешало спросить.
            """
            try:
                answers = resolver.resolve(f"{reversed_ip}.{SPAMHAUS_ZONE}", 'A')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return False
            except Exception:
                return None
            for rdata in answers:
                code = rdata.to_text()
                if code.startswith('127.0.0.') or code.startswith('127.0.1.'):
                    return True
            return False

        must_be_listed = listed(SPAMHAUS_SANITY_LISTED)
        must_be_clean = listed(SPAMHAUS_SANITY_CLEAN)

        # Контракт: тестовая запись обязана числиться, чистая — нет.
        # Любой другой исход означает, что зона нам не отвечает как надо.
        self._spamhaus_ok = (must_be_listed is True and must_be_clean is False)
        self._spamhaus_resolver = resolver if self._spamhaus_ok else None
        return bool(self._spamhaus_ok)

    def _spamhaus_lists(self, ip):
        """True/False по Spamhaus, None — не спрашивали или не смогли.

        None принципиально отличается от False: «не спросили» не означает
        «чисто», и наверх уходит именно неизвестность.
        """
        if not self._spamhaus_resolver or not self._spamhaus_ok:
            return None
        reversed_ip = '.'.join(reversed(ip.split('.')))
        try:
            answers = self._spamhaus_resolver.resolve(
                f"{reversed_ip}.{SPAMHAUS_ZONE}", 'A')
        # NoAnswer здесь по той же причине, что и в санити-контракте выше:
        # зона ответила «записи нет», то есть IP в ней не числится.
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            return None
        for rdata in answers:
            code = rdata.to_text()
            if code.startswith('127.0.0.') or code.startswith('127.0.1.'):
                return True
        return False

    def _get_mx_semaphore(self, mx_host: str) -> threading.Semaphore:
        """Возвращает семафор для конкретного MX-хоста (п.3.3 Rate Limiting + adaptive)."""
        mx_key = mx_host.lower()
        with self._mx_sem_lock:
            if mx_key not in self._mx_semaphores:
                self._mx_semaphores[mx_key] = threading.Semaphore(self._max_concurrent_per_mx)
            return self._mx_semaphores[mx_key]

    def _record_mx_error(self, mx_host: str):
        """Записывает 421-ошибку для MX. При 3+ ошибках уменьшает семафор (adaptive rate limiting)."""
        mx_key = mx_host.lower()
        with self._mx_error_lock:
            self._mx_error_counts[mx_key] = self._mx_error_counts.get(mx_key, 0) + 1
            errors = self._mx_error_counts[mx_key]
        # При 3+ ошибках — пересоздаём семафор с меньшим лимитом
        if errors == 3:
            with self._mx_sem_lock:
                self._mx_semaphores[mx_key] = threading.Semaphore(2)  # Снижаем до 2
        elif errors == 6:
            with self._mx_sem_lock:
                self._mx_semaphores[mx_key] = threading.Semaphore(1)  # Снижаем до 1

    def set_ptr_proxies(self, ptr_proxies):
        """Задаёт подмножество прокси, у которых есть обратный DNS (FCrDNS).

        Только через них можно проверять Yahoo/AOL/Verizon — остальные они
        отшивают на MAIL FROM ошибкой 5.7.25, не дойдя до проверки адреса.
        """
        if isinstance(ptr_proxies, (str, bytes)) or not hasattr(ptr_proxies, "__iter__"):
            ptr_proxies = []
        with self._proxy_score_lock:
            self._ptr_proxies = set(ptr_proxies or [])
            self._profiled = bool(ptr_proxies)

    def set_proxy_profiles(self, profiles):
        """Принимает результат profile_proxies(): выходной IP, PTR, чёрные списки.

        Позволяет выбирать прокси под задачу: Yahoo/AOL требуют PTR,
        Outlook/iCloud/GMX — чистую репутацию IP, остальным сойдёт любой живой.

        PTR хранится ТРЕМЯ состояниями. "Не удалось проверить" — это не то же
        самое, что "PTR нет": такие прокси стоит попробовать на Yahoo, если
        подтверждённых не осталось. Отказ от проверки гарантирует ноль
        результатов, а попытка стоит одного пинга.
        """
        profiles = profiles if isinstance(profiles, dict) else {}
        self._proxy_profiles = dict(profiles)
        with self._proxy_score_lock:
            # Факт профилирования храним отдельно от его результатов: если у ВСЕХ
            # прокси PTR точно отсутствует, все три множества окажутся пустыми,
            # и по ним нельзя отличить "профилировали, PTR ни у кого нет" от
            # "не профилировали вовсе". А это разные случаи: в первом Yahoo
            # проверять нечем, во втором ограничений нет.
            self._profiled = bool(profiles)
            self._ptr_proxies = {p for p, v in profiles.items() if v.get("has_ptr") is True}
            self._ptr_unknown = {p for p, v in profiles.items() if v.get("has_ptr") is None}

            # Измеренная задержка идёт в выбор прокси, а не только в лог.
            self._proxy_latency = {
                p: v.get("latency_ms") for p, v in profiles.items()
                if isinstance(v.get("latency_ms"), (int, float))
            }

            # "Грязный" = непригодный для провайдеров, чувствительных к репутации.
            # Три независимых признака, и прямая проба среди них ГЛАВНАЯ: замерено,
            # что Microsoft отвергает IP, которого нет ни в одном чёрном списке —
            # у него своя база репутации, и DNSBL её предсказывает лишь частично.
            self._dirty_proxies = {
                p for p, v in profiles.items()
                if v.get("in_dnsbl")                 # числится в чёрных списках
                or v.get("outlook_ok") is False      # Microsoft отверг напрямую
                or v.get("rdns_dirty")               # имя в PTR выдаёт прокси/VPN
            }

            # Прямые пробы Yahoo и iCloud. Раньше их пригодность выводилась —
            # у Yahoo из PTR, у iCloud из чёрных списков. Теперь она измерена,
            # и измеренное сильнее выведенного: прокси, которого Yahoo отверг
            # на MAIL FROM, в пул Yahoo не попадает, даже если PTR у него есть.
            self._yahoo_ok = {p for p, v in profiles.items() if v.get("yahoo_ok") is True}
            self._yahoo_bad = {p for p, v in profiles.items() if v.get("yahoo_ok") is False}
            self._icloud_bad = {p for p, v in profiles.items() if v.get("icloud_ok") is False}
            self._dirty_proxies |= self._icloud_bad

    def refresh_proxy_profiles(self, timeout=10, workers=30):
        """Переснимает профиль живых прокси и возвращает, что изменилось.

        Зачем: у ротирующегося прокси выходной IP меняется по ходу прогона, а
        профиль снимается один раз на старте. Маршрутизация продолжает считать,
        что у прокси есть PTR, когда его уже нет, и Yahoo уходит в пустоту.

        Тяжёлую пробу Microsoft не повторяем — репутация IP меняется медленно,
        а вот сам IP и его обратный DNS проверить надо. Прежние значения
        outlook_ok переносим из старого профиля.
        """
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
            # Репутацию у Microsoft заново не спрашивали — берём прежнюю
            if info.get("outlook_ok") is None and old.get("outlook_ok") is not None:
                info["outlook_ok"] = old["outlook_ok"]
                info["outlook_reason"] = old.get("outlook_reason")
            merged[proxy] = info

        self.set_proxy_profiles(merged)
        return {"checked": len(fresh), "ip_changed": ip_changed,
                "ptr_lost": ptr_lost, "ptr_gained": ptr_gained}

    def has_ptr_proxies(self):
        """True, если есть чем проверять Yahoo/AOL: подтверждённый PTR либо непроверенный."""
        with self._proxy_score_lock:
            return bool((self._ptr_proxies | self._ptr_unknown) - self._proxy_banned)

    def has_clean_proxies(self):
        with self._proxy_score_lock:
            alive = {p for p in self.proxies if p not in self._proxy_banned}
            return bool(alive - self._dirty_proxies)

    def _dns_proxy(self):
        """Прокси для DNS-запроса. Контракт описан в ProxiedResolver.resolve().

        Когда прокси заданы, но живых не осталось, возвращаем пустую строку, а не
        None: молча уйти на 8.8.8.8 напрямую — значит раскрыть реальный IP там,
        где пользователь этого не ждёт. Ровно та же логика, что у SMTP.
        """
        if not self._proxy_dns or not self.proxies:
            return None
        return self._pick_best_proxy() or ""

    def _proxy_country(self, proxy):
        """Двухбуквенный код страны выходного IP или пусто."""
        return ((self._proxy_profiles.get(proxy) or {}).get("asn_country") or "").upper()

    def _choose_from(self, candidates, want_country=""):
        """Берёт случайный из топа.

        Порядок: сначала health score, потом совпадение страны с доменом
        получателя, потом скорость, потом нагрузка на выходной IP.

        Про страну. Почтовики смотрят, откуда пришло письмо: проверять
        немецкий домен через бразильский адрес — лишний повод для отказа.
        Совпадение стоит ниже health score осознанно: мёртвый прокси из
        нужной страны бесполезнее живого из соседней.

        Про нагрузку. Считается по ВЫХОДНОМУ IP: десять прокси с общим
        выходом жгут репутацию одного адреса, и при прочих равных выбор
        уходит на менее нагруженный.
        """
        if not candidates or not hasattr(candidates, "__iter__"):
            return None
        want = (want_country or "").upper()

        def primary(proxy):
            """Ключи, по которым уступать нельзя: здоровье и страна."""
            return (-self._proxy_scores.get(proxy, 0),
                    0 if (want and self._proxy_country(proxy) == want) else 1)

        def secondary(proxy):
            """Ключи, по которым разброс допустим: скорость и нагрузка."""
            return (self._proxy_latency.get(proxy) or UNKNOWN_LATENCY_MS,
                    self.ip_load(proxy))

        candidates = list(candidates)
        if not candidates:
            return None

        # Случайность нужна, чтобы не бить одним прокси в один сервер, но она
        # не имеет права отменять предпочтение. Раньше здесь брались первые
        # пять по рангу и выбирался случайный из них — и на пуле из двух
        # прокси «первые пять» это ВЕСЬ пул, то есть ранжирование не работало
        # вовсе: прокси нужной страны выигрывал сортировку и тут же проигрывал
        # монетке. Теперь разброс идёт ТОЛЬКО среди равных по здоровью и стране.
        best = min(primary(p) for p in candidates)
        equals = [p for p in candidates if primary(p) == best]

        equals.sort(key=secondary)

        # Отсечение по трети остаётся жёстким: заведомо медленные прокси не
        # должны получать шанс вообще, иначе прогон растягивается на них же.
        top = equals[:max(5, len(equals) // 3)]

        # А вот ВНУТРИ среза раньше стоял равновероятный выбор, и на маленьком
        # пуле это обнуляло ранжирование: «первые пять» из двух прокси — оба,
        # то есть быстрый ненагруженный решался монеткой наравне с медленным
        # перегруженным. Вес по месту в ранге чинит именно это, не трогая
        # отсечение: лучший берётся чаще, но разброс внутри среза сохраняется.
        weights = [1.0 / (rank + 1) for rank in range(len(top))]
        return random.choices(top, weights=weights, k=1)[0]

    def _pick_best_proxy(self, need_ptr=False, need_clean=False, want_country=""):
        """Выбирает живой прокси с наивысшим health score (п.8).

        need_ptr=True  — только прокси с обратным DNS (для Yahoo/AOL/Verizon).
                         Если таких нет, возвращает None: идти без PTR бессмысленно.
        need_ptr=False — предпочитает прокси БЕЗ PTR, чтобы не расходовать
                         дефицитные PTR-прокси там, где они не нужны.
                         Если остались только PTR-прокси, берёт их.

        Возвращает None, если прокси не заданы вообще ИЛИ все забанены.
        Вызывающий код обязан различать эти случаи через has_proxies_configured().
        """
        if not self.proxies:
            return None
        with self._proxy_score_lock:
            # Забаненные прокси не воскрешаем — они выбыли навсегда
            alive = [p for p in self.proxies if p not in self._proxy_banned]
            if not alive:
                return None

            # Профилирование не проводилось — разделения нет, берём из общего пула.
            # ВАЖНО: проверяем именно факт профилирования, а не пустоту _ptr_proxies.
            # Раньше стояло "if not self._ptr_proxies", и когда подтверждённых PTR
            # не находилось, вся логика need_ptr обходилась: для Yahoo выбирался
            # прокси с ТОЧНО отсутствующим PTR — гарантированный холостой ход.
            if not self._profiled:
                return self._choose_from(alive, want_country)

            with_ptr = [p for p in alive if p in self._ptr_proxies]
            without_ptr = [p for p in alive if p not in self._ptr_proxies]

            if need_ptr:
                # Сначала подтверждённые PTR; если таких нет — пробуем те, что
                # проверить не удалось. Прокси с ТОЧНО отсутствующим PTR не берём
                # никогда: Yahoo отошьёт их на MAIL FROM, это гарантированный холостой ход.
                pool = with_ptr or [p for p in alive if p in self._ptr_unknown]
                # Прямая проба перевешивает вывод по PTR в обе стороны:
                # подтверждённо принятые идут первыми, подтверждённо
                # отвергнутые выбывают, даже если PTR у них в порядке.
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

            # Бережём PTR-прокси: для обычных доменов они не нужны
            pool = without_ptr or with_ptr
            if need_clean:
                # Outlook/iCloud/GMX режут по репутации — берём только чистые.
                # Если чистых не осталось, идём грязными: лучше попытка, чем ничего.
                pool = [p for p in pool if p not in self._dirty_proxies] or pool
            return self._choose_from(pool, want_country)

    def has_proxies_configured(self):
        """True, если пользователь загрузил прокси (независимо от того, живы ли они)."""
        return bool(self.proxies)

    def get_live_proxy_count(self):
        with self._proxy_score_lock:
            return len([p for p in self.proxies if p not in self._proxy_banned])

    def all_proxies_dead(self):
        return bool(self.proxies) and self.get_live_proxy_count() == 0

    def _mx_delay(self, mx_host):
        """Пауза перед запросом к MX. Растёт с числом полученных от него 421.

        Раньше пауза была фиксированной (0.1–0.4 с), и весь «back-off» сводился
        к разовому понижению параллельности 5 → 2 → 1. Но сервер, ответивший
        421, просит именно ПОДОЖДАТЬ. Теперь мы отступаем и по времени:
        экспоненциально, с потолком в 8 секунд, чтобы не подвесить прогон.
        """
        base = random.uniform(0.1, 0.4)
        if not isinstance(mx_host, str) or not mx_host:
            return base
        with self._mx_error_lock:
            errors = self._mx_error_counts.get(mx_host.lower(), 0)
        if not errors:
            return base
        return min(base * (2 ** min(errors, 5)), 8.0)

    def _update_proxy_score(self, proxy, success: bool, mx_record=None):
        """Обновляет health score прокси и банит его после N сбоев подряд (п.8).

        ВАЖНО про бан. Считать сбои только по прокси нельзя: наблюдалось, как
        рабочий прокси получил три таймаута подряд на ОДНОМ тугом MX и вылетел
        из ротации навсегда — а с ним встала и проверка DNS, которая тоже идёт
        через прокси. Три сбоя на одном сервере означают, что мёртв сервер;
        мёртвым прокси считается тот, кто сыпется на РАЗНЫХ серверах.
        """
        if not proxy:
            return
        with self._proxy_score_lock:
            if proxy not in self._proxy_scores:
                self._proxy_scores[proxy] = 0
                self._proxy_consecutive_fails[proxy] = 0
            if success:
                self._proxy_scores[proxy] += 1
                self._proxy_consecutive_fails[proxy] = 0  # Ожил — счётчик подряд сбрасываем
                self._proxy_fail_hosts.pop(proxy, None)
                return

            self._proxy_scores[proxy] -= 3  # Штраф за неудачу в 3 раза больше
            self._proxy_consecutive_fails[proxy] = self._proxy_consecutive_fails.get(proxy, 0) + 1

            hosts = self._proxy_fail_hosts.setdefault(proxy, set())
            if isinstance(mx_record, str) and mx_record:
                hosts.add(mx_record.lower())

            if self._proxy_consecutive_fails[proxy] < PROXY_MAX_CONSECUTIVE_FAILS:
                return

            # Сбои неизвестно на чём (сам прокси не поднялся) — банить можно.
            # Сбои, все до одного пришедшиеся на один сервер, — вина сервера.
            if not hosts or len(hosts) >= 2:
                self._proxy_banned.add(proxy)

    def check_dnsbl_ip(self, ip):
        """Проверяет ГОТОВЫЙ IP по чёрным спискам (без резолва имени).

        Нужна для прокси: там уже известен выходной IP, резолвить нечего.
        Листингом считается только 127.0.0.x / 127.0.1.x — см. check_dnsbl.
        """
        if not isinstance(ip, str) or not ip:
            return False
        with self._dnsbl_lock:
            if ip in self._dnsbl_cache:
                return self._dnsbl_cache[ip]

        # Spamhaus спрашиваем первым: он крупнейший, и положительный ответ
        # избавляет от опроса остальных семи зон.
        spamhaus = self._spamhaus_lists(ip)
        if spamhaus is True:
            with self._dnsbl_lock:
                self._dnsbl_cache[ip] = True
            return True

        result = False
        unreachable = 0
        reversed_ip = '.'.join(reversed(ip.split('.')))
        for bl in DNSBL_ZONES:
            try:
                answers = self.resolver.resolve(f"{reversed_ip}.{bl}", 'A')
                for rdata in answers:
                    code = rdata.to_text()
                    if code.startswith('127.0.0.') or code.startswith('127.0.1.'):
                        result = True
                        break
                if result:
                    break
            except DNSUnavailable:
                unreachable += 1
                continue
            except Exception:
                continue

        # Ни одна зона не ответила из-за DNS — это не «чисто», это «не спросили».
        # Не кэшируем, иначе первый же сбой закрепит False на весь прогон.
        if not result and unreachable == len(DNSBL_ZONES):
            return False

        with self._dnsbl_lock:
            self._dnsbl_cache[ip] = result
        return result

    def check_dnsbl(self, mx_host):
        """True = IP сервера реально в чёрном списке.

        ВАЖНО про коды ответов: листингом считается только 127.0.0.x / 127.0.1.x.
        Ответы вида 127.255.255.x — это НЕ листинг, а отказ самого блэклиста
        ("запрос с публичного DNS отклонён", "превышен лимит"). Раньше любой
        ответ трактовался как листинг, и при некоторых DNS каждый почтовый
        сервер получал -40 баллов ни за что.
        """
        with self._dnsbl_lock:
            if mx_host in self._dnsbl_cache:
                return self._dnsbl_cache[mx_host]

        result = False
        unreachable = 0
        try:
            ip = str(self.resolver.resolve(mx_host, 'A')[0])
            reversed_ip = '.'.join(reversed(ip.split('.')))
            for bl in DNSBL_ZONES:
                try:
                    answers = self.resolver.resolve(f"{reversed_ip}.{bl}", 'A')
                    for rdata in answers:
                        code = rdata.to_text()
                        if code.startswith('127.0.0.') or code.startswith('127.0.1.'):
                            result = True
                            break
                    if result:
                        break
                except DNSUnavailable:
                    unreachable += 1
                    continue
                except Exception:
                    continue  # Не в этом списке либо список не ответил
        except DNSUnavailable:
            return False  # Даже A-запись не спросили — вывода нет, не кэшируем
        except Exception:
            result = False

        if not result and unreachable == len(DNSBL_ZONES):
            return False

        with self._dnsbl_lock:
            self._dnsbl_cache[mx_host] = result
        return result

    def check_fcrdns(self, ip):
        """Forward-Confirmed reverse DNS для IP-адреса.

        Yahoo и AOL отшивают на MAIL FROM ошибкой 5.7.25 любой IP, у которого:
          - нет PTR-записи, ЛИБО
          - имя из PTR не резолвится обратно на этот же IP.
        Без FCrDNS проверить почту на Yahoo/AOL физически нельзя — нас не пускают
        до этапа RCPT. С FCrDNS всё работает как у остальных провайдеров.

        True  = FCrDNS в порядке, Yahoo/AOL пустят
        False = FCrDNS нет, Yahoo/AOL отошьют
        None  = проверить не удалось
        """
        if not ip:
            return None
        with self._fcrdns_lock:
            if ip in self._fcrdns_cache:
                return self._fcrdns_cache[ip]

        result = None
        try:
            rev_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(rev_name, 'PTR')
            hostname = str(ptr_answers[0]).rstrip('.')

            # Ключевой шаг: имя из PTR должно резолвиться ОБРАТНО на тот же IP
            forward = self.resolver.resolve(hostname, 'A')
            result = any(str(a) == ip for a in forward)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result = False  # PTR нет вовсе, либо имя никуда не резолвится
        except Exception:
            result = None   # DNS не ответил — вывода сделать нельзя

        # Неудачу не кэшируем: хороший прокси не должен вылететь из пула Yahoo
        # из-за одного таймаута DNS.
        if result is None:
            return None

        with self._fcrdns_lock:
            self._fcrdns_cache[ip] = result
        return result

    def get_ptr_hostname(self, ip):
        """Возвращает имя из PTR-записи IP или None.

        Нужно, чтобы посмотреть НА САМО ИМЯ: почтовики штрафуют хосты вида
        vpn-exit-12.host.net или pool-71-105.fios.verizon.net даже при
        валидном FCrDNS — по имени видно, что это не почтовый сервер.
        """
        if not isinstance(ip, str) or not ip:
            return None
        with self._ptr_lock:
            key = "name:" + ip
            if key in self._ptr_cache:
                return self._ptr_cache[key]
        name = None
        try:
            rev = dns.reversename.from_address(ip)
            name = str(self.resolver.resolve(rev, 'PTR')[0]).rstrip('.')
        except Exception:
            name = None
        with self._ptr_lock:
            self._ptr_cache["name:" + ip] = name
        return name

    def check_ptr(self, mx_host):
        """True = PTR есть, False = PTR точно нет, None = проверить не удалось.

        None важен: раньше любой сбой DNS выглядел как "PTR отсутствует"
        и почта незаслуженно получала штраф в скоринге.
        """
        with self._ptr_lock:
            if mx_host in self._ptr_cache:
                return self._ptr_cache[mx_host]
        try:
            ip_answers = self.resolver.resolve(mx_host, 'A')
            ip = str(ip_answers[0])
            rev_name = dns.reversename.from_address(ip)
            self.resolver.resolve(rev_name, 'PTR')
            result = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result = False
        except Exception:
            result = None
        if result is None:
            return None  # «не проверено» не кэшируем — иначе сбой станет вечным
        with self._ptr_lock:
            self._ptr_cache[mx_host] = result
        return result

    def get_mx_records(self, domain: str):
        """Ищет MX-записи домена, с фоллбэком на A и AAAA (RFC 5321, п.1.4).

        Возвращает:
          [хосты] — куда слать
          []      — записей нет, домен действительно мёртвый
          None    — СПРОСИТЬ НЕ УДАЛОСЬ (DNS через прокси не ответил)

        Различие между [] и None критично: без него сбой DNS выглядел бы как
        «домена не существует», и живой домен уехал бы в Invalid целиком.
        """
        domain = to_ascii_domain(domain)
        if not domain:
            return []

        with self.mx_lock:
            if domain in self.mx_cache:
                return self.mx_cache[domain]

        dns_failed = False

        try:
            answers = self.resolver.resolve(domain, 'MX')
            records = sorted(answers, key=lambda x: x.preference)

            # 1.1 Null MX Check (RFC 7505)
            if len(records) == 1 and records[0].preference == 0 and str(records[0].exchange) in ['.', '']:
                with self.mx_lock:
                    self.mx_cache[domain] = []
                return []

            result = [str(record.exchange).rstrip('.') for record in records]
            if result:
                with self.mx_lock:
                    self.mx_cache[domain] = result
                return result
        except DNSUnavailable:
            dns_failed = True
        except Exception:
            pass

        # Фоллбэк на A-запись (п.1.4): если MX нет — пробуем сам домен как mail-сервер
        try:
            self.resolver.resolve(domain, 'A')
            # A-запись существует — используем сам домен как почтовый сервер
            result = [domain]
            with self.mx_lock:
                self.mx_cache[domain] = result
            return result
        except DNSUnavailable:
            dns_failed = True
        except Exception:
            pass

        # Фоллбэк на AAAA-запись (IPv6) — п.1 DNS +1 балл
        try:
            self.resolver.resolve(domain, 'AAAA')
            result = [domain]
            with self.mx_lock:
                self.mx_cache[domain] = result
            return result
        except DNSUnavailable:
            dns_failed = True
        except Exception:
            pass

        # DNS не ответил — вывода о домене сделать нельзя. Не кэшируем:
        # иначе один сбой похоронил бы домен на весь прогон.
        if dns_failed:
            return None

        # Ни MX, ни A, ни AAAA — домен мёртвый
        with self.mx_lock:
            self.mx_cache[domain] = []
        return []

    def check_dns_health(self, domain: str, mx_record: str = "") -> dict:
        """
        Проверяет DNS-здоровье домена: наличие SPF, DMARC и DKIM записей (п.2.2+).
        Возвращает {'has_spf': bool, 'has_dmarc': bool, 'has_dkim': bool, 'score': int}
        score: 0 = ничего, 1 = один из трёх, 2 = два из трёх, 3 = все три

        mx_record сужает перебор DKIM-селекторов: если домен сидит на Google,
        селектор точно гугловский, и остальные два десятка спрашивать незачем.
        Через прокси каждый лишний DNS-запрос стоит заметно дороже.
        """
        with self._dns_health_lock:
            if domain in self._dns_health_cache:
                return self._dns_health_cache[domain]

        has_spf = False
        has_dmarc = False
        has_dkim = False
        dns_failed = False

        # Проверяем SPF (TXT-запись с v=spf1)
        try:
            txt_answers = self.resolver.resolve(domain, 'TXT')
            for rdata in txt_answers:
                txt_str = str(rdata).lower()
                if 'v=spf1' in txt_str:
                    has_spf = True
                    break
        except DNSUnavailable:
            dns_failed = True
        except Exception:
            pass

        # Проверяем DMARC (TXT-запись на _dmarc.domain)
        try:
            dmarc_answers = self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in dmarc_answers:
                txt_str = str(rdata).lower()
                if 'v=dmarc1' in txt_str:
                    has_dmarc = True
                    break
        except DNSUnavailable:
            dns_failed = True
        except Exception:
            pass

        # Проверяем DKIM (п.2 DNS-здоровье +1 балл) — пробуем популярные селекторы
        # Селекторы DKIM. Универсального способа их узнать нет — имя выбирает
        # владелец домена, в DNS оно не перечислено. Раньше список был короче,
        # и крупнейшие провайдеры давали ложное "DKIM нет": у Gmail селектор
        # 20230601, у Mail.ru — mailru, ни того ни другого в списке не было,
        # поэтому Gmail и Mail.ru никогда не получали +10 за полный DNS.
        dkim_selectors = _dkim_selectors_for(mx_record)
        for selector in dkim_selectors:
            try:
                dkim_answers = self.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                for rdata in dkim_answers:
                    txt_str = str(rdata).lower()
                    if 'v=dkim1' in txt_str or 'p=' in txt_str:
                        has_dkim = True
                        break
                if has_dkim:
                    break
            except DNSUnavailable:
                # DNS недоступен — перебирать остальные 20+ селекторов бессмысленно
                dns_failed = True
                break
            except Exception:
                continue

        score = int(has_spf) + int(has_dmarc) + int(has_dkim)
        result = {'has_spf': has_spf, 'has_dmarc': has_dmarc, 'has_dkim': has_dkim, 'score': score}

        # DNS не ответил и ничего не нашли — это «не проверили», а не «записей нет».
        # Кэшировать такой нуль нельзя: домен навсегда остался бы без бонуса.
        if dns_failed and score == 0:
            return result

        with self._dns_health_lock:
            self._dns_health_cache[domain] = result

        return result

    def _is_server_outdated(self, banner_text: str) -> bool:
        """
        Анализирует SMTP-баннер и определяет, устарел ли почтовый сервер.
        Устаревшие серверы (Postfix 2.x, Exim 4.6x, Sendmail 8.13 и т.д.)
        часто означают заброшенную инфраструктуру → меньше шансов на живого пользователя.
        """
        if not banner_text:
            return False
        if not isinstance(banner_text, str):
            return False
        b = banner_text.lower()
        
        import re
        
        # Postfix 2.x (вышел ~2005-2012, давно не поддерживается)
        if re.search(r'postfix\s*2\.\d', b):
            return True
        # Postfix 3.0-3.2 (2015-2017, устарели)
        if re.search(r'postfix\s*3\.[012]\b', b):
            return True
        
        # Exim 4.6x-4.7x (2006-2012)
        if re.search(r'exim\s*4\.[67]\d', b):
            return True
        
        # Sendmail 8.1x (2005-2010)
        if re.search(r'sendmail\s*8\.1[0-4]', b):
            return True
        
        # Courier MTA (очень старый)
        if 'courier' in b and re.search(r'courier\s*0\.\d', b):
            return True
        
        # hMailServer (популярный на Windows, часто необновляемый)
        if re.search(r'hmailserver\s*[0-4]\.', b):
            return True
        
        # Qmail (не обновляется с 2007 года)
        if 'qmail' in b:
            return True
            
        return False

    def _make_smtp_connection(self, proxy=None):
        """Создает SMTP соединение — либо через прокси, либо напрямую."""
        if proxy:
            parsed = _parse_proxy(proxy)
            if not parsed:
                raise ValueError("Неверный формат прокси")
            ip, port, user, password = parsed
            # Подключаемся тем же протоколом, которым прокси был проверен
            return SocksSMTP(ip, port, proxy_user=user, proxy_pass=password, timeout=self.timeout,
                             proxy_type=_PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5))
        else:
            return smtplib.SMTP(timeout=self.timeout)

    def _parse_smtp_response(self, code, message, email, domain):
        """
        Расшифровывает SMTP-ответ сервера максимально точно.
        Глубокий анализ баннеров (п.3 SMTP +4 балла).
        Возвращает словарь {'status': ..., 'reason': ...}
        """
        try:
            code = int(code)
        except (TypeError, ValueError):
            return {"status": "unknown", "reason": "Некорректный ответ сервера"}
        msg = message.decode('utf-8', 'ignore').lower() if isinstance(message, bytes) else str(message).lower()

        enhanced_match = re.search(r'(\d\.\d+\.\d+)\s', msg)
        enhanced_prefix = f"{enhanced_match.group(1)} " if enhanced_match else ""

        def make_result(st, reason):
            return {"status": st, "reason": enhanced_prefix + reason}

        if code == 250:
            return make_result("valid", "250 OK")

        # Переполненный ЯЩИК — доказательство, что он существует и активно используется.
        # Но переполнен может быть и СЕРВЕР: "452 4.3.1 Insufficient system storage"
        # означает, что на почтовике кончилось место на диске, и про ящик не говорит
        # ничего. Раньше подстрочный матч по "storage" стоял выше разбора кодов и
        # ловил любой код, из-за чего такие ответы уезжали в valid с бонусом +70.
        if code in (452, 552):
            if "insufficient system storage" in msg or "system storage" in msg:
                return make_result("unknown", f"{code} Server Out Of Disk Space")
            if ("over quota" in msg or "mailbox full" in msg or "quota exceeded" in msg
                    or "mailbox is full" in msg or code == 552):
                return make_result("valid", "250 OK (Full Inbox)")

        # 550 — самый информативный код, парсим текст детально
        if code == 550:
            # Сначала проверяем: наш IP/домен заблокирован? (НЕ значит что почта мёртва!)
            if any(x in msg for x in ["spam", "policy", "blocked", "denied",
                                       "blacklist", "rbl", "dnsbl", "spamhaus",
                                       "barracuda", "listed", "reputation", "client host"]):
                return make_result("unknown", "550 Our IP Blocked (Email May Exist)")
            # Отвергнут ОТПРАВИТЕЛЬ (наш MAIL FROM / прокси), а не получатель.
            # О существовании ящика это не говорит ничего.
            if any(x in msg for x in ["sender", "relay", "relaying", "not permitted",
                                       "unable to relay", "sender verify", "spf",
                                       "dmarc", "dkim", "helo", "ehlo", "authentication",
                                       "not authorized", "access denied"]):
                return make_result("unknown", "550 Sender/Relay Rejected (Email May Exist)")
            # 550 с временной формулировкой сам себе противоречит: код постоянный,
            # а текст говорит «приходи позже». Такое пишут перегруженные и
            # неверно настроенные серверы, и ящик за этим обычно живой.
            # Проверка стоит ВЫШЕ разбора текста: без неё "550 5.2.1 mailbox
            # temporarily unavailable" попадал в общую ветку по слову "mailbox"
            # и хоронил живой ящик.
            if _looks_transient(msg):
                return make_result("risky", "550 Временный отказ с постоянным кодом (ящик не проверен)")
            # Однозначно мёртв — ящик не существует
            if any(x in msg for x in ["does not exist", "not exist", "no such user",
                                       "invalid address", "user unknown", "unknown user",
                                       "bad destination", "no mailbox", "mailbox not found",
                                       "recipient rejected", "address rejected",
                                       "undeliverable", "unknown recipient",
                                       "no account", "mailbox unavailable",
                                       "mailbox not available", "no such recipient",
                                       "invalid recipient", "invalid mailbox",
                                       "user not found", "account has been disabled or discontinued"]):
                return make_result("invalid", "550 User Does Not Exist")
            # Аккаунт заморожен — физически есть, но недоступен
            if any(x in msg for x in ["disabled", "deactivated", "suspended", "frozen",
                                       "locked", "closed", "inactive account"]):
                return make_result("risky", "550 Account Disabled/Suspended")
            # Про получателя — но хоронить можно только при явном отрицании.
            #
            # Раньше здесь стояло просто «упомянут recipient/mailbox/user/address ->
            # invalid». Под это попадало всё подряд: "mailbox is full at this time",
            # "user busy", "address deferred". Слово о получателе само по себе
            # ничего не доказывает — доказывает ОТРИЦАНИЕ рядом с ним.
            if any(x in msg for x in ["recipient", "mailbox", "user", "address"]):
                if any(neg in msg for neg in _RECIPIENT_NEGATIONS):
                    return make_result("invalid", "550 Recipient Rejected")
                return make_result("risky", "550 Упомянут получатель без явного отрицания (не доказано)")
            # Голый "550 Rejected" без объяснений — НЕ доказательство смерти ящика.
            # Через прокси это чаще всего отказ по IP/отправителю, поэтому не хороним лид.
            return make_result("risky", "550 Rejected (Ambiguous)")

        if code == 551:
            return make_result("invalid", "551 User Not Local")

        if code == 553:
            return make_result("invalid", "553 Bad Address Format")

        if code == 554:
            if any(x in msg for x in ["spam", "blacklist", "blocked", "rbl", "dnsbl",
                                       "reputation", "not allowed"]):
                # Наш IP заблокирован — НЕ значит что почта мертва
                return make_result("unknown", "554 Our IP Blacklisted (Email May Exist)")
            return make_result("unknown", "554 Transaction Failed")

        # Временные ошибки (Greylisting / Server Busy) — email МОЖЕТ быть валидным
        if code == 450:
            if "grey" in msg or "greylist" in msg:
                return make_result("greylisted", "450 Greylisted (Retry Later)")
            if "try again" in msg or "later" in msg or "busy" in msg or "temporarily" in msg:
                return make_result("greylisted", "450 Greylisted (Retry Later)")
            if "rate" in msg or "too many" in msg or "throttl" in msg:
                return make_result("unknown", "450 Rate Limited (Retry Later)")
            return make_result("unknown", "450 Temp Unavailable")

        if code == 451:
            if "grey" in msg or "greylist" in msg or "try again" in msg:
                return make_result("greylisted", "451 Greylisted (Retry Later)")
            return make_result("greylisted", "451 Server Error")

        if code == 452:
            if "full" in msg or "quota" in msg or "over" in msg:
                # Ящик существует, просто сервер занят!
                return make_result("valid", "452 OK (Mailbox Full)")
            if "too many" in msg or "recipients" in msg:
                return make_result("unknown", "452 Too Many Recipients")
            return make_result("unknown", "452 Temp Error")

        # 421 — сервер перегружен или нас выкидывает (adaptive rate limiting)
        if code == 421:
            return make_result("unknown", "421 Service Busy (Rate Limit)")

        # Протокольные/серверные 5xx — это НЕ приговор ящику.
        # 500-504: сервер не понял нашу команду. 521: сервер вообще не принимает почту.
        # 530/535: требуется/провалена авторизация. 571: доставка не разрешена (блок по IP).
        # Ни один из них не означает "получателя не существует".
        if code in (500, 501, 502, 503, 504, 521, 530, 535, 571):
            return make_result("unknown", f"{code} Server/Auth Error (Email May Exist)")

        if code >= 500 and code < 600:
            # Неизвестный 5xx: постоянная ошибка, но без доказательства отсутствия ящика.
            return make_result("risky", f"{code} Permanent Error (Unverified)")

        if code >= 400 and code < 500:
            return make_result("unknown", f"{code} Temp Error")

        return make_result("unknown", f"{code} Unknown Response")

    def _do_single_ping(self, email, mx_record, proxy=None, from_email=None,
                        control_probe=False):
        """
        Делает один SMTP-пинг к серверу с Rate Limiting + adaptive (п.3.3+п.5).
        Возвращает {'status': ..., 'reason': ...}

        control_probe=True добавляет второй RCPT с выдуманным адресом в ТОЙ ЖЕ
        сессии, если первый вернул 250. Это ловит catch-all, который отдельная
        тройная проба пропустила (она могла сорваться на прокси, и её неудача
        читается как «не catch-all»). Лишних подключений при этом ноль.
        """
        # ЗАЩИТА ОТ УТЕЧКИ IP: если пользователь загрузил прокси, но все они выбыли,
        # НЕЛЬЗЯ молча ходить напрямую — это раскроет реальный IP. Честно сообщаем.
        if proxy is None and self.has_proxies_configured():
            return {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}

        # Ротация MAIL FROM (п.3.2)
        from_addr = from_email or random.choice(MAIL_FROM_POOL)
        domain = email.split("@")[1].lower() if "@" in email else ""
        server = None

        # Пауза перед запросом. Растёт, если этот сервер уже отвечал 421.
        #
        # Спим ДО захвата семафора, а не после. Раньше было наоборот, и слот
        # параллельности простаивал всё время сна: при back-off до 8 секунд и
        # пяти слотах на MX это резало пропускную способность к серверу до
        # пяти запросов за восемь секунд. Пауза при этом никуда не делась —
        # каждый поток по-прежнему выдерживает свою, — но ждёт он в стороне,
        # не занимая очередь.
        time.sleep(self._mx_delay(mx_record))

        # Rate Limiting: ждём своей очереди к этому MX-серверу (п.3.3)
        sem = self._get_mx_semaphore(mx_record)
        sem.acquire()

        # И к самому прокси: без этого при 300 потоках и пяти прокси в каждый
        # летело по 60 соединений, дешёвый SOCKS5 рвал связь и получал бан
        # за сбои, которых сам не совершал.
        slot = self.proxy_slot(proxy)
        if slot is not None:
            slot.acquire()

        try:
            # Обращение через выходной IP — считаем нагрузку на его репутацию
            self.note_ip_use(proxy)

            server = self._make_smtp_connection(proxy)
            banner_code, banner_msg = server.connect(mx_record, 25)
            
            # Сохраняем SMTP-баннер для анализа версии сервера
            banner_text = banner_msg.decode('utf-8', 'ignore') if isinstance(banner_msg, bytes) else str(banner_msg)

            # Сначала EHLO, если ошибка - фоллбэк на HELO
            try:
                ehlo_code, ehlo_msg = server.ehlo(self.helo_name)
                if ehlo_code >= 500:
                    server.helo(self.helo_name)
            except Exception:
                ehlo_msg = b""
                server.helo(self.helo_name)

            # Проверка STARTTLS
            has_starttls = False
            try:
                if server.has_extn('starttls'):
                    has_starttls = True
            except Exception:
                ehlo_str = ehlo_msg.decode('utf-8', 'ignore').lower() if isinstance(ehlo_msg, bytes) else str(ehlo_msg).lower()
                if 'starttls' in ehlo_str:
                    has_starttls = True

            # Если сервер отверг САМ MAIL FROM (репутация прокси, SPF, требование авторизации),
            # то последующий RCPT вернёт вводящий в заблуждение код вроде "503 Bad sequence",
            # который раньше молча превращался в "невалидный ящик". Проверяем явно.
            mail_code, mail_msg = server.mail(from_addr)
            if mail_code >= 400:
                mail_text = mail_msg.decode('utf-8', 'ignore') if isinstance(mail_msg, bytes) else str(mail_msg)
                low = mail_text.lower()

                # Отдельно распознаём FCrDNS: это НЕ проблема почты и не проблема
                # прокси-соединения — у исходящего IP просто нет обратного DNS.
                # Так Yahoo/AOL отшивают всех до этапа RCPT.
                if "5.7.25" in mail_text or "reverse dns" in low or "forward-confirmed" in low:
                    reason = ("550 Нет обратного DNS у нашего IP (FCrDNS) — "
                              "Yahoo/AOL не пускают. Нужен прокси с PTR-записью.")
                else:
                    reason = f"{mail_code} MAIL FROM Rejected (Email May Exist): {mail_text[:40]}"
                    self._update_proxy_score(proxy, False, mx_record=mx_record)  # Похоже на проблему прокси/IP

                return {
                    "status": "unknown",
                    "reason": reason,
                    "smtp_banner": banner_text,
                    "server_outdated": self._is_server_outdated(banner_text),
                    "has_starttls": has_starttls,
                }

            code, message = server.rcpt(email)

            result = self._parse_smtp_response(code, message, email, domain)

            # Контрольный RCPT в ТОЙ ЖЕ сессии.
            #
            # Сервер ответил 250 — но это ничего не значит, если он отвечает 250
            # на что угодно. Тройная проба catch-all делается ОТДЕЛЬНЫМ
            # подключением и до этого момента могла сорваться на прокси, а её
            # неудача трактуется как «не catch-all». Здесь мы спрашиваем прямо
            # в открытой сессии: соединение уже установлено, MAIL FROM принят,
            # и лишняя команда RCPT стоит одного пакета.
            #
            # Оба 250 — домен принимает любой адрес, и Valid ничего не доказывает.
            if control_probe and result["status"] == "valid" and domain:
                fake = f"{_generate_random_local('uuid')}@{domain}"
                try:
                    ctl_code, _ctl_msg = server.rcpt(fake)
                except Exception:
                    ctl_code = None
                if ctl_code is not None and 200 <= ctl_code < 300:
                    result["status"] = "catchall"
                    result["reason"] = ("Catch-All: сервер принял и выдуманный адрес "
                                        "в той же сессии")
                    with self.catchall_lock:
                        self.catchall_cache[domain] = True
                elif ctl_code is not None and ctl_code >= 500:
                    # Выдуманный адрес отвергнут — сервер отвечает честно, и
                    # 250 на реальный адрес это подтверждённый живой ящик.
                    with self.catchall_lock:
                        self.catchall_cache.setdefault(domain, False)
                    result["control_rcpt"] = "rejected"

            # Добавляем информацию о баннере для Engagement Score
            result["smtp_banner"] = banner_text
            result["server_outdated"] = self._is_server_outdated(banner_text)
            result["has_starttls"] = has_starttls

            # Adaptive Rate Limiting (п.5): если 421 — записываем ошибку для этого MX
            if code == 421:
                self._record_mx_error(mx_record)

            self._update_proxy_score(proxy, True)  # Прокси жив
            return result

        except smtplib.SMTPServerDisconnected:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": "Server Disconnected"}
        except socket.timeout:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": "Timeout"}
        except socks.ProxyConnectionError:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": "Proxy Dead"}
        except smtplib.SMTPConnectError:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": "SMTP Connect Error"}
        except smtplib.SMTPException as e:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": f"SMTP Error: {str(e)[:50]}"}
        except Exception as e:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": f"Error: {str(e)[:50]}"}
        finally:
            sem.release()  # Освобождаем слот для следующего потока
            if slot is not None:
                slot.release()
            if server:
                try:
                    server.quit()
                except Exception:
                    pass

    def _probe_recipients(self, addresses, mx_record, proxy=None, from_email=None):
        """Проверяет НЕСКОЛЬКО адресов в ОДНОЙ SMTP-сессии.

        Раньше тройная проба catch-all делала три отдельных подключения
        (connect + quit на каждое). На новом домене три коннекта подряд —
        быстрый путь к ограничению со стороны сервера. Здесь мы соединяемся
        один раз и шлём три RCPT TO, что и дешевле, и незаметнее.

        Возвращает список результатов той же формы, что и _do_single_ping.
        Досрочно прекращает перебор, если сервер отвалился.
        """
        if proxy is None and self.has_proxies_configured():
            fail = {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}
            return [dict(fail) for _ in addresses]

        from_addr = from_email or random.choice(MAIL_FROM_POOL)
        domain = addresses[0].split("@")[1].lower() if addresses and "@" in addresses[0] else ""
        results = []
        server = None

        # Та же причина, что и в _do_single_ping: сон не должен занимать слот.
        time.sleep(self._mx_delay(mx_record))

        sem = self._get_mx_semaphore(mx_record)
        sem.acquire()
        try:
            server = self._make_smtp_connection(proxy)
            server.connect(mx_record, 25)
            try:
                ehlo_code, _ = server.ehlo(self.helo_name)
                if ehlo_code >= 500:
                    server.helo(self.helo_name)
            except Exception:
                server.helo(self.helo_name)

            mail_code, mail_msg = server.mail(from_addr)
            if mail_code >= 400:
                text = mail_msg.decode('utf-8', 'ignore') if isinstance(mail_msg, bytes) else str(mail_msg)
                self._update_proxy_score(proxy, False, mx_record=mx_record)
                fail = {"status": "unknown",
                        "reason": f"{mail_code} MAIL FROM Rejected: {text[:40]}"}
                return [dict(fail) for _ in addresses]

            for address in addresses:
                code, message = server.rcpt(address)
                results.append(self._parse_smtp_response(code, message, address, domain))
                if code == 421:
                    self._record_mx_error(mx_record)
                    break
            self._update_proxy_score(proxy, True)
        except Exception as e:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            results.append({"status": "unknown", "reason": f"Error: {type(e).__name__}"})
        finally:
            sem.release()
            if server:
                try:
                    server.quit()
                except Exception:
                    pass

        while len(results) < len(addresses):
            results.append({"status": "unknown", "reason": "Сессия оборвалась"})
        return results

    def postmaster_is_honored(self, domain, mx_record):
        """Принимает ли сервер postmaster@ — то есть можно ли верить его 550.

        RFC 5321 §4.5.1 обязывает каждый принимающий почту домен обслуживать
        адрес postmaster@. Сервер, который отвечает на него 550, нарушает
        обязательный пункт стандарта — и его отказ РЕАЛЬНОМУ адресу после
        этого не доказывает ничего: так же он отвечает всем подряд.

        True  — postmaster принят, вердиктам сервера можно верить
        False — postmaster отвергнут, 550 этого сервера ничего не значит
        None  — спросить не удалось (в этом случае поведение прежнее)

        Стоит одной сессии на домен и кэшируется. Спрашиваем только перед тем,
        как похоронить адрес: на остальных путях это лишняя трата.
        """
        if not domain:
            return None
        with self._postmaster_lock:
            if domain in self._postmaster_cache:
                return self._postmaster_cache[domain]

        results = self._probe_recipients([f"postmaster@{domain}"], mx_record,
                                         proxy=self._pick_best_proxy())
        if not results:
            return None
        status = results[0].get("status")
        if status in ("valid", "catchall"):
            verdict = True
        elif status == "invalid":
            verdict = False
        else:
            # Таймаут, мёртвый прокси, отказ по репутации — вывода нет.
            # Не кэшируем: иначе один сбой навсегда лишил бы домен проверки.
            return None

        with self._postmaster_lock:
            self._postmaster_cache[domain] = verdict
        return verdict

    def is_catch_all_domain(self, domain, mx_record) -> bool:
        """
        Проверяет, является ли домен Catch-All (принимает любой адрес).
        Три разных паттерна — два коротких и UUID-подобный — в ОДНОЙ сессии.
        Результат кэшируется.
        """
        with self.catchall_lock:
            if domain in self.catchall_cache:
                return self.catchall_cache[domain]

        fakes = [
            f"{_generate_random_local('short')}@{domain}",
            f"{_generate_random_local('short')}@{domain}",
            f"{_generate_random_local('uuid')}@{domain}",
        ]
        results = self._probe_recipients(fakes, mx_record, proxy=self._pick_best_proxy())

        for result in results:
            # Проба сорвалась (мёртвый прокси, таймаут) — вывода сделать нельзя.
            # НЕ кэшируем: иначе catch-all домен потом молча выдаст Valid на всё.
            if result["status"] == "unknown":
                return False
            # Хоть один выдуманный адрес отвергнут — домен точно не catch-all
            if result["status"] != "valid":
                with self.catchall_lock:
                    self.catchall_cache[domain] = False
                return False

        with self.catchall_lock:
            self.catchall_cache[domain] = True
        return True

    def stealth_smtp_ping(self, email: str, mx_records: list,
                          control_probe=False) -> dict:
        """
        Умный SMTP-пинг с повторными попытками, мульти-MX фоллбэком (п.3.1),
        и кастомной логикой для проблемных почтовиков.

        control_probe пробрасывается в _do_single_ping: при 250 на реальный
        адрес в той же сессии проверяется выдуманный. См. там же почему.
        """
        domain = email.split("@")[1].lower() if "@" in email else ""

        # Yahoo/AOL/Verizon требуют обратный DNS у исходящего IP. Прокси без PTR
        # они отшивают на MAIL FROM, до проверки адреса дело не доходит — поэтому
        # для них берём только PTR-прокси, а остальным доменам PTR не нужен.
        needs_ptr = domain in YAHOO_DOMAINS or domain in AOL_DOMAINS
        needs_clean = domain in NEEDS_CLEAN_IP_DOMAINS

        # Страна домена получателя: при прочих равных берём прокси оттуда же.
        # Проверять web.de через бразильский адрес — лишний повод для отказа.
        want_country = country_code_for_domain(domain)
        if needs_ptr and self.proxies and self._ptr_proxies and not self.has_ptr_proxies():
            return {
                "status": "unknown",
                "reason": ("Нет прокси с обратным DNS (PTR) — Yahoo/AOL проверить нечем. "
                           "Нужен прокси или VPS с PTR-записью."),
            }

        # Yahoo/AOL: увеличиваем лимит попыток, они часто сбрасывают соединение
        if domain in YAHOO_DOMAINS or domain in AOL_DOMAINS:
            max_retries = 15 if self.proxies else 3
        elif domain in MICROSOFT_DOMAINS:
            max_retries = 8 if self.proxies else 2
        else:
            max_retries = 10 if self.proxies else 1

        last_result = {"status": "unknown", "reason": "No Response"}

        # Общий дедлайн на АДРЕС. Без него лимит попыток действовал на каждый MX
        # по отдельности: у yahoo.com три MX, то есть до 45 попыток, и при глухих
        # прокси один адрес мог занять несколько минут. Теперь сколько бы ни было
        # MX, дольше дедлайна на одном адресе не сидим.
        deadline = time.monotonic() + self.address_deadline

        # Мульти-MX: пробуем все MX-серверы по очереди (п.3.1) + smart proxy selection (п.8)
        for mx_record in mx_records:
            if time.monotonic() > deadline:
                break
            for attempt in range(max_retries):
                # Прокси кончились — повторять бессмысленно, только время тратить
                if self.all_proxies_dead():
                    return {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}

                if time.monotonic() > deadline:
                    last_result = {
                        "status": "unknown",
                        "reason": f"Timeout: адрес проверялся дольше {self.address_deadline}с",
                    }
                    break

                proxy = self._pick_best_proxy(need_ptr=needs_ptr,
                                              need_clean=needs_clean,
                                              want_country=want_country)
                result = self._do_single_ping(email, mx_record, proxy=proxy,
                                              control_probe=control_probe)

                # Если получили однозначный ответ — возвращаем сразу
                if result["status"] in ("valid", "invalid"):
                    return result

                # Отказ пришёл по репутации нашего IP — значит повторять
                # «следующим по списку» бессмысленно, нужен заведомо чистый.
                # Причина известна точно, глупо ею не воспользоваться.
                if _looks_like_ip_reputation(result.get("reason", "")):
                    needs_clean = True

                # Если greylisted — запоминаем и пробуем ещё
                if result["status"] == "greylisted":
                    last_result = result
                    continue

                # Для unknown — пробуем ещё раз со следующим прокси
                last_result = result
                continue

            # Однозначный ответ (valid/invalid) уже возвращён выше через return,
            # поэтому сюда мы попадаем только с unknown/greylisted и честно
            # пробуем следующий MX.

        return last_result

    def check_email(self, email: str) -> dict:
        """Полная сетевая проверка почты с RFC-валидацией, Catch-All детектором и DNS-здоровьем."""

        # Шаг 0: Проверка синтаксиса (п.1.3). IDN проходит — см. validate_email_syntax.
        if not validate_email_syntax(email):
            return {"status": "invalid", "reason": "Bad Syntax (RFC 5322)", "mx_record": "N/A"}

        # Не-ASCII локальная часть законна (RFC 6531), но `RCPT TO` с ней не
        # отправить: команда кодируется в ASCII. Это «не проверили», а не «мёртв».
        if has_non_ascii_local(email):
            return {"status": "unknown",
                    "reason": "Не-ASCII локальная часть (SMTPUTF8) — RCPT отправить нельзя",
                    "mx_record": "N/A"}

        local_part, _, raw_domain = email.rpartition("@")
        domain = to_ascii_domain(raw_domain.lower())
        if not domain:
            return {"status": "invalid", "reason": "Invalid Domain (IDNA Error)", "mx_record": "N/A"}

        # На проводе домен всегда в punycode: ivan@почта.рф -> ivan@xn--80a1acny.xn--p1ai
        probe_email = f"{local_part}@{domain}"

        # Шаг 1: DNS / MX Check (с A-фоллбэком — п.1.4)
        mx_records = self.get_mx_records(domain)
        if mx_records is None:
            # DNS не ответил через прокси. Домен НЕ мёртв — мы просто не спросили.
            return {"status": "unknown",
                    "reason": "DNS не удалось спросить через прокси (домен не проверен)",
                    "mx_record": "N/A"}
        if not mx_records:
            return {"status": "invalid", "reason": "No MX/A records (Dead Domain)", "mx_record": "N/A"}

        # Шаг 2: Защита от попадания в Blacklist (AV Honeypot-ловушки)
        av_vendors = [
            "fireeye.com",
            "phishline.com", "perimeterwatch.com",
            "agari.com", "emailsecurity.trendmicro.com"
        ]
        for mx in mx_records:
            mx_lower = mx.lower()
            if any(vendor in mx_lower for vendor in av_vendors):
                return {"status": "trap", "reason": "AV Vendor (Dangerous)", "mx_record": mx}

        primary_mx = mx_records[0]

        # Шаг 2.5: Почтовый шлюз безопасности перед доменом.
        # Proofpoint, Mimecast, IronPort и прочие принимают ЛЮБОЙ адрес и
        # фильтруют письмо позже — домен за таким шлюзом catch-all по
        # конструкции. Тройная проба выяснит то же самое, но потратит три
        # подключения и не объяснит причину.
        gateway = security_gateway(mx_records)
        if gateway:
            result = self.stealth_smtp_ping(probe_email, mx_records)
            if result["status"] == "valid":
                result["status"] = "catchall"
                result["reason"] = (f"Catch-All: почтовый шлюз {gateway} "
                                    "принимает любой адрес")
            result["mx_record"] = primary_mx
            result["mx_records"] = mx_records
            return result

        # Шаг 3: Catch-All проверка (не для гигантов — они точно не Catch-All)
        skip_catchall = (
            domain in YAHOO_DOMAINS or
            domain in MICROSOFT_DOMAINS or
            domain in AOL_DOMAINS or
            # ВАЖНО: mail.ru/bk.ru/inbox.ru/list.ru отсюда УБРАНЫ. Проверено вживую:
            # они отвечают 250 на любой случайный адрес, то есть являются catch-all.
            # Пока они были в этом списке, их несуществующие ящики шли как Valid.
            domain in {"gmail.com", "googlemail.com", "yandex.ru", "ya.ru",
                       "icloud.com", "me.com", "mac.com"}
        )

        if not skip_catchall:
            is_catchall = self.is_catch_all_domain(domain, primary_mx)
            if is_catchall:
                # Для Catch-All доменов: всё равно делаем пинг, но помечаем результат
                result = self.stealth_smtp_ping(probe_email, mx_records)
                if result["status"] == "valid":
                    # Сервер принял — но домен Catch-All, так что это ненадёжно
                    result["status"] = "catchall"
                    result["reason"] = "Catch-All Domain (Unverifiable)"
                result["mx_record"] = primary_mx
                result["mx_records"] = mx_records
                return result

        # Шаг 4: Обычный Stealth SMTP Ping (с мульти-MX — п.3.1).
        #
        # control_probe включаем ровно там, где тройная проба могла соврать:
        # у гигантов catch-all исключён по определению, а на обычном домене
        # её отрицательный ответ мог быть просто сорвавшейся пробой.
        result = self.stealth_smtp_ping(probe_email, mx_records,
                                        control_probe=not skip_catchall)

        # Шаг 4.5: сервер, отвергающий postmaster@, теряет право хоронить адрес.
        #
        # Проверяем ТОЛЬКО перед вердиктом invalid: это одна лишняя сессия на
        # домен, и тратить её на живые адреса незачем. Если сервер нарушает
        # обязательный пункт RFC 5321 §4.5.1, его "550 user unknown" — это не
        # доказательство отсутствия ящика, а привычка отвечать всем одинаково.
        if result["status"] == "invalid":
            honored = self.postmaster_is_honored(domain, primary_mx)
            if honored is False:
                result["status"] = "risky"
                result["reason"] = ("550, но сервер отвергает и обязательный "
                                    "postmaster@ — его отказам верить нельзя")
                result["postmaster_honored"] = False

        # Шаг 5: DNS-здоровье как бонус (п.2.2 + DKIM)
        # Если SMTP дал unknown, но DNS показывает здоровый домен — помечаем как Risky (не Unknown)
        if result["status"] in ("unknown", "greylisted"):
            dns_health = self.check_dns_health(domain)
            if dns_health["score"] >= 1:
                dns_tag = f" [DNS: SPF={'✓' if dns_health['has_spf'] else '✗'}, DMARC={'✓' if dns_health['has_dmarc'] else '✗'}, DKIM={'✓' if dns_health.get('has_dkim') else '✗'}]"
                # Домен имеет SPF/DMARC/DKIM — он точно почтовый, просто SMTP не ответил
                if result["status"] == "greylisted":
                    result["status"] = "greylisted"  # Оставляем для retry в pipeline
                    result["reason"] += dns_tag
                else:
                    result["status"] = "risky"
                    result["reason"] += dns_tag

        # Greylisted без retry оставляем как greylisted — pipeline сделает retry (п.2.4)
        if result["status"] == "greylisted":
            pass  # НЕ меняем на risky — pipeline сам перепроверит

        result["mx_record"] = primary_mx
        result["mx_records"] = mx_records
        return result
