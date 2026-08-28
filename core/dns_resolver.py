# core/dns_resolver.py
"""DNS через прокси — последний канал, по которому утекал настоящий IP.

Обычный резолвер ходит на 8.8.8.8 напрямую по UDP, а SOCKS-прокси UDP чаще
всего не пропускает. Для валидатора это утечка не мелкая: публичный DNS видел
и адрес проверяющего, и ПОЛНЫЙ список доменов проверяемой базы — то есть
ровно то, ради сокрытия чего покупались прокси. SMTP, Gravatar, RDAP и HTTP
уже шли через прокси, а DNS оставался прямым.

Порядок попыток: DoH поверх SOCKS, обычный DNS по TCP через SOCKS, отказ.
Прямого запроса в обход прокси нет вовсе — иначе смысл теряется.

Провайдер прокси передаётся функцией: резолверу не нужно знать, откуда тот
берётся и как выбирается.
"""
import socket
import threading

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename
import socks

from core.proxy_transport import (PROXY_TYPES as _PROXY_TYPES, _parse_proxy,
                                  _proxy_scheme, build_proxy_dict)

__all__ = ["ProxiedResolver", "DNSUnavailable", "DOH_ENDPOINTS"]

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


