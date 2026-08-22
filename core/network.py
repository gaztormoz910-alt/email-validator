# core/network.py
import dns.resolver
import dns.reversename
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

# RFC 5322 — строгая проверка синтаксиса email (п.1.3)
_RFC5322_REGEX = re.compile(
    r'^[a-zA-Z0-9]'                # Начинается с буквы или цифры
    r'[a-zA-Z0-9._%+\-]{0,63}'     # Локальная часть: до 64 символов
    r'@'
    r'[a-zA-Z0-9]'                 # Домен начинается с буквы/цифры
    r'[a-zA-Z0-9.\-]{0,251}'       # Тело домена
    r'\.[a-zA-Z]{2,}$'             # TLD минимум 2 буквы
)

_BAD_SYNTAX_PATTERNS = re.compile(
    r'(\.\.|'           # Двойные точки
    r'\.@|'             # Точка перед @
    r'@\.|'             # Точка после @
    r'\s)'              # Пробелы
)


def validate_email_syntax(email: str) -> bool:
    """Проверяет email по стандарту RFC 5322. Возвращает True если синтаксис корректен."""
    if not email or not isinstance(email, str):
        return False
    if len(email) > 320:  # RFC максимум: 64 (local) + 1 (@) + 255 (domain)
        return False
    if email.count('@') != 1:
        return False
    if _BAD_SYNTAX_PATTERNS.search(email):
        return False
    return bool(_RFC5322_REGEX.match(email))


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
    if proxy and "://" in proxy:
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
        if not proxy:
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


def check_single_proxy(proxy, timeout):
    try:
        parsed = _parse_proxy(proxy)
        if not parsed:
            return None
        ip, port, user, password = parsed
        server = SocksSMTP(ip, port, proxy_user=user, proxy_pass=password, timeout=timeout,
                           proxy_type=_PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5))
        server.connect("gmail-smtp-in.l.google.com", 25)
        server.quit()
        return proxy
    except Exception:
        return None


def split_proxies_by_fcrdns(proxies, timeout=4, workers=40, progress_callback=None):
    """Делит прокси на два пула: с обратным DNS (FCrDNS) и без него.

    Через прокси без PTR нельзя проверить Yahoo/AOL/Verizon — они отшивают такой
    IP на MAIL FROM ошибкой 5.7.25. Остальным провайдерам PTR не нужен, поэтому
    дефицитные PTR-прокси приберегаем для Yahoo.

    Возвращает (список_с_ptr, список_без_ptr).
    """
    if not proxies:
        return ([], [])

    validator = NetworkValidator(timeout=timeout)
    with_ptr = []
    without_ptr = []
    done = 0

    def check_one(p):
        parsed = _parse_proxy(p)
        if not parsed:
            return (p, False)
        return (p, validator.check_fcrdns(parsed[0]) is True)

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(proxies)))) as pool:
        for proxy, ok in pool.map(check_one, proxies):
            if ok:
                with_ptr.append(proxy)
            else:
                without_ptr.append(proxy)
            done += 1
            if progress_callback and (done % 100 == 0 or done == len(proxies)):
                progress_callback(done, len(proxies), len(with_ptr))

    return (with_ptr, without_ptr)


def filter_live_proxies(proxies, timeout, threads=100, progress_callback=None, log_callback=None):
    """Тестирует список прокси и возвращает только рабочие (у которых открыт 25 порт)."""
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
    def __init__(self, from_email="check@example.com", timeout=5, proxies=None):
        self.from_email = from_email
        self.timeout = timeout
        self.proxies = proxies if proxies else []
        # Потолок времени на ОДИН адрес, независимо от числа MX и повторов.
        # Держит прогон предсказуемым: без него адрес с тремя MX мог висеть минутами.
        self.address_deadline = max(30, min(180, timeout * 6))

        # Настройка DNS резолвера
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

        # Кэш MX-записей
        self.mx_cache = {}
        self.mx_lock = threading.Lock()

        # Кэш Catch-All доменов — чтобы не делать двойной пинг дважды для одного домена
        self.catchall_cache = {}
        self.catchall_lock = threading.Lock()

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
        # Прокси, севший MAX_CONSECUTIVE_FAILS раз ПОДРЯД, выбывает из ротации навсегда.
        # Иначе мёртвый прокси бесконечно тормозит прогон (10 повторов × таймаут на адрес).
        self._proxy_consecutive_fails = {}
        self._proxy_banned = set()
        # Прокси с обратным DNS — единственные, через кого проверяется Yahoo/AOL
        self._ptr_proxies = set()
        if self.proxies:
            for p in self.proxies:
                self._proxy_scores[p] = 0  # Начальный score = 0
                self._proxy_consecutive_fails[p] = 0

        # Случайный HELO-хост для этой сессии (выглядит как настоящий почтовый сервер)
        self.helo_name = random.choice(LEGIT_HELO_NAMES)

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
        with self._proxy_score_lock:
            self._ptr_proxies = set(ptr_proxies or [])

    def has_ptr_proxies(self):
        with self._proxy_score_lock:
            return bool(self._ptr_proxies - self._proxy_banned)

    def _choose_from(self, candidates):
        """Берёт случайный из топа по health score."""
        ranked = sorted(candidates, key=lambda p: self._proxy_scores.get(p, 0), reverse=True)
        top = ranked[:max(5, len(ranked) // 3)]
        return random.choice(top)

    def _pick_best_proxy(self, need_ptr=False):
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

            if not self._ptr_proxies:
                return self._choose_from(alive)

            with_ptr = [p for p in alive if p in self._ptr_proxies]
            without_ptr = [p for p in alive if p not in self._ptr_proxies]

            if need_ptr:
                return self._choose_from(with_ptr) if with_ptr else None

            # Бережём PTR-прокси: для обычных доменов они не нужны
            return self._choose_from(without_ptr or with_ptr)

    def has_proxies_configured(self):
        """True, если пользователь загрузил прокси (независимо от того, живы ли они)."""
        return bool(self.proxies)

    def get_live_proxy_count(self):
        with self._proxy_score_lock:
            return len([p for p in self.proxies if p not in self._proxy_banned])

    def all_proxies_dead(self):
        return bool(self.proxies) and self.get_live_proxy_count() == 0

    def _update_proxy_score(self, proxy, success: bool):
        """Обновляет health score прокси и банит его после N сбоев подряд (п.8)."""
        if not proxy:
            return
        with self._proxy_score_lock:
            if proxy not in self._proxy_scores:
                self._proxy_scores[proxy] = 0
                self._proxy_consecutive_fails[proxy] = 0
            if success:
                self._proxy_scores[proxy] += 1
                self._proxy_consecutive_fails[proxy] = 0  # Ожил — счётчик подряд сбрасываем
            else:
                self._proxy_scores[proxy] -= 3  # Штраф за неудачу в 3 раза больше
                self._proxy_consecutive_fails[proxy] = self._proxy_consecutive_fails.get(proxy, 0) + 1
                if self._proxy_consecutive_fails[proxy] >= PROXY_MAX_CONSECUTIVE_FAILS:
                    self._proxy_banned.add(proxy)

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
                except Exception:
                    continue  # Не в этом списке либо список не ответил
        except Exception:
            result = False

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

        with self._fcrdns_lock:
            self._fcrdns_cache[ip] = result
        return result

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
        with self._ptr_lock:
            self._ptr_cache[mx_host] = result
        return result

    def get_mx_records(self, domain: str) -> list:
        """Ищет MX-записи для домена. Если MX нет — фоллбэк на A-запись (RFC 5321, п.1.4)."""
        try:
            domain = domain.encode('idna').decode('ascii')
        except Exception:
            return []

        with self.mx_lock:
            if domain in self.mx_cache:
                return self.mx_cache[domain]

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
        except Exception:
            pass

        # Фоллбэк на AAAA-запись (IPv6) — п.1 DNS +1 балл
        try:
            self.resolver.resolve(domain, 'AAAA')
            result = [domain]
            with self.mx_lock:
                self.mx_cache[domain] = result
            return result
        except Exception:
            pass

        # Ни MX, ни A, ни AAAA — домен мёртвый
        with self.mx_lock:
            self.mx_cache[domain] = []
        return []

    def check_dns_health(self, domain: str) -> dict:
        """
        Проверяет DNS-здоровье домена: наличие SPF, DMARC и DKIM записей (п.2.2+).
        Возвращает {'has_spf': bool, 'has_dmarc': bool, 'has_dkim': bool, 'score': int}
        score: 0 = ничего, 1 = один из трёх, 2 = два из трёх, 3 = все три
        """
        with self._dns_health_lock:
            if domain in self._dns_health_cache:
                return self._dns_health_cache[domain]

        has_spf = False
        has_dmarc = False
        has_dkim = False

        # Проверяем SPF (TXT-запись с v=spf1)
        try:
            txt_answers = self.resolver.resolve(domain, 'TXT')
            for rdata in txt_answers:
                txt_str = str(rdata).lower()
                if 'v=spf1' in txt_str:
                    has_spf = True
                    break
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
        except Exception:
            pass

        # Проверяем DKIM (п.2 DNS-здоровье +1 балл) — пробуем популярные селекторы
        # Селекторы DKIM. Универсального способа их узнать нет — имя выбирает
        # владелец домена, в DNS оно не перечислено. Раньше список был короче,
        # и крупнейшие провайдеры давали ложное "DKIM нет": у Gmail селектор
        # 20230601, у Mail.ru — mailru, ни того ни другого в списке не было,
        # поэтому Gmail и Mail.ru никогда не получали +10 за полный DNS.
        dkim_selectors = [
            'google', '20230601', '20221208', '20210112', '20161025',   # Gmail
            'mailru', 'mail', 'dkim', 'default',                        # Mail.ru и общие
            'selector1', 'selector2',                                   # Microsoft 365
            'mx', 'yandex',                                             # Yandex
            'protonmail', 'protonmail2', 'protonmail3',                 # Proton
            'zoho', 'zmail',                                            # Zoho
            'k1', 'k2', 's1', 's2', 'sig1', 'smtp', 'key1', 'dkim1',    # прочие частые
        ]
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
            except Exception:
                continue

        score = int(has_spf) + int(has_dmarc) + int(has_dkim)
        result = {'has_spf': has_spf, 'has_dmarc': has_dmarc, 'has_dkim': has_dkim, 'score': score}

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
            # Явно про получателя, но без узнаваемой формулировки — считаем мёртвым
            if any(x in msg for x in ["recipient", "mailbox", "user", "address"]):
                return make_result("invalid", "550 Recipient Rejected")
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

    def _do_single_ping(self, email, mx_record, proxy=None, from_email=None):
        """
        Делает один SMTP-пинг к серверу с Rate Limiting + adaptive (п.3.3+п.5).
        Возвращает {'status': ..., 'reason': ...}
        """
        # ЗАЩИТА ОТ УТЕЧКИ IP: если пользователь загрузил прокси, но все они выбыли,
        # НЕЛЬЗЯ молча ходить напрямую — это раскроет реальный IP. Честно сообщаем.
        if proxy is None and self.has_proxies_configured():
            return {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}

        # Ротация MAIL FROM (п.3.2)
        from_addr = from_email or random.choice(MAIL_FROM_POOL)
        domain = email.split("@")[1].lower() if "@" in email else ""
        server = None
        ping_success = False

        # Rate Limiting: ждём своей очереди к этому MX-серверу (п.3.3)
        sem = self._get_mx_semaphore(mx_record)
        sem.acquire()

        try:
            # Небольшая задержка между запросами к одному серверу
            time.sleep(random.uniform(0.1, 0.4))

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
                    self._update_proxy_score(proxy, False)  # Похоже на проблему прокси/IP

                return {
                    "status": "unknown",
                    "reason": reason,
                    "smtp_banner": banner_text,
                    "server_outdated": self._is_server_outdated(banner_text),
                    "has_starttls": has_starttls,
                }

            code, message = server.rcpt(email)

            result = self._parse_smtp_response(code, message, email, domain)
            
            # Добавляем информацию о баннере для Engagement Score
            result["smtp_banner"] = banner_text
            result["server_outdated"] = self._is_server_outdated(banner_text)
            result["has_starttls"] = has_starttls

            # Adaptive Rate Limiting (п.5): если 421 — записываем ошибку для этого MX
            if code == 421:
                self._record_mx_error(mx_record)

            ping_success = True  # Соединение прошло (даже если ответ отрицательный)
            self._update_proxy_score(proxy, True)  # Прокси жив
            return result

        except smtplib.SMTPServerDisconnected:
            self._update_proxy_score(proxy, False)
            return {"status": "unknown", "reason": "Server Disconnected"}
        except socket.timeout:
            self._update_proxy_score(proxy, False)
            return {"status": "unknown", "reason": "Timeout"}
        except socks.ProxyConnectionError:
            self._update_proxy_score(proxy, False)
            return {"status": "unknown", "reason": "Proxy Dead"}
        except smtplib.SMTPConnectError:
            self._update_proxy_score(proxy, False)
            return {"status": "unknown", "reason": "SMTP Connect Error"}
        except smtplib.SMTPException as e:
            self._update_proxy_score(proxy, False)
            return {"status": "unknown", "reason": f"SMTP Error: {str(e)[:50]}"}
        except Exception as e:
            self._update_proxy_score(proxy, False)
            return {"status": "unknown", "reason": f"Error: {str(e)[:50]}"}
        finally:
            sem.release()  # Освобождаем слот для следующего потока
            if server:
                try:
                    server.quit()
                except Exception:
                    pass

    def is_catch_all_domain(self, domain, mx_record) -> bool:
        """
        Проверяет, является ли домен Catch-All (принимает любой адрес).
        Тройная проверка (п.4): 3 разных паттерна — short, short, UUID-style.
        Результат кэшируется.
        """
        with self.catchall_lock:
            if domain in self.catchall_cache:
                return self.catchall_cache[domain]

        # Первый случайный несуществующий адрес (короткий)
        fake_email_1 = f"{_generate_random_local('short')}@{domain}"
        result_1 = self._do_single_ping(fake_email_1, mx_record, proxy=self._pick_best_proxy())

        # Проба не удалась (мёртвый прокси, таймаут) — вывода сделать нельзя.
        # НЕ кэшируем: иначе catch-all домен потом молча выдаст "Valid" на любой адрес.
        if result_1["status"] == "unknown":
            return False

        # Если первый НЕ принят — однозначно не Catch-All
        if result_1["status"] != "valid":
            with self.catchall_lock:
                self.catchall_cache[domain] = False
            return False

        # Первый принят — проверяем вторым (другим случайным адресом)
        fake_email_2 = f"{_generate_random_local('short')}@{domain}"
        result_2 = self._do_single_ping(fake_email_2, mx_record, proxy=self._pick_best_proxy())

        if result_2["status"] == "unknown":
            return False  # Проба сорвалась — не кэшируем вывод

        if result_2["status"] != "valid":
            with self.catchall_lock:
                self.catchall_cache[domain] = False
            return False

        # Оба приняты — третья проверка с UUID-подобным адресом (совершенно другой паттерн)
        fake_email_3 = f"{_generate_random_local('uuid')}@{domain}"
        result_3 = self._do_single_ping(fake_email_3, mx_record, proxy=self._pick_best_proxy())

        if result_3["status"] == "unknown":
            return False  # Проба сорвалась — не кэшируем вывод

        # Все 3 приняты — точно Catch-All
        is_catchall = result_3["status"] == "valid"

        with self.catchall_lock:
            self.catchall_cache[domain] = is_catchall

        return is_catchall

    def stealth_smtp_ping(self, email: str, mx_records: list) -> dict:
        """
        Умный SMTP-пинг с повторными попытками, мульти-MX фоллбэком (п.3.1),
        и кастомной логикой для проблемных почтовиков.
        """
        domain = email.split("@")[1].lower() if "@" in email else ""

        # Yahoo/AOL/Verizon требуют обратный DNS у исходящего IP. Прокси без PTR
        # они отшивают на MAIL FROM, до проверки адреса дело не доходит — поэтому
        # для них берём только PTR-прокси, а остальным доменам PTR не нужен.
        needs_ptr = domain in YAHOO_DOMAINS or domain in AOL_DOMAINS
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

                proxy = self._pick_best_proxy(need_ptr=needs_ptr)
                result = self._do_single_ping(email, mx_record, proxy=proxy)

                # Если получили однозначный ответ — возвращаем сразу
                if result["status"] in ("valid", "invalid"):
                    return result

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

        # Шаг 0: Проверка синтаксиса по RFC 5322 (п.1.3)
        if not validate_email_syntax(email):
            return {"status": "invalid", "reason": "Bad Syntax (RFC 5322)", "mx_record": "N/A"}

        domain = email.rsplit("@", 1)[1].lower()
        try:
            domain = domain.encode('idna').decode('ascii')
        except Exception:
            return {"status": "invalid", "reason": "Invalid Domain (IDNA Error)", "mx_record": "N/A"}

        # Шаг 1: DNS / MX Check (с A-фоллбэком — п.1.4)
        mx_records = self.get_mx_records(domain)
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
                result = self.stealth_smtp_ping(email, mx_records)
                if result["status"] == "valid":
                    # Сервер принял — но домен Catch-All, так что это ненадёжно
                    result["status"] = "catchall"
                    result["reason"] = "Catch-All Domain (Unverifiable)"
                result["mx_record"] = primary_mx
                return result

        # Шаг 4: Обычный Stealth SMTP Ping (с мульти-MX — п.3.1)
        result = self.stealth_smtp_ping(email, mx_records)

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
        return result
