# core/network.py
import dns.resolver
import smtplib
import socket
import random
import string
import socks
import threading
import re
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

# Пул правдоподобных адресов для ротации MAIL FROM (п.3.2)
MAIL_FROM_POOL = [
    "check@example.com",
    "verify@mailcheck.net",
    "postmaster@validation-service.com",
    "noreply@mx-verify.org",
    "test@mail-validator.net",
    "bounce@delivery-check.com",
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


class SocksSMTP(smtplib.SMTP):
    """Custom SMTP class that routes traffic through a SOCKS5 proxy."""
    def __init__(self, proxy_ip, proxy_port, proxy_user=None, proxy_pass=None,
                 host='', port=0, local_hostname=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
        self.proxy_ip = proxy_ip
        self.proxy_port = proxy_port
        self.proxy_user = proxy_user
        self.proxy_pass = proxy_pass
        super().__init__(host, port, local_hostname, timeout)

    def _get_socket(self, host, port, timeout):
        return socks.create_connection(
            (host, port),
            timeout=timeout,
            proxy_type=socks.SOCKS5,
            proxy_addr=self.proxy_ip,
            proxy_port=self.proxy_port,
            proxy_username=self.proxy_user,
            proxy_password=self.proxy_pass
        )


def _parse_proxy(proxy):
    """Парсит строку прокси в компоненты. Возвращает (ip, port, user, password) или None."""
    try:
        proxy_clean = proxy.replace("socks5://", "").replace("socks4://", "").replace("http://", "").replace("https://", "")
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
        server = SocksSMTP(ip, port, proxy_user=user, proxy_pass=password, timeout=timeout)
        server.connect("gmail-smtp-in.l.google.com", 25)
        server.quit()
        return proxy
    except Exception:
        return None


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
        self.dns_health_cache = {}
        self.dns_health_lock = threading.Lock()

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
        if self.proxies:
            for p in self.proxies:
                self._proxy_scores[p] = 0  # Начальный score = 0

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

    def _pick_best_proxy(self):
        """Выбирает прокси с наивысшим health score (п.8)."""
        if not self.proxies:
            return None
        with self._proxy_score_lock:
            # Отфильтровываем мёртвые прокси (score < -5)
            alive = [p for p in self.proxies if self._proxy_scores.get(p, 0) > -5]
            if not alive:
                # Все прокси мёртвые — берём случайный из оригинального списка
                return random.choice(self.proxies)
            # Сортируем по score (лучшие сверху) и берём из топ-5 случайный
            alive_sorted = sorted(alive, key=lambda p: self._proxy_scores.get(p, 0), reverse=True)
            top = alive_sorted[:max(5, len(alive_sorted) // 3)]
            return random.choice(top)

    def _update_proxy_score(self, proxy, success: bool):
        """Обновляет health score прокси (п.8)."""
        if not proxy:
            return
        with self._proxy_score_lock:
            if proxy not in self._proxy_scores:
                self._proxy_scores[proxy] = 0
            if success:
                self._proxy_scores[proxy] += 1
            else:
                self._proxy_scores[proxy] -= 3  # Штраф за неудачу в 3 раза больше

    def get_mx_records(self, domain: str) -> list:
        """Ищет MX-записи для домена. Если MX нет — фоллбэк на A-запись (RFC 5321, п.1.4)."""
        with self.mx_lock:
            if domain in self.mx_cache:
                return self.mx_cache[domain]

        try:
            answers = self.resolver.resolve(domain, 'MX')
            records = sorted(answers, key=lambda x: x.preference)
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
        with self.dns_health_lock:
            if domain in self.dns_health_cache:
                return self.dns_health_cache[domain]

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
        dkim_selectors = ['google', 'default', 'selector1', 'selector2', 'k1', 'mail', 'dkim', 's1', 's2']
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

        with self.dns_health_lock:
            self.dns_health_cache[domain] = result

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
            return SocksSMTP(ip, port, proxy_user=user, proxy_pass=password, timeout=self.timeout)
        else:
            return smtplib.SMTP(timeout=self.timeout)

    def _parse_smtp_response(self, code, message, email, domain):
        """
        Расшифровывает SMTP-ответ сервера максимально точно.
        Глубокий анализ баннеров (п.3 SMTP +4 балла).
        Возвращает словарь {'status': ..., 'reason': ...}
        """
        msg = message.decode('utf-8', 'ignore').lower() if isinstance(message, bytes) else str(message).lower()

        if code == 250:
            return {"status": "valid", "reason": "250 OK"}

        # Ящик существует, но переполнен — всё равно валидный!
        if code == 552 or "over quota" in msg or "storage" in msg or "mailbox full" in msg:
            return {"status": "valid", "reason": "250 OK (Full Inbox)"}

        # 550 — самый информативный код, парсим текст детально
        if code == 550:
            # Сначала проверяем: наш IP/домен заблокирован? (НЕ значит что почта мёртва!)
            if any(x in msg for x in ["spam", "policy", "blocked", "denied",
                                       "blacklist", "rbl", "dnsbl", "spamhaus",
                                       "barracuda", "listed", "reputation", "client host"]):
                return {"status": "unknown", "reason": "550 Our IP Blocked (Email May Exist)"}
            # Однозначно мёртв — ящик не существует
            if any(x in msg for x in ["does not exist", "not exist", "no such user",
                                       "invalid address", "user unknown", "unknown user",
                                       "bad destination", "no mailbox", "mailbox not found",
                                       "recipient rejected", "address rejected",
                                       "undeliverable", "unknown recipient",
                                       "no account", "not available"]):
                return {"status": "invalid", "reason": "550 User Does Not Exist"}
            # Аккаунт заморожен — физически есть, но недоступен
            if any(x in msg for x in ["disabled", "deactivated", "suspended", "frozen",
                                       "locked", "closed", "inactive account"]):
                return {"status": "risky", "reason": "550 Account Disabled/Suspended"}
            # Мягкий reject без объяснений
            if "rejected" in msg:
                return {"status": "invalid", "reason": "550 Rejected"}
            return {"status": "invalid", "reason": "550 Rejected"}

        if code == 551:
            return {"status": "invalid", "reason": "551 User Not Local"}

        if code == 553:
            return {"status": "invalid", "reason": "553 Bad Address Format"}

        if code == 554:
            if any(x in msg for x in ["spam", "blacklist", "blocked", "rbl", "dnsbl",
                                       "reputation", "not allowed"]):
                # Наш IP заблокирован — НЕ значит что почта мертва
                return {"status": "unknown", "reason": "554 Our IP Blacklisted (Email May Exist)"}
            return {"status": "invalid", "reason": "554 Transaction Failed"}

        # Временные ошибки (Greylisting / Server Busy) — email МОЖЕТ быть валидным
        if code == 450:
            if "grey" in msg or "greylist" in msg:
                return {"status": "greylisted", "reason": "450 Greylisted (Retry Later)"}
            if "try again" in msg or "later" in msg or "busy" in msg or "temporarily" in msg:
                return {"status": "greylisted", "reason": "450 Greylisted (Retry Later)"}
            if "rate" in msg or "too many" in msg or "throttl" in msg:
                return {"status": "greylisted", "reason": "450 Rate Limited (Retry Later)"}
            return {"status": "unknown", "reason": "450 Temp Unavailable"}

        if code == 451:
            if "grey" in msg or "greylist" in msg or "try again" in msg:
                return {"status": "greylisted", "reason": "451 Greylisted (Retry Later)"}
            return {"status": "greylisted", "reason": "451 Server Error"}

        if code == 452:
            if "full" in msg or "quota" in msg or "over" in msg:
                # Ящик существует, просто сервер занят!
                return {"status": "valid", "reason": "452 OK (Mailbox Full)"}
            if "too many" in msg or "recipients" in msg:
                return {"status": "greylisted", "reason": "452 Too Many Recipients"}
            return {"status": "greylisted", "reason": "452 Temp Error"}

        # 421 — сервер перегружен или нас выкидывает (adaptive rate limiting)
        if code == 421:
            return {"status": "unknown", "reason": "421 Service Busy (Rate Limit)"}

        if code >= 500 and code < 600:
            return {"status": "invalid", "reason": f"{code} Permanent Error"}

        if code >= 400 and code < 500:
            return {"status": "unknown", "reason": f"{code} Temp Error"}

        return {"status": "unknown", "reason": f"{code} Unknown Response"}

    def _do_single_ping(self, email, mx_record, proxy=None, from_email=None):
        """
        Делает один SMTP-пинг к серверу с Rate Limiting + adaptive (п.3.3+п.5).
        Возвращает {'status': ..., 'reason': ...}
        """
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

            # Используем правдоподобное HELO имя вместо имени ПК
            server.helo(self.helo_name)

            # Для Yahoo и AOL используем специальный EHLO (они его лучше принимают)
            if domain in YAHOO_DOMAINS or domain in AOL_DOMAINS:
                try:
                    server.ehlo(self.helo_name)
                except Exception:
                    pass

            server.mail(from_addr)
            code, message = server.rcpt(email)

            result = self._parse_smtp_response(code, message, email, domain)
            
            # Добавляем информацию о баннере для Engagement Score
            result["smtp_banner"] = banner_text
            result["server_outdated"] = self._is_server_outdated(banner_text)

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

        proxy = self._pick_best_proxy()

        # Первый случайный несуществующий адрес (короткий)
        fake_email_1 = f"{_generate_random_local('short')}@{domain}"
        result_1 = self._do_single_ping(fake_email_1, mx_record, proxy=proxy)

        # Если первый НЕ принят — однозначно не Catch-All
        if result_1["status"] != "valid":
            with self.catchall_lock:
                self.catchall_cache[domain] = False
            return False

        # Первый принят — проверяем вторым (другим случайным адресом)
        fake_email_2 = f"{_generate_random_local('short')}@{domain}"
        result_2 = self._do_single_ping(fake_email_2, mx_record, proxy=proxy)

        if result_2["status"] != "valid":
            with self.catchall_lock:
                self.catchall_cache[domain] = False
            return False

        # Оба приняты — третья проверка с UUID-подобным адресом (совершенно другой паттерн)
        fake_email_3 = f"{_generate_random_local('uuid')}@{domain}"
        result_3 = self._do_single_ping(fake_email_3, mx_record, proxy=proxy)

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

        # Yahoo/AOL: увеличиваем лимит попыток, они часто сбрасывают соединение
        if domain in YAHOO_DOMAINS or domain in AOL_DOMAINS:
            max_retries = 15 if self.proxies else 3
        elif domain in MICROSOFT_DOMAINS:
            max_retries = 8 if self.proxies else 2
        else:
            max_retries = 10 if self.proxies else 1

        last_result = {"status": "unknown", "reason": "No Response"}

        # Мульти-MX: пробуем все MX-серверы по очереди (п.3.1) + smart proxy selection (п.8)
        for mx_record in mx_records:
            for attempt in range(max_retries):
                proxy = self._pick_best_proxy()  # Используем лучший прокси вместо random
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

            # Если primary MX дал только unknown/greylisted — пробуем следующий MX (п.3.1)
            if last_result["status"] in ("valid", "invalid"):
                break

        return last_result

    def check_email(self, email: str) -> dict:
        """Полная сетевая проверка почты с RFC-валидацией, Catch-All детектором и DNS-здоровьем."""

        # Шаг 0: Проверка синтаксиса по RFC 5322 (п.1.3)
        if not validate_email_syntax(email):
            return {"status": "invalid", "reason": "Bad Syntax (RFC 5322)", "mx_record": "N/A"}

        domain = email.rsplit("@", 1)[1].lower()

        # Шаг 1: DNS / MX Check (с A-фоллбэком — п.1.4)
        mx_records = self.get_mx_records(domain)
        if not mx_records:
            return {"status": "invalid", "reason": "No MX/A records (Dead Domain)", "mx_record": "N/A"}

        # Шаг 2: Защита от попадания в Blacklist (AV Honeypot-ловушки)
        av_vendors = [
            "proofpoint.com", "mimecast.com", "fireeye.com",
            "barracudanetworks.com", "phishline.com", "perimeterwatch.com",
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
            domain in {"gmail.com", "googlemail.com", "mail.ru", "bk.ru", "inbox.ru",
                       "list.ru", "yandex.ru", "ya.ru", "icloud.com", "me.com", "mac.com"}
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
