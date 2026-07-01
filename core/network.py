# core/network.py
import dns.resolver
import smtplib
import socket
import random
import socks
import threading

class SocksSMTP(smtplib.SMTP):
    """Custom SMTP class that routes traffic through a SOCKS5 proxy."""
    def __init__(self, proxy_ip, proxy_port, proxy_user=None, proxy_pass=None, host='', port=0, local_hostname=None, timeout=socket._GLOBAL_DEFAULT_TIMEOUT):
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

def check_single_proxy(proxy, timeout):
    try:
        proxy_clean = proxy.replace("socks5://", "").replace("socks4://", "").replace("http://", "").replace("https://", "")
        parts = proxy_clean.split(":")
        if len(parts) == 4:
            ip, port, user, password = parts
            server = SocksSMTP(ip, int(port), proxy_user=user, proxy_pass=password, timeout=timeout)
        elif len(parts) == 2:
            ip, port = parts
            server = SocksSMTP(ip, int(port), timeout=timeout)
        else:
            return None
            
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

    # We use mode="smtp" to ensure port 25 is open and responds with 220 greeting.
    live_proxies = run_async_checker(
        proxies=proxies,
        workers=threads,
        timeout=timeout,
        mode="smtp",
        progress_callback=on_prog
    )
    
    return live_proxies

class NetworkValidator:
    def __init__(self, from_email="check@example.com", timeout=5, proxies=None):
        self.from_email = from_email
        self.timeout = timeout
        self.proxies = proxies if proxies else []
        
        # Настройка DNS резолвера (используем публичные DNS для стабильности при 5000+ потоках)
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout
        
        # Кэш MX-записей (чтобы не дудосить DNS сервер 50000 запросами для одного gmail.com)
        self.mx_cache = {}
        self.mx_lock = threading.Lock()

    def get_mx_records(self, domain: str) -> list:
        """Ищет MX-записи для домена с использованием In-Memory кэша."""
        with self.mx_lock:
            if domain in self.mx_cache:
                return self.mx_cache[domain]
                
        try:
            answers = self.resolver.resolve(domain, 'MX')
            records = sorted(answers, key=lambda x: x.preference)
            result = [str(record.exchange).rstrip('.') for record in records]
            
            with self.mx_lock:
                self.mx_cache[domain] = result
            return result
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
            return []
        except Exception:
            return []

    def stealth_smtp_ping(self, email: str, mx_record: str) -> dict:
        """
        Тихий стук в сервер (Stealth Ping) с логикой повторных попыток для прокси.
        """
        # Делаем 10 попыток, если есть прокси, чтобы снизить шанс таймаута под нагрузкой
        max_retries = 10 if self.proxies else 1
        for attempt in range(max_retries):
            proxy = random.choice(self.proxies) if self.proxies else None
            
            try:
                if proxy:
                    proxy_clean = proxy.replace("socks5://", "").replace("socks4://", "").replace("http://", "").replace("https://", "")
                    parts = proxy_clean.split(":")
                    if len(parts) == 4:
                        ip, port, user, password = parts
                        server = SocksSMTP(ip, int(port), proxy_user=user, proxy_pass=password, timeout=self.timeout)
                    elif len(parts) == 2:
                        ip, port = parts
                        server = SocksSMTP(ip, int(port), timeout=self.timeout)
                    else:
                        raise ValueError("Invalid proxy format.")
                else:
                    server = smtplib.SMTP(timeout=self.timeout)
                    
                server.connect(mx_record, 25)
                server.helo(server.local_hostname or socket.getfqdn())
                server.mail(self.from_email)
                code, message = server.rcpt(email)
                server.quit()

                msg_str = message.decode('utf-8', 'ignore') if isinstance(message, bytes) else str(message)
                
                if code == 250:
                    return {"status": "valid", "reason": "250 OK"}
                elif code == 552 or "storage space" in msg_str.lower() or "over quota" in msg_str.lower():
                    # Ошибка 552 или переполненный ящик означает, что ящик ФИЗИЧЕСКИ СУЩЕСТВУЕТ!
                    return {"status": "valid", "reason": f"250 OK (Full Inbox/552)"}
                elif code == 550 and "disabled" in msg_str.lower():
                    # Аккаунт физически заблокирован/отключен самим провайдером (Google/Yahoo)
                    return {"status": "invalid", "reason": f"Disabled Account"}
                elif code >= 500:
                    return {"status": "invalid", "reason": f"{code} {msg_str}"}
                elif code in [450, 451, 452]:
                    return {"status": "risky", "reason": f"Greylisted {code}"}
                elif code >= 400 and code < 500:
                    return {"status": "risky", "reason": f"Temp Error {code} {msg_str}"}
                else:
                    return {"status": "unknown", "reason": f"{code} {msg_str}"}
                    
            except Exception as e:
                last_error = str(e)
                if isinstance(e, socks.ProxyConnectionError): last_error = "Proxy Dead"
                elif isinstance(e, smtplib.SMTPServerDisconnected): last_error = "Server Disconnected"
                elif isinstance(e, socket.timeout): last_error = "Timeout"
                
                # Если это не последняя попытка, идем на следующий круг цикла
                continue
                
        return {"status": "unknown", "reason": last_error}

    def check_email(self, email: str) -> dict:
        """Полная сетевая проверка почты."""
        if "@" not in email:
            return {"status": "invalid", "reason": "Bad syntax"}
            
        domain = email.rsplit("@", 1)[1]
        
        # Шаг 1: DNS / MX Check
        mx_records = self.get_mx_records(domain)
        if not mx_records:
            return {"status": "invalid", "reason": "No MX records", "mx_record": "N/A"}
            
        # Защита от попадания в Blacklist (Опыт Validol)
        av_vendors = ["proofpoint.com", "mimecast.com", "fireeye.com", "barracudanetworks.com", "phishline.com", "perimeterwatch.com"]
        for mx in mx_records:
            mx_lower = mx.lower()
            if any(vendor in mx_lower for vendor in av_vendors):
                return {"status": "trap", "reason": "AV Vendor (Dangerous)", "mx_record": mx}
            
        # Шаг 2: Stealth SMTP Ping (Берем самый приоритетный сервер)
        primary_mx = mx_records[0]
        result = self.stealth_smtp_ping(email, primary_mx)
        
        # Сохраняем имя MX-сервера для вывода в таблицу
        result["mx_record"] = primary_mx
        return result
