# core/network.py
import dns.resolver
import smtplib
import socket
import random
import socks

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

def filter_live_proxies(proxies, timeout, threads=100, progress_callback=None):
    """Тестирует список прокси и возвращает только рабочие (у которых открыт 25 порт)."""
    from concurrent.futures import ThreadPoolExecutor, as_completed
    live_proxies = []
    
    total = len(proxies)
    completed = 0
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        # submit tasks instead of map to track progress as they complete
        futures = {executor.submit(check_single_proxy, p, timeout): p for p in proxies}
        
        for future in as_completed(futures):
            res = future.result()
            completed += 1
            if progress_callback:
                progress_callback(completed, total)
            if res:
                live_proxies.append(res)
            
    return live_proxies

class NetworkValidator:
    def __init__(self, from_email="check@example.com", timeout=5, proxies=None):
        self.from_email = from_email
        self.timeout = timeout
        self.proxies = proxies if proxies else []
        
        # Настройка DNS резолвера
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

    def get_mx_records(self, domain: str) -> list:
        """Ищет MX-записи для домена. Если их нет - почта физически не может существовать."""
        try:
            answers = self.resolver.resolve(domain, 'MX')
            # Сортируем серверы по приоритету (preference)
            records = sorted(answers, key=lambda x: x.preference)
            return [str(record.exchange).rstrip('.') for record in records]
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
                elif code == 451 or code == 452:
                    return {"status": "risky", "reason": f"Greylisted {code}"}
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
            return {"status": "invalid", "reason": "No MX records"}
            
        # Шаг 2: Stealth SMTP Ping (Берем самый приоритетный сервер)
        primary_mx = mx_records[0]
        result = self.stealth_smtp_ping(email, primary_mx)
        
        # Сохраняем имя MX-сервера для вывода в таблицу
        result["mx_record"] = primary_mx
        return result
