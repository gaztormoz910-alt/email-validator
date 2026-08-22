# -*- coding: utf-8 -*-
"""Фаза 3, шаг 0: что вообще доступно из этого окружения."""
import socket, sys, time
sys.stdout.reconfigure(encoding='utf-8')
print("="*70); print("ОГРАНИЧЕНИЯ СРЕДЫ"); print("="*70)

def probe(host, port, label):
    t0=time.time()
    try:
        s = socket.create_connection((host, port), timeout=8)
        banner = b""
        if port == 25:
            s.settimeout(8)
            try: banner = s.recv(200)
            except Exception as e: banner = f"<no banner: {e}>".encode()
        s.close()
        print(f"  OK   {label:<42} {host}:{port}  ({time.time()-t0:.1f}s) {banner[:70]}")
        return True
    except Exception as e:
        print(f"  FAIL {label:<42} {host}:{port}  {type(e).__name__}: {e}")
        return False

r25a = probe("gmail-smtp-in.l.google.com", 25, "SMTP исходящий -> Gmail MX")
r25b = probe("mta5.am0.yahoodns.net", 25, "SMTP исходящий -> Yahoo MX")
r25c = probe("mxs.mail.ru", 25, "SMTP исходящий -> Mail.ru MX")
probe("gravatar.com", 443, "HTTPS -> gravatar")
probe("rdap.org", 443, "HTTPS -> rdap.org")
probe("8.8.8.8", 53, "DNS TCP -> 8.8.8.8")

print("\n  ИТОГ порт 25:", "ДОСТУПЕН" if (r25a or r25b or r25c) else "ЗАКРЫТ -> Этап 3 и S6.1 непроверяемы вживую")

# DNS
import dns.resolver
r = dns.resolver.Resolver(); r.nameservers=['8.8.8.8','1.1.1.1']; r.timeout=5; r.lifetime=5
try:
    a = r.resolve('gmail.com','MX')
    print(f"  OK   DNS резолвинг работает: gmail.com MX = {len(a)} записей")
except Exception as e:
    print(f"  FAIL DNS резолвинг: {e}")
try:
    import whois
    print("  OK   модуль whois импортируется")
except Exception as e:
    print(f"  FAIL модуль whois: {e}")
