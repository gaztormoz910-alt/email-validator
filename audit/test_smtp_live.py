# -*- coding: utf-8 -*-
"""ФАЗА 3: живой SMTP БЕЗ МОКОВ (S3.1, S3.2, S3.4, S3.7, S3.8, S2.1, S2.4).
Объём намеренно мал: по 2 адреса на домен."""
import sys, os, time, socket, json
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import NetworkValidator, _generate_random_local

v = NetworkValidator(timeout=12)   # без прокси -> прямое соединение разрешено

# 0. Наш собственный FCrDNS — от него зависит поведение Yahoo/AOL
print("="*78); print("0. FCrDNS НАШЕГО исходящего IP (S6.3 / G2)"); print("="*78)
import urllib.request
try:
    my_ip = urllib.request.urlopen("https://api.ipify.org", timeout=8).read().decode().strip()
except Exception as e:
    my_ip = None; print("  не удалось узнать внешний IP:", e)
if my_ip:
    print(f"  внешний IP: {my_ip}")
    print(f"  check_fcrdns({my_ip}) = {v.check_fcrdns(my_ip)}   (True=Yahoo/AOL пустят, False=отошьют, None=неизвестно)")

CASES = [
    ("gmail.com",        "postmaster",  "ожидаем: RCPT различает существующий/нет"),
    ("mail.ru",          "postmaster",  "в коде помечен как catch-all"),
    ("yandex.ru",        "postmaster",  "в skip_catchall"),
    ("outlook.com",      "postmaster",  "Microsoft, max_retries=2 без прокси"),
    ("yahoo.com",        "postmaster",  "требует FCrDNS (S6.3)"),
    ("aol.com",          "postmaster",  "требует FCrDNS"),
]

print("\n"+"="*78); print("1. RCPT-дискриминация: существующий vs заведомо несуществующий"); print("="*78)
results = {}
for dom, good_local, note in CASES:
    mx = v.get_mx_records(dom)
    print(f"\n--- {dom}  ({note})")
    print(f"    MX ({len(mx)}): {mx[:4]}")
    if not mx:
        print("    !! MX не получен"); continue
    bad_local = _generate_random_local('short')
    for label, local in (("СУЩЕСТВУЮЩИЙ", good_local), ("НЕСУЩЕСТВУЮЩИЙ", bad_local)):
        addr = f"{local}@{dom}"
        t0 = time.time()
        r = v.stealth_smtp_ping(addr, mx)
        dt = time.time() - t0
        results[(dom,label)] = r
        print(f"    {label:<15} {addr:<34} -> status={r.get('status'):<10} {dt:5.1f}s")
        print(f"        reason      : {r.get('reason')}")
        print(f"        starttls    : {r.get('has_starttls')}   outdated_server: {r.get('server_outdated')}")
        b = (r.get('smtp_banner') or '').replace('\n',' ')[:90]
        print(f"        banner      : {b}")
    a = results.get((dom,"СУЩЕСТВУЮЩИЙ"),{}).get('status')
    b = results.get((dom,"НЕСУЩЕСТВУЮЩИЙ"),{}).get('status')
    if a == 'valid' and b == 'invalid':
        print(f"    => ВЕРДИКТ: RCPT-верификация РАБОТАЕТ (различает {a}/{b})")
    elif a == b:
        print(f"    => ВЕРДИКТ: НЕ РАЗЛИЧАЕТ (оба '{a}') — либо catch-all, либо нас не пускают")
    else:
        print(f"    => ВЕРДИКТ: частично ({a} / {b})")

print("\n"+"="*78); print("2. S2.1 MX c фоллбэком на A-запись"); print("="*78)
for d in ["gmail.com", "example.com", "nonexistent-zzq7x4m2nv8w1k.com", "cloudflare.com"]:
    print(f"   get_mx_records({d:<36}) = {v.get_mx_records(d)[:3]}")

print("\n"+"="*78); print("3. S2.4 PTR почтового сервера (True/False/None)"); print("="*78)
for mx in ["gmail-smtp-in.l.google.com", "mxs.mail.ru", "mx.yandex.ru", "mta5.am0.yahoodns.net"]:
    print(f"   check_ptr({mx:<30}) = {v.check_ptr(mx)}")
v3 = NetworkValidator(timeout=2); v3.resolver.nameservers=['192.0.2.1']; v3.resolver.timeout=2; v3.resolver.lifetime=2
print(f"   check_ptr при мёртвом резолвере            = {v3.check_ptr('gmail-smtp-in.l.google.com')}  (ожидается None)")

print("\n"+"="*78); print("4. S2.2 DNS Health Score 0-3"); print("="*78)
for d in ["gmail.com", "github.com", "example.com"]:
    print(f"   check_dns_health({d:<14}) = {v.check_dns_health(d)}")
