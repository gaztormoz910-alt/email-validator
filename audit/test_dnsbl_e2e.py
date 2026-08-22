# -*- coding: utf-8 -*-
"""ФАЗА 4: end-to-end проверка check_dnsbl() БЕЗ моков.
nip.io отдаёт A-запись, равную имени: 127.0.0.2.nip.io -> 127.0.0.2
Значит check_dnsbl('127.0.0.2.nip.io') ОБЯЗАН вернуть True, если хоть одна зона жива.
"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import NetworkValidator, DNSBL_ZONES
import dns.resolver

v = NetworkValidator(timeout=6)
print("="*74); print("check_dnsbl() — сквозной прогон реального кода"); print("="*74)

for host, expect in [("127.0.0.2.nip.io", True), ("127.0.0.1.nip.io", False)]:
    try:
        ip = str(v.resolver.resolve(host, 'A')[0])
    except Exception as e:
        print(f"  {host}: не резолвится ({e}) — тест невозможен"); continue
    t0 = time.time()
    got = v.check_dnsbl(host)
    dt = time.time() - t0
    ok = "OK " if got == expect else "БАГ"
    print(f"  [{ok}] check_dnsbl({host}) A={ip} -> {got}  (ожидалось {expect})  {dt:.2f}s")

print("\n[Стоимость проверки] сколько DNS-запросов и времени тратится на мёртвые зоны:")
DEAD = ['zen.spamhaus.org', 'cbl.abuseat.org', 'dnsbl.sorbs.net']
r = dns.resolver.Resolver(); r.nameservers=['8.8.8.8','1.1.1.1']; r.timeout=6; r.lifetime=6
tot = 0
for z in DEAD:
    t0=time.time()
    try: r.resolve(f"26.114.250.142.{z}", 'A')
    except Exception: pass
    d=time.time()-t0; tot+=d
    print(f"   {z:<24} {d*1000:6.0f} ms впустую на 1 адрес")
print(f"   ИТОГО впустую: {tot*1000:.0f} ms на КАЖДЫЙ проверяемый MX (кэш по MX-хосту смягчает)")

print("\n[Реальные MX крупных провайдеров через check_dnsbl]:")
for mx in ["gmail-smtp-in.l.google.com", "mxs.mail.ru", "mx.yandex.ru"]:
    t0=time.time(); res = v.check_dnsbl(mx); print(f"   {mx:<32} in_dnsbl={res}  {time.time()-t0:.2f}s")

print("\n[Обработка сбоя DNS] что вернёт check_dnsbl, если резолвер недоступен:")
v2 = NetworkValidator(timeout=2)
v2.resolver.nameservers = ['192.0.2.1']   # RFC 5737 TEST-NET, гарантированно не отвечает
v2.resolver.timeout = 2; v2.resolver.lifetime = 2
t0=time.time(); res = v2.check_dnsbl("127.0.0.2.nip.io"); dt=time.time()-t0
print(f"   резолвер мёртв -> check_dnsbl вернул {res} за {dt:.1f}s "
      f"(ошибка запроса НЕОТЛИЧИМА от 'чисто')")
