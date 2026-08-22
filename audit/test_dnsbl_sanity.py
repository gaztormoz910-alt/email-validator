# -*- coding: utf-8 -*-
"""ФАЗА 4: адверсариальная проверка DNSBL (S2.5).

Санити-контракт каждой зоны:
  127.0.0.2 ОБЯЗАН числиться (тестовая запись по соглашению всех DNSBL)
  127.0.0.1 ОБЯЗАН НЕ числиться
Зона, проваливающая контракт, — мёртвая либо отвечает мусором.
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
import dns.resolver
from core.network import DNSBL_ZONES

r = dns.resolver.Resolver()
r.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1']   # ровно как в NetworkValidator
r.timeout = 6; r.lifetime = 6

def raw_query(ip, zone):
    rev = '.'.join(reversed(ip.split('.')))
    q = f"{rev}.{zone}"
    try:
        ans = r.resolve(q, 'A')
        return ("ANSWER", [str(x) for x in ans])
    except dns.resolver.NXDOMAIN:
        return ("NXDOMAIN", [])
    except dns.resolver.NoAnswer:
        return ("NOANSWER", [])
    except dns.resolver.Timeout:
        return ("TIMEOUT", [])
    except Exception as e:
        return (type(e).__name__, [str(e)[:60]])

# точная копия правила листинга из core/network.py:444
def counts_as_listed(codes):
    return any(c.startswith('127.0.0.') or c.startswith('127.0.1.') for c in codes)

print("="*78)
print("DNSBL SANITY (S2.5) — резолверы 8.8.8.8/1.1.1.1, как в проде")
print("="*78)
print(f"{'зона':<26}{'127.0.0.2 (должен быть В списке)':<40}{'127.0.0.1 (НЕ в списке)'}")
print("-"*78)

verdict = {}
for z in DNSBL_ZONES:
    s2, c2 = raw_query("127.0.0.2", z)
    s1, c1 = raw_query("127.0.0.1", z)
    l2 = counts_as_listed(c2); l1 = counts_as_listed(c1)
    ok = (l2 is True and l1 is False)
    verdict[z] = dict(pos=(s2,c2,l2), neg=(s1,c1,l1), ok=ok)
    print(f"{z:<26}{s2+' '+str(c2)+' listed='+str(l2):<40}{s1+' '+str(c1)+' listed='+str(l1)}")

print("-"*78)
alive = [z for z,v in verdict.items() if v['ok']]
dead  = [z for z,v in verdict.items() if not v['ok']]
print(f"ЗОН РЕАЛЬНО РАБОТАЕТ: {len(alive)} из {len(DNSBL_ZONES)}  -> {alive}")
print(f"ЗОН НЕ РАБОТАЕТ:      {len(dead)}  -> {dead}")
for z in dead:
    v = verdict[z]
    if not v['pos'][2]:
        print(f"   {z}: на 127.0.0.2 ответ {v['pos'][0]} {v['pos'][1]} — листинг НЕ распознан "
              f"(код кодом молча уходит в 'чисто')")
    if v['neg'][2]:
        print(f"   {z}: на 127.0.0.1 ответ {v['neg'][0]} {v['neg'][1]} — ЛОЖНЫЙ ЛИСТИНГ (-40 всем подряд!)")

# Обратный сценарий: зона, отвечающая 'listed' на что попало
print("\n[ПРОВЕРКА НА ТОТАЛЬНЫЙ ЛОЖНЫЙ ЛИСТИНГ] случайные заведомо чистые IP:")
CLEAN = ["8.8.8.8", "1.1.1.1", "142.250.114.26", "17.253.144.10"]  # Google DNS, CF, Gmail MX, Apple
for z in DNSBL_ZONES:
    hits = []
    for ip in CLEAN:
        st, cd = raw_query(ip, z)
        if counts_as_listed(cd):
            hits.append((ip, cd))
    flag = "ЛОЖНЫЕ ЛИСТИНГИ!" if hits else "чисто (ok)"
    print(f"   {z:<26}{flag} {hits if hits else ''}")

# Spamhaus 127.255.255.x — отличает ли код ошибку от листинга
print("\n[SPAMHAUS ERROR CODES] проверка обработки 127.255.255.x:")
st, cd = raw_query("127.255.255.254", "zen.spamhaus.org")   # спец-код 'query via public resolver'
print(f"   zen.spamhaus.org на 127.255.255.254 -> {st} {cd}; код счёл бы листингом: {counts_as_listed(cd)}")
for probe in ["127.255.255.252","127.255.255.254","127.255.255.255"]:
    st, cd = raw_query(probe, "zen.spamhaus.org")
    print(f"   zen.spamhaus.org / {probe} -> {st} {cd} listed={counts_as_listed(cd)}")
