# -*- coding: utf-8 -*-
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import NetworkValidator
v = NetworkValidator(timeout=6)
print("="*80); print("S2.2 DNS Health по крупным доменам (DKIM ищется по 9 селекторам)"); print("="*80)
for d in ["gmail.com","yandex.ru","mail.ru","github.com","microsoft.com","outlook.com","example.com"]:
    print("   %-16s %s" % (d, v.check_dns_health(d)))
print("\n   Селекторы в коде: ['google','default','selector1','selector2','k1','mail','dkim','s1','s2']")
import dns.resolver
r = dns.resolver.Resolver(); r.nameservers=['8.8.8.8']; r.timeout=5; r.lifetime=5
print("   Реальный DKIM-селектор Gmail (20230601._domainkey.gmail.com):")
try:
    a = r.resolve("20230601._domainkey.gmail.com","TXT"); print("      НАЙДЕН:", str(a[0])[:70])
except Exception as e: print("      ", type(e).__name__)
print("   => селектора gmail нет в списке -> gmail.com получает DNS 2/3 вместо 3/3")

print("\n"+"="*80); print("S4.6 ПОЛ: работает ли с enable_ml=True"); print("="*80)
from core.parser.ml_predictor import MLPredictor
for flag in (False, True):
    mp = MLPredictor(enable_ml=flag)
    print("   enable_ml=%s" % flag)
    for n,e in [("John Doe","john.doe@gmail.com"),("Ivan Petrov","ivan.petrov@mail.ru"),
                ("Maria Garcia","maria.garcia@empresa.es"),("Anna Smith","anna@corp.com")]:
        print("      %-14s -> %s" % (n, mp.predict(n, email=e)))
