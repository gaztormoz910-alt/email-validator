# -*- coding: utf-8 -*-
"""ФАЗА 2+4: S5.1-S5.4 скоринг — клампинг, грейды, краевые значения."""
import sys, os, itertools
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.scoring import calculate_engagement_score as S
from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS

print("="*80); print("S5.3 КЛАМПИНГ 0-100 И ГРЕЙДЫ"); print("="*80)

best = S(email="a@corp.com", smtp_status="Valid", smtp_reason="452 OK (Mailbox Full)",
         has_gravatar=True, dns_health_score=3, domain_age_days=5000,
         name_extracted="Ivan", has_ptr=True, has_starttls=True, in_dnsbl=False,
         has_live_website=True, original_smtp_status="Valid")
print(f"  МАКСИМУМ реально достижимый: {best['score']} / grade={best['grade']}")
for s in best['signals']: print(f"      {s}")

worst = S(email="xk3n9fj2q1x@corp.com", smtp_status="Risky", smtp_reason="",
          has_gravatar=False, is_disposable=True, dns_health_score=0, domain_age_days=5,
          name_extracted="", is_role_based=True, server_outdated=True,
          has_ptr=False, has_starttls=False, in_dnsbl=True, has_live_website=False,
          original_smtp_status="Risky", machine_generated=True,
          is_parked_domain=True)
print(f"\n  МИНИМУМ (все минусы + Risky): {worst['score']} / grade={worst['grade']}  "
      f"(сырая сумма была бы {20-50-20-15-10-40-10-5-5-20-30})")
print(f"  Клампинг снизу: {'РАБОТАЕТ' if worst['score']==0 else 'СЛОМАН'}")

print("\n  Проверка верхней границы искусственно завышенным входом:")
huge = S(email="a@corp.com", smtp_status="Valid", smtp_reason="Full Inbox",
         has_gravatar=True, dns_health_score=99, domain_age_days=99999,
         name_extracted="X", has_ptr=True, has_starttls=True, original_smtp_status="Valid")
print(f"    dns_health_score=99, age=99999 -> score={huge['score']} "
      f"({'клампинг сверху РАБОТАЕТ' if huge['score']<=100 else 'СЛОМАН'})")

print("\n  Границы грейдов:")
import core.scoring as sc
def grade_of(target):
    r = S(email="a@corp.com", smtp_status="Unknown", original_smtp_status="Unknown")
    return r
for b,label in [(70,"Hot"),(50,"Warm"),(30,"Neutral"),(10,"Cold"),(0,"Dead")]:
    print(f"    >= {b:>3} -> {label}")

print("\n"+"="*80); print("S5.4 ПОКРЫТИЕ: каждый сигнал влияет на балл?"); print("="*80)
BASE = dict(email="user@corp.com", smtp_status="Valid", smtp_reason="", original_smtp_status="Valid",
            has_gravatar=False, is_disposable=False, dns_health_score=0, domain_age_days=-1,
            name_extracted="", is_role_based=False, server_outdated=False, has_ptr=None,
            has_starttls=None, in_dnsbl=False, has_live_website=True,
            machine_generated=False, is_parked_domain=False)
base = S(**BASE)['score']
print(f"  База (Valid, всё остальное нейтрально) = {base}")
DELTAS = [
 ("полный ящик +70",         dict(smtp_reason="Mailbox Full")),
 ("SMTP 250 OK +55",         dict()),
 ("Risky +20",               dict(smtp_status="Risky", original_smtp_status="Risky")),
 ("Unknown +10",             dict(smtp_status="Unknown", original_smtp_status="Unknown")),
 ("Gravatar +10",            dict(has_gravatar=True)),
 ("корп.домен +5",           dict(has_ptr=True)),
 ("DNS 3/3 +10",             dict(dns_health_score=3)),
 ("DNS 2/3 +5",              dict(dns_health_score=2)),
 ("DNS 1/3 +2",              dict(dns_health_score=1)),
 ("домен >5 лет +5",         dict(domain_age_days=2000)),
 ("домен >1 года +3",        dict(domain_age_days=400)),
 ("имя +5",                  dict(name_extracted="Ivan")),
 ("disposable -50",          dict(is_disposable=True)),
 ("домен <30 дней -20",      dict(domain_age_days=10)),
 ("домен <90 дней -10",      dict(domain_age_days=60)),
 ("role-based -15",          dict(is_role_based=True)),
 ("древний сервер -10",      dict(server_outdated=True)),
 ("DNSBL -40",               dict(in_dnsbl=True)),
 ("нет PTR -10",             dict(has_ptr=False)),
 ("нет STARTTLS -5",         dict(has_starttls=False)),
 ("нет сайта -5",            dict(has_live_website=False)),
 ("машинный адрес -20",      dict(machine_generated=True)),
 ("припаркован -30",         dict(is_parked_domain=True)),
]
influential = 0
for name, over in DELTAS:
    kw = dict(BASE); kw.update(over)
    sc_ = S(**kw)['score']
    d = sc_ - base
    if d != 0: influential += 1
    print(f"    {name:<24} score={sc_:>3}  дельта={d:+d}  {'' if d else '<-- НЕ ВЛИЯЕТ'}")
print(f"  Сигналов, реально меняющих балл в этой конфигурации: {influential} из {len(DELTAS)}")

print("\n"+"="*80); print("S5.x КЛАССИФИКАЦИЯ FREE/CORPORATE (влияет на +5 и -5)"); print("="*80)
for d in ["gmail.com","yahoo.com","mail.ru","yandex.ru","protonmail.com","bk.ru",
          "qq.com","163.com","zoho.com","gmx.com","rambler.ru","tesla.com"]:
    inn = d in GLOBAL_VERIFIED_DOMAINS
    r = S(email=f"u@{d}", smtp_status="Valid", original_smtp_status="Valid",
          has_ptr=True, has_live_website=False)
    print(f"    {d:<18} in GLOBAL_VERIFIED={str(inn):<5} provider_type={r['provider_type']:<10} "
          f"score={r['score']:<4} {'<-- бесплатный провайдер считается КОРПОРАТИВНЫМ' if not inn else ''}")

print("\n"+"="*80); print("ПРОВЕРКА: Invalid обнуляет всё?"); print("="*80)
r = S(email="u@corp.com", smtp_status="Invalid/Bounce", original_smtp_status="Invalid/Bounce",
      has_gravatar=True, dns_health_score=3, domain_age_days=9000, name_extracted="Ivan")
print(f"    Invalid + все плюсы -> score={r['score']} grade={r['grade']} signals={r['signals']}")
