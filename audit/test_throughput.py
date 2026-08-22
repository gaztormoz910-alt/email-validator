# -*- coding: utf-8 -*-
"""ФАЗА 4 (финал): бюджет времени на 100 000 адресов — что развалится первым."""
import sys, os, time, socket, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import NetworkValidator
from core.pipeline import ValidationPipeline
from core.gravatar import GravatarChecker

v = NetworkValidator(timeout=10)
p = ValidationPipeline({'on_log': lambda *a: None})
g = GravatarChecker(timeout=3)

DOMAINS = ["stripe.com", "shopify.com", "atlassian.com", "figma.com", "notion.so"]
print("=" * 96)
print("СТОИМОСТЬ ОДНОГО НОВОГО (некэшированного) ДОМЕНА — только сетевые проверки")
print("=" * 96)
tot = {}
for d in DOMAINS:
    row = {}
    t = time.time(); mx = v.get_mx_records(d);            row["MX"] = time.time() - t
    t = time.time(); v.check_dns_health(d);               row["DNS health (SPF/DMARC/9xDKIM)"] = time.time() - t
    if mx:
        t = time.time(); v.check_dnsbl(mx[0]);            row["DNSBL (6 зон, 3 мертвы)"] = time.time() - t
        t = time.time()
        try: v.check_ptr(mx[0])
        except Exception: pass
        row["PTR"] = time.time() - t
    t = time.time(); p._get_domain_age_days(d);           row["WHOIS/RDAP"] = time.time() - t
    t = time.time(); p._check_http_alive(d);              row["HTTP HEAD сайта"] = time.time() - t
    print("  %-16s %s   ИТОГО %.1fs" % (d, "  ".join("%s=%.1fs" % (k.split()[0], x) for k, x in row.items()),
                                        sum(row.values())))
    for k, x in row.items():
        tot[k] = tot.get(k, 0) + x

n = len(DOMAINS)
print()
print("  Среднее на домен:")
for k, x in sorted(tot.items(), key=lambda i: -i[1]):
    print("     %-34s %5.2f s" % (k, x / n))
per_domain = sum(tot.values()) / n
print("     %-34s %5.2f s  <-- суммарно на ОДИН новый домен" % ("ВСЕГО", per_domain))

print()
print("=" * 96)
print("СТОИМОСТЬ, КОТОРАЯ НЕ КЭШИРУЕТСЯ И ПЛАТИТСЯ ЗА КАЖДЫЙ АДРЕС")
print("=" * 96)
t = time.time()
for i in range(5):
    g.has_gravatar("audit-probe-%d@example.com" % i)
gt = (time.time() - t) / 5
print("  Gravatar: %.2f s/адрес (кэш по АДРЕСУ, не по домену -> на 100k это 100k HTTPS-запросов)" % gt)
print("            все они идут НАПРЯМУЮ на gravatar.com с реального IP,")
print("            унося MD5 каждого адреса базы третьей стороне.")

print()
print("=" * 96)
print("ЭКСТРАПОЛЯЦИЯ НА 100 000 АДРЕСОВ")
print("=" * 96)
for uniq_domains, label in ((2000, "база с 2 000 уникальных доменов (B2C, много gmail)"),
                            (20000, "база с 20 000 уникальных доменов (B2B)")):
    dom_cost = uniq_domains * per_domain
    grav_cost = 100000 * gt
    print("  %s:" % label)
    print("     доменные проверки: %8.0f с = %6.1f ч (последовательно) / %5.1f ч при 100 потоках"
          % (dom_cost, dom_cost / 3600, dom_cost / 3600 / 100))
    print("     Gravatar:          %8.0f с = %6.1f ч (последовательно) / %5.1f ч при 100 потоках"
          % (grav_cost, grav_cost / 3600, grav_cost / 3600 / 100))
print()
print("  SMTP-часть (замерено на ловушке, время = число попыток x стоимость попытки):")
print("     Yahoo/AOL с прокси: 3 MX x 15 повторов = 45 попыток на ОДИН адрес.")
print("     При таймауте 10 с и глухом прокси это до 450 с (7.5 мин) на адрес.")
print("     Обычный домен с прокси: len(MX) x 10. Для 5 MX Gmail — 50 попыток.")
print()
print("  Greylisting-повтор: 90 с ожидания + ОДНОПОТОЧНЫЙ перебор очереди.")
print("     При 5 %% greylisted на 100k это 5 000 адресов подряд в один поток.")
print("     При 2 с на адрес — ещё 2.8 ч ПОСЛЕ окончания основного прогона,")
print("     и всё это время в выдаче их нет вовсе.")
