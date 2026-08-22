# -*- coding: utf-8 -*-
"""ФАЗА 3: сквозной прогон НАСТОЯЩЕГО пайплайна на реальных адресах.
Инвариант: каждый уникальный адрес на входе -> ровно один on_result на выходе.
Заодно: S4.4 автообновление списков, S2.3 WHOIS, S2.6 сайт, S5.3 скоринг, S4.6 имя/пол/страна.
"""
import sys, os, time, threading
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.pipeline import ValidationPipeline

INPUT = [
 "postmaster@gmail.com",                 # заведомо существующий
 "xd8ltnuw74w99641@gmail.com",           # заведомо несуществующий на том же домене
 "postmaster@yandex.ru",
 "dkrc37b4sykb3622@yandex.ru",
 "1ohtnnrfbj436408@mail.ru",             # catch-all домен
 "test@mailinator.com",                  # disposable
 "info@github.com",                      # role-based
 "user@nonexistent-zzq7x4m2nv8w1k.com",  # домен без MX
 "john.doe@gmail.com",                   # дубль по нормализации ->
 "johndoe@gmail.com",                    #    ... этих двоих должно схлопнуть
]
src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_input.txt")
open(src,"w",encoding="utf-8").write("\n".join(INPUT))

RESULTS = []; LOGS = []
lock = threading.Lock()
done = threading.Event()

cb = {
 'on_log':      lambda m,t="info": LOGS.append(m),
 'on_progress': lambda c,t: None,
 'on_result':   lambda e,s,r,mx,d: (lock.acquire(), RESULTS.append((e,s,r,mx,dict(d))), lock.release()),
 'on_complete': lambda: done.set(),
 'on_unique_count': lambda n: None,
}
p = ValidationPipeline(cb)
t0 = time.time()
p.start([{"type":"file","path":src}], threads=4, timeout=10, fix_typos=True, check_spam=True,
        deep_ping=True, enable_ai=False, proxies=None, enable_osint=False)
ok = done.wait(timeout=420)
dt = time.time()-t0

print("="*100); print(f"СКВОЗНОЙ ПРОГОН: завершён={ok}  время={dt:.1f}s"); print("="*100)
print("\nЛОГИ ПАЙПЛАЙНА:")
for m in LOGS: print("   ", m)

print(f"\nВХОД: {len(INPUT)} строк, уникальных после нормализации: 9")
print(f"ВЫХОД: {len(RESULTS)} результатов")
print("\n{:<38}{:<16}{:<9}{:<7}{:<44}".format("email","статус","score","grade","reason"))
print("-"*118)
for e,s,r,mx,d in sorted(RESULTS):
    print("{:<38}{:<16}{:<9}{:<7}{:<44}".format(
        e, s, str(d.get('engagement_score')), str(d.get('engagement_grade')), str(r)[:42]))
    print("        provider={} type={} name='{}' gender='{}' country='{}' gravatar={} mx={}".format(
        d.get('provider_name'), d.get('domain_type'), d.get('name'), d.get('gender'),
        d.get('country'), d.get('has_gravatar'), mx))

got = {e for e,_,_,_,_ in RESULTS}
inp = set(INPUT)
print("\n" + "="*100)
print("ИНВАРИАНТ СОХРАННОСТИ АДРЕСОВ")
print("="*100)
missing = inp - got
print(f"  адресов на входе (уникальных строк): {len(inp)}")
print(f"  адресов в результатах:               {len(got)}")
print(f"  ПОТЕРЯНО (нет ни одного результата): {len(missing) - 1} (минус 1 схлопнутый дубль) -> {missing}")
dups = len(RESULTS) - len(got)
print(f"  ДУБЛЕЙ в результатах:                {dups}")
