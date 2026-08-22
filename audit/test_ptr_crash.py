# -*- coding: utf-8 -*-
"""ФАЗА 4: check_ptr() падает с UnboundLocalError (S2.4).

Причина: `import dns.reversename` стоит ВНУТРИ try, третьей строкой.
Из-за этого имя `dns` для всей функции становится ЛОКАЛЬНЫМ. Если исключение
случилось РАНЬШЕ строки импорта (упал резолв A-записи), то при вычислении
`except (dns.resolver.NXDOMAIN, ...)` имя `dns` ещё не связано -> UnboundLocalError.
Это исключение возникает в самом except-предложении, поэтому следующий
`except Exception: result = None` его НЕ ловит.
"""
import sys, os, traceback
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import NetworkValidator

print("="*78); print("S2.4  check_ptr — поведение при сбое DNS"); print("="*78)

def run(label, setup):
    v = NetworkValidator(timeout=3)
    setup(v)
    try:
        r = v.check_ptr("gmail-smtp-in.l.google.com")
        print(f"  [OK ] {label:<46} -> вернул {r}")
        return None
    except Exception as e:
        print(f"  [БАГ] {label:<46} -> ИСКЛЮЧЕНИЕ {type(e).__name__}: {e}")
        return e

def dead(v):
    v.resolver.nameservers = ['192.0.2.1']; v.resolver.timeout=2; v.resolver.lifetime=2
def ok(v):
    pass

e1 = run("резолвер недоступен (таймаут A-записи)", dead)
e2 = run("резолвер работает", ok)

print("\n  Случай 2: MX-хост без A-записи (NXDOMAIN на A):")
v = NetworkValidator(timeout=5)
try:
    r = v.check_ptr("mx-does-not-exist-zzq7x4m2nv8w1k.invalid")
    print(f"  [OK ] вернул {r}")
except Exception as e:
    print(f"  [БАГ] ИСКЛЮЧЕНИЕ {type(e).__name__}: {e}")
    e1 = e1 or e

print("\n  Случай 3: тот же баг у check_fcrdns? (там import — ПЕРВАЯ строка try)")
v2 = NetworkValidator(timeout=3); v2.resolver.nameservers=['192.0.2.1']
v2.resolver.timeout=2; v2.resolver.lifetime=2
try:
    print(f"  [OK ] check_fcrdns при мёртвом DNS -> {v2.check_fcrdns('8.8.8.8')}")
except Exception as e:
    print(f"  [БАГ] check_fcrdns -> {type(e).__name__}: {e}")

print("\n  ПОСЛЕДСТВИЕ В ПРОДЕ: pipeline.py:405-408 оборачивает вызов в")
print("      try: has_ptr = self.network.check_ptr(mx_host)")
print("      except Exception: pass")
print("  -> исключение проглатывается, has_ptr остаётся None, кэш НЕ заполняется,")
print("     значит на каждом адресе того же домена всё повторяется заново.")
print("     Сигнал S2.4 при любом сбое DNS по A-записи не вычисляется вообще.")
if e1:
    print("\n  СТЕК:")
    traceback.print_exception(type(e1), e1, e1.__traceback__, limit=3)
