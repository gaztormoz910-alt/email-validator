# -*- coding: utf-8 -*-
"""ФАЗА 3+4: S3.5 Catch-All (сколько коннектов, кэш) и S4.1 Gravatar."""
import sys, os, socket, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')

SMTP_CONNECTS = []
_lock = threading.Lock()
_real = socket.socket.connect
def connect(self, addr):
    try:
        if addr[1] == 25:
            with _lock: SMTP_CONNECTS.append(addr[0])
    except Exception: pass
    return _real(self, addr)
socket.socket.connect = connect

from core.network import NetworkValidator
from core.gravatar import GravatarChecker

v = NetworkValidator(timeout=12)

print("="*78); print("S3.5 CATCH-ALL: тройная проверка — сколько SMTP-коннектов на домен"); print("="*78)
for dom in ["mail.ru", "gmail.com"]:
    mx = v.get_mx_records(dom)
    with _lock: SMTP_CONNECTS.clear()
    t0=time.time(); res = v.is_catch_all_domain(dom, mx[0]); dt=time.time()-t0
    with _lock: n1 = len(SMTP_CONNECTS)
    # второй вызов — работает ли кэш по домену
    with _lock: SMTP_CONNECTS.clear()
    res2 = v.is_catch_all_domain(dom, mx[0])
    with _lock: n2 = len(SMTP_CONNECTS)
    print(f"  {dom:<12} catch-all={res}  коннектов на порт 25: {n1}  за {dt:.1f}s")
    print(f"  {'':<12} повторный вызов: результат={res2}, новых коннектов={n2} "
          f"({'кэш РАБОТАЕТ' if n2==0 else 'кэша НЕТ'})")

print("\n  Проверка утверждения 'три адреса в одной сессии или тремя коннектами':")
print(f"  -> is_catch_all_domain вызывает _do_single_ping 3 раза, каждый делает")
print(f"     свой server.connect(mx,25) и server.quit() => ТРИ ОТДЕЛЬНЫХ КОННЕКТА.")

print("\n"+"="*78); print("S4.1 GRAVATAR — адверсариально"); print("="*78)
g = GravatarChecker(timeout=8)
cases = [
    ("заведомо несуществующий", "zzq7x4m2nv8w1k-nobody-here@example.invalid", False),
    ("случайный на gmail",      "xd8ltnuw74w99641@gmail.com",                 False),
    ("известный аккаунт",       "matt@automattic.com",                        None),
    ("beau@automattic.com",     "beau@automattic.com",                        None),
]
for label, addr, expect in cases:
    r = g.has_gravatar(addr)
    verdict = "" if expect is None else ("OK" if r==expect else "БАГ")
    print(f"  {label:<26} {addr:<44} -> {r}  {verdict}")
import urllib.request, hashlib
h = hashlib.md5(b"zzq7x4m2nv8w1k-nobody-here@example.invalid").hexdigest()
for u in [f"https://gravatar.com/avatar/{h}?d=404&s=1", f"https://gravatar.com/avatar/{h}?s=1"]:
    try:
        req = urllib.request.Request(u, method='HEAD'); req.add_header('User-Agent','Mozilla/5.0')
        with urllib.request.urlopen(req, timeout=8) as resp: st = resp.status
    except Exception as e: st = getattr(e, 'code', type(e).__name__)
    print(f"  сырой HTTP: {u.split('/')[-1]:<45} -> {st}")
print("  -> код использует d=404, поэтому 'аватар есть всегда' НЕ воспроизводится")

print(f"\n  LRU-кэш: лимит в коде = 50000, тип = OrderedDict, move_to_end при попадании")
g2 = GravatarChecker(timeout=1)
for i in range(3): g2.has_gravatar(f"probe{i}@example.invalid")
print(f"  после 3 проверок размер кэша = {len(g2._cache)}")
