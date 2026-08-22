# -*- coding: utf-8 -*-
"""ФАЗА 4: утечка реального IP (S6.5).

Метод: НЕ мокаем логику. Оборачиваем socket.socket.connect/connect_ex и
sendto так, чтобы КАЖДОЕ реальное исходящее соединение записывалось, и
пропускаем вызов дальше. Затем прогоняем реальный код с ЗАДАННЫМ, но
заведомо мёртвым пулом прокси — то есть ровно тот сценарий, ради которого
заявлена защита "прокси кончились -> не идём напрямую".
"""
import sys, os, socket, threading, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')

CONNS = []
_lock = threading.Lock()
_real_connect = socket.socket.connect
_real_connect_ex = socket.socket.connect_ex
_real_sendto = socket.socket.sendto

def _rec(kind, addr):
    try:
        host, port = addr[0], addr[1]
    except Exception:
        host, port = str(addr), "?"
    with _lock:
        CONNS.append((kind, str(host), port))

def connect(self, addr):
    _rec("TCP", addr);  return _real_connect(self, addr)
def connect_ex(self, addr):
    _rec("TCP", addr);  return _real_connect_ex(self, addr)
def sendto(self, data, *a):
    if a: _rec("UDP", a[-1])
    return _real_sendto(self, data, *a)

socket.socket.connect = connect
socket.socket.connect_ex = connect_ex
socket.socket.sendto = sendto

from core.network import NetworkValidator
from core.gravatar import GravatarChecker
from core.pipeline import ValidationPipeline

DEAD_PROXY = ["203.0.113.9:1080"]   # RFC 5737 TEST-NET-3, гарантированно мёртв

def show(title):
    with _lock:
        got = list(CONNS); CONNS.clear()
    uniq = {}
    for k,h,p in got:
        uniq[(k,h,p)] = uniq.get((k,h,p),0)+1
    print(f"\n--- {title}")
    if not uniq:
        print("     (исходящих соединений не было)")
    for (k,h,p),n in sorted(uniq.items(), key=lambda x:-x[1]):
        via = "  <-- ЧЕРЕЗ ПРОКСИ" if h == "203.0.113.9" else ""
        print(f"     {k} {h}:{p}  x{n}{via}")
    return uniq

print("="*78)
print("S6.5 УТЕЧКА IP: пул прокси задан, но МЁРТВ. Что уходит напрямую?")
print("="*78)

v = NetworkValidator(timeout=3, proxies=list(DEAD_PROXY))
show("старт (шум игнорируем)")

print("\n[1] SMTP-путь — заявленная защита")
r = v.stealth_smtp_ping("test@gmail.com", ["gmail-smtp-in.l.google.com"])
print(f"     результат: {r.get('status')} / {r.get('reason')}")
c1 = show("соединения во время SMTP-пинга")

print("\n[2] DNS: get_mx_records / check_dns_health")
v.get_mx_records("github.com"); v.check_dns_health("github.com")
c2 = show("соединения во время DNS-проверок")

print("\n[3] DNSBL-запросы")
v.check_dnsbl("gmail-smtp-in.l.google.com")
c3 = show("соединения во время DNSBL")

print("\n[4] PTR почтового сервера")
try: v.check_ptr("mxs.mail.ru")
except Exception as e: print("     check_ptr упал:", type(e).__name__)
c4 = show("соединения во время PTR")

print("\n[5] Gravatar (S4.1)")
GravatarChecker(timeout=5).has_gravatar("someone@example.com")
c5 = show("соединения во время Gravatar")

print("\n[6] WHOIS / RDAP — возраст домена (S2.3)")
p = ValidationPipeline({'on_log':lambda *a: None})
age = p._get_domain_age_days("github.com")
print(f"     возраст github.com = {age} дней")
c6 = show("соединения во время WHOIS/RDAP")

print("\n[7] HEAD живого сайта (S2.6)")
alive = p._check_http_alive("github.com")
print(f"     живой сайт: {alive}")
c7 = show("соединения во время HTTP HEAD")

print("\n" + "="*78)
print("ИТОГ S6.5")
print("="*78)
leaks = []
for name, c in [("DNS (MX/SPF/DMARC/DKIM)",c2), ("DNSBL",c3), ("PTR",c4),
                ("Gravatar",c5), ("WHOIS/RDAP",c6), ("HTTP HEAD сайта",c7)]:
    direct = [k for k in c if k[1] != "203.0.113.9"]
    if direct:
        leaks.append(name)
        print(f"  УТЕЧКА: {name:<26} -> {len(direct)} прямых соединений мимо прокси")
smtp_direct = [k for k in c1 if k[1] != "203.0.113.9"]
print(f"  SMTP: прямых соединений мимо прокси = {len(smtp_direct)} "
      f"({'защита работает' if not smtp_direct else 'ЗАЩИТА НЕ РАБОТАЕТ'})")
print(f"\n  Каналов, раскрывающих реальный IP: {len(leaks)} из 6 -> {leaks}")
