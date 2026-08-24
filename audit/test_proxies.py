# -*- coding: utf-8 -*-
"""ФАЗА 3+4: S6.1 порт 25, S6.2 совпадение протокола, S6.3 PTR-пулы, S6.4 бан прокси.

Локальный сервер-ловушка записывает ПЕРВЫЕ БАЙТЫ рукопожатия — по ним видно,
каким протоколом клиент реально заговорил. Ничего не мокаем: работает
настоящий SocksSMTP/PySocks поверх настоящего TCP.
"""
import sys, os, socket, threading, time, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import (NetworkValidator, SocksSMTP, _parse_proxy, _proxy_scheme,
                          _PROXY_TYPES, probe_proxy_target, PROXY_MAX_CONSECUTIVE_FAILS)
import socks


class TrapProxy(threading.Thread):
    """Принимает соединения, записывает рукопожатие, отвечает как рабочий прокси."""
    daemon = True

    def __init__(self):
        super().__init__()
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.log = []

    def run(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except Exception:
                return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        try:
            c.settimeout(6)
            head = c.recv(4)
            self.log.append(head)
            if not head:
                return
            if head[0] == 0x05:                       # SOCKS5 greeting
                nm = head[1]
                methods = head[2:2 + nm]
                if 0x02 in methods:
                    c.sendall(b"\x05\x02")            # требуем логин/пароль (RFC 1929)
                    c.recv(1)
                    ul = c.recv(1)[0]
                    user = c.recv(ul)
                    pl = c.recv(1)[0]
                    pw = c.recv(pl)
                    self.log.append(("AUTH", user, pw))
                    c.sendall(b"\x01\x00")
                else:
                    c.sendall(b"\x05\x00")
                req = c.recv(512)
                self.log.append(("CONNECT", req))
                c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("1.2.3.4") + struct.pack(">H", 25))
            elif head[0] == 0x04:                     # SOCKS4
                c.recv(512)
                port = struct.unpack(">H", head[2:4])[0]
                self.log.append(("SOCKS4_PORT", port))
                c.sendall(b"\x00\x5a" + b"\x00" * 6)
            else:                                     # HTTP CONNECT
                rest = head + c.recv(1024)
                self.log.append(("HTTP", rest.split(b"\r\n")[0]))
                c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            c.sendall(b"220 trap.local ESMTP ready\r\n")
            while True:
                d = c.recv(1024)
                if not d:
                    break
                if d.upper().startswith(b"QUIT"):
                    c.sendall(b"221 bye\r\n")
                    break
                c.sendall(b"250 ok\r\n")
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass


print("=" * 84)
print("S6.2 ПРОТОКОЛ ПОДКЛЮЧЕНИЯ СОВПАДАЕТ СО СХЕМОЙ")
print("=" * 84)
for scheme in ("socks5", "socks4", "http"):
    t = TrapProxy()
    t.start()
    proxy = "%s://user:pass@127.0.0.1:%d" % (scheme, t.port)
    parsed = _parse_proxy(proxy)
    v = NetworkValidator(timeout=6, proxies=[proxy])
    r = v._do_single_ping("x@example.com", "127.0.0.1", proxy=proxy)
    head = t.log[0] if t.log else b""
    if head[:1] == b"\x05":
        spoke = "SOCKS5"
    elif head[:1] == b"\x04":
        spoke = "SOCKS4"
    elif head[:4] == b"CONN":
        spoke = "HTTP"
    else:
        spoke = "?" + repr(head)
    expected = {"socks5": "SOCKS5", "socks4": "SOCKS4", "http": "HTTP"}[scheme]
    ok = (spoke == expected)
    print("  схема %-7s _parse_proxy=%s" % (scheme, parsed))
    print("     _PROXY_TYPES[%s] = %s" % (_proxy_scheme(proxy), _PROXY_TYPES.get(_proxy_scheme(proxy))))
    print("     первые байты на проводе: %r -> клиент говорил %s  [%s]"
          % (head, spoke, "OK" if ok else "РАСХОЖДЕНИЕ"))
    auths = [x for x in t.log if isinstance(x, tuple) and x[0] == "AUTH"]
    print("     RFC1929-авторизация: %s" % (auths if auths else "не запрашивалась сервером"))
    print("     результат пинга: %s / %s" % (r.get("status"), r.get("reason")))
    print()

print("=" * 84)
print("S6.1 ПРОВЕРКА ПРОКСИ ИДЁТ ПО ПОРТУ 25")
print("=" * 84)
import inspect
from core import async_proxy
srcp = inspect.getsource(async_proxy.AsyncProxyChecker.__init__)
print("   AsyncProxyChecker, ветка mode=smtp:")
for line in srcp.splitlines():
    s = line.strip()
    if "smtp" in s or "target_port" in s or "target_host" in s:
        print("     ", s)
t = TrapProxy()
t.start()
res = probe_proxy_target("socks5://u:p@127.0.0.1:%d" % t.port,
                         "gmail-smtp-in.l.google.com", 6)
print("   probe_proxy_target -> %s" % (res,))
conn = [x for x in t.log if isinstance(x, tuple) and x[0] == "CONNECT"]
if conn:
    req = conn[0][1]
    port = struct.unpack(">H", req[-2:])[0]
    host = req[5:-2].decode("utf-8", "ignore")
    print("   запрошенный через прокси адрес: host='%s' port=%d  [%s]"
          % (host, port, "OK: порт 25" if port == 25 else "РАСХОЖДЕНИЕ"))

print()
print("=" * 84)
print("S6.4 БАН ПРОКСИ ПОСЛЕ N СБОЕВ ПОДРЯД")
print("=" * 84)
v = NetworkValidator(timeout=1, proxies=["p1", "p2", "p3"])
print("   PROXY_MAX_CONSECUTIVE_FAILS = %d" % PROXY_MAX_CONSECUTIVE_FAILS)
for i in range(1, 5):
    v._update_proxy_score("p1", False)
    print("     сбой #%d: подряд=%d score=%d забанен=%s"
          % (i, v._proxy_consecutive_fails["p1"], v._proxy_scores["p1"], "p1" in v._proxy_banned))
v2 = NetworkValidator(timeout=1, proxies=["q1"])
v2._update_proxy_score("q1", False)
v2._update_proxy_score("q1", False)
v2._update_proxy_score("q1", True)
v2._update_proxy_score("q1", False)
v2._update_proxy_score("q1", False)
print("   сбой,сбой,УСПЕХ,сбой,сбой -> подряд=%d забанен=%s (%s)"
      % (v2._proxy_consecutive_fails["q1"], "q1" in v2._proxy_banned,
         "верно: сбои не подряд" if "q1" not in v2._proxy_banned else "ОШИБКА"))
v._update_proxy_score("p1", True)
print("   после УСПЕХА забаненный p1 забанен=%s (%s)"
      % ("p1" in v._proxy_banned,
         "бан навсегда — как заявлено" if "p1" in v._proxy_banned else "бан снялся — расхождение"))
for p in ("p2", "p3"):
    for _ in range(3):
        v._update_proxy_score(p, False)
print("   после бана всех: get_live_proxy_count()=%d all_proxies_dead()=%s _pick_best_proxy()=%s"
      % (v.get_live_proxy_count(), v.all_proxies_dead(), v._pick_best_proxy()))
r = v._do_single_ping("x@gmail.com", "gmail-smtp-in.l.google.com", proxy=None)
print("   _do_single_ping(proxy=None) при заданных прокси -> %s" % r)

print()
print("=" * 84)
print("S6.3 РАЗДЕЛЬНЫЕ ПУЛЫ ПО PTR")
print("=" * 84)
v = NetworkValidator(timeout=1, proxies=["ptr1", "ptr2", "plain1", "plain2", "plain3"])
v.set_ptr_proxies(["ptr1", "ptr2"])
picks_need = set(v._pick_best_proxy(need_ptr=True) for _ in range(300))
picks_norm = set(v._pick_best_proxy(need_ptr=False) for _ in range(300))
print("   need_ptr=True  -> %s  [%s]"
      % (sorted(picks_need), "OK" if picks_need <= {"ptr1", "ptr2"} else "УТЕЧКА PTR-ПУЛА"))
print("   need_ptr=False -> %s  [%s]"
      % (sorted(picks_norm),
         "OK: PTR сберегаются" if picks_norm <= {"plain1", "plain2", "plain3"} else "РАСХОЖДЕНИЕ"))
for p in ("ptr1", "ptr2"):
    for _ in range(3):
        v._update_proxy_score(p, False)
print("   после бана обоих PTR: has_ptr_proxies()=%s _pick_best_proxy(need_ptr=True)=%s"
      % (v.has_ptr_proxies(), v._pick_best_proxy(need_ptr=True)))
r = v.stealth_smtp_ping("u@yahoo.com", ["mta5.am0.yahoodns.net"])
print("   stealth_smtp_ping на yahoo.com без живых PTR-прокси -> %s: %s"
      % (r["status"], r["reason"][:90]))

print()
print("   S2.4 vs S6.3 — не перепутаны ли два разных PTR:")
print("     check_ptr(mx_host)     — PTR ПОЧТОВОГО СЕРВЕРА, идёт в скоринг (-10)")
print("     check_fcrdns(proxy_ip) — FCrDNS ВЫХОДНОГО IP, решает доступ к Yahoo/AOL")
import inspect as _i
print("     split_proxies_by_fcrdns использует: %s"
      % ("check_fcrdns" if "check_fcrdns" in _i.getsource(
          sys.modules["core.network"].split_proxies_by_fcrdns) else "check_ptr — ПЕРЕПУТАНЫ"))
print("     pipeline скоринг использует: %s"
      % ("check_ptr" if "check_ptr(mx_host)" in open("core/pipeline.py", encoding="utf-8").read()
         else "не check_ptr — ПЕРЕПУТАНЫ"))
