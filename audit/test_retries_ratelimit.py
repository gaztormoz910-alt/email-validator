# -*- coding: utf-8 -*-
"""ФАЗА 4: S3.1 (15 попыток), S3.4 (мульти-MX), S3.9 (rate limit + back-off).

Ловушка-прокси отвечает "421 busy" на RCPT — этого достаточно, чтобы цикл
повторов отработал целиком. Проверяется ЦИКЛ ПОВТОРОВ, а не SMTP-диалог,
поэтому заглушка вышестоящего сервера здесь уместна: считаем реальные
вызовы _do_single_ping настоящего кода и реальное время.
"""
import sys, os, socket, threading, time, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import NetworkValidator, YAHOO_DOMAINS, MICROSOFT_DOMAINS


class Trap(threading.Thread):
    """SOCKS5-прокси-заглушка: любой RCPT -> 421."""
    daemon = True

    def __init__(self, reply=b"421 4.7.0 too busy\r\n"):
        super().__init__()
        self.reply = reply
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(64)
        self.port = self.srv.getsockname()[1]
        self.hits = 0
        self.lock = threading.Lock()
        self.concurrent = 0
        self.max_concurrent = 0

    def run(self):
        while True:
            try:
                c, _ = self.srv.accept()
            except Exception:
                return
            threading.Thread(target=self.handle, args=(c,), daemon=True).start()

    def handle(self, c):
        with self.lock:
            self.hits += 1
            self.concurrent += 1
            self.max_concurrent = max(self.max_concurrent, self.concurrent)
        try:
            c.settimeout(8)
            head = c.recv(4)
            if head[:1] == b"\x05":
                c.sendall(b"\x05\x00")
                c.recv(512)
                c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("1.2.3.4") + struct.pack(">H", 25))
            c.sendall(b"220 trap ESMTP\r\n")
            while True:
                d = c.recv(1024)
                if not d:
                    break
                u = d.upper()
                if u.startswith(b"EHLO"):
                    c.sendall(b"250-trap\r\n250 STARTTLS\r\n")
                elif u.startswith(b"MAIL"):
                    c.sendall(b"250 ok\r\n")
                elif u.startswith(b"RCPT"):
                    c.sendall(self.reply)
                elif u.startswith(b"QUIT"):
                    c.sendall(b"221 bye\r\n")
                    break
                else:
                    c.sendall(b"250 ok\r\n")
        except Exception:
            pass
        finally:
            with self.lock:
                self.concurrent -= 1
            try:
                c.close()
            except Exception:
                pass


def count_pings(domain, mx_list, n_proxies=1, timeout=5):
    t = Trap()
    t.start()
    proxies = ["socks5://127.0.0.1:%d" % t.port for _ in range(n_proxies)]
    # чтобы прокси не забанился после 3 сбоев, ответ 421 считается успехом соединения
    v = NetworkValidator(timeout=timeout, proxies=proxies)
    calls = {"n": 0}
    real = v._do_single_ping

    def counted(*a, **k):
        calls["n"] += 1
        return real(*a, **k)
    v._do_single_ping = counted
    t0 = time.time()
    r = v.stealth_smtp_ping("user@" + domain, mx_list)
    dt = time.time() - t0
    return calls["n"], dt, r, t


print("=" * 88)
print("S3.1 / S3.4 — сколько SMTP-попыток реально делается на один адрес")
print("=" * 88)
print("  Лимиты из кода: Yahoo/AOL=15 (с прокси) / 3 (без);  Microsoft=8/2;  прочие=10/1")
print()
CASES = [
    ("yahoo.com",   ["mx1.trap", "mx2.trap", "mx3.trap"], "3 MX, лимит 15"),
    ("aol.com",     ["mx1.trap"],                          "1 MX, лимит 15"),
    ("outlook.com", ["mx1.trap"],                          "1 MX, лимит 8"),
    ("example.org", ["mx1.trap", "mx2.trap"],              "2 MX, лимит 10"),
]
for dom, mxs, note in CASES:
    n, dt, r, trap = count_pings(dom, mxs, n_proxies=3, timeout=5)
    print("  %-13s %-16s попыток=%-4d коннектов к прокси=%-4d время=%5.1fs  итог=%s"
          % (dom, note, n, trap.hits, dt, r["status"]))
    print("       => формула: len(MX) x max_retries = %d x ? = %d" % (len(mxs), n))

print()
print("  ПРОВЕРКА МЁРТВОЙ ВЕТКИ в stealth_smtp_ping:")
print("     for mx in mx_records:")
print("         for attempt in range(max_retries):   <- на valid/invalid делает return")
print("         if last_result['status'] in ('valid','invalid'): break   <- сюда")
print("            valid/invalid ПОПАСТЬ НЕ МОГУТ, они вышли по return.")
print("     => break недостижим, все MX перебираются ВСЕГДА до конца.")

print()
print("=" * 88)
print("S3.9 RATE LIMIT: семафор на КАЖДЫЙ MX отдельно или один общий?")
print("=" * 88)
v = NetworkValidator(timeout=3)
s1 = v._get_mx_semaphore("mx1.example.com")
s2 = v._get_mx_semaphore("mx2.example.com")
s1b = v._get_mx_semaphore("MX1.EXAMPLE.COM")
print("   семафор(mx1) is семафор(mx2): %s  (%s)"
      % (s1 is s2, "ОБЩИЙ — расхождение" if s1 is s2 else "РАЗНЫЕ — как заявлено"))
print("   семафор(mx1) is семафор(MX1 в верхнем регистре): %s (регистронезависимый ключ)" % (s1 is s1b))
print("   начальное значение _max_concurrent_per_mx = %d" % v._max_concurrent_per_mx)
print("   внутренний счётчик нового семафора = %d" % s1._value)

print()
print("   Реальная параллельность: 12 потоков к одному MX через ловушку")
trap = Trap(reply=b"250 ok\r\n")
trap.start()
proxy = "socks5://127.0.0.1:%d" % trap.port
v2 = NetworkValidator(timeout=8, proxies=[proxy])
ths = []
for i in range(12):
    th = threading.Thread(target=lambda: v2._do_single_ping("u%d@example.com" % i, "mx1.trap", proxy=proxy))
    ths.append(th)
for th in ths:
    th.start()
for th in ths:
    th.join()
print("   максимум одновременных соединений к одному MX: %d (лимит в коде: %d)  [%s]"
      % (trap.max_concurrent, v2._max_concurrent_per_mx,
         "OK" if trap.max_concurrent <= v2._max_concurrent_per_mx else "ЛИМИТ НАРУШЕН"))

print()
print("   Back-off на 421 — экспоненциальный?")
v3 = NetworkValidator(timeout=3)
for i in range(1, 8):
    v3._record_mx_error("mx1.example.com")
    sem = v3._get_mx_semaphore("mx1.example.com")
    print("     421 #%d -> счётчик=%d, лимит семафора=%d"
          % (i, v3._mx_error_counts["mx1.example.com"], sem._value))
print("     Задержка между запросами в _do_single_ping: time.sleep(random.uniform(0.1, 0.4))")
print("     -> ФИКСИРОВАННАЯ, от числа 421 не зависит.")
print("     => 'back-off' = только понижение параллельности 5->2->1, экспоненты нет.")
