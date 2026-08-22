# -*- coding: utf-8 -*-
"""ФАЗА 3: S3.7 STARTTLS (обе ветки) и S3.8 разбор баннера."""
import sys, os, socket, threading, struct
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout.reconfigure(encoding='utf-8')
from core.network import NetworkValidator

v = NetworkValidator(timeout=5)

print("=" * 92)
print("S3.8 РАЗБОР БАННЕРА — определение древних MTA")
print("=" * 92)
BANNERS = [
    ("220 mail.example.com ESMTP Postfix 2.11.3", True, "Postfix 2.x — древний"),
    ("220 mail.example.com ESMTP Postfix 3.1.4", True, "Postfix 3.0-3.2 — устарел"),
    ("220 mail.example.com ESMTP Postfix 3.8.1", False, "Postfix 3.8 — современный"),
    ("220 mail.example.com ESMTP Exim 4.69", True, "Exim 4.6x"),
    ("220 mail.example.com ESMTP Exim 4.96", False, "Exim 4.96 — современный"),
    ("220 mail.example.com Sendmail 8.13.8", True, "Sendmail 8.1x"),
    ("220 mail.example.com Sendmail 8.17.1", False, "Sendmail 8.17 — современный"),
    ("220 mail.example.com ESMTP qmail", True, "qmail — не обновляется с 2007"),
    ("220 mail.example.com hMailServer 4.2", True, "hMailServer 0-4"),
    ("220 mail.example.com Courier 0.60", True, "Courier очень старый"),
    ("220 mx.google.com ESMTP", False, "Gmail"),
    ("", False, "пустой баннер"),
    ("220 mail ESMTP Postfix", False, "Postfix без версии — не судим"),
    ("220 mail ESMTP Exim 4.94.2", False, "Exim 4.94 — версия 4.9x не в шаблоне"),
    ("220 Microsoft ESMTP MAIL Service, Version: 6.0.3790", False,
     "Exchange 2003 — древний, но НЕ распознаётся"),
    ("220 ESMTP Postfix 2.6.6 (Red Hat)", True, "Postfix 2.6"),
]
bad = 0
for b, exp, note in BANNERS:
    got = v._is_server_outdated(b)
    ok = got == exp
    if not ok:
        bad += 1
    print("  [%s] %-52s -> %-6s %s" % ("OK " if ok else "РАСХ", b[:52] or "(пусто)", got, note))
print("  Расхождений с ожиданием: %d" % bad)
print("  ПОКРЫТИЕ: шаблоны только для Postfix 2.x/3.0-3.2, Exim 4.6x-4.7x, Sendmail 8.10-8.14,")
print("  Courier 0.x, hMailServer 0-4, qmail. Старый Microsoft Exchange, Zimbra, MDaemon,")
print("  Lotus Domino, Merak, IMail — НЕ распознаются.")


class NoTlsTrap(threading.Thread):
    """SOCKS5-прокси-заглушка. advertise_tls=False -> EHLO без STARTTLS."""
    daemon = True

    def __init__(self, advertise_tls, banner=b"220 trap ESMTP Postfix 2.11.3\r\n"):
        super().__init__()
        self.tls = advertise_tls
        self.banner = banner
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]

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
            if head[:1] == b"\x05":
                c.sendall(b"\x05\x00")
                c.recv(512)
                c.sendall(b"\x05\x00\x00\x01" + socket.inet_aton("1.2.3.4") + struct.pack(">H", 25))
            c.sendall(self.banner)
            while True:
                d = c.recv(1024)
                if not d:
                    break
                u = d.upper()
                if u.startswith(b"EHLO"):
                    if self.tls:
                        c.sendall(b"250-trap\r\n250-SIZE 10240000\r\n250 STARTTLS\r\n")
                    else:
                        c.sendall(b"250-trap\r\n250 SIZE 10240000\r\n")
                elif u.startswith(b"MAIL"):
                    c.sendall(b"250 ok\r\n")
                elif u.startswith(b"RCPT"):
                    c.sendall(b"250 ok\r\n")
                elif u.startswith(b"QUIT"):
                    c.sendall(b"221 bye\r\n")
                    break
                else:
                    c.sendall(b"250 ok\r\n")
        except Exception:
            pass
        finally:
            try:
                c.close()
            except Exception:
                pass


print()
print("=" * 92)
print("S3.7 STARTTLS — обе ветки на живом TCP-диалоге")
print("=" * 92)
for tls in (True, False):
    t = NoTlsTrap(tls)
    t.start()
    proxy = "socks5://127.0.0.1:%d" % t.port
    vv = NetworkValidator(timeout=6, proxies=[proxy])
    r = vv._do_single_ping("u@example.com", "mx.trap", proxy=proxy)
    ok = (r.get("has_starttls") is tls)
    print("  сервер объявляет STARTTLS=%-5s -> has_starttls=%-5s server_outdated=%-5s  [%s]"
          % (tls, r.get("has_starttls"), r.get("server_outdated"), "OK" if ok else "РАСХОЖДЕНИЕ"))
    print("       баннер в результате: %r" % (r.get("smtp_banner") or "")[:60])
