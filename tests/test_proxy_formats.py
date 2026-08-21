"""Тесты разбора форматов прокси и авторизации SOCKS5.

Практический смысл: продавцы отдают прокси в разных форматах, и платные
почти всегда идут с логином/паролем. Если валидатор их не понимает,
пользователь платит за прокси, которые объявляются мёртвыми.
"""
import socket
import threading
import time
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.network import _parse_proxy
from core.async_proxy import run_async_checker


class TestProxyFormats(unittest.TestCase):
    def test_host_port(self):
        self.assertEqual(_parse_proxy("1.2.3.4:1080"), ("1.2.3.4", 1080, None, None))

    def test_host_port_user_pass(self):
        self.assertEqual(_parse_proxy("1.2.3.4:1080:user:pass"),
                         ("1.2.3.4", 1080, "user", "pass"))

    def test_user_pass_at_host_port(self):
        # Формат, который отдают многие продавцы
        self.assertEqual(_parse_proxy("user:pass@1.2.3.4:1080"),
                         ("1.2.3.4", 1080, "user", "pass"))

    def test_scheme_prefixes_are_stripped(self):
        for prefix in ("socks5://", "socks4://", "http://", "https://"):
            with self.subTest(prefix=prefix):
                self.assertEqual(_parse_proxy(f"{prefix}1.2.3.4:1080"),
                                 ("1.2.3.4", 1080, None, None))

    def test_scheme_with_at_credentials(self):
        self.assertEqual(_parse_proxy("socks5://user:pass@1.2.3.4:1080"),
                         ("1.2.3.4", 1080, "user", "pass"))

    def test_password_may_contain_at(self):
        # Разделяем по ПОСЛЕДНЕМУ "@", иначе пароль с "@" ломает разбор
        self.assertEqual(_parse_proxy("user:p@ss@1.2.3.4:1080"),
                         ("1.2.3.4", 1080, "user", "p@ss"))

    def test_case_preserved_in_credentials(self):
        # Логин и пароль регистрозависимы
        self.assertEqual(_parse_proxy("User:PaSS@1.2.3.4:1080"),
                         ("1.2.3.4", 1080, "User", "PaSS"))

    def test_garbage_returns_none(self):
        for bad in ["", None, "мусор", "1.2.3.4", "user@1.2.3.4:1080", "1.2.3.4:notaport"]:
            with self.subTest(bad=bad):
                self.assertIsNone(_parse_proxy(bad))


class _FakeSocks5Server:
    """Мини SOCKS5-сервер для проверки хендшейка."""

    def __init__(self, require_auth, user=b"u", password=b"p"):
        self.require_auth = require_auth
        self.user = user
        self.password = password
        self.offered_methods = None
        self.auth_ok = False
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except Exception:
            return
        try:
            head = conn.recv(2)
            self.offered_methods = list(conn.recv(head[1]))
            if self.require_auth:
                if 0x02 not in self.offered_methods:
                    conn.sendall(b"\x05\xff")
                    return
                conn.sendall(b"\x05\x02")
                conn.recv(1)
                ulen = conn.recv(1)[0]
                user = conn.recv(ulen)
                plen = conn.recv(1)[0]
                password = conn.recv(plen)
                if user != self.user or password != self.password:
                    conn.sendall(b"\x01\x01")
                    return
                self.auth_ok = True
                conn.sendall(b"\x01\x00")
            else:
                conn.sendall(b"\x05\x00")
            conn.recv(512)
            conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            conn.sendall(b"220 fake ESMTP ready\r\n")
            time.sleep(0.3)
        except Exception:
            pass
        finally:
            try:
                conn.close()
            except Exception:
                pass


class TestSocks5Auth(unittest.TestCase):
    def test_authenticated_proxy_is_detected_live(self):
        srv = _FakeSocks5Server(require_auth=True, user=b"myuser", password=b"s3cr3t")
        proxy = f"socks5://myuser:s3cr3t@127.0.0.1:{srv.port}"
        live = run_async_checker([proxy], workers=1, timeout=5, mode="smtp")
        self.assertEqual(live, [proxy])
        self.assertIn(0x02, srv.offered_methods)
        self.assertTrue(srv.auth_ok)

    def test_plain_proxy_still_works(self):
        srv = _FakeSocks5Server(require_auth=False)
        proxy = f"socks5://127.0.0.1:{srv.port}"
        live = run_async_checker([proxy], workers=1, timeout=5, mode="smtp")
        self.assertEqual(live, [proxy])
        self.assertEqual(srv.offered_methods, [0x00])

    def test_wrong_password_is_rejected(self):
        srv = _FakeSocks5Server(require_auth=True, user=b"myuser", password=b"correct")
        proxy = f"socks5://myuser:wrong@127.0.0.1:{srv.port}"
        live = run_async_checker([proxy], workers=1, timeout=5, mode="smtp")
        self.assertEqual(live, [])


if __name__ == '__main__':
    unittest.main()


class TestProxySchemeRouting(unittest.TestCase):
    """Подключаться надо тем же протоколом, которым прокси проверяли.

    Раньше тип соединения был жёстко зашит на SOCKS5, поэтому socks4/http
    прокси проходили проверку как рабочие, а на валидации отваливались.
    """

    def test_scheme_detection(self):
        from core.network import _proxy_scheme
        self.assertEqual(_proxy_scheme("1.2.3.4:1080"), "socks5")  # по умолчанию
        self.assertEqual(_proxy_scheme("socks5://1.2.3.4:1080"), "socks5")
        self.assertEqual(_proxy_scheme("socks4://1.2.3.4:1080"), "socks4")
        self.assertEqual(_proxy_scheme("http://1.2.3.4:8080"), "http")
        self.assertEqual(_proxy_scheme("HTTPS://1.2.3.4:8080"), "https")

    def test_scheme_maps_to_proxy_type(self):
        import socks
        from core.network import _PROXY_TYPES
        self.assertEqual(_PROXY_TYPES["socks5"], socks.SOCKS5)
        self.assertEqual(_PROXY_TYPES["socks4"], socks.SOCKS4)
        self.assertEqual(_PROXY_TYPES["http"], socks.HTTP)
        self.assertEqual(_PROXY_TYPES["https"], socks.HTTP)

    def test_socks_smtp_defaults_to_socks5(self):
        import socks
        from core.network import SocksSMTP
        s = SocksSMTP("1.2.3.4", 1080)
        self.assertEqual(s.proxy_type, socks.SOCKS5)

    def test_socks_smtp_honours_explicit_type(self):
        import socks
        from core.network import SocksSMTP
        s = SocksSMTP("1.2.3.4", 1080, proxy_type=socks.SOCKS4)
        self.assertEqual(s.proxy_type, socks.SOCKS4)
