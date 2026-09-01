"""DNS через прокси и разбор интернационализированных адресов.

Два класса ошибок, которые эти тесты сторожат:
  1. Утечка: при заданных прокси DNS не должен уходить напрямую.
  2. Ложный invalid: «DNS не ответил» и «IDN-адрес» — это НЕ «домена нет».
"""
import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import dns.resolver

from core.network import (DNSUnavailable, NetworkValidator, ProxiedResolver,
                          has_non_ascii_local, to_ascii_domain,
                          validate_email_syntax)


class TestIDNSyntax(unittest.TestCase):
    """IDN-адрес законен. Раньше ASCII-регулярка хоронила его как Bad Syntax."""

    def test_idn_domain_accepted(self):
        for email in ["ivan@почта.рф", "john@münchen.de", "anna@xn--80a1acny.xn--p1ai"]:
            with self.subTest(email=email):
                self.assertTrue(validate_email_syntax(email))

    def test_non_ascii_local_accepted_as_syntax(self):
        self.assertTrue(validate_email_syntax("иван@почта.рф"))
        self.assertTrue(has_non_ascii_local("иван@почта.рф"))
        self.assertFalse(has_non_ascii_local("ivan@почта.рф"))

    def test_broken_addresses_still_rejected(self):
        for email in ["john..doe@x.com", ".john@x.com", "john@x", "john doe@x.com",
                      "a" * 400 + "@x.com", "@x.com", "john@", "", None, 123]:
            with self.subTest(email=email):
                self.assertFalse(validate_email_syntax(email))

    def test_punycode_conversion(self):
        self.assertEqual(to_ascii_domain("почта.рф"), "xn--80a1acny.xn--p1ai")
        self.assertEqual(to_ascii_domain("gmail.com"), "gmail.com")
        self.assertIsNone(to_ascii_domain(""))
        self.assertIsNone(to_ascii_domain(None))

    def test_non_ascii_local_is_unknown_not_invalid(self):
        # Требование здесь одно и оно не менялось: за не-ASCII имя ящика
        # адрес хоронить нельзя.
        #
        # А вот КАКОЙ именно недоказанный статус получится — сместилось, и
        # осознанно. Раньше проверка разворачивала такой адрес на подходе и
        # всегда отвечала unknown. Теперь он доходит до сервера: если тот
        # объявил SMTPUTF8, будет настоящий вердикт, если не объявил —
        # unknown из самой сессии, а здоровый DNS домена поднимает его до
        # risky (это давнее правило: домен точно почтовый, просто ответа нет).
        #
        # Поэтому проверяется класс ответа, а не одно слово: invalid здесь
        # быть не может ни при каких обстоятельствах.
        v = NetworkValidator(timeout=2)
        res = v.check_email("иван@почта.рф")
        self.assertIn(res["status"], ("unknown", "risky", "valid"))
        self.assertNotEqual(res["status"], "invalid")


class TestResolverContract(unittest.TestCase):
    """Контракт proxy_provider: None — напрямую, "" — нельзя, строка — через прокси."""

    def test_no_proxies_means_direct(self):
        r = ProxiedResolver(["8.8.8.8"], timeout=2, proxy_provider=lambda: None)
        calls = []
        r._plain.resolve = lambda *a, **k: calls.append(a) or ["ok"]
        self.assertEqual(r.resolve("example.com", "A"), ["ok"])
        self.assertEqual(len(calls), 1)

    def test_dead_pool_never_falls_back_to_direct(self):
        # Прокси заданы, но живых нет. Уйти на 8.8.8.8 напрямую — раскрыть IP.
        r = ProxiedResolver(["8.8.8.8"], timeout=2, proxy_provider=lambda: "")
        r._plain.resolve = lambda *a, **k: self.fail("ушли напрямую в обход прокси")
        with self.assertRaises(DNSUnavailable):
            r.resolve("example.com", "A")

    def test_all_transports_failed_raises_dns_unavailable(self):
        r = ProxiedResolver(["8.8.8.8"], timeout=1,
                            proxy_provider=lambda: "socks5://127.0.0.1:1")
        r._via_doh = lambda *a, **k: None
        r._via_socks_tcp = lambda *a, **k: None
        with self.assertRaises(DNSUnavailable):
            r.resolve("example.com", "A")

    def test_dns_unavailable_is_not_nxdomain(self):
        # Самое важное различие во всём файле: «не спросили» != «домена нет».
        self.assertFalse(issubclass(DNSUnavailable, dns.resolver.NXDOMAIN))


class TestDeadDomainVsUnreachableDNS(unittest.TestCase):
    """[] — домен мёртв. None — DNS не ответил. Путать нельзя."""

    def setUp(self):
        self.v = NetworkValidator(timeout=2)

    def test_dns_failure_returns_none_not_empty(self):
        def boom(*_a, **_k):
            raise DNSUnavailable("нет транспорта")

        self.v.resolver.resolve = boom
        self.assertIsNone(self.v.get_mx_records("example.com"))

    def test_dns_failure_is_not_cached(self):
        def boom(*_a, **_k):
            raise DNSUnavailable("нет транспорта")

        self.v.resolver.resolve = boom
        self.v.get_mx_records("example.com")
        self.assertNotIn("example.com", self.v.mx_cache)

    def test_real_absence_returns_empty_and_is_cached(self):
        def nx(*_a, **_k):
            raise dns.resolver.NXDOMAIN

        self.v.resolver.resolve = nx
        self.assertEqual(self.v.get_mx_records("example.com"), [])
        self.assertEqual(self.v.mx_cache.get("example.com"), [])

    def test_check_email_returns_unknown_when_dns_unreachable(self):
        def boom(*_a, **_k):
            raise DNSUnavailable("нет транспорта")

        self.v.resolver.resolve = boom
        res = self.v.check_email("someone@example.com")
        self.assertEqual(res["status"], "unknown")
        self.assertNotEqual(res["status"], "invalid")

    def test_check_email_still_marks_truly_dead_domain(self):
        def nx(*_a, **_k):
            raise dns.resolver.NXDOMAIN

        self.v.resolver.resolve = nx
        res = self.v.check_email("someone@example.com")
        self.assertEqual(res["status"], "invalid")

    def test_dnsbl_not_cached_when_dns_unreachable(self):
        def boom(*_a, **_k):
            raise DNSUnavailable("нет транспорта")

        self.v.resolver.resolve = boom
        self.assertFalse(self.v.check_dnsbl_ip("203.0.113.9"))
        self.assertNotIn("203.0.113.9", self.v._dnsbl_cache)

    def test_ptr_unknown_not_cached(self):
        def boom(*_a, **_k):
            raise DNSUnavailable("нет транспорта")

        self.v.resolver.resolve = boom
        self.assertIsNone(self.v.check_ptr("mx.example.com"))
        self.assertNotIn("mx.example.com", self.v._ptr_cache)


class TestProxyDnsToggle(unittest.TestCase):
    def test_profiling_validator_does_not_route_dns_through_proxies(self):
        v = NetworkValidator(timeout=2, proxies=["socks5://1.2.3.4:1080"], proxy_dns=False)
        self.assertIsNone(v._dns_proxy())

    def test_configured_proxies_route_dns(self):
        v = NetworkValidator(timeout=2, proxies=["socks5://1.2.3.4:1080"])
        self.assertEqual(v._dns_proxy(), "socks5://1.2.3.4:1080")

    def test_banned_pool_returns_empty_marker(self):
        v = NetworkValidator(timeout=2, proxies=["socks5://1.2.3.4:1080"])
        v._proxy_banned.add("socks5://1.2.3.4:1080")
        self.assertEqual(v._dns_proxy(), "")

    def test_no_proxies_configured_means_direct(self):
        v = NetworkValidator(timeout=2)
        self.assertIsNone(v._dns_proxy())


if __name__ == "__main__":
    unittest.main()
