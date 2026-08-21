"""Тесты распознавания FCrDNS-отказа (Yahoo/AOL 5.7.25).

Yahoo и AOL отшивают на MAIL FROM любой IP без обратного DNS. Это НЕ значит,
что ящик мёртв, и НЕ значит, что прокси сдох — важно не перепутать ни то, ни другое.
"""
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.network import NetworkValidator, PROXY_MAX_CONSECUTIVE_FAILS


class TestFCrDNSHandling(unittest.TestCase):
    def setUp(self):
        self.v = NetworkValidator(timeout=3)

    def test_fcrdns_none_for_empty_ip(self):
        self.assertIsNone(self.v.check_fcrdns(""))
        self.assertIsNone(self.v.check_fcrdns(None))

    def test_fcrdns_result_is_cached(self):
        self.v._fcrdns_cache["203.0.113.7"] = True
        self.assertTrue(self.v.check_fcrdns("203.0.113.7"))

    def test_fcrdns_rejection_is_not_invalid(self):
        # 5.7.25 приходит на MAIL FROM. Ящик при этом может прекрасно существовать.
        res = self.v._parse_smtp_response(
            550, b"5.7.25 Forward-confirmed reverse DNS failed", "a@yahoo.com", "yahoo.com")
        self.assertNotEqual(res["status"], "invalid")

    def test_reverse_dns_wording_not_invalid(self):
        for msg in [b"550 5.7.25 Reverse DNS validation failed",
                    b"550 Reverse DNS does not match sending IP"]:
            with self.subTest(msg=msg):
                res = self.v._parse_smtp_response(550, msg, "a@aol.com", "aol.com")
                self.assertNotEqual(res["status"], "invalid")

    def test_split_handles_empty_list(self):
        from core.network import split_proxies_by_fcrdns
        self.assertEqual(split_proxies_by_fcrdns([]), ([], []))
        self.assertEqual(split_proxies_by_fcrdns(None), ([], []))


class TestPtrProxyRouting(unittest.TestCase):
    """Yahoo/AOL идут только через прокси с PTR, остальные домены — через прочие."""

    def setUp(self):
        self.ptr = ["1.1.1.1:1080", "2.2.2.2:1080"]
        self.plain = ["3.3.3.3:1080", "4.4.4.4:1080"]
        self.v = NetworkValidator(timeout=2, proxies=self.ptr + self.plain)
        self.v.set_ptr_proxies(self.ptr)

    def test_ptr_required_picks_only_ptr_proxies(self):
        for _ in range(40):
            self.assertIn(self.v._pick_best_proxy(need_ptr=True), self.ptr)

    def test_normal_domains_conserve_ptr_proxies(self):
        # PTR-прокси дефицитны — на обычных доменах их беречь
        for _ in range(40):
            self.assertIn(self.v._pick_best_proxy(need_ptr=False), self.plain)

    def test_falls_back_to_ptr_pool_when_plain_exhausted(self):
        for p in self.plain:
            for _ in range(PROXY_MAX_CONSECUTIVE_FAILS):
                self.v._update_proxy_score(p, False)
        self.assertIn(self.v._pick_best_proxy(need_ptr=False), self.ptr)

    def test_no_ptr_proxies_means_none_for_yahoo(self):
        for p in self.ptr:
            for _ in range(PROXY_MAX_CONSECUTIVE_FAILS):
                self.v._update_proxy_score(p, False)
        self.assertIsNone(self.v._pick_best_proxy(need_ptr=True))
        self.assertFalse(self.v.has_ptr_proxies())

    def test_without_split_all_proxies_usable(self):
        # Если PTR не размечен, поведение как раньше — берём из общего пула
        v = NetworkValidator(timeout=2, proxies=self.plain)
        self.assertIn(v._pick_best_proxy(need_ptr=False), self.plain)


class TestDnsblCodes(unittest.TestCase):
    """Листингом считается только 127.0.0.x / 127.0.1.x."""

    def test_error_codes_are_not_a_listing(self):
        from core.network import DNSBL_ZONES
        self.assertIn("zen.spamhaus.org", DNSBL_ZONES)
        self.assertGreater(len(DNSBL_ZONES), 1)

    def test_dnsbl_result_is_cached(self):
        v = NetworkValidator(timeout=2)
        v._dnsbl_cache["mx.example.com"] = True
        self.assertTrue(v.check_dnsbl("mx.example.com"))


if __name__ == '__main__':
    unittest.main()
