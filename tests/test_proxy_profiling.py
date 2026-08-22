"""Тесты профилирования прокси: выходной IP, PTR, чёрные списки.

Смысл: «живой» прокси и «пригодный для валидации» — разные вещи. Outlook,
iCloud и GMX режут по репутации IP, Yahoo и AOL требуют обратный DNS.
Знать это надо ДО прогона, а не выяснять по молчанию серверов.
"""
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.network import (NetworkValidator, profile_proxies, get_proxy_exit_ip,
                          NEEDS_CLEAN_IP_DOMAINS, _EXIT_IP_RE)


class TestExitIpParsing(unittest.TestCase):
    """Выходной IP берём из ответа Gmail на EHLO — он сообщает его сам."""

    def test_parses_gmail_ehlo_form(self):
        text = "mx.google.com at your service, [203.0.113.3]\nSIZE 157286400"
        self.assertEqual(_EXIT_IP_RE.search(text).group(1), "203.0.113.3")

    def test_no_ip_returns_no_match(self):
        self.assertIsNone(_EXIT_IP_RE.search("mx.google.com at your service"))

    def test_bad_proxy_gives_none(self):
        self.assertIsNone(get_proxy_exit_ip("мусор", timeout=2))
        self.assertIsNone(get_proxy_exit_ip(None, timeout=2))


class TestDnsblByIp(unittest.TestCase):
    """Санити-контракт чёрных списков: 127.0.0.2 числится, 127.0.0.1 нет."""

    def setUp(self):
        self.v = NetworkValidator(timeout=2)

    def test_empty_ip_is_not_listed(self):
        self.assertFalse(self.v.check_dnsbl_ip(""))
        self.assertFalse(self.v.check_dnsbl_ip(None))

    def test_result_is_cached(self):
        self.v._dnsbl_cache["9.9.9.9"] = True
        self.assertTrue(self.v.check_dnsbl_ip("9.9.9.9"))


class TestProfileAwareSelection(unittest.TestCase):
    """Прокси подбирается под требования конкретного провайдера."""

    POOL = ["ptr-clean:1080", "ptr-dirty:1080", "plain-clean:1080", "plain-dirty:1080"]
    PROFILES = {
        "ptr-clean:1080":   {"exit_ip": "1.1.1.1", "has_ptr": True,  "in_dnsbl": False},
        "ptr-dirty:1080":   {"exit_ip": "2.2.2.2", "has_ptr": True,  "in_dnsbl": True},
        "plain-clean:1080": {"exit_ip": "3.3.3.3", "has_ptr": False, "in_dnsbl": False},
        "plain-dirty:1080": {"exit_ip": "4.4.4.4", "has_ptr": False, "in_dnsbl": True},
    }

    def setUp(self):
        self.v = NetworkValidator(timeout=2, proxies=list(self.POOL))
        self.v.set_proxy_profiles(self.PROFILES)

    def sample(self, **kw):
        return {self.v._pick_best_proxy(**kw) for _ in range(60)}

    def test_yahoo_gets_only_ptr_proxies(self):
        self.assertTrue(self.sample(need_ptr=True) <= {"ptr-clean:1080", "ptr-dirty:1080"})

    def test_outlook_gets_only_clean_proxies(self):
        self.assertEqual(self.sample(need_clean=True), {"plain-clean:1080"})

    def test_ordinary_domains_conserve_ptr_proxies(self):
        picked = self.sample()
        self.assertTrue(picked <= {"plain-clean:1080", "plain-dirty:1080"})

    def test_both_requirements_pick_the_ideal_proxy(self):
        self.assertEqual(self.sample(need_ptr=True, need_clean=True), {"ptr-clean:1080"})

    def test_falls_back_to_dirty_when_no_clean_left(self):
        # Лучше попытка через грязный прокси, чем отказ от проверки
        v = NetworkValidator(timeout=2, proxies=["plain-dirty:1080"])
        v.set_proxy_profiles({"plain-dirty:1080": {"exit_ip": "4.4.4.4",
                                                   "has_ptr": False, "in_dnsbl": True}})
        self.assertEqual(v._pick_best_proxy(need_clean=True), "plain-dirty:1080")

    def test_helpers_report_pool_state(self):
        self.assertTrue(self.v.has_ptr_proxies())
        self.assertTrue(self.v.has_clean_proxies())


class TestCleanIpDomains(unittest.TestCase):
    def test_reputation_sensitive_providers_listed(self):
        for d in ["outlook.com", "hotmail.com", "live.com", "icloud.com", "gmx.com"]:
            with self.subTest(domain=d):
                self.assertIn(d, NEEDS_CLEAN_IP_DOMAINS)

    def test_gmail_and_yandex_not_reputation_sensitive(self):
        # Они отвечают честно с любого живого IP — чистый прокси на них тратить незачем
        for d in ["gmail.com", "yandex.ru", "proton.me"]:
            with self.subTest(domain=d):
                self.assertNotIn(d, NEEDS_CLEAN_IP_DOMAINS)


class TestProfileProxiesDegenerate(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(profile_proxies([]), {})
        self.assertEqual(profile_proxies(None), {})


if __name__ == '__main__':
    unittest.main()
