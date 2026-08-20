"""Тесты выбывания мёртвых прокси из ротации.

Главные инварианты:
  1. Прокси, севший N раз ПОДРЯД, больше никогда не выбирается.
  2. Успешный ответ сбрасывает счётчик подряд идущих сбоев.
  3. Если прокси загружены, но все выбыли — НЕ ходим напрямую (защита от утечки IP).
"""
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.network import NetworkValidator, PROXY_MAX_CONSECUTIVE_FAILS


class TestProxyBan(unittest.TestCase):
    def setUp(self):
        self.proxies = ["1.1.1.1:1080", "2.2.2.2:1080", "3.3.3.3:1080"]
        self.v = NetworkValidator(timeout=2, proxies=list(self.proxies))

    def test_proxy_banned_after_consecutive_fails(self):
        p = self.proxies[0]
        for _ in range(PROXY_MAX_CONSECUTIVE_FAILS):
            self.v._update_proxy_score(p, False)

        self.assertEqual(self.v.get_live_proxy_count(), len(self.proxies) - 1)
        # Забаненный больше не должен выбираться ни разу
        for _ in range(50):
            self.assertNotEqual(self.v._pick_best_proxy(), p)

    def test_success_resets_consecutive_counter(self):
        p = self.proxies[0]
        for _ in range(PROXY_MAX_CONSECUTIVE_FAILS - 1):
            self.v._update_proxy_score(p, False)
        self.v._update_proxy_score(p, True)   # ожил — счётчик обнуляется
        for _ in range(PROXY_MAX_CONSECUTIVE_FAILS - 1):
            self.v._update_proxy_score(p, False)

        # Сбои не шли подряд, значит бана быть не должно
        self.assertEqual(self.v.get_live_proxy_count(), len(self.proxies))
        self.assertFalse(self.v.all_proxies_dead())

    def test_all_dead_reports_exhausted(self):
        for p in self.proxies:
            for _ in range(PROXY_MAX_CONSECUTIVE_FAILS):
                self.v._update_proxy_score(p, False)

        self.assertTrue(self.v.all_proxies_dead())
        self.assertEqual(self.v.get_live_proxy_count(), 0)
        self.assertIsNone(self.v._pick_best_proxy())

    def test_no_direct_connection_when_proxies_exhausted(self):
        # Защита от утечки IP: прокси заданы, но все мертвы -> прямого коннекта быть не должно
        for p in self.proxies:
            for _ in range(PROXY_MAX_CONSECUTIVE_FAILS):
                self.v._update_proxy_score(p, False)

        res = self.v._do_single_ping("user@example.com", "mx.example.com", proxy=None)
        self.assertEqual(res["status"], "unknown")
        self.assertIn("Proxies Dead", res["reason"])

    def test_no_proxies_configured_allows_direct(self):
        # Без прокси прямое соединение — это норма, запрет не должен срабатывать
        v = NetworkValidator(timeout=2, proxies=None)
        self.assertFalse(v.has_proxies_configured())
        self.assertFalse(v.all_proxies_dead())
        self.assertIsNone(v._pick_best_proxy())

    def test_dead_proxy_never_resurrected(self):
        # Раньше при всех мёртвых прокси возвращался случайный из полного списка
        for p in self.proxies[:2]:
            for _ in range(PROXY_MAX_CONSECUTIVE_FAILS):
                self.v._update_proxy_score(p, False)

        survivor = self.proxies[2]
        for _ in range(50):
            self.assertEqual(self.v._pick_best_proxy(), survivor)


if __name__ == '__main__':
    unittest.main()
