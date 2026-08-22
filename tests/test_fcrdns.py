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


class _FakeAnswer:
    """Подделка ответа dnspython: список объектов с .to_text()."""

    class _R:
        def __init__(self, text):
            self._t = text

        def to_text(self):
            return self._t

    def __init__(self, codes):
        self._items = [self._R(c) for c in codes]

    def __iter__(self):
        return iter(self._items)

    def __getitem__(self, i):
        return self._items[i]


class TestDnsblCodes(unittest.TestCase):
    """Листингом считается ТОЛЬКО 127.0.0.x / 127.0.1.x.

    Раньше здесь стоял тест-пустышка: он проверял содержимое списка констант,
    а саму check_dnsbl не вызывал. Из-за этого мутация «DNSBL всем ставит -40»
    проходила незамеченной, хотя это -40 баллов каждому адресу базы.
    """

    def _validator_answering(self, codes_by_zone):
        v = NetworkValidator(timeout=1)

        def fake_resolve(name, rtype):
            name = str(name)
            if rtype == 'A' and not name.endswith(tuple(codes_by_zone.keys())):
                return _FakeAnswer(['1.2.3.4'])          # резолв самого MX-хоста
            for zone, codes in codes_by_zone.items():
                if name.endswith(zone):
                    if codes is None:
                        raise Exception("NXDOMAIN")      # не числится
                    return _FakeAnswer(codes)
            raise Exception("NXDOMAIN")

        v.resolver.resolve = fake_resolve
        return v

    def test_real_listing_is_detected(self):
        from core.network import DNSBL_ZONES
        v = self._validator_answering({DNSBL_ZONES[0]: ['127.0.0.2']})
        self.assertTrue(v.check_dnsbl("mx.listed.test"))

    def test_127_0_1_x_is_also_a_listing(self):
        from core.network import DNSBL_ZONES
        v = self._validator_answering({DNSBL_ZONES[0]: ['127.0.1.4']})
        self.assertTrue(v.check_dnsbl("mx.listed2.test"))

    def test_blocklist_error_code_is_not_a_listing(self):
        # 127.255.255.x = "запрос отклонён" (публичный DNS, лимит), а не листинг.
        # Именно на этом коде раньше вся база получала бы -40.
        from core.network import DNSBL_ZONES
        v = self._validator_answering({z: ['127.255.255.254'] for z in DNSBL_ZONES})
        self.assertFalse(v.check_dnsbl("mx.clean.test"))

    def test_no_answer_means_clean(self):
        from core.network import DNSBL_ZONES
        v = self._validator_answering({z: None for z in DNSBL_ZONES})
        self.assertFalse(v.check_dnsbl("mx.clean2.test"))

    def test_several_zones_are_queried(self):
        from core.network import DNSBL_ZONES
        self.assertGreater(len(DNSBL_ZONES), 1)
        # Листинг во ВТОРОЙ зоне тоже должен находиться, а не только в первой
        v = self._validator_answering({DNSBL_ZONES[1]: ['127.0.0.2']})
        self.assertTrue(v.check_dnsbl("mx.listed3.test"))


if __name__ == '__main__':
    unittest.main()
