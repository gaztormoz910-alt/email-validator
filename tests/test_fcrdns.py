"""Тесты распознавания FCrDNS-отказа (Yahoo/AOL 5.7.25).

Yahoo и AOL отшивают на MAIL FROM любой IP без обратного DNS. Это НЕ значит,
что ящик мёртв, и НЕ значит, что прокси сдох — важно не перепутать ни то, ни другое.
"""
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.network import NetworkValidator


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

    def test_survey_handles_empty_list(self):
        from core.network import survey_fcrdns_proxies
        self.assertEqual(survey_fcrdns_proxies([]), (0, 0))
        self.assertEqual(survey_fcrdns_proxies(None), (0, 0))


if __name__ == '__main__':
    unittest.main()
