"""Списки, шлюзы, операции с базами и защита прокси от чужих сбоёв."""
import os
import shutil
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core import baseops
from core.filters import BLACKLIST_SENTINELS, NON_BLACKLIST_FILES, SpamFilter
from core.network import (NetworkValidator, PROXY_MAX_CONSECUTIVE_FAILS,
                          _dkim_selectors_for, _looks_like_ip_reputation,
                          is_dirty_rdns, security_gateway)


class TestBlacklistSanityContract(unittest.TestCase):
    """Список одноразовых доменов с gmail.com внутри убил бы всю базу."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, domains):
        with open(os.path.join(self.tmp, name), "w", encoding="utf-8") as f:
            f.write("\n".join(domains))

    def test_poisoned_list_is_rejected_whole(self):
        self._write("bad.txt", ["mailinator.com", "gmail.com", "tempmail.com"])
        spam = SpamFilter(data_dir=self.tmp)
        self.assertFalse(spam.is_spam_or_disposable("someone@gmail.com"))
        self.assertFalse(spam.is_spam_or_disposable("x@mailinator.com")
                         and "mailinator.com" not in spam.blacklist_domains)
        self.assertTrue(spam.rejected_files)

    def test_clean_list_loads(self):
        self._write("good.txt", ["throwaway-xyz.com", "burner-abc.net"] * 1)
        spam = SpamFilter(data_dir=self.tmp)
        self.assertTrue(spam.is_spam_or_disposable("x@throwaway-xyz.com"))
        self.assertFalse(spam.rejected_files)

    def test_free_provider_file_is_never_loaded_as_blacklist(self):
        # Он лежит рядом и полон gmail.com — грузить его нельзя ни при каких
        self._write("free_providers.txt", ["gmail.com", "yahoo.com", "web.de"])
        spam = SpamFilter(data_dir=self.tmp)
        self.assertFalse(spam.is_spam_or_disposable("someone@gmail.com"))
        self.assertIn("free_providers.txt", NON_BLACKLIST_FILES)

    def test_sentinels_cover_major_providers(self):
        for domain in ["gmail.com", "yahoo.com", "outlook.com", "mail.ru"]:
            self.assertIn(domain, BLACKLIST_SENTINELS)

    def test_string_without_at_is_not_spam(self):
        # Мусорный ввод — не приговор: раньше функция возвращала на него True
        spam = SpamFilter(data_dir=self.tmp)
        for value in ["мусор", "", None, 42]:
            with self.subTest(value=value):
                self.assertFalse(spam.is_spam_or_disposable(value))


class TestSecurityGateways(unittest.TestCase):
    """Шлюз перед доменом означает catch-all по конструкции."""

    def test_known_gateways_are_recognised(self):
        cases = [("mx1.pphosted.com", "Proofpoint"),
                 ("eu-smtp-inbound-1.mimecast.com", "Mimecast"),
                 ("mx.iphmx.com", "Cisco IronPort"),
                 ("cudaxxx.barracudanetworks.com", "Barracuda"),
                 ("cluster.messagelabs.com", "Symantec")]
        for host, vendor in cases:
            with self.subTest(host=host):
                self.assertEqual(security_gateway([host]), vendor)

    def test_ordinary_mx_is_not_a_gateway(self):
        for host in ["aspmx.l.google.com", "mx.yandex.ru", "mail.protonmail.ch"]:
            with self.subTest(host=host):
                self.assertIsNone(security_gateway([host]))

    def test_garbage_input(self):
        for value in [None, "", 42, {}, []]:
            with self.subTest(value=value):
                self.assertIsNone(security_gateway(value))


class TestDirtyRdnsBoundaries(unittest.TestCase):
    """Совпадение по границам ярлыка, а не подстрокой."""

    def test_real_dynamic_hosts_are_dirty(self):
        for host in ["pool-71-105.fios.verizon.net", "tor-exit.example.org",
                     "vpn-gateway.host.net", "dsl-12-34.provider.com"]:
            with self.subTest(host=host):
                self.assertTrue(is_dirty_rdns(host))

    def test_innocent_hosts_are_clean(self):
        # exitcom и hosting-provider раньше ошибочно считались грязными,
        # а датацентровые прокси — ровно те, что нужны для валидации
        for host in ["mx.exitcom.net", "hosting-provider.net",
                     "mail-relay.company.com", "smtp.poolside.io"]:
            with self.subTest(host=host):
                self.assertFalse(is_dirty_rdns(host))

    def test_garbage_input(self):
        for value in [None, "", 42, []]:
            with self.subTest(value=value):
                self.assertFalse(is_dirty_rdns(value))


class TestDkimSelectorNarrowing(unittest.TestCase):
    def test_known_mx_narrows_the_list(self):
        google = _dkim_selectors_for("aspmx.l.google.com")
        self.assertIn("google", google)
        self.assertLess(len(google), len(_dkim_selectors_for("")))

    def test_microsoft_selectors(self):
        selectors = _dkim_selectors_for("corp-com.mail.protection.outlook.com")
        self.assertIn("selector1", selectors)

    def test_unknown_mx_falls_back_to_full_sweep(self):
        self.assertGreater(len(_dkim_selectors_for("mx.unknown-host.net")), 15)

    def test_garbage_input(self):
        for value in [None, "", "N/A", 42]:
            with self.subTest(value=value):
                self.assertGreater(len(_dkim_selectors_for(value)), 0)


class TestProxyNotBannedForOneBadMx(unittest.TestCase):
    """Три сбоя на ОДНОМ сервере — вина сервера, а не прокси."""

    def setUp(self):
        self.proxy = "socks5://1.2.3.4:1080"
        self.v = NetworkValidator(timeout=2, proxies=[self.proxy])

    def test_failures_on_one_mx_do_not_ban(self):
        for _ in range(PROXY_MAX_CONSECUTIVE_FAILS + 2):
            self.v._update_proxy_score(self.proxy, False, mx_record="slow.mx.example")
        self.assertNotIn(self.proxy, self.v._proxy_banned)
        self.assertEqual(self.v._pick_best_proxy(), self.proxy)

    def test_failures_across_different_mx_do_ban(self):
        for i in range(PROXY_MAX_CONSECUTIVE_FAILS):
            self.v._update_proxy_score(self.proxy, False, mx_record=f"mx{i}.example")
        self.assertIn(self.proxy, self.v._proxy_banned)

    def test_failures_without_known_mx_still_ban(self):
        # Прокси не поднялся вовсе — сервер тут ни при чём
        for _ in range(PROXY_MAX_CONSECUTIVE_FAILS):
            self.v._update_proxy_score(self.proxy, False)
        self.assertIn(self.proxy, self.v._proxy_banned)

    def test_success_resets_the_streak(self):
        self.v._update_proxy_score(self.proxy, False, mx_record="a.example")
        self.v._update_proxy_score(self.proxy, False, mx_record="b.example")
        self.v._update_proxy_score(self.proxy, True)
        self.v._update_proxy_score(self.proxy, False, mx_record="c.example")
        self.assertNotIn(self.proxy, self.v._proxy_banned)


class TestAdaptiveBackoff(unittest.TestCase):
    def setUp(self):
        self.v = NetworkValidator(timeout=2)

    def test_delay_grows_with_errors(self):
        quiet = self.v._mx_delay("mx.example.com")
        for _ in range(4):
            self.v._record_mx_error("mx.example.com")
        loaded = self.v._mx_delay("mx.example.com")
        self.assertGreater(loaded, quiet)

    def test_delay_is_capped(self):
        for _ in range(50):
            self.v._record_mx_error("mx.example.com")
        self.assertLessEqual(self.v._mx_delay("mx.example.com"), 8.0)

    def test_garbage_input(self):
        self.assertGreater(self.v._mx_delay(None), 0)


class TestIpReputationDetection(unittest.TestCase):
    def test_reputation_refusals_are_recognised(self):
        for reason in ["550 Our IP Blocked (Email May Exist)",
                       "5.7.1 Service unavailable, Client host [1.2.3.4] blocked",
                       "550 listed in Spamhaus SBL"]:
            with self.subTest(reason=reason):
                self.assertTrue(_looks_like_ip_reputation(reason))

    def test_mailbox_refusals_are_not(self):
        for reason in ["550 User Does Not Exist", "250 OK", "450 Greylisted"]:
            with self.subTest(reason=reason):
                self.assertFalse(_looks_like_ip_reputation(reason))


class TestBaseOps(unittest.TestCase):
    """Сравнение по каноническому виду: точки Gmail и плюс-теги — один ящик."""

    def test_subtract_matches_canonically(self):
        base = ["John.Doe@Gmail.com", "anna@web.de"]
        result = baseops.subtract(base, ["johndoe@gmail.com"])
        self.assertEqual(result, ["anna@web.de"])

    def test_subtract_keeps_original_spelling(self):
        result = baseops.subtract(["John.Doe@Gmail.com"], [])
        self.assertEqual(result, ["John.Doe@Gmail.com"])

    def test_merge_dedupes(self):
        result = baseops.merge(["a@x.com", "A@X.com"], ["b@y.com"])
        self.assertEqual(len(result), 2)

    def test_intersect(self):
        result = baseops.intersect(["a@x.com", "b@y.com"], ["A@x.com"])
        self.assertEqual(result, ["a@x.com"])

    def test_chunks_split_and_preserve_everything(self):
        items = [f"u{i}@x.com" for i in range(10)]
        parts = baseops.chunks(items, 3)
        self.assertEqual([len(p) for p in parts], [3, 3, 3, 1])
        self.assertEqual([e for p in parts for e in p], items)

    def test_zero_size_means_one_file(self):
        items = ["a@x.com", "b@x.com"]
        self.assertEqual(baseops.chunks(items, 0), [items])
        self.assertEqual(baseops.chunks(items, "мусор"), [items])

    def test_empty_input(self):
        self.assertEqual(baseops.chunks([], 5), [])
        self.assertEqual(baseops.merge(), [])
        self.assertEqual(baseops.subtract(None, None), [])


class TestBaseOpsFiles(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _file(self, name, text):
        path = os.path.join(self.tmp, name)
        with open(path, "w", encoding="utf-8") as f:
            f.write(text)
        return path

    def test_reads_plain_and_csv_lines(self):
        path = self._file("a.txt", "john@x.com\nAnna Smith,anna@y.com,DE\n# коммент\n\n")
        self.assertEqual(baseops.read_emails(path), ["john@x.com", "anna@y.com"])

    def test_missing_file_is_empty_not_an_error(self):
        self.assertEqual(baseops.read_emails(os.path.join(self.tmp, "nope.txt")), [])
        self.assertEqual(baseops.read_emails(None), [])

    def test_write_chunks_numbers_files(self):
        rows = [f"u{i}@x.com" for i in range(7)]
        target = os.path.join(self.tmp, "out.txt")
        written = baseops.write_chunks(
            rows, target, 3, lambda h, part: h.writelines(e + "\n" for e in part))
        self.assertEqual(len(written), 3)
        for path in written:
            self.assertTrue(os.path.exists(path))

    def test_single_chunk_keeps_the_original_name(self):
        target = os.path.join(self.tmp, "out.txt")
        written = baseops.write_chunks(
            ["a@x.com"], target, 0, lambda h, part: h.writelines(e + "\n" for e in part))
        self.assertEqual(written, [target])


if __name__ == "__main__":
    unittest.main()
