import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser.name_extractor import NameExtractor
from core.network import NetworkValidator


class TestProgress(unittest.TestCase):

    def test_progress_defers_do_not_advance_the_bar(self):
        import inspect
        from core.pipeline import ValidationPipeline
        source = inspect.getsource(ValidationPipeline.run_pipeline)

        self.assertIn("defer(email, data, is_role", source)
        self.assertGreaterEqual(source.count("return False"), 2,
                                "откладывание перестало сообщать о себе вызывающему")
        self.assertIn("if not deferred:", source,
                      "прогресс снова двигается независимо от того, получен "
                      "вердикт или адрес только отложен")

    def test_progress_retry_advances_the_bar(self):
        import inspect
        from core.pipeline import ValidationPipeline
        source = inspect.getsource(ValidationPipeline.run_pipeline)
        after_retry = source[source.index("retry_count += 1"):]
        self.assertIn("processed_count += 1", after_retry[:600],
                      "после перепроверки прогресс не двигается — бар "
                      "остановится, не дойдя до конца")


class TestSemaphoreScope(unittest.TestCase):

    def test_semaphore_is_per_exit_ip_not_per_mx(self):
        v = NetworkValidator(timeout=1, proxies=["p1:1", "p2:2"])
        v.set_proxy_profiles({
            "p1:1": {"exit_ip": "1.1.1.1"},
            "p2:2": {"exit_ip": "2.2.2.2"},
        })
        first = v._get_mx_semaphore("gmail-smtp-in.l.google.com", "p1:1")
        second = v._get_mx_semaphore("gmail-smtp-in.l.google.com", "p2:2")
        self.assertIsNot(first, second,
                         "два разных выходных IP делят один лимит к серверу — "
                         "база из одних гуглов упрётся в пять соединений")

    def test_semaphore_same_proxy_shares_one_slot(self):
        v = NetworkValidator(timeout=1, proxies=["p1:1"])
        v.set_proxy_profiles({"p1:1": {"exit_ip": "1.1.1.1"}})
        a = v._get_mx_semaphore("mx.example.com", "p1:1")
        b = v._get_mx_semaphore("mx.example.com", "p1:1")
        self.assertIs(a, b, "лимит на один выходной адрес перестал действовать")

    def test_semaphore_adaptive_limit_uses_the_same_key(self):
        v = NetworkValidator(timeout=1, proxies=["p1:1"])
        v.set_proxy_profiles({"p1:1": {"exit_ip": "1.1.1.1"}})
        before = v._get_mx_semaphore("mx.example.com", "p1:1")
        for _ in range(3):
            v._record_mx_error("mx.example.com", "p1:1")
        after = v._get_mx_semaphore("mx.example.com", "p1:1")
        self.assertIsNot(before, after,
                         "адаптивное торможение создало семафор под другим "
                         "ключом — снижение никуда не применилось")


class TestNames(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.ex = NameExtractor(enable_osint=False)

    def test_names_slavic_surname_is_kept_whole(self):
        self.assertEqual(self.ex.extract_name("zogbinanatol1@gmail.com") or "", "")

    def test_names_surname_with_initial(self):
        self.assertEqual(self.ex.extract_name("zogbina@gmail.com") or "", "")

    def test_names_short_syllables_survive(self):
        self.assertEqual(self.ex.extract_name("minhanhtran07@gmail.com"),
                         "Minh Anh Tran",
                         "починка обломков склеила настоящие короткие имена")

    def test_names_english_cases_unchanged(self):
        cases = {
            "robertanderson@gmail.com": "Robert Anderson",
            "mohammedlahlali@yahoo.fr": "Mohammed Lahlali",
            "john.doe@gmail.com": "John Doe",
            "j.smith@gmail.com": "J Smith",
            "sarah.jones91@outlook.com": "Sarah Jones",
        }
        for email, expected in cases.items():
            with self.subTest(email=email):
                self.assertEqual(self.ex.extract_name(email), expected)

    def test_names_role_accounts_are_still_not_people(self):
        for email in ("info@corp.com", "noreply@corp.com", "support@corp.com"):
            with self.subTest(email=email):
                self.assertFalse(self.ex.extract_name(email),
                                 f"{email} снова стал именем человека")

    def test_names_repair_helper_is_index_aware(self):
        repaired = self.ex._repair_oversegmentation(["zog", "bin", "anatol"])
        self.assertEqual(repaired, ["zogbin", "anatol"])
        kept = self.ex._repair_oversegmentation(["minh", "anh", "tran"])
        self.assertEqual(kept, ["minh", "anh", "tran"])


if __name__ == "__main__":
    unittest.main()
