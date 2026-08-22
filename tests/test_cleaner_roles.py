"""Тесты детерминизма очистки, чистки хвостов и распознавания ролевых ящиков."""
import subprocess
import sys
import os
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.cleaner import EmailCleaner
from core.heuristics import is_role_based


class TestCleanerDeterminism(unittest.TestCase):
    """Один и тот же адрес обязан давать один и тот же результат.

    Раньше перебор шёл по set, порядок которого меняется между запусками:
    bob@x.gmail.com.y.yahoo.com.z за 12 прогонов дал 7 раз gmail.com и 5 раз
    yahoo.com. Прогон базы дважды давал разные адреса и разные вердикты.
    """

    AMBIGUOUS = "bob@x.gmail.com.y.yahoo.com.z"

    def test_stable_within_one_process(self):
        c = EmailCleaner()
        results = {c.clean_email(self.AMBIGUOUS) for _ in range(50)}
        self.assertEqual(len(results), 1)

    def test_stable_across_processes(self):
        # Ключевой тест: разные процессы = разный hash seed = разный порядок set
        code = (
            "from core.cleaner import EmailCleaner;"
            f"print(EmailCleaner().clean_email({self.AMBIGUOUS!r}))"
        )
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        seen = set()
        for _ in range(6):
            out = subprocess.run([sys.executable, "-c", code], cwd=root,
                                 capture_output=True, text=True).stdout.strip()
            seen.add(out)
        self.assertEqual(len(seen), 1, f"результаты разошлись между запусками: {seen}")


class TestTldTailStripping(unittest.TestCase):
    """Мусор, приклеенный к TLD, должен срезаться у ЛЮБОГО домена.

    Раньше чистились только домены из списка парсера, поэтому живые адреса
    вроде bob@yandex.rublahblah уезжали в Invalid как «мёртвый домен».
    """

    def setUp(self):
        self.c = EmailCleaner()

    def test_tail_stripped_for_any_domain(self):
        cases = {
            "bob@yandex.rublahblah": "bob@yandex.ru",
            "bob@mail.ruXXX": "bob@mail.ru",
            "bob@gmail.comtelefoon": "bob@gmail.com",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(self.c.clean_email(raw), expected)

    def test_compound_tlds_not_broken(self):
        for e in ["bob@corp.co.uk", "bob@site.com.br", "bob@shop.co.in"]:
            with self.subTest(e=e):
                self.assertEqual(self.c.clean_email(e), e)

    def test_normal_domains_untouched(self):
        for e in ["bob@gmail.com", "bob@tesla.com", "bob@sberbank.ru"]:
            with self.subTest(e=e):
                self.assertEqual(self.c.clean_email(e), e)


class TestRoleBased(unittest.TestCase):
    """Ролевые ящики образуются не только точным словом.

    Раньше сравнение было строго на равенство, поэтому sales-team@,
    noreply2@, do-not-reply@ и mailer-daemon@ проходили как личные адреса.
    """

    ROLES = [
        "info@x.com", "noreply@x.com", "sales-team@x.com", "info.desk@x.com",
        "noreply2@x.com", "do-not-reply@x.com", "mailer-daemon@x.com",
        "newsletter@x.com", "careers@x.com", "support01@x.com",
        "no_reply@x.com", "donotreply@x.com",
    ]

    PEOPLE = [
        "ivan.petrov@x.com", "john.doe@x.com", "kovbinb@gmail.com",
        "a.smith@x.com", "maria@x.com", "infomir@x.com",
        "salesman.ivan@x.com", "teamlead.bob@x.com",
    ]

    def test_role_addresses_detected(self):
        missed = [e for e in self.ROLES if not is_role_based(e)]
        self.assertEqual(missed, [], f"не пойманы ролевые: {missed}")

    def test_real_people_not_flagged(self):
        wrong = [e for e in self.PEOPLE if is_role_based(e)]
        self.assertEqual(wrong, [], f"живые помечены ролевыми: {wrong}")

    def test_degenerate_input(self):
        for bad in ["", None, "notanemail", "@x.com"]:
            with self.subTest(bad=bad):
                self.assertFalse(is_role_based(bad))


class TestDisposableExtension(unittest.TestCase):
    """Встроенная база одноразовых должна пополняться из авто-обновляемых списков."""

    def test_extend_adds_domains_and_subdomains_work(self):
        from core.disposable import extend_disposable_domains, is_disposable
        added = extend_disposable_domains(["totally-new-temp-domain-xyz.com"])
        self.assertGreaterEqual(added, 1)
        self.assertTrue(is_disposable("a@totally-new-temp-domain-xyz.com"))
        # Поддомен добавленного домена тоже должен ловиться
        self.assertTrue(is_disposable("a@sub.totally-new-temp-domain-xyz.com"))

    def test_extend_ignores_garbage(self):
        from core.disposable import extend_disposable_domains
        self.assertEqual(extend_disposable_domains([]), 0)
        self.assertEqual(extend_disposable_domains(None), 0)
        self.assertEqual(extend_disposable_domains(["", "  ", "notadomain"]), 0)


if __name__ == '__main__':
    unittest.main()
