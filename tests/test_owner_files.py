import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cleaner import EmailCleaner, normalize_for_dedup
from core.network import validate_email_syntax
from core.local_rules import check_local_part, IMPOSSIBLE, UNLIKELY, OK
from core.heuristics import is_role_based
from core.disposable import is_disposable

TESTDATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "testdata")

EXPECTED = {
    "test_base.txt": {"lines": 10, "unique": 10},
    "test_1.txt": {"lines": 70, "unique": 59},
    "test.txt": {"lines": 10, "unique": 9},
}

HAVE_OWNER_FILES = all(os.path.exists(os.path.join(TESTDATA, n)) for n in EXPECTED)
needs_owner_files = unittest.skipUnless(
    HAVE_OWNER_FILES, "файлов владельца data/testdata нет — они не в git, только на его машине")

COMPETITOR_BAD = ("ca@gmail.com", "marcusvey1994@gmail.com.", "wenlifang.dev@gmail.com.")


def lines_of(name):
    with io.open(os.path.join(TESTDATA, name), encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def unique_of(name, cleaner=None):
    cleaner = cleaner or EmailCleaner()
    keys = set()
    for raw in lines_of(name):
        cleaned = cleaner.clean_email(raw)
        if cleaned:
            keys.add(normalize_for_dedup(cleaned))
    return keys


@needs_owner_files
class TestCounts(unittest.TestCase):

    def test_counts_files_are_present(self):
        for name in EXPECTED:
            with self.subTest(name=name):
                self.assertTrue(os.path.exists(os.path.join(TESTDATA, name)),
                                f"нет файла {name} — проверять не на чем")

    def test_counts_line_counts_match(self):
        for name, expected in EXPECTED.items():
            with self.subTest(name=name):
                self.assertEqual(len(lines_of(name)), expected["lines"],
                                 f"{name}: файл изменился, ожидания устарели")

    def test_counts_unique_matches_competitor(self):
        for name, expected in EXPECTED.items():
            with self.subTest(name=name):
                got = len(unique_of(name))
                self.assertEqual(
                    got, expected["unique"],
                    f"{name}: у нас {got} уникальных, у конкурента "
                    f"{expected['unique']} — канонизация адресов разошлась")

    def test_counts_dedup_actually_collapsed_something(self):
        raw = len(lines_of("test_1.txt"))
        unique = len(unique_of("test_1.txt"))
        self.assertGreater(raw - unique, 5,
                           "дедуп ничего не схлопнул — значит совпадение чисел "
                           "выше было бы случайным")

    def test_counts_case_and_dots_are_collapsed(self):
        cleaner = EmailCleaner()
        keys = unique_of("test_1.txt", cleaner)
        by_lower = {}
        for raw in lines_of("test_1.txt"):
            by_lower.setdefault(raw.lower(), set()).add(raw)
        pairs = [sorted(group) for group in by_lower.values() if len(group) > 1]
        self.assertTrue(pairs, "в test_1 нет ящика в двух регистрах — проверять нечего")
        for group in pairs:
            with self.subTest(group=len(group)):
                variants = {normalize_for_dedup(cleaner.clean_email(raw)) for raw in group}
                self.assertEqual(len(variants), 1, "написания одного ящика дали разные ключи")
                self.assertIn(variants.pop(), keys)


class TestVerdicts(unittest.TestCase):

    def test_verdicts_trailing_dot_is_repaired_not_rejected(self):
        cleaner = EmailCleaner()
        for raw in ("marcusvey1994@gmail.com.", "wenlifang.dev@gmail.com."):
            with self.subTest(raw=raw):
                cleaned = cleaner.clean_email(raw)
                self.assertTrue(cleaned, f"{raw}: очистка вернула пусто")
                self.assertFalse(cleaned.endswith("."))
                self.assertTrue(validate_email_syntax(cleaned),
                                f"{raw} -> {cleaned}: не прошёл синтаксис")
                self.assertEqual(check_local_part(cleaned)[0], OK,
                                 f"{cleaned}: починенный адрес получил придирку")

    def test_verdicts_short_gmail_name_never_reaches_valid_silently(self):
        verdict, reason = check_local_part("ca@gmail.com")
        self.assertEqual(verdict, UNLIKELY,
                         "правило длины имени Gmail не сработало вовсе")
        self.assertTrue(reason, "нарушение без объяснения бесполезно пользователю")

    def test_verdicts_backtick_address_is_rescued(self):
        cleaned = EmailCleaner().clean_email("`kpierson@gmail.com")
        self.assertEqual(cleaned, "kpierson@gmail.com")
        self.assertTrue(validate_email_syntax(cleaned),
                        "живой адрес из файла владельца уходит в invalid из-за "
                        "мусорного символа")

    @needs_owner_files
    def test_verdicts_no_owner_address_is_declared_impossible(self):
        cleaner = EmailCleaner()
        condemned = []
        for name in EXPECTED:
            for raw in lines_of(name):
                cleaned = cleaner.clean_email(raw)
                if cleaned and check_local_part(cleaned)[0] == IMPOSSIBLE:
                    condemned.append((name, raw, cleaned))
        self.assertEqual(condemned, [],
                         "правила объявили несуществующими живые адреса: "
                         + str(condemned[:5]))

    def test_verdicts_known_junk_is_still_caught(self):
        self.assertTrue(is_disposable("hacker@tempmail.com"),
                        "одноразовый домен из test.txt не распознан")
        cleaner = EmailCleaner()
        self.assertEqual(cleaner.clean_email("user@gamil.com"),
                         "user@gamil.com",
                         "домен подменён молча — вердикт будет про чужой ящик")
        self.assertEqual(cleaner.suggest_domain_fix("user@gamil.com"),
                         "user@gmail.com",
                         "предложение об исправлении потерялось")


@needs_owner_files
class TestPipeline(unittest.TestCase):

    def test_pipeline_processes_every_line(self):
        cleaner = EmailCleaner()
        processed = 0
        for name in EXPECTED:
            for raw in lines_of(name):
                cleaned = cleaner.clean_email(raw)
                if not cleaned:
                    continue
                normalize_for_dedup(cleaned)
                is_disposable(cleaned)
                is_role_based(cleaned)
                validate_email_syntax(cleaned)
                check_local_part(cleaned)
                processed += 1
        self.assertEqual(processed, 90,
                         f"через конвейер прошло {processed} адресов из 90")

    def test_pipeline_is_deterministic(self):
        first = {name: sorted(unique_of(name)) for name in EXPECTED}
        second = {name: sorted(unique_of(name)) for name in EXPECTED}
        self.assertEqual(first, second,
                         "результат обработки одних и тех же файлов плавает")

    def test_pipeline_disposable_and_role_are_flagged(self):
        found_disposable = [e for e in unique_of("test.txt") if is_disposable(e)]
        self.assertTrue(found_disposable,
                        "в test.txt есть одноразовый адрес, но он не найден")

    def test_pipeline_every_surviving_address_is_syntactically_valid(self):
        cleaner = EmailCleaner()
        broken = []
        for name in EXPECTED:
            for raw in lines_of(name):
                cleaned = cleaner.clean_email(raw)
                if cleaned and not validate_email_syntax(cleaned):
                    broken.append((name, raw, cleaned))
        self.assertEqual(broken, [],
                         "после очистки остались синтаксически битые адреса: "
                         + str(broken[:5]))


if __name__ == "__main__":
    unittest.main()
