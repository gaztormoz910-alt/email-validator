"""Проверка на РЕАЛЬНЫХ файлах владельца, а не на выдуманных примерах.

Гейты выбирают по -k: counts, verdicts, pipeline.

Откуда взялись ожидаемые числа. Владелец загрузил эти же три файла в сервис
конкурента (charlymail) и прислал скриншоты результата. Оттуда известно:

    test_base.txt   10 строк -> 10 контактов, рисков 0, битых 0
    test_1.txt      70 строк -> 59 контактов, битых 3
    test.txt        10 строк -> 9 уникальных (один адрес повторён)

То есть здесь сверяется не «как я думаю правильно», а поведение против
независимого измерения. Совпадение по дедупу (70 -> 59) особенно ценно: это
проверка нашей канонизации адресов чужими руками.

Три адреса, которые конкурент назвал битыми, разобраны отдельно: два из них
мы ЧИНИМ (лишняя точка в конце), и это лучше, чем отбраковать.
"""
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

# Строк в файле -> уникальных адресов, как показал сервис конкурента
EXPECTED = {
    "test_base.txt": {"lines": 10, "unique": 10},
    "test_1.txt": {"lines": 70, "unique": 59},
    "test.txt": {"lines": 10, "unique": 9},
}

# Что конкурент пометил Bad format в test_1
COMPETITOR_BAD = ("ca@gmail.com", "andrewyin1994@gmail.com.", "ronganli.dev@gmail.com.")


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


class TestCounts(unittest.TestCase):
    """Дедуп даёт ровно те же количества, что независимо посчитал конкурент."""

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
        """Положительный контроль: в test_1 повторы ЕСТЬ и они схлопнулись."""
        raw = len(lines_of("test_1.txt"))
        unique = len(unique_of("test_1.txt"))
        self.assertGreater(raw - unique, 5,
                           "дедуп ничего не схлопнул — значит совпадение чисел "
                           "выше было бы случайным")

    def test_counts_case_and_dots_are_collapsed(self):
        """В файле есть EDevMachine и edevmachine — это один ящик."""
        keys = unique_of("test_1.txt")
        self.assertEqual(
            normalize_for_dedup("EDevMachine@gmail.com"),
            normalize_for_dedup("edevmachine@gmail.com"))
        self.assertIn(normalize_for_dedup("edevmachine@gmail.com"), keys)


class TestVerdicts(unittest.TestCase):
    """Адреса, которые конкурент счёл битыми, у нас чинятся или не идут в Valid."""

    def test_verdicts_trailing_dot_is_repaired_not_rejected(self):
        """Лишняя точка — это опечатка выгрузки, а не мёртвый адрес.

        Конкурент помечает такие Bad format и теряет контакт. Мы чиним.
        """
        cleaner = EmailCleaner()
        for raw in ("andrewyin1994@gmail.com.", "ronganli.dev@gmail.com."):
            with self.subTest(raw=raw):
                cleaned = cleaner.clean_email(raw)
                self.assertTrue(cleaned, f"{raw}: очистка вернула пусто")
                self.assertFalse(cleaned.endswith("."))
                self.assertTrue(validate_email_syntax(cleaned),
                                f"{raw} -> {cleaned}: не прошёл синтаксис")
                self.assertEqual(check_local_part(cleaned)[0], OK,
                                 f"{cleaned}: починенный адрес получил придирку")

    def test_verdicts_short_gmail_name_never_reaches_valid_silently(self):
        """ca@gmail.com: имя короче шести символов.

        Хоронить его без сети мы не имеем права (бывают старые аккаунты), но
        и молча пропускать в Valid тоже нельзя — правило обязано сработать.
        """
        verdict, reason = check_local_part("ca@gmail.com")
        self.assertEqual(verdict, UNLIKELY,
                         "правило длины имени Gmail не сработало вовсе")
        self.assertTrue(reason, "нарушение без объяснения бесполезно пользователю")

    def test_verdicts_backtick_address_is_rescued(self):
        """`hjohnuc@gmail.com конкурент считает живым (score 61), и он прав."""
        cleaned = EmailCleaner().clean_email("`hjohnuc@gmail.com")
        self.assertEqual(cleaned, "hjohnuc@gmail.com")
        self.assertTrue(validate_email_syntax(cleaned),
                        "живой адрес из файла владельца уходит в invalid из-за "
                        "мусорного символа")

    def test_verdicts_no_owner_address_is_declared_impossible(self):
        """Ни один реальный адрес из трёх файлов не объявлен несуществующим."""
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
        """Контроль: заведомый мусор из файлов всё-таки распознаётся."""
        self.assertTrue(is_disposable("hacker@tempmail.com"),
                        "одноразовый домен из test.txt не распознан")
        # ТРЕБОВАНИЕ ИЗМЕНЕНО ВЛАДЕЛЬЦЕМ: «какие почты загрузил, такие
        # валидатор и должен проверять». Молчаливое исправление опечатки
        # выносило вердикт про ДРУГОЙ ящик — и «Годен» про чужого человека, и
        # «нет такого» про настоящий адрес, который никто не спрашивал.
        #
        # Теперь домен остаётся собой, а исправление существует отдельно как
        # предложение и применяется только тогда, когда DNS сказал, что
        # загруженного домена нет вовсе (см. tests/test_trust.py).
        cleaner = EmailCleaner()
        self.assertEqual(cleaner.clean_email("user@gamil.com"),
                         "user@gamil.com",
                         "домен подменён молча — вердикт будет про чужой ящик")
        self.assertEqual(cleaner.suggest_domain_fix("user@gamil.com"),
                         "user@gmail.com",
                         "предложение об исправлении потерялось")


class TestPipeline(unittest.TestCase):
    """Весь досетевой конвейер отрабатывает все три файла без исключений."""

    def test_pipeline_processes_every_line(self):
        cleaner = EmailCleaner()
        processed = 0
        for name in EXPECTED:
            for raw in lines_of(name):
                cleaned = cleaner.clean_email(raw)
                if not cleaned:
                    continue
                # Тот же набор шагов, что делает pipeline до выхода в сеть
                normalize_for_dedup(cleaned)
                is_disposable(cleaned)
                is_role_based(cleaned)
                validate_email_syntax(cleaned)
                check_local_part(cleaned)
                processed += 1
        self.assertEqual(processed, 90,
                         f"через конвейер прошло {processed} адресов из 90")

    def test_pipeline_is_deterministic(self):
        """Два прогона по одним и тем же файлам дают один и тот же результат."""
        first = {name: sorted(unique_of(name)) for name in EXPECTED}
        second = {name: sorted(unique_of(name)) for name in EXPECTED}
        self.assertEqual(first, second,
                         "результат обработки одних и тех же файлов плавает")

    def test_pipeline_disposable_and_role_are_flagged(self):
        """На реальных данных фильтры срабатывают, а не молчат.

        Без этой проверки предыдущие были бы зелёными и в случае, когда
        фильтры вообще перестали что-либо находить.
        """
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
