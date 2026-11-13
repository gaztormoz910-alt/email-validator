"""Разбор имени на РЕАЛЬНЫХ адресах из баз владельца.

Все адреса здесь взяты из трёх txt-файлов владельца и из его же скриншотов
чужого сервиса. Это не выдуманные примеры: каждый случай кто-то реально
получил в колонке «Имя».

Три класса ошибок, которые здесь закрыты и не должны вернуться:

1. **Ложное имя.** `qqq482615@gmail.com` превращался в «Fff», потому что база
   на 138 млн записей подтверждает почти любое трёхбуквенное сочетание.
   Мусор в колонке хуже пустоты: по нему потом обращаются в письме.

2. **Потерянное имя.** `justinbrody57`, `suelovesfrogs7`, `leo.fontanieu`
   отдавали ПУСТОТУ, хотя имя написано открытым текстом. Виноваты были два
   правила: «слово есть в английском словаре — значит не имя» (под него
   попадали justin, leo, sue) и «кусков больше трёх — сдаёмся».

3. **Разваленное имя.** `johnoakreps` -> «John Oak Reps», `savithrek` ->
   «Sa Vithrek»: английский сегментатор режет чужие фамилии на слова.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser.name_extractor import NameExtractor

_extractor = None


def extractor():
    """Один экземпляр на весь файл: конструктор грузит базу на 138 млн имён."""
    global _extractor
    if _extractor is None:
        _extractor = NameExtractor()
    return _extractor


class TestNoFalseNames(unittest.TestCase):
    """Мусор обязан оставаться пустотой, а не становиться именем."""

    JUNK = [
        "qqq482615@gmail.com",          # обломок из трёх букв
        "qv5871@gmail.com",             # две буквы
        "2018oregonrn@gmail.com",   # год плюс аббревиатура
        "info@company.com",
        "admin@example.com",
        "support@example.com",
        "noreply@example.com",
        "webmaster@example.com",
    ]

    def test_junk_yields_no_name(self):
        for address in self.JUNK:
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address) or "", "",
                                 "мусор попал в колонку «Имя»")


class TestNamesAreNotLost(unittest.TestCase):
    """Имя, написанное в адресе открытым текстом, обязано находиться."""

    KNOWN = {
        # Раньше отдавали пустоту из-за проверки по английскому словарю
        "justinbrody57@gmail.com": "Justin Brody",
        # Имя Sue находится по-прежнему, а хвост «loves frogs» — фраза, а не
        # фамилия: «Sue Lovesfrogs» владелец 06.11.2026 назвал мусором.
        "suelovesfrogs7@gmail.com": "Sue",
        "leo.fontanieu@gmail.com": "Leo Fontanieu",
        # Раньше отдавали пустоту из-за правила «кусков больше трёх». Имя
        # находится, а «da koala girl» — фраза, фамилии в ней нет.
        "rachaeldakoalagirl@gmail.com": "Rachael",
        # Разваливались сегментатором
        "johnoakreps@gmail.com": "John Oakreps",
        "janedoe@gmail.com": "Jane Doe",
        # Работали и раньше — контроль, что починка их не сломала
        "minpark@gmail.com": "Min Park",
        # «Bvk» база фамилий не знает, а три буквы без опоры — обломок, по
        # нему к человеку не обратишься. Имя Salim остаётся.
        "salim.bvk88@gmail.com": "Salim",
        "michaelbauer4321@gmail.com": "Michael Bauer",
        "richardpike2006@gmail.com": "Richard Pike",
        "joshualuna517@gmail.com": "Joshua Luna",
        "stevenliang030@gmail.com": "Steven Liang",
        "gauravkolwar@gmail.com": "Gaurav Kolwar",
        "alvaromendaluz@gmail.com": "Alvaro Mendaluz",
        "harshavemuri29@gmail.com": "Harsha Vemuri",
        # Galang — фамилия, которую база знает (67-е место на Филиппинах), и
        # «m» между именем и ней — средний инициал. «Mdizon» был обломком
        # английского сегментатора.
        "kennethmdizon@gmail.com": "Kenneth M Dizon",
        "sebastienmorvat@gmail.com": "Sebastien Morvat",
        "pavansaimuddam@gmail.com": "Pavan Saimuddam",
        # Cole — имя, Whitlock — фамилия, которую база знает: имя из трёх
        # частей, а не «Colewhitlock», склеенный из обломков.
        "justincolewhitlock@gmail.com": "Justin Cole Whitlock",
        "swathinaidu062001@gmail.com": "Swathi Naidu",
        "jeronimo.alcott@gmail.com": "Jeronimo Alcott",
        "chris.montoya417@gmail.com": "Chris Montoya",
    }

    def test_known_names_are_extracted(self):
        for address, expected in self.KNOWN.items():
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address), expected)


class TestPhraseWordBeforeTheName(unittest.TestCase):
    """Слово фразы перед именем снимается, а не хоронит имя.

    Раньше эти адреса лежали в «мусоре»: английский сегментатор не умел
    снять ведущее «the» и «live» и выдавал «Thea Damvelardes». Теперь куски
    ищутся по индексу имён, и строка читается так, как её прочтёт человек:
    «the|adam|velardes», «live|marko». Для первого это и есть настоящее имя
    — его подтверждает профиль Gravatar того же адреса
    (tests/test_enrichment_sources.py, «Adam Velardes»).
    """

    def test_leading_phrase_word_is_dropped(self):
        for address, expected in (("theadamvelardes@gmail.com", "Adam Velardes"),
                                  ("livemarko@gmail.com", "Nicko")):
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address) or "", expected)


class TestExplicitSeparatorsAreRespected(unittest.TestCase):
    """Точку в адресе поставил человек — чинить её нельзя.

    Починка развала предназначена для СЛИТНЫХ строк, которые режет
    сегментатор. Применённая к явным разделителям, она склеивала куски
    обратно: `bo.johansson` превращался в «Bojohansson», а
    `jonathan.k.ward` — в «Jonathan Kward».
    """

    CASES = {
        "john.smith@example.com": "John Smith",
        "j.smith@example.com": "J Smith",
        "bo.johansson@example.com": "Bo Johansson",
        "ed.harris@example.com": "Ed Harris",
        "jo.baker@example.com": "Jo Baker",
        "jonathan.k.ward2@gmail.com": "Jonathan K Ward",
        "nikhil.ram.sethi@gmail.com": "Nikhil Ram Sethi",
        "leo.fontanieu@gmail.com": "Leo Fontanieu",
        "george.lam77@gmail.com": "George Lam",
    }

    def test_separated_parts_stay_separate(self):
        for address, expected in self.CASES.items():
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address), expected)


class TestMultipartNamesSurvive(unittest.TestCase):
    """Настоящее трёхсоставное имя не должно склеиваться в фамилию.

    Склейка хвоста чинит развал сегментатора, но вьетнамские и китайские
    имена из трёх частей — не развал. Отличаются они тем, что КАЖДУЮ часть
    знает индекс популярных имён.
    """

    def test_vietnamese_three_part_name(self):
        self.assertEqual(extractor().extract_name("minhanhtran07@gmail.com"),
                         "Minh Anh Tran")

    def test_positive_control_fake_three_part_is_collapsed(self):
        """Контроль: похожая по форме, но НЕ именная тройка обязана склеиться.

        Без него предыдущая проверка была бы зелёной и в том случае, если
        склейка вообще перестала работать.
        """
        self.assertEqual(extractor().extract_name("johnoakreps@gmail.com"),
                         "John Oakreps")


class TestBusinessWordsTrimmedNotFatal(unittest.TestCase):
    """Род занятий рядом с личным именем не должен хоронить имя целиком."""

    def test_trailing_business_word_is_dropped(self):
        self.assertEqual(extractor().extract_name("laura.ribeiro.tech@gmail.com"),
                         "Laura Ribeiro")

    def test_business_address_still_yields_nothing(self):
        for address in ("info.tech@company.com", "sales.group@company.com",
                        "support.services@company.com"):
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address) or "", "")


class TestFusedSlavicAddressesSurvive(unittest.TestCase):
    """Слитные адреса со славянской фамилией — самая заметная проверка из всех."""

    def test_fused_names(self):
        cases = {
            "rogbinanatol1@gmail.com": "Rogbin Anatol",
            "rogbina@gmail.com": "Rogbin A",
            # `zvanatol` — сокращённая фамилия плюс имя. Разобрать это верно
            # нельзя: «zv» не имя и не инициал, а обрубок, и выдать «Zv
            # Anatol» значило бы поставить в колонку то, чего в адресе нет.
            # Пустота честнее — она хотя бы не попадёт в обращение письма.
            "zvanatol264@gmail.com": "",
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address) or "", expected)


class TestGarbageInput(unittest.TestCase):
    def test_broken_input_does_not_crash(self):
        for junk in (None, "", "   ", "@", "a@", "@b.com", 0, [], {},
                     "a" * 500 + "@b.com", "\x00@b.com", b"a@b.com"):
            with self.subTest(junk=junk):
                result = extractor().extract_name(junk)
                self.assertIn(type(result).__name__, ("str", "NoneType"))


if __name__ == "__main__":
    unittest.main()
