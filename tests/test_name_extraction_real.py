"""Разбор имени на РЕАЛЬНЫХ адресах из баз владельца.

Все адреса здесь взяты из трёх txt-файлов владельца и из его же скриншотов
чужого сервиса. Это не выдуманные примеры: каждый случай кто-то реально
получил в колонке «Имя».

Три класса ошибок, которые здесь закрыты и не должны вернуться:

1. **Ложное имя.** `fff089739@gmail.com` превращался в «Fff», потому что база
   на 138 млн записей подтверждает почти любое трёхбуквенное сочетание.
   Мусор в колонке хуже пустоты: по нему потом обращаются в письме.

2. **Потерянное имя.** `justinkyle89`, `suelovesjunk3`, `leo.duquesnel`
   отдавали ПУСТОТУ, хотя имя написано открытым текстом. Виноваты были два
   правила: «слово есть в английском словаре — значит не имя» (под него
   попадали justin, leo, sue) и «кусков больше трёх — сдаёмся».

3. **Разваленное имя.** `johnacreps` -> «John Acre Ps», `pavithrav` ->
   «Pa Vithrav»: английский сегментатор режет чужие фамилии на слова.
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
        "fff089739@gmail.com",          # обломок из трёх букв
        "jy6993@gmail.com",             # две буквы
        "2018californiarn@gmail.com",   # год плюс аббревиатура
        "livenicko@gmail.com",          # начинается со служебного слова
        "theadamoliveras@gmail.com",    # то же самое
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
        "justinkyle89@gmail.com": "Justin Kyle",
        "suelovesjunk3@gmail.com": "Sue Lovesjunk",
        "leo.duquesnel@gmail.com": "Leo Duquesnel",
        # Раньше отдавали пустоту из-за правила «кусков больше трёх»
        "rachaeldaslothgirl@gmail.com": "Rachael Daslothgirl",
        # Разваливались сегментатором
        "johnacreps@gmail.com": "John Acreps",
        "janedoe@gmail.com": "Jane Doe",
        # Работали и раньше — контроль, что починка их не сломала
        "changpark@gmail.com": "Chang Park",
        "salim.atm88@gmail.com": "Salim Atm",
        "michaelkoch4444@gmail.com": "Michael Koch",
        "richardsang2008@gmail.com": "Richard Sang",
        "joshuavera265@gmail.com": "Joshua Vera",
        "stevenhuang010@gmail.com": "Steven Huang",
        "gauravgaggar@gmail.com": "Gaurav Gaggar",
        "alvarolandaluce@gmail.com": "Alvaro Landaluce",
        "harshagattu31@gmail.com": "Harsha Gattu",
        "kennethmgalang@gmail.com": "Kenneth Mgalang",
        "sebastiencallait@gmail.com": "Sebastien Callait",
        "pavansaichennam@gmail.com": "Pavan Saichennam",
        "justincolefrawley@gmail.com": "Justin Colefrawley",
        "swathireddy052000@gmail.com": "Swathi Reddy",
        "jeronimo.cuthbert@gmail.com": "Jeronimo Cuthbert",
        "chris.velasquez511@gmail.com": "Chris Velasquez",
    }

    def test_known_names_are_extracted(self):
        for address, expected in self.KNOWN.items():
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address), expected)


class TestExplicitSeparatorsAreRespected(unittest.TestCase):
    """Точку в адресе поставил человек — чинить её нельзя.

    Починка развала предназначена для СЛИТНЫХ строк, которые режет
    сегментатор. Применённая к явным разделителям, она склеивала куски
    обратно: `bo.johansson` превращался в «Bojohansson», а
    `jonathan.y.tom` — в «Jonathan Ytom».
    """

    CASES = {
        "john.smith@example.com": "John Smith",
        "j.smith@example.com": "J Smith",
        "bo.johansson@example.com": "Bo Johansson",
        "ed.harris@example.com": "Ed Harris",
        "jo.baker@example.com": "Jo Baker",
        "jonathan.y.tom1@gmail.com": "Jonathan Y Tom",
        "satwik.yash.padhy@gmail.com": "Satwik Yash Padhy",
        "leo.duquesnel@gmail.com": "Leo Duquesnel",
        "george.sam91@gmail.com": "George Sam",
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
        self.assertEqual(extractor().extract_name("haingocnguyen21@gmail.com"),
                         "Hai Ngoc Nguyen")

    def test_positive_control_fake_three_part_is_collapsed(self):
        """Контроль: похожая по форме, но НЕ именная тройка обязана склеиться.

        Без него предыдущая проверка была бы зелёной и в том случае, если
        склейка вообще перестала работать.
        """
        self.assertEqual(extractor().extract_name("johnacreps@gmail.com"),
                         "John Acreps")


class TestBusinessWordsTrimmedNotFatal(unittest.TestCase):
    """Род занятий рядом с личным именем не должен хоронить имя целиком."""

    def test_trailing_business_word_is_dropped(self):
        self.assertEqual(extractor().extract_name("laura.oliveira.tech@gmail.com"),
                         "Laura Oliveira")

    def test_business_address_still_yields_nothing(self):
        for address in ("info.tech@company.com", "sales.group@company.com",
                        "support.services@company.com"):
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address) or "", "")


class TestOwnerAddressesSurvive(unittest.TestCase):
    """Адреса самого владельца — самая заметная проверка из всех."""

    def test_owner_names(self):
        cases = {
            "kovbinbogdan1@gmail.com": "Kovbin Bogdan",
            "kovbinb@gmail.com": "Kovbin B",
            # `tsbogdan` — сокращённая фамилия плюс имя. Разобрать это верно
            # нельзя: «ts» не имя и не инициал, а обрубок, и выдать «Ts
            # Bogdan» значило бы поставить в колонку то, чего в адресе нет.
            # Пустота честнее — она хотя бы не попадёт в обращение письма.
            "tsbogdan264@gmail.com": "",
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
