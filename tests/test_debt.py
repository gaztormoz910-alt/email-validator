# -*- coding: utf-8 -*-
import os
import random
import unittest

import pytest

from core.provider import (canonical_country, canonical_gender,
                           country_is_known, _КАНОНИЧЕСКИЕ_СТРАНЫ)
from core.streamer import (StreamLoader, _COUNTRY_VALUES, _адрес_из_части,
                           _имя_из_обёртки, _починить_пробел_в_домене,
                           _похоже_на_колонку_паролей)

ГОЛОВА = "\n".join([
    "QOVARESTE@YAHOO.COM,MAURICIO",
    "ccaltrovez8@yahoo.com,Crystal",
    "CLDIXIE.MORVANE@AOL.COM,DIXIE",
    "d6bgelvin@realty-example.com,Stephen",
    "darvelind2@gmail.com,Deborah",
    "c5dmarlowe@netzero.net,Daniel",
    "cilox3001f4@yahoo.com,Theresa",
    "chswerti1@stonepath-example.com,Idiot",
    "bforvelind0@aol.com,Betty",
    "bcolverx2@erols.com,Bethany",
])


def выдача(текст, заметки=None):
    источник = [{"type": "text", "content": текст}]
    подписчик = заметки.append if заметки is not None else None
    return list(StreamLoader(источник, on_note=подписчик).stream_emails())


def строка_в_контексте(строка):
    выдано = выдача(ГОЛОВА + "\n" + строка)
    assert len(выдано) == 11, "строка не доехала: " + строка
    return выдано[-1]


СЛОГИ = ["qwe", "asd", "zxc", "poi", "lkj", "mnb", "tre", "ghj", "vbn",
         "rty", "fgh", "cvb", "hjk", "wer", "sdf"]
ВЬЕТНАМСКИЕ = ["Nguyen", "Tran", "Le", "Pham", "Hoang", "Phan", "Vu",
               "Dang", "Bui", "Do"]
ИМЕНА_США = ["MAURICIO", "Crystal", "DIXIE", "Stephen", "Deborah", "Daniel",
             "Theresa", "Idiot", "Betty", "Bethany", "John", "Mary", "David",
             "Sarah", "Michael"]


def _колонка(значения):
    return "\n".join("u%d@x%d.com:%s" % (i, i % 50, значение)
                     for i, значение in enumerate(значения))


class TestКолонкаПаролей(unittest.TestCase):

    def setUp(self):
        random.seed(7)

    def test_пароли_не_становятся_именами(self):
        пароли = ["".join(random.choice(СЛОГИ) for _ in range(3))
                  for _ in range(200)]
        заметки = []
        выдано = выдача(_колонка(пароли), заметки)
        self.assertEqual(len(выдано), 200)
        self.assertEqual([д["name"] for _, д in выдано], [""] * 200)
        self.assertTrue(заметки, "решение принято молча")

    def test_решение_объявлено_вслух(self):
        пароли = ["".join(random.choice(СЛОГИ) for _ in range(3))
                  for _ in range(200)]
        заметки = []
        выдача(_колонка(пароли), заметки)
        self.assertEqual(len(заметки), 1)
        self.assertIn("пароли", заметки[0].lower())

    def test_вьетнамские_фамилии_не_теряются(self):
        значения = [random.choice(ВЬЕТНАМСКИЕ) for _ in range(200)]
        заметки = []
        выдано = выдача(_колонка(значения), заметки)
        self.assertEqual(заметки, [])
        self.assertTrue(all(д["name"] for _, д in выдано))

    def test_обычные_имена_не_теряются(self):
        значения = [random.choice(ИМЕНА_США) for _ in range(200)]
        заметки = []
        выдано = выдача(_колонка(значения), заметки)
        self.assertEqual(заметки, [])
        self.assertTrue(all(д["name"] for _, д in выдано))

    def test_полные_имена_не_теряются(self):
        значения = ["%s %s" % (random.choice(["William", "Robert", "Eric",
                                              "Marc", "Susan", "Linda"]),
                               random.choice(["Lynch", "Hamilton", "Springle",
                                              "Horten", "Miller", "Davis"]))
                    for _ in range(200)]
        заметки = []
        выдано = выдача(_колонка(значения), заметки)
        self.assertEqual(заметки, [])
        self.assertTrue(all(д["name"] for _, д in выдано))

    def test_вьетнамские_полные_имена_не_теряются(self):
        значения = ["%s %s %s" % (random.choice(ВЬЕТНАМСКИЕ),
                                  random.choice(["Van", "Thi", "Duc"]),
                                  random.choice(["An", "Binh", "Cuong"]))
                    for _ in range(200)]
        заметки = []
        выдано = выдача(_колонка(значения), заметки)
        self.assertEqual(заметки, [])
        self.assertTrue(all(д["name"] for _, д in выдано))

    def test_на_малой_пробе_правило_молчит(self):
        пароли = ["".join(random.choice(СЛОГИ) for _ in range(3))
                  for _ in range(20)]
        заметки = []
        выдано = выдача(_колонка(пароли), заметки)
        self.assertEqual(заметки, [])
        self.assertEqual(len(выдано), 20)

    def test_мусор_не_роняет(self):
        for значение in [None, "", 42, [], {}, [None, 42], ["a"] * 500]:
            with self.subTest(значение=значение):
                self.assertIsInstance(_похоже_на_колонку_паролей(значение),
                                      bool)


class TestИмяВУгловыхСкобках(unittest.TestCase):

    def test_имя_и_адрес_берутся_оба(self):
        выдано = выдача("Ivan Petrov <ivan@gmail.com>\n"
                        "Mary Smith <mary@x.com>")
        self.assertEqual([п for п, _ in выдано],
                         ["ivan@gmail.com", "mary@x.com"])
        self.assertEqual([д["name"] for _, д in выдано],
                         ["Ivan Petrov", "Mary Smith"])

    def test_без_подписи_имени_нет(self):
        _, данные = выдача("<solo@x.com>")[0]
        self.assertEqual(данные["name"], "")

    def test_подпись_не_перебивает_настоящую_колонку_имени(self):
        почта, данные = строка_в_контексте(
            "Ivan Petrov <ivan@gmail.com>,Настоящее Имя")
        self.assertEqual(почта, "ivan@gmail.com")
        self.assertEqual(данные["name"], "Настоящее Имя")

    def test_мусорная_подпись_не_проходит(self):
        for часть in ["<a@b.com>", "123 <a@b.com>", "a@b.com <c@d.com>",
                      "p@ssw0rd1 <a@b.com>", "<>", "a@b.com"]:
            with self.subTest(часть=часть):
                self.assertEqual(_имя_из_обёртки(часть), "")

    def test_мусор_не_роняет(self):
        for часть in [None, 42, [], "", "<" * 500]:
            with self.subTest(часть=часть):
                self.assertEqual(_имя_из_обёртки(часть), "")


class TestСловариСтранНеРасходятся(unittest.TestCase):

    def test_ни_одного_безымянного_слова(self):
        безымянные = sorted(
            слово for слово in _COUNTRY_VALUES
            if canonical_country(слово) not in _КАНОНИЧЕСКИЕ_СТРАНЫ)
        self.assertEqual(безымянные, [])

    def test_словарь_не_опустел(self):
        self.assertGreater(len(_COUNTRY_VALUES), 300)

    def test_русские_написания(self):
        for слово, ждём in [("сша", "США"), ("германия", "Германия"),
                            ("япония", "Япония"), ("юар", "ЮАР"),
                            ("оаэ", "ОАЭ"), ("южная корея", "Южная Корея")]:
            with self.subTest(слово=слово):
                self.assertEqual(canonical_country(слово), ждём)

    def test_великобритания(self):
        for слово in ["great britain", "Great Britain", "united kingdom",
                      "UK", "gb"]:
            with self.subTest(слово=слово):
                self.assertEqual(canonical_country(слово), "Великобритания")

    def test_строка_37379_файла_владельца(self):
        почта, данные = строка_в_контексте(
            "Jones,jonesg2490@gmail.com,Great Britain (Uk)")
        self.assertEqual(почта, "jonesg2490@gmail.com")
        self.assertEqual(данные["country"], "Великобритания")
        self.assertEqual(данные["name"], "Jones")

    def test_country_is_known(self):
        for значение in ["USA", "сша", "Россия", "Great Britain", "ru",
                         "Чад", "Ямайка"]:
            with self.subTest(значение=значение):
                self.assertTrue(country_is_known(значение), значение)
        for значение in ["Freedonia", "xx", "", None, 42, "secretword"]:
            with self.subTest(значение=значение):
                self.assertFalse(country_is_known(значение))

    def test_определение_страны_по_домену_не_тронуто(self):
        from core.provider import country_from_domain
        self.assertEqual(country_from_domain("x.ru"), "Россия")
        self.assertEqual(country_from_domain("web.de"), "Германия")
        self.assertEqual(country_from_domain("x.ao"), "")
        self.assertEqual(country_from_domain("x.sr"), "")


class TestСпорноеСловоИзАдреса(unittest.TestCase):

    def test_имя_совпавшее_со_страной_видно_по_адресу(self):
        for строка, имя, страна in [
                ("Jamaica,jamaica.ivey@flash.net,male,USA", "Jamaica", "США"),
                ("Germany,germany.tongish@bellsouth.net,female,USA",
                 "Germany", "США")]:
            with self.subTest(строка=строка):
                _, данные = строка_в_контексте(строка)
                self.assertEqual(данные["name"], имя)
                self.assertEqual(данные["country"], страна)

    def test_случайная_подстрока_страну_не_отнимает(self):
        for строка in ["tanjusaymontejesseal@yahoo.com,,USA",
                       "romernusabhsn@yahoo.co.id,,USA"]:
            with self.subTest(строка=строка):
                _, данные = строка_в_контексте(строка)
                self.assertEqual(данные["country"], "США")

    def test_адрес_сильнее_позиции(self):
        _, данные = строка_в_контексте(
            "USA,jamaica.ivey@flash.net,Jamaica")
        self.assertEqual(данные["name"], "Jamaica")
        self.assertEqual(данные["country"], "США")

    def test_двух_стран_у_человека_не_бывает(self):
        for строка, имя in [("Togo,wendy045@gmail.com,male,USA", "Togo"),
                            ("Cuba,csundar@yahoo.com,female,USA", "Cuba")]:
            with self.subTest(строка=строка):
                _, данные = строка_в_контексте(строка)
                self.assertEqual(данные["country"], "США")
                self.assertEqual(данные["name"], имя)

    def test_одна_страна_остаётся_страной(self):
        for строка in ["USA,x@y.com", "united states,eborneke@hotmail.com",
                       "x@y.com,Ivan,male,сша"]:
            with self.subTest(строка=строка):
                _, данные = строка_в_контексте(строка)
                self.assertEqual(данные["country"], "США")


class TestКавычкиВнутриИмени(unittest.TestCase):

    def test_прозвище_в_кавычках_цело(self):
        _, данные = строка_в_контексте('gregcasar@gmail.com,Gregorio "Greg",USA')
        self.assertEqual(данные["name"], 'Gregorio "Greg"')

    def test_непарная_кавычка_снимается(self):
        _, данные = строка_в_контексте('x@y.com,"Doe,USA')
        self.assertEqual(данные["name"], "Doe")


class TestДвеСобаки(unittest.TestCase):

    def test_из_двух_адресов_остаётся_один(self):
        выдано = выдача(
            ГОЛОВА + "\nmaria.fultz@precon.com # mariafultz@pcdci.com,"
            "maria,female,united states")
        self.assertEqual(len(выдано), 11)
        почта, данные = выдано[-1]
        self.assertEqual(почта, "maria.fultz@precon.com")
        self.assertEqual(данные["name"], "maria")
        self.assertEqual(данные["gender"], "Женский")
        self.assertEqual(данные["country"], "США")

    def test_склеенные_вплотную_остаются_одной_битой_строкой(self):
        from core.email_syntax import validate_email_syntax
        for строка in ["duncan.dzlzgrl819@insightbb.com@yahoo.com",
                       "bunnellsabunnells@yahoo.com@hotmail.com",
                       "Rbaseinger@gmail@gmail.com"]:
            with self.subTest(строка=строка):
                выдано = выдача(ГОЛОВА + "\n" + строка + ",Some,USA")
                self.assertEqual(len(выдано), 11)
                self.assertFalse(validate_email_syntax(выдано[-1][0]))


class TestПробелВнутриАдреса(unittest.TestCase):

    ЧИНИТСЯ = [
        ("jumpsdropskicks@aol. com", "jumpsdropskicks@aol.com"),
        ("saritha.sv@gmail. com", "saritha.sv@gmail.com"),
        ("Onecrazyhouse@ live.com", "Onecrazyhouse@live.com"),
        ("Emadels@ ix.netcom.com", "Emadels@ix.netcom.com"),
    ]

    НЕ_ЧИНИТСЯ = [
        "donald.m ross@yahoo.com",
        "mary beth tyler_tood@verizon.net",
        "clarencejohnson sr@yahoo.com",
        "juanita.modisett claybon@yahoo.com",
        "darcy thompson_darcy thompson@yahoo.com",
    ]

    def test_пробел_в_домене_чинится(self):
        for испорчен, ждём in self.ЧИНИТСЯ:
            with self.subTest(испорчен=испорчен):
                self.assertEqual(_починить_пробел_в_домене(испорчен), ждём)
                self.assertEqual(_адрес_из_части(испорчен), ждём)

    def test_пробел_в_имени_ящика_не_трогаем(self):
        for испорчен in self.НЕ_ЧИНИТСЯ:
            with self.subTest(испорчен=испорчен):
                self.assertEqual(_починить_пробел_в_домене(испорчен), "")

    def test_имя_ящика_переносится_дословно(self):
        для_проверки = [и for и, _ in self.ЧИНИТСЯ] + self.НЕ_ЧИНИТСЯ + [
            '"john smith"@x. com', "a.b@c d.com", "a@b. c. com"]
        сработало = 0
        for испорчен in для_проверки:
            with self.subTest(испорчен=испорчен):
                готово = _починить_пробел_в_домене(испорчен)
                if not готово:
                    continue
                сработало += 1
                self.assertEqual(готово.rsplit("@", 1)[0],
                                 испорчен.rsplit("@", 1)[0])
        self.assertGreaterEqual(сработало, 4, "починка не сработала ни разу — "
                                "проверка стала бы пустой")

    def test_имя_ящика_в_кавычках_чинится_как_все(self):
        self.assertEqual(_починить_пробел_в_домене('"john smith"@x. com'),
                         '"john smith"@x.com')

    def test_битый_адрес_с_пробелом_в_имени_всё_равно_доезжает(self):
        from core.email_syntax import validate_email_syntax
        почта, _ = строка_в_контексте("donald.m ross@yahoo.com,Donald,USA")
        self.assertIn("@", почта)
        self.assertFalse(validate_email_syntax(почта))

    def test_починка_только_если_результат_законен(self):
        for испорчен in ["a@b c", "a@ .com", "a@b. ", "@ x.com"]:
            with self.subTest(испорчен=испорчен):
                готово = _починить_пробел_в_домене(испорчен)
                if готово:
                    from core.email_syntax import validate_email_syntax
                    self.assertTrue(validate_email_syntax(готово))

    def test_мусор_не_роняет(self):
        for значение in [None, 42, [], "", "@@@", "a@b@c", "a b c"]:
            with self.subTest(значение=значение):
                self.assertIsInstance(_починить_пробел_в_домене(значение), str)


ФАЙЛ_ПО_УМОЛЧАНИЮ = ""


def _путь_к_файлу():
    return os.environ.get("VALIDATOR_OWNER_RECIPIENTS") or ФАЙЛ_ПО_УМОЛЧАНИЮ


нужен_файл = pytest.mark.skipif(
    not os.path.exists(_путь_к_файлу()),
    reason="файл получателей владельца лежит вне репозитория")


@нужен_файл
class TestФайлВладельцаПослеДолга(unittest.TestCase):

    ВСЕГО_АДРЕСОВ = 412733
    СТРАН_НЕ_МЕНЬШЕ = 386179
    ПОЛОВ_НЕ_МЕНЬШЕ = 16928

    @classmethod
    def setUpClass(cls):
        cls.всего = cls.со_страной = cls.с_полом = 0
        cls.страны = set()
        cls.полы = set()
        cls.адреса_с_пробелом = 0
        источник = [{"type": "file", "path": _путь_к_файлу()}]
        for почта, данные in StreamLoader(источник).stream_emails():
            cls.всего += 1
            if " " in почта:
                cls.адреса_с_пробелом += 1
            пол = (данные.get("gender") or "").strip()
            страна = (данные.get("country") or "").strip()
            if пол:
                cls.с_полом += 1
                cls.полы.add(пол)
            if страна:
                cls.со_страной += 1
                cls.страны.add(страна)

    def test_адресов_столько_же(self):
        self.assertEqual(self.всего, self.ВСЕГО_АДРЕСОВ)

    def test_страна_не_просела(self):
        self.assertGreaterEqual(self.со_страной, self.СТРАН_НЕ_МЕНЬШЕ)

    def test_пол_не_просел(self):
        self.assertGreaterEqual(self.с_полом, self.ПОЛОВ_НЕ_МЕНЬШЕ)

    def test_все_страны_канонические(self):
        self.assertLessEqual(self.страны, set(_КАНОНИЧЕСКИЕ_СТРАНЫ))
        self.assertIn("Великобритания", self.страны)

    def test_все_полы_канонические(self):
        self.assertLessEqual(self.полы, {"Мужской", "Женский"})

    def test_пробелы_внутри_адресов_остались_видимыми(self):
        self.assertGreater(self.адреса_с_пробелом, 400)
        self.assertLess(self.адреса_с_пробелом, 3000)


class TestПриведениеНеПотерялоЗначения(unittest.TestCase):

    def test_страна(self):
        self.assertEqual(canonical_country("Freedonia"), "Freedonia")
        self.assertEqual(canonical_country("Indiana"), "Indiana")

    def test_пол(self):
        self.assertEqual(canonical_gender("небинарный"), "небинарный")
