# -*- coding: utf-8 -*-
"""Любой порядок полей во входном файле: почта обязательна, остальное — нет.

Требование владельца от 06.09.2026 дословно: софт обязан принимать почту,
имя, гендер и страну в ЛЮБОМ порядке и в любой комбинации, почта — единственное
обязательное поле. Если в файле есть всё — обогащать нечего, надо только
проверить; если чего-то нет — дополнять только пробелы.

Что здесь сторожится и почему именно это.

1. ГРАММАТИКА. Ветка для не-ASCII имени ящика проверяла только точки, и
   строка `Иван,Мужской,Россия,ivan@gmail.com` признавалась ОДНИМ законным
   адресом. Загрузчик на этом основании не дробил её вовсе. С латиницей тот
   же файл разбирался верно — то есть поведение зависело от алфавита.

2. РАЗДЕЛИТЕЛЬ «|». Вертикальная черта входит в atext RFC 5322, поэтому
   `Ivan|ivan@gmail.com` проходил проверку целиком — и на латинице тоже.

3. РАСКЛАДКА НА СТРОКУ. Карта колонок одна на весь файл, а файл владельца
   неоднороден: 345 921 строка с почтой в первой колонке и 66 812 во второй,
   страна в третьей и четвёртой. Страна и пол выбрасывались целиком.

4. НИ ОДИН АДРЕС НЕ ТЕРЯЕТСЯ. Строка с испорченным адресом обязана доехать
   до проверки и получить там честное «неправильный синтаксис». Молча
   выброшенный контакт хуже видимого отказа: его исчезновение не заметит
   ни лог, ни счётчик.
"""
import itertools
import os
import unittest

import pytest

from core.email_syntax import validate_email_syntax
from core.provider import canonical_country, canonical_gender
from core.streamer import (StreamLoader, _detect_column_map, _detect_delimiter,
                           _parse_line_smart, _разделитель_снаружи)


def выдача(текст):
    """Что загрузчик отдаёт из куска текста."""
    return list(StreamLoader([{"type": "text", "content": текст}]).stream_emails())


def разбор(строка):
    """Строка в контексте настоящей головы файла владельца.

    Карту колонок нельзя снимать с той же одной строки, которую разбираешь:
    голосование по одной строке — это не карта, а её собственное содержимое,
    и проверка вырождается в тавтологию. У владельца карта снимается с
    десятка первых строк файла, поэтому и здесь так же.
    """
    выдано = выдача(ГОЛОВА + "\n" + строка)
    assert len(выдано) == len(ГОЛОВА.split("\n")) + 1, "строка не доехала"
    return выдано[-1]


# --------------------------------------------------------------------------
# 1. Грамматика имени ящика
# --------------------------------------------------------------------------

class TestГрамматикаUTF8(unittest.TestCase):
    """Не-ASCII имя ящика подчиняется той же грамматике, что и латинское.

    RFC 6531 расширяет НАБОР ЗНАКОВ, а не грамматику dot-atom. Проверяем это
    парами: одна и та же форма на латинице и на кириллице обязана получать
    ОДИН вердикт. Пара — это и есть обратный контроль: пока ветки расходились,
    любая такая пара давала (False, True).
    """

    ПАРЫ = [
        ("ivan,ivan@gmail.com", "иван,ivan@gmail.com"),
        ("ivan;ivan@gmail.com", "иван;ivan@gmail.com"),
        ("ivan:ivan@gmail.com", "иван:ivan@gmail.com"),
        ("ivan ivan@gmail.com", "иван иван@gmail.com"),
        ("ivan<ivan@gmail.com", "иван<ivan@gmail.com"),
        ("ivan[ivan@gmail.com", "иван[ivan@gmail.com"),
        (".ivan@gmail.com", ".иван@gmail.com"),
        ("ivan.@gmail.com", "иван.@gmail.com"),
        ("iv..an@gmail.com", "ив..ан@gmail.com"),
        ("ivan.petrov@gmail.com", "иван.петров@gmail.com"),
        ("o'brien@gmail.com", "о'брайен@gmail.com"),
        ("ivan|ivan@gmail.com", "иван|ivan@gmail.com"),
    ]

    def test_алфавит_не_меняет_вердикт(self):
        for латиница, кириллица in self.ПАРЫ:
            with self.subTest(пара=(латиница, кириллица)):
                self.assertEqual(validate_email_syntax(латиница),
                                 validate_email_syntax(кириллица))

    def test_живые_международные_адреса_остаются_законными(self):
        """Обратный контроль строгости: перегиб хоронит адрес без сети."""
        for адрес in ["иван@почта.рф", "müller@bücher.de", "日本@example.jp",
                      "иван.петров@почта.рф", "üser@[192.168.1.1]",
                      "оле-ся@корп.рф", "ivan+news@gmail.com"]:
            with self.subTest(адрес=адрес):
                self.assertTrue(validate_email_syntax(адрес), адрес)

    def test_разделители_колонок_в_имени_ящика_запрещены(self):
        for адрес in ["Иван,ivan@gmail.com", "Иван;ivan@gmail.com",
                      "Иван:ivan@gmail.com", "Мужской,Россия,ivan@gmail.com",
                      "Иван Петров,ivan@gmail.com"]:
            with self.subTest(адрес=адрес):
                self.assertFalse(validate_email_syntax(адрес), адрес)


class TestРазделительСнаружи(unittest.TestCase):
    """Домен-литерал дробить нельзя, колонки — надо."""

    def test_двоеточие_внутри_литерала_не_считается(self):
        self.assertFalse(_разделитель_снаружи("user@[IPv6:2001:db8::1]", ":"))

    def test_двоеточие_снаружи_считается(self):
        self.assertTrue(_разделитель_снаружи("user@x.com:password", ":"))

    def test_черта_снаружи_считается(self):
        self.assertTrue(_разделитель_снаружи("Ivan|ivan@gmail.com", "|"))

    def test_кавычки_прячут_разделитель(self):
        self.assertFalse(_разделитель_снаружи('"a,b"@example.com', ","))

    def test_мусор_не_роняет(self):
        for строка, разделитель in [(None, ","), ("a,b", None), ("a,b", ""),
                                    (42, ","), ("a,b", ",,")]:
            with self.subTest(вход=(строка, разделитель)):
                _разделитель_снаружи(строка, разделитель)

    def test_литерал_доезжает_целиком(self):
        """Ради чего оговорка вообще существует."""
        адреса = [почта for почта, _ in выдача("user@[IPv6:2001:db8::1]")]
        self.assertEqual(адреса, ["user@[ipv6:2001:db8::1]"])


# --------------------------------------------------------------------------
# 2. Все 49 комбинаций владельца
# --------------------------------------------------------------------------

ПОЛЯ = {
    "почта": ["ivan@gmail.com", "maria@yandex.ru", "petr@mail.ru", "olga@bk.ru"],
    "имя": ["Иван", "Мария", "Пётр", "Ольга"],
    "гендер": ["Мужской", "Женский", "Мужской", "Женский"],
    "гео": ["Россия", "Россия", "Россия", "Россия"],
}


def все_комбинации():
    """24 перестановки четвёрки + 18 троек + 6 пар + одна почта = 49."""
    имена = ["почта", "имя", "гендер", "гео"]
    из4 = list(itertools.permutations(имена))
    из3 = [p for p in itertools.permutations(имена, 3) if "почта" in p]
    из2 = [p for p in itertools.permutations(имена, 2) if "почта" in p]
    return из4 + из3 + из2 + [("почта",)]


class TestВсе49Комбинаций(unittest.TestCase):
    """Скриншоты владельца целиком, на каждом из четырёх разделителей.

    ЗАМЕРЕНО до правки: 34 из 49 на запятой, точке с запятой и вертикальной
    черте. Все 15 провалов — почта в ПОСЛЕДНЕЙ колонке.
    """

    def test_число_комбинаций_ровно_49(self):
        self.assertEqual(len(все_комбинации()), 49)

    def test_каждая_комбинация_на_каждом_разделителе(self):
        for разделитель in [",", ";", "|", "\t"]:
            for порядок in все_комбинации():
                with self.subTest(разделитель=разделитель, порядок=порядок):
                    текст = "\n".join(
                        разделитель.join(ПОЛЯ[поле][i] for поле in порядок)
                        for i in range(4))
                    выдано = выдача(текст)
                    self.assertEqual(len(выдано), 4)
                    for i, (почта, данные) in enumerate(выдано):
                        self.assertEqual(почта, ПОЛЯ["почта"][i])
                        self.assertEqual(
                            данные.get("name", ""),
                            ПОЛЯ["имя"][i] if "имя" in порядок else "")
                        self.assertEqual(
                            данные.get("gender", ""),
                            ПОЛЯ["гендер"][i] if "гендер" in порядок else "")
                        self.assertEqual(
                            данные.get("country", ""),
                            ПОЛЯ["гео"][i] if "гео" in порядок else "")


# --------------------------------------------------------------------------
# 3. Раскладка определяется на строку, а не на файл
# --------------------------------------------------------------------------

# Голова файла владельца: две колонки, `почта,имя`. Карта, снятая с неё,
# натягивается дальше на строки совсем другой формы.
ГОЛОВА = "\n".join([
    "ANMURESTE@YAHOO.COM,MAURICIO",
    "ccaldronez8@yahoo.com,Crystal",
    "CLDIXIE.RANDALL@AOL.COM,DIXIE",
    "d6bgehris@c21callfirst.com,Stephen",
    "dardingerd2@gmail.com,Deborah",
    "c5dmitchell@netzero.net,Daniel",
    "cilah3001f4@yahoo.com,Theresa",
    "chswangi1@stonesilk.com,Idiot",
    "bforgersond0@aol.com,Betty",
    "bcorkerx2@erols.com,Bethany",
])


class TestРаскладкаНаСтроку(unittest.TestCase):
    """Строки чужой формы внутри файла с известной картой колонок."""

    def _одна(self, строка):
        выдано = выдача(ГОЛОВА + "\n" + строка)
        self.assertEqual(len(выдано), 11, "строка не доехала")
        return выдано[-1]

    def test_карта_по_файлу_определяется_как_прежде(self):
        строки = ГОЛОВА.split("\n")
        разделитель = _detect_delimiter(строки)
        карта, заголовок = _detect_column_map(строки, разделитель)
        self.assertEqual(разделитель, ",")
        self.assertEqual(карта, {0: "email", 1: "name"})
        self.assertFalse(заголовок)

    def test_почта_во_второй_колонке(self):
        почта, данные = self._одна("Jennifer,jenher75@gmail.com,United States")
        self.assertEqual(почта, "jenher75@gmail.com")
        self.assertEqual(данные["name"], "Jennifer")
        self.assertEqual(данные["country"], "США")

    def test_страна_первой_колонкой(self):
        почта, данные = self._одна("united states,eborneke@hotmail.com")
        self.assertEqual(почта, "eborneke@hotmail.com")
        self.assertEqual(данные["country"], "США")
        self.assertEqual(данные["name"], "")

    def test_страна_в_колонке_которой_нет_в_карте(self):
        почта, данные = self._одна("amiexplore@hotmail.com,May,USA")
        self.assertEqual(почта, "amiexplore@hotmail.com")
        self.assertEqual(данные["name"], "May")
        self.assertEqual(данные["country"], "США")

    def test_пол_и_страна_в_колонках_которых_нет_в_карте(self):
        почта, данные = self._одна(
            "eborneke@hotmail.com,eva,female,united states")
        self.assertEqual(почта, "eborneke@hotmail.com")
        self.assertEqual(данные["name"], "eva")
        self.assertEqual(данные["gender"], "Женский")
        self.assertEqual(данные["country"], "США")

    def test_пустая_ячейка_пола_не_ломает_страну(self):
        почта, данные = self._одна(
            "leslie.pagnotta@medtronic.com,leslie,,united states")
        self.assertEqual(данные["gender"], "")
        self.assertEqual(данные["country"], "США")

    def test_имя_и_почта_и_пол_и_страна_в_четырёх_колонках(self):
        почта, данные = self._одна("Marsha,mlk@sigecom.net,male,USA")
        self.assertEqual(почта, "mlk@sigecom.net")
        self.assertEqual(данные["name"], "Marsha")
        self.assertEqual(данные["gender"], "Мужской")
        self.assertEqual(данные["country"], "США")

    def test_собственный_адрес_не_уезжает_в_имя(self):
        """ЗАМЕРЕНО до правки: 66 824 строки владельца с адресом в «Имя»."""
        _, данные = self._одна("united states,rm0475@yahoo.com")
        self.assertNotIn("@", данные["name"])


class TestКолонкаПаролей(unittest.TestCase):
    """Колонка, признанная мусором по всему файлу, мусором и остаётся.

    Иначе догадка «похоже на имя» затащила бы в базу владельца чужие пароли:
    на `secretword` она отвечает «имя». Переспорить голосование по файлу
    вправе только словарь — пол или страна.
    """

    ПАРОЛИ = "\n".join([
        "john@gmail.com:p@ssw0rd1", "mary@yahoo.com:qwerty123",
        "pete@mail.ru:letmein99", "anna@bk.ru:sunshine7",
        "oleg@list.ru:football1", "iva@inbox.ru:baseball2",
        "kat@rambler.ru:monkey33", "sem@ya.ru:dragon44",
        "tim@aol.com:shadow55", "zoe@msn.com:master66",
    ])

    def test_пароли_не_становятся_именами(self):
        for _, данные in выдача(self.ПАРОЛИ):
            self.assertEqual(данные["name"], "")

    def test_страна_в_мусорной_колонке_всё_же_берётся(self):
        текст = self.ПАРОЛИ + "\nnew@x.com:qwerty123:USA"
        почта, данные = выдача(текст)[-1]
        self.assertEqual(почта, "new@x.com")
        self.assertEqual(данные["country"], "США")


# --------------------------------------------------------------------------
# 4. Запятая внутри имени
# --------------------------------------------------------------------------

class TestЗапятаяВИмени(unittest.TestCase):
    """`William John Lynch, Sr` — четыре колонки, но три поля.

    Отдельная ловушка: `sr` совпадает с кодом Суринама в списке стран, и без
    правила про хвосты имени строка приезжала СТРАНОЙ «Sr», а настоящая
    страна из четвёртой колонки терялась. Это подмена, а не потеря.
    """

    СЛУЧАИ = [
        ("heavnsangel307@aol.com,William John Lynch, Sr,United States",
         "heavnsangel307@aol.com", "William John Lynch, Sr", "США"),
        ("whh@cybermesa.com,William H Hamilton,Jr.,United States",
         "whh@cybermesa.com", "William H Hamilton, Jr.", "США"),
        ("sankat@mindspring.com,Eric D Springle,Jr,United States",
         "sankat@mindspring.com", "Eric D Springle, Jr", "США"),
        ("mommyofangels@aol.com,Marc P Horten, Jr.,United States",
         "mommyofangels@aol.com", "Marc P Horten, Jr.", "США"),
    ]

    def test_хвост_имени_остаётся_в_имени(self):
        for строка, почта, имя, страна in self.СЛУЧАИ:
            with self.subTest(строка=строка):
                выдано = выдача(ГОЛОВА + "\n" + строка)
                self.assertEqual(len(выдано), 11)
                факт_почта, данные = выдано[-1]
                self.assertEqual(факт_почта, почта)
                self.assertEqual(данные["name"], имя)
                self.assertEqual(данные["country"], страна)

    def test_обратный_контроль_хвост_не_становится_страной(self):
        for строка, _, _, _ in self.СЛУЧАИ:
            with self.subTest(строка=строка):
                _, данные = выдача(ГОЛОВА + "\n" + строка)[-1]
                self.assertNotIn(данные["country"], ("Sr", "Jr", "Jr.",
                                                     "Суринам"))

    def test_лишняя_фамилия_склеивается_пробелом(self):
        _, данные = выдача(ГОЛОВА + "\nx@y.com,John,Smith")[-1]
        self.assertEqual(данные["name"], "John Smith")


# --------------------------------------------------------------------------
# 5. Приведение к одному виду
# --------------------------------------------------------------------------

class TestОдинВид(unittest.TestCase):
    """Одна страна и один пол — одним словом.

    ЗАМЕРЕНО на `Получатели.txt`: страна записана тремя способами (USA
    314 561, united states 66 536, United States 5 096), пол — восемью. В
    фильтре окна это четыре кучки вместо одной и девять вместо двух, потому
    что предиктор и домен зовут их «США» и «Мужской».
    """

    def test_страна(self):
        for значение in ["USA", "usa", "united states", "United States",
                         "US", "us", "america"]:
            with self.subTest(значение=значение):
                self.assertEqual(canonical_country(значение), "США")

    def test_пол(self):
        for значение in ["male", "Male", "M", "m", "муж", "мужской"]:
            with self.subTest(значение=значение):
                self.assertEqual(canonical_gender(значение), "Мужской")
        for значение in ["female", "Female", "F", "f", "жен", "женский"]:
            with self.subTest(значение=значение):
                self.assertEqual(canonical_gender(значение), "Женский")

    def test_неизвестный_пол_это_пустота_а_не_третье_значение(self):
        for значение in ["unknown", "andy", "n/a", "-", ""]:
            with self.subTest(значение=значение):
                self.assertEqual(canonical_gender(значение), "")

    def test_незнакомое_возвращается_как_есть_а_не_теряется(self):
        self.assertEqual(canonical_country("Freedonia"), "Freedonia")
        self.assertEqual(canonical_gender("небинарный"), "небинарный")

    def test_подстрока_не_считается_страной(self):
        """Обратный контроль: `Indiana` не Индия, `Chadron` не Чад."""
        self.assertEqual(canonical_country("Indiana"), "Indiana")
        self.assertEqual(canonical_country("Chadron"), "Chadron")

    def test_мусор_не_роняет(self):
        for значение in [None, 42, [], {}]:
            with self.subTest(значение=значение):
                self.assertEqual(canonical_country(значение), "")
                self.assertEqual(canonical_gender(значение), "")

    def test_в_таблицу_приходит_уже_приведённое(self):
        выдано = выдача("ivan@gmail.com,Ivan,male,USA\n"
                        "mary@x.com,Mary,female,united states")
        self.assertEqual([д["gender"] for _, д in выдано],
                         ["Мужской", "Женский"])
        self.assertEqual([д["country"] for _, д in выдано], ["США", "США"])


class TestСпорныеСлова(unittest.TestCase):
    """Chad, Georgia, India, Jamaica — это и страны, и живые имена.

    Ошибиться здесь значит не потерять данные владельца, а ПОДМЕНИТЬ их:
    имя человека уехало бы в колонку страны и наоборот.
    """

    def test_имя_совпавшее_со_страной_остаётся_именем(self):
        for строка, имя in [("Chad,chad@gmail.com", "Chad"),
                            ("Georgia,g@x.com,USA", "Georgia"),
                            ("Jamaica,jamaica.ivey@flash.net,male,USA",
                             "Jamaica")]:
            with self.subTest(строка=строка):
                _, данные = разбор(строка)
                self.assertEqual(данные["name"], имя)

    def test_настоящая_страна_при_этом_не_теряется(self):
        _, данные = разбор("Jamaica,jamaica.ivey@flash.net,male,USA")
        self.assertEqual(данные["country"], "США")
        self.assertEqual(данные["gender"], "Мужской")

    def test_страна_без_соперника_остаётся_страной(self):
        for строка in ["USA,x@y.com", "united states,eborneke@hotmail.com"]:
            with self.subTest(строка=строка):
                _, данные = разбор(строка)
                self.assertEqual(данные["country"], "США")
                self.assertEqual(данные["name"], "")


# --------------------------------------------------------------------------
# 6. Ни один адрес не теряется молча
# --------------------------------------------------------------------------

class TestНиОдинАдресНеПропал(unittest.TestCase):
    """Испорченный в исходнике адрес обязан доехать до проверки.

    Все восемь форм ниже взяты ИЗ ФАЙЛА ВЛАДЕЛЬЦА. Прежний разбор отдавал их
    наружу, и они получали честное «неправильный синтаксис» — владелец видел
    их в отчёте. Тихое исчезновение хуже: ни вердикта, ни строки в логе, ни
    разницы в счётчике.
    """

    БИТЫЕ = [
        "ISABELGUTIERREZ@BAMMODELS,Isabel,USA",
        "BURICH10@MSN,Anthony,USA",
        "jumpsdropskicks@aol. com,E.j.,USA",
        "UNITYDEE.@AOL.COM,Debra,USA",
        "paulsims5@embarq/mail.com,Paul Sims,United States",
        "www.wolfdavinchi@.com,James Brown,United States",
        "chaille.duncan....@sbcglobal.net,Chaille,USA",
        "andrewakajadakiss2122006@yahoo.,Joanne,USA",
    ]

    def test_битый_адрес_доезжает(self):
        for строка in self.БИТЫЕ:
            with self.subTest(строка=строка):
                выдано = выдача(ГОЛОВА + "\n" + строка)
                self.assertEqual(len(выдано), 11, "адрес исчез: " + строка)
                self.assertIn("@", выдано[-1][0])

    def test_строка_без_собаки_адресом_не_становится(self):
        """Почта — обязательное поле. Прямое требование владельца."""
        мусор = ["jfdkjfk,joe,USA", "N/A,Barbara,USA", "None,Frank,USA",
                 "email,name,country", "email1,fname,USA",
                 "www.felisavasquezatt.net,Felisa,USA"]
        выдано = выдача(ГОЛОВА + "\n" + "\n".join(мусор))
        self.assertEqual(len(выдано), 10)


class TestМусорНеРоняетРазбор(unittest.TestCase):
    """Разбор строки вызывается на каждую строку чужого файла.

    Исключение отсюда проглотил бы except уровнем выше: адрес молча исчез бы
    из выдачи, а счётчик его засчитал.
    """

    def test_разбор_переживает_что_угодно(self):
        for строка in [None, "", 42, [], "a" * 5000, ",,,,,", "@@@@",
                       "\x00\x01", "почта@\U0010ffff.com"]:
            for разделитель in [",", ":", None, "", 42]:
                for карта in [{0: "email"}, {}, None, "не карта"]:
                    with self.subTest(строка=строка, разделитель=разделитель):
                        почта, данные = _parse_line_smart(
                            строка, разделитель, карта)
                        self.assertIsInstance(почта, str)
                        self.assertIsInstance(данные, dict)


# --------------------------------------------------------------------------
# 7. Обогащение не трогает то, что пришло из файла
# --------------------------------------------------------------------------

class _Сеть:
    """Сеть-заглушка: вердикт всегда Valid, сетевых запросов нет."""

    def check_email(self, email):
        return {"status": "valid", "reason": "250 OK",
                "mx_record": "mx.example.com", "mx_records": ["mx.example.com"],
                "has_starttls": True, "server_outdated": False}

    def check_dns_health(self, domain, mx_record=""):
        return {"has_spf": True, "has_dmarc": True, "has_dkim": True, "score": 3}

    def check_dnsbl(self, host):
        return False

    def check_ptr(self, host):
        return True

    def all_proxies_dead(self):
        return False

    def has_proxies_configured(self):
        return False


class TestОбогащениеНеТрогаетФайл(unittest.TestCase):
    """Всё пришло из файла — обогащать нечего, только проверить.

    Прямое требование владельца. Проверяется не отсутствием вызовов, а тем,
    что попадёт в таблицу: значения совпадают с файлом, а источник помечен
    словом «файл», а не «имя» или «домен».
    """

    def setUp(self):
        from core.parser.ml_predictor import MLPredictor
        from core.parser.name_extractor import NameExtractor
        from core.pipeline import ValidationPipeline

        self.строки = []
        self.pipeline = ValidationPipeline(callbacks={
            "on_log": lambda m, t="info": None,
            "on_result": lambda e, s, r, mx, d: self.строки.append((e, dict(d))),
            "on_progress": lambda c, t: None,
            "on_complete": lambda: None,
        })
        self.pipeline.network = _Сеть()
        self.pipeline.name_extractor = NameExtractor(enable_osint=False)
        self.pipeline.ml_predictor = MLPredictor(enable_ml=True)
        self.pipeline.gravatar_checker = type(
            "G", (), {"has_gravatar": lambda s, e: False})()
        self.pipeline.filter = None
        self.pipeline.ai = None
        self.pipeline.cache = None
        self.pipeline._get_domain_age_days = lambda d: -1
        self.pipeline._check_http_alive = lambda d: True

    def _прогон(self, текст):
        self.строки.clear()
        self.pipeline.run_pipeline(
            [{"type": "text", "content": текст}], threads=2, fix_typos=True,
            check_spam=False, deep_ping=True, enable_ai=False)
        return {почта: данные for почта, данные in self.строки}

    def test_всё_из_файла_остаётся_из_файла(self):
        данные = self._прогон(
            "bogdan.petrov@yandex.ru,Богдан Петров,male,USA")
        строка = данные["bogdan.petrov@yandex.ru"]
        self.assertEqual(строка["name"], "Богдан Петров")
        self.assertEqual(строка["gender"], "Мужской")
        self.assertEqual(строка["country"], "США")
        self.assertEqual(строка["name_source"], "файл")
        self.assertEqual(строка["gender_source"], "файл")
        self.assertEqual(строка["country_source"], "файл")

    def test_обратный_контроль_домен_перебивает_пустую_колонку(self):
        """Без страны в файле источником обязан стать домен, а не «файл»."""
        данные = self._прогон("bogdan.petrov@yandex.ru,Богдан Петров")
        строка = данные["bogdan.petrov@yandex.ru"]
        self.assertEqual(строка["country"], "Россия")
        self.assertEqual(строка["country_source"], "домен")

    def test_дополняется_только_пробел(self):
        """Есть имя и страна, нет пола — дополнить обязан только пол."""
        данные = self._прогон("john.smith@gmail.com,John Smith,,USA")
        строка = данные["john.smith@gmail.com"]
        self.assertEqual(строка["name"], "John Smith")
        self.assertEqual(строка["name_source"], "файл")
        self.assertEqual(строка["country"], "США")
        self.assertEqual(строка["country_source"], "файл")
        self.assertEqual(строка["gender"], "Мужской")
        self.assertEqual(строка["gender_source"], "имя")

    def test_страна_из_файла_доходит_до_словаря_имён(self):
        """Последствие порядка источников, названное вслух.

        Пол определяется по имени С УЧЁТОМ страны, а страна теперь берётся
        из файла. Значит колонка страны влияет на колонку пола: `Svetlana`
        в русском столбце словаря женское, а в американском помечено как
        унисекс — и пол честно остаётся пустым, потому что врать про пол
        хуже, чем не указать его.

        ЗАМЕРЕНО на 20 000 строк файла владельца: на его данных это не
        меняет НИЧЕГО — пол определился у 17 524 строк и до правки, и после,
        и все 20 000 вердиктов совпали. Тест сторожит сам механизм, а не
        число.
        """
        сша = self._прогон("svetlana.orlova@gmail.com,Svetlana Orlova,,USA")
        россия = self._прогон("svetlana.orlova@gmail.com,Svetlana Orlova,,Россия")
        self.assertEqual(сша["svetlana.orlova@gmail.com"]["country"], "США")
        self.assertEqual(россия["svetlana.orlova@gmail.com"]["country"], "Россия")
        self.assertEqual(россия["svetlana.orlova@gmail.com"]["gender"], "Женский")


# --------------------------------------------------------------------------
# 8. Настоящий файл владельца
# --------------------------------------------------------------------------

ФАЙЛ_ПО_УМОЛЧАНИЮ = os.path.join(
    "C:\\", "Users", "user", "OneDrive", "Desktop", "Мой софт", "200m",
    "Почты", "Получатели.txt")


def _путь_к_файлу():
    return os.environ.get("VALIDATOR_OWNER_RECIPIENTS") or ФАЙЛ_ПО_УМОЛЧАНИЮ


нужен_файл = pytest.mark.skipif(
    not os.path.exists(_путь_к_файлу()),
    reason="файл получателей владельца лежит вне репозитория")


@нужен_файл
class TestНастоящийФайлВладельца(unittest.TestCase):
    """Числа ниже ЗАМЕРЕНЫ на `Получатели.txt` (412 755 строк, 14.1 МБ).

    До правки: адресов 417 083, имён 413 867 (из них 66 824 — сам адрес в
    колонке «Имя»), пол 0, страна 0.
    """

    # Числа пересчитаны 06.09.2026 после решения владельца схлопывать
    # адреса одного человека: из строки с несколькими адресами остаётся
    # один. Было 417 083 адреса, ушли ровно 4 350 лишних.
    ВСЕГО_АДРЕСОВ = 412733
    СТРАН_НЕ_МЕНЬШЕ = 386179
    ПОЛОВ_НЕ_МЕНЬШЕ = 16928

    @classmethod
    def setUpClass(cls):
        cls.всего = cls.со_страной = cls.с_полом = cls.почта_в_имени = 0
        cls.страны = set()
        cls.полы = set()
        источник = [{"type": "file", "path": _путь_к_файлу()}]
        for почта, данные in StreamLoader(источник).stream_emails():
            cls.всего += 1
            имя = (данные.get("name") or "").strip()
            пол = (данные.get("gender") or "").strip()
            страна = (данные.get("country") or "").strip()
            if "@" in имя:
                cls.почта_в_имени += 1
            if пол:
                cls.с_полом += 1
                cls.полы.add(пол)
            if страна:
                cls.со_страной += 1
                cls.страны.add(страна)

    def test_адресов_ровно_столько_сколько_замерено(self):
        self.assertEqual(self.всего, self.ВСЕГО_АДРЕСОВ)

    def test_страна_берётся_из_файла(self):
        self.assertGreaterEqual(self.со_страной, self.СТРАН_НЕ_МЕНЬШЕ)

    def test_пол_берётся_из_файла(self):
        self.assertGreaterEqual(self.с_полом, self.ПОЛОВ_НЕ_МЕНЬШЕ)

    def test_страны_приведены_к_одному_виду(self):
        self.assertIn("США", self.страны)
        for лишнее in ("USA", "usa", "united states", "United States", "US"):
            self.assertNotIn(лишнее, self.страны)

    def test_полы_приведены_к_одному_виду(self):
        self.assertTrue(self.полы <= {"Мужской", "Женский"}, self.полы)

    def test_адрес_больше_не_уезжает_в_колонку_имени(self):
        """Было 66 824. Остаток — строки с ДВУМЯ собаками, их не трогали."""
        self.assertLessEqual(self.почта_в_имени, 20)
