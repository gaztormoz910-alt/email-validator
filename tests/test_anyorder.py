# -*- coding: utf-8 -*-
import itertools
import os
import unittest

import pytest

from core.email_syntax import validate_email_syntax
from core.provider import canonical_country, canonical_gender
from core.streamer import (StreamLoader, _detect_column_map, _detect_delimiter,
                           _parse_line_smart, _разделитель_снаружи)


def выдача(текст):
    return list(StreamLoader([{"type": "text", "content": текст}]).stream_emails())


def разбор(строка):
    выдано = выдача(ГОЛОВА + "\n" + строка)
    assert len(выдано) == len(ГОЛОВА.split("\n")) + 1, "строка не доехала"
    return выдано[-1]


class TestГрамматикаUTF8(unittest.TestCase):

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
        адреса = [почта for почта, _ in выдача("user@[IPv6:2001:db8::1]")]
        self.assertEqual(адреса, ["user@[ipv6:2001:db8::1]"])


ПОЛЯ = {
    "почта": ["ivan@gmail.com", "maria@yandex.ru", "petr@mail.ru", "olga@bk.ru"],
    "имя": ["Иван", "Мария", "Пётр", "Ольга"],
    "гендер": ["Мужской", "Женский", "Мужской", "Женский"],
    "гео": ["Россия", "Россия", "Россия", "Россия"],
}


def все_комбинации():
    имена = ["почта", "имя", "гендер", "гео"]
    из4 = list(itertools.permutations(имена))
    из3 = [p for p in itertools.permutations(имена, 3) if "почта" in p]
    из2 = [p for p in itertools.permutations(имена, 2) if "почта" in p]
    return из4 + из3 + из2 + [("почта",)]


class TestВсе49Комбинаций(unittest.TestCase):

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


class TestРаскладкаНаСтроку(unittest.TestCase):

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
        _, данные = self._одна("united states,rm0475@yahoo.com")
        self.assertNotIn("@", данные["name"])


class TestКолонкаПаролей(unittest.TestCase):

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


class TestЗапятаяВИмени(unittest.TestCase):

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


class TestОдинВид(unittest.TestCase):

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


class TestНиОдинАдресНеПропал(unittest.TestCase):

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
        мусор = ["jfdkjfk,joe,USA", "N/A,Barbara,USA", "None,Frank,USA",
                 "email,name,country", "email1,fname,USA",
                 "www.felisavasquezatt.net,Felisa,USA"]
        выдано = выдача(ГОЛОВА + "\n" + "\n".join(мусор))
        self.assertEqual(len(выдано), 10)


class TestМусорНеРоняетРазбор(unittest.TestCase):

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


class _Сеть:

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
            "anatol.petrov@yandex.ru,Анатоль Петров,male,USA")
        строка = данные["anatol.petrov@yandex.ru"]
        self.assertEqual(строка["name"], "Анатоль Петров")
        self.assertEqual(строка["gender"], "Мужской")
        self.assertEqual(строка["country"], "США")
        self.assertEqual(строка["name_source"], "файл")
        self.assertEqual(строка["gender_source"], "файл")
        self.assertEqual(строка["country_source"], "файл")

    def test_обратный_контроль_домен_перебивает_пустую_колонку(self):
        данные = self._прогон("anatol.petrov@yandex.ru,Анатоль Петров")
        строка = данные["anatol.petrov@yandex.ru"]
        self.assertEqual(строка["country"], "Россия")
        self.assertEqual(строка["country_source"], "домен")

    def test_дополняется_только_пробел(self):
        данные = self._прогон("john.smith@gmail.com,John Smith,,USA")
        строка = данные["john.smith@gmail.com"]
        self.assertEqual(строка["name"], "John Smith")
        self.assertEqual(строка["name_source"], "файл")
        self.assertEqual(строка["country"], "США")
        self.assertEqual(строка["country_source"], "файл")
        self.assertEqual(строка["gender"], "Мужской")
        self.assertEqual(строка["gender_source"], "имя")

    def test_страна_из_файла_доходит_до_словаря_имён(self):
        сша = self._прогон("svetlana.orlova@gmail.com,Svetlana Orlova,,USA")
        россия = self._прогон("svetlana.orlova@gmail.com,Svetlana Orlova,,Россия")
        self.assertEqual(сша["svetlana.orlova@gmail.com"]["country"], "США")
        self.assertEqual(россия["svetlana.orlova@gmail.com"]["country"], "Россия")
        self.assertEqual(россия["svetlana.orlova@gmail.com"]["gender"], "Женский")


ФАЙЛ_ПО_УМОЛЧАНИЮ = ""


def _путь_к_файлу():
    return os.environ.get("VALIDATOR_OWNER_RECIPIENTS") or ФАЙЛ_ПО_УМОЛЧАНИЮ


нужен_файл = pytest.mark.skipif(
    not os.path.exists(_путь_к_файлу()),
    reason="файл получателей владельца лежит вне репозитория")


@нужен_файл
class TestНастоящийФайлВладельца(unittest.TestCase):

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
        self.assertLessEqual(self.почта_в_имени, 20)
