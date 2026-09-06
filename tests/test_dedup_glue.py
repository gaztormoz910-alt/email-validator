# -*- coding: utf-8 -*-
"""Один адрес на человека и склейка пробелов внутри адреса.

Оба решения принял владелец 06.09.2026, ответив на прямые вопросы.

1. «Дедубликацию всё равно проводить нужно. Если есть почта с доменом вроде
   Gmail, Yahoo, AOL, Outlook — приоритет отдавать ей, а все остальные
   отсеивать как дубликаты.»

2. «Пробелы склеивать надо между собой, чтобы одна полноценная почта
   получилась.»

Второе — РАЗМЕН, и он назван вслух до того, как был сделан: у
`donald.m ross@yahoo.com` три прочтения, склейка берёт одно, и если верным
было другое, письмо уйдёт чужому существующему человеку. Владелец выбрал
шанс вместо гарантированной потери: до правки все 425 таких адресов не
проходили синтаксис, то есть были потеряны наверняка.
"""
import os
import unittest

import pytest

from core.cleaner import EmailCleaner
from core.email_syntax import validate_email_syntax
from core.provider import address_priority, best_address
from core.streamer import StreamLoader

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


def выдача(текст, заметки=None):
    источник = [{"type": "text", "content": текст}]
    return list(StreamLoader(источник,
                             on_note=заметки.append if заметки is not None
                             else None).stream_emails())


# --------------------------------------------------------------------------
# Л1. Один адрес на человека
# --------------------------------------------------------------------------

class TestПриоритетАдреса(unittest.TestCase):
    """Порядок предпочтения — это ПРОВЕРЯЕМОСТЬ, а не вкус.

    Смысл выбора в том, чтобы у человека остался адрес, про который мы
    вообще способны узнать правду. Gmail отвечает честно с любого IP, Yahoo
    требует PTR, Mail.ru отвечает «250 OK» на любой выдуманный ящик и не
    проверяется ничем.
    """

    ПОРЯДОК = [
        ("x@gmail.com", 5), ("x@yandex.ru", 5),
        ("x@outlook.com", 4), ("x@icloud.com", 4), ("x@gmx.com", 4),
        ("x@yahoo.com", 3), ("x@aol.com", 3),
        ("x@comcast.net", 2), ("x@netzero.net", 2),
        ("x@precon.com", 1),
        ("x@mail.ru", 0), ("x@bk.ru", 0),
    ]

    def test_баллы_расставлены_как_объявлено(self):
        for адрес, балл in self.ПОРЯДОК:
            with self.subTest(адрес=адрес):
                self.assertEqual(address_priority(адрес), балл)

    def test_крупный_почтовик_бьёт_корпоративный(self):
        """Прямое правило владельца."""
        self.assertGreater(address_priority("a@gmail.com"),
                           address_priority("a@precon.com"))
        self.assertGreater(address_priority("a@yahoo.com"),
                           address_priority("a@precon.com"))
        self.assertGreater(address_priority("a@aol.com"),
                           address_priority("a@teleflex.com"))

    def test_непроверяемый_почтовик_последний(self):
        """Mail.ru отвечает 250 на любой выдуманный ящик.

        Оставить его вместо корпоративного — значит своими руками сделать
        контакт недоказуемым.
        """
        self.assertLess(address_priority("a@mail.ru"),
                        address_priority("a@precon.com"))

    def test_мусор_не_роняет(self):
        for значение in [None, 42, [], "", "без собаки"]:
            with self.subTest(значение=значение):
                self.assertIsInstance(address_priority(значение), int)
        for значение in [None, 42, [], "", ["мусор"], [None]]:
            with self.subTest(значение=значение):
                self.assertIsInstance(best_address(значение), str)


class TestВыборИзГруппы(unittest.TestCase):
    """Настоящие группы из файла владельца, взятые поимённо."""

    СЛУЧАИ = [
        (["emily.holcombe@teleflex.com", "efh262@gmail.com"],
         "efh262@gmail.com"),
        (["iamiambic@comcast.net", "voxnotrox@aol.com"],
         "voxnotrox@aol.com"),
        (["xiufengzhong@yahoo.com.cn", "xiufeng.zhong@gmail.com"],
         "xiufeng.zhong@gmail.com"),
        (["captjnorton@att.net", "islandsinthesun@aol.com",
          "captjnorton@aol.com"], "islandsinthesun@aol.com"),
        (["butler.cody@sysco.com", "ccbutler83@yahoo.com",
          "butler.cody@ar.sysco.com"], "ccbutler83@yahoo.com"),
    ]

    def test_выбирается_приоритетный(self):
        for группа, ждём in self.СЛУЧАИ:
            with self.subTest(группа=группа):
                self.assertEqual(best_address(группа), ждём)

    def test_когда_крупного_нет_выбор_всё_равно_однозначен(self):
        """710 строк файла владельца — все адреса корпоративные.

        Правило «брать бесплатный» там не решает ничего, и без запасного
        выбора строка осталась бы без ответа.
        """
        группа = ["maria.fultz@precon.com", "mariafultz@pcdci.com"]
        self.assertEqual(best_address(группа), "maria.fultz@precon.com")
        self.assertEqual(best_address(list(reversed(группа))),
                         "mariafultz@pcdci.com")

    def test_при_равном_приоритете_побеждает_первый(self):
        """Выдумывать предпочтение там, где его нет, нельзя."""
        группа = ["zhangdennis@gmail.com", "zhang.dennis@gmail.com"]
        self.assertEqual(best_address(группа), "zhangdennis@gmail.com")


class TestГруппаВЗагрузчике(unittest.TestCase):
    """Сквозь загрузчик: из строки выходит РОВНО ОДИН адрес."""

    СТРОКА = ("emily.holcombe@teleflex.com # efh262@gmail.com,"
              "emily,female,united states")

    def test_из_строки_выходит_один_адрес(self):
        выдано = выдача(ГОЛОВА + "\n" + self.СТРОКА)
        self.assertEqual(len(выдано), 11)
        почта, данные = выдано[-1]
        self.assertEqual(почта, "efh262@gmail.com")
        self.assertEqual(данные["name"], "emily")
        self.assertEqual(данные["gender"], "Женский")
        self.assertEqual(данные["country"], "США")

    def test_отсев_объявлен_в_лог(self):
        """Молча схлопнутый адрес — это потеря без единой строки в логе."""
        заметки = []
        выдача(ГОЛОВА + "\n" + self.СТРОКА, заметки)
        self.assertEqual(len(заметки), 1)
        self.assertIn("1", заметки[0])
        self.assertIn("Схлопнуто", заметки[0])

    def test_обычные_строки_не_тронуты(self):
        """Обратный контроль: без группы отсева быть не должно."""
        заметки = []
        выдано = выдача(ГОЛОВА, заметки)
        self.assertEqual(len(выдано), 10)
        self.assertEqual(заметки, [])

    def test_число_отсеянных_считается_по_адресам_и_по_строкам(self):
        текст = ГОЛОВА + "\n" + "\n".join([
            "a@precon.com # b@gmail.com,one,male,USA",
            "c@precon.com # d@precon.com # e@gmail.com,two,male,USA",
        ])
        заметки = []
        выдано = выдача(текст, заметки)
        self.assertEqual(len(выдано), 12)
        self.assertEqual([п for п, _ in выдано[10:]],
                         ["b@gmail.com", "e@gmail.com"])
        # Три отсеянных адреса в двух строках.
        self.assertIn("3", заметки[0])
        self.assertIn("2", заметки[0])


# --------------------------------------------------------------------------
# Л2. Склейка пробелов
# --------------------------------------------------------------------------

class TestСклейкаПробелов(unittest.TestCase):
    """Настоящие адреса из файла владельца, названные им поимённо."""

    СЛУЧАИ = [
        ("donald.m ross@yahoo.com", "donald.mross@yahoo.com"),
        ("juanita.modisett claybon@yahoo.com",
         "juanita.modisettclaybon@yahoo.com"),
        ("mary beth tyler_tood@verizon.net",
         "marybethtyler_tood@verizon.net"),
        ("clarencejohnson sr@yahoo.com", "clarencejohnsonsr@yahoo.com"),
        ("jumpsdropskicks@aol. com", "jumpsdropskicks@aol.com"),
        ("darcy thompson_darcy thompson@yahoo.com",
         "darcythompson_darcythompson@yahoo.com"),
    ]

    def setUp(self):
        self.cleaner = EmailCleaner()

    def test_склеивается_в_один_адрес(self):
        for испорчен, ждём in self.СЛУЧАИ:
            with self.subTest(испорчен=испорчен):
                self.assertEqual(self.cleaner.clean_email(испорчен), ждём)

    def test_склеенный_адрес_проходит_синтаксис(self):
        """Ради этого всё и делалось: до правки все 425 были мертвы."""
        for испорчен, _ in self.СЛУЧАИ:
            with self.subTest(испорчен=испорчен):
                self.assertFalse(validate_email_syntax(испорчен))
                self.assertTrue(
                    validate_email_syntax(self.cleaner.clean_email(испорчен)))

    def test_имя_ящика_в_кавычках_не_склеивается(self):
        """Там пробел законен по RFC 5321 §4.1.2 и является частью адреса."""
        self.assertEqual(self.cleaner.clean_email('"john smith"@x.com'),
                         '"john smith"@x.com')

    def test_целый_адрес_не_меняется(self):
        for адрес in ["john.doe@gmail.com", "o'brien@example.com",
                      "user@[192.168.1.1]", "иван@почта.рф"]:
            with self.subTest(адрес=адрес):
                self.assertEqual(self.cleaner.clean_email(адрес), адрес)


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


class TestИсходнаяСтрокаНеТеряется(unittest.TestCase):
    """Склейка — это догадка, и владелец обязан видеть, что было в файле."""

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

    def test_склеенный_адрес_помнит_исходную_строку(self):
        данные = self._прогон("donald.m ross@yahoo.com,Donald,male,USA")
        self.assertIn("donald.mross@yahoo.com", данные)
        строка = данные["donald.mross@yahoo.com"]
        self.assertEqual(строка.get("original_email"),
                         "donald.m ross@yahoo.com")

    def test_нетронутый_адрес_исходной_строки_не_заводит(self):
        """Обратный контроль: пометка появляется только при изменении."""
        данные = self._прогон("john.doe@gmail.com,John,male,USA")
        self.assertNotIn("original_email", данные["john.doe@gmail.com"])


# --------------------------------------------------------------------------
# Л3. Защиты от недоказуемого «Годен»
# --------------------------------------------------------------------------

class TestЗащитыОтЛожногоГоден(unittest.TestCase):
    """Владелец спросил прямо: станет ли ложных «Годен» больше.

    Защит три, и все три включены значениями по умолчанию в ядре — окна их
    не передают и выключить не могут:

      1. Контрольный RCPT в той же сессии: сразу после реального адреса
         спрашивается выдуманный. Оба 250 — статус `catchall`, а не Valid.
      2. Канарейка: заведомо мёртвый адрес отдельной пробой — ловит
         тарпитинг, включившийся посреди прогона.
      3. Второе мнение: `Годен` переспрашивается с ДРУГОГО выхода, и если
         тот отверг — вердикт становится Unknown.

    Проверка сторожит именно то, что однажды уже ломалось: `confirm_valid`
    читался как `getattr(self, 'confirm_valid', False)` и был выключен,
    пока в окне стояла галочка.
    """

    def setUp(self):
        from core.pipeline import ValidationPipeline
        self.pipeline = ValidationPipeline(callbacks={
            "on_log": lambda m, t="info": None,
            "on_result": lambda *a: None,
            "on_progress": lambda *a: None,
            "on_complete": lambda: None,
        })

    def test_второе_мнение_включено_по_умолчанию(self):
        self.assertTrue(self.pipeline.confirm_valid)

    def test_окна_его_не_выключают(self):
        import inspect
        from core.pipeline import ValidationPipeline
        подпись = inspect.signature(ValidationPipeline.start)
        self.assertIs(подпись.parameters["confirm_valid"].default, True)
        подпись2 = inspect.signature(ValidationPipeline.run_pipeline)
        for имя in ("deep_ping", "enable_ai", "enable_osint", "resume"):
            self.assertIs(подпись2.parameters[имя].default, True, имя)

    def test_catchall_не_считается_подтверждением(self):
        from core.provider import VERIFIABILITY
        self.assertEqual(VERIFIABILITY.get("Mail.ru"), "never")


# --------------------------------------------------------------------------
# Настоящий файл владельца
# --------------------------------------------------------------------------

ФАЙЛ_ПО_УМОЛЧАНИЮ = os.path.join(
    "C:\\", "Users", "Bog_1", "OneDrive", "Desktop", "Мой софт", "200m",
    "Почты", "Получатели.txt")


def _путь_к_файлу():
    return os.environ.get("VALIDATOR_OWNER_RECIPIENTS") or ФАЙЛ_ПО_УМОЛЧАНИЮ


нужен_файл = pytest.mark.skipif(
    not os.path.exists(_путь_к_файлу()),
    reason="файл получателей владельца лежит вне репозитория")


@нужен_файл
class TestФайлВладельца(unittest.TestCase):
    """ЗАМЕРЕНО на `Получатели.txt` после обеих правок.

    Было 417 083 адреса, стало 412 733: ушли ровно 4 350 лишних, то есть
    вторые и третьи адреса тех же людей. Строк с группой — 2 898.
    """

    ВСЕГО_АДРЕСОВ = 412733
    СХЛОПНУТО = 4350
    СТРОК_С_ГРУППОЙ = 2898

    @classmethod
    def setUpClass(cls):
        cls.заметки = []
        cls.всего = 0
        cls.склеено = 0
        cls.битых = 0
        cleaner = EmailCleaner()
        источник = [{"type": "file", "path": _путь_к_файлу()}]
        for почта, _ in StreamLoader(источник,
                                     on_note=cls.заметки.append).stream_emails():
            cls.всего += 1
            чистый = cleaner.clean_email(почта)
            if чистый and " " in почта and " " not in чистый:
                cls.склеено += 1
            if not чистый or not validate_email_syntax(чистый):
                cls.битых += 1

    def test_адресов_ровно_столько(self):
        self.assertEqual(self.всего, self.ВСЕГО_АДРЕСОВ)

    def test_схлопнуто_объявлено_числом(self):
        self.assertEqual(len(self.заметки), 1)
        self.assertIn(str(self.СХЛОПНУТО), self.заметки[0])
        self.assertIn(str(self.СТРОК_С_ГРУППОЙ), self.заметки[0])

    def test_склеено_425(self):
        self.assertEqual(self.склеено, 425)

    def test_битых_осталось_мало(self):
        """Было 425 с пробелом плюс полсотни порченых в исходнике."""
        self.assertLessEqual(self.битых, 60)
