# -*- coding: utf-8 -*-
import pytest
import unittest

import dns.resolver

from core.email_syntax import validate_email_syntax
from core.mail_constants import reserved_zone
from core.network import NetworkValidator


class TestЗарезервированныеЗоны(unittest.TestCase):

    МЁРТВЫЕ = [
        ("example.test", "test"),
        ("a.invalid", "invalid"),
        ("box.localhost", "localhost"),
        ("srv.local", "local"),
        ("x.internal", "internal"),
        ("y.corp", "corp"),
        ("z.lan", "lan"),
        ("hot.mail", "mail"),
        ("host.home.arpa", "home.arpa"),
        ("1.2.3.4.in-addr.arpa", "in-addr.arpa"),
    ]

    ЖИВЫЕ = ["gmail.com", "yahoo.com", "mail.ru", "example.com", "sberbank.ru",
             "почта.рф", "x.arpa", "test.com", "local.com", "internal.org"]

    def test_зона_опознаётся(self):
        for домен, зона in self.МЁРТВЫЕ:
            with self.subTest(домен=домен):
                self.assertEqual(reserved_zone(домен), зона)

    def test_живые_домены_не_задеты(self):
        for домен in self.ЖИВЫЕ:
            with self.subTest(домен=домен):
                self.assertEqual(reserved_zone(домен), "")

    def test_мусор_не_роняет(self):
        for значение in [None, 42, [], "", "   ", ".", "..", "a"]:
            with self.subTest(значение=значение):
                self.assertEqual(reserved_zone(значение), "")

    def test_вердикт_invalid_без_единого_запроса_в_сеть(self):
        сеть = NetworkValidator(timeout=1)
        сеть.resolver = _Резолвер(лечь=True)
        for домен, зона in self.МЁРТВЫЕ:
            with self.subTest(домен=домен):
                итог = сеть.check_email("ivan@" + домен)
                self.assertEqual(итог["status"], "invalid")
                self.assertIn(зона, итог["reason"])
                self.assertIn("зарезервирована", итог["reason"])

    def test_это_не_ошибка_синтаксиса(self):
        сеть = NetworkValidator(timeout=1)
        сеть.resolver = _Резолвер(лечь=True)
        for домен, _зона in self.МЁРТВЫЕ:
            with self.subTest(домен=домен):
                self.assertTrue(validate_email_syntax("ivan@" + домен))
                итог = сеть.check_email("ivan@" + домен)
                self.assertNotIn("Syntax", итог["reason"])


class _Ответ:
    def __init__(self, адрес="93.184.216.34"):
        self.адрес = адрес

    def __iter__(self):
        return iter([self.адрес])

    def __bool__(self):
        return True


class _Резолвер:

    def __init__(self, правила=None, лечь=False):
        self.правила = правила or {}
        self.лечь = лечь
        self.спрошено = []

    def resolve(self, имя, тип=None, *a, **k):
        self.спрошено.append((str(имя), тип))
        if self.лечь:
            raise AssertionError("сеть не должна спрашиваться вовсе")
        что = self.правила.get(str(имя).rstrip("."), "таймаут")
        if что == "есть":
            return _Ответ()
        if что == "нет":
            raise dns.resolver.NXDOMAIN(str(имя))
        if что == "пусто":
            raise dns.resolver.NoAnswer()
        raise dns.exception.Timeout()


@pytest.mark.настоящий_mx_hosts_alive
class TestХостИзMXНеСуществует(unittest.TestCase):

    def сеть(self, правила):
        v = NetworkValidator(timeout=1)
        v.resolver = _Резолвер(правила)
        return v

    def test_все_хосты_nxdomain_это_приговор(self):
        v = self.сеть({"mx1.dead.example": "нет", "mx2.dead.example": "нет"})
        self.assertIs(v.mx_hosts_alive(["mx1.dead.example",
                                        "mx2.dead.example"]), False)

    def test_хотя_бы_один_живой_снимает_вопрос(self):
        v = self.сеть({"mx1.dead.example": "нет", "mx2.live.example": "есть"})
        self.assertIs(v.mx_hosts_alive(["mx1.dead.example",
                                        "mx2.live.example"]), True)

    def test_таймаут_НЕ_приговор(self):
        v = self.сеть({"mx1.x.example": "таймаут", "mx2.x.example": "таймаут"})
        self.assertIsNone(v.mx_hosts_alive(["mx1.x.example", "mx2.x.example"]))

    def test_смесь_nxdomain_и_таймаута_НЕ_приговор(self):
        v = self.сеть({"mx1.x.example": "нет", "mx2.x.example": "таймаут"})
        self.assertIsNone(v.mx_hosts_alive(["mx1.x.example", "mx2.x.example"]))

    def test_имя_есть_но_адреса_нет_это_НЕ_приговор(self):
        v = self.сеть({"mx1.x.example": "пусто"})
        self.assertIsNone(v.mx_hosts_alive(["mx1.x.example"]))

    def test_голый_адрес_вместо_имени_не_резолвится(self):
        v = self.сеть({})
        self.assertIs(v.mx_hosts_alive(["1.2.3.4"]), True)
        self.assertEqual(v.resolver.спрошено, [], "адрес спрашивать незачем")

    def test_один_хост_спрашивается_один_раз(self):
        v = self.сеть({"mx.shared.example": "нет"})
        for _ in range(5):
            v.mx_hosts_alive(["mx.shared.example"])
        спрошено = [и for и, _т in v.resolver.спрошено]
        self.assertEqual(спрошено.count("mx.shared.example"), 1)

    def test_мусор_не_роняет(self):
        v = self.сеть({})
        for значение in [None, 42, "", "строка", [], [None], [42], [""]]:
            with self.subTest(значение=значение):
                self.assertIn(v.mx_hosts_alive(значение), (True, False, None))

    def test_вердикт_целиком(self):
        v = NetworkValidator(timeout=1)
        v.resolver = _Резолвер({"mx.dead.example": "нет"})
        v.get_mx_records = lambda d: ["mx.dead.example"]
        итог = v.check_email("ivan@somedomain.com")
        self.assertEqual(итог["status"], "invalid")
        self.assertIn("NXDOMAIN", итог["reason"])

    def test_обратный_контроль_живой_mx_доходит_до_smtp(self):
        v = NetworkValidator(timeout=1)
        v.resolver = _Резолвер({"mx.live.example": "есть"})
        v.get_mx_records = lambda d: ["mx.live.example"]
        достучались = {"было": False}

        def подмена(*a, **k):
            достучались["было"] = True
            return {"status": "unknown", "reason": "заглушка", "mx_record": ""}

        v.stealth_smtp_ping = подмена
        v.is_catch_all_domain = lambda d, mx: False
        итог = v.check_email("ivan@somedomain.com")
        self.assertTrue(достучались["было"], "до SMTP дело не дошло")
        self.assertNotEqual(итог["status"], "invalid")
