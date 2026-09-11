# -*- coding: utf-8 -*-
"""Две проверки, превращающие «не проверено» в честный «мёртв».

Владелец одобрил их 06.09.2026 по итогам аудита 750 критериев.

    Л1  зона зарезервирована стандартом — домена нет и быть не может
    Л2  MX-запись есть, а её сервер не существует (NXDOMAIN)

ОБЩЕЕ ПРАВИЛО, которое здесь важнее обеих правок: приговор выносится только
на ОТВЕТ сервера. `NXDOMAIN` — это ответ «такого имени нет». Таймаут,
SERVFAIL и сбой прокси — это НАША неудача, и хоронить за неё чужой домен
нельзя. Обе правки существуют ровно затем, чтобы отделить первое от второго,
и половина проверок ниже сторожит именно вторую половину этого правила.
"""
import pytest
import unittest

import dns.resolver

from core.email_syntax import validate_email_syntax
from core.mail_constants import reserved_zone
from core.network import NetworkValidator


# --------------------------------------------------------------------------
# Л1. Зарезервированные зоны
# --------------------------------------------------------------------------

class TestЗарезервированныеЗоны(unittest.TestCase):
    """Зоны, которых нет в корне интернета и не будет.

    RFC 2606 и 6761 (.test .example .invalid .localhost), RFC 6762 (.local),
    RFC 8375 (home.arpa), решение ICANN 2024 (.internal). Плюс зоны, которые
    ICANN рассматривал и НЕ делегировал: .corp .home .mail .lan — их пишут в
    роутерах и доменах Windows, а в интернете их нет.
    """

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
        """Обратный контроль. `test.com` и `local.com` — обычные домены:
        зарезервирована ЗОНА, а не слово в имени."""
        for домен in self.ЖИВЫЕ:
            with self.subTest(домен=домен):
                self.assertEqual(reserved_zone(домен), "")

    def test_мусор_не_роняет(self):
        for значение in [None, 42, [], "", "   ", ".", "..", "a"]:
            with self.subTest(значение=значение):
                self.assertEqual(reserved_zone(значение), "")

    def test_вердикт_invalid_без_единого_запроса_в_сеть(self):
        сеть = NetworkValidator(timeout=1)
        сеть.resolver = _Резолвер(лечь=True)   # любой запрос — исключение
        for домен, зона in self.МЁРТВЫЕ:
            with self.subTest(домен=домен):
                итог = сеть.check_email("ivan@" + домен)
                self.assertEqual(итог["status"], "invalid")
                self.assertIn(зона, итог["reason"])
                self.assertIn("зарезервирована", итог["reason"])

    def test_это_не_ошибка_синтаксиса(self):
        """Синтаксис у такого адреса ПРАВИЛЬНЫЙ, и врать про него нельзя.

        Причина отказа другая, и владелец должен прочитать её словами, а не
        гадать, за что адрес похоронили.
        """
        сеть = NetworkValidator(timeout=1)
        сеть.resolver = _Резолвер(лечь=True)
        for домен, _зона in self.МЁРТВЫЕ:
            with self.subTest(домен=домен):
                self.assertTrue(validate_email_syntax("ivan@" + домен))
                итог = сеть.check_email("ivan@" + домен)
                self.assertNotIn("Syntax", итог["reason"])


# --------------------------------------------------------------------------
# Л2. MX есть, а сервера из неё нет
# --------------------------------------------------------------------------

class _Ответ:
    def __init__(self, адрес="93.184.216.34"):
        self.адрес = адрес

    def __iter__(self):
        return iter([self.адрес])

    def __bool__(self):
        return True


class _Резолвер:
    """Резолвер-заглушка: сеть не задействуется вовсе.

    `правила` — имя хоста -> что сделать: 'есть', 'нет' (NXDOMAIN),
    'пусто' (NoAnswer), 'таймаут' (любая другая беда).
    """

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
    """MX-запись живёт в DNS отдельно от сервера, на который указывает.

    Домен съезжает с Microsoft 365, подписку закрывают, хост исчезает — а
    запись остаётся. ЗАМЕРЕНО на 300 редких доменах базы владельца: 3 домена
    (1.0%) именно такие, NXDOMAIN подтверждён тремя запросами подряд при
    живом контроле `gmail-smtp-in.l.google.com`.
    """

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
        """Главная проверка файла.

        Сбой DNS не имеет права хоронить домен: иначе одна плохая минута
        связи выносит приговор всей базе, и отменить его будет нечем.
        """
        v = self.сеть({"mx1.x.example": "таймаут", "mx2.x.example": "таймаут"})
        self.assertIsNone(v.mx_hosts_alive(["mx1.x.example", "mx2.x.example"]))

    def test_смесь_nxdomain_и_таймаута_НЕ_приговор(self):
        """Один ответил «нет», другой промолчал — вывода нет."""
        v = self.сеть({"mx1.x.example": "нет", "mx2.x.example": "таймаут"})
        self.assertIsNone(v.mx_hosts_alive(["mx1.x.example", "mx2.x.example"]))

    def test_имя_есть_но_адреса_нет_это_НЕ_приговор(self):
        """`NoAnswer` — это «записи такого типа нет», а не «имени нет».

        Подключиться некуда, но приговор здесь строился бы на отсутствии
        записи, а не на ответе сервера «такого имени не существует».
        """
        v = self.сеть({"mx1.x.example": "пусто"})
        self.assertIsNone(v.mx_hosts_alive(["mx1.x.example"]))

    def test_голый_адрес_вместо_имени_не_резолвится(self):
        v = self.сеть({})
        self.assertIs(v.mx_hosts_alive(["1.2.3.4"]), True)
        self.assertEqual(v.resolver.спрошено, [], "адрес спрашивать незачем")

    def test_один_хост_спрашивается_один_раз(self):
        """Одно имя обслуживает тысячи доменов — без кеша это сто тысяч
        запросов за прогон."""
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
        """Сквозь check_email: домен с мёртвым MX получает invalid."""
        v = NetworkValidator(timeout=1)
        v.resolver = _Резолвер({"mx.dead.example": "нет"})
        v.get_mx_records = lambda d: ["mx.dead.example"]
        итог = v.check_email("ivan@somedomain.com")
        self.assertEqual(итог["status"], "invalid")
        self.assertIn("NXDOMAIN", итог["reason"])

    def test_обратный_контроль_живой_mx_доходит_до_smtp(self):
        """При живом MX вердикт НЕ выносится по DNS — идём спрашивать почту."""
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
