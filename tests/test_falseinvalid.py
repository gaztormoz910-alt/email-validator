# -*- coding: utf-8 -*-
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.cleaner import EmailCleaner
from core.email_syntax import validate_email_syntax
from core.inputnorm import strip_comments
from core.network import NetworkValidator

CLEANER = EmailCleaner()


@pytest.mark.parametrize("исходный,ожидаемый", [
    ("john(note)@example.com", "john@example.com"),
    ("(note)john@example.com", "john@example.com"),
    ("john@(note)example.com", "john@example.com"),
    ("john@example.com(note)", "john@example.com"),
    ("(a)john(b)@(c)example.com(d)", "john@example.com"),
])
def test_cfws_comment_is_stripped(исходный, ожидаемый):
    assert strip_comments(исходный) == ожидаемый


def test_cfws_address_becomes_valid_syntax():
    assert CLEANER.correct_and_normalize("john(note)@example.com") == "john@example.com"
    assert validate_email_syntax(CLEANER.correct_and_normalize("john(note)@example.com"))


def test_cfws_same_answer_for_cyrillic():
    латиница = strip_comments("john(note)@example.com")
    кириллица = strip_comments("john(заметка)@example.com")
    assert латиница == "john@example.com"
    assert кириллица == "john@example.com"


def test_cfws_parens_inside_atom_are_left_alone():
    for целый in ("a(b)c@example.com", "jo(hn@example.com", "john)note(@x.com"):
        assert strip_comments(целый) == целый


def test_cfws_unbalanced_parens_are_left_alone():
    for целый in ("john(note@example.com", "john)@example.com",
                  "john((a)@example.com"):
        assert strip_comments(целый) == целый


def test_cfws_quoted_local_keeps_its_parens():
    в_кавычках = '"a(b)c"@example.com'
    assert strip_comments(в_кавычках) == в_кавычках


def test_cfws_does_not_touch_ordinary_addresses():
    for обычный in ("ivan@gmail.com", "john.smith@corp.co.uk",
                    "user+tag@example.com", "a%b@corp.com",
                    "иван@почта.рф", '"very.unusual"@example.com'):
        assert strip_comments(обычный) == обычный


@pytest.mark.parametrize("адрес", [
    "user@[192.168.1.1]",
    "user@[93.184.216.34]",
    "user@[IPv6:2001:db8::1]",
    "user@[IPv6:::1]",
])
def test_literal_is_valid_syntax(адрес):
    assert validate_email_syntax(адрес), "законный домен-литерал отвергнут"


def test_literal_survives_the_cleaner():
    assert CLEANER.correct_and_normalize("user@[93.184.216.34]") == "user@[93.184.216.34]"


def test_literal_ipv6_survives_the_cleaner():
    вышло = CLEANER.correct_and_normalize("user@[IPv6:2001:DB8::1]")
    assert validate_email_syntax(вышло), "после очистки литерал IPv6 сломался: %r" % вышло
    assert вышло.startswith("user@["), вышло


@pytest.mark.parametrize("мусор", [
    "user@[999.1.1.1]",
    "user@[not-an-ip]",
    "user@[192.168.1]",
    "user@[]",
    "user@[192.168.1.1",
    "user@192.168.1.1]",
])
def test_literal_garbage_is_still_rejected(мусор):
    assert not validate_email_syntax(мусор), "мусор принят как домен-литерал"


class _Сервер(object):
    command_encoding = "ascii"

    def __init__(self, куда):
        self.куда = куда

    def connect(self, host, port):
        self.куда.append(host)
        return 220, b"mx.test ESMTP"

    def ehlo(self, n):
        return 250, b"ok"

    def helo(self, n):
        return 250, b"ok"

    def has_extn(self, n):
        return False

    def mail(self, a, options=None):
        return 250, b"ok"

    def rcpt(self, e):
        return 250, b"2.1.5 OK"

    def verify(self, e):
        return 252, b"no"

    def quit(self):
        return 221, b"bye"

    def close(self):
        pass


def _проба(адрес):
    куда = []
    nv = NetworkValidator(proxies=[])
    nv._mx_delay = lambda mx: 0.0
    nv.country_for_domain = lambda d, mx_host="": ""
    nv.check_dns_health = lambda d, mx_record="": {"score": 0}
    nv._make_smtp_connection = lambda proxy=None: _Сервер(куда)
    итог = nv.check_email(адрес)
    return куда, итог.get("status"), итог.get("reason") or ""


@pytest.mark.parametrize("адрес", [
    "user@[192.168.1.1]",
    "user@[127.0.0.1]",
    "user@[10.0.0.1]",
    "user@[169.254.1.1]",
    "user@[IPv6:::1]",
])
def test_ssrf_private_literal_is_never_probed(адрес):
    куда, статус, _ = _проба(адрес)
    assert куда == [], "валидатор подключился к внутреннему адресу: %s" % куда
    assert статус == "unknown", "вердикт %r вместо «не проверено»" % статус


def _загрузить(строка):
    from core.streamer import StreamLoader
    return [e for e, _ in StreamLoader(
        [{"type": "text", "content": строка + "\n"}]).stream_emails()]


def test_loader_keeps_ipv6_literal_whole():
    вышло = _загрузить("user@[IPv6:2001:DB8::1]")
    assert len(вышло) == 1, вышло
    assert вышло[0].startswith("user@[") and вышло[0].endswith("]"), вышло[0]
    assert validate_email_syntax(вышло[0]), "литерал доехал сломанным: %r" % вышло[0]


def test_loader_never_reports_about_a_neighbouring_mailbox():
    вышло = _загрузить("a(b)c@example.com")
    assert вышло == ["a(b)c@example.com"], (
        "загрузчик подменил адрес: %s" % вышло)
    assert not validate_email_syntax(вышло[0]), (
        "битая строка обязана отвергаться синтаксисом, а не проверяться")


@pytest.mark.parametrize("строка,ожидаемый", [
    ("Ivan Petrov <ivan@corp.com>", "ivan@corp.com"),
    ("Мария Иванова <maria@corp.ru>;", "maria@corp.ru"),
    ('"ivan@corp.com",', "ivan@corp.com"),
    ("ivan@gmail.com:parol123", "ivan@gmail.com"),
    ("ivan@gmail.com", "ivan@gmail.com"),
])
def test_loader_still_unwraps_ordinary_forms(строка, ожидаемый):
    assert _загрузить(строка) == [ожидаемый]


def test_ssrf_public_literal_is_probed():
    куда, статус, _ = _проба("user@[93.184.216.34]")
    assert куда, "к публичному литералу не подключились вовсе"
    assert set(куда) == {"93.184.216.34"}, "ушли не туда: %s" % куда
    assert статус in ("valid", "catchall"), "вердикт %r" % статус
