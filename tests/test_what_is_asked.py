# -*- coding: utf-8 -*-
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.canary import CANARY_MARK
from core.network import NetworkValidator

ЗАГРУЖЕНО = "vikramsethi.ca@corp-example-t.com"


class _Сервер(object):

    def __init__(self, журнал, правило):
        self.журнал = журнал
        self.правило = правило
        self.command_encoding = "ascii"

    def connect(self, host, port):
        return 220, b"ESMTP ready"

    def ehlo(self, name):
        return 250, b"ok"

    def helo(self, name):
        return 250, b"ok"

    def has_extn(self, name):
        return False

    def mail(self, addr, options=None):
        return 250, b"2.1.0 Sender OK"

    def rcpt(self, email):
        код, текст = self.правило(email)
        self.журнал.append(email)
        return код, текст.encode("utf-8")

    def verify(self, email):
        return 252, b"cannot VRFY"

    def quit(self):
        return 221, b"bye"

    def close(self):
        pass


def _прогнать(правило, адрес=ЗАГРУЖЕНО):
    журнал = []
    nv = NetworkValidator(proxies=[])
    nv._mx_delay = lambda mx: 0.0
    nv.country_for_domain = lambda domain, mx_host="": ""
    nv.check_dns_health = lambda d, mx_record="": {"score": 0}
    nv.get_mx_records = lambda d: ["mx.corp-example-t.com"]
    nv._make_smtp_connection = lambda proxy=None: _Сервер(журнал, правило)
    return nv.check_email(адрес), журнал


ЧЕСТНЫЙ = lambda e: ((250, "2.1.5 Recipient OK") if e == ЗАГРУЖЕНО
                     else (550, "5.1.1 No such user"))
НЕТ_ЯЩИКА = lambda e: ((250, "2.1.5 OK")
                       if e.split("@")[0] in ("postmaster", "abuse")
                       else (550, "5.1.1 No such user"))
ВСЁ_ПОДРЯД = lambda e: (250, "2.1.5 Recipient OK")


def test_asked_the_loaded_address_itself():
    for правило in (ЧЕСТНЫЙ, НЕТ_ЯЩИКА, ВСЁ_ПОДРЯД):
        _итог, журнал = _прогнать(правило)
        assert ЗАГРУЖЕНО in журнал, (
            "загруженный адрес не спрашивали вовсе: %s" % журнал)


def test_asked_domain_is_not_swapped():
    _итог, журнал = _прогнать(ЧЕСТНЫЙ)
    наши = [а for а in журнал if not _выдуманный(а)]
    assert наши, "среди отправленного нет ни одного нашего адреса"
    for адрес in наши:
        assert адрес.split("@")[1] == ЗАГРУЖЕНО.split("@")[1], адрес


def test_asked_mailbox_name_is_not_rewritten():
    смешанный = "John.Smith@corp-example-t.com"
    _итог, журнал = _прогнать(
        lambda e: (250, "2.1.5 OK") if e == смешанный else (550, "5.1.1 no"),
        адрес=смешанный)
    assert смешанный in журнал, журнал


def _выдуманный(адрес):
    имя = адрес.split("@")[0]
    return (CANARY_MARK in адрес
            or имя in ("postmaster", "abuse")
            or (имя not in (ЗАГРУЖЕНО.split("@")[0], "John.Smith")))


def test_verdict_follows_the_answer_about_the_loaded_address():
    итог, _журнал = _прогнать(ЧЕСТНЫЙ)
    assert итог["status"] == "valid", итог


def test_verdict_invalid_only_when_the_server_denies_our_mailbox():
    итог, _журнал = _прогнать(НЕТ_ЯЩИКА)
    assert итог["status"] == "invalid", итог


def test_verdict_a_made_up_answer_can_only_lower_it():
    итог, журнал = _прогнать(ВСЁ_ПОДРЯД)
    assert итог["status"] == "catchall", итог
    assert ЗАГРУЖЕНО in журнал, "и при этом его всё равно спросили"


def test_verdict_control_a_made_up_answer_never_creates_a_valid():
    итог, _журнал = _прогнать(
        lambda e: (550, "5.1.1 No such user") if e == ЗАГРУЖЕНО
        else (250, "2.1.5 OK"))
    assert итог["status"] != "valid", итог


def test_verdict_server_that_denies_postmaster_cannot_condemn():
    итог, _журнал = _прогнать(lambda e: (550, "5.1.1 No such user"))
    assert итог["status"] == "risky", итог


def test_row_carries_the_loaded_address():
    from core.cleaner import EmailCleaner
    from core.streamer import StreamLoader

    исходные = ["vikramsethi.ca@gmail.com", "John.Smith@Corp-Example.com",
                "user@sky.company.co.uk", "a@geometrixx.info"]
    загружено = [e for e, _ in StreamLoader(
        [{"type": "text", "content": "\n".join(исходные) + "\n"}]).stream_emails()]
    cleaner = EmailCleaner()

    расхождения = []
    for исходный, после in zip(исходные, загружено):
        итог = cleaner.correct_and_normalize(после)
        if (итог or "").lower() != исходный.lower():
            расхождения.append("%s -> %s" % (исходный, итог))
    assert not расхождения, "адрес изменился по пути: %s" % расхождения


def test_checked_as_is_actually_filled_now():
    from исходники import исходник_конвейера
    import inspect
    from core.pipeline import ValidationPipeline
    источник = исходник_конвейера()
    assert 'data["checked_as"]' in источник, "поле по-прежнему никто не пишет"
    assert inspect.getsource(ValidationPipeline.run_pipeline).count("self._settle(") >= 2, (
        "лестницу зовёт только одна ветка — в другой строка останется пустой")


def test_checked_as_uses_the_same_function_as_the_probe():
    сеть = io.open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "core", "network.py"), encoding="utf-8").read()
    assert "def probe_form" in сеть
    assert "probe_email = self.probe_form(email)" in сеть, (
        "проверка собирает адрес своим способом, а окно — другим")


def test_checked_as_shows_the_loaded_address_unchanged():
    assert NetworkValidator.probe_form(ЗАГРУЖЕНО) == ЗАГРУЖЕНО


def test_checked_as_control_punycode_is_the_one_difference():
    вышло = NetworkValidator.probe_form("иван@почта.рф")
    assert вышло == "иван@xn--80a1acny.xn--p1ai", вышло
    assert вышло.split("@")[0] == "иван", "имя ящика переписано"
    assert NetworkValidator.probe_form("John.Smith@Corp.COM") == "John.Smith@corp.com"

