# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core.network import NetworkValidator
from core.reject_control import compare_rejections, reject_shape
from core.smtp_codes import WEAK_REJECT_REASON, classify_smtp_response

АДРЕС = "anna.petrova@corpmail.test"
MX = "mx1.corpmail.test"
СПОРНЫЙ = (550, b"5.5.0 Requested action not taken: mailbox unavailable")
НЕТ_ЯЩИКА = (550, b"5.1.1 <someone@corpmail.test>: Recipient address rejected: User unknown")


class _Сервер(object):
    command_encoding = "ascii"

    def __init__(self, настоящему, прочим, журнал):
        self.настоящему, self.прочим, self.журнал = настоящему, прочим, журнал

    def connect(self, host, port):
        return 220, b"mx.corpmail.test ESMTP"

    def ehlo(self, n):
        return 250, b"ok"

    def helo(self, n):
        return 250, b"ok"

    def has_extn(self, n):
        return False

    def mail(self, a, options=None):
        return 250, b"ok"

    def rcpt(self, e):
        self.журнал.append(e)
        if e == АДРЕС:
            return self.настоящему
        if isinstance(self.прочим, Exception):
            raise self.прочим
        return self.прочим

    def verify(self, e):
        return 252, b"no"

    def quit(self):
        return 221, b"bye"

    def close(self):
        pass


def _сессия(настоящему, прочим):
    журнал = []
    nv = NetworkValidator(proxies=[])
    nv._mx_delay = lambda mx: 0.0
    nv._make_smtp_connection = lambda proxy=None: _Сервер(настоящему, прочим, журнал)
    return nv._do_single_ping(АДРЕС, MX), журнал


def test_shape_ignores_echoed_addresses_and_numbers():
    a = reject_shape(550, b"5.1.1 <anna@corpmail.test>: rejected, queue 81723 at 12:01")
    b = reject_shape(550, b"5.1.1 <zq7x@corpmail.test>: rejected, queue 99 at 13:44")
    assert a == b


def test_shape_keeps_enhanced_code_and_basic_code_apart():
    assert reject_shape(550, b"5.1.1 nope") != reject_shape(550, b"5.7.1 nope")
    assert reject_shape(550, b"5.1.1 nope") != reject_shape(554, b"5.1.1 nope")


def test_compare_four_outcomes():
    assert compare_rejections(*СПОРНЫЙ, *СПОРНЫЙ)[0] == "same"
    assert compare_rejections(*СПОРНЫЙ, 250, b"2.1.5 OK")[0] == "fake_accepted"
    assert compare_rejections(*СПОРНЫЙ, *НЕТ_ЯЩИКА)[0] == "fake_differs"
    assert compare_rejections(*СПОРНЫЙ, 451, b"4.7.1 try later")[0] == "inconclusive"
    assert compare_rejections(*СПОРНЫЙ, None, b"")[0] == "inconclusive"
    assert compare_rejections(*СПОРНЫЙ, 550, b"invalid mailbox")[0] == "inconclusive"


def test_weak_phrase_is_what_the_parser_still_calls_weak():
    v = classify_smtp_response(*СПОРНЫЙ)
    assert v["status"] == "invalid" and WEAK_REJECT_REASON in v["reason"]
    v = classify_smtp_response(*НЕТ_ЯЩИКА)
    assert v["status"] == "invalid" and WEAK_REJECT_REASON not in v["reason"]


def test_same_reject_to_fake_keeps_the_verdict():
    итог, журнал = _сессия(СПОРНЫЙ, СПОРНЫЙ)
    assert итог["status"] == "invalid"
    assert итог["fake_reject_compare"] == "same"
    assert "тот же отказ" in итог["reason"]
    assert len(журнал) == 2 and журнал[0] == АДРЕС and журнал[1] != АДРЕС


def test_fake_accepted_but_this_one_rejected_is_policy_not_absence():
    итог, _ = _сессия(СПОРНЫЙ, (250, b"2.1.5 OK"))
    assert итог["status"] == "risky"
    assert итог["fake_reject_compare"] == "fake_accepted"
    assert "не доказано" in итог["reason"]


def test_fake_gets_explicit_user_unknown_this_one_does_not():
    итог, _ = _сессия(СПОРНЫЙ, НЕТ_ЯЩИКА)
    assert итог["status"] == "risky"
    assert итог["fake_reject_compare"] == "fake_differs"
    assert "отвечает иначе" in итог["reason"]


@pytest.mark.parametrize("прочим", [
    (451, b"4.7.1 Greylisted, try again later"),
    (421, b"4.7.0 Too many errors, closing"),
    OSError("connection reset"),
])
def test_failed_comparison_changes_nothing(прочим):
    итог, журнал = _сессия(СПОРНЫЙ, прочим)
    assert итог["status"] == "invalid"
    assert итог["fake_reject_compare"] == "inconclusive"
    assert len(журнал) == 2


def test_explicit_no_mailbox_is_not_compared():
    итог, журнал = _сессия(НЕТ_ЯЩИКА, (250, b"2.1.5 OK"))
    assert итог["status"] == "invalid"
    assert "fake_reject_compare" not in итог
    assert журнал == [АДРЕС]


def test_vrfy_verdict_is_not_compared_with_rcpt():
    nv = NetworkValidator(proxies=[])
    журнал = []
    сервер = _Сервер(СПОРНЫЙ, (250, b"ok"), журнал)
    res = {"status": "invalid", "reason": "550 " + WEAK_REJECT_REASON, "via_vrfy": True}
    nv._compare_with_fake_reject(сервер, "corpmail.test", res, 550, СПОРНЫЙ[1], АДРЕС)
    assert res["status"] == "invalid" and журнал == []


def test_fake_address_itself_is_not_compared_with_itself():
    nv = NetworkValidator(proxies=[])
    журнал = []
    сервер = _Сервер(СПОРНЫЙ, (250, b"ok"), журнал)
    выдуманный = nv._control_address("corpmail.test")
    res = {"status": "invalid", "reason": "550 " + WEAK_REJECT_REASON}
    nv._compare_with_fake_reject(сервер, "corpmail.test", res, 550, СПОРНЫЙ[1], выдуманный)
    assert res["status"] == "invalid" and журнал == []
