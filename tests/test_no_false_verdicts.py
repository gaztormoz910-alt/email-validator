# -*- coding: utf-8 -*-
import os
import sys

import dns.exception
import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.email_syntax import validate_email_syntax
from core.local_rules import IMPOSSIBLE, check_local_part
from core.smtp_codes import classify_smtp_response


LEGAL = [
    "ivan@gmail.com",
    "иван@почта.рф",
    "müller@bücher.de",
    "ivan+news@gmail.com",
    "o'brien@example.com",
    "d'angelo@example.com",
    "ivan.petrov-smith@sub.example.co.uk",
    "a@b.io",
    "ivan_petrov@example.com",
    "123456@qq.com",
    "ivan!test@example.com",
    "ivan#tag@example.com",
    "ivan$d@example.com",
    "ivan%p@example.com",
    "ivan&a@example.com",
    "ivan*s@example.com",
    "ivan/sl@example.com",
    "ivan=eq@example.com",
    "ivan?q@example.com",
    "ivan^h@example.com",
    "ivan`t@example.com",
    "ivan{b}@example.com",
    "ivan|p@example.com",
    "ivan~t@example.com",
    "x@xn--80a1acny.xn--p1ai",
    "ivan@a-b.example.com",
]

JUNK = [
    "", "@", "a@", "@b.com", "a@@b.com", "a b@c.com",
    ".ivan@e.com",
    "ivan.@e.com",
    "ivan..p@e.com",
    "ivan@e",
    "ivan@.com", "ivan@e..com",
    "ivan@-e.com",
    "ivan@e-.com",
    "a" * 70 + "@e.com",
    "ivan@" + "d" * 260 + ".com",
]


@pytest.mark.parametrize("email", LEGAL)
def test_syntax_never_kills_a_legal_address(email):
    assert validate_email_syntax(email) is True, email


@pytest.mark.parametrize("email", JUNK)
def test_syntax_still_rejects_real_junk(email):
    assert validate_email_syntax(email) is False, email


def test_syntax_allows_the_whole_rfc_atext_set():
    for char in "!#$%&'*+-/=?^_`{|}~":
        assert validate_email_syntax("a%sb@example.com" % char) is True, char


def test_localrule_kills_only_what_could_never_exist():
    assert check_local_part("@gmail.com")[0] == IMPOSSIBLE
    assert check_local_part("a" * 35 + "@gmail.com")[0] != IMPOSSIBLE


@pytest.mark.parametrize("email,why", [
    ("ca@gmail.com", "короткое имя: минимальную длину вводили позже"),
    ("ivan@gmail.com", "четыре знака, но такие ящики живы с 2004 года"),
    ("ivan_petrov@gmail.com", "подчёркивание: аккаунты из Google Apps"),
    ("ivan-p@gmail.com", "дефис: сейчас не выдают, раньше бывало"),
    ("иван@gmail.com", "кириллица у Gmail: правило нынешнее, не вечное"),
    ("a@yahoo.com", "коротко для Yahoo"),
    ("johnoakreps@gmail.com", "обычный живой адрес"),
    ("ivan@corporate-domain.com", "чужой домен — правил нет, молчим"),
    ("a" * 35 + "@gmail.com", "длиннее предела: предел из таблицы, не с сервера"),
    (".".join("johndoesmithjr") + "@gmail.com", "точки Gmail в длину не входят"),
])
def test_localrule_sends_everything_else_to_the_server(email, why):
    assert check_local_part(email)[0] != IMPOSSIBLE, why


def _validator_raising(exc):
    from core.network import NetworkValidator

    validator = NetworkValidator(timeout=2, proxy_dns=False)

    class Resolver:
        def resolve(self, name, rtype):
            raise exc

    validator.resolver = Resolver()
    validator.mx_cache.clear()
    return validator


@pytest.mark.parametrize("exc,label", [
    (dns.exception.Timeout("нет ответа"), "таймаут"),
    (dns.resolver.NoNameservers("нет серверов"), "серверы имён недоступны"),
    (OSError("сеть отвалилась"), "обрыв сети"),
])
def test_dns_failure_is_not_a_dead_domain(exc, label):
    assert _validator_raising(exc).get_mx_records("example.com") is None, label


@pytest.mark.parametrize("exc,label", [
    (dns.resolver.NXDOMAIN("нет домена"), "домена действительно нет"),
    (dns.resolver.NoAnswer("нет записей"), "записей такого типа нет"),
])
def test_dns_real_answer_still_buries_the_domain(exc, label):
    assert _validator_raising(exc).get_mx_records("example.com") == [], label


def test_dns_failure_is_not_cached():
    validator = _validator_raising(dns.exception.Timeout("нет ответа"))
    validator.get_mx_records("example.com")
    assert "example.com" not in validator.mx_cache


def test_idna_failure_does_not_kill_a_legal_domain():
    from core.email_syntax import to_ascii_domain

    assert to_ascii_domain("почта.рф") == "xn--80a1acny.xn--p1ai"
    assert to_ascii_domain("bücher.de") == "xn--bcher-kva.de"
    assert to_ascii_domain("gmail.com") == "gmail.com"


@pytest.mark.parametrize("code,text,label", [
    (550, "5.7.1 Service unavailable, Client host [1.2.3.4] blocked using Spamhaus",
     "репутация нашего IP"),
    (550, "5.7.25 Reverse DNS lookup failed", "нет FCrDNS у нас"),
    (553, "5.1.8 Sender address rejected", "отказ ОТПРАВИТЕЛЮ"),
    (550, "5.7.1 Unable to relay", "релей запрещён"),
    (554, "5.7.1 Message rejected due to content", "политика по содержимому"),
    (550, "Please try again later", "временный текст при постоянном коде"),
    (452, "4.3.1 Insufficient system storage", "место кончилось на СЕРВЕРЕ"),
    (552, "5.3.4 Message size exceeds fixed limit", "лимит размера письма"),
    (500, "Syntax error, command unrecognized", "сервер не понял НАС"),
    (521, "Server does not accept mail", "домен не принимает почту вовсе"),
    (450, "4.1.8 Sender address rejected: Domain not found", "проблема отправителя"),
    (421, "4.7.0 Try again later", "лимит скорости"),
])
def test_notproof_never_becomes_a_verdict(code, text, label):
    status = classify_smtp_response(code, text)["status"]
    assert status != "invalid", (label, status)


@pytest.mark.parametrize("code,text", [
    (550, "5.1.1 The email account that you tried to reach does not exist."),
    (550, "5.7.1 No such user!"),
    (550, "5.1.1 user unknown"),
    (550, "Requested action not taken: mailbox unavailable"),
])
def test_notproof_real_proof_still_convicts(code, text):
    assert classify_smtp_response(code, text)["status"] == "invalid", text


def test_proofset_never_overlaps_with_policy_wording():
    from core.smtp_codes import _NO_MAILBOX_PROOF, _POLICY_MARKERS

    for proof in _NO_MAILBOX_PROOF:
        for policy in _POLICY_MARKERS:
            assert policy not in proof, (proof, policy)


def test_proofset_covers_the_big_providers():
    from core.smtp_codes import _NO_MAILBOX_PROOF

    for wording in ("does not exist", "no such user", "user unknown",
                    "mailbox not found", "recipient not found"):
        assert wording in _NO_MAILBOX_PROOF, wording


def test_catchall_is_never_called_valid():
    from core.settle import DISPLAY_OF
    assert DISPLAY_OF["catchall"] == "Unknown",         "catch-all перестал переводиться в «не доказано»"
    assert DISPLAY_OF["unconfirmed"] != "Valid"


def test_catchall_row_is_visible_in_the_table():
    from ui.result_store import group_of

    shown = {"valid", "invalid", "spam", "unknown"}
    for status in ("Valid", "Invalid/Bounce", "Risky", "Unknown", "Role-based",
                   "Trap/Disposable", "Unverified", "Catch-All", "что-то новое"):
        assert group_of(status) in shown, status


def test_validsource_no_valid_without_a_server_answer():
    for code in (250, 251, 200, 299):
        assert classify_smtp_response(code, "OK")["status"] == "valid", code
    for code, text in ((550, "5.1.1 does not exist"), (450, "greylisted"),
                       (421, "try later"), (0, "")):
        assert classify_smtp_response(code, text)["status"] != "valid", code


def test_validsource_full_mailbox_is_not_sendable():
    assert classify_smtp_response(452, "4.2.2 over quota")["status"] == "full"
    assert classify_smtp_response(552, "mailbox is full")["status"] == "full"
    assert classify_smtp_response(452, "4.3.1 insufficient system storage")["status"] not in (
        "valid", "full")


@pytest.mark.parametrize("junk", [
    None, 123, [], {}, b"\xff\xfe", "\x00" * 50, " " * 200, object(),
])
def test_fuzz_classifier_never_invents_a_verdict(junk):
    for code in (junk, 250, 550, "чепуха"):
        result = classify_smtp_response(code, junk)
        assert isinstance(result, dict) and "status" in result
        if not isinstance(code, int):
            assert result["status"] == "unknown", (code, junk, result)


@pytest.mark.parametrize("junk", [None, 123, [], {}, b"a@b.c", "\x00@\x00"])
def test_fuzz_syntax_never_crashes_or_passes_junk(junk):
    assert validate_email_syntax(junk) is False


@pytest.mark.parametrize("junk", [None, 123, [], {}, "", "@@@"])
def test_fuzz_local_rules_survive(junk):
    verdict, reason = check_local_part(junk)
    assert isinstance(verdict, str) and isinstance(reason, str)
