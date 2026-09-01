# -*- coding: utf-8 -*-
"""Ни одного вердикта без доказательства.

Владелец просит нулевую вероятность ложного ответа. Половина этой задачи
достижима полностью, половина — нет, и смешивать их нельзя.

ДОСТИЖИМО: ни одного `invalid` без доказательства. Каждый приговор либо
опирается на ответ почтовика, либо на факт, который нельзя оспорить.

НЕДОСТИЖИМО физически: гарантия, что `valid` не окажется ложным. На catch-all
домене сервер отвечает 250 на любой выдуманный адрес — узнать, существует ли
конкретный ящик, нельзя ничем. Цель тут другая: такой ответ не должен
НАЗЫВАТЬСЯ valid.

Самое опасное место — приговор БЕЗ запроса к серверу: ошибка там неисправима
и не оставляет следа, кроме слова в логе.
"""
import os
import sys

import dns.exception
import dns.resolver
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.email_syntax import validate_email_syntax  # noqa: E402
from core.local_rules import IMPOSSIBLE, check_local_part  # noqa: E402
from core.smtp_codes import classify_smtp_response  # noqa: E402


# ══════════════════════════════════════════════════════ синтаксис

# Законные формы, которые самописные валидаторы режут чаще всего.
# RFC 5322 §3.2.3 разрешает в имени: ! # $ % & ' * + - / = ? ^ _ ` { | } ~
LEGAL = [
    "ivan@gmail.com",
    "иван@почта.рф",                      # IDN законен (RFC 6531)
    "müller@bücher.de",
    "ivan+news@gmail.com",
    "o'brien@example.com",                # апостроф: ирландские фамилии
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
    "x@xn--80a1acny.xn--p1ai",            # punycode-зона
    "ivan@a-b.example.com",               # дефис ВНУТРИ метки законен
]

# Мусор, который обязан отсеиваться. Каждая строка нарушает сам стандарт, а
# не наши представления о красоте.
JUNK = [
    "", "@", "a@", "@b.com", "a@@b.com", "a b@c.com",
    ".ivan@e.com",                         # точка первой
    "ivan.@e.com",                         # точка последней
    "ivan..p@e.com",                       # две точки подряд
    "ivan@e",                              # домен без точки
    "ivan@.com", "ivan@e..com",
    "ivan@-e.com",                         # метка начинается дефисом
    "ivan@e-.com",                         # метка кончается дефисом
    "a" * 70 + "@e.com",                   # локальная часть > 64 байт
    "ivan@" + "d" * 260 + ".com",          # домен > 255 байт
]


@pytest.mark.parametrize("email", LEGAL)
def test_syntax_never_kills_a_legal_address(email):
    """Приговор без сети неисправим: адрес умирает молча.

    Замерено до починки: из 24 живых форм отвергались 14 — регулярка
    разрешала только `._%+-` вместо полного набора atext. Среди убитых был
    o'brien@example.com, а таких ящиков миллионы.
    """
    assert validate_email_syntax(email) is True, email


@pytest.mark.parametrize("email", JUNK)
def test_syntax_still_rejects_real_junk(email):
    """Положительный контроль: послабление не должно пропускать что попало."""
    assert validate_email_syntax(email) is False, email


def test_syntax_allows_the_whole_rfc_atext_set():
    """Полный набор символов RFC 5322 §3.2.3, а не урезанный."""
    for char in "!#$%&'*+-/=?^_`{|}~":
        assert validate_email_syntax("a%sb@example.com" % char) is True, char


# ══════════════════════════════════════════════ правило имени провайдера

def test_localrule_kills_only_what_could_never_exist():
    """Приговор без сети — только там, где адресовать нечего."""
    # Пустое имя невозможно ни у кого: адресовать нечего.
    assert check_local_part("@gmail.com")[0] == IMPOSSIBLE
    # А длина приговором быть перестала: предел списан со страницы помощи
    # провайдера, а не получен от сервера. См. core/local_rules.py.
    assert check_local_part("a" * 35 + "@gmail.com")[0] != IMPOSSIBLE


@pytest.mark.parametrize("email,why", [
    ("ca@gmail.com", "короткое имя: минимальную длину вводили позже"),
    ("ivan@gmail.com", "четыре знака, но такие ящики живы с 2004 года"),
    ("ivan_petrov@gmail.com", "подчёркивание: аккаунты из Google Apps"),
    ("ivan-p@gmail.com", "дефис: сейчас не выдают, раньше бывало"),
    ("иван@gmail.com", "кириллица у Gmail: правило нынешнее, не вечное"),
    ("a@yahoo.com", "коротко для Yahoo"),
    ("johnacreps@gmail.com", "обычный живой адрес"),
    ("ivan@corporate-domain.com", "чужой домен — правил нет, молчим"),
    ("a" * 35 + "@gmail.com", "длиннее предела: предел из таблицы, не с сервера"),
    (".".join("johndoesmithjr") + "@gmail.com", "точки Gmail в длину не входят"),
])
def test_localrule_sends_everything_else_to_the_server(email, why):
    """Всё, что нарушает лишь НЫНЕШНИЕ правила, обязано идти на сервер.

    Ответ почтовика важнее нашего представления о том, какие имена он
    выдаёт: старые ящики заводились до введения правил.
    """
    assert check_local_part(email)[0] != IMPOSSIBLE, why


# ══════════════════════════════════════════════════════════ DNS

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
    """Сбой DNS обязан читаться как «не спросили», а не «домена нет».

    До починки таймаут возвращал тот же пустой список, что и NXDOMAIN, —
    то есть ПРИГОВОР ВСЕМУ ДОМЕНУ. Моргнувший интернет хоронил живые адреса
    целыми доменами под вывеской «No MX/A records (Dead Domain)».
    """
    assert _validator_raising(exc).get_mx_records("example.com") is None, label


@pytest.mark.parametrize("exc,label", [
    (dns.resolver.NXDOMAIN("нет домена"), "домена действительно нет"),
    (dns.resolver.NoAnswer("нет записей"), "записей такого типа нет"),
])
def test_dns_real_answer_still_buries_the_domain(exc, label):
    """Положительный контроль: настоящий ответ DNS приговор выносить обязан.

    Иначе «сбой не хоронит домен» достигалось бы тем, что не хоронит ничто.
    """
    assert _validator_raising(exc).get_mx_records("example.com") == [], label


def test_dns_failure_is_not_cached():
    """Один сбой не должен хоронить домен на весь прогон."""
    validator = _validator_raising(dns.exception.Timeout("нет ответа"))
    validator.get_mx_records("example.com")
    assert "example.com" not in validator.mx_cache


# ═══════════════════════════════════════════ IDNA и пустой домен

def test_idna_failure_does_not_kill_a_legal_domain():
    """Законный интернационализированный домен обязан переводиться."""
    from core.email_syntax import to_ascii_domain

    assert to_ascii_domain("почта.рф") == "xn--80a1acny.xn--p1ai"
    assert to_ascii_domain("bücher.de") == "xn--bcher-kva.de"
    assert to_ascii_domain("gmail.com") == "gmail.com"


# ═══════════════════════════════ ответ сервера, который НЕ доказательство

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
    """Ответ про НАС не может стать приговором ящику."""
    status = classify_smtp_response(code, text)["status"]
    assert status != "invalid", (label, status)


@pytest.mark.parametrize("code,text", [
    (550, "5.1.1 The email account that you tried to reach does not exist."),
    (550, "5.7.1 No such user!"),                 # Yandex: смысл в тексте
    (550, "5.1.1 user unknown"),
    (550, "Requested action not taken: mailbox unavailable"),
])
def test_notproof_real_proof_still_convicts(code, text):
    """Положительный контроль: настоящее доказательство приговор выносит.

    Без него «ничто не становится приговором» достигалось бы отказом от
    вердиктов вообще — и все мёртвые адреса уехали бы в рассылку.
    """
    assert classify_smtp_response(code, text)["status"] == "invalid", text


def test_proofset_never_overlaps_with_policy_wording():
    """Формулировки-доказательства не должны означать ничего, кроме ящика.

    Если строка из списка доказательств встретится внутри политики, приговор
    начнёт выноситься по отказу репутации.
    """
    from core.smtp_codes import _NO_MAILBOX_PROOF, _POLICY_MARKERS

    for proof in _NO_MAILBOX_PROOF:
        for policy in _POLICY_MARKERS:
            assert policy not in proof, (proof, policy)


def test_proofset_covers_the_big_providers():
    """Формулировки главных почтовиков обязаны распознаваться как приговор."""
    from core.smtp_codes import _NO_MAILBOX_PROOF

    for wording in ("does not exist", "no such user", "user unknown",
                    "mailbox not found", "recipient not found"):
        assert wording in _NO_MAILBOX_PROOF, wording


# ═══════════════════════════════════════════════════ ложный valid

def test_catchall_is_never_called_valid():
    """Единственное место, где физика не даёт гарантии.

    Сервер отвечает 250 на любой выдуманный адрес — значит про конкретный
    ящик не сказано ничего, и называть это «можно слать» нельзя.
    """
    import io as _io

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "core", "pipeline.py")
    with _io.open(path, encoding="utf-8") as handle:
        source = handle.read()

    assert 'status_display = "Unknown"  # Catch-All' in source, \
        "catch-all перестал переводиться в «не доказано»"


def test_catchall_row_is_visible_in_the_table():
    """Проверенный адрес не должен пропадать из выдачи.

    Catch-All и Unverified попадали в группу other, которую не показывает ни
    один фильтр окна: адрес считался в «Всего проверено» и исчезал из
    таблицы.
    """
    from ui.result_store import group_of

    shown = {"valid", "invalid", "spam", "unknown"}
    for status in ("Valid", "Invalid/Bounce", "Risky", "Unknown", "Role-based",
                   "Trap/Disposable", "Unverified", "Catch-All", "что-то новое"):
        assert group_of(status) in shown, status


def test_validsource_no_valid_without_a_server_answer():
    """Ни один код 2xx не выдумывается: valid рождается только из ответа."""
    for code in (250, 251, 200, 299):
        assert classify_smtp_response(code, "OK")["status"] == "valid", code
    # А без ответа сервера — ничего похожего на valid.
    for code, text in ((550, "5.1.1 does not exist"), (450, "greylisted"),
                       (421, "try later"), (0, "")):
        assert classify_smtp_response(code, text)["status"] != "valid", code


def test_validsource_full_mailbox_is_proof_not_a_guess():
    """Переполненный ящик — доказательство существования И пользования."""
    assert classify_smtp_response(452, "4.2.2 over quota")["status"] == "valid"
    assert classify_smtp_response(552, "mailbox is full")["status"] == "valid"
    # Но не всё подряд с этими кодами: место на сервере ящиком не является.
    assert classify_smtp_response(452, "4.3.1 insufficient system storage")["status"] != "valid"


# ══════════════════════════════════════════════════════════ сито

@pytest.mark.parametrize("junk", [
    None, 123, [], {}, b"\xff\xfe", "\x00" * 50, " " * 200, object(),
])
def test_fuzz_classifier_never_invents_a_verdict(junk):
    """Мусор не должен рождать ни valid, ни invalid."""
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
