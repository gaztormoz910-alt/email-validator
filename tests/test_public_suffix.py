# -*- coding: utf-8 -*-
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cleaner import EmailCleaner
from core.disposable import (DISPOSABLE_DOMAINS,
                             extend_disposable_domains, is_disposable)
from core.public_suffix import (зоны_верхнего_уровня,
                                правил_прочитано,
                                версия_списка,
                                публичный_суффикс)


def test_список_прочитан_и_не_пуст():
    assert правил_прочитано() >= 10000, (
        "правил всего %d — список не прочитан или подменён"
        % правил_прочитано())
    assert версия_списка(), "в списке нет строки VERSION — это не файл Mozilla"


def test_зоны_знают_и_юникод_и_punycode():
    зоны = зоны_верхнего_уровня()
    assert "рф" in зоны
    assert "xn--p1ai" in зоны, "punycode-вид зоны IDN в списке не завёлся"


@pytest.mark.parametrize("имя", [
    "co.uk", "msk.ru", "info.pl", "ddns.net", "hopto.org", "blogspot.com",
    "com", "ru",
])
def test_публичный_суффикс_узнаётся(имя):
    assert публичный_суффикс(имя)


@pytest.mark.parametrize("имя", [
    "bbc.co.uk", "gmail.com", "mailinator.com", "gaggle.net", "33mail.com",
])
def test_обычный_домен_суффиксом_не_считается(имя):
    assert not публичный_суффикс(имя)


def test_разбирает_подстановку_и_исключение():
    assert публичный_суффикс("foo.ck"), "правило `*.ck` не разобрано"
    assert not публичный_суффикс("city.kawasaki.jp"), (
        "правило-исключение `!city.kawasaki.jp` не разобрано")


@pytest.mark.parametrize("мусор", [None, "", 123, "   ", "."])
def test_мусор_не_роняет(мусор):
    assert публичный_суффикс(мусор) is False


@pytest.mark.parametrize("зона", [
    "deloitte", "chanel", "dentist", "archi", "bestbuy", "capitalone",
    "creditunion", "bridgestone", "calvinklein", "firestone", "fidelity",
])
def test_настоящая_зона_не_калечится(зона):
    домен = "mycompany." + зона
    стало = (EmailCleaner().clean_email("ivan@" + домен) or "").rsplit("@", 1)[-1]
    assert стало == домен, (
        "зона покалечена: загрузили %r, проверять будем %r" % (домен, стало))


def test_ни_одна_зона_из_списка_не_калечится():
    чистильщик = EmailCleaner()
    покалечены = []
    for зона in sorted(зоны_верхнего_уровня()):
        if "." in зона or not зона.isascii():
            continue
        домен = "mycompany." + зона
        стало = (чистильщик.clean_email("ivan@" + домен)
                 or "").rsplit("@", 1)[-1]
        if стало != домен:
            покалечены.append((домен, стало))
    assert not покалечены, (
        "очистка калечит %d настоящих зон, например: %s"
        % (len(покалечены), покалечены[:5]))


@pytest.mark.parametrize("домен,ждём", [
    ("yandex.rublahblah", "yandex.ru"),
    ("mail.ruxxx", "mail.ru"),
    ("corp.despam", "corp.de"),
    ("gmail.comtelefoon", "gmail.com"),
    ("lee.neteditorryan", "lee.net"),
    ("woh.rr.comjwm", "woh.rr.com"),
    ("mobot.orgor", "mobot.org"),
    ("lsu.eduor", "lsu.edu"),
])
def test_настоящие_склейки_по_прежнему_чинятся(домен, ждём):
    стало = (EmailCleaner().clean_email("ivan@" + домен) or "").rsplit("@", 1)[-1]
    assert стало == ждём, "склейка не починена: %r -> %r" % (домен, стало)


@pytest.mark.parametrize("домен", ["example.comau", "shop.couk", "firma.orguk"])
def test_потерянная_точка_в_составной_зоне_не_чинится_догадкой(домен):
    стало = (EmailCleaner().clean_email("ivan@" + домен) or "").rsplit("@", 1)[-1]
    assert стало == домен, (
        "потерянная точка «починена» догадкой: %r -> %r" % (домен, стало))


@pytest.mark.parametrize("зона,адрес", [
    ("msk.ru", "a@echo.msk.ru"),
    ("info.pl", "b@firma.info.pl"),
    ("co.uk", "c@shop.co.uk"),
    ("ddns.net", "d@my.ddns.net"),
])
def test_зона_в_списке_не_хоронит_домен(зона, адрес):
    было = set(DISPOSABLE_DOMAINS)
    try:
        extend_disposable_domains({зона})
        assert not is_disposable(адрес), (
            "домен объявлен одноразовым из-за зоны %r в скачанном списке" % (зона,))
    finally:
        DISPOSABLE_DOMAINS.clear()
        DISPOSABLE_DOMAINS.update(было)


@pytest.mark.parametrize("сервис,адрес", [
    ("mailinator.com", "a@foo.mailinator.com"),
    ("gaggle.net", "b@asd5.gaggle.net"),
    ("mail-tester.com", "c@srv1.mail-tester.com"),
])
def test_поддомен_настоящего_сервиса_по_прежнему_ловится(сервис, адрес):
    было = set(DISPOSABLE_DOMAINS)
    try:
        extend_disposable_domains({сервис})
        assert is_disposable(адрес), (
            "поддомен сервиса %r перестал ловиться" % (сервис,))
    finally:
        DISPOSABLE_DOMAINS.clear()
        DISPOSABLE_DOMAINS.update(было)
