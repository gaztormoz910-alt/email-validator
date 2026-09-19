# -*- coding: utf-8 -*-
"""Список публичных суффиксов Mozilla: где кончается чужая зона.

Зачем он заведён. Два места держались на самодельном перечне из ста семи зон,
и оба из-за его неполноты врали:

* **очистка домена** принимала настоящую зону за «короткая зона плюс мусор».
  Замерено на списке Mozilla: из 1181 зоны, которых в самодельном перечне не
  было, очистка калечила 41 — `mycompany.deloitte` -> `mycompany.de`,
  `mycompany.chanel` -> `mycompany.ch`, `mycompany.dentist` -> `mycompany.de`.
  Каждая такая строка — вердикт о постороннем человеке;

* **фильтр одноразовых** хоронил целую зону из-за одной строки в скачанном
  списке. Прежний признак («первое слово длиннее трёх букв») отделял зоны на
  глаз и пропускал те, у которых первое слово длинное: `info.pl`.

Все проверки ниже написаны ДО перехода на список и на самодельном перечне
красные. Контроли на обратное идут рядом с каждой: без них «зоны целы»
доказывалось бы простым отключением починки, а «зона не хоронится» —
отключением фильтра.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cleaner import EmailCleaner                    # noqa: E402
from core.disposable import (DISPOSABLE_DOMAINS,         # noqa: E402
                             extend_disposable_domains, is_disposable)
from core.public_suffix import (зоны_верхнего_уровня,    # noqa: E402
                                правил_прочитано,
                                версия_списка,
                                публичный_суффикс)


# ═════════════════════════════ сам список

def test_список_прочитан_и_не_пуст():
    """Файл поставляемый: если он не прочитался, обе защиты молча отключатся."""
    assert правил_прочитано() >= 10000, (
        "правил всего %d — список не прочитан или подменён"
        % правил_прочитано())
    assert версия_списка(), "в списке нет строки VERSION — это не файл Mozilla"


def test_зоны_знают_и_юникод_и_punycode():
    """Файл Mozilla пишет зоны IDN буквами, а программа приходит с punycode.

    В самом файле `xn--` не встречается ни разу. Если хранить только то, что
    написано, список не узнает ни одной зоны IDN, и `почта.рф` останется без
    защиты — при том что домен переводится в punycode ещё до очистки.
    """
    зоны = зоны_верхнего_уровня()
    assert "рф" in зоны
    assert "xn--p1ai" in зоны, "punycode-вид зоны IDN в списке не завёлся"


@pytest.mark.parametrize("имя", [
    "co.uk", "msk.ru", "info.pl", "ddns.net", "hopto.org", "blogspot.com",
    "com", "ru",
])
def test_публичный_суффикс_узнаётся(имя):
    """Под этими именами регистрируются посторонние — владельца у них нет."""
    assert публичный_суффикс(имя)


@pytest.mark.parametrize("имя", [
    "bbc.co.uk", "gmail.com", "mailinator.com", "gaggle.net", "33mail.com",
])
def test_обычный_домен_суффиксом_не_считается(имя):
    """Контроль на обратное: у этих имён ОДИН владелец."""
    assert not публичный_суффикс(имя)


def test_разбирает_подстановку_и_исключение():
    """Подстановки и исключения — то, ради чего список ведут руками."""
    assert публичный_суффикс("foo.ck"), "правило `*.ck` не разобрано"
    assert not публичный_суффикс("city.kawasaki.jp"), (
        "правило-исключение `!city.kawasaki.jp` не разобрано")


@pytest.mark.parametrize("мусор", [None, "", 123, "   ", "."])
def test_мусор_не_роняет(мусор):
    """Зовут из рабочих потоков: исключение здесь стоит потерянного адреса."""
    assert публичный_суффикс(мусор) is False


# ═════════════════════════════ очистка домена

@pytest.mark.parametrize("зона", [
    "deloitte", "chanel", "dentist", "archi", "bestbuy", "capitalone",
    "creditunion", "bridgestone", "calvinklein", "firestone", "fidelity",
])
def test_настоящая_зона_не_калечится(зона):
    """`mycompany.deloitte` обязан остаться собой, а не стать `mycompany.de`."""
    домен = "mycompany." + зона
    стало = (EmailCleaner().clean_email("ivan@" + домен) or "").rsplit("@", 1)[-1]
    assert стало == домен, (
        "зона покалечена: загрузили %r, проверять будем %r" % (домен, стало))


def test_ни_одна_зона_из_списка_не_калечится():
    """Все однословные зоны разом — чтобы не ловить их по одной."""
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
    """Контроль на обратное: список зон не должен отменить саму починку."""
    стало = (EmailCleaner().clean_email("ivan@" + домен) or "").rsplit("@", 1)[-1]
    assert стало == ждём, "склейка не починена: %r -> %r" % (домен, стало)


@pytest.mark.parametrize("домен", ["example.comau", "shop.couk", "firma.orguk"])
def test_потерянная_точка_в_составной_зоне_не_чинится_догадкой(домен):
    """`example.comau` — это потерянная точка в `example.com.au`, а не мусор.

    Восстановить её нельзя: неизвестно, куда она делась. Прежний код резал
    такую строку до `example.co` — то есть выдавал домен в зоне Колумбии,
    которого владелец не загружал. Оставляем как есть: DNS честно скажет,
    что домена нет.
    """
    стало = (EmailCleaner().clean_email("ivan@" + домен) or "").rsplit("@", 1)[-1]
    assert стало == домен, (
        "потерянная точка «починена» догадкой: %r -> %r" % (домен, стало))


# ═════════════════════════════ фильтр одноразовых

@pytest.mark.parametrize("зона,адрес", [
    ("msk.ru", "a@echo.msk.ru"),
    ("info.pl", "b@firma.info.pl"),
    ("co.uk", "c@shop.co.uk"),
    ("ddns.net", "d@my.ddns.net"),
])
def test_зона_в_списке_не_хоронит_домен(зона, адрес):
    """Одна строка в скачанном списке не имеет права хоронить всю зону."""
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
    ("33mail.com", "c@bearcat.33mail.com"),
])
def test_поддомен_настоящего_сервиса_по_прежнему_ловится(сервис, адрес):
    """Контроль на обратное: разбор родителей нужен и должен работать."""
    было = set(DISPOSABLE_DOMAINS)
    try:
        extend_disposable_domains({сервис})
        assert is_disposable(адрес), (
            "поддомен сервиса %r перестал ловиться" % (сервис,))
    finally:
        DISPOSABLE_DOMAINS.clear()
        DISPOSABLE_DOMAINS.update(было)
