# -*- coding: utf-8 -*-
"""Досетевые инварианты на РЕАЛЬНОЙ базе владельца.

Зачем отдельный файл. Все прочие тесты работают на выдуманных адресах, а
выдумывает их тот же человек, который писал код, — и потому они проверяют те
случаи, о которых он уже подумал. Живая база проверяет остальные.

Она это уже сделала: на 5000 адресов нашлась подмена домена
`geometrixx.info` -> `geometrixx.in`. Зона Индии существует, домен в ней тоже
может существовать, и вердикт получился бы настоящий — но про ЧУЖОЙ ящик, под
именем моего. Два адреса из пяти тысяч — это порядка восьмидесяти тысяч
подменённых контактов на базе в двести миллионов, и ни один из них не выглядит
подозрительно ни в таблице, ни в выгрузке.

Сеть здесь не задействуется вовсе: проверяется только то, что происходит с
адресом ДО первого запроса — очистка, синтаксис, правила провайдера, ключ
дедупа. Именно на этом отрезке вердикт выносится тише всего.

Файл базы лежит вне репозитория, поэтому в CI и на чужой машине набор себя
пропускает. Путь переопределяется переменной окружения VALIDATOR_OWNER_BASE.
"""
import os

import pytest

from core.cleaner import EmailCleaner, normalize_for_dedup, strip_wrapping_junk
from core.email_syntax import validate_email_syntax
from core.local_rules import IMPOSSIBLE, check_local_part

DEFAULT_BASE = os.path.join(
    "C:\\", "Users", "user", "OneDrive", "Desktop", "Мой софт", "200m",
    "Почты", "emails.csv")


def _base_path():
    return os.environ.get("VALIDATOR_OWNER_BASE") or DEFAULT_BASE


needs_base = pytest.mark.skipif(
    not os.path.exists(_base_path()),
    reason="базы владельца нет на этой машине — задай VALIDATOR_OWNER_BASE")


@pytest.fixture(scope="module")
def rows():
    """Адреса из файла без заголовка. utf-8-sig — файл выгружен из Excel с BOM."""
    with open(_base_path(), "r", encoding="utf-8-sig") as handle:
        lines = [line.strip() for line in handle if line.strip()]
    # Первая строка — имя колонки, а не адрес: в ней нет «@».
    if lines and "@" not in lines[0]:
        lines = lines[1:]
    assert lines, "файл базы пуст"
    return lines


def _domain_of(address):
    return address.rsplit("@", 1)[1] if "@" in address else ""


# --- сама проверка, ради которой файл и заведён -----------------------------

@needs_base
def test_cleaner_never_moves_address_to_another_domain(rows):
    """Очистка не имеет права менять домен на живой базе.

    Снятие обёртки (`<...>`, `mailto:`, кавычки, регистр) доменом не считается —
    его берём уже из распакованной строки. Всё, что меняется ПОСЛЕ этого, —
    решение программы за владельца, и на настоящей базе таких решений быть не
    должно ни одного.
    """
    cleaner = EmailCleaner()
    moved = []
    for raw in rows:
        unwrapped = strip_wrapping_junk(raw)
        if "@" not in unwrapped:
            continue
        cleaned = cleaner.clean_email(raw)
        if not cleaned:
            continue
        before, after = _domain_of(unwrapped), _domain_of(cleaned)
        if before != after:
            moved.append("%s: %s -> %s" % (raw, before, after))

    assert not moved, (
        "очистка увела %d адресов на другой домен — вердикт будет про чужой "
        "ящик:\n  %s" % (len(moved), "\n  ".join(moved[:10])))


@needs_base
def test_no_address_is_lost_by_cleaning(rows):
    """Ни один адрес не исчезает молча: подано столько же, сколько вышло."""
    cleaner = EmailCleaner()
    dropped = [raw for raw in rows if not cleaner.clean_email(raw)]
    assert not dropped, (
        "очистка выбросила %d адресов, в таблицу они не попадут вовсе:\n  %s"
        % (len(dropped), "\n  ".join(repr(d) for d in dropped[:10])))


@needs_base
def test_no_offline_verdict_without_proof(rows):
    """Приговор без сети ставится только за факт, а не за правило провайдера.

    На этой базе фактов нет: адреса собраны с живых страниц и синтаксически
    исправны. Ноль здесь — измеренное свойство базы, а не догадка; если базу
    заменят на другую, число надо перемерить, а не подогнать.
    """
    cleaner = EmailCleaner()
    condemned = []
    for raw in rows:
        cleaned = cleaner.clean_email(raw)
        if not cleaned:
            continue
        if not validate_email_syntax(cleaned):
            condemned.append("%s: синтаксис" % cleaned)
            continue
        verdict, why = check_local_part(cleaned)
        if verdict == IMPOSSIBLE:
            condemned.append("%s: %s" % (cleaned, why))

    assert not condemned, (
        "%d адресов получили Invalid без единого запроса к серверу:\n  %s"
        % (len(condemned), "\n  ".join(condemned[:10])))


@needs_base
def test_dedup_key_is_stable_between_runs(rows):
    """Ключ дедупа не зависит от порядка обхода и от запуска процесса.

    Плавающий ключ означает, что список отписок сверяется то так, то этак: тот,
    кто уже попросил его не трогать, получит письмо снова.
    """
    cleaner = EmailCleaner()
    first = [normalize_for_dedup(cleaner.clean_email(raw) or raw) for raw in rows]
    second = [normalize_for_dedup(EmailCleaner().clean_email(raw) or raw)
              for raw in rows]
    assert first == second, "ключ дедупа изменился между двумя проходами"


# --- то же свойство единичными случаями, без файла --------------------------
#
# Эти проверки идут и в CI, где базы владельца нет. Файл нашёл дефект, а
# закрепляют его они.

@pytest.mark.parametrize("address, expected", [
    # Зона целиком — не мусор. `in` начинает `info`, `co` — `company`,
    # `me` — `media`: без предохранителя адрес уезжал на чужой домен.
    ("aparker@geometrixx.info", "aparker@geometrixx.info"),
    ("a@acme.company", "a@acme.company"),
    ("a@x.institute", "a@x.institute"),
    ("a@y.media", "a@y.media"),
    ("a@z.careers", "a@z.careers"),
])
def test_known_zone_is_never_shortened(address, expected):
    assert EmailCleaner().clean_email(address) == expected


@pytest.mark.parametrize("address, expected", [
    # Положительный контроль: настоящие склейки по-прежнему чинятся. Без него
    # предыдущий тест прошёл бы и на функции, которая не делает ничего.
    ("b@yandex.rublahblah", "b@yandex.ru"),
    ("c@mail.ruXXX", "c@mail.ru"),
    ("d@corp.deSpam", "d@corp.de"),
    ("e@gmail.comtelefoon", "e@gmail.com"),
    ("f@corp.com-jobs", "f@corp.com"),
])
def test_glued_junk_is_still_cut(address, expected):
    assert EmailCleaner().clean_email(address) == expected
