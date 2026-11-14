# -*- coding: utf-8 -*-
"""Буква — не имя (этап 2 плана 14.11.2026, решения владельца 14.11).

1. Колонки имени и фамилии не заполняются одной буквой: «J Smith» — имя
   пусто, фамилия Smith. «Здравствуйте, J» в рассылке хуже пустого
   обращения.
2. «Буква + слово, которое бывает и именем, и фамилией» между разделителями
   (m.martin, m.david) — «M Martin», а не «Martin»; имя пусто, фамилия Martin.

Тесты без «_control_» в имени падали на коде до правки (0dc95ca), контроли
проходили и там: см. .unlazy/names-stage2/red_green.py. Адреса выдуманы.
"""
import pytest

from core.parser.ml_predictor import get_country_mode, set_country_mode
from core.parser.name_extractor import NameExtractor, split_name

_extractor = {}


@pytest.fixture(params=["accuracy", "coverage"])
def name_of(request):
    """Имя из адреса в обоих режимах; режим возвращается после теста."""
    was = get_country_mode()
    set_country_mode(request.param)
    if "x" not in _extractor:
        # Конструктор грузит базу имён — один экземпляр на файл.
        _extractor["x"] = NameExtractor(enable_osint=False)
    yield lambda local: _extractor["x"].extract_name(local + "@example.com") or ""
    set_country_mode(was)


# ═══════════════ 1. Одна буква не уходит в колонки имени и фамилии ═══════════

@pytest.mark.parametrize("name, expected", [
    ("J Smith", ("", "Smith")),
    ("J. Smith", ("", "Smith")),
    ("M Martin", ("", "Martin")),
    ("A B Jones", ("", "Jones")),
    ("R James Smith", ("James", "Smith")),
    ("Smith J", ("Smith", "")),
    ("Anna Maria K", ("Anna", "")),
    ("J", ("", "")),
])
def test_split_name_letter_is_not_a_name(name, expected):
    assert split_name(name) == expected


@pytest.mark.parametrize("name, expected", [
    ("Lan Thi Tran", ("Lan", "Tran")),
    ("John F Kennedy", ("John", "Kennedy")),
    ("Kevin", ("Kevin", "")),
    ("Elena Corvetti", ("Elena", "Corvetti")),
    ("", ("", "")),
])
def test_split_name_control_words_are_split_as_before(name, expected):
    assert split_name(name) == expected


# ═══════════ 2. «буква + имя-и-фамилия» — запись «И. Фамилия» ═══════════════

@pytest.mark.parametrize("local, expected", [
    ("m.martin", "M Martin"),
    ("m.david", "M David"),
    ("j.thomas", "J Thomas"),
    ("j.martin84", "J Martin"),
])
def test_initial_with_dual_word_keeps_the_letter(name_of, local, expected):
    assert name_of(local) == expected
    assert split_name(name_of(local)) == ("", expected.split()[-1])


@pytest.mark.parametrize("local, expected", [
    # Слова, которые читаются только именем, — буква снимается, как раньше.
    ("k.zoltan", "Zoltan"),
    ("m.deepika", "Deepika"),
    ("s.priya", "Priya"),
    # Фамилия — «M Garcia», как и было.
    ("m.garcia", "M Garcia"),
    # Три куска: Martin здесь имя, правило «буква + одно слово» не действует.
    ("m.martin.jones", "Martin Jones"),
    # Слитно правило не действует: границу буквы человек не ставил.
    ("jallen", "Allen"),
    ("mmartin", "Martin"),
])
def test_initial_control_given_names_and_surnames_as_before(name_of, local, expected):
    assert name_of(local) == expected
