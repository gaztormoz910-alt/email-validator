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


# ═══════════ 3. Догадка «Заполненности» из двух слов — с именем впереди ══════
# Решение владельца 14.11.2026, замер 15.11.2026: .unlazy/names-stage2b/LABELS.md.

@pytest.fixture
def coverage_name():
    was = get_country_mode()
    set_country_mode("coverage")
    if "x" not in _extractor:
        _extractor["x"] = NameExtractor(enable_osint=False)
    yield lambda local: _extractor["x"].extract_name(local + "@example.com") or ""
    set_country_mode(was)


@pytest.mark.parametrize("local", ["zeloterasports", "quorvelpaint"])
def test_coverage_two_word_guess_without_leading_name_is_dropped(coverage_name, local):
    # Было «Zelo Terasports», «Quor Velpaint»: первое слово не имя.
    assert coverage_name(local) == ""


def test_coverage_refused_guess_is_not_replaced_by_another_reading(coverage_name):
    # Разбор адреса отклонил «Malhar Singh» (Malhar база не знает); прежняя
    # догадка подставила бы «Mal Har Singh» — другое прочтение тех же букв.
    assert coverage_name("malharsingh") == ""


@pytest.mark.parametrize("local, expected", [
    ("johnbirchly", "John Birchly"),        # первое слово разбор читает именем
    ("kellybarros", "Kelly Barros"),        # его берёт и «Точность»
    # Henry и Kelly разбор читает фамилией (частые фамилии), но это частые
    # имена, и каждый кусок база знает: вторая часть правила (_guess_head_ok).
    ("henrycastellano", "Henry Castellano"),
    ("kellyzamorano", "Kelly Zamorano"),
])
def test_coverage_control_guess_with_leading_name_stays(coverage_name, local, expected):
    assert coverage_name(local) == expected


@pytest.mark.parametrize("local, expected", [
    ("zeloterasports", ""), ("henrycastellano", ""), ("kellybarros", "Kelly Barros"),
])
def test_coverage_control_accuracy_unchanged(local, expected):
    # Правило касается только «Заполненности»: «Точность» — как раньше.
    was = get_country_mode()
    set_country_mode("accuracy")
    try:
        if "x" not in _extractor:
            _extractor["x"] = NameExtractor(enable_osint=False)
        assert (_extractor["x"].extract_name(local + "@example.com") or "") == expected
    finally:
        set_country_mode(was)


# ═══════════ 4. «Точность»: слитная строка из трёх кусков ════════════════════
# Замер 15.11.2026: .unlazy/names-stage2c/LABELS.md.

def _accuracy(local):
    was = get_country_mode()
    set_country_mode("accuracy")
    try:
        if "x" not in _extractor:
            _extractor["x"] = NameExtractor(enable_osint=False)
        return _extractor["x"].extract_name(local + "@example.com") or ""
    finally:
        set_country_mode(was)


@pytest.mark.parametrize("local", ["saraferolli", "lucytabiendo", "jonpattiendo"])
def test_three_pieces_cut_from_two_words_are_dropped_in_accuracy(local):
    # Было «Sara Fer Olli», «Lucy Tabi Endo», «Jon Patti Endo».
    assert _accuracy(local) == ""


@pytest.mark.parametrize("local, expected", [
    ("danielcolebarrow", "Daniel Cole Barrow"),   # имя + второе имя + фамилия
    ("linxuanzhou", "Lin Xuan Zhou"),             # слоги (Zhou — и частая фамилия)
    ("linxuanfu", "Lin Xuan Fu"),                 # слоги; держится только на них
    ("monaferroni", "Mona Ferroni"),               # два куска — не трогается
])
def test_three_pieces_control_real_names_stay(local, expected):
    assert _accuracy(local) == expected


def test_three_pieces_control_coverage_untouched(coverage_name):
    assert coverage_name("saraferolli") == "Sara Fer Olli"
