# -*- coding: utf-8 -*-
import pytest

from core.parser.ml_predictor import get_country_mode, set_country_mode
from core.parser.name_extractor import NameExtractor, split_name

_extractor = {}


@pytest.fixture(params=["accuracy", "coverage"])
def name_of(request):
    was = get_country_mode()
    set_country_mode(request.param)
    if "x" not in _extractor:
        _extractor["x"] = NameExtractor(enable_osint=False)
    yield lambda local: _extractor["x"].extract_name(local + "@example.com") or ""
    set_country_mode(was)


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
    ("k.zoltan", "Zoltan"),
    ("m.deepika", "Deepika"),
    ("s.priya", "Priya"),
    ("m.garcia", "M Garcia"),
    ("m.martin.jones", "Martin Jones"),
    ("jallen", "Allen"),
    ("mmartin", "Martin"),
])
def test_initial_control_given_names_and_surnames_as_before(name_of, local, expected):
    assert name_of(local) == expected


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
    assert coverage_name(local) == ""


def test_coverage_refused_guess_is_not_replaced_by_another_reading(coverage_name):
    assert coverage_name("malharsingh") == ""


@pytest.mark.parametrize("local, expected", [
    ("johnbirchly", "John Birchly"),
    ("kellybarros", "Kelly Barros"),
    ("henrycastellano", "Henry Castellano"),
    ("kellyzamorano", "Kelly Zamorano"),
])
def test_coverage_control_guess_with_leading_name_stays(coverage_name, local, expected):
    assert coverage_name(local) == expected


@pytest.mark.parametrize("local, expected", [
    ("zeloterasports", ""), ("henrycastellano", ""), ("kellybarros", "Kelly Barros"),
])
def test_coverage_control_accuracy_unchanged(local, expected):
    was = get_country_mode()
    set_country_mode("accuracy")
    try:
        if "x" not in _extractor:
            _extractor["x"] = NameExtractor(enable_osint=False)
        assert (_extractor["x"].extract_name(local + "@example.com") or "") == expected
    finally:
        set_country_mode(was)


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
    assert _accuracy(local) == ""


@pytest.mark.parametrize("local, expected", [
    ("danielcolebarrow", "Daniel Cole Barrow"),
    ("linxuanzhou", "Lin Xuan Zhou"),
    ("linxuanfu", "Lin Xuan Fu"),
    ("monaferroni", "Mona Ferroni"),
])
def test_three_pieces_control_real_names_stay(local, expected):
    assert _accuracy(local) == expected


def test_three_pieces_control_coverage_untouched(coverage_name):
    assert coverage_name("saraferolli") == "Sara Fer Olli"
