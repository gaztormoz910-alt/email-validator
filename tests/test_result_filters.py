# -*- coding: utf-8 -*-
"""Отбор результатов по граням и поиск адреса.

Требование владельца: фильтровать не только по вердикту, но и по стране,
полу, почтовику и скору, плюс искать конкретный адрес среди всей загруженной
базы.

Опасность здесь не в логике, а в цене. Фильтр, честно перебирающий базу в
питоне, на трёхстах тысячах строк вешал окно — этим уже болел фильтр по
скору, и лечился он выносом значения в колонку с индексом. Поэтому тут есть
не только проверки правильности, но и замер (test_speed_*), падающий, если
отбор снова уедет в перебор.
"""
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.result_store import ResultStore, normalize_filters  # noqa: E402


COUNTRIES = ["США", "Индия", "Германия", ""]
GENDERS = ["Мужской", "Женский", ""]
DOMAINS = ["gmail.com", "yahoo.com", "aol.com", "mail.ru"]


@pytest.fixture
def store():
    result = ResultStore()
    yield result
    result.close()


@pytest.fixture
def filled(store):
    """Небольшая база, где каждое сочетание граней встречается предсказуемо."""
    for i in range(120):
        store.append(
            "user%02d@%s" % (i, DOMAINS[i % 4]),
            "Valid" if i % 3 else "Invalid/Bounce",
            "250 OK", "mx",
            {"engagement_score": (i % 10) * 10,
             "country": COUNTRIES[i % 4],
             "gender": GENDERS[i % 3],
             "name": "Имя %d" % i})
    return store


# ────────────────────────────────────────────────────────── facets

def test_facets_filter_by_country(filled):
    total = filled.matching_count(filters={"groups": ["valid", "invalid"]})
    only_usa = filled.matching_count(
        filters={"groups": ["valid", "invalid"], "country": ["США"]})
    assert 0 < only_usa < total
    rows = filled.page(filters={"groups": ["valid", "invalid"],
                                "country": ["США"]}, size=1000)
    assert rows and all(r["data"]["country"] == "США" for r in rows)
    assert len(rows) == only_usa


def test_facets_filter_by_gender(filled):
    rows = filled.page(filters={"groups": ["valid", "invalid"],
                                "gender": ["Женский"]}, size=1000)
    assert rows and all(r["data"]["gender"] == "Женский" for r in rows)


def test_facets_filter_by_provider(filled):
    rows = filled.page(filters={"groups": ["valid", "invalid"],
                                "provider": ["gmail.com"]}, size=1000)
    assert rows and all(r["email"].endswith("@gmail.com") for r in rows)


def test_facets_provider_is_matched_case_insensitively(store):
    store.append("Ivan@GMAIL.com", "Valid", "250 OK", "mx", {})
    rows = store.page(filters={"groups": ["valid"], "provider": ["gmail.com"]})
    assert len(rows) == 1


def test_facets_combine_with_each_other_and_with_score(filled):
    picked = {"groups": ["valid", "invalid"], "country": ["США"],
              "gender": ["Мужской"], "provider": ["gmail.com"], "minScore": 50}
    rows = filled.page(filters=picked, size=1000)
    for row in rows:
        assert row["data"]["country"] == "США"
        assert row["data"]["gender"] == "Мужской"
        assert row["email"].endswith("@gmail.com")
        assert row["data"]["engagement_score"] >= 50
    assert filled.matching_count(filters=picked) == len(rows)


def test_facets_verdict_still_rules(filled):
    """Грани сужают выборку внутри вердикта, а не поверх него.

    Вердикт SMTP — самое сильное доказательство, и никакой фильтр по стране не
    имеет права вытащить в выборку «можно слать» адрес, которого нет.
    """
    rows = filled.page(filters={"groups": ["valid"], "country": ["США"]},
                       size=1000)
    assert rows and all(r["status"] == "Valid" for r in rows)


def test_facets_empty_value_is_selectable(filled):
    """«Без страны» — законный выбор, а не отсутствие фильтра."""
    rows = filled.page(filters={"groups": ["valid", "invalid"], "country": [""]},
                       size=1000)
    assert rows and all(not r["data"]["country"] for r in rows)


def test_facets_unknown_value_finds_nothing(filled):
    assert filled.matching_count(
        filters={"groups": ["valid", "invalid"], "country": ["Марс"]}) == 0


def test_facets_no_filters_behaves_as_before(filled):
    """Старый вызов без фильтров обязан работать в точности как раньше."""
    assert filled.matching_count(("valid",)) == filled.counts()["valid"]
    assert len(filled.page(("valid",), page=1, size=10)) == 10


def test_facets_paging_stays_consistent(filled):
    picked = {"groups": ["valid", "invalid"], "provider": ["gmail.com"]}
    total = filled.matching_count(filters=picked)
    first = filled.page(filters=picked, page=1, size=7)
    second = filled.page(filters=picked, page=2, size=7)
    assert len(first) == 7
    assert not ({r["email"] for r in first} & {r["email"] for r in second})
    collected = []
    page = 1
    while True:
        rows = filled.page(filters=picked, page=page, size=7)
        if not rows:
            break
        collected.extend(rows)
        page += 1
    assert len(collected) == total


def test_facets_export_sees_the_same_selection(filled):
    """Выгрузка обязана отдать ровно то, что владелец видит на экране."""
    picked = {"groups": ["valid"], "country": ["Индия"], "minScore": 30}
    on_screen = filled.matching_count(filters=picked)
    exported = list(filled.iter_matching(filters=picked))
    assert len(exported) == on_screen


# ────────────────────────────────────────────────────────── search

def test_search_finds_a_substring_of_the_address(filled):
    rows = filled.page(filters={"groups": ["valid", "invalid"],
                                "search": "user07"}, size=100)
    assert len(rows) == 1
    assert rows[0]["email"].startswith("user07@")


def test_search_ignores_case_on_both_sides(store):
    store.append("Ivan.Petrov@GMAIL.com", "Valid", "250 OK", "mx", {})
    for needle in ("ivan", "IVAN", "PeTrOv", "GMAIL"):
        rows = store.page(filters={"groups": ["valid"], "search": needle})
        assert len(rows) == 1, needle


def test_search_matches_the_domain_too(filled):
    rows = filled.page(filters={"groups": ["valid", "invalid"],
                                "search": "yahoo"}, size=1000)
    assert rows and all("yahoo" in r["email"] for r in rows)


def test_search_combines_with_the_other_filters(filled):
    picked = {"groups": ["valid", "invalid"], "search": "user1",
              "provider": ["gmail.com"]}
    rows = filled.page(filters=picked, size=1000)
    assert rows
    for row in rows:
        assert "user1" in row["email"] and row["email"].endswith("@gmail.com")
    assert filled.matching_count(filters=picked) == len(rows)


def test_search_treats_percent_and_underscore_literally(store):
    """Без экранирования поиск «a_b» нашёл бы «axb», а «%» — вообще всё."""
    store.append("a_b@gmail.com", "Valid", "250 OK", "mx", {})
    store.append("axb@gmail.com", "Valid", "250 OK", "mx", {})
    store.append("plain@gmail.com", "Valid", "250 OK", "mx", {})

    rows = store.page(filters={"groups": ["valid"], "search": "a_b"})
    assert [r["email"] for r in rows] == ["a_b@gmail.com"]

    assert store.matching_count(filters={"groups": ["valid"], "search": "%"}) == 0


def test_search_for_nothing_returns_everything(filled):
    assert (filled.matching_count(filters={"groups": ["valid"], "search": ""})
            == filled.counts()["valid"])


def test_search_missing_address_finds_nothing(filled):
    assert filled.matching_count(
        filters={"groups": ["valid", "invalid"], "search": "нетутакого"}) == 0


# ────────────────────────────────────────────────────────── facet_values

def test_facet_values_come_from_the_base_not_from_a_dictionary(filled):
    values = filled.facet_values(filters={"groups": ["valid", "invalid"]})
    countries = {item["value"] for item in values["country"]}
    assert countries == set(COUNTRIES)
    assert "Марс" not in countries

    providers = {item["value"] for item in values["provider"]}
    assert providers == set(DOMAINS)

    genders = {item["value"] for item in values["gender"]}
    assert genders == set(GENDERS)


def test_facet_values_carry_honest_counts(filled):
    values = filled.facet_values(filters={"groups": ["valid", "invalid"]})
    for item in values["provider"]:
        expected = filled.matching_count(
            filters={"groups": ["valid", "invalid"], "provider": [item["value"]]})
        assert item["count"] == expected, item


def test_facet_values_do_not_collapse_when_one_is_chosen(filled):
    """Выбрав страну, владелец обязан видеть остальные — иначе выбор необратим."""
    chosen = {"groups": ["valid", "invalid"], "country": ["США"]}
    values = filled.facet_values(filters=chosen)
    countries = {item["value"] for item in values["country"]}
    assert len(countries) > 1, countries
    # А вот другая грань считается уже с учётом выбранной страны.
    providers = values["provider"]
    assert providers
    for item in providers:
        expected = filled.matching_count(
            filters={"groups": ["valid", "invalid"], "country": ["США"],
                     "provider": [item["value"]]})
        assert item["count"] == expected, item


def test_facet_values_respect_the_verdict(filled):
    only_valid = filled.facet_values(filters={"groups": ["valid"]})
    for item in only_valid["country"]:
        expected = filled.matching_count(
            filters={"groups": ["valid"], "country": [item["value"]]})
        assert item["count"] == expected


# ────────────────────────────────────────────────────────── speed

BIG = 200_000


@pytest.fixture(scope="module")
def big_store():
    """Двести тысяч строк — тот масштаб, на котором перебор уже виден."""
    store = ResultStore()
    for i in range(BIG):
        store.append(
            "user%06d@%s" % (i, DOMAINS[i % 4]), "Valid", "250 OK", "mx",
            {"engagement_score": (i % 10) * 10,
             "country": COUNTRIES[i % 4], "gender": GENDERS[i % 3]})
    store.matching_count(("valid",))     # дописать хвост пачки на диск
    yield store
    store.close()


def _timed(call):
    start = time.perf_counter()
    result = call()
    return result, time.perf_counter() - start


def test_speed_page_with_every_filter_is_fast(big_store):
    picked = {"groups": ["valid"], "country": ["США"], "gender": ["Мужской"],
              "provider": ["gmail.com"], "minScore": 50}
    rows, spent = _timed(lambda: big_store.page(filters=picked, page=1, size=100))
    assert rows, "фильтр не нашёл ничего — измерять нечего"
    # Порог с большим запасом: перебор двухсот тысяч строк по одной занимает
    # секунды, запрос по индексу — доли секунды.
    assert spent < 1.5, "страница с фильтрами заняла %.2f с" % spent


def test_speed_count_with_every_filter_is_fast(big_store):
    picked = {"groups": ["valid"], "country": ["Индия"], "minScore": 30}
    total, spent = _timed(lambda: big_store.matching_count(filters=picked))
    assert total > 0
    assert spent < 1.5, "счёт совпадений занял %.2f с" % spent


def test_speed_search_is_fast(big_store):
    rows, spent = _timed(lambda: big_store.page(
        filters={"groups": ["valid"], "search": "user000123"}, size=100))
    assert len(rows) == 1
    assert spent < 1.5, "поиск занял %.2f с" % spent


def test_speed_facet_values_are_fast(big_store):
    values, spent = _timed(lambda: big_store.facet_values(
        filters={"groups": ["valid"]}))
    assert values["provider"]
    assert spent < 2.0, "сбор значений фильтров занял %.2f с" % spent


def test_speed_positive_control_the_data_really_is_big(big_store):
    """Замеры выше ничего не стоят, если база на деле маленькая."""
    assert big_store.counts()["total"] == BIG


# ────────────────────────────────────────────────────────── разбор запроса

def test_normalize_accepts_both_spellings():
    picked = normalize_filters({"groups": ["valid"], "minScore": "70",
                                "country": "США", "provider": ["GMAIL.com"]})
    assert picked["groups"] == ("valid",)
    assert picked["min_score"] == 70
    assert picked["country"] == ["США"]
    assert picked["provider"] == ["gmail.com"]


def test_normalize_survives_junk():
    picked = normalize_filters({"minScore": "чепуха", "country": None,
                                "search": None})
    assert picked["min_score"] == 0
    assert picked["country"] == []
    assert picked["search"] == ""
