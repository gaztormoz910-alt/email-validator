# -*- coding: utf-8 -*-
"""Скорость показа на большой базе — замером, а не на глаз.

Владелец спросил, можно ли грузить миллион и десять миллионов строк без
подвисаний. Отвечать на такое обещанием нельзя: подвисание — это цифра, и
цифру надо снять.

Что было найдено замером на миллионе результатов:

  * поиск адреса в базе      — 4.24 с. Причина: `LIKE '%иголка%'` начинается
    со звёздочки, индексом воспользоваться не может, и SQLite читал ВСЮ
    таблицу — 454 МБ. Всё это время хранилище под замком, то есть прогон стоит.
  * отбор по стране и полу   — 0.40 с. Причина: по одиночным индексам SQLite
    берёт ОДИН из них, а остальное проверяет перебором найденного.

Обе беды лечатся индексами, а НЕ урезанием смысла: поиск как искал вхождение,
так и ищет. Первое, что приходит в голову — искать только по началу строки, —
здесь отвергнуто сознательно: `xuser1@gmail.com` перестал бы находиться по
запросу «user1», и владелец даже не узнал бы, что что-то потерял.

Пороги в проверках взяты с большим запасом к замеру: тест должен ловить
возвращение полной перечитки таблицы, а не колебания машины.
"""

import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Столько строк хватает, чтобы разница между «по индексу» и «перебором всей
# таблицы» вылезла из шума, и при этом набор не превращается в долгий прогон.
ROWS = 60_000


@pytest.fixture(scope="module")
def store():
    from ui.result_store import ResultStore

    made = ResultStore()
    for i in range(ROWS):
        made.append(
            "user%d@gmail.com" % i, "Valid", "250 OK", "mx.google.com",
            {"gender": "Мужской" if i % 2 else "Женский",
             "country": "Россия" if i % 3 else "США",
             "engagement_score": 55 + (i % 40),
             "provider_name": "Gmail", "name": "Имя%d" % i})
    # Один адрес, у которого искомое лежит В СЕРЕДИНЕ, а не в начале: на нём
    # проверяется, что поиск остался поиском по вхождению.
    made.append("zzz-user1-tail@mail.ru", "Valid", "250 OK", "mx.mail.ru",
                {"country": "Россия", "engagement_score": 70})
    yield made
    made.close()


# Сколько раз повторять замер. Берём ЛУЧШЕЕ время, а не единственное.
#
# ПОЧЕМУ. Замерено 11.09.2026: страница поиска в чистом процессе занимает
# 0.027-0.032 с при пороге 0.5 — запас в шестнадцать раз. В полном наборе тот
# же вызов дал 0.578 с, и проверка покраснела. Мерила она при этом не поиск, а
# помехи: к моменту её запуска живы фоновые потоки предыдущих тестов.
#
# Лучшее из нескольких — это по-прежнему время НАШЕГО кода, просто без чужого
# шума. Пороги не тронуты: настоящее замедление даже в десять раз останется
# красным. Все замеряемые здесь действия — только чтение, поэтому повтор
# ничего не портит.
ПОВТОРОВ = 3


def took(fn, повторов=ПОВТОРОВ):
    лучшее = None
    result = None
    for _ in range(max(1, повторов)):
        started = time.monotonic()
        result = fn()
        прошло = time.monotonic() - started
        лучшее = прошло if лучшее is None else min(лучшее, прошло)
    return лучшее, result


def test_control_timer_still_sees_something_slow():
    """ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к замерщику.

    «Лучшее из трёх» не должно превратиться в «всегда быстро»: тогда все
    проверки скорости в этом файле стали бы пустыми и ничего не сторожили.
    """
    spent, _ = took(lambda: time.sleep(0.2), повторов=2)
    assert spent >= 0.2, spent


# ═══════════════════════════════ G1: поиск не читает всю таблицу

def test_search_by_full_address_is_fast(store):
    """Поиск конкретного адреса — самое частое действие владельца."""
    spent, found = took(lambda: store.matching_count(
        filters={"search": "user59999@gmail.com"}))
    assert found == 1
    assert spent < 0.5, "поиск занял %.2f с — похоже, снова читается вся таблица" % spent


def test_search_by_domain_is_fast(store):
    """«@mail.ru» — тоже вхождение, и тоже не повод перечитывать базу."""
    spent, found = took(lambda: store.matching_count(filters={"search": "@mail.ru"}))
    assert found == 1
    assert spent < 0.5, spent


def test_search_page_is_fast(store):
    """Страница результатов поиска, а не только счётчик."""
    spent, rows = took(lambda: store.page(page=1, size=100,
                                          filters={"search": "user5999"}))
    assert rows, "поиск ничего не нашёл — проверка ничего не меряет"
    assert spent < 0.5, spent


def test_search_uses_the_covering_index(store):
    """Замер может повезти на тёплом кэше — план запроса не врёт."""
    from ui.result_store import normalize_filters

    store._flush_locked()
    where, params = store._where(normalize_filters({"search": "user1"}))
    plan = store._conn.execute(
        "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM rows WHERE " + where, params
    ).fetchall()
    text = " ".join(str(row[-1]) for row in plan)
    assert "rows_grp_email" in text, text


# ═══════════════════════════════ G2: смысл поиска не изменился

def test_search_still_finds_a_match_in_the_middle(store):
    """Главная проверка всего файла.

    Быстрый поиск «по началу строки» был бы вдвое проще и ещё быстрее — и
    молча терял бы адреса, у которых искомое стоит не в начале. Такую цену за
    скорость платить нельзя: потеря была бы невидимой.
    """
    rows = store.page(page=1, size=100, filters={"search": "user1-tail"})
    assert [row["email"] for row in rows] == ["zzz-user1-tail@mail.ru"]


def test_search_finds_both_beginning_and_middle(store):
    """Один запрос обязан находить и то, и другое."""
    found = {row["email"] for row in
             store.page(page=1, size=500, filters={"search": "user1-"})}
    assert "zzz-user1-tail@mail.ru" in found


def test_search_is_case_insensitive(store):
    assert store.matching_count(filters={"search": "USER59999@GMAIL.COM"}) == 1


def test_search_does_not_match_everything(store):
    """Отрицательный контроль: несуществующая строка ничего не находит."""
    assert store.matching_count(filters={"search": "такого-адреса-нет"}) == 0


def test_search_escapes_wildcards(store):
    """`_` в запросе — это подчёркивание, а не «любой символ»."""
    assert store.matching_count(filters={"search": "user_9999@gmail.com"}) == 0


# ═══════════════════════════════ G3: отбор по граням

def test_facet_filter_is_fast(store):
    spent, found = took(lambda: store.matching_count(
        filters={"country": ["США"], "gender": ["Мужской"]}))
    assert found > 0
    assert spent < 0.5, spent


def test_facet_filter_with_score_is_fast(store):
    spent, found = took(lambda: store.matching_count(
        filters={"country": ["США"], "gender": ["Мужской"], "minScore": 80}))
    assert found > 0
    assert spent < 0.5, spent


def test_facet_filter_uses_the_composite_index(store):
    """План запроса: один индекс на все грани, а не один плюс перебор."""
    from ui.result_store import normalize_filters

    store._flush_locked()
    where, params = store._where(normalize_filters(
        {"country": ["США"], "gender": ["Мужской"]}))
    plan = store._conn.execute(
        "EXPLAIN QUERY PLAN SELECT COUNT(*) FROM rows WHERE " + where, params
    ).fetchall()
    text = " ".join(str(row[-1]) for row in plan)
    assert "rows_facets" in text, text


def test_facet_filter_counts_exactly(store):
    """Скорость не куплена ценой точности: считаем вручную и сверяем."""
    # США — это i % 3 == 0, Мужской — это i % 2 == 1.
    expected = sum(1 for i in range(ROWS) if i % 3 == 0 and i % 2 == 1)
    assert store.matching_count(
        filters={"country": ["США"], "gender": ["Мужской"]}) == expected


# ═══════════════════════════════ G4: показ не зависит от размера базы

def test_first_page_is_instant(store):
    spent, rows = took(lambda: store.page(page=1, size=100))
    assert len(rows) == 100
    assert spent < 0.2, spent


def test_counters_cost_nothing(store):
    spent, counts = took(lambda: store.counts())
    assert counts["total"] == ROWS + 1
    assert spent < 0.05, spent


def test_indexes_that_make_this_possible_exist(store):
    """Оба индекса заведены при создании базы, а не руками в тесте."""
    store._flush_locked()
    names = {row[0] for row in store._conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index'").fetchall()}
    assert "rows_grp_email" in names
    assert "rows_facets" in names
