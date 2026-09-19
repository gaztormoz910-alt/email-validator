# -*- coding: utf-8 -*-
"""Догадка модели не выносит приговор, а факт о домене — выносит.

Владелец увидел в логе:

    [TRAP/DISPOSABLE] mkstring1104@gmail.com -> AI: Bot/Spam Pattern

и спросил: «тебе не кажется, что даже почта с бессмысленным набором букв
может быть валидной, если она реально по всем критериям проходит?»

Он прав, и это не вкусовщина. Модель обучена на СТРОКАХ, а не на ответах
почтовиков. Люди заводят почту с цифрами, аббревиатурами и транслитом, а у
Gmail есть ровно один способ узнать правду — спросить сервер, и он на такие
вопросы отвечает честно. Приговор без запроса — это ложный invalid, то есть
навсегда потерянный живой контакт.

Обратная сторона так же важна: совпадение с внешним списком одноразовых
доменов — это ФАКТ о домене, а не догадка о строке. Его вердикт остаётся.
Каждый тест здесь идёт парой, чтобы одна половина не была починена за счёт
другой.
"""
# Разрезанные модули читаются вместе с примесями: после разделения
# половина кода лежит не в исходном файле, и чтение одного файла
# сделало бы проверку зелёной по ошибке. См. tests/исходники.py.
from исходники import исходник_конвейера
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline import AI_SUSPICION_PENALTY  # noqa: E402


class FakeAI:
    """Модель, считающая подозрительным всё, что ей назвали."""

    def __init__(self, suspicious):
        self.suspicious = set(suspicious)

    def predict(self, email):
        return email in self.suspicious


def read_source():
    """Исходник ВСЕГО конвейера, включая примеси."""
    return исходник_конвейера()


# ──────────────────────────────────────────── вердикт

def test_verdict_ai_no_longer_emits_a_result():
    """Догадка модели больше не заканчивает обработку адреса.

    Признак прямой: рядом с меткой подозрения не должно быть ни отправки
    результата, ни выхода из функции — иначе адрес снова не дойдёт до
    сервера.
    """
    source = read_source()
    marker = 'data["ai_suspicious"] = True'
    assert marker in source, "метка подозрения исчезла из кода"

    start = source.index(marker)
    block = source[start:start + 400]
    assert "on_result" not in block, "догадка модели снова отправляет вердикт"
    assert "Bot/Spam Pattern" not in source, "старый вердикт модели вернулся"


def test_verdict_suspicion_lowers_the_score_without_killing_it():
    """Подозрение опускает оценку, но не обнуляет её.

    Обнулить — значит снова выдать догадку за приговор, только тише: ноль в
    колонке качества читается как «мёртв».
    """
    source = read_source()
    assert "AI_SUSPICION_PENALTY" in source
    assert AI_SUSPICION_PENALTY > 0
    # Ниже единицы не опускаем: ноль зарезервирован за доказанным Invalid.
    assert "max(1, score - AI_SUSPICION_PENALTY)" in source


def test_verdict_penalty_keeps_a_live_address_above_the_unproven():
    """Подозрительный живой адрес должен стоять выше всего недоказанного.

    Иначе сортировка по качеству ставила бы доказанный ящик ниже адреса, о
    котором вообще ничего не известно.
    """
    proven_live = 75            # обычный подтверждённый Gmail
    unproven = 40               # типичная оценка недоказанного
    assert proven_live - AI_SUSPICION_PENALTY > unproven, (
        "штраф слишком велик: доказанный ящик уйдёт ниже недоказанных")


def test_verdict_zero_score_is_left_alone():
    """Доказанный Invalid остаётся нулём: подозрение его не поднимает."""
    source = read_source()
    assert "if score else score" in source, \
        "нулевая оценка должна оставаться нулём, а не подниматься до единицы"


def test_verdict_suspicion_is_explained_to_the_owner():
    """Молчаливый штраф — это необъяснимое число в колонке качества."""
    source = read_source()
    assert 'data["ai_note"]' in source
    assert "вердикт от него" in source


# ──────────────────────────────────────────── одноразовые домены

def test_disposable_domain_still_gets_a_verdict():
    """Факт о домене вердикт ставит: tempmail.com — не догадка.

    Положительный контроль для проверки выше: если бы её чинили грубо, из
    кода исчезли бы оба случая сразу, и одноразовые домены поехали бы в
    рассылку.
    """
    source = read_source()
    # Результаты уходят через общую дверь _emit: она считает выданное
    # для инварианта «подано = выдано». Форма вызова другая, смысл тот же.
    assert 'self._emit(email, "Trap/Disposable", "Disposable Email Domain"' in source, \
        "вердикт по одноразовому домену пропал"


def test_disposable_external_list_still_gets_a_verdict():
    source = read_source()
    assert '"External Blacklist Match"' in source, \
        "вердикт по внешнему списку пропал"


def test_disposable_is_recognised_for_real():
    """Проверка не бумажная: детектор действительно ловит tempmail."""
    from core.disposable import is_disposable

    assert is_disposable("hacker@tempmail.com") is True
    # И не ловит обычный ящик — иначе «работает» означало бы «отвергает всё».
    assert is_disposable("mkstring1104@gmail.com") is False


def test_disposable_and_suspicion_are_different_paths():
    """Два случая не должны сойтись в одну ветку кода.

    Смешать их — значит либо хоронить живых по догадке, либо пропускать
    tempmail в рассылку. Проверяется, что метка подозрения и вердикт по
    домену стоят в разных местах.
    """
    source = read_source()
    suspicion = source.index('data["ai_suspicious"] = True')
    disposable = source.index('"Disposable Email Domain"')
    assert suspicion != disposable
    # Между ними должен лежать код, а не соседние строки одной ветки.
    assert abs(suspicion - disposable) > 200


# ──────────────────────────────────────────── поведение модели

def test_verdict_model_is_still_consulted():
    """Модель не выключена — она по-прежнему опрашивается.

    Без этого «починка» свелась бы к удалению функции целиком, а владелец
    просил не хоронить адреса, а не отказаться от сигнала.
    """
    source = read_source()
    assert "self.ai.predict(email)" in source


@pytest.mark.parametrize("email", [
    "mkstring1104@gmail.com",
    "xk3n9fj2q@gmail.com",
    "2700483djsleepy1985@gmail.com",
])
def test_verdict_machine_looking_names_are_not_verdicts_by_themselves(email):
    """Ни одно из этих имён само по себе не повод для приговора.

    Первое — из лога владельца, живой Gmail. Третье в его же прогоне
    оказалось мёртвым, но узнал это СЕРВЕР, а не модель: 550 в ответ на
    RCPT. Разница между ними видна только оттуда.
    """
    ai = FakeAI([email])
    assert ai.predict(email) is True
    # Мнение модели существует, но вердиктом не является: в коде за ним
    # больше не следует отправка результата.
    source = read_source()
    start = source.index('data["ai_suspicious"] = True')
    assert "return" not in source[start:start + 200]
