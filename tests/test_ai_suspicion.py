# -*- coding: utf-8 -*-
from исходники import исходник_конвейера
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline import AI_SUSPICION_PENALTY


class FakeAI:

    def __init__(self, suspicious):
        self.suspicious = set(suspicious)

    def predict(self, email):
        return email in self.suspicious


def read_source():
    return исходник_конвейера()


def test_verdict_ai_no_longer_emits_a_result():
    source = read_source()
    marker = 'data["ai_suspicious"] = True'
    assert marker in source, "метка подозрения исчезла из кода"

    start = source.index(marker)
    block = source[start:start + 400]
    assert "on_result" not in block, "догадка модели снова отправляет вердикт"
    assert "Bot/Spam Pattern" not in source, "старый вердикт модели вернулся"


def test_verdict_suspicion_lowers_the_score_without_killing_it():
    source = read_source()
    assert "AI_SUSPICION_PENALTY" in source
    assert AI_SUSPICION_PENALTY > 0
    assert "max(1, score - AI_SUSPICION_PENALTY)" in source


def test_verdict_penalty_keeps_a_live_address_above_the_unproven():
    proven_live = 75
    unproven = 40
    assert proven_live - AI_SUSPICION_PENALTY > unproven, (
        "штраф слишком велик: доказанный ящик уйдёт ниже недоказанных")


def test_verdict_zero_score_is_left_alone():
    source = read_source()
    assert "if score else score" in source, \
        "нулевая оценка должна оставаться нулём, а не подниматься до единицы"


def test_verdict_suspicion_is_explained_to_the_owner():
    source = read_source()
    assert 'data["ai_note"]' in source
    assert "вердикт от него" in source


def test_disposable_domain_still_gets_a_verdict():
    source = read_source()
    assert 'self._emit(email, "Trap/Disposable", "Disposable Email Domain"' in source, \
        "вердикт по одноразовому домену пропал"


def test_disposable_external_list_still_gets_a_verdict():
    source = read_source()
    assert '"External Blacklist Match"' in source, \
        "вердикт по внешнему списку пропал"


def test_disposable_is_recognised_for_real():
    from core.disposable import is_disposable

    assert is_disposable("hacker@tempmail.com") is True
    assert is_disposable("zkstring2207@gmail.com") is False


def test_disposable_and_suspicion_are_different_paths():
    source = read_source()
    suspicion = source.index('data["ai_suspicious"] = True')
    disposable = source.index('"Disposable Email Domain"')
    assert suspicion != disposable
    assert abs(suspicion - disposable) > 200


def test_verdict_model_is_still_consulted():
    source = read_source()
    assert "self.ai.predict(email)" in source


@pytest.mark.parametrize("email", [
    "zkstring2207@gmail.com",
    "xk3n9fj2q@gmail.com",
    "4810276djdreamy1979@gmail.com",
])
def test_verdict_machine_looking_names_are_not_verdicts_by_themselves(email):
    ai = FakeAI([email])
    assert ai.predict(email) is True
    source = read_source()
    start = source.index('data["ai_suspicious"] = True')
    assert "return" not in source[start:start + 200]
