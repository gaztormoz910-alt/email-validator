# -*- coding: utf-8 -*-
import csv
import os

import pytest

from core.cleaner import EmailCleaner, strip_wrapping_junk
from core.disposable import is_disposable
from core.email_syntax import validate_email_syntax
from core.local_rules import IMPOSSIBLE, check_local_part
from core.streamer import StreamLoader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT = os.path.join(ROOT, "data", "owner_sample", "sample.csv")


def _path():
    return os.environ.get("VALIDATOR_OWNER_SAMPLE") or DEFAULT


needs_sample = pytest.mark.skipif(
    not os.path.exists(_path()),
    reason="кусочка баз владельца нет — он не в git, только на его машине")


@pytest.fixture(scope="module")
def rows():
    with open(_path(), encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def _load(raw):
    return [e for e, _ in StreamLoader([{"type": "text", "content": raw + "\n"}]).stream_emails()]


@needs_sample
def test_sample_has_enough_server_answers(rows):
    labels = [r["label"] for r in rows]
    assert labels.count("Valid") >= 100, "живых по ответу сервера слишком мало"
    assert labels.count("Invalid/Bounce") >= 30, "мёртвых по ответу сервера слишком мало"


@needs_sample
def test_no_offline_verdict_on_a_mailbox_the_server_accepted(rows):
    cleaner = EmailCleaner()
    buried = []
    for r in rows:
        if r["label"] != "Valid":
            continue
        loaded = _load(r["email"])
        cleaned = cleaner.clean_email(loaded[0]) if loaded else None
        if not cleaned:
            buried.append("%s: потерян на входе или в очистке" % r["email"])
            continue
        if not validate_email_syntax(cleaned):
            buried.append("%s: отвергнут синтаксисом" % cleaned)
        verdict, why = check_local_part(cleaned)
        if verdict == IMPOSSIBLE:
            buried.append("%s: правило провайдера — %s" % (cleaned, why))
        if is_disposable(cleaned):
            buried.append("%s: помечен одноразовым" % cleaned)
    assert not buried, "живые по ответу сервера ящики осуждены без сети (%d):\n  %s" % (
        len(buried), "\n  ".join(buried[:10]))


@needs_sample
def test_cleaning_never_moves_an_address_to_a_foreign_domain(rows):
    from core.filters import BLACKLIST_SENTINELS
    cleaner = EmailCleaner()
    known = set(BLACKLIST_SENTINELS) | set(cleaner.popular_domains)
    moved = []
    for r in rows:
        for e in _load(r["email"]):
            cleaned = cleaner.clean_email(e)
            if not cleaned:
                continue
            before = strip_wrapping_junk(e).rsplit("@", 1)[-1]
            after = cleaned.rsplit("@", 1)[-1]
            if after != before and not (before.startswith(after) and after in known):
                moved.append("%s -> %s" % (before, after))
    assert not moved, "очистка увела адреса на чужой домен (%d):\n  %s" % (
        len(moved), "\n  ".join(moved[:10]))


@needs_sample
def test_every_row_survives_the_input_and_cleaning(rows):
    cleaner = EmailCleaner()
    lost = []
    for r in rows:
        loaded = _load(r["email"])
        if not loaded or not any(cleaner.clean_email(e) for e in loaded):
            lost.append((r["email"][:60], r["label"]))
    labeled_lost = [x for x, label in lost if label]
    assert not labeled_lost, labeled_lost[:5]
    assert len(lost) <= len(rows) // 100, "потеряно строк: %d" % len(lost)
