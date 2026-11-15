# -*- coding: utf-8 -*-
"""Досетевая часть на кусочке баз владельца с ОТВЕТАМИ НАСТОЯЩИХ СЕРВЕРОВ.

Кусочек (15.11.2026): 624 строки. 300 из них — адреса, по которым почтовый
сервер уже ответил в прошлых прогонах (225 «ящик есть», 75 «ящика нет»), это
эталон. Остальные — случайные строки из двух его баз и тестовой базы, без
эталона: на них проверяется, что вход и очистка никого не теряют и не
переносят на чужой домен.

Что здесь сторожится. Сеть не нужна: всё, что программа решает ДО первого
запроса к серверу, не имеет права похоронить ящик, который сервер признал
живым. Такой приговор — самая дорогая ошибка валидатора: контакт
выбрасывается навсегда, и никакой перепроверки уже не будет.

Первый же прогон нашёл дефект: «…@gmail.com.regarde» (слово прилипло после
адреса) очистка превращала в чужой домен «gmail.com.re». Закрыт правкой
_почтовик_с_меткой в core/cleaner.py.

Файл кусочка — данные чужих людей, в git его нет: data/owner_sample/ в
.gitignore. Без файла (CI, чужая копия) тесты честно пропускаются. Путь можно
переопределить переменной окружения VALIDATOR_OWNER_SAMPLE.
"""
import csv
import os

import pytest

from core.cleaner import EmailCleaner, strip_wrapping_junk
from core.disposable import is_disposable
from core.email_syntax import validate_email_syntax
from core.local_rules import IMPOSSIBLE, check_local_part
from core.streamer import StreamLoader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Путь внутри проекта, а не на машине владельца: сведений о нём он не несёт.
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
    """Контроль: без эталона проверки ниже ничего бы не значили."""
    labels = [r["label"] for r in rows]
    assert labels.count("Valid") >= 100, "живых по ответу сервера слишком мало"
    assert labels.count("Invalid/Bounce") >= 30, "мёртвых по ответу сервера слишком мало"


@needs_sample
def test_no_offline_verdict_on_a_mailbox_the_server_accepted(rows):
    """Сервер сказал 250 — значит без сети хоронить этот ящик нельзя ничем."""
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
    """Домен остаётся собой или чинится до почтовика, стоящего в его начале.

    `gmail.comopened` -> `gmail.com` — починка склейки, это законно.
    `gmail.com.regarde` -> `gmail.com.re` — чужой домен, этого быть не должно.
    """
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
    """Ни одна строка не роняет вход и не исчезает без следа."""
    cleaner = EmailCleaner()
    lost = []
    for r in rows:
        loaded = _load(r["email"])
        if not loaded or not any(cleaner.clean_email(e) for e in loaded):
            lost.append((r["email"][:60], r["label"]))
    # Без эталона бывают обрывки самих файлов (адрес с многоточием посреди
    # домена) — им законно не во что очиститься. С ответом сервера — ни одного.
    labeled_lost = [x for x, label in lost if label]
    assert not labeled_lost, labeled_lost[:5]
    assert len(lost) <= len(rows) // 100, "потеряно строк: %d" % len(lost)
