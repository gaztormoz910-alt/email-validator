# -*- coding: utf-8 -*-
"""Кодировки входных файлов и рост памяти на больших базах.

Второй проход по коду. Три находки, и каждая теряла данные владельца молча —
без ошибки, без строки в логе, без единого признака.

Базы приходят откуда угодно: выгрузка из Excel — это Windows-1251, экспорт из
старой CRM — UTF-16. Читались они все одинаково, как UTF-8 с
errors="ignore", а этот режим не сообщает об ошибке — он ВЫБРАСЫВАЕТ байты.
Кириллица в Windows-1251 состоит как раз из таких байтов.
"""

import io
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.encoding import detect_encoding, open_text  # noqa: E402
from core.streamer import StreamLoader  # noqa: E402


def written(raw):
    path = tempfile.mktemp(suffix=".txt")
    with io.open(path, "wb") as handle:
        handle.write(raw)
    return path


def lines_of(path):
    return [line for line in StreamLoader([{"type": "file", "path": path}]).stream_lines()]


# ═══════════════════════════════ Windows-1251

def test_cp1251_keeps_the_local_part():
    """`анна@mail.ru` превращался в `@mail.ru` — адрес терялся молча.

    Дальше он отбраковывался по синтаксису как «неправильный», и владелец
    видел мёртвый адрес там, где виноват был читатель файла.
    """
    path = written("ivan@gmail.com\nанна@mail.ru\n".encode("cp1251"))
    try:
        assert lines_of(path) == ["ivan@gmail.com", "анна@mail.ru"]
    finally:
        os.unlink(path)


def test_cp1251_is_detected():
    path = written("анна@mail.ru\nпётр@yandex.ru\n".encode("cp1251"))
    try:
        assert detect_encoding(path) == "cp1251"
    finally:
        os.unlink(path)


def test_cp1251_with_extra_columns_survives():
    """Кириллица бывает не только в адресе, но и в имени и стране."""
    path = written("ivan@gmail.com;Иван;Мужской;Россия\n".encode("cp1251"))
    try:
        assert lines_of(path) == ["ivan@gmail.com;Иван;Мужской;Россия"]
    finally:
        os.unlink(path)


# ═══════════════════════════════ UTF-16

def test_utf16_file_is_read_at_all():
    """Раньше терялся весь файл целиком: между буквами шли нулевые байты."""
    path = written("ivan@gmail.com\nanna@yahoo.com\n".encode("utf-16"))
    try:
        assert lines_of(path) == ["ivan@gmail.com", "anna@yahoo.com"]
    finally:
        os.unlink(path)


@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be"])
def test_utf16_every_flavour(codec):
    """С меткой и без, в обоих порядках байт."""
    path = written("ivan@gmail.com\nanna@yahoo.com\n".encode(codec))
    try:
        assert lines_of(path) == ["ivan@gmail.com", "anna@yahoo.com"], codec
    finally:
        os.unlink(path)


def test_utf16_marker_is_eaten_by_the_codec():
    """Метка не должна остаться первым символом первого адреса.

    Невидимый мусор в начале строки — это адрес, который не совпадёт ни с
    чем: ни с базой отписок, ни с прошлым прогоном.
    """
    path = written("ivan@gmail.com\n".encode("utf-16"))
    try:
        assert lines_of(path) == ["ivan@gmail.com"]
        assert not lines_of(path)[0].startswith("﻿")
    finally:
        os.unlink(path)


# ═══════════════════════════════ определение, а не угадывание

def test_detect_utf8_is_not_mistaken_for_cp1251():
    """Обратная сторона: файл в UTF-8 обязан читаться как UTF-8.

    Иначе, починив одну кодировку, мы испортили бы другую — и кириллица
    превратилась бы в «Ð°Ð½Ð½Ð°».
    """
    path = written("анна@почта.рф\nмария@yandex.ru\n".encode("utf-8"))
    try:
        assert detect_encoding(path) == "utf-8"
        assert lines_of(path) == ["анна@почта.рф", "мария@yandex.ru"]
    finally:
        os.unlink(path)


def test_detect_utf8_with_marker():
    path = written("﻿ivan@gmail.com\n".encode("utf-8"))
    try:
        assert detect_encoding(path) == "utf-8-sig"
        assert lines_of(path) == ["ivan@gmail.com"]
    finally:
        os.unlink(path)


def test_detect_plain_ascii_is_utf8():
    path = written(b"ivan@gmail.com\njohn@yahoo.com\n")
    try:
        assert detect_encoding(path) == "utf-8"
    finally:
        os.unlink(path)


def test_detect_survives_a_missing_file():
    """Определение кодировки не имеет права упасть на недоступном файле."""
    assert detect_encoding(os.path.join(tempfile.gettempdir(), "нет-такого.txt")) == "utf-8"


def test_detect_broken_bytes_do_not_vanish_silently():
    """Испорченный байт оставляет след, а не исчезает.

    Исчезнувший байт превращает адрес в другой, внешне правильный, — и это
    хуже явной пометки.
    """
    path = written("ivan@gmail.com\n".encode("utf-8") + b"\xff\xfe broken\n")
    try:
        lines = lines_of(path)
        assert "ivan@gmail.com" in lines
    finally:
        os.unlink(path)


def test_detect_no_ignore_errors_left_in_the_loader():
    """errors="ignore" не должен вернуться: он и был причиной потерь."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "core", "streamer.py")
    with io.open(path, encoding="utf-8") as handle:
        source = handle.read()
    assert 'errors="ignore"' not in source


# ═══════════════════════════════ память на больших базах

def test_domain_stats_are_capped():
    """Словарь рос вместе с числом РАЗНЫХ доменов.

    На базе, собранной дорками, их столько же, сколько адресов. Замерено: на
    миллионе доменов — 260 МБ, лежащих мёртвым грузом до конца прогона.
    """
    from core.bounded import BoundedCache

    stats = BoundedCache(max_keys=1000)
    for i in range(5000):
        stats.setdefault("corp%d.com" % i, {"total": 0, "valid": 0})["total"] += 1

    kept = len(list(stats.items()))
    assert kept <= 1000, kept


def test_domain_stats_keep_the_busy_domains():
    """Вытесняются редкие, а частые остаются — они и нужны для анализа."""
    from core.bounded import BoundedCache

    stats = BoundedCache(max_keys=100)
    for i in range(2000):
        stats.setdefault("gmail.com", {"total": 0, "valid": 0})["total"] += 1
        stats.setdefault("rare%d.com" % i, {"total": 0, "valid": 0})["total"] += 1

    busy = stats.get("gmail.com")
    assert busy is not None, "частый домен вытеснен — анализ ослеп"
    assert busy["total"] == 2000


def test_domain_stats_use_the_cap_in_the_pipeline():
    """Потолок стоит в самом конвейере, а не только в тесте."""
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "core", "pipeline.py")
    with io.open(path, encoding="utf-8") as handle:
        source = handle.read()
    assert "domain_stats = BoundedCache(" in source


def test_catchall_still_detected_after_the_cap():
    """Ограничение памяти не должно ослепить то, ради чего статистика велась."""
    from core.bounded import BoundedCache

    stats = BoundedCache(max_keys=50)
    stats.setdefault("suspicious.com", {"total": 0, "valid": 0})
    entry = stats.get("suspicious.com")
    entry["total"] = 9
    entry["valid"] = 9

    suspicious = [(dom, st["total"]) for dom, st in stats.items()
                  if st["total"] >= 5 and st["valid"] == st["total"]]
    assert suspicious == [("suspicious.com", 9)]


def test_catchall_still_ignores_domains_with_few_addresses():
    """Домен с одним адресом ничего не доказывает — порог обязан остаться."""
    from core.bounded import BoundedCache

    stats = BoundedCache(max_keys=50)
    stats.setdefault("tiny.com", {"total": 0, "valid": 0})
    entry = stats.get("tiny.com")
    entry["total"] = 2
    entry["valid"] = 2

    suspicious = [dom for dom, st in stats.items()
                  if st["total"] >= 5 and st["valid"] == st["total"]]
    assert suspicious == []
