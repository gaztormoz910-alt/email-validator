# -*- coding: utf-8 -*-
import io
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.encoding import detect_encoding, open_text
from core.streamer import StreamLoader


def written(raw):
    path = tempfile.mktemp(suffix=".txt")
    with io.open(path, "wb") as handle:
        handle.write(raw)
    return path


def lines_of(path):
    return [line for line in StreamLoader([{"type": "file", "path": path}]).stream_lines()]


def test_cp1251_keeps_the_local_part():
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
    path = written("ivan@gmail.com;Иван;Мужской;Россия\n".encode("cp1251"))
    try:
        assert lines_of(path) == ["ivan@gmail.com;Иван;Мужской;Россия"]
    finally:
        os.unlink(path)


def test_utf16_file_is_read_at_all():
    path = written("ivan@gmail.com\nanna@yahoo.com\n".encode("utf-16"))
    try:
        assert lines_of(path) == ["ivan@gmail.com", "anna@yahoo.com"]
    finally:
        os.unlink(path)


@pytest.mark.parametrize("codec", ["utf-16", "utf-16-le", "utf-16-be"])
def test_utf16_every_flavour(codec):
    path = written("ivan@gmail.com\nanna@yahoo.com\n".encode(codec))
    try:
        assert lines_of(path) == ["ivan@gmail.com", "anna@yahoo.com"], codec
    finally:
        os.unlink(path)


def test_utf16_marker_is_eaten_by_the_codec():
    path = written("ivan@gmail.com\n".encode("utf-16"))
    try:
        assert lines_of(path) == ["ivan@gmail.com"]
        assert not lines_of(path)[0].startswith("﻿")
    finally:
        os.unlink(path)


def test_detect_utf8_is_not_mistaken_for_cp1251():
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
    assert detect_encoding(os.path.join(tempfile.gettempdir(), "нет-такого.txt")) == "utf-8"


def test_detect_broken_bytes_do_not_vanish_silently():
    path = written("ivan@gmail.com\n".encode("utf-8") + b"\xff\xfe broken\n")
    try:
        lines = lines_of(path)
        assert "ivan@gmail.com" in lines
    finally:
        os.unlink(path)


def test_detect_no_ignore_errors_left_in_the_loader():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "core", "streamer.py")
    with io.open(path, encoding="utf-8") as handle:
        source = handle.read()
    assert 'errors="ignore"' not in source


def test_domain_stats_are_capped():
    from core.bounded import BoundedCache

    stats = BoundedCache(max_keys=1000)
    for i in range(5000):
        stats.setdefault("corp%d.com" % i, {"total": 0, "valid": 0})["total"] += 1

    kept = len(list(stats.items()))
    assert kept <= 1000, kept


def test_domain_stats_keep_the_busy_domains():
    from core.bounded import BoundedCache

    stats = BoundedCache(max_keys=100)
    for i in range(2000):
        stats.setdefault("gmail.com", {"total": 0, "valid": 0})["total"] += 1
        stats.setdefault("rare%d.com" % i, {"total": 0, "valid": 0})["total"] += 1

    busy = stats.get("gmail.com")
    assert busy is not None, "частый домен вытеснен — анализ ослеп"
    assert busy["total"] == 2000


def test_domain_stats_use_the_cap_in_the_pipeline():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "core", "pipeline.py")
    with io.open(path, encoding="utf-8") as handle:
        source = handle.read()
    assert "domain_stats = BoundedCache(" in source


def test_catchall_still_detected_after_the_cap():
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
    from core.bounded import BoundedCache

    stats = BoundedCache(max_keys=50)
    stats.setdefault("tiny.com", {"total": 0, "valid": 0})
    entry = stats.get("tiny.com")
    entry["total"] = 2
    entry["valid"] = 2

    suspicious = [dom for dom, st in stats.items()
                  if st["total"] >= 5 and st["valid"] == st["total"]]
    assert suspicious == []
