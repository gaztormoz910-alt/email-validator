# -*- coding: utf-8 -*-
import os

import pytest

from core.input_guard import KIND_DORK, KIND_EMAIL, check_text


def _rows(fmt, n=5):
    return "\n".join(fmt.format(i=i) for i in range(n))


@pytest.mark.parametrize("text", [
    'Full Name,Email Address\nAnna Bell,anna.bell@corp.test',
    '"Full Name","Email Address"\n"Anna Bell","anna.bell@corp.test"',
    'E-mail Address\nanna.bell@corp.test',
])
def test_header_with_a_space_and_one_contact_is_accepted(text):
    assert check_text(text, KIND_EMAIL)["ok"]


@pytest.mark.parametrize("fmt", [
    'user{i}@corp.test,"Link: acme{i}.test"',
    '"Mira Lind {i}","user{i}@corp.test","Link: acme{i}.test"',
    'user{i}@corp.test,site:acme{i}.test',
])
def test_note_column_with_an_operator_word_is_accepted(fmt):
    assert check_text(_rows(fmt), KIND_EMAIL)["ok"]


@pytest.mark.parametrize("fmt", [
    '"Mira Lind {i}":"user{i}@corp.test"',
    '"user{i}@corp.test" : "Mira Lind {i}"',
])
def test_quoted_fields_joined_by_colon_are_accepted(fmt):
    assert check_text(_rows(fmt), KIND_EMAIL)["ok"]


@pytest.mark.parametrize("text", [
    _rows('"@gmail.com" "CEO {i}"'),
    _rows('site:linkedin.com "@gmail.com" {i}'),
    _rows('"@gmail.com",site:acme{i}.test'),
    'First Name,Email Address',
    _rows('buy cheap shoes {i}'),
])
def test_control_queries_and_bare_header_are_still_refused_as_emails(text):
    assert not check_text(text, KIND_EMAIL)["ok"]


def test_control_query_field_still_takes_queries():
    assert check_text(_rows('site:linkedin.com "@gmail.com" {i}'), KIND_DORK)["ok"]


def _load(tmp_path, text):
    from core.streamer import StreamLoader

    path = os.path.join(str(tmp_path), "in.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")
    return {email: data.get("name", "")
            for email, data in StreamLoader([{"type": "file", "path": path}]).stream_emails()}


def test_quoted_csv_name_loses_its_quotes(tmp_path):
    names = _load(tmp_path, _rows('"Mira Lind {i}","user{i}@corp.test"', 3))
    assert names["user0@corp.test"] == "Mira Lind 0"


def test_note_key_value_is_not_a_name(tmp_path):
    names = _load(tmp_path, _rows('"Mira Lind {i}","user{i}@corp.test","Notes: VIP"', 3))
    assert names["user0@corp.test"] == "Mira Lind 0"
    names = _load(tmp_path, _rows('user{i}@corp.test,"Link: acme{i}.test"', 3))
    assert names["user0@corp.test"] == ""


@pytest.mark.parametrize("text, email, expected", [
    (_rows('Gregorio "Greg" Ruiz,u{i}@corp.test', 3), "u0@corp.test", 'Gregorio "Greg" Ruiz'),
    (_rows("O'Brien,Sean,u{i}@corp.test", 3), "u0@corp.test", "O'Brien Sean"),
])
def test_control_names_inside_quotes_are_untouched(tmp_path, text, email, expected):
    assert _load(tmp_path, text)[email] == expected
