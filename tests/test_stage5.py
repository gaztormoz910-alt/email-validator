import os

import pytest


def _load(tmp_path, text):
    from core.streamer import StreamLoader

    path = os.path.join(str(tmp_path), "in.txt")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text + "\n")
    return {email: data.get("name", "")
            for email, data in StreamLoader([{"type": "file", "path": path}]).stream_emails()}


def _rows(fmt, n=3):
    return "\n".join(fmt.format(i=i) for i in range(n))


@pytest.mark.parametrize("fmt, expected", [
    ('"Brenner, Olav" <ob{i}@corp.test>', "Olav Brenner"),
    ('Brenner, Olav <ob{i}@corp.test>', "Olav Brenner"),
    ('"Lund Haugen, Jr" <ob{i}@corp.test>', "Lund Haugen, Jr"),
    ('Olav, Brenner <ob{i}@corp.test>', "Olav Brenner"),
])
def test_comma_display_name_keeps_both_parts(tmp_path, fmt, expected):
    assert _load(tmp_path, _rows(fmt))["ob0@corp.test"] == expected


@pytest.mark.parametrize("fmt, expected", [
    ('"Olav Brenner" <ob{i}@corp.test>', "Olav Brenner"),
    ('Olav Brenner <ob{i}@corp.test>', "Olav Brenner"),
    ("Brenner,Olav,ob{i}@corp.test", "Brenner Olav"),
])
def test_control_display_names_without_reordering(tmp_path, fmt, expected):
    assert _load(tmp_path, _rows(fmt))["ob0@corp.test"] == expected


def test_comma_form_with_bad_address_is_not_invented(tmp_path):
    from core.streamer import _подпись_с_запятой

    assert _подпись_с_запятой('"Brenner, Olav" <not an address>') is None
    assert _подпись_с_запятой('"A, B, C" <ob@corp.test>') is None
    assert _подпись_с_запятой('id123, Olav <ob@corp.test>') is None


def _get(port, path):
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, resp.getheader("Content-Type") or "", resp.read()
    finally:
        conn.close()


@pytest.fixture
def bridge_port():
    from ui.webapp import ValidatorApi, start_api_server

    server, port, _token = start_api_server(ValidatorApi())
    yield port
    server.shutdown()


def test_favicon_is_served_without_token(bridge_port):
    status, ctype, body = _get(bridge_port, "/favicon.ico")
    assert status == 200
    assert ctype == "image/x-icon"
    assert body[:4] == b"\x00\x00\x01\x00"


def test_page_names_its_icon():
    from ui.webapp import WEB_DIR

    with open(os.path.join(WEB_DIR, "index.html"), encoding="utf-8") as handle:
        assert '<link rel="icon" href="/favicon.ico">' in handle.read()


@pytest.mark.parametrize("path", ["/", "/index.html", "/favicon.ico/../index.html"])
def test_control_page_still_needs_token(bridge_port, path):
    status, _ctype, body = _get(bridge_port, path)
    assert status == 403, body


@pytest.mark.parametrize("line", [
    '"*@gmail.com":"CEO"',
    '"*@gmail.com",CEO',
    'Moscow:"*@gmail.com"',
    '*@corp.test',
])
def test_wildcard_pattern_is_not_an_address_list(line):
    from core.input_guard import KIND_EMAIL, check_text

    assert not check_text("\n".join([line] * 3), KIND_EMAIL)["ok"]


@pytest.mark.parametrize("line", [
    'ml{i}@corp.test,"*@gmail.com"',
    '"Mira Lind":"ml{i}@corp.test"',
    'ml{i}@corp.test:CEO',
    'ml{i}%relay.test@corp.test',
])
def test_control_real_addresses_next_to_patterns_are_accepted(line):
    from core.input_guard import KIND_EMAIL, check_text

    assert check_text(_rows(line), KIND_EMAIL)["ok"]
