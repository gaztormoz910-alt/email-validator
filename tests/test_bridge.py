# -*- coding: utf-8 -*-
import io
import json
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.crashlog as crashlog
from ui.webapp import ValidatorApi, start_api_server

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def log(tmp_path, monkeypatch):
    path = str(tmp_path / "crash.log")
    monkeypatch.setattr(crashlog, "CRASH_LOG_PATH", path)
    return path


def read(path):
    if not os.path.exists(path):
        return ""
    with io.open(path, encoding="utf-8") as handle:
        return handle.read()


@pytest.fixture
def bridge():
    api = ValidatorApi()
    _server, port, token = start_api_server(api)
    return api, port, token


def raw_request(sock, port, token, method="state", body=b"{}"):
    head = (
        "POST /api/%s HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "X-Token: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "\r\n" % (method, port, token, len(body))
    ).encode("ascii")
    sock.sendall(head + body)

    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            return data
        data += chunk
    headers, _, rest = data.partition(b"\r\n\r\n")
    length = 0
    for line in headers.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    while len(rest) < length:
        chunk = sock.recv(4096)
        if not chunk:
            break
        rest += chunk
    return headers + b"\r\n\r\n" + rest


def test_keepalive_serves_many_requests_on_one_socket(bridge):
    _api, port, token = bridge
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        for number in range(5):
            answer = raw_request(sock, port, token)
            assert answer, "соединение закрылось после запроса %d" % number
            assert b"200 OK" in answer.split(b"\r\n")[0], answer[:80]
            assert b'"state"' in answer, "ответ пришёл пустым"
    finally:
        sock.close()


def test_keepalive_is_declared_in_the_answer(bridge):
    _api, port, token = bridge
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        answer = raw_request(sock, port, token)
        assert answer.startswith(b"HTTP/1.1"), answer[:40]
        assert b"Connection: close" not in answer, (
            "сервер просит закрыть соединение — keep-alive не работает")
    finally:
        sock.close()


def test_keepalive_control_one_socket_is_enough_for_many(bridge):
    _api, port, token = bridge
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        local_port = sock.getsockname()[1]
        for _ in range(20):
            assert raw_request(sock, port, token), "соединение оборвалось"
        assert sock.getsockname()[1] == local_port
    finally:
        sock.close()


def test_aborted_client_leaves_no_traceback(bridge, log, capfd):
    _api, port, token = bridge
    for _ in range(5):
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        head = (
            "POST /api/state HTTP/1.1\r\n"
            "Host: 127.0.0.1:%d\r\n"
            "X-Token: %s\r\n"
            "Content-Length: 2\r\n\r\n{}" % (port, token)
        ).encode("ascii")
        sock.sendall(head)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                        b"\x01\x00\x00\x00\x00\x00\x00\x00")
        sock.close()

    import time
    time.sleep(0.5)
    out, err = capfd.readouterr()
    both = out + err
    assert "ConnectionAbortedError" not in both, both[-400:]
    assert "Traceback" not in both, both[-400:]


def test_aborted_control_real_failure_still_recorded(bridge, log):
    import urllib.error
    import urllib.request

    api, port, token = bridge
    api.boom = lambda payload=None: 1 / 0

    request = urllib.request.Request(
        "http://127.0.0.1:%d/api/boom" % port, data=b"{}",
        headers={"Content-Type": "application/json", "X-Token": token})
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(request, timeout=5)

    text = read(log)
    assert "ZeroDivisionError" in text, "настоящая ошибка потерялась"
    assert "метод boom" in text


def test_announce_says_nothing_in_the_window(log):
    from ui.webapp import _announce_past_crashes

    crashlog.log_crash("рабочий поток", "вчерашняя авария", ValueError("x"))
    api = ValidatorApi()
    assert _announce_past_crashes(api) == 1

    rows = api.log_tail()["log"]
    assert rows == [], "в окне снова появилась строка: %r" % (rows,)


def crash_path_in(text):
    return crashlog.crash_log_path() in text


def test_announce_control_the_record_survives(log):
    from ui.webapp import _announce_past_crashes

    crashlog.log_crash("мост", "падение обработчика", ValueError("x"))
    api = ValidatorApi()
    assert _announce_past_crashes(api) >= 1
    assert crashlog.recent_crashes(within_hours=24), "запись о сбое потерялась"
    файл = io.open(crashlog.crash_log_path(), encoding="utf-8",
                   errors="replace").read()
    assert "падение обработчика" in файл, "запись есть, но не та"


def test_empty_record_is_not_written(log):
    assert crashlog.log_crash("окно", "") is False
    assert crashlog.log_crash("окно", None) is False
    assert crashlog.log_crash("окно", "   ") is False
    assert not read(log)


def test_empty_control_a_record_with_words_is_written(log):
    assert crashlog.log_crash("окно", "[ошибка JS] TypeError: x is null") is True
    assert "TypeError" in read(log)
    assert crashlog.log_crash("окно", "", ValueError("есть чем разбираться")) is True
    assert "есть чем разбираться" in read(log)


def test_empty_client_error_is_refused(log):
    api = ValidatorApi()
    assert api.client_error({"message": "", "where": "", "stack": ""})["ok"] is False
    assert api.client_error({})["ok"] is False
    assert not read(log)
    assert api.client_error({"message": "[отказ обещания] Error: боль"})["ok"] is True
    assert "боль" in read(log)


def test_still_works_methods_answer(bridge):
    import urllib.request

    _api, port, token = bridge
    for method in ("state", "parser_state", "sources"):
        request = urllib.request.Request(
            "http://127.0.0.1:%d/api/%s" % (port, method), data=b"{}",
            headers={"Content-Type": "application/json", "X-Token": token})
        answer = json.loads(urllib.request.urlopen(request, timeout=5).read())
        assert isinstance(answer, dict), method


def test_still_works_payload_arrives_whole(bridge):
    api, port, token = bridge
    api.echo = lambda payload=None: {"получено": (payload or {}).get("текст", "")}

    import urllib.request

    body = json.dumps({"текст": "проверка связи ЖЁЛТЫЙ"}).encode("utf-8")
    request = urllib.request.Request(
        "http://127.0.0.1:%d/api/echo" % port, data=body,
        headers={"Content-Type": "application/json", "X-Token": token})
    answer = json.loads(urllib.request.urlopen(request, timeout=5).read())
    assert answer["получено"] == "проверка связи ЖЁЛТЫЙ"


def test_still_works_token_is_checked(bridge):
    import urllib.error
    import urllib.request

    _api, port, _token = bridge
    request = urllib.request.Request(
        "http://127.0.0.1:%d/api/state" % port, data=b"{}",
        headers={"Content-Type": "application/json", "X-Token": "wrong-token"})
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request, timeout=5)
    assert caught.value.code == 403


def test_still_works_static_is_served(bridge):
    import urllib.request

    _api, port, _token = bridge
    body = urllib.request.urlopen(
        "http://127.0.0.1:%d/app.js" % port, timeout=5).read()
    assert b"function api" in body, "app.js отдан не целиком"
