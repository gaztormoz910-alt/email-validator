# -*- coding: utf-8 -*-
"""Мост между окном и питоном: соединения, обрывы, шум в логе.

Всё здесь найдено на машине владельца измерением, а не чтением кода:

* мост говорил HTTP/1.0, то есть открывал НОВОЕ TCP-соединение на каждый
  запрос. При шести запросах в секунду и выдержке TIME_WAIT в четыре минуты
  замерено 923 занятых порта на 127.0.0.1 из 16384 доступных;
* обрыв со стороны браузера печатал в консоль полную трассировку
  `ConnectionAbortedError [WinError 10053]` — на месте, где ничего не
  сломалось;
* объявление о прошлых сбоях кричало «[DEAD]» и перечисляло записи, в
  которых не было ни одного слова.

Проверки здесь ведут себя как настоящий клиент: открывают сокет, шлют
запросы, считают соединения. Чтение констант доказывало бы, что константа
написана, а не что она работает.
"""
import io
import json
import os
import socket
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.crashlog as crashlog                                  # noqa: E402
from ui.webapp import ValidatorApi, start_api_server               # noqa: E402

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
    """Настоящий мост на настоящем порту."""
    api = ValidatorApi()
    _server, port, token = start_api_server(api)
    return api, port, token


def raw_request(sock, port, token, method="state", body=b"{}"):
    """Один HTTP-запрос в УЖЕ ОТКРЫТЫЙ сокет. Возвращает ответ целиком."""
    head = (
        "POST /api/%s HTTP/1.1\r\n"
        "Host: 127.0.0.1:%d\r\n"
        "X-Token: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n"
        "\r\n" % (method, port, token, len(body))
    ).encode("ascii")
    sock.sendall(head + body)

    # Читаем ровно один ответ: заголовки, затем тело по Content-Length.
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


# ══════════════════════════ B1: одно соединение на много запросов

def test_keepalive_serves_many_requests_on_one_socket(bridge):
    """Пять запросов в ОДИН сокет — пять ответов.

    Это и есть разница между HTTP/1.0 и HTTP/1.1, и проверять её надо
    поведением: при HTTP/1.0 сервер закрывает соединение после первого
    ответа, и второй запрос уходит в пустоту.
    """
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
    """И сервер честно называет версию: HTTP/1.1, а не 1.0."""
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
    """Контроль: двадцать запросов НЕ открывают двадцать соединений.

    Ради этого всё и делалось: при шести запросах в секунду старый мост жёг
    по шесть портов в секунду, и каждый Windows держал ещё четыре минуты.
    """
    _api, port, token = bridge
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        local_port = sock.getsockname()[1]
        for _ in range(20):
            assert raw_request(sock, port, token), "соединение оборвалось"
        # Порт на нашей стороне не менялся — значит соединение было одно.
        assert sock.getsockname()[1] == local_port
    finally:
        sock.close()


# ══════════════════════════ B2: обрыв клиента — не авария

def test_aborted_client_leaves_no_traceback(bridge, log, capfd):
    """Браузер ушёл, не дочитав ответ, — сервер молчит.

    Так ведёт себя всякая страница при перезагрузке и при уходе с неё. Раньше
    на это в консоль печаталась полная трассировка WinError 10053, и владелец
    видел красное полотно там, где ничего не сломалось.
    """
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
        # Рвём связь сразу, не читая ответ, — как делает браузер.
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
    """Контроль: настоящая ошибка обработчика по-прежнему записывается.

    Глушить надо ТОЛЬКО обрыв связи. Если заодно замолчали и настоящие
    поломки, лечение хуже болезни.
    """
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


# ══════════════════════════ B3: объявление не кричит

def test_announce_says_nothing_in_the_window(log):
    """О ПРОШЛОЙ аварии в окне не сообщается вовсе.

    ПУТЬ ЭТОГО ТРЕБОВАНИЯ. Сначала было красное полотно, потом одна спокойная
    строка с меткой INFO, теперь — тишина. 11.09.2026 владелец сказал прямо:
    «не надо мне лишние логи отображать». Сообщение о ВЧЕРАШНЕЙ аварии
    встречало его на пустом месте, когда прямо сейчас ничего не сломалось, и
    сделать с ним он всё равно ничего не мог.

    Проверка не удалена, а перевёрнута: раньше сторожила формулировку, теперь
    сторожит отсутствие строки при сохранной записи на диске.
    """
    from ui.webapp import _announce_past_crashes

    crashlog.log_crash("рабочий поток", "вчерашняя авария", ValueError("x"))
    api = ValidatorApi()
    # Считает — значит запись видит. Пустое окно не оттого, что искать нечего.
    assert _announce_past_crashes(api) == 1

    rows = api.log_tail()["log"]
    assert rows == [], "в окне снова появилась строка: %r" % (rows,)


def crash_path_in(text):
    return crashlog.crash_log_path() in text


def test_announce_control_the_record_survives(log):
    """Контроль: тишина в окне — не потеря улики.

    Если бы вместе с выводом исчезла и запись на диске, разбирать аварию
    стало бы нечем, а сторож превратился бы в украшение.
    """
    from ui.webapp import _announce_past_crashes

    crashlog.log_crash("мост", "падение обработчика", ValueError("x"))
    api = ValidatorApi()
    assert _announce_past_crashes(api) >= 1
    assert crashlog.recent_crashes(within_hours=24), "запись о сбое потерялась"
    # Сверяем по САМОМУ ФАЙЛУ: recent_crashes отдаёт только заголовки записей,
    # и по ним не видно, та ли это авария.
    файл = io.open(crashlog.crash_log_path(), encoding="utf-8",
                   errors="replace").read()
    assert "падение обработчика" in файл, "запись есть, но не та"


# ══════════════════════════ B4: пустых записей не бывает

def test_empty_record_is_not_written(log):
    """Сбой без единого слова описания в журнал не попадает.

    У владельца скопилось двадцать записей «Ошибка в окне» без деталей:
    место занято, разобрать нельзя, а программа о них ещё и докладывала.
    Пустая улика хуже отсутствия улики.
    """
    assert crashlog.log_crash("окно", "") is False
    assert crashlog.log_crash("окно", None) is False
    assert crashlog.log_crash("окно", "   ") is False
    assert not read(log)


def test_empty_control_a_record_with_words_is_written(log):
    """Контроль: запись с содержанием пишется как раньше."""
    assert crashlog.log_crash("окно", "[ошибка JS] TypeError: x is null") is True
    assert "TypeError" in read(log)
    # И запись без текста, но С ИСКЛЮЧЕНИЕМ — тоже: трассировка и есть
    # содержание.
    assert crashlog.log_crash("окно", "", ValueError("есть чем разбираться")) is True
    assert "есть чем разбираться" in read(log)


def test_empty_client_error_is_refused(log):
    """И окно получает отказ, а не молчаливое согласие."""
    api = ValidatorApi()
    assert api.client_error({"message": "", "where": "", "stack": ""})["ok"] is False
    assert api.client_error({})["ok"] is False
    assert not read(log)
    # А с содержанием — принимается.
    assert api.client_error({"message": "[отказ обещания] Error: боль"})["ok"] is True
    assert "боль" in read(log)


# ══════════════════════════ B5: мост не сломан

def test_still_works_methods_answer(bridge):
    """Обычные вызовы отвечают как раньше."""
    import urllib.request

    _api, port, token = bridge
    for method in ("state", "parser_state", "sources"):
        request = urllib.request.Request(
            "http://127.0.0.1:%d/api/%s" % (port, method), data=b"{}",
            headers={"Content-Type": "application/json", "X-Token": token})
        answer = json.loads(urllib.request.urlopen(request, timeout=5).read())
        assert isinstance(answer, dict), method


def test_still_works_payload_arrives_whole(bridge):
    """Тело запроса доезжает целиком — включая кириллицу.

    Проверка не праздная: именно потеря тела дала бы пустые записи, а
    keep-alive меняет то, как сервер читает поток.
    """
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
    """Контроль: чужой без токена по-прежнему не проходит.

    Мост слушает петлевой адрес, но на машине могут работать другие
    программы, и открывать им базу адресов незачем.
    """
    import urllib.error
    import urllib.request

    _api, port, _token = bridge
    request = urllib.request.Request(
        "http://127.0.0.1:%d/api/state" % port, data=b"{}",
        # Токен латиницей: в заголовки HTTP кириллица не помещается по
        # стандарту, и падало бы здесь, а не на самой проверке доступа.
        headers={"Content-Type": "application/json", "X-Token": "wrong-token"})
    with pytest.raises(urllib.error.HTTPError) as caught:
        urllib.request.urlopen(request, timeout=5)
    assert caught.value.code == 403


def test_still_works_static_is_served(bridge):
    """Оформление отдаётся и не требует токена — иначе окно не нарисуется."""
    import urllib.request

    _api, port, _token = bridge
    body = urllib.request.urlopen(
        "http://127.0.0.1:%d/app.js" % port, timeout=5).read()
    assert b"function api" in body, "app.js отдан не целиком"
