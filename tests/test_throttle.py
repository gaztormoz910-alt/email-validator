# -*- coding: utf-8 -*-
import io
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.crashlog as crashlog
from ui.webapp import (WEBVIEW_NO_THROTTLE, ValidatorApi,
                       WindowWatchdog, apply_no_throttle)

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


def test_browser_args_disable_throttling():
    environ = {}
    result = apply_no_throttle(environ)
    for flag in ("--disable-background-timer-throttling",
                 "--disable-renderer-backgrounding",
                 "--disable-backgrounding-occluded-windows"):
        assert flag in result, "нет ключа %s" % flag
    assert environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] == result


def test_browser_args_are_not_doubled():
    environ = {}
    first = apply_no_throttle(environ)
    second = apply_no_throttle(environ)
    assert first == second
    assert second.count("--disable-renderer-backgrounding") == 1


def test_browser_args_keep_what_the_owner_set():
    environ = {"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": "--host-rules=MAP * 127.0.0.1"}
    result = apply_no_throttle(environ)
    assert "--host-rules=MAP * 127.0.0.1" in result
    assert "--disable-renderer-backgrounding" in result


def test_before_start_env_is_set_before_webview_import():
    with io.open(os.path.join(ROOT, "ui", "webapp.py"), encoding="utf-8") as h:
        source = h.read()
    body = source[source.index("def run("):]
    body = body[:body.index("webview.start(")]
    assert "apply_no_throttle()" in body, "ключи не применяются при запуске"
    assert body.index("apply_no_throttle()") < body.index("import webview"), (
        "ключи ставятся ПОСЛЕ импорта webview — поздно")


def test_reports_throttling_from_the_watchdog():
    with io.open(os.path.join(ROOT, "ui", "webapp.py"), encoding="utf-8") as h:
        источник = h.read()
    assert "SLOW_RATE" in источник, "нет порога частоты"
    assert "def check_rate" in источник, "нет проверки частоты"
    блок = источник[источник.index("def check_rate"):]
    блок = блок[:блок.index("\n    def ", 10)]
    assert "подавлен" in блок, "по записи не отличить подавление от ошибки"
    assert "rate" in блок


def test_reports_control_says_it_once(log):
    with io.open(os.path.join(ROOT, "ui", "webapp.py"), encoding="utf-8") as h:
        источник = h.read()
    блок = источник[источник.index("def check_rate"):]
    блок = блок[:блок.index("\n    def ", 10)]
    assert "_throttle_said" in блок or "reported" in блок.lower(), (
        "нет защиты от повтора: доклад пойдёт на каждый замер")


def test_control_visibility_change_writes_nothing_to_the_log():
    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    блок = app[app.index("function onVisibilityChange"):]
    блок = блок[:блок.index("\n}")]
    ветка = блок[:блок.index("return;")]
    assert "reportClientCrash(" not in ветка, (
        "сворачивание окна снова пишется как сбой")
    assert "visibilityState" in блок


def test_catches_up_when_visibility_returns():
    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    block = app[app.index("function onVisibilityChange"):]
    block = block[:block.index("\n}")]
    for call in ("tick()", "parserTick()", "refreshRows(true)", "refreshFound(true)"):
        assert call in block, "при возврате не обновляется: %s" % call


def test_catches_up_control_does_nothing_while_hidden():
    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    block = app[app.index("function onVisibilityChange"):]
    block = block[:block.index("\n}")]
    hidden = block[:block.index("return;")]
    assert "tick()" not in hidden, "догоняем на скрытой странице"


def test_watchdog_notices_a_throttled_window(log):
    api = ValidatorApi()
    guard = WindowWatchdog(api, check_every=5.0)

    now = 1000.0
    api.request_count = 100
    assert guard.check_rate(now=now) is False

    api.request_count = 110
    assert guard.check_rate(now=now + 10) is True

    text = read(log)
    assert "намного реже" in text
    assert "невидимой" in text, "не названа причина"
    assert "1.0 запроса" in text, "не назван измеренный темп"


def test_watchdog_control_normal_rate_is_silent(log):
    api = ValidatorApi()
    guard = WindowWatchdog(api, check_every=5.0)

    now = 1000.0
    api.request_count = 0
    guard.check_rate(now=now)
    api.request_count = 60
    assert guard.check_rate(now=now + 10) is False
    assert not read(log)


def test_watchdog_control_silence_is_not_slowness(log):
    api = ValidatorApi()
    guard = WindowWatchdog(api, check_every=5.0)

    now = 1000.0
    api.request_count = 50
    guard.check_rate(now=now)
    assert guard.check_rate(now=now + 10) is False
    assert not read(log)


def test_watchdog_control_says_it_once_per_episode(log):
    api = ValidatorApi()
    guard = WindowWatchdog(api, check_every=5.0)

    now = 1000.0
    api.request_count = 0
    guard.check_rate(now=now)
    for step in range(1, 5):
        api.request_count += 10
        guard.check_rate(now=now + 10 * step)
    assert read(log).count("намного реже") == 1

    api.request_count += 100
    guard.check_rate(now=now + 60)
    api.request_count += 10
    guard.check_rate(now=now + 70)
    assert read(log).count("намного реже") == 2


def test_watchdog_counter_grows_on_real_requests():
    import urllib.request

    from ui.webapp import start_api_server

    api = ValidatorApi()
    assert api.request_count == 0
    _server, port, token = start_api_server(api)

    for _ in range(3):
        request = urllib.request.Request(
            "http://127.0.0.1:%d/api/state" % port, data=b"{}",
            headers={"Content-Type": "application/json", "X-Token": token})
        urllib.request.urlopen(request, timeout=5).read()

    assert api.request_count == 3, "счётчик не считает: %d" % api.request_count
