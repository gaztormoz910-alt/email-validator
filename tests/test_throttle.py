# -*- coding: utf-8 -*-
"""Окно замирает, потому что браузер считает его невидимым.

Всё здесь получено ЗАМЕРОМ на живой странице, а не рассуждением. Владелец
четыре раза показывал одно и то же: после перехода на вкладку «Найденные
адреса» интерфейс перестаёт отвечать, «как будто идёт работа». Питон при
этом жив и отвечает за миллисекунды.

Замерено:

    document.visibilityState  = hidden
    тиков валидатора          = 9 за 8 секунд вместо 32
    тиков сбора               = 9 за 8 секунд вместо 16
    кадров requestAnimationFrame = 0 за 30 секунд
    ошибок                    = 0
    запрос к питону           = 3-5 мс

Механизм: браузер зажимает таймеры невидимой страницы до одного раза в
секунду и полностью останавливает отрисовку. Клики доходят, обработчики
срабатывают, картинка не меняется. Ни перехватчик ошибок, ни сторож тишины
такого не ловят — ошибки нет, а запросы идут.
"""
import io
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.crashlog as crashlog                                  # noqa: E402
from ui.webapp import (WEBVIEW_NO_THROTTLE, ValidatorApi,         # noqa: E402
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


# ══════════════════════════ T1: ключи запуска

def test_browser_args_disable_throttling():
    """Три ключа, и каждый выключает свою часть подавления."""
    environ = {}
    result = apply_no_throttle(environ)
    for flag in ("--disable-background-timer-throttling",
                 "--disable-renderer-backgrounding",
                 "--disable-backgrounding-occluded-windows"):
        assert flag in result, "нет ключа %s" % flag
    assert environ["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] == result


def test_browser_args_are_not_doubled():
    """Контроль: повторный запуск не удлиняет строку.

    Иначе при каждом старте переменная росла бы, и однажды перестала
    помещаться в окружение.
    """
    environ = {}
    first = apply_no_throttle(environ)
    second = apply_no_throttle(environ)
    assert first == second
    assert second.count("--disable-renderer-backgrounding") == 1


def test_browser_args_keep_what_the_owner_set():
    """Контроль: чужие ключи не затираются.

    Владелец мог задать свои — молча отменить его настройку хуже, чем не
    добавить свою.
    """
    environ = {"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS": "--host-rules=MAP * 127.0.0.1"}
    result = apply_no_throttle(environ)
    assert "--host-rules=MAP * 127.0.0.1" in result
    assert "--disable-renderer-backgrounding" in result


# ══════════════════════════ T2: ключи ставятся ДО запуска окна

def test_before_start_env_is_set_before_webview_import():
    """WebView2 читает переменную в момент создания движка.

    Выставленная позже, она уже ни на что не влияет — это самая частая
    ошибка при работе с этими ключами, и проверить порядок надо явно.
    """
    with io.open(os.path.join(ROOT, "ui", "webapp.py"), encoding="utf-8") as h:
        source = h.read()
    # Ищем по "def run(", а не по "def run():": у функции появился
    # параметр самопроверки, и точное совпадение перестало находиться.
    body = source[source.index("def run("):]
    body = body[:body.index("webview.start(")]
    assert "apply_no_throttle()" in body, "ключи не применяются при запуске"
    assert body.index("apply_no_throttle()") < body.index("import webview"), (
        "ключи ставятся ПОСЛЕ импорта webview — поздно")


# ══════════════════════════ T3: подавление названо вслух

def test_reports_throttling_from_the_watchdog():
    """О подавлении докладывает СТОРОЖ, сравнивая частоту запросов.

    Это единственный случай, который не ловит ничто другое: ошибки нет,
    запросы идут, программа исправна — а владелец видит замерший экран.

    Раньше доклад стоял в обработчике `visibilitychange` в app.js, и это
    была ложная тревога чистой воды: `hidden` наступает, когда окно свёрнуто
    или владелец переключился на другую программу. Замерено в
    data/crash.log — три записи за сутки, все три об этом, настоящих сбоев
    ноль; при следующем запуске они же давали красную строку «сбои за
    сутки». Признак подавления не в видимости, а в ЧАСТОТЕ: подавленная
    страница продолжает спрашивать, просто вчетверо реже.
    """
    with io.open(os.path.join(ROOT, "ui", "webapp.py"), encoding="utf-8") as h:
        источник = h.read()
    assert "SLOW_RATE" in источник, "нет порога частоты"
    assert "def check_rate" in источник, "нет проверки частоты"
    блок = источник[источник.index("def check_rate"):]
    блок = блок[:блок.index("\n    def ", 10)]
    assert "подавлен" in блок, "по записи не отличить подавление от ошибки"
    assert "rate" in блок


def test_reports_control_says_it_once(log):
    """Контроль: доклад идёт ОДИН раз, а не на каждую проверку частоты.

    Сторож смотрит темп постоянно; запись на каждый замер означала бы
    журнал из одних докладов.
    """
    with io.open(os.path.join(ROOT, "ui", "webapp.py"), encoding="utf-8") as h:
        источник = h.read()
    блок = источник[источник.index("def check_rate"):]
    блок = блок[:блок.index("\n    def ", 10)]
    assert "_throttle_said" in блок or "reported" in блок.lower(), (
        "нет защиты от повтора: доклад пойдёт на каждый замер")


def test_control_visibility_change_writes_nothing_to_the_log():
    """Контроль: сворачивание окна НЕ пишет в журнал ничего.

    Обратная сторона той же правки. Если сюда вернут запись, вернётся и
    красная строка при следующем запуске — та самая, на которую владелец
    жаловался трижды.
    """
    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    блок = app[app.index("function onVisibilityChange"):]
    блок = блок[:блок.index("\n}")]
    ветка = блок[:блок.index("return;")]
    # Ищем ВЫЗОВ, а не слово: в комментарии рядом объяснено, почему вызова
    # здесь больше нет, и наивный поиск по имени падал на этом объяснении.
    # Проверка, срабатывающая на собственный комментарий, ничего не охраняет.
    assert "reportClientCrash(" not in ветка, (
        "сворачивание окна снова пишется как сбой")
    assert "visibilityState" in блок


# ══════════════════════════ T4: возврат видимости догоняет состояние

def test_catches_up_when_visibility_returns():
    """Вернулась видимость — окно догоняет немедленно, а не через секунду."""
    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    block = app[app.index("function onVisibilityChange"):]
    block = block[:block.index("\n}")]
    for call in ("tick()", "parserTick()", "refreshRows(true)", "refreshFound(true)"):
        assert call in block, "при возврате не обновляется: %s" % call


def test_catches_up_control_does_nothing_while_hidden():
    """Контроль: пока страница скрыта, догонять нечего — и мы не пытаемся.

    Запросы со скрытой страницы всё равно зажаты, а лишние вызовы только
    добавят работы там, где её и так не успевают делать.
    """
    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    block = app[app.index("function onVisibilityChange"):]
    block = block[:block.index("\n}")]
    hidden = block[:block.index("return;")]
    assert "tick()" not in hidden, "догоняем на скрытой странице"


# ══════════════════════════ T5: сторож видит темп, а не только тишину

def test_watchdog_notices_a_throttled_window(log):
    """Окно, отвечающее намного реже обычного, попадает в журнал.

    Тишины тут не наступает никогда: подавленное окно шлёт запрос раз в
    секунду. Проверка по паузе такое пропускает полностью, и именно поэтому
    четыре захода подряд журнал оставался пуст.
    """
    api = ValidatorApi()
    guard = WindowWatchdog(api, check_every=5.0)

    now = 1000.0
    api.request_count = 100
    assert guard.check_rate(now=now) is False        # первый замер — точка отсчёта

    # За 10 секунд пришло 10 запросов = 1 в секунду вместо шести.
    api.request_count = 110
    assert guard.check_rate(now=now + 10) is True

    text = read(log)
    assert "намного реже" in text
    assert "невидимой" in text, "не названа причина"
    assert "1.0 запроса" in text, "не назван измеренный темп"


def test_watchdog_control_normal_rate_is_silent(log):
    """Контроль: окно в нормальном темпе сторож не трогает."""
    api = ValidatorApi()
    guard = WindowWatchdog(api, check_every=5.0)

    now = 1000.0
    api.request_count = 0
    guard.check_rate(now=now)
    api.request_count = 60                      # шесть в секунду — норма
    assert guard.check_rate(now=now + 10) is False
    assert not read(log)


def test_watchdog_control_silence_is_not_slowness(log):
    """Контроль: полная тишина — это ДРУГОЙ случай, и здесь она не считается.

    У неё своя проверка и своя формулировка. Смешав их, мы получили бы
    запись «отвечает вшестеро реже» про окно, которое не отвечает вовсе.
    """
    api = ValidatorApi()
    guard = WindowWatchdog(api, check_every=5.0)

    now = 1000.0
    api.request_count = 50
    guard.check_rate(now=now)
    assert guard.check_rate(now=now + 10) is False   # ни одного запроса
    assert not read(log)


def test_watchdog_control_says_it_once_per_episode(log):
    """Контроль: одно подавление — одна запись, а не по записи на проверку."""
    api = ValidatorApi()
    guard = WindowWatchdog(api, check_every=5.0)

    now = 1000.0
    api.request_count = 0
    guard.check_rate(now=now)
    for step in range(1, 5):
        api.request_count += 10                  # один запрос в секунду
        guard.check_rate(now=now + 10 * step)
    assert read(log).count("намного реже") == 1

    # Окно ожило и снова подавлено — это НОВЫЙ случай, его пишем.
    api.request_count += 100                     # десять в секунду
    guard.check_rate(now=now + 60)
    api.request_count += 10
    guard.check_rate(now=now + 70)
    assert read(log).count("намного реже") == 2


def test_watchdog_counter_grows_on_real_requests():
    """Счётчик растёт от НАСТОЯЩИХ запросов, а не только в тесте."""
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
