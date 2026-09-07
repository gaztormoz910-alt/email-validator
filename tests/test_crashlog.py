# -*- coding: utf-8 -*-
"""Программа обязана рассказывать, как она сломалась.

Владелец дважды сказал «софт наебнулся», и оба раза причину назвать было
нечем: на диск не писалось ничего, а журнал событий Windows про поломку
ВНУТРИ процесса не знает, если процесс не рухнул целиком.

Здесь каждый перехватчик проверяется НАСТОЯЩИМ сбоем: поток, который правда
падает; метод моста, который правда бросает; окно, которое правда прислало
ошибку. Проверка «в коде есть слово except» доказывала бы только то, что
слово написано.
"""
import io
import json
import os
import subprocess
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.crashlog as crashlog                                  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@pytest.fixture
def log(tmp_path, monkeypatch):
    """Журнал во временной папке: настоящий data/crash.log трогать нельзя."""
    path = str(tmp_path / "crash.log")
    monkeypatch.setattr(crashlog, "CRASH_LOG_PATH", path)
    return path


def read(path):
    if not os.path.exists(path):
        return ""
    with io.open(path, encoding="utf-8") as handle:
        return handle.read()


# ══════════════════════════ C1: сам писатель

def test_writer_records_what_happened(log):
    """Время, вид, текст и полная трассировка — всё, что нужно для разбора."""
    try:
        raise ValueError("ящик не нашёлся")
    except ValueError as exc:
        assert crashlog.log_crash("рабочий поток", "Проверка сорвалась", exc,
                                  context="адрес user@corp.test") is True

    text = read(log)
    assert "рабочий поток" in text
    assert "Проверка сорвалась" in text
    assert "ValueError" in text and "ящик не нашёлся" in text
    assert "Traceback" in text, "без трассировки разбирать нечего"
    assert "адрес user@corp.test" in text
    assert time.strftime("%Y-%m-%d") in text, "нет даты — непонятно, когда"


def test_writer_never_raises_on_junk(log):
    """Мусор на входе не роняет журнал: его зовут из обработчиков аварий."""
    for kind, message, exc in ((None, None, None), (42, object(), "не исключение"),
                               ("вид", b"\xff\xfe", ValueError("x")),
                               ({}, [], KeyError("y"))):
        crashlog.log_crash(kind, message, exc)      # не должно бросить
    assert read(log), "при мусоре не записалось вообще ничего"


def test_writer_survives_unwritable_path(tmp_path, monkeypatch):
    """Некуда писать — возвращает False, но НЕ бросает.

    Диск полон, папка только на чтение, файл занят антивирусом: ни один из
    этих случаев не должен помешать проверке почты.
    """
    # Путь, у которого «папкой» оказывается файл — записать туда нельзя.
    blocker = tmp_path / "не-папка"
    blocker.write_text("я файл", encoding="utf-8")
    monkeypatch.setattr(crashlog, "CRASH_LOG_PATH", str(blocker / "crash.log"))
    assert crashlog.log_crash("вид", "текст", ValueError("x")) is False


def test_writer_trims_and_keeps_the_newest(log, monkeypatch):
    """Потолок работает, и после обрезки остаётся СВЕЖЕЕ, а не старое.

    Программа умеет сыпать одной ошибкой в цикле; без потолка такой журнал
    съест диск за ночь. Но обрезать надо старое: разбирают последний сбой.
    """
    monkeypatch.setattr(crashlog, "MAX_BYTES", 4000)
    crashlog.log_crash("вид", "САМАЯ-ПЕРВАЯ-ЗАПИСЬ")
    for i in range(200):
        crashlog.log_crash("вид", "запись номер %d" % i)
    crashlog.log_crash("вид", "САМАЯ-ПОСЛЕДНЯЯ-ЗАПИСЬ")

    text = read(log)
    assert len(text.encode("utf-8")) <= crashlog.MAX_BYTES * 1.2, "потолок не сработал"
    assert "САМАЯ-ПОСЛЕДНЯЯ-ЗАПИСЬ" in text, "выбросили свежее вместо старого"
    assert "САМАЯ-ПЕРВАЯ-ЗАПИСЬ" not in text, "старое не выброшено"
    assert text.lstrip().startswith(crashlog.SEPARATOR), (
        "файл начинается с середины записи — такую трассировку не прочесть")


# ══════════════════════════ C2: перехватчики потоков

@pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_hooks_catch_a_real_worker_thread_crash(log):
    """Поток, который ПРАВДА упал, попадает в журнал.

    Это главный случай: конвейер живёт в сотне потоков, и до этой правки
    падение любого из них не было видно нигде — поток тихо умирал, его
    адреса пропадали из выдачи, а счётчик их засчитывал.
    """
    previous_sys = sys.excepthook
    previous_thread = threading.excepthook
    crashlog._installed = False
    try:
        assert crashlog.install_hooks() is True

        def падающий():
            raise RuntimeError("прокси кончились посреди работы")

        worker = threading.Thread(target=падающий, name="проверка-адресов")
        worker.start()
        worker.join()

        text = read(log)
        assert "рабочий поток" in text
        assert "проверка-адресов" in text, "не сказано, КАКОЙ поток упал"
        assert "прокси кончились посреди работы" in text
        assert "RuntimeError" in text
    finally:
        sys.excepthook = previous_sys
        threading.excepthook = previous_thread
        crashlog._installed = False


@pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_hooks_ignore_a_normal_thread_stop(log):
    """Контроль: SystemExit в потоке — не авария, а просьба завершиться.

    Записывать его значит забить журнал штатными остановками, и настоящая
    авария утонет среди них.
    """
    previous_sys = sys.excepthook
    previous_thread = threading.excepthook
    crashlog._installed = False
    try:
        crashlog.install_hooks()
        worker = threading.Thread(target=lambda: (_ for _ in ()).throw(SystemExit))
        worker.start()
        worker.join()
        assert "SystemExit" not in read(log)
    finally:
        sys.excepthook = previous_sys
        threading.excepthook = previous_thread
        crashlog._installed = False


@pytest.mark.filterwarnings(
    "ignore::pytest.PytestUnhandledThreadExceptionWarning")
def test_hooks_keep_the_previous_handler(log):
    """Контроль: прежний перехватчик по-прежнему зовётся.

    При запуске из терминала трассировка в консоли читается быстрее файла,
    и терять её незачем.
    """
    previous_sys = sys.excepthook
    previous_thread = threading.excepthook
    crashlog._installed = False
    called = []
    try:
        threading.excepthook = lambda args: called.append(args.exc_type)
        crashlog.install_hooks()
        worker = threading.Thread(target=lambda: 1 / 0)
        worker.start()
        worker.join()
        assert called == [ZeroDivisionError], "прежний перехватчик потерян"
    finally:
        sys.excepthook = previous_sys
        threading.excepthook = previous_thread
        crashlog._installed = False


def test_hooks_are_installed_once(log):
    """Контроль: повторный вызов не наслаивает перехватчики друг на друга."""
    previous_sys = sys.excepthook
    previous_thread = threading.excepthook
    crashlog._installed = False
    try:
        assert crashlog.install_hooks() is True
        assert crashlog.install_hooks() is False
    finally:
        sys.excepthook = previous_sys
        threading.excepthook = previous_thread
        crashlog._installed = False


def test_hooks_are_armed_at_startup():
    """Перехватчики ставятся в main.py ДО импорта интерфейсов.

    Сбой при самой загрузке модулей тоже должен оставить след: именно он
    выглядит как «программа мигнула и закрылась».
    """
    with io.open(os.path.join(ROOT, "main.py"), encoding="utf-8") as handle:
        source = handle.read()
    assert "install_hooks" in source
    # Раньше сравнивалось с `def run_classic` — этой функции больше нет.
    # Смысл тот же: перехватчики обязаны стоять ДО функции, которая
    # поднимает окно, иначе сбой при загрузке модулей следа не оставит.
    assert source.index("install_hooks") < source.index("def run_web"), (
        "перехватчики ставятся позже загрузки интерфейса")


# ══════════════════════════ C3: мост

def test_bridge_records_a_failing_method(log):
    """Ошибка обработчика записывается, а не исчезает в ответе 500.

    Настоящий HTTP-запрос к настоящему мосту: до этой правки окно получало
    500, показывало пустоту и выглядело зависшим, а причина не попадала
    никуда.
    """
    import urllib.error
    import urllib.request

    from ui.webapp import start_api_server

    class Ломается:
        # Имена ASCII: они уходят в HTTP-путь, а кириллица там требует
        # процентного кодирования и к делу отношения не имеет.
        def boom(self, payload=None):
            raise ValueError("в обработчике всё плохо")

        def fine(self, payload=None):
            return {"ok": True}

    _server, port, token = start_api_server(Ломается())

    def позвать(method):
        request = urllib.request.Request(
            "http://127.0.0.1:%d/api/%s" % (port, method), data=b"{}",
            headers={"Content-Type": "application/json", "X-Token": token})
        return urllib.request.urlopen(request, timeout=5)

    assert json.loads(позвать("fine").read())["ok"] is True
    assert not read(log), "исправный метод что-то записал"

    with pytest.raises(urllib.error.HTTPError) as caught:
        позвать("boom")
    assert caught.value.code == 500

    text = read(log)
    assert "мост" in text
    assert "метод boom" in text, "не сказано, какой метод сломался"
    assert "в обработчике всё плохо" in text
    assert "Traceback" in text


# ══════════════════════════ C4: сбой в самом окне

def test_client_error_reaches_the_same_log(log):
    """Ошибка JS доезжает до того же файла, что и питоновская."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    result = api.client_error({
        "message": "Cannot read properties of null",
        "where": "app.js:1268",
        "stack": "at refreshFound (app.js:1268)",
    })
    assert result["ok"] is True
    text = read(log)
    assert "окно" in text
    assert "Cannot read properties of null" in text
    assert "app.js:1268" in text


def test_client_error_treats_the_payload_as_data(log):
    """Контроль: пришедшее из окна кладётся как ТЕКСТ и обрезается.

    Содержимое приходит из места, где выполняется наш же JavaScript. Оно
    записывается, а не исполняется, и не может раздуть файл одним запросом.
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.client_error({"message": "A" * 5000, "stack": "B" * 20000,
                      "where": {"не": "строка"}})
    text = read(log)
    assert "A" * 5000 not in text, "длина сообщения не ограничена"
    assert len(text) < 12000, "одна запись из окна раздула журнал"
    # Мусор вместо словаря не должен РОНЯТЬ метод — но и записывать нечего,
    # поэтому теперь он получает честный отказ, а не молчаливое согласие.
    # Раньше здесь подставлялось «Ошибка в окне», и в журнале владельца
    # скопилось двадцать таких записей без единого слова содержания.
    assert api.client_error("не словарь")["ok"] is False
    assert api.client_error(None)["ok"] is False


def test_client_error_is_wired_in_the_window():
    """В окне стоят оба перехватчика, и отчёт идёт мимо api().

    Мимо — намеренно: если сломан сам api(), сообщение об этом им же и не
    уедет.
    """
    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    assert 'addEventListener("error"' in app
    assert 'addEventListener("unhandledrejection"' in app
    body = app[app.index("function reportClientCrash"):]
    body = body[:body.index("\n}")]
    assert 'fetch("/api/client_error"' in body, "отчёт идёт через api()"
    assert "crashReports >= 20" in body, (
        "нет потолка: ошибка в тике повторяется дважды в секунду")


# ══════════════════════════ C5: незащищённый вызов закрыт

def test_guarded_refresh_found_no_longer_bare():
    """У refreshFound появился перехват, и он докладывает о сбое."""
    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    body = app[app.index("async function refreshFound"):]
    body = body[:body.index("\n}")]
    assert "try {" in body and "catch" in body, "вызов снова без перехвата"
    assert "reportClientCrash" in body, "перехватили и промолчали"


def test_guarded_control_every_tick_call_is_protected():
    """Контроль: в тике сбора не осталось ни одного голого await api().

    Именно асимметрия и была бедой: parser_state обёрнут с самого начала, а
    соседний вызов — нет.
    """
    import re

    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    tick = app[app.index("async function parserTick"):]
    tick = tick[:tick.index("\n/* ── обработчики второго экрана ── */")]
    for call in re.findall(r"await api\(\"(\w+)\"", tick):
        assert call == "parser_state", (
            "в тике голый вызов api(%r) без перехвата" % call)


# ══════════════════════════ C6: владелец узнаёт о сбое

def test_announce_tells_about_a_recent_crash(log):
    """При запуске программа сама говорит, что в прошлый раз сломалась."""
    from ui.webapp import ValidatorApi, _announce_past_crashes

    crashlog.log_crash("рабочий поток", "вчерашняя авария", ValueError("x"))

    api = ValidatorApi()
    said = _announce_past_crashes(api)
    assert said >= 1

    lines = " ".join(row["text"] for row in api.log_tail()["log"])
    # Формулировка сменилась намеренно: прежняя кричала «[DEAD] программа
    # сломалась» и перечисляла каждую запись красной строкой. У владельца
    # это дало красное полотно сразу после запуска — на месте, где ничего
    # не сломалось ПРЯМО СЕЙЧАС. Сообщение о прошлой аварии не должно
    # выглядеть как авария текущая.
    assert "сбо" in lines.lower(), "о сбое не сказано вовсе"
    assert crashlog.crash_log_path() in lines, "не сказано, ГДЕ смотреть"
    assert "[DEAD]" not in lines, "прошлая авария снова помечена как текущая"


def test_announce_stays_silent_when_all_is_well(log):
    """Контроль: без сбоев — ни слова.

    Строка «в прошлый раз всё сломалось» на каждом чистом запуске
    обесценила бы саму себя.
    """
    from ui.webapp import ValidatorApi, _announce_past_crashes

    api = ValidatorApi()
    assert _announce_past_crashes(api) == 0


def test_announce_ignores_an_ancient_crash(log):
    """Контроль: полугодовая запись к сегодняшнему запуску не относится."""
    from ui.webapp import ValidatorApi, _announce_past_crashes

    crashlog.log_crash("вид", "древняя авария")
    api = ValidatorApi()
    assert _announce_past_crashes(api, within_hours=0) == 0


# ══════════════════════════ C7: журнал не уезжает в репозиторий

def test_private_crash_log_is_ignored_by_git():
    """В трассировке лежат адреса из базы владельца — коммитить нельзя.

    Спрашиваем сам git, а не читаем .gitignore глазами: правило может быть
    написано и перекрыто следующей строкой.
    """
    target = os.path.join(ROOT, "data", "crash.log")
    result = subprocess.run(["git", "check-ignore", "-v", target],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode == 0, (
        "git готов закоммитить журнал сбоев: %s" % (result.stderr or "нет правила"))


def test_private_control_source_is_not_ignored():
    """Контроль: тот же вопрос про исходник git отвечает «нет».

    Иначе проверка выше доказывала бы, что игнорируется ВСЁ подряд.
    """
    target = os.path.join(ROOT, "core", "crashlog.py")
    result = subprocess.run(["git", "check-ignore", "-v", target],
                            cwd=ROOT, capture_output=True, text=True)
    assert result.returncode != 0, "исходники тоже игнорируются — правило слишком широкое"


# ══════════════════════════ C9: сторож ловит ТИШИНУ

def test_watchdog_reports_a_frozen_window(log):
    """Замершее окно попадает в журнал, хотя исключения не было вовсе.

    Это и есть случай владельца: интерфейс замирает, `window.onerror` не
    срабатывает никогда, ловить нечего — и журнал остаётся пустым. Тишину
    приходится замечать отдельно.
    """
    from ui.webapp import ValidatorApi, WindowWatchdog

    api = ValidatorApi()
    guard = WindowWatchdog(api, silence_seconds=20.0)

    # Окно отвечало полминуты назад и с тех пор молчит.
    api.last_seen_at = time.time() - 30
    assert guard.check_once() is True

    text = read(log)
    assert "перестало отвечать" in text
    assert "Питон при этом жив" in text, "не сказано, где искать причину"
    assert "последний раз окно отвечало" in text


def test_watchdog_stays_silent_while_the_window_answers(log):
    """Контроль: работающее окно сторож не трогает."""
    from ui.webapp import ValidatorApi, WindowWatchdog

    api = ValidatorApi()
    guard = WindowWatchdog(api, silence_seconds=20.0)
    api.last_seen_at = time.time()
    assert guard.check_once() is False
    assert not read(log)


def test_watchdog_says_nothing_before_the_first_request(log):
    """Контроль: пока окно ни разу не спрашивало, судить о тишине не по чему.

    Иначе каждый запуск начинался бы с записи «окно не отвечает» — за те
    полсекунды, что оно ещё не успело загрузиться.
    """
    from ui.webapp import ValidatorApi, WindowWatchdog

    api = ValidatorApi()
    assert api.last_seen_at == 0.0
    assert WindowWatchdog(api).check_once() is False
    assert not read(log)


def test_watchdog_records_one_entry_per_freeze(log):
    """Контроль: одна тишина — одна запись, а не по записи на проверку.

    Окно, замолчавшее на час, должно дать одну строку, а не четырнадцать
    тысяч: иначе журнал переполнится собственным нытьём и вытеснит причину.
    """
    from ui.webapp import ValidatorApi, WindowWatchdog

    api = ValidatorApi()
    guard = WindowWatchdog(api, silence_seconds=20.0)
    api.last_seen_at = time.time() - 30
    assert guard.check_once() is True
    for _ in range(5):
        assert guard.check_once() is False
    assert read(log).count("перестало отвечать") == 1

    # А когда окно ожило и замолчало снова — это НОВАЯ авария, и её пишем.
    api.last_seen_at = time.time()
    guard.check_once()
    api.last_seen_at = time.time() - 30
    assert guard.check_once() is True
    assert read(log).count("перестало отвечать") == 2


def test_watchdog_mark_is_set_by_ordinary_requests(log):
    """Отметка ставится на запросах, которые идут и так — без лишних.

    Живое окно спрашивает состояние четыре раза в секунду; заводить ради
    сторожа отдельный запрос значило бы удвоить трафик моста ни за чем.
    """
    import urllib.request

    from ui.webapp import ValidatorApi, start_api_server

    api = ValidatorApi()
    assert api.last_seen_at == 0.0
    _server, port, token = start_api_server(api)

    request = urllib.request.Request(
        "http://127.0.0.1:%d/api/state" % port, data=b"{}",
        headers={"Content-Type": "application/json", "X-Token": token})
    urllib.request.urlopen(request, timeout=5).read()

    assert api.last_seen_at > 0.0, "обычный запрос не отметил окно живым"


def test_client_error_keeps_the_details(log):
    """Ошибка окна больше не записывается пустой.

    Первая версия перехватчика поймала у владельца десять сбоев и записала
    все десять без единого слова: она верила, что у события есть message.
    Пустая запись стоит ровно столько же, сколько её отсутствие.
    """
    with io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8") as h:
        app = h.read()
    assert "function describe" in app, "нечем описать причину без message"
    for case in ('value instanceof Error', '"[object Object]"',
                 'тип ${typeof value}'):
        assert case in app, "не разобран случай: %s" % case
    # Ошибка загрузки ресурса не всплывает без фазы перехвата — без true
    # именно она и записывалась пустой.
    # Блок берём до СЛЕДУЮЩЕГО перехватчика, а не до первой закрывающей
    # скобки: внутри есть свои, и обрезка по ним отсекала полтела.
    listener = app[app.index('window.addEventListener("error"'):
                   app.index('window.addEventListener("unhandledrejection"')]
    assert "target.tagName" in listener, "ошибка загрузки ресурса снова без описания"
    assert "}, true)" in listener, (
        "перехватчик без фазы захвата не увидит ошибки загрузки ресурсов — "
        "именно они и записывались пустыми")
    assert "[ошибка JS]" in app and "[отказ обещания]" in app, (
        "по записи не отличить, какой перехватчик сработал")
