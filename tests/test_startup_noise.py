# -*- coding: utf-8 -*-
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.winnoise import (CHROMIUM_QUIET_FLAGS,
                           WEBVIEW_BUSY_HINT, WebViewReaper,
                           install_webview_noise_filter, quiet_chromium)

СТЕНА = (
    "WebView2 initialization failed with exception:\n "
    "(0x800700AA): Требуемый ресурс занят. (Исключение из HRESULT: 0x800700AA)\n\n"
    "   в System.Runtime.InteropServices.Marshal.ThrowExceptionForHRInternal(...)\n\n"
    "   в Microsoft.Web.WebView2.Core.CoreWebView2Environment.<...>d__21.MoveNext()\n\n"
    "--- Конец трассировка стека из предыдущего расположения ---\n\n"
    "   в System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\n"
)


class _Ловушка(logging.Handler):

    def __init__(self):
        logging.Handler.__init__(self)
        self.записи = []

    def emit(self, record):
        self.записи.append(record)

    @property
    def тексты(self):
        return [r.getMessage() for r in self.записи]


def _логгер(имя):
    logger = logging.getLogger(имя)
    logger.handlers = []
    logger.filters = []
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    ловушка = _Ловушка()
    logger.addHandler(ловушка)
    return logger, ловушка


def test_wall_becomes_one_readable_line():
    logger, ловушка = _логгер("тест.шум.стена")
    install_webview_noise_filter(logger_name="тест.шум.стена")
    logger.error(СТЕНА)

    assert len(ловушка.записи) == 1
    текст = ловушка.тексты[0]
    assert текст == WEBVIEW_BUSY_HINT, текст
    assert "System.Runtime" not in текст, "трассировка .NET просочилась"
    assert "\n" not in текст, "сообщение снова многострочное"


def test_wall_says_what_to_do_not_what_broke():
    assert "профил" in WEBVIEW_BUSY_HINT.lower()
    assert "прошлого запуска" in WEBVIEW_BUSY_HINT
    assert "запустите заново" in WEBVIEW_BUSY_HINT
    assert "0x800700AA" in WEBVIEW_BUSY_HINT


def test_wall_is_downgraded_from_error_to_warning():
    logger, ловушка = _логгер("тест.шум.уровень")
    install_webview_noise_filter(logger_name="тест.шум.уровень")
    logger.error(СТЕНА)
    assert ловушка.записи[0].levelno == logging.WARNING
    assert ловушка.записи[0].levelname == "WARNING"


def test_control_other_pywebview_messages_pass_through():
    logger, ловушка = _логгер("тест.шум.чужое")
    install_webview_noise_filter(logger_name="тест.шум.чужое")

    чужие = [
        "Using WinForms / EdgeChromium",
        "Window created",
        "Cannot load URL http://127.0.0.1:8000: соединение отвергнуто",
        "Renderer process crashed",
        "WebView2 runtime is not installed",
    ]
    for текст in чужие:
        logger.error(текст)

    assert ловушка.тексты == чужие, "фильтр съел чужое сообщение"


def test_control_a_different_init_failure_is_not_disguised():
    logger, ловушка = _логгер("тест.шум.другая")
    install_webview_noise_filter(logger_name="тест.шум.другая")
    logger.error("WebView2 initialization failed with exception:\n "
                 "(0x80070002): Не удается найти указанный файл.\n"
                 "   в Microsoft.Web.WebView2.Core...")

    текст = ловушка.тексты[0]
    assert текст != WEBVIEW_BUSY_HINT, "чужая причина выдана за нашу"
    assert "0x80070002" in текст, "исходная причина потеряна"
    assert "System" not in текст, "трассировка всё-таки просочилась"


def test_control_filter_is_installed_once():
    logger, ловушка = _логгер("тест.шум.дубль")
    первый = install_webview_noise_filter(logger_name="тест.шум.дубль")
    второй = install_webview_noise_filter(logger_name="тест.шум.дубль")
    assert первый is второй
    assert len(logger.filters) == 1
    logger.error(СТЕНА)
    assert len(ловушка.записи) == 1


def test_control_hint_reaches_the_window_log():
    сказано = []
    logger, _ = _логгер("тест.шум.окно")
    install_webview_noise_filter(on_hint=сказано.append,
                                 logger_name="тест.шум.окно")
    logger.error(СТЕНА)
    assert сказано == [WEBVIEW_BUSY_HINT]


def test_control_broken_record_does_not_crash_the_filter():
    logger, ловушка = _логгер("тест.шум.мусор")
    install_webview_noise_filter(logger_name="тест.шум.мусор")
    logger.error("%s %s", "мало")
    assert len(ловушка.записи) == 1


def test_chromium_log_level_is_added():
    окружение = {}
    quiet_chromium(окружение)
    assert CHROMIUM_QUIET_FLAGS in окружение[
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"]


def test_control_chromium_flag_does_not_erase_the_others():
    окружение = {"WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS":
                 "--disable-background-timer-throttling --foo"}
    quiet_chromium(окружение)
    итог = окружение["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"]
    assert "--disable-background-timer-throttling" in итог
    assert "--foo" in итог
    assert CHROMIUM_QUIET_FLAGS in итог


def test_control_chromium_flag_is_not_added_twice():
    окружение = {}
    quiet_chromium(окружение)
    quiet_chromium(окружение)
    итог = окружение["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"]
    assert итог.count(CHROMIUM_QUIET_FLAGS) == 1


class _Проц(object):

    def __init__(self, pid, упрямый=False):
        self.pid = pid
        self.упрямый = упрямый
        self.terminated = False
        self.killed = False

    def terminate(self):
        self.terminated = True

    def kill(self):
        self.killed = True


def test_reaper_kills_only_what_this_run_started():
    reaper = WebViewReaper()
    чужие = {100, 101}
    reaper._живые = staticmethod(lambda: чужие)
    assert reaper.snapshot() == 2

    reaper._живые = staticmethod(lambda: чужие | {200, 201})

    убитые = []

    class _psutil(object):
        NoSuchProcess = Exception

        @staticmethod
        def Process(pid):
            proc = _Проц(pid)
            убитые.append(proc)
            return proc

        @staticmethod
        def wait_procs(procs, timeout=None):
            return procs, []

    sys.modules["psutil"] = _psutil
    try:
        снято = reaper.reap()
    finally:
        del sys.modules["psutil"]

    assert снято == 2, снято
    assert sorted(p.pid for p in убитые) == [200, 201], \
        "тронуты чужие процессы: %s" % [p.pid for p in убитые]
    assert all(p.terminated for p in убитые)


def test_reaper_finishes_off_the_stubborn():
    reaper = WebViewReaper()
    reaper._живые = staticmethod(lambda: set())
    reaper.snapshot()
    reaper._живые = staticmethod(lambda: {300})

    упрямый = _Проц(300)

    class _psutil(object):
        @staticmethod
        def Process(pid):
            return упрямый

        @staticmethod
        def wait_procs(procs, timeout=None):
            return [], list(procs)

    sys.modules["psutil"] = _psutil
    try:
        reaper.reap()
    finally:
        del sys.modules["psutil"]

    assert упрямый.terminated and упрямый.killed


def test_control_reaper_with_nothing_new_does_nothing():
    reaper = WebViewReaper()
    reaper._живые = staticmethod(lambda: {100})
    reaper.snapshot()

    class _psutil(object):
        @staticmethod
        def Process(pid):
            raise AssertionError("тронут чужой процесс %s" % pid)

    sys.modules["psutil"] = _psutil
    try:
        assert reaper.reap() == 0
    finally:
        del sys.modules["psutil"]


def test_control_reaper_survives_without_psutil():
    reaper = WebViewReaper()
    сохранён = sys.modules.get("psutil")
    sys.modules["psutil"] = None
    try:
        сколько = reaper.snapshot()
        assert isinstance(сколько, int), "снимок обязан вернуть число"
        if sys.platform == "win32":
            assert isinstance(reaper.до, set)
        else:
            assert сколько == 0, "без psutil вне Windows переписи нет"
        assert reaper.reap() == 0
    finally:
        if сохранён is None:
            del sys.modules["psutil"]
        else:
            sys.modules["psutil"] = сохранён


def test_window_start_wires_snapshot_before_and_reap_after():
    import io as _io
    источник = _io.open(
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "ui", "webapp.py"), encoding="utf-8").read()
    снимок = источник.index("reaper.snapshot()")
    старт = источник.index("webview.start(")
    уборка = источник.index("reaper.reap()")
    assert снимок < старт < уборка, "порядок нарушен"
    assert "finally:" in источник[старт - 200:уборка], "уборка не в finally"
