import logging
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.winnoise as winnoise
from core import timing

ПРЕРВАНО = ("WebView2 initialization failed with exception:\n "
            "(0x80004004): Операция прервана (Исключение из HRESULT: 0x80004004 (E_ABORT))\n"
            "   в Microsoft.Web.WebView2.Core...")


class _Ловушка(logging.Handler):
    def __init__(self):
        logging.Handler.__init__(self)
        self.записи = []

    def emit(self, record):
        self.записи.append(record)


def _логгер(имя):
    logger = logging.getLogger(имя)
    logger.handlers, logger.filters, logger.propagate = [], [], False
    logger.setLevel(logging.DEBUG)
    ловушка = _Ловушка()
    logger.addHandler(ловушка)
    return logger, ловушка


@pytest.fixture(autouse=True)
def _не_закрывается(monkeypatch):
    monkeypatch.setattr(winnoise, "_закрывается", False)


def test_abort_after_close_is_a_note_not_an_error():
    logger, ловушка = _логгер("тест.чисто.закрыто")
    подсказки = []
    winnoise.install_webview_noise_filter(on_hint=подсказки.append,
                                          logger_name="тест.чисто.закрыто")
    winnoise.отметить_закрытие()
    logger.error(ПРЕРВАНО)
    запись = ловушка.записи[0]
    assert запись.levelno == logging.INFO
    assert запись.getMessage() == winnoise.ЗАКРЫТО_ДО_ЗАПУСКА
    assert подсказки == []


def test_control_abort_without_close_is_still_a_warning():
    logger, ловушка = _логгер("тест.чисто.открыто")
    подсказки = []
    winnoise.install_webview_noise_filter(on_hint=подсказки.append,
                                          logger_name="тест.чисто.открыто")
    logger.error(ПРЕРВАНО)
    запись = ловушка.записи[0]
    assert запись.levelno == logging.WARNING
    assert "0x80004004" in запись.getMessage()
    assert len(подсказки) == 1


def test_control_other_failure_after_close_is_not_hidden():
    logger, ловушка = _логгер("тест.чисто.другое")
    winnoise.install_webview_noise_filter(logger_name="тест.чисто.другое")
    winnoise.отметить_закрытие()
    logger.error("WebView2 initialization failed with exception:\n "
                 "(0x80070002): Не удается найти указанный файл.")
    assert ловушка.записи[0].levelno == logging.WARNING
    assert "0x80070002" in ловушка.записи[0].getMessage()


class _Событие:
    def __init__(self, было):
        self.было = было

    def wait(self, предел):
        return self.было


class _События:
    def __init__(self, shown, loaded):
        self.shown, self.loaded = _Событие(shown), _Событие(loaded)


@pytest.fixture
def замер(monkeypatch):
    monkeypatch.setattr(timing, "_отметки", [("перед webview.start", 1.0)])
    monkeypatch.setattr(timing, "_начало", 0.0)


@pytest.mark.parametrize("shown, loaded, причина", [
    (False, True, "окно показалось"),
    (True, False, "страница загрузилась"),
])
def test_timing_fails_when_window_or_page_never_comes(tmp_path, замер, shown, loaded, причина):
    провал = timing.дождаться_окна(_События(shown, loaded), показ=1, страница=1)
    assert причина in провал
    путь = str(tmp_path / "t.txt")
    timing.записать(путь, провал)
    текст = open(путь, encoding="utf-8").read()
    assert "TIMING_FAILED" in текст and "TIMING_OK" not in текст


def test_control_timing_ok_when_page_loaded(tmp_path, замер):
    провал = timing.дождаться_окна(_События(True, True))
    assert провал == ""
    assert [имя for имя, _ in timing._отметки][1:] == ["окно показалось", "страница загрузилась"]
    путь = str(tmp_path / "t.txt")
    timing.записать(путь, провал)
    assert open(путь, encoding="utf-8").read().rstrip().endswith("TIMING_OK")


def test_window_close_is_wired_to_the_filter():
    import inspect

    from ui import webapp
    исходник = inspect.getsource(webapp.run)
    assert "window.events.closing += отметить_закрытие" in исходник
    assert "дождаться_окна(window.events)" in исходник
