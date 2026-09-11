# -*- coding: utf-8 -*-
"""Красная стена при запуске: её нет, а настоящая ошибка осталась.

Владелец жаловался трижды. Замерено запуском, а не чтением кода:

    с сиротами:  2.4с | [pywebview] WebView2 initialization failed
                 2.4с | (0x800700AA): Требуемый ресурс занят
                 2.4с | ...семь строк трассировки .NET...
    без сирот:   ни одной строки при старте

Причина: программа оставляет после себя процессы msedgewebview2 (насчитано
шесть от прошлого запуска). Они держат папку профиля, и следующий запуск
получает «ресурс занят».

Главная проверка в этом файле — НЕ «стало тихо». Тихо сделать легко и
опасно: глушилка, съедающая всё, прячет настоящую поломку, и владелец
узнаёт о ней по последствиям. Поэтому рядом с каждой проверкой тишины стоит
проверка, что чужие сообщения проходят насквозь.
"""
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.winnoise import (CHROMIUM_QUIET_FLAGS,      # noqa: E402
                           WEBVIEW_BUSY_HINT, WebViewReaper,
                           install_webview_noise_filter, quiet_chromium)

# Ровно то, что pywebview кладёт в logger.error — см. его edgechromium.py:270.
СТЕНА = (
    "WebView2 initialization failed with exception:\n "
    "(0x800700AA): Требуемый ресурс занят. (Исключение из HRESULT: 0x800700AA)\n\n"
    "   в System.Runtime.InteropServices.Marshal.ThrowExceptionForHRInternal(...)\n\n"
    "   в Microsoft.Web.WebView2.Core.CoreWebView2Environment.<...>d__21.MoveNext()\n\n"
    "--- Конец трассировка стека из предыдущего расположения ---\n\n"
    "   в System.Runtime.ExceptionServices.ExceptionDispatchInfo.Throw()\n"
)


class _Ловушка(logging.Handler):
    """Собирает то, что дошло до вывода после фильтра."""

    def __init__(self):
        logging.Handler.__init__(self)
        self.записи = []

    def emit(self, record):
        self.записи.append(record)

    @property
    def тексты(self):
        return [r.getMessage() for r in self.записи]


def _логгер(имя):
    """Изолированный логгер: общий 'pywebview' переживал бы между тестами."""
    logger = logging.getLogger(имя)
    logger.handlers = []
    logger.filters = []
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    ловушка = _Ловушка()
    logger.addHandler(ловушка)
    return logger, ловушка


# ══════════════════════════ стена заменена одной строкой ════════════════

def test_wall_becomes_one_readable_line():
    """Девять строк трассировки .NET превращаются в одну по-русски."""
    logger, ловушка = _логгер("тест.шум.стена")
    install_webview_noise_filter(logger_name="тест.шум.стена")
    logger.error(СТЕНА)

    assert len(ловушка.записи) == 1
    текст = ловушка.тексты[0]
    assert текст == WEBVIEW_BUSY_HINT, текст
    assert "System.Runtime" not in текст, "трассировка .NET просочилась"
    assert "\n" not in текст, "сообщение снова многострочное"


def test_wall_says_what_to_do_not_what_broke():
    """В строке есть причина и действие, а не имя исключения.

    Владельцу от «ThrowExceptionForHRInternal» пользы ноль. Ему нужно знать,
    что окно откроется и что делать, если поведёт себя странно.
    """
    assert "профил" in WEBVIEW_BUSY_HINT.lower()
    assert "прошлого запуска" in WEBVIEW_BUSY_HINT
    assert "запустите заново" in WEBVIEW_BUSY_HINT
    # Код оставлен для поиска, но в скобках и в конце.
    assert "0x800700AA" in WEBVIEW_BUSY_HINT


def test_wall_is_downgraded_from_error_to_warning():
    """Уровень понижается: это не поломка, окно после неё работает."""
    logger, ловушка = _логгер("тест.шум.уровень")
    install_webview_noise_filter(logger_name="тест.шум.уровень")
    logger.error(СТЕНА)
    assert ловушка.записи[0].levelno == logging.WARNING
    assert ловушка.записи[0].levelname == "WARNING"


# ══════════════════════════ КОНТРОЛЬ: чужое проходит ════════════════════

def test_control_other_pywebview_messages_pass_through():
    """Всё остальное pywebview печатает как раньше, слово в слово.

    Это главная проверка файла. Сделать тихо легко — и опасно: глушилка,
    съедающая всё подряд, прячет настоящую поломку, и владелец узнаёт о ней
    по последствиям, а не из лога.
    """
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
    """Другая причина падения показывается своей, а не «ресурс занят».

    Подставить одну заготовленную строку под ЛЮБОЙ отказ значит соврать:
    отсутствующий рантайм WebView2 лечится установкой, а не перезапуском.
    """
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
    """Повторная установка не плодит копий.

    Иначе одно сообщение размножилось бы на столько строк, сколько раз
    вызвали, — и вместо стены владелец получил бы эхо.
    """
    logger, ловушка = _логгер("тест.шум.дубль")
    первый = install_webview_noise_filter(logger_name="тест.шум.дубль")
    второй = install_webview_noise_filter(logger_name="тест.шум.дубль")
    assert первый is второй
    assert len(logger.filters) == 1
    logger.error(СТЕНА)
    assert len(ловушка.записи) == 1


def test_control_hint_reaches_the_window_log():
    """Строка доходит до лога ОКНА, а не только до консоли.

    Владелец запускает и через ярлык тоже: консоли перед глазами может не
    быть вовсе.
    """
    сказано = []
    logger, _ = _логгер("тест.шум.окно")
    install_webview_noise_filter(on_hint=сказано.append,
                                 logger_name="тест.шум.окно")
    logger.error(СТЕНА)
    assert сказано == [WEBVIEW_BUSY_HINT]


def test_control_broken_record_does_not_crash_the_filter():
    """Запись, у которой не собирается текст, фильтр не роняет.

    Он стоит на пути КАЖДОГО сообщения pywebview: исключение отсюда убило бы
    логирование целиком.
    """
    logger, ловушка = _логгер("тест.шум.мусор")
    install_webview_noise_filter(logger_name="тест.шум.мусор")
    logger.error("%s %s", "мало")          # аргументов не хватает
    assert len(ловушка.записи) == 1        # запись прошла, фильтр выжил


# ══════════════════════════ тишина Chromium ═════════════════════════════

def test_chromium_log_level_is_added():
    """Chromium пишет в stderr мимо logging — его глушит только флаг."""
    окружение = {}
    quiet_chromium(окружение)
    assert CHROMIUM_QUIET_FLAGS in окружение[
        "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"]


def test_control_chromium_flag_does_not_erase_the_others():
    """Контроль: флаги против удушения фоновой страницы не затёрты.

    Они лежат в той же переменной. Затерев их, мы вернули бы поломку, на
    которую владелец жаловался отдельно.
    """
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


# ══════════════════════════ уборщик процессов ═══════════════════════════

class _Проц(object):
    """Процесс-пустышка: терминируется, считается, может заупрямиться."""

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
    """Снимаются процессы, появившиеся ПРИ нас. Чужие не трогаются.

    На машине владельца WebView2 крутится не только у нас — замерено, там же
    процессы Windows Search на том же движке. Снести их разом значит сломать
    чужую программу ради чистоты своей.
    """
    reaper = WebViewReaper()
    чужие = {100, 101}
    reaper._живые = staticmethod(lambda: чужие)
    assert reaper.snapshot() == 2

    # После запуска появились наши.
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
    """Не ушедший по-хорошему снимается принудительно.

    Именно уцелевший процесс и держит папку профиля — ради него всё и
    затевалось.
    """
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
            return [], list(procs)      # никто не ушёл

    sys.modules["psutil"] = _psutil
    try:
        reaper.reap()
    finally:
        del sys.modules["psutil"]

    assert упрямый.terminated and упрямый.killed


def test_control_reaper_with_nothing_new_does_nothing():
    """Контроль: когда своих процессов нет, не трогается никто."""
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
    """Без psutil уборщик не роняет закрытие программы.

    Он зовётся последним, когда работа уже сделана: исключение отсюда стало
    бы последним, что владелец увидит.

    ПРОВЕРКА ПЕРЕНАЦЕЛЕНА 12.09.2026. Раньше здесь стояло
    `assert reaper.snapshot() == 0` — то есть закреплялось, что без psutil
    уборщик СЛЕПОЙ. Это было правдой, пока перепись процессов шла через
    psutil, и стоило владельцу двадцати трёх секунд на каждом запуске: на его
    машине 4038 процессов, и psutil открывал их по одному.

    Теперь на Windows перепись делает один системный вызов, и psutil для неё
    не нужен вовсе. Требовать ноля значило бы требовать вернуть медленный
    способ обратно.
    """
    reaper = WebViewReaper()
    сохранён = sys.modules.get("psutil")
    sys.modules["psutil"] = None        # импорт даст ImportError
    try:
        сколько = reaper.snapshot()
        assert isinstance(сколько, int), "снимок обязан вернуть число"
        if sys.platform == "win32":
            # На Windows перепись psutil не нужна: она обязана работать.
            assert isinstance(reaper.до, set)
        else:
            assert сколько == 0, "без psutil вне Windows переписи нет"
        # Уборка без psutil молчит и не падает при любом раскладе.
        assert reaper.reap() == 0
    finally:
        if сохранён is None:
            del sys.modules["psutil"]
        else:
            sys.modules["psutil"] = сохранён


def test_window_start_wires_snapshot_before_and_reap_after():
    """Снимок делается ДО открытия окна, уборка — в finally.

    Порядок здесь и есть вся суть: снимок после старта не отличит наши
    процессы от чужих, а уборка вне finally не сработает при исключении.
    """
    import io as _io
    источник = _io.open(
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "ui", "webapp.py"), encoding="utf-8").read()
    снимок = источник.index("reaper.snapshot()")
    старт = источник.index("webview.start(")
    уборка = источник.index("reaper.reap()")
    assert снимок < старт < уборка, "порядок нарушен"
    assert "finally:" in источник[старт - 200:уборка], "уборка не в finally"
