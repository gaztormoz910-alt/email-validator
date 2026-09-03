# -*- coding: utf-8 -*-
"""Красная стена при запуске: причина и уборка за собой.

ЧТО ВИДЕЛ ВЛАДЕЛЕЦ. Через `python main.py` — девять красных строк на 2.4-й
секунде, до того как окно успело открыться:

    [pywebview] WebView2 initialization failed with exception:
      (0x800700AA): Требуемый ресурс занят. (Исключение из HRESULT: 0x800700AA)
       в System.Runtime.InteropServices.Marshal.ThrowExceptionForHRInternal(...)
       в Microsoft.Web.WebView2.Core.CoreWebView2Environment.<...>d__21.MoveNext()
       --- Конец трассировка стека из предыдущего расположения ---
       ... ещё четыре строки .NET ...

Окно при этом открывалось и работало. То есть красным кричало о том, что не
сломано, — а это хуже молчания: в следующий раз он не поверит и настоящей
ошибке.

ПРИЧИНА, ЗАМЕРЕННАЯ ЗАПУСКОМ, А НЕ ПРОЧТЁННАЯ В КОДЕ. Приложение оставляет
после себя процессы `msedgewebview2` — насчитано шесть штук от предыдущего
запуска. Они держат папку профиля WebView2, и следующий запуск получает
0x800700AA «требуемый ресурс занят». Проверено разницей: с сиротами — девять
красных строк, после их снятия — ни одной.

ПОЧЕМУ ДВЕ ЧАСТИ, А НЕ ОДНА. Убрать шум мало: молчащая программа с занятым
ресурсом будет стартовать медленнее и однажды не стартует вовсе. Убрать
сирот тоже мало: WebView2 умеет упасть и по другим причинам, и тогда стена
вернётся. Поэтому здесь и уборка причины, и честная формулировка вместо
трассировки.

ЧЕГО ЗДЕСЬ НЕТ НАМЕРЕННО: глобального гашения логов. Фильтр трогает ровно
одно сообщение, всё остальное pywebview печатает как раньше. Глушилка,
съедающая всё подряд, хуже красной стены — она прячет настоящую поломку.
"""

import logging
import os

__all__ = [
    "install_webview_noise_filter",
    "WebViewReaper",
    "CHROMIUM_QUIET_FLAGS",
    "WEBVIEW_BUSY_HINT",
]

# Chromium пишет своё в stderr сам, мимо logging Python:
#   [0903/222519:ERROR:ui\gfx\win\window_impl.cc:172] Failed to unregister
#   class Chrome_WidgetWin_0. Error = 1411
# Это уборка окна при закрытии; 1411 — «класс не зарегистрирован», то есть
# жалоба на то, что убирать уже нечего. Через logging его не поймать, зато
# уровень логов Chromium задаётся флагом: 3 — только фатальные.
CHROMIUM_QUIET_FLAGS = "--log-level=3"

# Что писать вместо трассировки .NET. Владельцу нужно не имя исключения, а
# что делать; поэтому здесь причина и действие, а код HRESULT — в скобках,
# для поиска.
WEBVIEW_BUSY_HINT = (
    "Движок окна (WebView2) не смог занять свою папку профиля: её держит "
    "процесс от прошлого запуска. Окно откроется, но если оно ведёт себя "
    "странно — закройте программу и запустите заново. (HRESULT 0x800700AA)"
)

_ЗАЧИН = "webview2 initialization failed"


class _WebViewNoise(logging.Filter):
    """Одно сообщение pywebview заменяет на одну понятную строку.

    Не наследуемся от «отфильтровать всё»: `filter` возвращает True для
    любой записи, кроме той единственной, которую переписывает. Проверка на
    это стоит в tests/test_startup_noise.py — иначе однажды кто-нибудь
    «упростит» фильтр до `return False`, и настоящая ошибка исчезнет молча.
    """

    def __init__(self, on_hint=None):
        logging.Filter.__init__(self)
        # Куда сказать по-человечески. Обычно это лог окна; когда его нет
        # (запуск из консоли, тест) — просто печать.
        self.on_hint = on_hint
        self.перехвачено = 0

    def filter(self, record):
        try:
            текст = str(record.getMessage() or "")
        except Exception:
            return True
        if _ЗАЧИН not in текст.lower():
            return True
        self.перехвачено += 1
        # «Ресурс занят» — единственный случай, который мы объясняем: он
        # наш и лечится уборкой. Любую другую причину показываем как есть,
        # только без трассировки: имя исключения владельцу пригодится, если
        # он придёт с ним ко мне.
        if "0x800700aa" in текст.lower() or "занят" in текст.lower():
            подсказка = WEBVIEW_BUSY_HINT
        else:
            первая = текст.split("\n")[1].strip() if "\n" in текст else текст
            подсказка = ("Движок окна (WebView2) сообщил об ошибке "
                         "инициализации: %s" % первая[:200])
        record.msg = подсказка
        record.args = ()
        record.levelno = logging.WARNING
        record.levelname = "WARNING"
        if callable(self.on_hint):
            try:
                self.on_hint(подсказка)
            except Exception:
                pass
        return True


def install_webview_noise_filter(on_hint=None, logger_name="pywebview"):
    """Ставит фильтр на логгер pywebview. Возвращает сам фильтр.

    Повторный вызов не плодит копии: при каждом запуске программы фильтр
    ставился бы заново, и одно сообщение размножалось бы на столько строк,
    сколько раз вызвали.
    """
    logger = logging.getLogger(logger_name)
    for уже in logger.filters:
        if isinstance(уже, _WebViewNoise):
            уже.on_hint = on_hint or уже.on_hint
            return уже
    фильтр = _WebViewNoise(on_hint=on_hint)
    logger.addFilter(фильтр)
    return фильтр


class WebViewReaper(object):
    """Снимает процессы WebView2, поднятые ЭТИМ запуском, и только их.

    Устройство намеренно простое: снимок чужих процессов до старта, разница
    после. Всё, что было до нас, — чужое: вторая копия программы, виджеты
    Windows, любой другой обозреватель на том же движке. Убить чужое здесь
    хуже, чем не убрать своё.

    Почему не «убить всё по имени»: у владельца на машине WebView2 крутится
    не только у нас (замерено — процессы Windows Search на том же движке).
    Разом снести их значит сломать чужую программу ради чистоты своей.
    """

    ИМЯ = "msedgewebview2"

    def __init__(self):
        self.до = set()
        self.снято = 0

    @staticmethod
    def _живые():
        """PID всех процессов движка. Пустое множество, если psutil молчит."""
        try:
            import psutil
        except Exception:
            return set()
        найдено = set()
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    имя = (proc.info.get("name") or "").lower()
                except Exception:
                    continue
                if WebViewReaper.ИМЯ in имя:
                    найдено.add(proc.info["pid"])
        except Exception:
            return set()
        return найдено

    def snapshot(self):
        """Запомнить, что было ДО нас. Зовётся перед открытием окна."""
        self.до = self._живые()
        return len(self.до)

    def reap(self, grace=1.5):
        """Снять то, что появилось при нас и пережило закрытие окна.

        Возвращает, сколько снято. Тихо: программа в этот момент уже
        закончила работу, и падение уборщика не должно быть последним, что
        видит владелец.
        """
        try:
            import psutil
        except Exception:
            return 0
        наши = self._живые() - self.до
        if not наши:
            return 0
        процессы = []
        for pid in наши:
            try:
                процессы.append(psutil.Process(pid))
            except Exception:
                continue
        # Сначала вежливо. Движок закрывает свои дочерние сам, и половина
        # списка обычно уходит без принуждения.
        for proc in процессы:
            try:
                proc.terminate()
            except Exception:
                pass
        живы = []
        try:
            _ушли, живы = psutil.wait_procs(процессы, timeout=grace)
        except Exception:
            живы = процессы
        for proc in живы:
            try:
                proc.kill()
            except Exception:
                pass
        self.снято = len(процессы)
        return self.снято


def quiet_chromium(environ=None):
    """Дописывает флаг тишины Chromium в переменную окружения WebView2.

    Дописывает, а не перезаписывает: рядом уже лежат флаги против удушения
    фоновой страницы, и затирать их значит вернуть прежнюю поломку.
    """
    environ = os.environ if environ is None else environ
    key = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"
    current = environ.get(key, "")
    if CHROMIUM_QUIET_FLAGS in current:
        return current
    environ[key] = (current + " " + CHROMIUM_QUIET_FLAGS).strip()
    return environ[key]
