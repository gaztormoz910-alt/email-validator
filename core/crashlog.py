# core/crashlog.py
"""Журнал сбоев: единственное место, куда программа пишет, как она сломалась.

Зачем понадобился. Владелец дважды сказал «софт наебнулся», и оба раза
причину назвать было нечем: программа не писала на диск ничего. Трассировка
уходила в консоль, а при запуске двойным кликом консоли нет вовсе. Разбор
приходилось вести по журналу событий Windows — который про сбой ВНУТРИ
процесса не знает ничего, если процесс не рухнул целиком.

Три правила, из которых здесь всё следует:

**Журнал не имеет права уронить программу.** Он существует ради разбора
аварии, и стать причиной второй аварии — худшее, что он может сделать.
Поэтому все функции глушат свои исключения молча: диск может быть полон,
папка — только на чтение, файл — занят антивирусом. Ни один из этих случаев
не должен помешать проверке почты.

**Пишется ТО, ЧТО СЛУЧИЛОСЬ, а не то, что мы подумали.** Никаких «произошла
ошибка»: время, вид сбоя, тип исключения, текст и полная трассировка. Разбор
ведётся по этому файлу, и всё, чего в нём нет, придётся выяснять заново.

**Файл не растёт бесконечно.** Программа может сыпать одной и той же ошибкой
в цикле по десять раз в секунду; без потолка такой журнал за ночь съест диск.
При переполнении старое отбрасывается, свежее остаётся — разбирают всегда
последний сбой.
"""
import datetime
import io
import os
import threading
import traceback
from core.paths import data_path

__all__ = ["log_crash", "install_hooks", "recent_crashes", "crash_log_path",
           "CRASH_LOG_PATH", "MAX_BYTES"]

# Рядом с кэшем и долгой памятью: всё, что программа пишет про себя, лежит в
# одной папке, и владельцу не приходится искать по всему проекту.
CRASH_LOG_PATH = data_path("crash.log")

# Потолок файла. Двух мегабайт хватает на сотни трассировок — больше для
# разбора всё равно не читают, а расти без предела журналу нельзя.
MAX_BYTES = 2 * 1024 * 1024

# Разделитель записей. Достаточно приметный, чтобы файл можно было читать
# глазами и резать по нему программой.
SEPARATOR = "=" * 78

_lock = threading.Lock()
_installed = False


def crash_log_path():
    """Полный путь к журналу — его показывают владельцу, а не относительный."""
    try:
        return os.path.abspath(CRASH_LOG_PATH)
    except Exception:
        return CRASH_LOG_PATH


def _trim(path):
    """Оставляет в файле только свежий хвост, если он перерос потолок.

    Режем по границе записи, а не по байтам: обрубленная посередине
    трассировка бесполезна ровно так же, как её отсутствие.
    """
    try:
        if os.path.getsize(path) <= MAX_BYTES:
            return
        with io.open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        # Берём последнюю половину потолка и отбрасываем всё до ближайшего
        # начала записи, чтобы файл не начинался с середины трассировки.
        tail = text[-(MAX_BYTES // 2):]
        cut = tail.find(SEPARATOR)
        if cut > 0:
            tail = tail[cut:]
        with io.open(path, "w", encoding="utf-8") as handle:
            handle.write(tail)
    except Exception:
        pass


def log_crash(kind, message, exc=None, context=None):
    """Записывает один сбой. Возвращает True, если запись удалась.

    kind    — откуда прилетело: «главный поток», «рабочий поток», «мост»,
              «окно». По нему видно, где искать, ещё до чтения трассировки.
    message — что случилось, словами.
    exc     — исключение, если оно есть; из него берётся трассировка.
    context — что происходило вокруг: имя метода, адрес, страница.

    Никогда не бросает: зовут из обработчиков аварий, и исключение отсюда
    означало бы потерю самой аварии.
    """
    try:
        # Запись без единого слова описания не нужна никому.
        #
        # Первая версия перехватчика в окне присылала пустые сообщения, и в
        # журнале скопилось двадцать записей «Ошибка в окне» без деталей.
        # Разбирать их нельзя, а при запуске программа о них ещё и
        # рассказывала. Пустая запись хуже её отсутствия: она создаёт
        # видимость улики.
        has_words = bool(str(message or "").strip()) or exc is not None
        if not has_words:
            return False

        stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        parts = ["", SEPARATOR, "%s  [%s]" % (stamp, kind), str(message)]
        if context:
            parts.append("Что делали: %s" % context)
        if exc is not None:
            try:
                parts.append("".join(traceback.format_exception(
                    type(exc), exc, exc.__traceback__)).rstrip())
            except Exception:
                parts.append("Тип: %s" % type(exc).__name__)
        text = "\n".join(parts) + "\n"

        with _lock:
            directory = os.path.dirname(CRASH_LOG_PATH)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with io.open(CRASH_LOG_PATH, "a", encoding="utf-8") as handle:
                handle.write(text)
            _trim(CRASH_LOG_PATH)
        return True
    except Exception:
        # Диск полон, папка только на чтение, файл занят — всё это не повод
        # ронять проверку почты. Молчим.
        return False


def recent_crashes(within_hours=24, limit=3):
    """Последние записи за указанный срок. Пустой список — сбоев не было.

    Нужна при запуске: владелец должен УЗНАТЬ о вчерашней аварии, а не
    наткнуться на файл случайно. Срок ограничен, потому что запись
    полугодовой давности к сегодняшнему запуску отношения не имеет.
    """
    try:
        if not os.path.exists(CRASH_LOG_PATH):
            return []
        with io.open(CRASH_LOG_PATH, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
    except Exception:
        return []

    edge = datetime.datetime.now() - datetime.timedelta(hours=max(0, within_hours))
    found = []
    for block in text.split(SEPARATOR):
        block = block.strip()
        if not block:
            continue
        head = block.splitlines()[0]
        try:
            when = datetime.datetime.strptime(head[:19], "%Y-%m-%d %H:%M:%S")
        except (ValueError, IndexError):
            continue
        if when >= edge:
            found.append(head)
    return found[-limit:] if limit else found


def install_hooks():
    """Ставит перехватчики на главный и на РАБОЧИЕ потоки.

    Рабочие важнее. Конвейер проверки живёт в сотне потоков, и падение
    любого из них сейчас не видно нигде: поток тихо умирает, его адреса
    пропадают из выдачи, а счётчик их засчитывает. `threading.excepthook`
    существует ровно для этого случая (Python 3.8+).

    Прежние перехватчики вызываются следом, а не заменяются: консольный
    вывод при запуске из терминала терять незачем — там он читается быстрее
    файла.

    Повторный вызов ничего не делает: иначе перехватчики наслаивались бы
    друг на друга при каждом импорте.
    """
    global _installed
    if _installed:
        return False
    import sys

    previous_excepthook = sys.excepthook

    def on_main_thread(exc_type, exc, tb):
        log_crash("главный поток", "Необработанное исключение", exc)
        try:
            previous_excepthook(exc_type, exc, tb)
        except Exception:
            pass

    sys.excepthook = on_main_thread

    previous_thread_hook = getattr(threading, "excepthook", None)

    def on_worker_thread(args):
        # SystemExit в потоке — это НЕ авария: так поток просят завершиться.
        # Записывать его значит забивать журнал штатными остановками.
        if args.exc_type is not SystemExit:
            log_crash("рабочий поток",
                      "Необработанное исключение в потоке %s"
                      % getattr(args.thread, "name", "?"),
                      args.exc_value)
        if previous_thread_hook is not None:
            try:
                previous_thread_hook(args)
            except Exception:
                pass

    if previous_thread_hook is not None:
        threading.excepthook = on_worker_thread

    _installed = True
    return True
