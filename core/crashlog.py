import datetime
import io
import os
import threading
import traceback
from core.paths import data_path

__all__ = ["log_crash", "install_hooks", "recent_crashes", "crash_log_path",
           "CRASH_LOG_PATH", "MAX_BYTES"]

CRASH_LOG_PATH = data_path("crash.log")

MAX_BYTES = 2 * 1024 * 1024

SEPARATOR = "=" * 78

_lock = threading.Lock()
_installed = False


def crash_log_path():
    try:
        return os.path.abspath(CRASH_LOG_PATH)
    except Exception:
        return CRASH_LOG_PATH


def _trim(path):
    try:
        if os.path.getsize(path) <= MAX_BYTES:
            return
        with io.open(path, encoding="utf-8", errors="replace") as handle:
            text = handle.read()
        tail = text[-(MAX_BYTES // 2):]
        cut = tail.find(SEPARATOR)
        if cut > 0:
            tail = tail[cut:]
        with io.open(path, "w", encoding="utf-8") as handle:
            handle.write(tail)
    except Exception:
        pass


def log_crash(kind, message, exc=None, context=None):
    try:
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
        return False


def recent_crashes(within_hours=24, limit=3):
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

    enable_fatal_dump()
    _installed = True
    return True


FATAL_LOG_PATH = data_path("fatal.log")
_fatal_file = None


def enable_fatal_dump():
    global _fatal_file
    try:
        import faulthandler
        if _fatal_file is not None:
            return False
        _trim(FATAL_LOG_PATH)
        _fatal_file = io.open(FATAL_LOG_PATH, "a", encoding="utf-8")
        faulthandler.enable(file=_fatal_file, all_threads=True)
        return True
    except Exception:
        return False
