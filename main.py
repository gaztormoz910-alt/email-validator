import os
import sys
import time

_МОМЕНТ_СТАРТА = time.perf_counter()

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from core.nullstream import ensure_streams

    try:
        from core.paths import data_dir as _папка_данных

        ensure_streams(куда=_папка_данных())
    except Exception:
        ensure_streams()
except Exception:
    pass


class StderrFilter:

    def __init__(self, original_stderr):
        self.original_stderr = original_stderr

    def write(self, msg):
        noisy = ("expected message id:", "ignoring response from", "dropped")
        if any(marker in msg for marker in noisy):
            return
        поток = self.original_stderr
        if поток is None or not hasattr(поток, "write"):
            return
        try:
            поток.write(msg)
        except Exception:
            pass

    def flush(self):
        поток = self.original_stderr
        if поток is None or not hasattr(поток, "flush"):
            return
        try:
            поток.flush()
        except Exception:
            pass


sys.stderr = StderrFilter(sys.stderr)

try:
    from core.crashlog import install_hooks as _install_crash_hooks

    _install_crash_hooks()
except Exception:
    pass


def _включить_замер():
    for i, arg in enumerate(sys.argv):
        if arg == "--timing":
            from core.timing import включить
            включить(_МОМЕНТ_СТАРТА)
            return sys.argv[i + 1] if i + 1 < len(sys.argv) else "timing.log"
    return None


def run_web():
    if sys.platform.startswith("linux"):
        os.environ.setdefault("PYWEBVIEW_GUI", "qt")

    from core.timing import отметить

    отметить("до import webview")
    try:
        import webview
    except ImportError:
        print("Не установлен pywebview — окно им и рисуется.\n"
              "Поставьте его командой:\n\n    pip install pywebview\n")
        raise SystemExit(1)

    отметить("import webview")

    from core.winicon import set_app_user_model_id
    set_app_user_model_id("MailFact.App")
    отметить("имя для панели задач")

    from ui.webapp import run
    отметить("import ui.webapp")

    закрыть = None
    for i, arg in enumerate(sys.argv):
        if arg == "--selftest-close" and i + 1 < len(sys.argv):
            try:
                закрыть = float(sys.argv[i + 1])
            except ValueError:
                закрыть = None
    run(selftest_close=закрыть)


def main():
    путь_замера = _включить_замер()
    if путь_замера:
        os.environ["MAILFACT_TIMING_FILE"] = путь_замера

    for i, arg in enumerate(sys.argv):
        if arg == "--version":
            путь = sys.argv[i + 1] if i + 1 < len(sys.argv) else "version.txt"
            try:
                import io as _io
                from core.paths import app_version
                каталог = os.path.dirname(os.path.abspath(путь))
                if каталог:
                    os.makedirs(каталог, exist_ok=True)
                with _io.open(путь, "w", encoding="utf-8", newline="") as ф:
                    ф.write(app_version())
            except Exception:
                raise SystemExit(1)
            raise SystemExit(0)

    for i, arg in enumerate(sys.argv):
        if arg == "--selftest-dialog":
            путь = sys.argv[i + 1] if i + 1 < len(sys.argv) else "dialog.log"
            from core.dialogprobe import run as проба_диалога
            raise SystemExit(проба_диалога(путь))

    for i, arg in enumerate(sys.argv):
        if arg == "--selftest":
            путь = sys.argv[i + 1] if i + 1 < len(sys.argv) else "selftest.log"
            from core.selftest import run as selftest_run
            raise SystemExit(selftest_run(путь))
    run_web()


if __name__ == "__main__":
    main()
