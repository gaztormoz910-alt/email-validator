# main.py
"""Запуск валидатора.

По умолчанию открывается окно на веб-стеке (pywebview поверх WebView2) —
то же, на чём сделан youtube-parser. Прежнее окно на CustomTkinter никуда не
делось и запускается флагом --classic: оно покрыто тестами и остаётся
запасным путём, пока новое не отработает на живых прогонах. Движок проверки
у обоих один и тот же.

    python main.py             новое окно
    python main.py --classic   прежнее окно
"""
import os
import sys


class StderrFilter:
    """Глушит болтовню dnspython про потерянные UDP-пакеты.

    Она печатается на каждый повторный запрос и забивает консоль так, что
    настоящую ошибку в ней не найти.
    """

    def __init__(self, original_stderr):
        self.original_stderr = original_stderr

    def write(self, msg):
        noisy = ("expected message id:", "ignoring response from", "dropped")
        if any(marker in msg for marker in noisy):
            return
        self.original_stderr.write(msg)

    def flush(self):
        self.original_stderr.flush()


sys.stderr = StderrFilter(sys.stderr)
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


def run_classic():
    """Прежнее окно на CustomTkinter."""
    from ui.gui import ValidatorApp

    app = ValidatorApp()
    app.safe_log("[INFO] Система успешно инициализирована. Валидатор готов к работе.", "info")
    app.safe_log("[INFO] Ожидание загрузки базы (.txt)...", "info")
    app.mainloop()


def run_web():
    """Окно на веб-стеке. При отсутствии pywebview честно объясняет, что делать."""
    try:
        import webview  # noqa: F401
    except ImportError:
        print("Не установлен pywebview — окно на веб-стеке им и рисуется.\n"
              "Поставьте его командой:\n\n    pip install pywebview\n\n"
              "или запустите прежнее окно:\n\n    python main.py --classic\n")
        raise SystemExit(1)

    from ui.webapp import run
    run()


def main():
    if "--classic" in sys.argv:
        run_classic()
    else:
        run_web()


if __name__ == "__main__":
    main()
