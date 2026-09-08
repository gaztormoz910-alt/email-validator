# main.py
"""Запуск валидатора.

Окно одно — на веб-стеке (pywebview поверх WebView2), разметка в ui/web.

Прежнее окно на CustomTkinter удалено 06.09.2026 по решению владельца: два
окна на один движок означали две панели настроек, которые молча расходились.
Живой пример перед удалением: режим определения страны стоял «Точность» в
одном окне и «Заполненность» в другом, и одна и та же база давала разную
страну в зависимости от того, каким окном её открыли.

    python main.py
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

# Перехватчики аварий ставятся ПЕРВЫМ делом — до импорта интерфейсов и до
# создания окна. Сбой при самой загрузке модулей тоже должен оставить след:
# именно он выглядит как «программа мигнула и закрылась», и именно про него
# рассказать сложнее всего.
#
# Рабочий каталог у окна и у консоли один и тот же (папка проекта), поэтому
# журнал всегда оказывается в data/crash.log рядом с кэшем.
try:
    from core.crashlog import install_hooks as _install_crash_hooks

    _install_crash_hooks()
except Exception:
    # Программа обязана запуститься даже без журнала: он про разбор аварий,
    # а не про проверку почты.
    pass


def run_web():
    """Окно на веб-стеке. При отсутствии pywebview честно объясняет, что делать."""
    try:
        import webview  # noqa: F401
    except ImportError:
        print("Не установлен pywebview — окно им и рисуется.\n"
              "Поставьте его командой:\n\n    pip install pywebview\n")
        raise SystemExit(1)

    # Имя приложения для панели задач. Обязано стоять ДО создания окна:
    # после Windows уже сгруппировала окно под чужим идентификатором, и
    # при запуске из исходников на панели висела бы иконка python.exe.
    from core.winicon import set_app_user_model_id
    set_app_user_model_id("MailFact.App")

    from ui.webapp import run

    # --selftest-close N: открыть окно и закрыть его через N секунд. Нужен
    # проверке про осиротевшие процессы движка, см. .unlazy/round2.
    закрыть = None
    for i, arg in enumerate(sys.argv):
        if arg == "--selftest-close" and i + 1 < len(sys.argv):
            try:
                закрыть = float(sys.argv[i + 1])
            except ValueError:
                закрыть = None
    run(selftest_close=закрыть)


def main():
    # --selftest ЛОГ: пройти настоящий путь основного сценария на трёх адресах
    # и выйти с кодом 0/1. Нужен потому, что открывшееся окно не доказывает
    # почти ничего: словари имён, модель spaCy, корпус wordsegment и запись
    # sqlite подключаются позже и ломаются уже у пользователя.
    for i, arg in enumerate(sys.argv):
        if arg == "--selftest":
            путь = sys.argv[i + 1] if i + 1 < len(sys.argv) else "selftest.log"
            from core.selftest import run as selftest_run
            raise SystemExit(selftest_run(путь))
    run_web()


if __name__ == "__main__":
    main()
