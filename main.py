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

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# ПОТОКИ ВЫВОДА — САМЫМ ПЕРВЫМ ДЕЙСТВИЕМ, ДО ЛЮБЫХ ДРУГИХ ИМПОРТОВ.
#
# У собранной с console=False программы sys.stdout и sys.stderr равны None.
#
# Замерено 11.09.2026 на релизе 1.1.8. webview.OPEN_DIALOG оказался не
# константой, а свойством модуля: при каждом обращении оно пишет
# предупреждение об устаревании через logging. Дальше — тонкость, которую
# легко описать неверно, поэтому она здесь дословно.
#
# САМ ПО СЕБЕ None БЕЗОПАСЕН. logging.Handler.handleError начинается с
# `if raiseExceptions and sys.stderr:` и при None молча ничего не делает.
# Ронял ДРУГОЙ поток — тот, что ЕСТЬ, но при записи падает. И создавала его
# строка ниже: StderrFilter(None) — объект истинный по `if`, а write у него
# бросает AttributeError. handleError доходил до sys.stderr.write, ловил там
# только OSError, и AttributeError уезжал наружу — тому, кто всего лишь
# позвал функцию. В окне это становилось ответом 500, и не работали ВСЕ
# ЧЕТЫРЕ диалога: выбор базы, две выгрузки и выбор папки.
#
# Замер (tests/test_nostream.py, отдельный процесс):
#     stderr=None          -> НЕ УПАЛО
#     stderr=Фильтр(None)  -> AttributeError: 'NoneType' object ... 'write'
# и код возврата процесса 120: сбросить сломанные потоки на выходе CPython
# тоже не смог.
#
# Раньше всех, потому что логгеры чужих библиотек захватывают sys.stderr в
# момент своего импорта: поток, подставленный позже, до них уже не дойдёт.
try:
    from core.nullstream import ensure_streams

    try:
        from core.paths import data_dir as _папка_данных

        ensure_streams(куда=_папка_данных())
    except Exception:
        ensure_streams()
except Exception:
    # Без потоков программа обязана хотя бы попытаться запуститься.
    pass


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
        # Своя защита, даже после ensure_streams. Фильтр оборачивает ЧУЖОЙ
        # поток, и если тот окажется негодным, падать обязан не он, а ничего:
        # задача фильтра — убрать шум, а не решать судьбу программы.
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
    # На Linux движок окна выбирается ДО импорта pywebview: он читает эту
    # переменную один раз при загрузке. Явный выбор нужен потому, что
    # pywebview сначала ищет GTK в системе, а мы кладём в сборку Qt — чтобы
    # программа не требовала от человека системного WebKitGTK. Без этой
    # строки на машине с GTK взялся бы системный движок, а на машине без
    # него — ничего, хотя свой лежит внутри.
    #
    # Уважаем чужой выбор: если переменная уже выставлена, не трогаем.
    if sys.platform.startswith("linux"):
        os.environ.setdefault("PYWEBVIEW_GUI", "qt")

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
    # --version ФАЙЛ: записать свой номер версии в файл и выйти.
    #
    # ЗАЧЕМ ОТДЕЛЬНЫЙ КЛЮЧ. Версия больше не показывается в заголовке окна —
    # решение владельца 11.09.2026. Но заголовок был ПЯТЫМ местом сверки
    # версий (tools/check_version.py), и именно он ловил случай «собрано из
    # одного исходника, установлено из другого»: остальные четыре места
    # читают файлы, а это — ответ ЗАПУЩЕННОЙ программы. Просто убрать место
    # сверки значило бы подогнать проверку под правку.
    #
    # В ФАЙЛ, А НЕ НА ПЕЧАТЬ: у сборки с console=False потоков вывода нет,
    # и печать ушла бы в data/stdout.log вперемешку с чужими сообщениями.
    # Человеку этот ключ не показывается нигде и в окно ничего не выводит.
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

    # --selftest ЛОГ: пройти настоящий путь основного сценария на трёх адресах
    # и выйти с кодом 0/1. Нужен потому, что открывшееся окно не доказывает
    # почти ничего: словари имён, модель spaCy, корпус wordsegment и запись
    # sqlite подключаются позже и ломаются уже у пользователя.
    # --selftest-dialog ЛОГ: поднять настоящее окно и проверить САМ диалог
    # выбора файла. Обычный самотест подменяет его результат и до него не
    # достаёт, а сломался у владельца именно он.
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
