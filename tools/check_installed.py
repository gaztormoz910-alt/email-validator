# -*- coding: utf-8 -*-
"""Проверяет то, что реально получает человек, а не то, что лежит в папке.

Делает ровно то же, что сделает пользователь: качает установщик ПО ПОСТОЯННОЙ
ССЫЛКЕ, ставит его молча, запускает установленную копию и смотрит на неё.

ПОЧЕМУ ПО ССЫЛКЕ, А НЕ ПО ЛОКАЛЬНОЙ ПАПКЕ. Проверка, идущая по `dist\\`,
доказывает «исправлено у меня», а не «исправлено у пользователя». Между ними
помещается целый релиз: не тот тег, не собравшийся workflow, не приложенный
файл. Режим --local существует только для отладки до первого релиза и об этом
говорит вслух.

ПОЧЕМУ ОКНО ИЩЕТСЯ ПО PID, А НЕ ПО ЗАГОЛОВКУ. Искать окно по ожидаемому
заголовку значит заранее исключить тот самый случай, который ловишь: при
падении PyInstaller показывает окно с заголовком «Unhandled exception in
script», и поиск по 'MailFact*' его просто не найдёт, отрапортовав «окна нет»
вместо «программа упала».

ПРО DPI. Скрипт объявляет себя DPI-aware до первого обращения к метрикам:
иначе `GetSystemMetrics` вернёт размеры без учёта масштаба экрана, и сравнение
с реальными иконками окна будет ложным на любой машине со 125% и выше.

    python tools/check_installed.py                 # скачать из релиза
    python tools/check_installed.py --local ПАПКА   # взять готовую сборку
    python tools/check_installed.py --setup ФАЙЛ    # взять готовый установщик
"""
import argparse
import hashlib
import os
import subprocess
import sys
import time

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, КОРЕНЬ)

ИМЯ = "MailFact"
ВЛАДЕЛЕЦ = "gaztormoz910-alt"
РЕПОЗИТОРИЙ = "email-validator"
ССЫЛКА = ("https://github.com/%s/%s/releases/latest/download/%s-setup.exe"
          % (ВЛАДЕЛЕЦ, РЕПОЗИТОРИЙ, ИМЯ))

# DPI объявляем ДО любых метрик. См. «ПРО DPI» в шапке.
if sys.platform == "win32":
    import ctypes
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

from core.winicon import (ICON_BIG, ICON_SMALL, _окна_процесса,  # noqa: E402
                          expected_icon_sizes, window_icon_sizes)

ПРОВАЛЫ = []


def шаг(ок, текст):
    print("  %s %s" % ("ok  " if ок else "НЕТ ", текст))
    if not ок:
        ПРОВАЛЫ.append(текст)
    return ок


def sha256(путь):
    h = hashlib.sha256()
    with open(путь, "rb") as f:
        for кусок in iter(lambda: f.read(1 << 20), b""):
            h.update(кусок)
    return h.hexdigest()


def скачать(url, куда):
    import urllib.request
    print("качаю:", url)
    запрос = urllib.request.Request(url, headers={"User-Agent": "MailFact-check"})
    with urllib.request.urlopen(запрос, timeout=180) as ответ, \
            open(куда, "wb") as f:
        while True:
            кусок = ответ.read(1 << 20)
            if not кусок:
                break
            f.write(кусок)
    return куда


def поставить_молча(установщик, куда):
    """Тихая установка. Код возврата 0 — обязателен."""
    команда = [установщик, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
               "/DIR=" + куда]
    print("ставлю:", " ".join(команда))
    готово = subprocess.run(команда, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=600)
    return готово.returncode, (готово.stdout or "") + (готово.stderr or "")


def проверить_сборку(папка):
    """Всё, что можно спросить у установленной копии, не запуская её."""
    exe = os.path.join(папка, ИМЯ + ".exe")
    шаг(os.path.exists(exe), "есть %s" % exe)
    if not os.path.exists(exe):
        return None

    # Иконка ВНУТРИ установленной сборки против иконки в репозитории. Без
    # этого «иконка исправлена» означало бы лишь «исправлена у меня в папке».
    свой = os.path.join(КОРЕНЬ, "assets", ИМЯ + ".ico")
    внутри = None
    for основа in (папка, os.path.join(папка, "_internal")):
        кандидат = os.path.join(основа, "assets", ИМЯ + ".ico")
        if os.path.exists(кандидат):
            внутри = кандидат
            break
    if шаг(внутри is not None, "иконка найдена внутри сборки"):
        a, b = sha256(свой), sha256(внутри)
        шаг(a == b, "sha256 иконки совпадает с репозиторием (%s)" % a[:16])

    # Версия внутри сборки против единственного источника.
    ожидается = open(os.path.join(КОРЕНЬ, "VERSION"), encoding="utf-8").read().strip()
    найдена = None
    for основа in (папка, os.path.join(папка, "_internal")):
        кандидат = os.path.join(основа, "VERSION")
        if os.path.exists(кандидат):
            найдена = open(кандидат, encoding="utf-8").read().strip()
            break
    шаг(найдена == ожидается,
        "VERSION в сборке = %r, в репозитории = %r" % (найдена, ожидается))
    return exe


def запустить_и_посмотреть(exe, ждать=45):
    """Запускает программу, находит ЕЁ окно по PID и смотрит на иконки."""
    print("запускаю:", exe)
    процесс = subprocess.Popen([exe], cwd=os.path.dirname(exe))
    try:
        hwnd = None
        предел = time.time() + ждать
        while time.time() < предел:
            if процесс.poll() is not None:
                шаг(False, "программа завершилась сама, код %s"
                    % процесс.returncode)
                return
            окна = _окна_процесса(процесс.pid)
            if окна:
                hwnd = окна[0]
                break
            time.sleep(0.5)

        if not шаг(hwnd is not None, "окно процесса найдено за %d с" % ждать):
            return

        u = ctypes.windll.user32
        буфер = ctypes.create_unicode_buffer(512)
        u.GetWindowTextW(ctypes.c_void_p(hwnd), буфер, 512)
        заголовок = буфер.value
        print("     заголовок окна: %r" % заголовок)

        # PyInstaller показывает трассировку в окне с этим заголовком. Ищем
        # его ЯВНО: окно найдено по PID, поэтому падение мы увидим, а не
        # примем за «окна нет».
        шаг("Unhandled exception" not in заголовок,
            "окно не является окном трассировки")
        шаг(заголовок.startswith(ИМЯ),
            "заголовок начинается с %s" % ИМЯ)

        версия = open(os.path.join(КОРЕНЬ, "VERSION"), encoding="utf-8").read().strip()
        шаг(версия in заголовок,
            "в заголовке стоит версия %s" % версия)

        # Иконке нужно время: её ставит отдельный поток после появления окна.
        #
        # ЖДЁМ СОВПАДЕНИЯ, А НЕ ПЕРВОГО НЕПУСТОГО ЗНАЧЕНИЯ. Первая версия этой
        # проверки выходила из цикла, как только оба слота оказывались
        # заполнены, — а заполнены они с самого начала иконкой по умолчанию
        # 48x48 в обоих. Проверка читала её и объявляла провал, хотя через
        # две секунды в ICON_SMALL уже стояло правильное 24x24. То есть
        # мерила скорость своего цикла, а не работу программы.
        итог, ждём = {}, expected_icon_sizes()
        предел = time.time() + 20
        while time.time() < предел:
            итог = window_icon_sizes(hwnd)
            совпало = all(итог.get(с) and итог[с][0] == ждём.get(с)
                          for с in (ICON_SMALL, ICON_BIG))
            if совпало:
                break
            time.sleep(0.5)
        print("     Windows просит: ICON_SMALL=%s ICON_BIG=%s"
              % (ждём.get(ICON_SMALL), ждём.get(ICON_BIG)))
        print("     у окна стоит:   ICON_SMALL=%s ICON_BIG=%s"
              % (итог.get(ICON_SMALL), итог.get(ICON_BIG)))
        for слот, имя in ((ICON_SMALL, "ICON_SMALL"), (ICON_BIG, "ICON_BIG")):
            есть = итог.get(слот)
            надо = ждём.get(слот)
            шаг(bool(есть) and есть[0] == надо,
                "%s = %s, Windows просит %s" % (имя, есть, надо))
    finally:
        try:
            процесс.terminate()
            процесс.wait(timeout=20)
        except Exception:
            процесс.kill()


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--local", default=None,
                   help="готовая папка сборки (отладка до релиза)")
    p.add_argument("--setup", default=None, help="готовый файл установщика")
    p.add_argument("--keep", action="store_true",
                   help="не удалять установленную копию")
    args = p.parse_args()

    if sys.platform != "win32":
        print("проверка имеет смысл только на Windows")
        return 1

    if args.local:
        print("РЕЖИМ --local: проверяется ЛОКАЛЬНАЯ сборка, а не то, что "
              "получит человек из релиза.")
        exe = проверить_сборку(os.path.abspath(args.local))
        if exe:
            запустить_и_посмотреть(exe)
    else:
        врем = os.path.join(os.environ.get("TEMP", "."), "mailfact-check")
        os.makedirs(врем, exist_ok=True)
        установщик = args.setup
        if not установщик:
            установщик = скачать(ССЫЛКА, os.path.join(врем, "setup.exe"))
        мб = os.path.getsize(установщик) / (1024 * 1024)
        print("установщик: %s (%.1f МБ)" % (установщик, мб))
        шаг(мб >= 15, "установщик не подозрительно мал: %.1f МБ" % мб)

        куда = os.path.join(врем, "installed")
        код, вывод = поставить_молча(установщик, куда)
        шаг(код == 0, "тихая установка вернула 0 (получено %s)" % код)
        if вывод.strip():
            print("     вывод установщика:", вывод.strip()[:300])
        exe = проверить_сборку(куда)
        if exe:
            запустить_и_посмотреть(exe)

    print()
    if ПРОВАЛЫ:
        print("ПРОВАЛОВ: %d" % len(ПРОВАЛЫ))
        for т in ПРОВАЛЫ:
            print("   -", т)
        return 1
    print("INSTALLED_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
