# -*- coding: utf-8 -*-
import argparse
import hashlib
import os
import re
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


def _репозиторий():
    владелец = os.environ.get("GITHUB_REPOSITORY_OWNER", "")
    имя = os.environ.get("GITHUB_REPOSITORY_NAME", "")
    if владелец and имя:
        return владелец, имя
    try:
        адрес = subprocess.run(["git", "remote", "get-url", "origin"], cwd=КОРЕНЬ,
                               capture_output=True, text=True, timeout=10).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        адрес = ""
    найдено = re.search(r"[:/]([^/:]+)/([^/]+?)(?:\.git)?/?$", адрес)
    if найдено:
        return владелец or найдено.group(1), имя or найдено.group(2)
    return None, None


ВЛАДЕЛЕЦ, РЕПОЗИТОРИЙ = _репозиторий()
ССЫЛКА = ("https://github.com/%s/%s/releases/latest/download/%s-setup.exe"
          % (ВЛАДЕЛЕЦ, РЕПОЗИТОРИЙ, ИМЯ)) if ВЛАДЕЛЕЦ else ""

if sys.platform == "win32":
    import ctypes
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass

from core.winicon import (ICON_BIG, ICON_SMALL, _окна_процесса,
                          expected_icon_sizes, window_icon_sizes)

ПРОВАЛЫ = []


def _версия_от_программы(exe, ждать=60):
    import subprocess
    import tempfile

    держатель = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
    держатель.close()
    try:
        готово = subprocess.run([exe, "--version", держатель.name],
                                cwd=os.path.dirname(exe), timeout=ждать,
                                capture_output=True)
        if готово.returncode != 0:
            return "КОД ВОЗВРАТА %s" % готово.returncode
        with open(держатель.name, encoding="utf-8") as ф:
            return ф.read().strip()
    except Exception as беда:
        return "НЕ ВЫШЛО: %s" % беда
    finally:
        try:
            os.remove(держатель.name)
        except OSError:
            pass


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
    команда = [установщик, "/VERYSILENT", "/SUPPRESSMSGBOXES", "/NORESTART",
               "/DIR=" + куда]
    print("ставлю:", " ".join(команда))
    готово = subprocess.run(команда, capture_output=True, text=True,
                            encoding="utf-8", errors="replace", timeout=600)
    return готово.returncode, (готово.stdout or "") + (готово.stderr or "")


def проверить_сборку(папка):
    exe = os.path.join(папка, ИМЯ + ".exe")
    шаг(os.path.exists(exe), "есть %s" % exe)
    if not os.path.exists(exe):
        return None

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


def _ключ_удаления():
    import re
    текст = open(os.path.join(КОРЕНЬ, "MailFact.iss"), encoding="utf-8-sig").read()
    найдено = re.search(r"^AppId=\{\{([0-9A-Fa-f-]+)\}", текст, re.M)
    if not найдено:
        return None
    return r"Software\Microsoft\Windows\CurrentVersion\Uninstall\{%s}_is1" % найдено.group(1)


def _ключ_есть(ключ):
    import winreg
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, ключ))
        return True
    except OSError:
        return False


def удалить_молча(папка):
    ключ = _ключ_удаления()
    шаг(ключ is not None, "AppId найден в MailFact.iss")
    деинсталлятор = os.path.join(папка, "unins000.exe")
    if not шаг(os.path.exists(деинсталлятор), "есть деинсталлятор unins000.exe"):
        return
    готово = subprocess.run([деинсталлятор, "/VERYSILENT", "/SUPPRESSMSGBOXES",
                             "/NORESTART"], capture_output=True, timeout=300)
    шаг(готово.returncode == 0, "деинсталлятор вернул 0 (получено %s)" % готово.returncode)
    предел = time.time() + 120
    while time.time() < предел and (os.path.exists(папка) or (ключ and _ключ_есть(ключ))):
        time.sleep(1)
    шаг(not os.path.exists(папка), "папки программы после удаления нет")
    if ключ:
        шаг(not _ключ_есть(ключ), "в «Установке и удалении программ» записи не осталось")


def запустить_и_посмотреть(exe, ждать=45):
    print("запускаю:", exe)
    процесс = subprocess.Popen([exe], cwd=os.path.dirname(exe))
    try:
        hwnd = None
        начало = time.time()
        предел = начало + ждать
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

        if not шаг(hwnd is not None, ("окно процесса найдено за %.1f с" % (time.time() - начало))
                   if hwnd is not None else "окна процесса нет за %d с" % ждать):
            return

        u = ctypes.windll.user32
        буфер = ctypes.create_unicode_buffer(512)
        u.GetWindowTextW(ctypes.c_void_p(hwnd), буфер, 512)
        заголовок = буфер.value
        print("     заголовок окна: %r" % заголовок)

        шаг("Unhandled exception" not in заголовок,
            "окно не является окном трассировки")
        шаг(заголовок.startswith(ИМЯ),
            "заголовок начинается с %s" % ИМЯ)

        версия = open(os.path.join(КОРЕНЬ, "VERSION"), encoding="utf-8").read().strip()
        шаг(версия not in заголовок,
            "версии в заголовке нет (в нём %r)" % заголовок)

        сказано = _версия_от_программы(exe)
        print("     программа назвала версию: %r" % сказано)
        шаг(сказано == версия, "программа называет %s" % версия)

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
        корень = os.environ.get("MAILFACT_WORK") or os.path.join(
            os.path.expanduser("~"), "MailFact-work")
        врем = os.path.join(корень, "check")
        os.makedirs(врем, exist_ok=True)
        установщик = args.setup
        if not установщик and not ССЫЛКА:
            print("ОШИБКА: не знаю репозитория выпусков — нет origin и нет "
                  "GITHUB_REPOSITORY_OWNER/GITHUB_REPOSITORY_NAME")
            return 1
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
        if not args.keep:
            удалить_молча(куда)

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
