# -*- coding: utf-8 -*-
"""Проверяет, что номер версии сходится во всех пяти местах сразу.

ЗАЧЕМ. Пока версия живёт в нескольких файлах, она разъезжается молча: на
соседнем проекте заголовок окна показывал v4.0, когда релиз был уже 4.0.3, и
ни одна проверка этого не поймала. Здесь единственный источник — файл VERSION,
а проверка идёт по всей цепочке до конца:

  1. файл VERSION в репозитории;
  2. его копия ВНУТРИ собранной программы;
  3. ресурс версии самого .exe (то, что видно в свойствах файла);
  4. DisplayVersion в записи деинсталляции (реестр Uninstall);
  5. версия, которую называет сама запущенная программа
     (ключом --version; в окне версия не показывается —
     решение владельца, см. ui/webapp.py).

Пункты 4 и 5 требуют установленной копии и пропускаются с явным сообщением,
если её нет: молча считать пропущенное пройденным нельзя.

    python tools/check_version.py --dist ПАПКА_СБОРКИ
"""
import argparse
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
GUID = "{DA2BCC50-6779-4561-BC18-C83D41C3A275}"

ПРОВАЛЫ = []
ПРОПУЩЕНО = []


def шаг(ок, текст):
    print("  %s %s" % ("ok  " if ок else "НЕТ ", текст))
    if not ок:
        ПРОВАЛЫ.append(текст)
    return ок


def пропуск(текст):
    print("  --   пропущено: %s" % текст)
    ПРОПУЩЕНО.append(текст)


def версия_exe(путь):
    """Ресурс версии .exe — то, что Windows показывает в свойствах файла."""
    if sys.platform != "win32":
        return None
    import ctypes
    from ctypes import wintypes
    v = ctypes.windll.version
    v.GetFileVersionInfoSizeW.argtypes = [wintypes.LPCWSTR,
                                          ctypes.POINTER(wintypes.DWORD)]
    размер = v.GetFileVersionInfoSizeW(путь, None)
    if not размер:
        return None
    буфер = ctypes.create_string_buffer(размер)
    if not v.GetFileVersionInfoW(путь, 0, размер, буфер):
        return None
    указатель = ctypes.c_void_p()
    длина = ctypes.c_uint()
    if not v.VerQueryValueW(буфер, "\\", ctypes.byref(указатель),
                            ctypes.byref(длина)):
        return None

    class VS_FIXEDFILEINFO(ctypes.Structure):
        _fields_ = [("dwSignature", ctypes.c_uint32),
                    ("dwStrucVersion", ctypes.c_uint32),
                    ("dwFileVersionMS", ctypes.c_uint32),
                    ("dwFileVersionLS", ctypes.c_uint32),
                    ("dwProductVersionMS", ctypes.c_uint32),
                    ("dwProductVersionLS", ctypes.c_uint32),
                    ("dwFileFlagsMask", ctypes.c_uint32),
                    ("dwFileFlags", ctypes.c_uint32),
                    ("dwFileOS", ctypes.c_uint32),
                    ("dwFileType", ctypes.c_uint32),
                    ("dwFileSubtype", ctypes.c_uint32),
                    ("dwFileDateMS", ctypes.c_uint32),
                    ("dwFileDateLS", ctypes.c_uint32)]

    инфо = ctypes.cast(указатель,
                       ctypes.POINTER(VS_FIXEDFILEINFO)).contents
    return "%d.%d.%d.%d" % (инфо.dwFileVersionMS >> 16,
                            инфо.dwFileVersionMS & 0xFFFF,
                            инфо.dwFileVersionLS >> 16,
                            инфо.dwFileVersionLS & 0xFFFF)


def версия_в_реестре():
    """DisplayVersion из записи деинсталляции. None, если не установлено."""
    if sys.platform != "win32":
        return None
    import winreg
    ветки = [(winreg.HKEY_CURRENT_USER,
              r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
             (winreg.HKEY_LOCAL_MACHINE,
              r"Software\Microsoft\Windows\CurrentVersion\Uninstall")]
    for корень, путь in ветки:
        for подпуть in (GUID + "_is1", GUID):
            try:
                with winreg.OpenKey(корень, путь + "\\" + подпуть) as ключ:
                    return winreg.QueryValueEx(ключ, "DisplayVersion")[0]
            except OSError:
                continue
    return None


def версия_от_программы(exe, ждать=60):
    """Спрашивает версию у ЗАПУЩЕННОЙ программы ключом --version.

    ПОЧЕМУ НЕ ПО ЗАГОЛОВКУ ОКНА, КАК РАНЬШЕ. Версию убрали из заголовка —
    решение владельца 11.09.2026: в софте её нигде явно не показывать. Но
    сверять её у запущенной программы всё равно надо: остальные четыре места
    читают ФАЙЛЫ, и только это отвечает за то, что запустившийся код берёт
    версию оттуда же. Иначе «собрано из одного исходника, установлено из
    другого» никто не поймает.

    Ответ идёт в файл, а не на печать: у сборки без консоли потоков вывода
    нет. Возвращает строку версии или объяснение, почему не вышло.
    """
    import tempfile

    держатель = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
    держатель.close()
    try:
        готово = subprocess.run([exe, "--version", держатель.name],
                                cwd=os.path.dirname(exe), timeout=ждать,
                                capture_output=True)
        if готово.returncode != 0:
            return "ПРОГРАММА ВЕРНУЛА КОД %s" % готово.returncode
        with open(держатель.name, encoding="utf-8") as ф:
            return ф.read().strip()
    except subprocess.TimeoutExpired:
        return "ПРОГРАММА НЕ ОТВЕТИЛА ЗА %s с" % ждать
    except OSError as беда:
        return "ЗАПУСК НЕ УДАЛСЯ: %s" % беда
    finally:
        try:
            os.remove(держатель.name)
        except OSError:
            pass

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dist", default=None,
                   help="папка собранной программы")
    p.add_argument("--no-window", action="store_true",
                   help="не запускать окно (для машин без рабочего стола)")
    args = p.parse_args()

    эталон = open(os.path.join(КОРЕНЬ, "VERSION"),
                  encoding="utf-8").read().strip()
    print("1. VERSION в репозитории: %s" % эталон)
    шаг(bool(эталон) and эталон != "0.0.0", "VERSION заполнен")

    папка = os.path.abspath(args.dist) if args.dist else None
    exe = os.path.join(папка, ИМЯ + ".exe") if папка else None

    print("2. копия VERSION внутри сборки")
    if папка and os.path.isdir(папка):
        найдено = None
        for основа in (папка, os.path.join(папка, "_internal")):
            кандидат = os.path.join(основа, "VERSION")
            if os.path.exists(кандидат):
                найдено = open(кандидат, encoding="utf-8").read().strip()
                break
        шаг(найдено == эталон, "в сборке %r, ждали %r" % (найдено, эталон))
    else:
        пропуск("папка сборки не указана или не существует")

    print("3. ресурс версии .exe")
    if exe and os.path.exists(exe):
        в_ресурсе = версия_exe(exe)
        # Windows хранит РОВНО четыре числа: 1.0.0 лежит как 1.0.0.0.
        ждём = эталон + ".0" * (4 - len(эталон.split(".")))
        шаг(в_ресурсе == ждём, "в свойствах файла %r, ждали %r"
            % (в_ресурсе, ждём))
    else:
        пропуск(".exe не найден")

    print("4. DisplayVersion в записи деинсталляции")
    в_реестре = версия_в_реестре()
    if в_реестре is None:
        пропуск("программа не установлена (записи Uninstall нет)")
    else:
        шаг(в_реестре == эталон,
            "в реестре %r, ждали %r" % (в_реестре, эталон))

    print("5. версия, которую называет сама запущенная программа")
    if args.no_window:
        пропуск("запуск программы отключён ключом --no-window")
    elif exe and os.path.exists(exe):
        сказано = версия_от_программы(exe)
        print("     программа ответила: %r" % сказано)
        # Сравнение ТОЧНОЕ, а не вхождением: раньше искали версию внутри
        # заголовка, и «1.1.9» нашлось бы внутри «11.1.90». Здесь ответ
        # состоит ровно из версии, и послаблять сравнение незачем.
        шаг(сказано == эталон, "программа называет %s" % эталон)
    else:
        пропуск(".exe не найден")

    print()
    if ПРОПУЩЕНО:
        print("ПРОПУЩЕНО (не проверено): %d" % len(ПРОПУЩЕНО))
        for т in ПРОПУЩЕНО:
            print("   -", т)
    if ПРОВАЛЫ:
        print("ПРОВАЛОВ: %d" % len(ПРОВАЛЫ))
        for т in ПРОВАЛЫ:
            print("   -", т)
        return 1
    if ПРОПУЩЕНО:
        # Пропуск — это не успех. Печатаем другой токен, чтобы гейт не
        # засчитал неполную проверку как полную.
        print("VERSION_PARTIAL")
        return 0
    print("VERSION_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
