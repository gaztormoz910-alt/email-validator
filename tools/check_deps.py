# -*- coding: utf-8 -*-
import argparse
import ast
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ИМЯ = "MailFact"

ПРОПУСК = {".git", "__pycache__", ".pytest_cache", "tor_bin",
           "audit", "tests", "tools", "build", "dist", "installer",
           ".mypy_cache", ".github"}

СВОИ = {"core", "ui", "api", "tools", "tests", "audit", "cli", "main",
        "engine"}

БЭКЕНД_ОКНА = {
    "win32": ["clr"],
    "darwin": ["objc"],
    "linux": ["PyQt6"],
}


def нужный_бэкенд(папка):
    for ключ, модули in БЭКЕНД_ОКНА.items():
        if sys.platform.startswith(ключ):
            return модули
    return []


def импорты_проекта():
    найдено = set()
    for каталог, папки, файлы in os.walk(КОРЕНЬ):
        папки[:] = [d for d in папки if d not in ПРОПУСК]
        for имя in файлы:
            if not имя.endswith(".py"):
                continue
            путь = os.path.join(каталог, имя)
            try:
                with open(путь, "r", encoding="utf-8") as f:
                    дерево = ast.parse(f.read(), путь)
            except Exception:
                continue
            for узел in ast.walk(дерево):
                if isinstance(узел, ast.Import):
                    for a in узел.names:
                        найдено.add(a.name.split(".")[0])
                elif (isinstance(узел, ast.ImportFrom) and узел.level == 0
                        and узел.module):
                    найдено.add(узел.module.split(".")[0])
    return {m for m in найдено
            if m not in СВОИ and m not in sys.stdlib_module_names}


def модули_в_pyz(exe):
    try:
        from PyInstaller.archive.readers import CArchiveReader
    except Exception as e:
        print("  не удалось загрузить читатель архивов PyInstaller:", e)
        return None
    try:
        архив = CArchiveReader(exe)
        имена = [k for k in архив.toc
                 if isinstance(k, str) and k.upper().endswith(".PYZ")]
        if not имена:
            print("  в таблице содержимого нет записи PYZ")
            return None
        внутренний = архив.open_embedded_archive(имена[0])
    except Exception as e:
        print("  не удалось открыть архив внутри .exe:", e)
        return None

    for имя in ("toc", "_toc", "contents"):
        toc = getattr(внутренний, имя, None)
        if toc is None:
            continue
        try:
            ключи = list(toc.keys()) if hasattr(toc, "keys") else list(toc)
        except Exception:
            continue
        имена = set()
        for k in ключи:
            if isinstance(k, (tuple, list)):
                k = k[0]
            if isinstance(k, str):
                имена.add(k.split(".")[0])
        if имена:
            return имена
    print("  таблица содержимого архива не разобрана")
    return None


def модули_в_internal(папка):
    имена = set()
    варианты = [os.path.join(папка, "_internal"),
                os.path.join(папка, "Contents", "Frameworks"),
                os.path.join(папка, "Contents", "Resources")]
    корни = [папка] + [в for в in варианты if os.path.isdir(в)]
    for корень in корни:
        try:
            записи = os.listdir(корень)
        except OSError:
            continue
        for имя in записи:
            путь = os.path.join(корень, имя)
            if os.path.isdir(путь):
                имена.add(имя)
            elif имя.endswith((".pyd", ".so")):
                имена.add(имя.split(".")[0].split("-")[0])
            elif имя.endswith(".dll"):
                имена.add(имя.split(".")[0].split("-")[0])
    return имена


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dist", default=os.path.join("dist", ИМЯ))
    args = p.parse_args()

    папка = os.path.abspath(args.dist)
    кандидаты = [os.path.join(папка, ИМЯ + ".exe"), os.path.join(папка, ИМЯ)]
    кандидаты.append(os.path.join(папка, ИМЯ + ".app", "Contents", "MacOS", ИМЯ))
    exe = next((к for к in кандидаты
                if os.path.isfile(к) and os.access(к, os.X_OK)), None)
    if exe is None:
        print("нет сборки, искал:")
        for к in кандидаты:
            print("   -", к)
        return 1
    print("исполняемый файл:", exe)

    нужны = импорты_проекта()
    print("сторонних модулей в исходниках: %d" % len(нужны))
    print("  " + ", ".join(sorted(нужны)))

    из_pyz = модули_в_pyz(exe)
    на_диске = модули_в_internal(папка)
    print("модулей в архиве PYZ: %s"
          % ("не разобрано" if из_pyz is None else len(из_pyz)))
    print("имён рядом со сборкой: %d" % len(на_диске))

    if из_pyz is None:
        print("ПРОВАЛ: архив PYZ не разобран, сверять не с чем")
        return 1

    есть = из_pyz | на_диске
    нет = sorted(m for m in нужны if m not in есть)

    print()
    if нет:
        print("НЕ НАЙДЕНО В СБОРКЕ (%d):" % len(нет))
        for m in нет:
            print("   -", m)
        return 1

    for m in sorted(нужны):
        где = []
        if m in из_pyz:
            где.append("PYZ")
        if m in на_диске:
            где.append("_internal")
        print("  ok   %-18s %s" % (m, "+".join(где)))

    print()
    плохо_бэкенда = 0
    нужны_бэкенды = нужный_бэкенд(папка)
    print("движок окна для %s: %s" % (sys.platform, нужны_бэкенды or "не задан"))
    for м in нужны_бэкенды:
        есть_он = м in есть
        if not есть_он:
            плохо_бэкенда += 1
        print("  %s %-18s %s" % ("ok  " if есть_он else "НЕТ ", м,
                                 "найден в сборке" if есть_он
                                 else "В СБОРКЕ НЕТ — окно не откроется"))
    if плохо_бэкенда:
        print("ПРОВАЛ: движка окна в сборке нет, программа не покажет окно")
        return 1

    выдуманный = "заведомо-отсутствующий-модуль"
    if выдуманный in есть:
        print("ДЕТЕКТОР СЛОМАН: находит несуществующее")
        return 1
    print("  ok   обратный контроль: выдуманный модуль не находится")

    print()
    print("DEPS_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
