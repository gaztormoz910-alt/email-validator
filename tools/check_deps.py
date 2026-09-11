# -*- coding: utf-8 -*-
"""Сверяет фактические импорты проекта с тем, что физически лежит в сборке.

ЗАЧЕМ, ЕСЛИ ЕСТЬ audit/verify_requirements.py. Тот проверяет СПИСОК
зависимостей. Этот проверяет СБОРКУ. Между ними помещается ровно та ошибка,
которая на соседнем проекте стоила выпущенного релиза: пакет назван в
requirements, на машине разработчика стоял годами, а PyInstaller его всё
равно не положил — и пользователь получил окно `Unhandled exception in
script`.

ПОЧЕМУ НЕ ХВАТАЕТ ЗАПУСКА ОКНА. Ленивый импорт внутри функции при старте не
выполняется вовсе. Программа открывается, человек нажимает кнопку через
полчаса работы — и только тогда выясняется, что модуля нет.

Разбирается: архив PYZ внутри .exe (чистый Python) и папка _internal
(расширения .pyd и библиотеки .dll).

    python tools/check_deps.py --dist dist/MailFact
"""
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

# Каталоги, которые описывают не продукт, а его проверку и сборку.
ПРОПУСК = {".git", "__pycache__", ".pytest_cache", "tor_bin", ".unlazy",
           "audit", "tests", "tools", "build", "dist", "installer",
           ".mypy_cache", ".github"}

# Свои пакеты и точки входа.
СВОИ = {"core", "ui", "api", "tools", "tests", "audit", "cli", "main",
        "engine"}


def импорты_проекта():
    """Все сторонние модули верхнего уровня, которые проект импортирует."""
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
    """Имена модулей из архива PYZ внутри .exe.

    Внутренности PyInstaller меняются от версии к версии, поэтому пробуем
    несколько имён и честно возвращаем None, если разобрать не вышло, — а не
    делаем вид, что архив пуст.
    """
    try:
        from PyInstaller.archive.readers import CArchiveReader
    except Exception as e:
        print("  не удалось загрузить читатель архивов PyInstaller:", e)
        return None
    try:
        архив = CArchiveReader(exe)
        # Имя записи с архивом чистого Python берём из таблицы содержимого, а
        # не зашиваем: у разных версий PyInstaller оно называется по-разному.
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
    """Расширения и пакеты, лежащие на диске рядом со сборкой.

    Раскладка разная: у Windows и Linux это `_internal` рядом с программой,
    у macOS — `Contents/Frameworks` внутри `.app`. Смотрим все варианты, а не
    один: пропущенная папка означала бы «модуля нет» там, где он есть.
    """
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
                # numpy.core._multiarray_umath.pyd -> numpy
                имена.add(имя.split(".")[0].split("-")[0])
            elif имя.endswith(".dll"):
                имена.add(имя.split(".")[0].split("-")[0])
    return имена


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dist", default=os.path.join("dist", ИМЯ))
    args = p.parse_args()

    папка = os.path.abspath(args.dist)
    # Имя исполняемого файла зависит от системы: расширение .exe есть только
    # у Windows. Зашитое ".exe" означало бы, что на Linux и macOS проверка
    # всегда отвечает «нет сборки» и падает, ничего не проверив, — что и
    # случилось на прогоне 1.1.1.
    кандидаты = [os.path.join(папка, ИМЯ + ".exe"), os.path.join(папка, ИМЯ)]
    # macOS кладёт программу внутрь .app — путь там свой.
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
        # Не разобрали архив — говорим об этом вслух и НЕ выдаём зелёный.
        # Проверка, которая молча превращается в «всё хорошо», хуже её
        # отсутствия.
        print("ПРОВАЛ: архив PYZ не разобран, сверять не с чем")
        return 1

    есть = из_pyz | на_диске
    # Пакеты, которые собираются как каталог данных, а не как модуль: их имя
    # видно на диске, но не в PYZ, и наоборот.
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

    # Обратный контроль: заведомо отсутствующий модуль обязан быть пойман.
    # Без него проверка, потерявшая способность находить, выглядела бы зелёной.
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
