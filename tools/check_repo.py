# -*- coding: utf-8 -*-
import os
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

СБОРОЧНОЕ = ("core/", "ui/", "api/", "assets/", "data/", "main.py", "cli.py",
             "VERSION", "MailFact.spec", "MailFact.iss", "version_info.txt",
             "requirements.txt", ".github/workflows/")

ПРОВАЛЫ = []


def шаг(ок, текст):
    print("  %s %s" % ("ok  " if ок else "НЕТ ", текст))
    if not ок:
        ПРОВАЛЫ.append(текст)
    return ок


def git(*args):
    готово = subprocess.run(["git"] + list(args), cwd=КОРЕНЬ,
                            capture_output=True, text=True,
                            encoding="utf-8", errors="replace")
    return готово.returncode, готово.stdout.strip(), готово.stderr.strip()


def main():
    версия = open(os.path.join(КОРЕНЬ, "VERSION"),
                  encoding="utf-8").read().strip()
    тег = "v" + версия
    print("версия: %s, ожидаемый тег: %s" % (версия, тег))

    print("1. рабочее дерево")
    код, вывод, _ = git("status", "--porcelain")
    if вывод:
        print("     незакоммиченное:")
        for строка in вывод.splitlines()[:20]:
            print("       ", строка)
    шаг(код == 0 and not вывод, "дерево чистое")

    print("2. ветка запушена")
    _, ветка, _ = git("rev-parse", "--abbrev-ref", "HEAD")
    _, head, _ = git("rev-parse", "HEAD")
    print("     ветка: %s, HEAD: %s" % (ветка, head[:12]))
    _, удалённые, _ = git("remote")
    список = [r for r in удалённые.splitlines() if r.strip()]
    шаг(bool(список), "удалённые репозитории есть: %s" % (список or "нет"))
    for remote in список:
        код, вывод, ошибка = git("ls-remote", remote, "refs/heads/" + ветка)
        если_есть = вывод.split("\t")[0] if вывод else ""
        шаг(если_есть == head,
            "%s/%s = %s (локально %s)" % (remote, ветка,
                                          если_есть[:12] or "НЕТ ВЕТКИ",
                                          head[:12]))

    print("3. тег версии")
    код, коммит_тега, _ = git("rev-parse", "refs/tags/" + тег + "^{}")
    if код != 0:
        шаг(False, "тега %s нет" % тег)
        коммит_тега = None
    else:
        шаг(True, "тег %s -> коммит %s" % (тег, коммит_тега[:12]))
        for remote in список:
            _, вывод, _ = git("ls-remote", remote, "refs/tags/" + тег)
            шаг(bool(вывод), "тег %s есть на %s" % (тег, remote))

    print("4. содержимое сборки: тег против HEAD")
    if not коммит_тега:
        шаг(False, "сверять не с чем: тега нет")
    elif коммит_тега == head:
        шаг(True, "тег стоит ровно на HEAD, сверять нечего")
    else:
        код, вывод, _ = git("diff", "--name-only", коммит_тега, "HEAD")
        изменено = [f for f in вывод.splitlines() if f.strip()]
        сборочные = [f for f in изменено
                     if any(f.startswith(p) for p in СБОРОЧНОЕ)]
        print("     файлов разошлось всего: %d, из них сборочных: %d"
              % (len(изменено), len(сборочные)))
        for f in сборочные[:15]:
            print("       ", f)
        шаг(not сборочные,
            "сборочные файлы у тега и у HEAD совпадают")

    print()
    if ПРОВАЛЫ:
        print("ПРОВАЛОВ: %d" % len(ПРОВАЛЫ))
        for т in ПРОВАЛЫ:
            print("   -", т)
        return 1
    print("REPO_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
