#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Ни один модуль проекта не длиннее бюджета строк.

Зачем это гейт, а не совет. Монолит не появляется сразу — он отрастает по
пятьдесят строк за правку, и заметить это по диффу невозможно. Единственное,
что реально держит границу, — проверка, которая падает.

Бюджет в 1500 строк выбран не из красоты: это примерно тот размер, при
котором файл ещё читается целиком за один заход. network.py на 2858 строках и
gui.py на 2227 читались уже только грепом, и оба были названы монолитами в
двух аудитах подряд.

ПОЧЕМУ ФАЙЛ ЛЕЖИТ ЗДЕСЬ, А НЕ В .unlazy/. Раньше задание CI звало его по пути
`.unlazy/precision/verify_module_sizes.py`, а `.unlazy/` числится в
`.gitignore` — то есть на машине разработчика файл был, а после `checkout` в
CI его не было, и задание падало с «файл не найден» на каждом прогоне. Это
не находило монолитов и не могло их найти: проверка не доходила до кода.
Провал выглядел как работающий гейт, что хуже отсутствующего гейта.
"""
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Два подъёма: tools/verify_module_sizes.py -> tools -> корень репозитория.
# В прежнем месте (.unlazy/precision/) подъёмов было три, и переносить файл,
# не поправив эту строку, значило бы считать размеры в родительской папке.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LINE_BUDGET = 1500
FOLDERS = ("core", "core/parser", "ui", "api", "tools", "tests")


def measure(root=ROOT):
    """Возвращает (список превысивших, сколько модулей посчитано)."""
    oversized = []
    counted = 0
    for folder in FOLDERS:
        directory = os.path.join(root, folder)
        if not os.path.isdir(directory):
            continue
        for name in sorted(os.listdir(directory)):
            if not name.endswith(".py"):
                continue
            path = os.path.join(directory, name)
            with open(path, "rb") as handle:
                lines = sum(1 for _ in handle)
            counted += 1
            if lines > LINE_BUDGET:
                oversized.append((f"{folder}/{name}", lines))
    return oversized, counted


def main():
    oversized, counted = measure()

    for path, lines in oversized:
        print(f"[МОНОЛИТ] {path}: {lines} строк (бюджет {LINE_BUDGET})")

    if not counted:
        # Пустой результат — это сломанная проверка, а не успех. Именно так
        # выглядел бы неверный ROOT после переноса файла.
        print("модулей не найдено — проверка ничего не измерила")
        return 1
    if oversized:
        print(f"\nПревысили бюджет: {len(oversized)} из {counted}")
        return 1

    print(f"Проверено модулей: {counted}; ни один не длиннее {LINE_BUDGET} строк.")
    print("MODULE-SIZES-OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
