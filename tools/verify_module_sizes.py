#!/usr/bin/env python
# -*- coding: utf-8 -*-
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

LINE_BUDGET = 1500
FOLDERS = ("core", "core/parser", "ui", "api", "tools", "tests")


def measure(root=ROOT):
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
