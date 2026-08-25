#!/usr/bin/env python
"""Оракул: в пайплайне не осталось долгой блокирующей паузы.

Что именно ищется. Разбирается СИНТАКСИЧЕСКОЕ ДЕРЕВО, а не текст: grep по
"sleep(90)" не увидел бы ни `for _ in range(90): time.sleep(1)`, ни
`time.sleep(PAUSE)`. Нарушением считается любой вызов sleep, который способен
удержать поток дольше порога:

  * sleep(x) с константой x >= порога;
  * sleep внутри цикла range(n) с константой, где n * x >= порога.

Короткий сон в цикле ожидания — не нарушение: именно так и делается ожидание,
которое можно прервать кнопкой «Стоп».

Негативный контроль обязателен. Детектор, который ничего не находит, выглядит
одинаково и когда код чист, и когда он сломан. Поэтому перед проверкой боевых
файлов он запускается на заведомо плохом образце и обязан на нём сработать.

Успех печатает NO BLOCKING SLEEP и выходит с нулём.
"""

import ast
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Порог в секундах. Прогон на сотнях тысяч адресов не имеет права замирать
# дольше этого: за паузой не работает ни прогресс, ни остановка.
MAX_BLOCKING_SECONDS = 10

WATCHED = ["core/pipeline.py"]

BAD_SAMPLE = """
import time
def run():
    for _ in range(90):
        time.sleep(1)
"""

GOOD_SAMPLE = """
import time
def run(stop):
    while not stop.is_set():
        time.sleep(0.2)
"""


def _is_sleep(node):
    func = node.func
    if isinstance(func, ast.Attribute) and func.attr == "sleep":
        return True
    return isinstance(func, ast.Name) and func.id == "sleep"


def _const_number(node):
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
        return float(node.value)
    return None


def _range_count(node):
    """Число повторов цикла `for _ in range(N)`, иначе None."""
    if not isinstance(node, ast.For):
        return None
    it = node.iter
    if not (isinstance(it, ast.Call) and isinstance(it.func, ast.Name)
            and it.func.id == "range" and len(it.args) == 1):
        return None
    return _const_number(it.args[0])


def scan(source, label):
    """Список найденных блокирующих пауз в исходнике."""
    tree = ast.parse(source)
    findings = []

    # Для каждого узла помним, во сколько раз его повторяет объемлющий цикл
    multiplier = {}

    def walk(node, factor):
        for child in ast.iter_child_nodes(node):
            child_factor = factor
            count = _range_count(child)
            if count:
                child_factor = factor * count
            multiplier[child] = child_factor
            walk(child, child_factor)

    multiplier[tree] = 1.0
    walk(tree, 1.0)

    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and _is_sleep(node) and node.args):
            continue
        seconds = _const_number(node.args[0])
        if seconds is None:
            continue          # переменная — судить нечем, это не улика
        total = seconds * multiplier.get(node, 1.0)
        if total >= MAX_BLOCKING_SECONDS:
            findings.append(
                f"{label}:{node.lineno} — пауза до {total:.0f}с "
                f"(sleep({seconds:g}) × {multiplier.get(node, 1.0):g})")
    return findings


def main():
    # Негативный контроль: детектор обязан ловить заведомо плохой образец
    if not scan(BAD_SAMPLE, "<образец>"):
        print("DETECTOR BROKEN: заведомо блокирующий образец не пойман — "
              "зелёный цвет этой проверки ничего не значил бы")
        return 1
    if scan(GOOD_SAMPLE, "<образец>"):
        print("DETECTOR BROKEN: короткий прерываемый сон помечен нарушением")
        return 1

    findings = []
    for rel in WATCHED:
        path = os.path.join(ROOT, *rel.split("/"))
        with open(path, "r", encoding="utf-8") as handle:
            findings.extend(scan(handle.read(), rel))

    if findings:
        print(f"BLOCKING SLEEP FOUND ({len(findings)})")
        for line in findings:
            print("  - " + line)
        return 1
    print(f"NO BLOCKING SLEEP (порог {MAX_BLOCKING_SECONDS}с, файлов: {len(WATCHED)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
