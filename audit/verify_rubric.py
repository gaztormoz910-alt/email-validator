#!/usr/bin/env python
"""Оракул для гейтов оценки: пересчитывает итоговые баллы из их собственного разбора.

Что он доказывает, а что нет. Он НЕ может подтвердить, что оценка «правильная» —
это суждение. Он ловит другое, и это самая частая порча отчётов с числами:
заголовочная цифра, которая не сходится с разбором под ней. Если в отчёте
написано 82, а критерии дают 79 — гейт краснеет.

Дополнительно проверяется, что:
  * веса складываются ровно в 100 (иначе «взвешенная оценка» — фикция);
  * у каждого критерия есть и «за», и «против» — оценка без названного изъяна
    не оценка, а реклама;
  * оценка прокси внутри разбора софта совпадает с отдельной оценкой прокси.

Успех печатает RUBRIC OK и выходит с нулём.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def audit_block(name, block):
    weights = sum(c["weight"] for c in block["criteria"])
    check(weights == 100, f"{name}: веса критериев дают {weights}, а не 100")

    for c in block["criteria"]:
        check(0 <= c["score"] <= 100,
              f"{name}/{c['id']}: балл {c['score']} вне диапазона 0-100")
        check(c["weight"] > 0, f"{name}/{c['id']}: нулевой вес")
        check(len(c.get("why", "").strip()) >= 40,
              f"{name}/{c['id']}: аргумент «за» слишком короткий, чтобы быть доводом")
        check(len(c.get("gap", "").strip()) >= 20,
              f"{name}/{c['id']}: не назван ни один изъян — это реклама, а не оценка")

    total = sum(c["score"] * c["weight"] for c in block["criteria"]) / 100.0
    headline = block["headline"]
    check(abs(total - headline) <= 0.5,
          f"{name}: заголовочная оценка {headline}, а разбор даёт {total:.2f}")
    return total


def main():
    rubric = json.load(open(os.path.join(ROOT, "audit", "audit_rubric.json"),
                            encoding="utf-8"))

    software = audit_block("software", rubric["software"])
    proxy = audit_block("proxy", rubric["proxy"])

    # Оценка прокси входит в оценку софта отдельным критерием — они обязаны
    # совпадать, иначе один и тот же предмет получает два разных балла.
    inner = [c for c in rubric["software"]["criteria"] if c["id"] == "proxy"]
    check(len(inner) == 1, "в разборе софта нет критерия «прокси»")
    if inner:
        check(inner[0]["score"] == rubric["proxy"]["headline"],
              f"прокси в разборе софта оценены на {inner[0]['score']}, "
              f"а отдельно на {rubric['proxy']['headline']}")

    # Ни один блок не должен быть «всё отлично»: разброс баллов — признак того,
    # что критерии оценивались по отдельности, а не одним настроением.
    for name, block in (("software", rubric["software"]), ("proxy", rubric["proxy"])):
        scores = [c["score"] for c in block["criteria"]]
        check(max(scores) - min(scores) >= 10,
              f"{name}: все критерии в пределах {max(scores) - min(scores)} баллов — "
              "похоже, оценка выставлена одним махом")

    if failures:
        print(f"RUBRIC MISMATCH ({len(failures)})")
        for line in failures:
            print("  - " + line)
        return 1
    print(f"RUBRIC OK (software={software:.2f}, proxy={proxy:.2f})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
