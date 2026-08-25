#!/usr/bin/env python
"""Оракул для гейта обогащения: измеряет цепочку имя -> страна -> пол.

Проверяется не наличие кода, а результат на конкретных адресах. Отдельно
измеряется САМОЕ СЛАБОЕ место цепочки — страна по имени: пороги там выставлены
в ноль осознанно, то есть колонка заполняется всегда, но частью выдумкой.
Гейт обязан это подтверждать, а не заминать: если пороги молча вернут,
цифры в отчёте станут неверными, и он покраснеет.

Успех печатает ENRICH OK и выходит с нулём.
"""

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

failures = []


def check(cond, msg):
    if not cond:
        failures.append(msg)


def main():
    from core.parser.name_extractor import NameExtractor
    from core.parser.ml_predictor import (MLPredictor, NAME_COUNTRY_MIN_SHARE,
                                          NAME_COUNTRY_MIN_RATIO)
    from core.parser.names_index import is_known_name
    from core.parser.translit import variants
    from core.provider import country_from_domain, country_from_location

    # --- Имя из структуры адреса ---------------------------------------------
    ex = NameExtractor(enable_osint=False)
    cases = {
        "john.doe@gmail.com": "John Doe",
        "robertanderson@gmail.com": "Robert Anderson",
        "sarah.jones91@outlook.com": "Sarah Jones",
        "mohammedlahlali@yahoo.fr": "Mohammed Lahlali",
    }
    for email, expected in cases.items():
        got = ex.extract_name(email)
        check(got == expected, f"имя из {email}: ожидалось {expected!r}, получено {got!r}")

    # Ролевые и организации именем становиться не должны
    for email in ("info@corp.com", "support@corp.com", "noreply@corp.com"):
        got = ex.extract_name(email)
        check(not got, f"ролевой {email} превращён в имя {got!r}")

    # --- Транслит: одно имя, разные написания --------------------------------
    v = set(variants("dmitriy"))
    check(len(v) > 1, "транслит не порождает вариантов написания")

    # --- Локальный индекс имён ----------------------------------------------
    check(is_known_name("wolfgang"), "популярное имя не найдено в индексе")
    check(not is_known_name("zzzqqxk"), "мусор найден в индексе имён")

    # --- Страна: домен решает раньше имени -----------------------------------
    check(country_from_domain("web.de") == "Германия", "web.de -> не Германия")
    check(country_from_domain("gmail.com") == "", "gmail.com выдал страну, хотя не знает её")
    check(country_from_location("Berlin, Germany") == "Германия",
          "локация Gravatar не разбирается")

    # --- Пол: страна снимает неоднозначность ---------------------------------
    ml = MLPredictor(enable_ml=False)
    check(ml.gender_detector is not None,
          "словарь пола не загружен при выключенном ИИ — колонка «Пол» будет пустой")
    check(ml.predict_gender("John") == "Мужской", "John не определён как мужчина")
    check(ml.predict_gender("Sarah") == "Женский", "Sarah не определена как женщина")
    # Унисекс не выдумывается: пустая клетка честнее неверного пола
    check(ml.predict_gender("Zzzqqxk") == "", "неизвестному имени приписан пол")
    andrea_it = ml.predict_gender("Andrea", "Италия")
    andrea_de = ml.predict_gender("Andrea", "Германия")
    check(andrea_it == "Мужской",
          f"Andrea в Италии определена как {andrea_it!r}, а не мужчина")
    check(andrea_it != andrea_de,
          "страна не влияет на пол неоднозначного имени — выигрыш точности потерян")

    # --- Страна по имени: пороги выключены осознанно -------------------------
    # Это доказательство слабого места, а не его отсутствия.
    check(NAME_COUNTRY_MIN_SHARE == 0.0 and NAME_COUNTRY_MIN_RATIO == 0.0,
          "пороги страны по имени не нулевые — цифры точности в отчёте устарели")
    # Само распределение по странам живёт в базе имён, а она грузится только
    # вместе с ИИ. Берём отдельный предиктор, иначе проверять было бы нечего.
    ml_full = MLPredictor(enable_ml=True)
    if ml_full.nd is not None:
        leader, share, second = ml_full.country_distribution("Ivan")
        check(bool(leader), "распределение имени Ivan по странам пустое")
        check(share < 0.5,
              f"доля страны-лидера у Ivan {share:.3f} — отчёт утверждает, что "
              "распределение размазано, а оно уверенное")
        check(share < second * 2.0 if second else True,
              f"лидер у Ivan отрывается от второго более чем вдвое "
              f"({share:.3f} против {second:.3f}) — утверждение отчёта неверно")
        # Ненулевые пороги отсекли бы такое имя; нулевые — заполняют колонку
        check(ml_full.predict_country("Ivan") != "",
              "при нулевых порогах страна по имени всё равно пустая")
    else:
        check(False, "база имён не установлена — глубину обогащения измерить нечем")

    if failures:
        print(f"ENRICH MISMATCH ({len(failures)})")
        for line in failures:
            print("  - " + line)
        return 1
    print("ENRICH OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
