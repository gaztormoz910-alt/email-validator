#!/usr/bin/env python
"""Оракул: окно валидатора строится целиком на настоящем Tk.

Зачем именно так. Импорт ui.gui доказывает только то, что файл разбирается.
Половина ошибок интерфейса живёт не в синтаксисе, а в сборке: обращение к
виджету, который ещё не создан, опечатка в имени цвета, перепутанный
менеджер геометрии. Всё это всплывает лишь тогда, когда окно действительно
создаётся, — поэтому здесь оно и создаётся, прогоняется по всем вкладкам и
закрывается.

Окно намеренно не показывается: withdraw() убирает его с экрана, но виджеты
при этом создаются полностью, и update() прогоняет очередь событий Tk.

Панель прокси проверяется на РЕАЛЬНОЙ сводке, собранной core/proxy_profile.py,
а не на выдуманном словаре: иначе панель могла бы разойтись с тем, что ей
действительно приходит из пайплайна.

Успех печатает GUI OK и выходит с нулём.
"""

import os
import sys
import traceback

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def main():
    try:
        import tkinter
        tkinter.Tk().destroy()
    except Exception as exc:
        # Без дисплея проверка не имеет смысла, но и «зелёной» быть не должна:
        # непроверенное окно — это непроверенное окно.
        print(f"GUI UNCHECKED: Tk недоступен ({type(exc).__name__}) — "
              "сборку окна проверить нечем")
        return 1

    from core.proxy_profile import pool_summary
    from ui.gui import ValidatorApp

    app = None
    try:
        app = ValidatorApp()
        app.withdraw()
        app.update()

        # Реальная сводка того же вида, что приходит из пайплайна
        summary = pool_summary({
            "a:1": {"exit_ip": "1.1.1.1", "has_ptr": True, "latency_ms": 120,
                    "asn_country": "DE", "ip_type": "datacenter", "outlook_ok": True},
            "b:2": {"exit_ip": "1.1.1.1", "has_ptr": True, "latency_ms": 240,
                    "asn_country": "DE", "ip_type": "datacenter"},
            "c:3": {"exit_ip": "2.2.2.2", "has_ptr": False, "in_dnsbl": True,
                    "latency_ms": 90, "asn_country": "US", "ip_type": "residential",
                    "rdns_dirty": True},
            "d:4": {"exit_ip": None, "has_ptr": None},
        })
        app._store_proxy_summary(summary)

        for tab in ("Результаты", "Прокси", "Терминал"):
            app._switch_tab(tab)
            app.update()

        # Панель обязана показать именно то, что посчитала сводка
        app._switch_tab("Прокси")
        app.update()
        shown = app.proxy_cards.get("rotation")
        if not shown:
            print("GUI BROKEN: панель прокси не построила плитку ротации")
            return 1
        expected = f"{summary['unique_ips']} / {summary['total']}"
        actual = shown[0].cget("text")
        if actual != expected:
            print(f"GUI BROKEN: ротация показана как {actual!r}, а сводка даёт {expected!r}")
            return 1

        # Поток результатов через настоящий тик интерфейса
        for i in range(500):
            app.safe_add_result(f"u{i}@example.com",
                                "Valid" if i % 3 else "Invalid/Bounce",
                                "250 OK", "mx.example.com",
                                {"engagement_score": 80, "name": f"U{i}"})
        app._poll_validator_queues()
        app.update()

        counts = app.result_store.counts()
        if counts["total"] != 500:
            print(f"GUI BROKEN: из 500 результатов в хранилище дошло {counts['total']}")
            return 1

        app._switch_tab("Результаты")
        app.update()
        rows = len(app.tree.get_children())
        if rows == 0:
            print("GUI BROKEN: таблица пуста, хотя результаты есть")
            return 1

        # Переключатель режима страны обязан действительно двигать пороги, а не
        # просто перекрашиваться: раньше этот выбор был правкой исходника.
        import core.parser.ml_predictor as MP
        app._on_country_mode_change("Точность")
        app.update()
        if (MP.NAME_COUNTRY_MIN_SHARE, MP.NAME_COUNTRY_MIN_RATIO) != MP.COUNTRY_MODES["accuracy"]:
            print("GUI BROKEN: переключатель «Точность» не поменял пороги страны")
            return 1
        app._on_country_mode_change("Заполненность")
        app.update()
        if (MP.NAME_COUNTRY_MIN_SHARE, MP.NAME_COUNTRY_MIN_RATIO) != MP.COUNTRY_MODES["coverage"]:
            print("GUI BROKEN: переключатель не вернулся в режим заполненности")
            return 1

        # --- Замер отзывчивости под нагрузкой ------------------------------
        #
        # Главное обещание переделки: окно не замирает на большой базе. Здесь
        # оно проверяется в лоб — через настоящий тик интерфейса прогоняются
        # десятки тысяч результатов, и меряется, сколько занимает САМЫЙ долгий
        # тик. Раньше стоимость тика росла вместе с базой (перебор всех строк
        # ради одной страницы), поэтому важен именно максимум, а не среднее.
        import time

        app._switch_tab("Результаты")
        app.update()

        worst = 0.0
        ticks = 0
        for batch in range(20):
            for i in range(1000):
                app.safe_add_result(
                    f"load{batch}_{i}@example.com", "Valid", "250 OK",
                    "mx.example.com", {"engagement_score": 75, "name": "X"})
            started = time.perf_counter()
            app._poll_validator_queues()
            app.update()
            worst = max(worst, time.perf_counter() - started)
            ticks += 1

        total_rows = app.result_store.counts()["total"]
        if total_rows < 20000:
            print(f"GUI BROKEN: из 20000 результатов дошло {total_rows}")
            return 1

        # Порог щедрый: даже 0.25с на тик — это ещё отзывчивое окно, а старое
        # поведение на 20k строк давало на порядок больше.
        if worst > 0.25:
            print(f"GUI SLOW: самый долгий тик занял {worst * 1000:.0f} мс "
                  f"на базе в {total_rows} строк — окно будет подтормаживать")
            return 1

        print(f"GUI OK (вкладок: 3, строк в таблице: {rows}, ротация: {actual}; "
              f"нагрузка: {total_rows} результатов за {ticks} тиков, "
              f"худший тик {worst * 1000:.0f} мс)")
        return 0
    except Exception:
        print("GUI BROKEN: окно не собралось")
        traceback.print_exc()
        return 1
    finally:
        if app is not None:
            try:
                app.destroy()
            except Exception:
                pass


if __name__ == "__main__":
    sys.exit(main())
