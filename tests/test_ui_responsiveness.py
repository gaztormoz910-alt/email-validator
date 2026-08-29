"""Отзывчивость интерфейса: измеряем, а не обещаем.

Главная проверка здесь — `paging`. Она не засекает время (на загруженной
машине это гадание), а СЧИТАЕТ, сколько строк интерфейс трогает, чтобы
показать одну страницу. Старый код трогал всю базу целиком на каждом тике;
новый обязан трогать порядка размера страницы независимо от того, сто в базе
адресов или сто тысяч.

У проверки есть положительный контроль: тот же счётчик прогоняется по старому
способу выборки, и тест требует, чтобы он СРАБОТАЛ на нём. Без этого счётчик,
случайно перестав считать, сделал бы всю проверку зелёной и бессмысленной.
"""
import os
import statistics
import sys
import threading
import time
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ui.result_store import ResultStore, group_of, GROUPS
from ui.log_buffer import LogBuffer, Throttle
from core.proxy_profile import pool_summary, provider_fitness

# Берём НАСТОЯЩИЙ метод окна, а не его копию: проверка обязана ломаться,
# если защиту из окна уберут. Само окно поднимать незачем — метод не
# зависит ни от чего, кроме after().
from ui.gui import ValidatorApp
ValidatorAppUiCall = ValidatorApp._ui_call


def _new_window():
    """Пустое окно тем же способом, каким его создаёт программа."""
    import customtkinter as ctk
    root = ctk.CTk()
    root.withdraw()
    return root


class CountingStore(ResultStore):
    """Хранилище, считающее, сколько СТРОК оно на самом деле достало.

    Раньше здесь подменялся внутренний список `_rows`. Списка больше нет:
    содержимое строк уехало в SQLite, чтобы память не росла вместе с базой,
    а в ОЗУ остались только позиции. Считать теперь надо не обращения к
    списку, а поднятые строки — это ровно та же величина «сколько работы
    стоил показ» и она не зависит от того, где строки лежат.
    """

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.rows_fetched = 0

    def _fetch(self, positions):
        self.rows_fetched += len(positions)
        return super()._fetch(positions)


def build(store, count, status="Valid", score=90):
    for i in range(count):
        store.append(f"user{i}@example.com", status, "250 OK", "mx.example.com",
                     {"engagement_score": score, "name": f"User{i}"})


class TestPagingCost(unittest.TestCase):
    """Стоимость показа страницы не должна расти вместе с базой."""

    def _reads_for_first_page(self, size):
        store = CountingStore()
        self.addCleanup(store.close)
        build(store, size)
        rows = store.page(("valid",), page=1, size=100)
        self.assertEqual(len(rows), 100)
        return store.rows_fetched

    def test_paging_cost_is_independent_of_base_size(self):
        small = self._reads_for_first_page(1000)
        large = self._reads_for_first_page(100000)
        self.assertLessEqual(small, 120, "даже на малой базе трогается лишнее")
        self.assertLessEqual(
            large, 120,
            f"на базе в 100k строк для одной страницы поднято {large} строк — "
            "стоимость показа зависит от размера базы")
        self.assertLessEqual(
            large, small * 2,
            f"стоимость выросла с {small} до {large} при росте базы в 100 раз")

    def test_positive_control_old_approach_would_be_caught(self):
        """Счётчик обязан ловить старый способ — иначе он ничего не проверяет."""
        store = CountingStore()
        self.addCleanup(store.close)
        build(store, 5000)
        # Ровно то, что делал прежний _get_filtered_results: перебор ВСЕЙ базы
        filtered = [row for row in store.all_rows()
                    if row["status"] == "Valid"][:100]
        self.assertEqual(len(filtered), 100)
        self.assertGreater(
            store.rows_fetched, 1000,
            "положительный контроль не сработал: счётчик не видит полный перебор, "
            "значит и основную проверку он не доказывает")

    def test_deep_page_still_returns_right_rows(self):
        store = ResultStore()
        self.addCleanup(store.close)
        build(store, 5000)
        page_one = store.page(("valid",), page=1, size=100)
        page_ten = store.page(("valid",), page=10, size=100)
        self.assertEqual(page_one[0]["email"], "user0@example.com")
        self.assertEqual(page_ten[0]["email"], "user900@example.com")
        self.assertEqual(len(page_ten), 100)


class TestStatsAreCheap(unittest.TestCase):
    """Счётчики берутся готовыми, а не пересчитываются перебором."""

    def test_counts_do_not_scan_rows(self):
        store = CountingStore()
        self.addCleanup(store.close)
        build(store, 20000)
        counts = store.counts()
        self.assertEqual(counts["valid"], 20000)
        self.assertEqual(counts["total"], 20000)
        self.assertEqual(counts["names"], 20000)
        self.assertEqual(store.rows_fetched, 0,
                         "счётчики перебирают строки, хотя должны быть готовыми")

    def test_matching_count_without_score_filter_is_free(self):
        store = CountingStore()
        self.addCleanup(store.close)
        build(store, 20000)
        self.assertEqual(store.matching_count(("valid",)), 20000)
        self.assertEqual(store.rows_fetched, 0,
                         "подсчёт подходящих строк без порога всё ещё перебирает базу")

    def test_stats_updates_are_throttled(self):
        clock = {"t": 0.0}
        throttle = Throttle(0.5, clock=lambda: clock["t"])
        allowed = 0
        # Тысяча результатов приходит за полсекунды — как на реальном прогоне
        for i in range(1000):
            clock["t"] += 0.0005
            if throttle.ready():
                allowed += 1
        self.assertLessEqual(allowed, 3,
                             f"за 0.5с обновление счётчиков прошло {allowed} раз — "
                             "интерфейс дёргает виджеты на каждом адресе")
        self.assertGreaterEqual(allowed, 1, "обновление не прошло ни разу")


class TestLogBuffer(unittest.TestCase):
    """Терминал не растёт бесконечно и не теряет строки молча."""

    def test_log_buffer_is_capped(self):
        buf = LogBuffer(capacity=500)
        for i in range(100000):
            buf.put(f"строка {i}", "info")
        self.assertLessEqual(len(buf), 500,
                             "буфер лога не ограничен — на большой базе он съест память")
        self.assertEqual(buf.total, 100000)
        self.assertGreater(buf.dropped, 0, "потери строк не считаются")

    def test_log_drain_returns_and_empties(self):
        buf = LogBuffer(capacity=100)
        for i in range(10):
            buf.put(f"строка {i}")
        chunk = buf.drain()
        self.assertEqual(len(chunk), 10)
        self.assertEqual(len(buf), 0)
        self.assertEqual(chunk[0], ("строка 0", "info"))

    def test_log_drain_respects_limit(self):
        buf = LogBuffer(capacity=100)
        for i in range(50):
            buf.put(f"строка {i}")
        chunk = buf.drain(limit=20)
        self.assertEqual(len(chunk), 20)
        self.assertEqual(len(buf), 30, "остаток должен дождаться следующего тика")


class TestStatusGrouping(unittest.TestCase):
    """Группы фильтра описаны в одном месте и покрывают все статусы пайплайна."""

    def test_known_statuses_map_to_expected_groups(self):
        cases = {
            "Valid": "valid",
            "Invalid/Bounce": "invalid",
            "Trap/Disposable": "spam",
            "Role-based": "spam",
            # Risky — это «не доказано», а не спам. Пока он лежал в spam,
            # карточка «Спам / Ловушки» показывала 58 при шести настоящих
            # ловушках, и владелец принимал по этому числу решение о рассылке.
            "Risky": "unknown",
            "Unknown": "unknown",
            "Unverified": "other",
        }
        for status, expected in cases.items():
            self.assertEqual(group_of(status), expected, f"статус {status}")

    def test_risky_is_never_counted_as_spam(self):
        """Отдельно и явно: смешение прямо влияет на решение о рассылке."""
        self.assertNotEqual(group_of("Risky"), "spam")
        self.assertEqual(group_of("Risky"), group_of("Unknown"),
                         "Risky и Unknown одинаково означают «вердикта нет»")

    def test_things_that_must_never_be_sent_stay_together(self):
        for status in ("Trap/Disposable", "Role-based"):
            self.assertEqual(group_of(status), "spam", f"статус {status}")

    def test_every_group_is_declared(self):
        for status in ("Valid", "Invalid/Bounce", "Trap/Disposable",
                       "Role-based", "Risky", "Unknown", "Unverified"):
            self.assertIn(group_of(status), GROUPS)

    def test_garbage_status_does_not_crash(self):
        for junk in (None, 123, [], {}, b"x"):
            self.assertIn(group_of(junk), GROUPS)

    def test_mixed_groups_keep_arrival_order(self):
        store = ResultStore()
        store.append("a@x.com", "Valid", "", "", {})
        store.append("b@x.com", "Unknown", "", "", {})
        store.append("c@x.com", "Valid", "", "", {})
        rows = store.page(("valid", "unknown"), page=1, size=10)
        self.assertEqual([r["email"] for r in rows],
                         ["a@x.com", "b@x.com", "c@x.com"],
                         "слияние групп перепутало порядок добавления")


class TestScoreFilter(unittest.TestCase):
    def test_score_filter_selects_and_stops_early(self):
        store = ResultStore()
        for i in range(2000):
            store.append(f"u{i}@x.com", "Valid", "", "",
                         {"engagement_score": 90 if i % 2 == 0 else 10})
        rows = store.page(("valid",), page=1, size=50, min_score=70)
        self.assertEqual(len(rows), 50)
        self.assertTrue(all(r["data"]["engagement_score"] >= 70 for r in rows))
        self.assertEqual(store.matching_count(("valid",), min_score=70), 1000)

    def test_broken_score_does_not_crash_filter(self):
        store = ResultStore()
        store.append("a@x.com", "Valid", "", "", {"engagement_score": "мусор"})
        store.append("b@x.com", "Valid", "", "", {"engagement_score": 80})
        rows = store.page(("valid",), page=1, size=10, min_score=50)
        self.assertEqual([r["email"] for r in rows], ["b@x.com"])


class TestProxyPanelData(unittest.TestCase):
    """Панель прокси показывает измеренное, а не пересказанное.

    Числа для неё считает core/proxy_profile.pool_summary — тот же код,
    который наполняет лог и CLI. Проверяем здесь именно его: если панель
    начнёт считать что-то своё, эти проверки перестанут её описывать.
    """

    def _pool(self):
        return {
            "a:1": {"exit_ip": "1.1.1.1", "has_ptr": True, "latency_ms": 120,
                    "asn_country": "de", "ip_type": "datacenter", "outlook_ok": True},
            "b:2": {"exit_ip": "1.1.1.1", "has_ptr": True, "latency_ms": 240,
                    "asn_country": "DE", "ip_type": "datacenter"},
            "c:3": {"exit_ip": "2.2.2.2", "has_ptr": False, "in_dnsbl": True,
                    "latency_ms": 90, "asn_country": "US", "ip_type": "residential",
                    "rdns_dirty": True},
            "d:4": {"exit_ip": None, "has_ptr": None},
        }

    def test_panel_shows_real_rotation_not_line_count(self):
        s = pool_summary(self._pool())
        self.assertEqual(s["total"], 4)
        self.assertEqual(s["unique_ips"], 2,
                         "ротация считается по строкам прокси, а не по выходным адресам")
        self.assertEqual(s["duplicates"], 1)
        self.assertEqual(s["largest_group"], 2)

    def test_panel_shows_ip_type_and_country(self):
        s = pool_summary(self._pool())
        self.assertEqual(s["by_type"], {"datacenter": 1, "residential": 1},
                         "тип считается по прокси, а не по разным выходным адресам")
        # Регистр страны приходит по-разному — панель обязана его схлопнуть
        self.assertEqual(s["countries"], {"DE": 1, "US": 1})

    def test_panel_shows_hygiene_counters(self):
        s = pool_summary(self._pool())
        self.assertEqual(s["with_ptr"], 2)
        self.assertEqual(s["ptr_unknown"], 1)
        self.assertEqual(s["in_dnsbl"], 1)
        self.assertEqual(s["rdns_dirty"], 1)
        self.assertEqual(s["latency_min"], 90)
        self.assertEqual(s["latency_max"], 240)

    def test_panel_fitness_prefers_direct_probe_over_guess(self):
        """Прямая проба почтовика важнее вывода из списков."""
        fit = provider_fitness({
            # В чёрном списке, но Microsoft ПРИНЯЛ напрямую — значит годен
            "a:1": {"exit_ip": "1.1.1.1", "in_dnsbl": True, "outlook_ok": True},
            # Чистый по спискам, но Microsoft отверг — значит не годен
            "b:2": {"exit_ip": "2.2.2.2", "in_dnsbl": False, "outlook_ok": False},
        })
        self.assertEqual(fit["Outlook / Hotmail"]["ok"], 1)
        self.assertEqual(fit["Outlook / Hotmail"]["no"], 1)
        self.assertEqual(fit["Outlook / Hotmail"]["unknown"], 0)

    def test_panel_fitness_keeps_unknown_separate_from_no(self):
        """«Не проверяли» не имеет права выглядеть как «не пустят»."""
        fit = provider_fitness({"a:1": {"exit_ip": "1.1.1.1", "has_ptr": None}})
        self.assertEqual(fit["Yahoo / AOL"]["unknown"], 1)
        self.assertEqual(fit["Yahoo / AOL"]["no"], 0)

    def test_panel_survives_garbage_profiles(self):
        for junk in (None, "мусор", [], {"a": None}, {"a": "строка"}):
            s = pool_summary(junk)
            self.assertIsInstance(s, dict)
            self.assertIn("unique_ips", s)


class TestBackgroundThreadDoesNotStarveTheWindow(unittest.TestCase):
    """Пока в фоне разбирается база, окно обязано продолжать тикать.

    Меряется не время и не «худшая задержка», а СКОЛЬКО РАЗ успел сработать
    повторяющийся таймер окна за один и тот же кусок фоновой работы. Обе
    отвергнутые метрики врали, и стоит сказать чем, чтобы их не вернули:

      * «Худшая задержка» бесполезна: на ХОЛОСТОМ ходу окно само даёт разрыв
        в 212 мс. Любой порог либо ниже этого шума, либо выше настоящей беды.
      * Замер через update() в цикле меряет не то: главный поток при этом сам
        непрерывно борется за GIL, и картина получается обратная настоящей.
        Через него выходило, что со вдохами 14 мс, а без них 274 — числа
        правдоподобные и по сути случайные.

    Настоящий mainloop на пятнадцати секундах фонового скана дал вот что:

        холостой ход   468 тиков | медиана 11 мс | p99  12.6 мс
        скан БЕЗ вдохов 21 тик   | медиана 67 мс | p99  9915 мс
        скан СО вдохами 473 тика | медиана 11 мс | p99  15.9 мс

    То есть без вдохов окно замирало почти на десять секунд подряд, а со
    вдохами неотличимо от простоя. Разница в числе тиков двадцатикратная —
    по ней и проверяем: она не зависит от того, чем ещё занята машина.
    """

    SAMPLE = 200_000
    TICK_MS = 20
    # Нагрузка держится фиксированное время, а не один проход. Один проход
    # длится полсекунды, и половину тиков окно успевает выдать на старте
    # mainloop, ещё до того как фоновый поток разогнался: разница выходит
    # трёхкратной вместо двадцатикратной и на шуме теряется. Под непрерывной
    # нагрузкой видно то, что видит человек, который ждёт у окна.
    LOAD_SECONDS = 4.0
    MIN_RATIO = 4.0
    MIN_TICKS_PER_SECOND = 10.0

    # Окно на весь класс, одно. Второй Tk-корень в том же процессе на этой
    # сборке Python не поднимается — интерпретатор теряет путь к init.tcl,
    # хотя первое окно работает. Замерам это безразлично: между прогонами
    # окно ничего не накапливает.
    root = None

    @classmethod
    def setUpClass(cls):
        # Берём НАСТОЯЩЕЕ окно программы, а не пустой корень Tk. Разница
        # решает исход: на пустом корне разрыв между «со вдохами» и «без»
        # выходит двукратным, на настоящем — двадцатикратным. Пустое окно
        # почти ничего не делает и потому восстанавливается там, где окно с
        # тремя вкладками, таблицей и собственным опросом очередей — нет.
        # Проверять надо то, что подмерзает у пользователя.
        #
        # Окно общее на весь прогон и НЕ уничтожается: второй корень Tk в
        # этом процессе не поднимается, и своё окно здесь означало бы, что
        # эта проверка молча уходит в skip внутри полного прогона. См.
        # tests/gui_fixture.py.
        from tests.gui_fixture import shared_app
        try:
            cls.root = shared_app()
        except RuntimeError as exc:
            raise unittest.SkipTest(str(exc))

    def _base(self):
        text = chr(10).join(f"user{i}@gmail.com" for i in range(self.SAMPLE))
        return [{"type": "text", "content": text}]

    def _ticks_per_second(self, breathe_every):
        """Частота тиков окна, пока в фоне НЕПРЕРЫВНО идёт разбор базы."""
        from core.provider import scan_base_providers

        root = self.root
        sources = self._base()          # строку готовим ДО замера
        finished = threading.Event()
        ticks = [0]

        def heartbeat():
            ticks[0] += 1
            if finished.is_set():
                root.quit()
                return
            root.after(self.TICK_MS, heartbeat)

        def work():
            try:
                end = time.perf_counter() + self.LOAD_SECONDS
                while time.perf_counter() < end:
                    scan_base_providers(sources, limit=self.SAMPLE,
                                        breathe_every=breathe_every)
            finally:
                finished.set()

        worker = threading.Thread(target=work, daemon=True)
        started = time.perf_counter()
        worker.start()
        root.after(self.TICK_MS, heartbeat)
        root.mainloop()
        worker.join(timeout=60)
        elapsed = max(0.001, time.perf_counter() - started)
        return ticks[0] / elapsed

    def test_window_keeps_ticking_and_would_not_without_breathing(self):
        """Один прогон, два утверждения — и оба обязаны держаться."""
        breathed = self._ticks_per_second(1000)
        starved = self._ticks_per_second(0)

        self.assertGreaterEqual(
            breathed, self.MIN_TICKS_PER_SECOND,
            f"под фоновым разбором окно тикало {breathed:.1f} раз в секунду "
            f"вместо {1000 / self.TICK_MS:.0f} — оно подмерзает")
        self.assertGreaterEqual(
            breathed, starved * self.MIN_RATIO,
            "замер не различает поток со вдохами и без — он слеп, и зелёный "
            f"результат ничего не значит (со вдохами {breathed:.1f} тиков/с, "
            f"без вдохов {starved:.1f})")

    def test_breathing_does_not_change_the_answer(self):
        from core.provider import scan_base_providers
        sources = [{"type": "text",
                    "content": chr(10).join(f"user{i}@gmail.com" for i in range(5000))}]
        plain = scan_base_providers(sources, limit=5000)
        breathed = scan_base_providers(sources, limit=5000, breathe_every=100)
        self.assertEqual(plain["total"], breathed["total"])
        self.assertEqual(dict(plain["providers"]), dict(breathed["providers"]))

    def test_garbage_breathe_value_does_not_crash(self):
        from core.provider import scan_base_providers
        sources = [{"type": "text",
                    "content": chr(10).join(f"user{i}@gmail.com" for i in range(100))}]
        for junk in (None, "часто", -5, 1.5, [], {}):
            scan = scan_base_providers(sources, limit=100, breathe_every=junk)
            self.assertEqual(scan["total"], 100)

    def test_window_actually_asks_the_scan_to_breathe(self):
        """Само окно обязано просить вдохи — иначе починка живёт только в тесте."""
        import inspect
        source = inspect.getsource(ValidatorApp._scan_base_composition)
        self.assertIn("breathe_every", source)
        self.assertGreater(int(ValidatorApp.BREATHE_EVERY), 0)


class TestClosedWindowIsNotAnError(unittest.TestCase):
    """Фоновое чтение переживает закрытие окна, а не падает стеком в консоль.

    Пользователь выбрал файл на гигабайт и передумал. Поток предпросмотра в
    этот момент зовёт after() у уничтоженного окна — раньше это был
    RuntimeError, стек в консоли и поток, умерший не закрыв файл.
    """

    class FakeApp:
        def __init__(self, error):
            self.error = error
            self.calls = 0

        def after(self, delay, fn):
            self.calls += 1
            if self.error is not None:
                raise self.error
            fn()

        _ui_call = ValidatorAppUiCall

    def test_closed_window_returns_false_instead_of_raising(self):
        import tkinter as tk
        for error in (RuntimeError("main thread is not in main loop"),
                      tk.TclError("application has been destroyed")):
            app = self.FakeApp(error)
            self.assertFalse(app._ui_call(lambda: None))
            self.assertEqual(app.calls, 1)

    def test_live_window_still_runs_the_work(self):
        app = self.FakeApp(None)
        seen = []
        self.assertTrue(app._ui_call(lambda: seen.append(1)))
        self.assertEqual(seen, [1])

    def test_real_error_is_not_swallowed(self):
        """Ошибка САМОЙ работы обязана быть видна, а не съедена глушилкой."""
        app = self.FakeApp(None)
        with self.assertRaises(ZeroDivisionError):
            app._ui_call(lambda: 1 / 0)


if __name__ == "__main__":
    unittest.main()
