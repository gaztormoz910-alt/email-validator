import os
import sys
import sqlite3
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.result_store import ResultStore


def fill(store, count, status="Valid"):
    for i in range(count):
        store.append(
            f"user{i}@example.com", status, "250 OK", "mx.example.com",
            {"engagement_score": 80, "name": f"User {i}", "gender": "male",
             "country": "US", "provider": "Gmail"})


КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ЗАМЕРЩИК = chr(10).join([
    "import sys, tracemalloc",
    "sys.path.insert(0, %r)" % КОРЕНЬ,
    "from ui.result_store import ResultStore",
    "режим, сколько = sys.argv[1], int(sys.argv[2])",
    "",
    "def заполнить(хранилище, н):",
    "    for i in range(н):",
    "        хранилище.append('user%d@example.com' % i, 'Valid', '250 OK',",
    "                         'mx.example.com',",
    "                         {'engagement_score': 80, 'name': 'User %d' % i,",
    "                          'gender': 'male', 'country': 'US',",
    "                          'provider': 'Gmail'})",
    "",
    "def на_диске(н):",
    "    хранилище = ResultStore()",
    "    try:",
    "        заполнить(хранилище, н)",
    "    finally:",
    "        хранилище.close()",
    "",
    "def в_озу(н):",
    "    строки = []",
    "    for i in range(н):",
    "        строки.append({'email': 'user%d@example.com' % i,",
    "                       'status': 'Valid', 'reason': '250 OK',",
    "                       'mx': 'mx.example.com',",
    "                       'data': {'engagement_score': 80,",
    "                                'name': 'User %d' % i, 'gender': 'male',",
    "                                'country': 'US', 'provider': 'Gmail'}})",
    "    return len(строки)",
    "",
    "работа = на_диске if режим == 'store' else в_озу",
    "работа(2000)   # прогрев: одноразовые импорты мимо замера",
    "tracemalloc.start()",
    "работа(сколько)",
    "_т, пик = tracemalloc.get_traced_memory()",
    "tracemalloc.stop()",
    "print(пик / 1048576.0)",
])


def пик_в_потомке(режим, сколько):
    import subprocess

    вышло = subprocess.run(
        [sys.executable, "-X", "utf8", "-c", ЗАМЕРЩИК, режим, str(сколько)],
        cwd=КОРЕНЬ, capture_output=True, text=True, timeout=900)
    assert вышло.returncode == 0, вышло.stderr
    return float(вышло.stdout.strip().splitlines()[-1])


class TestMemoryIsBounded(unittest.TestCase):

    ROWS = 60_000
    CAP_MB = 3

    def test_peak_memory_stays_under_cap(self):
        peak = пик_в_потомке("store", self.ROWS)
        per_row = peak * 1024 * 1024 / self.ROWS
        self.assertLess(
            peak, self.CAP_MB,
            f"{self.ROWS} результатов заняли {peak:.1f} МБ "
            f"({per_row:.0f} байт на строку) — строки лежат в ОЗУ")

    def test_positive_control_in_memory_store_is_heavier(self):
        on_disk = пик_в_потомке("store", self.ROWS)
        in_ram = пик_в_потомке("ram", self.ROWS)
        self.assertGreater(
            in_ram, on_disk * 3,
            f"хранение словарями заняло {in_ram:.1f} МБ против {on_disk:.1f} МБ "
            "у дискового — замер не различает эти два пути")
        self.assertGreater(
            in_ram, self.CAP_MB,
            f"потолок {self.CAP_MB} МБ выше самой поломки ({in_ram:.1f} МБ) — "
            "он ничего не сторожит")
        self.assertLess(
            on_disk, self.CAP_MB,
            f"потолок {self.CAP_MB} МБ ниже обычного расхода ({on_disk:.2f} МБ)")

    def test_memory_does_not_scale_with_row_count(self):
        small = пик_в_потомке("store", 5_000)
        large = пик_в_потомке("store", 50_000)
        self.assertLess(
            large, max(small * 4, 4),
            f"строк стало в 10 раз больше, пик вырос с {small:.2f} до "
            f"{large:.2f} МБ — память зависит от размера базы")

    def test_positive_control_measurement_sees_growth(self):
        мало = пик_в_потомке("ram", 5_000)
        много = пик_в_потомке("ram", 50_000)
        self.assertGreater(много, мало * 4,
                           f"замерщик не видит роста: {мало:.2f} -> {много:.2f} МБ")


class TestContentSurvivesTheDisk(unittest.TestCase):

    def setUp(self):
        self.store = ResultStore()
        self.addCleanup(self.store.close)

    def test_rows_come_back_intact(self):
        self.store.append("a@example.com", "Valid", "250 OK", "mx.a",
                          {"name": "Анна", "engagement_score": 91})
        self.store.append("b@example.com", "Invalid (No User)", "550", "mx.b", {})
        rows = self.store.page(("valid", "invalid"), page=1, size=10)
        self.assertEqual([r["email"] for r in rows],
                         ["a@example.com", "b@example.com"])
        self.assertEqual(rows[0]["data"]["name"], "Анна")
        self.assertEqual(rows[0]["data"]["engagement_score"], 91)
        self.assertEqual(rows[0]["reason"], "250 OK")
        self.assertEqual(rows[1]["mx"], "mx.b")

    def test_order_is_preserved_across_the_flush_boundary(self):
        fill(self.store, 1200)
        rows = self.store.page(("valid",), page=1, size=1200)
        self.assertEqual(len(rows), 1200)
        self.assertEqual(rows[0]["email"], "user0@example.com")
        self.assertEqual(rows[499]["email"], "user499@example.com")
        self.assertEqual(rows[500]["email"], "user500@example.com")
        self.assertEqual(rows[-1]["email"], "user1199@example.com")

    def test_unflushed_rows_are_visible_immediately(self):
        self.store.append("fresh@example.com", "Valid", "250 OK", "mx", {})
        rows = self.store.page(("valid",), page=1, size=10)
        self.assertEqual(rows[0]["email"], "fresh@example.com")

    def test_counts_match_the_rows(self):
        fill(self.store, 300, status="Valid")
        fill(self.store, 100, status="Invalid (No User)")
        counts = self.store.counts()
        self.assertEqual(counts["valid"], 300)
        self.assertEqual(counts["invalid"], 100)
        self.assertEqual(counts["total"], 400)
        self.assertEqual(len(self.store.page(("invalid",), page=1, size=1000)), 100)

    def test_clear_empties_everything(self):
        fill(self.store, 700)
        self.store.clear()
        self.assertEqual(len(self.store), 0)
        self.assertEqual(self.store.counts()["valid"], 0)
        self.assertEqual(self.store.page(("valid",), page=1, size=10), [])
        self.store.append("again@example.com", "Valid", "250 OK", "mx", {})
        self.assertEqual(len(self.store.page(("valid",), page=1, size=10)), 1)

    def test_score_filter_still_selects(self):
        for i in range(200):
            self.store.append(f"u{i}@example.com", "Valid", "250 OK", "mx",
                              {"engagement_score": 90 if i % 2 == 0 else 10})
        rows = self.store.page(("valid",), page=1, size=1000, min_score=50)
        self.assertEqual(len(rows), 100)
        self.assertTrue(all(r["data"]["engagement_score"] == 90 for r in rows))
        self.assertEqual(self.store.matching_count(("valid",), min_score=50), 100)

    def test_export_stream_is_a_generator_not_a_list(self):
        import types
        fill(self.store, 50)
        stream = self.store.iter_matching(("valid",))
        self.assertIsInstance(stream, types.GeneratorType)
        self.assertEqual(len(list(stream)), 50)

    def test_export_stream_survives_a_huge_selection(self):
        fill(self.store, 5000)
        seen = sum(1 for _ in self.store.iter_matching(("valid",)))
        self.assertEqual(seen, 5000)


class TestWorksWithoutDisk(unittest.TestCase):

    def test_falls_back_to_memory(self):
        store = ResultStore()
        self.addCleanup(store.close)
        try:
            store._conn.close()
        except Exception:
            pass
        store._conn = None
        store.append("nodb@example.com", "Valid", "250 OK", "mx", {"name": "X"})
        rows = store.page(("valid",), page=1, size=10)
        self.assertEqual(rows[0]["email"], "nodb@example.com")
        self.assertEqual(rows[0]["data"]["name"], "X")
        self.assertEqual(store.counts()["valid"], 1)

    def test_write_failure_mid_run_keeps_earlier_rows(self):
        store = ResultStore()
        self.addCleanup(store.close)
        fill(store, 600)
        before = store.page(("valid",), page=1, size=5)
        self.assertEqual(len(before), 5)

        class WriteOnlyBroken:

            def __init__(self, real):
                self._real = real

            def executemany(self, *_a, **_kw):
                raise sqlite3.OperationalError("disk I/O error")

            def __getattr__(self, name):
                return getattr(self._real, name)

        store._conn = WriteOnlyBroken(store._conn)
        store.append("after@example.com", "Valid", "250 OK", "mx", {})
        fill(store, 600)

        after = store.page(("valid",), page=1, size=5)
        self.assertEqual([r["email"] for r in before], [r["email"] for r in after],
                         "ранее записанные строки исчезли из таблицы")
        self.assertEqual(store.counts()["valid"], 1201)
        tail = store.page(("valid",), page=61, size=10)
        self.assertIn("after@example.com", [r["email"] for r in tail])


class TestGarbageInput(unittest.TestCase):

    def setUp(self):
        self.store = ResultStore()
        self.addCleanup(self.store.close)

    def test_non_dict_data(self):
        for junk in (None, "text", 42, [], object()):
            with self.subTest(junk=junk):
                self.store.append("x@example.com", "Valid", "r", "mx", junk)
        rows = self.store.page(("valid",), page=1, size=10)
        self.assertEqual(len(rows), 5)
        self.assertTrue(all(isinstance(r["data"], dict) for r in rows))

    def test_unserialisable_values_do_not_break_the_row(self):
        self.store.append("y@example.com", "Valid", "r", "mx",
                          {"name": "Ok", "obj": object(), "when": object()})
        rows = self.store.page(("valid",), page=1, size=10)
        self.assertEqual(rows[0]["data"]["name"], "Ok")

    def test_unknown_status_is_visible_not_hidden(self):
        self.store.append("z@example.com", None, "r", "mx", {})
        self.assertEqual(self.store.counts()["other"], 0)
        self.assertEqual(self.store.counts()["unknown"], 1)
        self.assertEqual(len(self.store.page(("unknown",), size=10)), 1)


if __name__ == "__main__":
    unittest.main()
