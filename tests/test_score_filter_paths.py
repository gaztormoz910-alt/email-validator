import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ui.result_store import ResultStore


SCORES = [0, 1, 7, 42, 49, 50, 51, 99, 100, None, "", "нет", -3, 3.9]
STATUSES = ["Valid", "Invalid/Bounce", "Risky", "Unknown", "Role-based"]


def fill(store, count=400):
    for i in range(count):
        store.append(f"user{i}@example{i % 7}.com",
                     STATUSES[i % len(STATUSES)],
                     "250 OK", "mx.example.com",
                     {"engagement_score": SCORES[i % len(SCORES)],
                      "name": f"User{i}"})


class SlowStore(ResultStore):

    def _sql_ready(self, groups):
        return False


class TestBothPathsAgree(unittest.TestCase):

    GROUP_SETS = [("valid",), ("invalid",), ("spam",), ("unknown",),
                  ("valid", "invalid"), ("valid", "spam", "unknown"),
                  ("valid", "invalid", "spam", "unknown", "other")]
    THRESHOLDS = [1, 5, 42, 50, 51, 99, 100, 101]

    def setUp(self):
        self.fast = ResultStore()
        self.slow = SlowStore()
        self.addCleanup(self.fast.close)
        self.addCleanup(self.slow.close)
        fill(self.fast)
        fill(self.slow)

    def test_counts_match(self):
        for groups in self.GROUP_SETS:
            for threshold in self.THRESHOLDS:
                with self.subTest(groups=groups, min_score=threshold):
                    self.assertEqual(
                        self.fast.matching_count(groups, min_score=threshold),
                        self.slow.matching_count(groups, min_score=threshold))

    def test_pages_match(self):
        for groups in self.GROUP_SETS:
            for threshold in (1, 50, 99):
                for page in (1, 2, 3):
                    with self.subTest(groups=groups, min_score=threshold, page=page):
                        fast = [r["email"] for r in self.fast.page(
                            groups, page=page, size=25, min_score=threshold)]
                        slow = [r["email"] for r in self.slow.page(
                            groups, page=page, size=25, min_score=threshold)]
                        self.assertEqual(fast, slow)

    def test_page_rows_really_pass_the_threshold(self):
        rows = self.fast.page(("valid", "invalid", "spam", "unknown"),
                              page=1, size=100, min_score=50)
        self.assertTrue(rows, "выборка пуста — сравнивать было бы нечего")
        for row in rows:
            score = row["data"].get("engagement_score")
            self.assertIsInstance(score, int)
            self.assertGreaterEqual(score, 50)

    def test_positive_control_threshold_actually_cuts(self):
        everything = self.fast.matching_count(("valid", "invalid", "spam",
                                               "unknown", "other"), min_score=0)
        filtered = self.fast.matching_count(("valid", "invalid", "spam",
                                             "unknown", "other"), min_score=50)
        self.assertGreater(everything, filtered,
                           "порог не отсёк ни одной строки — проверка слепая")
        self.assertGreater(filtered, 0, "порог отсёк всё — сравнивать нечего")

    def test_broken_score_is_not_counted_as_high(self):
        store = ResultStore()
        self.addCleanup(store.close)
        for junk in (None, "", "много", [], {}, object()):
            store.append("j@example.com", "Valid", "250 OK", "mx",
                         {"engagement_score": junk})
        self.assertEqual(store.matching_count(("valid",), min_score=1), 0)
        self.assertEqual(store.matching_count(("valid",), min_score=0), 6)


class TestScoreFilterIsCheap(unittest.TestCase):

    def test_count_with_threshold_does_not_read_every_row(self):
        class CountingStore(ResultStore):
            rows_fetched = 0

            def _fetch(self, positions):
                type(self).rows_fetched += len(positions)
                return super()._fetch(positions)

        store = CountingStore()
        self.addCleanup(store.close)
        fill(store, count=5_000)
        CountingStore.rows_fetched = 0
        store.matching_count(("valid", "invalid", "spam", "unknown"), min_score=50)
        self.assertLess(CountingStore.rows_fetched, 100,
                        f"подсчёт поднял {CountingStore.rows_fetched} строк — "
                        "он снова читает всю базу")

    def test_positive_control_slow_path_would_be_caught(self):
        class CountingSlowStore(SlowStore):
            rows_fetched = 0

            def _fetch(self, positions):
                type(self).rows_fetched += len(positions)
                return super()._fetch(positions)

        store = CountingSlowStore()
        self.addCleanup(store.close)
        fill(store, count=5_000)
        CountingSlowStore.rows_fetched = 0
        store.matching_count(("valid", "invalid", "spam", "unknown"), min_score=50)
        self.assertGreater(CountingSlowStore.rows_fetched, 100,
                           "счётчик не считает — зелёный результат ничего не значит")


if __name__ == "__main__":
    unittest.main()
