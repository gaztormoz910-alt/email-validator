"""Таблица не пересобирает то, что не могло измениться — и не врёт при этом.

Показ глубокой страницы на многомиллионной базе стоит дорого: SQL с большим
OFFSET перебирает всё, что лежит до неё. Замерено на трёх миллионах строк —
0.85 с на страницу. Таблица обновляется дважды в секунду, пока идёт прогон,
и человеку, который просто пролистал далеко, окно вставало колом.

Пересобирать её не нужно: строки нумеруются по порядку прихода, новые
результаты всегда получают номер больше всех прежних, и попасть на уже
НАБРАННУЮ страницу они не могут. Меняться может только последняя, неполная.

Ускорение, которое показывает несвежие данные, хуже медленной правды —
поэтому здесь проверяется ровно это: полная страница не пересобирается,
неполная пересобирается всегда, а смена страницы или фильтра сбрасывает
запомненное.
"""
import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tests.gui_fixture import shared_app


class CountingCalls:
    """Считает, сколько раз хранилище просили собрать страницу."""

    def __init__(self, store):
        self.store = store
        self.calls = 0
        self._real = store.page

    def __enter__(self):
        def counted(*a, **kw):
            self.calls += 1
            return self._real(*a, **kw)
        self.store.page = counted
        return self

    def __exit__(self, *exc):
        self.store.page = self._real
        return False


class TestTableSkipsOnlyWhatCannotChange(unittest.TestCase):

    PAGE = 100

    def setUp(self):
        try:
            self.app = shared_app()
        except RuntimeError as exc:
            self.skipTest(str(exc))
        self.app._active_tab = "Результаты"

    def _add(self, count, start=0):
        for i in range(start, start + count):
            self.app.result_store.append(
                f"user{i}@example.com", "Valid", "250 OK", "mx.example.com",
                {"engagement_score": 90, "name": f"User{i}"})

    def test_full_page_is_not_rebuilt_twice(self):
        self._add(250)
        self.app.validator_page = 1
        self.app.refresh_validator_tree(force=True)
        with CountingCalls(self.app.result_store) as counter:
            for _ in range(10):
                self.app.refresh_validator_tree()
        self.assertEqual(counter.calls, 0,
                         "полная страница пересобирается заново на каждом тике")

    def test_partial_last_page_is_always_rebuilt(self):
        """Последняя страница неполная — на ней и появляются новые строки."""
        self._add(250)
        self.app.validator_page = 3          # 50 строк из 100
        self.app.refresh_validator_tree(force=True)
        shown_before = list(self.app._shown_emails)
        self.assertEqual(len(shown_before), 50)

        self._add(30, start=250)
        self.app.refresh_validator_tree()
        self.assertEqual(len(self.app._shown_emails), 80,
                         "новые строки не появились на неполной странице")

    def test_switching_page_invalidates(self):
        self._add(250)
        self.app.validator_page = 1
        self.app.refresh_validator_tree(force=True)
        first = list(self.app._shown_emails)
        self.app.validator_page = 2
        self.app.refresh_validator_tree()
        self.assertNotEqual(first, self.app._shown_emails,
                            "смена страницы не сбросила запомненное")

    def test_switching_filter_invalidates(self):
        # Сильных МЕНЬШЕ страницы, слабых много. Порядок теперь по убыванию
        # качества, поэтому сильные всегда сверху; чтобы порог менял
        # СОДЕРЖИМОЕ первой страницы, а не только её длину, слабые должны
        # попадать в ту же сотню — и выпадать из неё при пороге.
        for i in range(30):
            self.app.result_store.append(
                f"strong{i}@example.com", "Valid", "250 OK", "mx",
                {"engagement_score": 90})
        for i in range(30, 300):
            self.app.result_store.append(
                f"weak{i}@example.com", "Valid", "250 OK", "mx",
                {"engagement_score": 10})
        self.app.validator_page = 1
        self.app._on_filter_change()
        with_all = list(self.app._shown_emails)
        self.assertTrue(with_all[0].startswith("strong"),
                        "лучшие должны идти первыми: %s" % with_all[:3])
        self.assertTrue(any(e.startswith("weak") for e in with_all),
                        "слабые обязаны попасть в ту же страницу, иначе порог "
                        "не изменит её содержимое")

        self.app.min_score_var.set("50")
        self.app._on_filter_change()
        self.assertNotEqual(with_all, self.app._shown_emails,
                            "смена порога скора не сбросила запомненное")
        self.app.min_score_var.set("0")

    def test_positive_control_counter_actually_counts(self):
        """Если бы счётчик не считал, первая проверка была бы пустой."""
        self._add(250)
        self.app.validator_page = 1
        with CountingCalls(self.app.result_store) as counter:
            self.app.refresh_validator_tree(force=True)
            self.app.refresh_validator_tree(force=True)
        self.assertEqual(counter.calls, 2,
                         "счётчик обращений к хранилищу сломан")


if __name__ == "__main__":
    unittest.main()
