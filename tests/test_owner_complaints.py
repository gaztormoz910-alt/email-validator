# -*- coding: utf-8 -*-
from исходники import исходник_конвейера
import inspect
import unittest

from ui.result_store import group_of


class TestRiskyIsNotSpam(unittest.TestCase):

    def test_risky_goes_with_unknown(self):
        self.assertEqual(group_of("Risky"), "unknown")
        self.assertEqual(group_of("Risky"), group_of("Unknown"))

    def test_only_the_undeliverable_stay_in_spam(self):
        for status in ("Trap/Disposable", "Role-based"):
            with self.subTest(status=status):
                self.assertEqual(group_of(status), "spam")

    def test_card_labels_do_not_promise_spam(self):
        import io
        import os
        путь = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "ui", "web", "index.html")
        разметка = io.open(путь, encoding="utf-8").read()
        self.assertNotIn("Спам / Ловушки", разметка,
                         "подпись обещает спам, а туда попадают и ролевые")
        self.assertIn("Ловушки, роль, недоставляемые", разметка,
                      "корзина должна называть все свои содержимые")


class TestNameIsSplitIntoParts(unittest.TestCase):

    def test_two_words_split(self):
        from core.parser.name_extractor import split_name
        self.assertEqual(split_name("Zogbin Anatol"), ("Zogbin", "Anatol"))

    def test_three_words_keep_first_and_last(self):
        from core.parser.name_extractor import split_name
        self.assertEqual(split_name("Minh Anh Tran"), ("Minh", "Tran"))

    def test_single_word_leaves_surname_empty(self):
        from core.parser.name_extractor import split_name
        self.assertEqual(split_name("Kevin"), ("Kevin", ""))

    def test_garbage_does_not_crash(self):
        from core.parser.name_extractor import split_name
        for junk in (None, 123, "", "   ", [], {}):
            self.assertEqual(split_name(junk), ("", ""))

    def test_export_has_the_columns(self):
        from ui import webapp
        source = inspect.getsource(webapp)
        self.assertIn("FirstName", source)
        self.assertIn("LastName", source)
        self.assertIn('"first_name"', source)

    def test_cli_export_has_the_columns(self):
        import cli
        self.assertIn("first_name", cli.EXPORT_FIELDS)
        self.assertIn("last_name", cli.EXPORT_FIELDS)


class TestRiskyKeepsItsOwnName(unittest.TestCase):

    def test_group_is_shared_but_the_status_is_not(self):
        self.assertEqual(group_of("Risky"), group_of("Unknown"))
        self.assertNotEqual("Risky", "Unknown")

    def test_pipeline_does_not_rename_risky(self):
        from core import pipeline
        источник = исходник_конвейера()
        self.assertNotIn('"Risky" -> "Unknown"', источник)
        self.assertIn("Risky", источник, "статус Risky исчез из пайплайна")


if __name__ == "__main__":
    unittest.main()
