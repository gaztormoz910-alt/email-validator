"""S4: режим определения страны по имени переключается без правки исходника."""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.parser.ml_predictor as mp
from core.parser.ml_predictor import (MLPredictor, COUNTRY_MODES,
                                      DEFAULT_COUNTRY_MODE, set_country_mode,
                                      get_country_mode)


class TestCountryModeSwitch(unittest.TestCase):

    def setUp(self):
        self._saved = get_country_mode()

    def tearDown(self):
        set_country_mode(self._saved)

    def test_two_modes_exist_and_differ(self):
        self.assertIn("coverage", COUNTRY_MODES)
        self.assertIn("accuracy", COUNTRY_MODES)
        self.assertNotEqual(COUNTRY_MODES["coverage"], COUNTRY_MODES["accuracy"],
                            "оба режима задают одни и те же пороги — переключать нечего")

    def test_default_mode_keeps_previous_behaviour(self):
        """Смена по умолчанию сломала бы уже собранные базы — её быть не должно."""
        self.assertEqual(DEFAULT_COUNTRY_MODE, "coverage")
        self.assertEqual(COUNTRY_MODES["coverage"], (0.0, 0.0))

    def test_switch_moves_the_actual_thresholds(self):
        set_country_mode("accuracy")
        self.assertEqual(get_country_mode(), "accuracy")
        self.assertEqual(mp.NAME_COUNTRY_MIN_SHARE, 0.35)
        self.assertEqual(mp.NAME_COUNTRY_MIN_RATIO, 2.0)

        set_country_mode("coverage")
        self.assertEqual(mp.NAME_COUNTRY_MIN_SHARE, 0.0)
        self.assertEqual(mp.NAME_COUNTRY_MIN_RATIO, 0.0)

    def test_unknown_mode_is_ignored_not_applied(self):
        """Молча включить противоположное поведение хуже, чем не включить ничего."""
        set_country_mode("accuracy")
        result = set_country_mode("нет-такого-режима")
        self.assertEqual(result, "accuracy")
        self.assertEqual(mp.NAME_COUNTRY_MIN_SHARE, 0.35)

    def test_switch_changes_the_verdict_on_a_weak_distribution(self):
        """Главное: переключатель меняет РЕЗУЛЬТАТ, а не только константы."""
        ml = MLPredictor(enable_ml=False)
        # Слабое распределение: доля мала и отрыва от второго нет
        ml.country_distribution = lambda name: ("Russian Federation", 0.20, 0.15)

        set_country_mode("coverage")
        self.assertTrue(ml.predict_country("Тест"),
                        "в режиме заполненности слабое распределение обязано дать страну")

        set_country_mode("accuracy")
        self.assertEqual(ml.predict_country("Тест"), "",
                         "в режиме точности слабое распределение обязано дать пусто")

    def test_strong_distribution_survives_both_modes(self):
        """Негативный контроль: строгий режим не должен резать уверенные имена."""
        ml = MLPredictor(enable_ml=False)
        ml.country_distribution = lambda name: ("Russian Federation", 0.90, 0.05)
        for mode in ("coverage", "accuracy"):
            with self.subTest(mode=mode):
                set_country_mode(mode)
                self.assertEqual(ml.predict_country("Тест"), "Россия")

    def test_domain_still_outranks_name_in_both_modes(self):
        """Инвариант проекта: домен знает страну точно и решает первым."""
        from core.provider import country_from_domain
        for mode in ("coverage", "accuracy"):
            with self.subTest(mode=mode):
                set_country_mode(mode)
                self.assertEqual(country_from_domain("web.de"), "Германия")


if __name__ == "__main__":
    unittest.main()
