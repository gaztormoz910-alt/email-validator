import pytest

pytestmark = pytest.mark.slow

import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.parser.name_extractor import NameExtractor


class FakeProfiles:

    def __init__(self, profiles):
        self.profiles = profiles
        self.asked = []

    def get_profile(self, email):
        self.asked.append(email)
        return self.profiles.get(email)


class TestProfileBeatsGuess(unittest.TestCase):

    def _extractor(self, profiles):
        extractor = NameExtractor(enable_osint=True)
        extractor.osint_operator = FakeProfiles(profiles)
        return extractor, extractor.osint_operator

    def test_profile_wins_over_a_readable_guess(self):
        extractor, fake = self._extractor(
            {"theadamvelardes@gmail.com": {"name": "Adam Velardes",
                                           "location": "", "accounts": []}})
        self.assertEqual(extractor.extract_name("theadamvelardes@gmail.com"),
                         "Adam Velardes")
        self.assertIn("theadamvelardes@gmail.com", fake.asked,
                      "профиль даже не спросили")
        self.assertEqual(extractor.last_name_source(), "профиль")

    def test_login_in_the_profile_is_not_a_name(self):
        extractor, _ = self._extractor(
            {"johnoakreps@gmail.com": {"name": "johnoakreps",
                                      "location": "", "accounts": []}})
        self.assertEqual(extractor.extract_name("johnoakreps@gmail.com"),
                         "John Oakreps")

    def test_empty_profile_falls_back_to_the_address(self):
        extractor, _ = self._extractor({})
        self.assertEqual(extractor.extract_name("leo.fontanieu@gmail.com"),
                         "Leo Fontanieu")

    def test_exactly_one_request_per_address(self):
        extractor, fake = self._extractor({})
        extractor.extract_name("nosuchprofile12345@gmail.com")
        self.assertEqual(len(fake.asked), 1, f"запросов: {len(fake.asked)}")

    def test_disabled_enrichment_makes_no_requests_at_all(self):
        extractor = NameExtractor(enable_osint=False)
        fake = FakeProfiles({"x@gmail.com": {"name": "Real Name"}})
        extractor.osint_operator = fake
        extractor.extract_name("theadamvelardes@gmail.com")
        self.assertEqual(fake.asked, [],
                         "обогащение выключено, а в сеть всё равно сходили")

    def test_broken_profile_source_does_not_kill_the_address(self):
        class Exploding:
            def get_profile(self, email):
                raise RuntimeError("сеть легла")

        extractor = NameExtractor(enable_osint=True)
        extractor.osint_operator = Exploding()
        self.assertEqual(extractor.extract_name("leo.fontanieu@gmail.com"),
                         "Leo Fontanieu")


class TestCacheDoesNotFreezeEnrichment(unittest.TestCase):

    def test_only_network_facts_are_carried_over(self):
        from core.pipeline import _CACHE_KEEPS
        for field in ("name", "gender", "country", "engagement_score",
                      "name_source", "gender_source", "country_source"):
            with self.subTest(field=field):
                self.assertNotIn(
                    field, _CACHE_KEEPS,
                    f"«{field}» берётся из кэша — настройки окна не подействуют")

    def test_cache_branch_recomputes_the_enrichment(self):
        import inspect
        from core.pipeline import ValidationPipeline
        source = inspect.getsource(ValidationPipeline.run_pipeline)
        head = source[:source.index("# Шаг 3: Глубокий SMTP Ping")]
        self.assertIn("_enrich_and_score", head,
                      "в ветке кэша обогащение не пересчитывается")

    def test_the_two_country_modes_really_differ(self):
        from core.parser.ml_predictor import MLPredictor, set_country_mode, get_country_mode
        was = get_country_mode()
        self.addCleanup(set_country_mode, was)

        predictor = MLPredictor()
        names = ["Kenneth Mdizon", "Jane Doe", "Ivan Petrov", "Adam Velardes",
                 "Salim Bvk", "Swathi Naidu", "George Lam", "Michael Bauer"]

        set_country_mode("coverage")
        coverage = sum(1 for n in names if predictor.predict_country(n))
        set_country_mode("accuracy")
        accuracy = sum(1 for n in names if predictor.predict_country(n))

        self.assertGreater(
            coverage, accuracy,
            f"режимы дают одно и то же ({coverage} против {accuracy}) — "
            "переключатель в окне ничего не значит")


if __name__ == "__main__":
    unittest.main()
