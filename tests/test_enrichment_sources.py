"""Порядок источников обогащения: факт важнее догадки, настройка важнее кэша.

Два дефекта, оба тихие — они не падают, а молча портят колонку на всей базе.

1. Профиль спрашивался ТОЛЬКО когда из адреса имя вытащить не удалось. То
   есть обогащение работало на остатках. Замерено живьём на базе владельца:
   `theadamoliveras@gmail.com` — разбор адреса даёт «Thea Damoliveras», а
   профиль отдаёт настоящее «Adam Oliveras». Границу «thead|amoliveras» знает
   только сам человек, и он её указал — в профиле.

2. Кэш вердиктов возвращал вместе со статусом ещё и имя, пол и страну,
   посчитанные в прошлый раз. Настройки окна при этом молча не действовали:
   владелец переключал «Страну по имени» между заполненностью и точностью и
   видел один и тот же результат, потому что 72 адреса из 78 приходили из
   кэша.

Сеть здесь не нужна: профиль подменяется, и это правильно — проверяется
ПОРЯДОК источников, а не доступность Gravatar.
"""
import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.parser.name_extractor import NameExtractor


class FakeProfiles:
    """Подставной Gravatar: отвечает из словаря и считает запросы."""

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
        """Ровно случай владельца: из адреса читается, но читается неверно."""
        extractor, fake = self._extractor(
            {"theadamoliveras@gmail.com": {"name": "Adam Oliveras",
                                           "location": "", "accounts": []}})
        self.assertEqual(extractor.extract_name("theadamoliveras@gmail.com"),
                         "Adam Oliveras")
        self.assertIn("theadamoliveras@gmail.com", fake.asked,
                      "профиль даже не спросили")

    def test_login_in_the_profile_is_not_a_name(self):
        """Gravatar отдаёт логин, когда имени человек не указывал."""
        extractor, _ = self._extractor(
            {"johnacreps@gmail.com": {"name": "johnacreps",
                                      "location": "", "accounts": []}})
        self.assertEqual(extractor.extract_name("johnacreps@gmail.com"),
                         "John Acreps")

    def test_empty_profile_falls_back_to_the_address(self):
        extractor, _ = self._extractor({})
        self.assertEqual(extractor.extract_name("leo.duquesnel@gmail.com"),
                         "Leo Duquesnel")

    def test_exactly_one_request_per_address(self):
        """Второй запрос удвоил бы сетевую нагрузку на всю базу."""
        extractor, fake = self._extractor({})
        extractor.extract_name("nosuchprofile12345@gmail.com")
        self.assertEqual(len(fake.asked), 1, f"запросов: {len(fake.asked)}")

    def test_disabled_enrichment_makes_no_requests_at_all(self):
        extractor = NameExtractor(enable_osint=False)
        fake = FakeProfiles({"x@gmail.com": {"name": "Real Name"}})
        extractor.osint_operator = fake
        extractor.extract_name("theadamoliveras@gmail.com")
        self.assertEqual(fake.asked, [],
                         "обогащение выключено, а в сеть всё равно сходили")

    def test_broken_profile_source_does_not_kill_the_address(self):
        class Exploding:
            def get_profile(self, email):
                raise RuntimeError("сеть легла")

        extractor = NameExtractor(enable_osint=True)
        extractor.osint_operator = Exploding()
        self.assertEqual(extractor.extract_name("leo.duquesnel@gmail.com"),
                         "Leo Duquesnel")


class TestCacheDoesNotFreezeEnrichment(unittest.TestCase):
    """Кэш хранит вердикт SMTP. Имя, пол и страна пересчитываются."""

    def test_only_network_facts_are_carried_over(self):
        from core.pipeline import _CACHE_KEEPS
        for field in ("name", "gender", "country", "engagement_score",
                      "name_source", "gender_source", "country_source"):
            with self.subTest(field=field):
                self.assertNotIn(
                    field, _CACHE_KEEPS,
                    f"«{field}» берётся из кэша — настройки окна не подействуют")

    def test_cache_branch_recomputes_the_enrichment(self):
        """Ветка кэша обязана звать общий пересчёт, а не копировать поля."""
        import inspect
        from core.pipeline import ValidationPipeline
        source = inspect.getsource(ValidationPipeline.run_pipeline)
        head = source[:source.index("# Шаг 3: Глубокий SMTP Ping")]
        self.assertIn("_enrich_and_score", head,
                      "в ветке кэша обогащение не пересчитывается")

    def test_the_two_country_modes_really_differ(self):
        """Контроль: если бы режимы совпадали, пересчёт был бы бессмысленным."""
        from core.parser.ml_predictor import MLPredictor, set_country_mode, get_country_mode
        was = get_country_mode()
        self.addCleanup(set_country_mode, was)

        predictor = MLPredictor()
        names = ["Kenneth Mgalang", "Jane Doe", "Ivan Petrov", "Adam Oliveras",
                 "Salim Atm", "Swathi Reddy", "George Sam", "Michael Koch"]

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
