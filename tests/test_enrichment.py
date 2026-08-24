"""Обогащение: страна, пол, имя, год рождения.

Главный инвариант файла: домен знает страну ТОЧНЕЕ имени, и никакое
предсказание по имени не имеет права его перебить. Именно на этом
`bogdan.petrov@yandex.ru` превращался в итальянца.
"""
import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.ai_engine import EmailAI
from core.heuristics import extract_birth_year, is_parked_domain, is_role_based
from core.parser.ml_predictor import (NAME_COUNTRY_MIN_RATIO,
                                      NAME_COUNTRY_MIN_SHARE, MLPredictor)
from core.parser.names_index import countries_for, is_known_name, sole_country
from core.parser.translit import variants
from core.provider import (country_from_domain, country_from_location,
                           classify_domain, is_free_mail_domain)
from core.scoring import _is_free_provider


class TestCountryFromDomain(unittest.TestCase):
    """Домен — самый надёжный источник страны, и он должен быть первым."""

    def test_provider_domain_wins_over_tld(self):
        for domain, expected in [("web.de", "Германия"), ("orange.fr", "Франция"),
                                 ("libero.it", "Италия"), ("bigpond.com", "Австралия"),
                                 ("comcast.net", "США"), ("ukr.net", "Украина")]:
            with self.subTest(domain=domain):
                self.assertEqual(country_from_domain(domain), expected)

    def test_com_domains_without_signal_stay_empty(self):
        # Пустая строка честнее выдумки: gmail.com ничего не говорит о стране.
        self.assertEqual(country_from_domain("gmail.com"), "")
        self.assertEqual(country_from_domain("some-startup.com"), "")

    def test_compound_zones(self):
        self.assertEqual(country_from_domain("corp.co.uk"), "Великобритания")
        self.assertEqual(country_from_domain("shop.com.au"), "Австралия")

    def test_idn_zone(self):
        self.assertEqual(country_from_domain("x.xn--p1ai"), "Россия")

    def test_garbage_input(self):
        for value in [None, "", 42, [], "nodot", {}]:
            with self.subTest(value=value):
                self.assertEqual(country_from_domain(value), "")


class TestCountryFromLocation(unittest.TestCase):
    def test_reads_country_from_free_text(self):
        for text, expected in [("Berlin, Germany", "Германия"),
                               ("Москва", "Россия"),
                               ("San Francisco, CA", "США"),
                               ("Tokyo", "Япония")]:
            with self.subTest(text=text):
                self.assertEqual(country_from_location(text), expected)

    def test_unknown_place_is_empty(self):
        self.assertEqual(country_from_location("Средиземье"), "")
        self.assertEqual(country_from_location(""), "")
        self.assertEqual(country_from_location(None), "")


class TestFreeProviders(unittest.TestCase):
    """Раньше эти домены считались корпоративными и получали лишние +5."""

    def test_lesser_known_free_mail_is_recognised(self):
        for domain in ["mail.com", "zoho.com", "seznam.cz", "rambler.ru",
                       "gmx.at", "tutanota.com", "wp.pl", "abv.bg"]:
            with self.subTest(domain=domain):
                self.assertTrue(is_free_mail_domain(domain))
                self.assertTrue(_is_free_provider(domain))

    def test_corporate_domains_stay_corporate(self):
        for domain in ["sberbank.ru", "tesla.com", "some-agency.io"]:
            with self.subTest(domain=domain):
                self.assertFalse(is_free_mail_domain(domain))
                self.assertFalse(_is_free_provider(domain))

    def test_classification_marks_them_personal(self):
        _provider, domain_type = classify_domain("x@zoho.com")
        self.assertEqual(domain_type, "Personal")


class TestGenderWithCountry(unittest.TestCase):
    def setUp(self):
        # enable_ml=False специально: словарь имён обязан работать и без ИИ
        self.ml = MLPredictor(enable_ml=False)

    def test_gender_works_without_ai(self):
        for name, expected in [("John", "Мужской"), ("Sarah", "Женский"),
                               ("Ivan", "Мужской"), ("Svetlana", "Женский")]:
            with self.subTest(name=name):
                self.assertEqual(self.ml.predict(name, email="x@gmail.com")[0], expected)

    def test_country_flips_ambiguous_names(self):
        # Andrea в Италии мужское, в Германии женское. Страну знаем из домена.
        self.assertEqual(self.ml.predict_gender("Andrea", "Италия"), "Мужской")
        self.assertEqual(self.ml.predict_gender("Andrea", "Германия"), "Женский")
        self.assertEqual(self.ml.predict_gender("Simone", "Италия"), "Мужской")

    def test_unknown_gender_stays_empty(self):
        # Врать про пол хуже, чем не указать его
        self.assertEqual(self.ml.predict_gender("Zzqxwv"), "")
        self.assertEqual(self.ml.predict_gender(""), "")
        self.assertEqual(self.ml.predict_gender(None), "")

    def test_country_comes_from_domain_not_name(self):
        _gender, country = self.ml.predict("Bogdan Petrov", email="b@yandex.ru")
        self.assertEqual(country, "Россия")


class TestCountryByNameThreshold(unittest.TestCase):
    """Страна по имени принимается только при явной уверенности."""

    def setUp(self):
        self.ml = MLPredictor(enable_ml=True)
        if not self.ml.nd:
            self.skipTest("names_dataset не установлен")

    def test_smeared_distribution_gives_nothing(self):
        # Ivan: Italy 0.235 при Mexico 0.135 — это шум, а не знание
        for name in ["Ivan", "Bogdan", "Aiko"]:
            with self.subTest(name=name):
                self.assertEqual(self.ml.predict_country(name), "")

    def test_confident_distribution_passes(self):
        self.assertEqual(self.ml.predict_country("Svetlana"), "Россия")

    def test_translit_spelling_is_found(self):
        self.assertEqual(self.ml.predict_country("Dmitriy"), "Россия")

    def test_distribution_is_exposed_for_inspection(self):
        leader, share, second = self.ml.country_distribution("Svetlana")
        self.assertTrue(leader)
        self.assertGreaterEqual(share, NAME_COUNTRY_MIN_SHARE)
        self.assertGreaterEqual(share, second * NAME_COUNTRY_MIN_RATIO)

    def test_unknown_name_gives_nothing(self):
        self.assertEqual(self.ml.predict_country("Zzqxwvfjk"), "")
        self.assertEqual(self.ml.predict_country(""), "")

    def test_share_and_ratio_are_checked_separately(self):
        """Два порога — две разные ошибки, и подменять один другим нельзя.

        На живых именах они перекрываются: у Ivan и доля мала, и отрыва нет,
        поэтому отключение любого из них поодиночке ничего не меняет. Чтобы
        каждый порог действительно что-то сторожил, распределение задаётся
        руками.
        """
        cases = [
            # (доля лидера, доля второго, ждём ли страну)
            (0.90, 0.05, True),    # и крупный, и оторвался
            (0.40, 0.05, False),   # оторвался, но сам по себе мелкий
            (0.60, 0.50, False),   # крупный, но второй дышит в спину
            (0.55, 0.10, True),    # ровно по обоим условиям
        ]
        for share, second, expected in cases:
            with self.subTest(share=share, second=second):
                self.ml.country_distribution = (
                    lambda name, s=share, r=second: ("Russian Federation", s, r))
                got = bool(self.ml.predict_country("Тест"))
                self.assertEqual(got, expected)


class TestBirthYear(unittest.TestCase):
    def test_extracts_plausible_years(self):
        for email, expected in [("sarah.jones91@x.com", 1991),
                                ("karl1985@x.com", 1985),
                                ("ivan_77@x.com", 1977),
                                ("anna.2001.k@x.com", 2001)]:
            with self.subTest(email=email):
                self.assertEqual(extract_birth_year(email), expected)

    def test_registration_year_is_not_a_birth_year(self):
        # 2024 — это год регистрации ящика, человеку не может быть 2 года
        self.assertIsNone(extract_birth_year("user2024@x.com"))

    def test_no_year_means_none(self):
        for email in ["john@x.com", "123456@x.com", "", None, "noatsign", 42]:
            with self.subTest(email=email):
                self.assertIsNone(extract_birth_year(email))


class TestParkedDomainAcrossRecords(unittest.TestCase):
    def test_parking_on_second_mx_is_caught(self):
        # Раньше смотрелся только первый MX — второй проходил незамеченным
        self.assertTrue(is_parked_domain(["mx1.normal.net", "park.sedoparking.com"]))

    def test_single_record_still_works(self):
        self.assertTrue(is_parked_domain("ns1.bodis.com"))
        self.assertFalse(is_parked_domain("aspmx.l.google.com"))

    def test_garbage_input(self):
        for value in [None, "", "N/A", 42, {}, []]:
            with self.subTest(value=value):
                self.assertFalse(is_parked_domain(value))


class TestRoleDetectionBreadth(unittest.TestCase):
    def test_industry_roles_are_caught(self):
        for email in ["dispatch@corp.com", "procurement@corp.com",
                      "helpdesk@corp.com", "invoices@corp.com",
                      "recruitment@corp.com", "notifications@corp.com"]:
            with self.subTest(email=email):
                self.assertTrue(is_role_based(email))

    def test_people_are_not_roles(self):
        for email in ["ivan.petrov@corp.com", "j.smith@corp.com", "anna@corp.com"]:
            with self.subTest(email=email):
                self.assertFalse(is_role_based(email))


class TestNameIndex(unittest.TestCase):
    def test_index_is_loaded(self):
        self.assertTrue(is_known_name("ivan"))
        self.assertTrue(is_known_name("Sarah"))
        self.assertFalse(is_known_name("zzqxwvfjk"))

    def test_common_names_span_many_countries(self):
        # Именно поэтому глобальное распределение и не годится для страны
        self.assertGreater(len(countries_for("ivan")), 1)
        self.assertIsNone(sole_country("ivan"))

    def test_unknown_name_has_no_countries(self):
        self.assertEqual(countries_for("zzqxwvfjk"), ())


class TestTranslit(unittest.TestCase):
    def test_common_spellings_are_generated(self):
        got = variants("dmitriy")
        self.assertIn("dmitriy", got)
        self.assertTrue({"dmitry", "dmitri"} & set(got))

    def test_non_latin_is_left_alone(self):
        self.assertEqual(variants("иван"), ["иван"])

    def test_garbage_input(self):
        self.assertEqual(variants(None), [])
        self.assertEqual(variants(""), [])


class TestMachineGeneratedFilter(unittest.TestCase):
    """ИИ-фильтр заменён на измеренную эвристику — поведение должно остаться."""

    def setUp(self):
        self.ai = EmailAI()
        self.ai.train_models()

    def test_bots_are_caught(self):
        for email in ["xk3n9fj2q@gmail.com", "a7f3k2m9x1@x.com", "qwerty123@x.com"]:
            with self.subTest(email=email):
                self.assertTrue(self.ai.predict(email))

    def test_people_are_never_touched(self):
        for email in ["john.doe@gmail.com", "ivan.petrov@mail.ru",
                      "wolfgangschmidt@web.de", "anna@x.com"]:
            with self.subTest(email=email):
                self.assertFalse(self.ai.predict(email))

    def test_privacy_relay_is_not_a_bot(self):
        # Apple Private Relay выдаёт случайную локальную часть живым людям
        self.assertFalse(self.ai.predict("dq5xr2mkpz@privaterelay.appleid.com"))

    def test_garbage_input(self):
        for value in [None, "", 42, "noatsign", []]:
            with self.subTest(value=value):
                self.assertFalse(self.ai.predict(value))


class _Net:
    """Сеть-заглушка: вердикт всегда Valid, сетевых запросов нет."""

    def check_email(self, email):
        return {"status": "valid", "reason": "250 OK", "mx_record": "mx.example.com",
                "mx_records": ["mx.example.com"], "has_starttls": True,
                "server_outdated": False}

    def check_dns_health(self, domain, mx_record=""):
        return {"has_spf": True, "has_dmarc": True, "has_dkim": True, "score": 3}

    def check_dnsbl(self, host):
        return False

    def check_ptr(self, host):
        return True

    def all_proxies_dead(self):
        return False

    def has_proxies_configured(self):
        return False


class TestPipelineCountryPriority(unittest.TestCase):
    """Сквозная проверка порядка источников страны.

    Это тот самый баг, ради которого всё затевалось: в пайплайне стояло
    `country = по_имени if по_имени else по_домену`, и bogdan.petrov@yandex.ru
    уезжал в выгрузку как Италия. Проверяем не функции по отдельности, а
    именно то, что попадёт в таблицу.
    """

    def setUp(self):
        from core.parser.name_extractor import NameExtractor
        from core.pipeline import ValidationPipeline

        self.rows = []
        self.pipeline = ValidationPipeline(callbacks={
            "on_log": lambda m, t="info": None,
            "on_result": lambda e, s, r, mx, d: self.rows.append((e, s, dict(d))),
            "on_progress": lambda c, t: None,
            "on_complete": lambda: None,
        })
        self.pipeline.network = _Net()
        self.pipeline.name_extractor = NameExtractor(enable_osint=False)
        self.pipeline.ml_predictor = MLPredictor(enable_ml=True)
        self.pipeline.gravatar_checker = type("G", (), {"has_gravatar": lambda s, e: False})()
        self.pipeline.filter = None
        self.pipeline.ai = None
        self.pipeline.cache = None
        self.pipeline._get_domain_age_days = lambda d: -1
        self.pipeline._check_http_alive = lambda d: True

    def _run(self, addresses):
        self.rows.clear()
        self.pipeline.run_pipeline(
            [{"type": "text", "content": "\n".join(addresses)}],
            threads=2, fix_typos=True, check_spam=False, deep_ping=True,
            enable_ai=False)
        return {row[0]: row[2] for row in self.rows}

    def test_domain_beats_name(self):
        data = self._run(["bogdan.petrov@yandex.ru", "ivan.sidorov@mail.ru"])
        self.assertEqual(data["bogdan.petrov@yandex.ru"]["country"], "Россия")
        self.assertEqual(data["ivan.sidorov@mail.ru"]["country"], "Россия")

    def test_domain_beats_even_a_confident_name(self):
        """Ключевой случай: имя УВЕРЕННО указывает на другую страну.

        Svetlana проходит порог (0.575 против 0.135) и в одиночку дала бы
        Россию. Но домен web.de — это Германия, и он должен победить: человек
        с русским именем вполне может жить в Германии, а вот немецкий
        почтовик про свою страну не ошибается.

        Без этого случая тест ничего не сторожит: у имён вроде Bogdan
        предсказание и так пустое, и перестановка источников остаётся
        незамеченной.
        """
        data = self._run(["svetlana.mueller@web.de"])
        row = data["svetlana.mueller@web.de"]
        self.assertEqual(row["country"], "Германия")
        self.assertEqual(row["country_source"], "домен")

    def test_provider_domain_without_tld_signal(self):
        data = self._run(["hans.mueller@web.de", "pierre.dupont@orange.fr"])
        self.assertEqual(data["hans.mueller@web.de"]["country"], "Германия")
        self.assertEqual(data["pierre.dupont@orange.fr"]["country"], "Франция")

    def test_country_source_is_recorded(self):
        data = self._run(["bogdan.petrov@yandex.ru"])
        self.assertEqual(data["bogdan.petrov@yandex.ru"]["country_source"], "домен")

    def test_gender_filled_without_ai(self):
        data = self._run(["svetlana.orlova@mail.ru"])
        self.assertEqual(data["svetlana.orlova@mail.ru"]["gender"], "Женский")

    def test_birth_year_lands_in_the_row(self):
        data = self._run(["sarah.jones91@gmail.com"])
        self.assertEqual(data["sarah.jones91@gmail.com"]["birth_year"], 1991)


if __name__ == "__main__":
    unittest.main()
