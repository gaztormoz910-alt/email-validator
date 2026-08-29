"""Кэш: две регрессии, которые я внёс сам, и которые сюда больше не вернутся.

Владелец заподозрил, что после правок валидатор стал врать. Подозрение
оказалось наполовину верным — не про вердикт, но про то, что рядом с ним.

1. СКОР РОЛЕВОГО ЯЩИКА ОБНУЛЯЛСЯ. В скоринг уходил ОТОБРАЖАЕМЫЙ статус, а
   для `info@`-адреса это «Role-based». По такому имени SMTP-баллы не
   начисляются вовсе, и подтверждённо живой ролевой ящик получал 0 вместо
   полусотни. В кэше при этом лежит правильный статус: cache.put() кладёт
   доказанный, а не отображаемый.

2. КЭШ ПЕРЕСТАЛ БЫТЬ КЭШЕМ. Пересчёт обогащения шёл на каждом попадании, а
   он ходит в сеть — Gravatar на каждый адрес плюс DNS, DNSBL, PTR, WHOIS и
   HTTP на каждый домен. На стотысячной базе это сто тысяч запросов там, где
   раньше не было ни одного. Кэш заводился ровно ради того, чтобы их не
   делать.

Решение — отпечаток настроек: совпал, значит обогащение из прошлого прогона
годится как есть; не совпал, значит владелец сменил настройку и ждёт другого
результата, и вот тогда считаем заново.

Сеть здесь не нужна: и кэш, и обогащение подменяются, и проверяется ровно
то, ЧТО и КОГДА вызывается.
"""
import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.pipeline import ValidationPipeline, _enrich_signature


class FakeCache:
    """Кэш с одной записью. Считает, что у него спросили."""

    def __init__(self, entry):
        self.entry = entry
        self.puts = []

    def get(self, email):
        return self.entry

    def put(self, email, status, reason, mx, data=None):
        self.puts.append((email, status, dict(data or {})))

    def close(self):
        pass


def cached_entry(status="Valid", data=None):
    return {
        "status": status,
        "reason": "250 OK",
        "mx": "gmail-smtp-in.l.google.com",
        "checked_at": "2026-08-28T10:00:00+00:00",
        "age_days": 0,
        "data": data or {},
    }


class Harness:
    """Пайплайн, у которого вырезано всё сетевое, кроме учёта вызовов."""

    def __init__(self, cached, osint=False, ai=False, country_mode=None):
        from core.parser.ml_predictor import set_country_mode
        if country_mode:
            set_country_mode(country_mode)

        self.results = []
        self.enrich_calls = []
        self.pipeline = ValidationPipeline(callbacks={
            "on_log": lambda *a, **kw: None,
            "on_result": lambda *a: self.results.append(a),
            "on_progress": lambda *a: None,
            "on_complete": lambda: None,
        })
        self.pipeline.cache = FakeCache(cached)
        self.osint = osint
        self.ai = ai

        real_enrich = self.pipeline._enrich_and_score

        def counted(email, data, res, status_display, original, is_role, enable_ai):
            self.enrich_calls.append({
                "email": email, "status_display": status_display,
                "original": original, "is_role": is_role,
            })
            return real_enrich(email, data, res, status_display, original,
                               is_role, enable_ai)

        self.pipeline._enrich_and_score = counted


class TestRoleBasedKeepsItsScore(unittest.TestCase):
    """Доказанный статус, а не отображаемый, решает скор."""

    def test_scoring_gets_the_proven_status_not_the_label(self):
        from core.scoring import calculate_engagement_score

        proven = calculate_engagement_score(
            email="info@corp-example.com", smtp_status="Role-based",
            smtp_reason="250 OK", original_smtp_status="Valid",
            is_role_based=True)
        mislabelled = calculate_engagement_score(
            email="info@corp-example.com", smtp_status="Role-based",
            smtp_reason="250 OK", original_smtp_status="Role-based",
            is_role_based=True)

        self.assertGreater(
            proven["score"], mislabelled["score"],
            "скоринг не различает доказанный статус и подпись — "
            "проверка ниже тогда ничего не значит")
        self.assertEqual(mislabelled["score"], 0,
                         "именно так выглядела регрессия: ноль вместо баллов")

    def test_cache_branch_passes_the_proven_status(self):
        """Ветка кэша обязана отдать в скоринг cached['status']."""
        import inspect
        source = inspect.getsource(ValidationPipeline.run_pipeline)
        head = source[:source.index("# Шаг 3: Глубокий SMTP Ping")]
        self.assertIn('cached["status"],', head,
                      "в скоринг из кэша уходит не доказанный статус")
        self.assertNotIn("status_display, status_display", head,
                         "отображаемый статус подставлен вместо доказанного")


class TestCacheStaysACache(unittest.TestCase):
    """Пересчёт — только когда настройки изменились."""

    def test_signature_changes_with_every_setting(self):
        base = _enrich_signature(False, False)
        self.assertNotEqual(base, _enrich_signature(True, False),
                            "тумблер обогащения не отражён в отпечатке")
        self.assertNotEqual(base, _enrich_signature(False, True),
                            "тумблер ИИ не отражён в отпечатке")

    def test_signature_changes_with_country_mode(self):
        from core.parser.ml_predictor import set_country_mode, get_country_mode
        was = get_country_mode()
        self.addCleanup(set_country_mode, was)

        set_country_mode("coverage")
        coverage = _enrich_signature(False, False)
        set_country_mode("accuracy")
        accuracy = _enrich_signature(False, False)
        self.assertNotEqual(coverage, accuracy,
                            "режим страны не отражён — именно на нём владелец "
                            "и заметил, что кэш всё отменяет")

    def test_same_settings_do_not_recompute(self):
        """Отпечаток совпал — ни одного пересчёта, ни одного запроса."""
        signature = _enrich_signature(False, False)
        harness = Harness(cached_entry(data={
            "enrich_sig": signature, "name": "Ivan Petrov",
            "engagement_score": 75, "engagement_grade": "Hot",
        }))
        self._run_one(harness, "someone@gmail.com")

        self.assertEqual(harness.enrich_calls, [],
                         "обогащение пересчитано, хотя настройки те же — "
                         "кэш снова ходит в сеть на каждый адрес")
        self.assertEqual(harness.results[0][4].get("engagement_score"), 75,
                         "скор из кэша не подхвачен")

    def test_changed_settings_do_recompute(self):
        """Контроль: иначе первая проверка зелёная просто потому, что
        пересчёт не зовётся НИКОГДА."""
        harness = Harness(cached_entry(data={
            "enrich_sig": "osint=False;ai=False;country=ДРУГОЙ",
            "name": "Ivan Petrov",
        }))
        self._run_one(harness, "someone@gmail.com")

        self.assertEqual(len(harness.enrich_calls), 1,
                         "настройки сменились, а обогащение не пересчитано — "
                         "переключатели в окне опять ничего не значат")

    def test_missing_signature_recomputes(self):
        """Запись из старого кэша отпечатка не имеет — считаем заново."""
        harness = Harness(cached_entry(data={"name": "Ivan Petrov"}))
        self._run_one(harness, "someone@gmail.com")
        self.assertEqual(len(harness.enrich_calls), 1)

    def test_fresh_check_stores_the_signature(self):
        """Иначе отпечаток не совпадёт НИКОГДА и кэш не заработает."""
        import inspect
        source = inspect.getsource(ValidationPipeline._enrich_and_score)
        self.assertIn('data["enrich_sig"]', source,
                      "свежая проверка не кладёт отпечаток настроек в кэш")

    # --- вспомогательное ------------------------------------------------

    def _run_one(self, harness, email):
        """Прогоняет один адрес через ветку кэша, без сети и без потоков."""
        pipeline = harness.pipeline
        pipeline.is_running = True
        pipeline.is_paused = False

        from core.parser.name_extractor import NameExtractor
        from core.parser.ml_predictor import MLPredictor
        pipeline.name_extractor = NameExtractor(enable_osint=False)
        pipeline.ml_predictor = MLPredictor(enable_ml=False)

        # Тот же путь, что и в бою: process_single живёт внутри run_pipeline,
        # поэтому зовём его через маленький повтор ветки кэша. Проверяется
        # РЕШЕНИЕ (пересчитывать или нет), и оно целиком в этой ветке.
        import core.pipeline as module
        cached = pipeline.cache.get(email)
        data = {"validated_at": "2026-08-29 00:00"}
        cached_data = cached.get("data") or {}
        want = module._enrich_signature(harness.osint, harness.ai)
        status_display = cached["status"]

        if cached_data.get("enrich_sig") == want:
            computed = ("engagement_score", "engagement_grade", "provider_type",
                        "provider_name", "domain_type", "has_gravatar")
            for key, value in cached_data.items():
                if key in computed or not data.get(key):
                    data[key] = value
        else:
            for key, value in cached_data.items():
                if key in module._CACHE_KEEPS and not data.get(key):
                    data[key] = value
            pipeline._enrich_and_score(
                email, data,
                {"status": cached["status"], "reason": cached["reason"],
                 "mx_record": cached["mx"], "mx_records": [cached["mx"]],
                 "has_starttls": None},
                status_display, cached["status"], False, harness.ai)
            data["enrich_sig"] = want

        harness.results.append((email, status_display, cached["reason"],
                                cached["mx"], data))


class TestCacheBranchMatchesTheHelper(unittest.TestCase):
    """Повтор ветки в тесте обязан совпадать с настоящей — иначе он врёт."""

    def test_helper_mirrors_the_real_branch(self):
        import inspect
        source = inspect.getsource(ValidationPipeline.run_pipeline)
        head = source[:source.index("# Шаг 3: Глубокий SMTP Ping")]
        for marker in ('cached_data.get("enrich_sig") == want',
                       '_enrich_signature(enable_osint, enable_ai)',
                       'data["enrich_sig"] = want'):
            with self.subTest(marker=marker):
                self.assertIn(marker, head,
                              "ветка кэша изменилась, а повтор в тесте — нет")


if __name__ == "__main__":
    unittest.main()
