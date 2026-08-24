"""Кэш вердиктов между прогонами.

Главный инвариант: в кэш попадает только ДОКАЗАННОЕ. Unknown и Risky —
это сбой нашей стороны, и закэшировать их значит навсегда лишить адрес
второго шанса.
"""
import datetime
import os
import shutil
import sys
import tempfile
import threading
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.cache import CACHEABLE_STATUSES, ResultCache


class CacheTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "cache.sqlite")
        self.cache = ResultCache(path=self.path)

    def tearDown(self):
        self.cache.close()
        shutil.rmtree(self.tmp, ignore_errors=True)


class TestWhatGetsCached(CacheTestBase):
    def test_proven_verdicts_are_stored(self):
        for status in CACHEABLE_STATUSES:
            with self.subTest(status=status):
                self.assertTrue(self.cache.put(f"a{status}@x.com", status, "250 OK", "mx.x.com"))
                self.assertIsNotNone(self.cache.get(f"a{status}@x.com"))

    def test_unproven_verdicts_are_never_stored(self):
        # Ровно то, ради чего кэш ограничен двумя статусами.
        for status in ["Unknown", "Risky", "Role-based", "Trap/Disposable",
                       "catchall", "greylisted", "Unverified", ""]:
            with self.subTest(status=status):
                self.assertFalse(self.cache.put("u@x.com", status, "Timeout", "mx.x.com"))
                self.assertIsNone(self.cache.get("u@x.com"))

    def test_lookup_is_case_insensitive(self):
        self.cache.put("John.Doe@X.com", "Valid", "250 OK", "mx")
        self.assertIsNotNone(self.cache.get("john.doe@x.com"))

    def test_payload_round_trips(self):
        data = {"name": "Иван", "engagement_score": 77, "gender": "male"}
        self.cache.put("p@x.com", "Valid", "250 OK", "mx.x.com", data)
        got = self.cache.get("p@x.com")
        self.assertEqual(got["data"]["name"], "Иван")
        self.assertEqual(got["data"]["engagement_score"], 77)

    def test_miss_on_unknown_address(self):
        self.assertIsNone(self.cache.get("nobody@x.com"))
        self.assertIsNone(self.cache.get(""))
        self.assertIsNone(self.cache.get(None))


class TestExpiry(CacheTestBase):
    def _store_with_age(self, email, status, days):
        stamp = (datetime.datetime.now(datetime.timezone.utc)
                 - datetime.timedelta(days=days)).isoformat()
        with self.cache._lock:
            self.cache._conn.execute(
                "INSERT OR REPLACE INTO results VALUES (?,?,?,?,?,?)",
                (email, status, "reason", "mx", "{}", stamp))
            self.cache._conn.commit()

    def test_fresh_valid_is_served(self):
        self._store_with_age("fresh@x.com", "Valid", 5)
        self.assertIsNotNone(self.cache.get("fresh@x.com"))

    def test_stale_valid_is_rechecked(self):
        self._store_with_age("stale@x.com", "Valid", 400)
        self.assertIsNone(self.cache.get("stale@x.com"))

    def test_invalid_lives_longer_than_valid(self):
        # Подтверждённый отскок — устойчивое состояние, срок годности больше.
        self._store_with_age("v@x.com", "Valid", 45)
        self._store_with_age("i@x.com", "Invalid/Bounce", 45)
        self.assertIsNone(self.cache.get("v@x.com"))
        self.assertIsNotNone(self.cache.get("i@x.com"))

    def test_purge_removes_expired_only(self):
        self._store_with_age("keep@x.com", "Valid", 1)
        self._store_with_age("drop@x.com", "Valid", 999)
        self.cache.purge_expired()
        self.assertIsNotNone(self.cache.get("keep@x.com"))
        self.assertIsNone(self.cache.get("drop@x.com"))


class TestDurabilityAndSafety(CacheTestBase):
    def test_survives_reopen(self):
        self.cache.put("keep@x.com", "Valid", "250 OK", "mx")
        self.cache.close()
        reopened = ResultCache(path=self.path)
        try:
            self.assertIsNotNone(reopened.get("keep@x.com"))
        finally:
            reopened.close()

    def test_broken_storage_disables_cache_but_does_not_raise(self):
        # Кэш — ускорение, а не источник истины: сломался — валидация идёт дальше.
        blocked = ResultCache(path=os.path.join(self.tmp, "nope\x00bad", "c.sqlite"))
        self.assertFalse(blocked.enabled)
        self.assertIsNone(blocked.get("a@x.com"))
        self.assertFalse(blocked.put("a@x.com", "Valid", "r", "mx"))
        self.assertEqual(blocked.size(), 0)
        blocked.close()

    def test_concurrent_writes_do_not_corrupt(self):
        def work(n):
            for i in range(40):
                self.cache.put(f"t{n}-{i}@x.com", "Valid", "250 OK", "mx")

        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(self.cache.size(), 8 * 40)

    def test_hit_counter(self):
        self.cache.put("h@x.com", "Valid", "250 OK", "mx")
        self.cache.get("h@x.com")
        self.cache.get("h@x.com")
        self.cache.get("miss@x.com")
        self.assertEqual(self.cache.hits, 2)


class _StubNetwork:
    """Сеть-заглушка: считает, сколько раз её реально спросили."""

    def __init__(self, status="valid", reason="250 OK"):
        self.calls = []
        self.status = status
        self.reason = reason

    def check_email(self, email):
        self.calls.append(email)
        return {"status": self.status, "reason": self.reason,
                "mx_record": "mx.example.com", "has_starttls": True,
                "server_outdated": False}

    def check_dns_health(self, domain):
        return {"has_spf": True, "has_dmarc": True, "has_dkim": True, "score": 3}

    def check_dnsbl(self, host):
        return False

    def check_ptr(self, host):
        return True

    def all_proxies_dead(self):
        return False

    def has_proxies_configured(self):
        return False


class _StubNames:
    def extract_name(self, email):
        return "Test User"


class _StubML:
    def predict(self, name, email=None):
        return ("male", "US")

    def predict_country(self, name):
        return "US"

    def is_person(self, name):
        return True


class _StubGravatar:
    def has_gravatar(self, email):
        return False


class TestPipelineUsesCache(unittest.TestCase):
    """Сквозная проверка: закэшированный адрес не уходит в сеть повторно."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.results = []
        self.logs = []
        from core.pipeline import ValidationPipeline
        self.pipeline = ValidationPipeline(callbacks={
            'on_log': lambda m, t="info": self.logs.append(m),
            'on_result': lambda e, s, r, mx, d: self.results.append((e, s, r, dict(d))),
            'on_progress': lambda c, t: None,
            'on_complete': lambda: None,
        })
        self.net = _StubNetwork()
        self.pipeline.network = self.net
        self.pipeline.name_extractor = _StubNames()
        self.pipeline.ml_predictor = _StubML()
        self.pipeline.gravatar_checker = _StubGravatar()
        self.pipeline.filter = None
        self.pipeline.ai = None
        self.pipeline._get_domain_age_days = lambda d: -1
        self.pipeline._check_http_alive = lambda d: True
        self.pipeline.cache = ResultCache(path=os.path.join(self.tmp, "c.sqlite"))

    def tearDown(self):
        if self.pipeline.cache:
            self.pipeline.cache.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, addresses):
        self.pipeline.run_pipeline(
            [{"type": "text", "content": "\n".join(addresses)}],
            threads=2, fix_typos=True, check_spam=False, deep_ping=True, enable_ai=False)

    def test_second_run_does_not_touch_the_network(self):
        self._run(["someone@example.com"])
        self.assertEqual(len(self.net.calls), 1)

        # Второй прогон: вердикт уже доказан, сеть трогать незачем.
        self.net.calls.clear()
        self.results.clear()
        self.pipeline.cache = ResultCache(path=os.path.join(self.tmp, "c.sqlite"))
        self._run(["someone@example.com"])
        self.assertEqual(self.net.calls, [])
        self.assertEqual(self.results[0][1], "Valid")
        self.assertIn("из кэша", self.results[0][2])

    def test_cached_row_keeps_enrichment_and_original_date(self):
        self._run(["someone@example.com"])
        first_date = self.results[0][3]["validated_at"]

        self.results.clear()
        self.pipeline.cache = ResultCache(path=os.path.join(self.tmp, "c.sqlite"))
        self._run(["someone@example.com"])
        row = self.results[0][3]
        self.assertEqual(row["name"], "Test User")
        self.assertEqual(row["validated_at"], first_date)
        self.assertTrue(row["from_cache"])

    def test_unknown_verdict_is_rechecked_next_run(self):
        # Unknown — сбой нашей стороны. Кэшировать его значит навсегда закрыть
        # адресу дорогу к нормальной проверке.
        self.pipeline.network = _StubNetwork(status="unknown", reason="Catch-All Domain")
        self._run(["ghost@example.com"])
        self.assertEqual(len(self.pipeline.network.calls), 1)

        self.pipeline.network.calls.clear()
        self.pipeline.cache = ResultCache(path=os.path.join(self.tmp, "c.sqlite"))
        self._run(["ghost@example.com"])
        self.assertEqual(len(self.pipeline.network.calls), 1)

    def test_disabled_cache_always_rechecks(self):
        self._run(["someone@example.com"])
        self.net.calls.clear()
        self.pipeline.cache = None
        self._run(["someone@example.com"])
        self.assertEqual(len(self.net.calls), 1)


if __name__ == "__main__":
    unittest.main()
