import os
import sys
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.network as N
from core.network import NetworkValidator, country_code_for_domain


def make(proxies, profiles):
    v = NetworkValidator(timeout=1, proxies=list(proxies))
    v.set_proxy_profiles(profiles)
    return v


class TestGeoRouting(unittest.TestCase):

    def test_geo_country_code_from_domain(self):
        self.assertEqual(country_code_for_domain("web.de"), "DE")
        self.assertEqual(country_code_for_domain("orange.fr"), "FR")
        self.assertEqual(country_code_for_domain("mail.ru"), "RU")

    def test_geo_country_code_empty_for_neutral_zones(self):
        for domain in ("gmail.com", "example.net", "", "нет-точки"):
            with self.subTest(domain=domain):
                self.assertEqual(country_code_for_domain(domain), "")

    def test_geo_prefers_matching_country(self):
        v = make(["de:1", "br:2"], {
            "de:1": {"exit_ip": "1.1.1.1", "asn_country": "DE", "latency_ms": 300},
            "br:2": {"exit_ip": "2.2.2.2", "asn_country": "BR", "latency_ms": 100},
        })
        picks = {v._pick_best_proxy(want_country="DE") for _ in range(40)}
        self.assertEqual(picks, {"de:1"},
                         "прокси нужной страны не выбран, хотя он есть")

    def test_geo_preference_beats_lower_latency(self):
        v = make(["de:1", "br:2"], {
            "de:1": {"exit_ip": "1.1.1.1", "asn_country": "DE", "latency_ms": 900},
            "br:2": {"exit_ip": "2.2.2.2", "asn_country": "BR", "latency_ms": 50},
        })
        self.assertEqual(v._pick_best_proxy(want_country="DE"), "de:1")

    def test_geo_falls_back_when_no_local_proxy(self):
        v = make(["br:2"], {
            "br:2": {"exit_ip": "2.2.2.2", "asn_country": "BR", "latency_ms": 50},
        })
        self.assertEqual(v._pick_best_proxy(want_country="DE"), "br:2",
                         "отсутствие прокси нужной страны обнулило выбор")

    def test_geo_does_not_override_health(self):
        v = make(["de:1", "br:2"], {
            "de:1": {"exit_ip": "1.1.1.1", "asn_country": "DE", "latency_ms": 100},
            "br:2": {"exit_ip": "2.2.2.2", "asn_country": "BR", "latency_ms": 100},
        })
        for _ in range(5):
            v._update_proxy_score("de:1", False, mx_record=f"mx{_}.com")
        v._update_proxy_score("br:2", True)
        self.assertEqual(v._pick_best_proxy(want_country="DE"), "br:2",
                         "выбран прокси нужной страны, но с плохим здоровьем")


class TestDirectProbe(unittest.TestCase):

    def test_direct_probe_targets_include_yahoo_and_icloud(self):
        names = [name for name, _host in N.PROXY_PROBE_TARGETS]
        self.assertIn("Yahoo", names)
        self.assertIn("iCloud", names)

    def test_direct_probe_result_beats_ptr_inference(self):
        v = make(["ok:1", "bad:2"], {
            "ok:1": {"exit_ip": "1.1.1.1", "has_ptr": True, "yahoo_ok": True},
            "bad:2": {"exit_ip": "2.2.2.2", "has_ptr": True, "yahoo_ok": False},
        })
        picks = {v._pick_best_proxy(need_ptr=True) for _ in range(40)}
        self.assertEqual(picks, {"ok:1"},
                         "прокси, отвергнутый Yahoo напрямую, всё ещё в пуле Yahoo")

    def test_direct_probe_lifts_measured_proxy_without_ptr(self):
        v = make(["measured:1", "ptronly:2"], {
            "measured:1": {"exit_ip": "1.1.1.1", "has_ptr": None, "yahoo_ok": True},
            "ptronly:2": {"exit_ip": "2.2.2.2", "has_ptr": True, "yahoo_ok": None},
        })
        picks = {v._pick_best_proxy(need_ptr=True) for _ in range(40)}
        self.assertIn("measured:1", picks,
                      "измеренная пригодность к Yahoo не учитывается")

    def test_direct_probe_icloud_rejection_marks_dirty(self):
        v = make(["clean:1", "icloud_bad:2"], {
            "clean:1": {"exit_ip": "1.1.1.1", "icloud_ok": True},
            "icloud_bad:2": {"exit_ip": "2.2.2.2", "icloud_ok": False},
        })
        self.assertIn("icloud_bad:2", v._dirty_proxies,
                      "прокси, отвергнутый iCloud, не помечен грязным")

    def test_direct_probe_absent_data_changes_nothing(self):
        v = make(["a:1", "b:2"], {
            "a:1": {"exit_ip": "1.1.1.1", "has_ptr": True},
            "b:2": {"exit_ip": "2.2.2.2", "has_ptr": False},
        })
        self.assertEqual(v._pick_best_proxy(need_ptr=True), "a:1")


class TestPerProxyConcurrency(unittest.TestCase):

    def test_concurrency_limit_is_enforced(self):
        v = NetworkValidator(timeout=1, proxies=["p:1"])
        v.set_proxy_concurrency(3)
        slot = v.proxy_slot("p:1")

        peak = [0]
        current = [0]
        guard = threading.Lock()

        def worker():
            slot.acquire()
            try:
                with guard:
                    current[0] += 1
                    peak[0] = max(peak[0], current[0])
                time.sleep(0.02)
            finally:
                with guard:
                    current[0] -= 1
                slot.release()

        threads = [threading.Thread(target=worker) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertLessEqual(peak[0], 3,
                             f"через прокси прошло {peak[0]} соединений при лимите 3")

    def test_concurrency_slot_capacity_is_exact(self):
        v = NetworkValidator(timeout=1, proxies=["p:1"])
        v.set_proxy_concurrency(3)
        slot = v.proxy_slot("p:1")

        взято = [slot.acquire(blocking=False) for _ in range(4)]
        try:
            self.assertEqual(
                взято, [True, True, True, False],
                "слот отдал места как %s при лимите 3: третье место обязано "
                "быть, четвёртого — нет" % взято)
        finally:
            for получилось in взято:
                if получилось:
                    slot.release()

    def test_concurrency_same_slot_per_proxy(self):
        v = NetworkValidator(timeout=1, proxies=["p:1", "q:2"])
        self.assertIs(v.proxy_slot("p:1"), v.proxy_slot("p:1"))
        self.assertIsNot(v.proxy_slot("p:1"), v.proxy_slot("q:2"))

    def test_concurrency_no_slot_without_proxy(self):
        v = NetworkValidator(timeout=1)
        self.assertIsNone(v.proxy_slot(None))

    def test_concurrency_limit_is_bounded(self):
        v = NetworkValidator(timeout=1)
        self.assertEqual(v.set_proxy_concurrency(0), 1)
        self.assertEqual(v.set_proxy_concurrency(10_000), 64)
        self.assertEqual(v.set_proxy_concurrency("мусор"), 64)


class TestSpamhaus(unittest.TestCase):

    def test_spamhaus_is_silent_without_own_resolver(self):
        v = NetworkValidator(timeout=1)
        self.assertIsNone(v._spamhaus_lists("1.2.3.4"),
                          "Spamhaus ответил, хотя резолвер не задан")

    def test_spamhaus_rejects_resolver_failing_sanity_contract(self):
        v = NetworkValidator(timeout=1)

        class Broken:
            def resolve(self, name, rdtype='A'):
                raise Exception("не отвечает")

        v.__class__
        import core.dns_checks as DC
        original = DC.ProxiedResolver
        try:
            N.ProxiedResolver = lambda **kw: Broken()
            self.assertFalse(v.set_spamhaus_resolver(["10.0.0.53"]))
            self.assertIsNone(v._spamhaus_lists("1.2.3.4"))
        finally:
            DC.ProxiedResolver = original

    def test_spamhaus_accepts_resolver_passing_sanity_contract(self):
        v = NetworkValidator(timeout=1)

        class Rdata:
            def __init__(self, text):
                self._text = text

            def to_text(self):
                return self._text

        class Good:
            def resolve(self, name, rdtype='A'):
                if name.startswith("2.0.0.127."):
                    return [Rdata("127.0.0.2")]
                raise N.dns.resolver.NXDOMAIN

        import core.dns_checks as DC
        original = DC.ProxiedResolver
        try:
            DC.ProxiedResolver = lambda **kw: Good()
            self.assertTrue(v.set_spamhaus_resolver(["10.0.0.53"]))
            self.assertIs(v._spamhaus_lists("127.0.0.2"), True)
            self.assertIs(v._spamhaus_lists("9.9.9.9"), False)
        finally:
            DC.ProxiedResolver = original

    def test_spamhaus_zone_is_not_in_public_list(self):
        self.assertNotIn(N.SPAMHAUS_ZONE, N.DNSBL_ZONES)

    def test_spamhaus_hit_short_circuits_other_zones(self):
        v = NetworkValidator(timeout=1)
        v._spamhaus_lists = lambda ip: True
        asked = []
        v.resolver = type("R", (), {"resolve": lambda self, n, t='A': asked.append(n)})()
        self.assertTrue(v.check_dnsbl_ip("1.2.3.4"))
        self.assertEqual(asked, [],
                         "после попадания в Spamhaus зря опрошены остальные зоны")


class TestIpLoad(unittest.TestCase):

    def test_load_counts_by_exit_ip_not_by_proxy_line(self):
        v = make(["a:1", "b:2"], {
            "a:1": {"exit_ip": "1.1.1.1"},
            "b:2": {"exit_ip": "1.1.1.1"},
        })
        v.note_ip_use("a:1")
        v.note_ip_use("b:2")
        self.assertEqual(v.ip_load("a:1"), 2,
                         "нагрузка считается по строке прокси, а не по выходному IP")
        self.assertEqual(v.ip_load("b:2"), 2)

    def test_load_separates_different_exit_ips(self):
        v = make(["a:1", "b:2"], {
            "a:1": {"exit_ip": "1.1.1.1"},
            "b:2": {"exit_ip": "2.2.2.2"},
        })
        v.note_ip_use("a:1", 5)
        self.assertEqual(v.ip_load("a:1"), 5)
        self.assertEqual(v.ip_load("b:2"), 0)

    def test_load_moves_choice_to_the_quieter_proxy(self):
        import random

        v = make(["hot:1", "cold:2"], {
            "hot:1": {"exit_ip": "1.1.1.1", "latency_ms": 100},
            "cold:2": {"exit_ip": "2.2.2.2", "latency_ms": 100},
        })
        v.note_ip_use("hot:1", 500)
        state = random.getstate()
        random.seed(20260901)
        try:
            picks = [v._pick_best_proxy() for _ in range(60)]
        finally:
            random.setstate(state)
        self.assertGreater(picks.count("cold:2"), picks.count("hot:1"),
                           "нагруженный адрес выбирается не реже свободного")

    def test_load_reports_overloaded_ips(self):
        v = make(["a:1"], {"a:1": {"exit_ip": "1.1.1.1"}})
        self.assertEqual(v.overloaded_ips(), {})
        v.note_ip_use("a:1", v._ip_load_soft_cap)
        self.assertIn("1.1.1.1", v.overloaded_ips(),
                      "перегруженный выходной IP не отмечен")

    def test_load_soft_cap_matches_industry_guidance(self):
        v = NetworkValidator(timeout=1)
        self.assertGreaterEqual(v._ip_load_soft_cap, 500)
        self.assertLessEqual(v._ip_load_soft_cap, 1000)


if __name__ == "__main__":
    unittest.main()


class TestMxSemaphoreDoesNotHoldDuringSleep(unittest.TestCase):

    LIMIT = 2
    DELAY = 0.3
    THREADS = 6
    BARRIER_TIMEOUT = 10.0

    def _threads_meeting_inside_the_delay(self):
        v = NetworkValidator(timeout=1)
        v._max_concurrent_per_mx = self.LIMIT

        barrier = threading.Barrier(self.THREADS)
        сошлись = []
        guard = threading.Lock()

        def задержка(mx_host):
            try:
                barrier.wait(timeout=self.BARRIER_TIMEOUT)
            except threading.BrokenBarrierError:
                return 0.0
            with guard:
                сошлись.append(mx_host)
            return 0.0

        v._mx_delay = задержка

        def boom(proxy=None):
            raise OSError("соединение не нужно для этого замера")

        v._make_smtp_connection = boom

        threads = [threading.Thread(
            target=lambda: v._do_single_ping("a@b.com", "mx.b.com", proxy=None))
            for _ in range(self.THREADS)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return len(сошлись)

    def test_semaphore_is_free_while_the_delay_runs(self):
        сошлось = self._threads_meeting_inside_the_delay()
        self.assertEqual(
            сошлось, self.THREADS,
            f"внутри паузы перед MX одновременно оказалось {сошлось} потоков "
            f"из {self.THREADS} при лимите {self.LIMIT} — значит пауза снова "
            "идёт ПОД семафором и держит слот параллельности")

    def test_delay_before_mx_is_actually_applied(self):
        v = NetworkValidator(timeout=1)
        v._max_concurrent_per_mx = self.LIMIT
        v._mx_delay = lambda mx_host: self.DELAY

        def boom(proxy=None):
            raise OSError("соединение не нужно для этого замера")

        v._make_smtp_connection = boom

        started = time.monotonic()
        v._do_single_ping("a@b.com", "mx.b.com", proxy=None)
        elapsed = time.monotonic() - started

        self.assertGreaterEqual(
            elapsed, self.DELAY * 0.9,
            f"один запрос занял {elapsed:.3f}с при паузе {self.DELAY}с — "
            "пауза перед запросом к MX не применяется вовсе")

    def test_semaphore_still_limits_concurrency(self):
        v = NetworkValidator(timeout=1)
        v._max_concurrent_per_mx = self.LIMIT
        v._mx_delay = lambda mx_host: 0.0

        inside = []
        peak = [0]
        lock = threading.Lock()

        def slow_connect(proxy=None):
            with lock:
                inside.append(1)
                peak[0] = max(peak[0], len(inside))
            time.sleep(0.05)
            with lock:
                inside.pop()
            raise OSError("дальше не идём")

        v._make_smtp_connection = slow_connect

        threads = [threading.Thread(
            target=lambda: v._do_single_ping("a@b.com", "mx.b.com", proxy=None))
            for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertLessEqual(
            peak[0], self.LIMIT,
            f"одновременно к MX ушло {peak[0]} обращений при лимите {self.LIMIT} — "
            "перенос паузы сломал само ограничение параллельности")


class TestIpBudgetEnforced(unittest.TestCase):

    def _pool(self):
        v = make(["hot:1", "cold:2"], {
            "hot:1": {"exit_ip": "1.1.1.1", "latency_ms": 10},
            "cold:2": {"exit_ip": "2.2.2.2", "latency_ms": 900},
        })
        return v

    def test_budget_enforced_excludes_overloaded_proxy(self):
        v = self._pool()
        before = [v._pick_best_proxy() for _ in range(60)]
        self.assertIn("hot:1", before, "быстрый прокси не выбирается вовсе")
        self.assertGreater(before.count("hot:1"), before.count("cold:2"),
                           "быстрый прокси не имеет преимущества — значит и "
                           "проверка на его исключение ничего не докажет")

        v.note_ip_use("hot:1", v._ip_load_soft_cap + 1)
        picks = {v._pick_best_proxy() for _ in range(60)}
        self.assertEqual(picks, {"cold:2"},
                         "перегруженный адрес всё ещё выбирается, хотя есть свободный")

    def test_budget_enforced_falls_back_when_everything_is_loaded(self):
        v = self._pool()
        v.note_ip_use("hot:1", v._ip_load_soft_cap + 1)
        v.note_ip_use("cold:2", v._ip_load_soft_cap + 1)
        self.assertIn(v._pick_best_proxy(), {"hot:1", "cold:2"},
                      "при поголовной перегрузке выбор обнулился")

    def test_budget_enforced_counts_by_exit_ip(self):
        v = make(["a:1", "b:2", "free:3"], {
            "a:1": {"exit_ip": "1.1.1.1", "latency_ms": 10},
            "b:2": {"exit_ip": "1.1.1.1", "latency_ms": 10},
            "free:3": {"exit_ip": "9.9.9.9", "latency_ms": 500},
        })
        v.note_ip_use("a:1", v._ip_load_soft_cap + 1)
        picks = {v._pick_best_proxy() for _ in range(60)}
        self.assertEqual(picks, {"free:3"},
                         "второй прокси того же выхода не считается перегруженным")


class TestLatencyLive(unittest.TestCase):

    def test_latency_live_smooths_new_measurement(self):
        v = make(["p:1"], {"p:1": {"exit_ip": "1.1.1.1", "latency_ms": 1000}})
        v._note_latency("p:1", 0)
        measured = v._proxy_latency["p:1"]
        self.assertLess(measured, 1000, "новый замер не повлиял на задержку")
        self.assertGreater(measured, 0,
                           "одиночный замер полностью заменил прежний — "
                           "случайный всплеск будет выкидывать рабочий прокси")

    def test_latency_live_converges_to_reality(self):
        v = make(["p:1"], {"p:1": {"exit_ip": "1.1.1.1", "latency_ms": 10}})
        for _ in range(30):
            v._note_latency("p:1", 900)
        self.assertGreater(v._proxy_latency["p:1"], 700,
                           "задержка не сходится к наблюдаемой")

    def test_latency_live_ignores_garbage(self):
        v = make(["p:1"], {"p:1": {"exit_ip": "1.1.1.1", "latency_ms": 100}})
        for junk in (None, -5, "мусор", [], {}):
            v._note_latency("p:1", junk)
        self.assertEqual(v._proxy_latency["p:1"], 100)

    def test_latency_live_first_measurement_sets_value(self):
        v = make(["p:1"], {"p:1": {"exit_ip": "1.1.1.1"}})
        v._note_latency("p:1", 250)
        self.assertEqual(v._proxy_latency["p:1"], 250)


class TestGeoNeutral(unittest.TestCase):

    def test_geo_neutral_zone_uses_mx_country(self):
        v = NetworkValidator(timeout=1)
        self.assertEqual(country_code_for_domain("example.com"), "")

        calls = []

        def fake_meta(ip, **kw):
            calls.append(ip)
            return {"asn_country": "us", "asn": "AS15169", "ip_type": "datacenter"}

        import core.proxy_profile as PP
        original = PP.lookup_ip_meta
        try:
            PP.lookup_ip_meta = fake_meta
            v.resolver = type("R", (), {"resolve": staticmethod(
                lambda name, rdtype='A': ["93.184.216.34"])})()
            self.assertEqual(v.country_for_domain("example.com", "mx.example.com"), "US")
            self.assertEqual(v.country_for_domain("example.com", "mx.example.com"), "US")
            self.assertEqual(len(calls), 1, "страна MX спрашивается на каждом адресе")
        finally:
            PP.lookup_ip_meta = original

    def test_geo_neutral_zone_wins_when_known(self):
        v = NetworkValidator(timeout=1)
        self.assertEqual(v.country_for_domain("web.de", "mx.google.com"), "DE")

    def test_geo_neutral_returns_empty_without_mx(self):
        v = NetworkValidator(timeout=1)
        self.assertEqual(v.country_for_domain("example.com", ""), "")
        self.assertEqual(v.country_for_domain("example.com", "N/A"), "")

    def test_geo_neutral_survives_lookup_failure(self):
        v = NetworkValidator(timeout=1)
        v.resolver = type("R", (), {"resolve": staticmethod(
            lambda *a, **k: (_ for _ in ()).throw(Exception("нет DNS")))})()
        self.assertEqual(v.country_for_domain("example.com", "mx.example.com"), "")


class TestWhoisProxied(unittest.TestCase):

    def test_whois_helper_exists_and_uses_socks(self):
        import inspect
        source = inspect.getsource(N._whois_ask)
        self.assertIn("socks.socksocket", source,
                      "WHOIS ходит голым сокетом — реальный IP утекает регистратору")
        self.assertIn("set_proxy", source)

    def test_whois_parses_creation_date_from_body(self):
        crlf = chr(13) + chr(10)
        body = ("Domain Name: EXAMPLE.COM" + crlf
                + "Registrar: Example Inc" + crlf
                + "Creation Date: 1995-08-14T04:00:00Z" + crlf)
        found = N._WHOIS_CREATED_RE.search(body)
        self.assertIsNotNone(found, "дата регистрации не распознана")
        self.assertEqual(found.group(1), "1995-08-14T04:00:00Z")

    def test_whois_parses_referral(self):
        crlf = chr(13) + chr(10)
        iana = "domain:        COM" + crlf + "refer:         whois.verisign-grs.com" + crlf
        found = N._WHOIS_REFER_RE.search(iana)
        self.assertIsNotNone(found, "сервер зоны не распознан")
        self.assertEqual(found.group(1), "whois.verisign-grs.com")

    def test_whois_bad_input_returns_empty(self):
        for junk in (None, "", "no-dot", 123, []):
            with self.subTest(junk=junk):
                self.assertEqual(N.whois_creation_date(junk), "")

    def test_whois_pipeline_no_longer_skips_it(self):
        import inspect
        from core.pipeline import ValidationPipeline
        source = inspect.getsource(ValidationPipeline._fetch_domain_age)
        self.assertIn("whois_creation_date", source)
        self.assertNotIn("whois не проксируется", source)
