"""Задержка прокси участвует в выборе, а профилирование слушает ползунок потоков.

Плюс проверка, что переименование spam_traps.txt -> disposable_extra.txt
не оставляет два файла рядом: SpamFilter грузит все .txt из data/.
"""
import json
import os
import shutil
import sys
import tempfile
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.github_parser import BlacklistDownloader
from core.network import NetworkValidator, profile_proxies


class TestLatencyInSelection(unittest.TestCase):
    """При равном health score выбирается быстрый прокси, а не случайный.

    Тесты дёргают САМ `_pick_best_proxy`, а не повторяют его сортировку: иначе
    они проверяли бы собственную копию логики и прошли бы даже тогда, когда
    задержка в рабочем коде не учитывается вовсе.

    Список специально задан от медленных к быстрым. Если задержку не учитывать,
    sorted() устойчива и оставит наверху первых по списку — то есть самых
    медленных, и тест это увидит.
    """

    POOL = 30           # больше 5: иначе в топ попадает весь пул (см. последний тест)
    SAMPLES = 200

    def setUp(self):
        # p0 — самый медленный (3000 мс), p29 — самый быстрый (100 мс)
        self.proxies = [f"socks5://10.0.0.{i + 1}:1080" for i in range(self.POOL)]
        self.latency = {p: 3000 - i * 100 for i, p in enumerate(self.proxies)}
        self.v = NetworkValidator(timeout=3, proxies=self.proxies)
        self.v.set_proxy_profiles({
            p: {"has_ptr": False, "in_dnsbl": False, "rdns_dirty": False,
                "outlook_ok": True, "latency_ms": self.latency[p]}
            for p in self.proxies
        })
        self.fastest_third = set(sorted(self.proxies, key=lambda p: self.latency[p])[:10])

    def test_latency_is_stored_from_profiles(self):
        self.assertEqual(self.v._proxy_latency[self.proxies[0]], 3000)
        self.assertEqual(self.v._proxy_latency[self.proxies[-1]], 100)

    def test_only_fastest_third_is_ever_picked(self):
        picked = {self.v._pick_best_proxy() for _ in range(self.SAMPLES)}
        self.assertTrue(picked)
        self.assertTrue(picked <= self.fastest_third,
                        f"выбраны медленные прокси: {sorted(picked - self.fastest_third)}")

    def test_slowest_proxy_is_never_picked(self):
        picked = {self.v._pick_best_proxy() for _ in range(self.SAMPLES)}
        self.assertNotIn(self.proxies[0], picked)   # 3000 мс

    def test_health_score_still_outranks_latency(self):
        # Скорость — вторичный критерий: живой медленный лучше быстрого дохлого.
        slowest = self.proxies[0]
        self.v._proxy_scores[slowest] = 500
        picked = {self.v._pick_best_proxy() for _ in range(self.SAMPLES)}
        self.assertIn(slowest, picked)

    def test_measured_proxy_beats_unmeasured_one(self):
        # «Не измерили» не должно выигрывать у измеренного быстрого.
        v = NetworkValidator(timeout=3, proxies=self.proxies)
        profiles = {p: {"has_ptr": False, "in_dnsbl": False, "rdns_dirty": False,
                        "latency_ms": None} for p in self.proxies}
        for p in list(self.fastest_third):
            profiles[p]["latency_ms"] = self.latency[p]
        v.set_proxy_profiles(profiles)
        picked = {v._pick_best_proxy() for _ in range(self.SAMPLES)}
        self.assertTrue(picked <= self.fastest_third,
                        f"непрофилированные обошли измеренных: {sorted(picked - self.fastest_third)}")

    def test_unmeasured_latency_does_not_crash_selection(self):
        v = NetworkValidator(timeout=3, proxies=self.proxies)
        v.set_proxy_profiles({p: {"has_ptr": None, "in_dnsbl": False, "latency_ms": None}
                              for p in self.proxies})
        self.assertIn(v._pick_best_proxy(), self.proxies)

    def test_selection_survives_missing_profile_data(self):
        v = NetworkValidator(timeout=3, proxies=[self.proxies[0]])
        self.assertEqual(v._pick_best_proxy(), self.proxies[0])

    def test_tiny_pool_keeps_rotating_all_proxies(self):
        # Осознанное поведение: на пуле из 5 и меньше важнее ротация, чем
        # скорость, поэтому в топ попадают все — иначе один прокси выжигался бы.
        small = self.proxies[:4]
        v = NetworkValidator(timeout=3, proxies=small)
        v.set_proxy_profiles({p: {"has_ptr": False, "in_dnsbl": False,
                                  "latency_ms": self.latency[p]} for p in small})
        picked = {v._pick_best_proxy() for _ in range(self.SAMPLES)}
        self.assertEqual(picked, set(small))


class TestProfilingWorkers(unittest.TestCase):
    """Число потоков профилирования приходит снаружи, а не захардкожено."""

    def test_workers_argument_is_honoured(self):
        seen = {}
        import core.network as net
        real_pool = net.ThreadPoolExecutor

        class SpyPool(real_pool):
            def __init__(self, max_workers=None, **kw):
                seen["max_workers"] = max_workers
                super().__init__(max_workers=max_workers, **kw)

        net.ThreadPoolExecutor = SpyPool
        try:
            profile_proxies(["socks5://127.0.0.1:1"] * 50, timeout=1, workers=120,
                            probe_outlook=False)
        finally:
            net.ThreadPoolExecutor = real_pool
        self.assertEqual(seen["max_workers"], 50)  # ограничено размером списка

    def test_workers_are_capped_and_sanitised(self):
        import core.network as net
        real_pool = net.ThreadPoolExecutor
        seen = {}

        class SpyPool(real_pool):
            def __init__(self, max_workers=None, **kw):
                seen["max_workers"] = max_workers
                super().__init__(max_workers=max_workers, **kw)

        net.ThreadPoolExecutor = SpyPool
        try:
            proxies = ["socks5://127.0.0.1:%d" % (i + 1) for i in range(600)]
            profile_proxies(proxies, timeout=1, workers=99999, probe_outlook=False)
        finally:
            net.ThreadPoolExecutor = real_pool
        self.assertEqual(seen["max_workers"], 300)  # аппаратный потолок

    def test_garbage_workers_value_does_not_crash(self):
        self.assertEqual(profile_proxies([], workers="много"), {})


class TestLegacyListRename(unittest.TestCase):
    """Старый spam_traps.txt переезжает в disposable_extra.txt, а не дублируется."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_legacy_file_is_renamed(self):
        legacy = os.path.join(self.tmp, "spam_traps.txt")
        with open(legacy, "w", encoding="utf-8") as f:
            f.write("mailinator.com\n")
        BlacklistDownloader(data_dir=self.tmp)
        self.assertFalse(os.path.exists(legacy))
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "disposable_extra.txt")))

    def test_etag_moves_with_the_file(self):
        with open(os.path.join(self.tmp, "spam_traps.txt"), "w", encoding="utf-8") as f:
            f.write("mailinator.com\n")
        etag_path = os.path.join(self.tmp, ".blacklist_etags.json")
        with open(etag_path, "w", encoding="utf-8") as f:
            json.dump({"spam_traps.txt": "abc123"}, f)
        BlacklistDownloader(data_dir=self.tmp)
        with open(etag_path, encoding="utf-8") as f:
            etags = json.load(f)
        self.assertEqual(etags.get("disposable_extra.txt"), "abc123")
        self.assertNotIn("spam_traps.txt", etags)

    def test_duplicate_is_removed_not_kept(self):
        # Оставить оба файла нельзя: SpamFilter грузит все .txt подряд.
        for name in ("spam_traps.txt", "disposable_extra.txt"):
            with open(os.path.join(self.tmp, name), "w", encoding="utf-8") as f:
                f.write("mailinator.com\n")
        BlacklistDownloader(data_dir=self.tmp)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "spam_traps.txt")))
        self.assertTrue(os.path.exists(os.path.join(self.tmp, "disposable_extra.txt")))

    def test_no_legacy_file_is_a_noop(self):
        BlacklistDownloader(data_dir=self.tmp)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, "disposable_extra.txt")))

    def test_source_list_uses_honest_name(self):
        d = BlacklistDownloader(data_dir=self.tmp)
        self.assertIn("disposable_extra.txt", d.sources)
        self.assertNotIn("spam_traps.txt", d.sources)


if __name__ == "__main__":
    unittest.main()
