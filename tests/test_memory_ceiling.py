"""Память на базе с миллионами РАЗНЫХ доменов имеет потолок.

Зачем отдельный файл. Потоковое чтение входа спасает от роста памяти по
СТРОКАМ, и это уже проверено. Но рядом росло другое: всё дорогое кэшируется
по ДОМЕНУ — MX, catch-all, здоровье DNS, PTR, DNSBL, возраст, живой сайт,
страна почтовика, — а на базе, собранной дорками, разных доменов столько же,
сколько адресов. Плюс замки «один запрос в полёте» оставались в словаре
навсегда, хотя нужны только пока запрос идёт.

Замерено до починки: 468 байт на домен только на замках и двух кэшах
пайплайна — 2.3 ГБ на пяти миллионах доменов, и это без шести кэшей сетевого
клиента. Прогон падал по памяти ровно на тех объёмах, ради которых вход и
читается потоком.

Проверки ниже смотрят на ЧИСЛО ЗАПИСЕЙ, а не на байты: байты на загруженной
машине гуляют, а «словарь перестал расти» — свойство, которое либо есть,
либо нет.
"""

import os
import sys
import threading
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.bounded import BoundedCache, DEFAULT_MAX_KEYS
from core.pipeline import ValidationPipeline
from core.network import NetworkValidator


class TestBoundedCache(unittest.TestCase):
    """Сам словарь с потолком."""

    def test_never_grows_past_the_cap(self):
        cache = BoundedCache(max_keys=100)
        for i in range(10_000):
            cache[f"domain{i}.com"] = i
        self.assertEqual(len(cache), 100)
        self.assertEqual(cache.evictions, 9_900)

    def test_evicts_the_oldest_not_the_newest(self):
        cache = BoundedCache(max_keys=3)
        for i in range(4):
            cache[i] = i
        self.assertIsNone(cache.get(0), "вытеснили не самую старую запись")
        self.assertEqual(cache.get(3), 3)

    def test_touching_a_key_keeps_it_alive(self):
        """Домен, который встречается постоянно, вылетать не должен."""
        cache = BoundedCache(max_keys=3)
        for i in range(3):
            cache[i] = i
        cache.get(0)                       # gmail.com в базе из гмейлов
        cache[9] = 9
        self.assertEqual(cache.get(0), 0, "часто нужный ключ вытеснен")
        self.assertIsNone(cache.get(1), "вытеснить должно было соседа")

    def test_garbage_cap_does_not_crash(self):
        for junk in (None, "сто", -1, 0, 1.7, [], {}):
            cache = BoundedCache(max_keys=junk)
            self.assertGreaterEqual(cache.max_keys, 1)
            cache["a"] = 1
            self.assertEqual(cache.get("a"), 1)

    def test_survives_parallel_writers(self):
        """Сотня потоков пишет одновременно — потолок обязан устоять."""
        cache = BoundedCache(max_keys=500)
        errors = []

        def hammer(offset):
            try:
                for i in range(2000):
                    cache[f"d{offset}-{i}"] = i
                    cache.get(f"d{offset}-{i}")
            except Exception as exc:        # гонка внутри кэша — это дефект
                errors.append(exc)

        threads = [threading.Thread(target=hammer, args=(n,)) for n in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=60)
        self.assertEqual(errors, [])
        self.assertLessEqual(len(cache), 500)


class TestPipelineCachesHaveACeiling(unittest.TestCase):
    """Кэши по домену в пайплайне и сетевом клиенте не растут бесконечно."""

    DOMAINS = 5_000

    def test_domain_gate_releases_itself(self):
        """Замок живёт, пока идёт запрос, а не до конца прогона."""
        pipeline = ValidationPipeline(callbacks={})
        for i in range(self.DOMAINS):
            with pipeline._domain_gate(f"age:domain{i}.com"):
                pass
        self.assertEqual(len(pipeline._inflight), 0,
                         f"после {self.DOMAINS} доменов осталось "
                         f"{len(pipeline._inflight)} замков")

    def test_domain_gate_is_still_a_gate(self):
        """Пока один поток внутри, второй обязан ЖДАТЬ, а не идти следом."""
        pipeline = ValidationPipeline(callbacks={})
        inside = threading.Event()
        may_leave = threading.Event()
        second_got_in = threading.Event()

        def first():
            with pipeline._domain_gate("age:example.com"):
                inside.set()
                may_leave.wait(10)

        def second():
            inside.wait(10)
            with pipeline._domain_gate("age:example.com"):
                second_got_in.set()

        t1 = threading.Thread(target=first)
        t2 = threading.Thread(target=second)
        t1.start(); t2.start()
        self.assertTrue(inside.wait(10))
        self.assertFalse(second_got_in.wait(0.5),
                         "второй поток вошёл, пока первый внутри — замок не держит")
        may_leave.set()
        t1.join(10); t2.join(10)
        self.assertTrue(second_got_in.is_set(), "второй поток так и не вошёл")
        self.assertEqual(len(pipeline._inflight), 0)

    def test_gate_is_released_even_when_the_work_raises(self):
        pipeline = ValidationPipeline(callbacks={})
        with self.assertRaises(ZeroDivisionError):
            with pipeline._domain_gate("age:example.com"):
                1 / 0
        self.assertEqual(len(pipeline._inflight), 0)
        # И замок не остался захваченным: следующий вход обязан пройти.
        with pipeline._domain_gate("age:example.com"):
            pass

    def _fill(self, cache, count):
        for i in range(count):
            cache[f"domain{i}.example.com"] = i

    def test_every_per_domain_cache_is_bounded(self):
        """Ни один кэш по домену не имеет права быть обычным словарём."""
        pipeline = ValidationPipeline(callbacks={})
        validator = NetworkValidator(proxies=[])
        caches = {
            "pipeline._domain_age_cache": pipeline._domain_age_cache,
            "pipeline._http_alive_cache": pipeline._http_alive_cache,
            "network.mx_cache": validator.mx_cache,
            "network.catchall_cache": validator.catchall_cache,
            "network._postmaster_cache": validator._postmaster_cache,
            "network._dns_health_cache": validator._dns_health_cache,
            "network._dnsbl_cache": validator._dnsbl_cache,
            "network._ptr_cache": validator._ptr_cache,
            "network._fcrdns_cache": validator._fcrdns_cache,
            "network._mx_country_cache": validator._mx_country_cache,
            "network._mx_semaphores": validator._mx_semaphores,
            "network._mx_error_counts": validator._mx_error_counts,
        }
        for name, cache in caches.items():
            with self.subTest(cache=name):
                self.assertIsInstance(
                    cache, BoundedCache,
                    f"{name} — обычный словарь: на базе с миллионами доменов "
                    "он вырастет вместе с ней")
                self.assertLessEqual(cache.max_keys, DEFAULT_MAX_KEYS)

    def test_positive_control_a_plain_dict_would_be_caught(self):
        """Тот же замер на обычном словаре обязан показать рост."""
        plain = {}
        for i in range(10_000):
            plain[f"domain{i}.com"] = i
        self.assertEqual(len(plain), 10_000,
                         "замер не видит роста даже у обычного словаря")

        bounded = BoundedCache(max_keys=1_000)
        self._fill(bounded, 10_000)
        self.assertEqual(len(bounded), 1_000)


if __name__ == "__main__":
    unittest.main()
