"""Любой объём входа: измеряем память и ленивость, а не обещаем их.

Гейты выбирают по -k: stream_proxies, chunked, gui_load, memory.

Главная проверка здесь — `memory`. Она не рассуждает про потоковость, а
СЧИТАЕТ пиковую память через tracemalloc: сначала на ленивом пути, потом на
том же входе, но материализованном в список. Второй замер служит положительным
контролем: если бы измеритель сломался, оба числа оказались бы одинаково
маленькими, и тест бы это увидел.
"""
import asyncio
import inspect
import io
import os
import sys
import tracemalloc
import types
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network import dedupe_proxies, dedupe_proxies_stream
from core.async_proxy import AsyncProxyChecker


def proxy_lines(count, unique=True):
    """Генератор строк прокси. Ленивый: ничего не материализует, и это важно для замера."""
    for i in range(count):
        if unique:
            yield f"10.{i // 65536 % 256}.{i // 256 % 256}.{i % 256}:1080"
        else:
            yield "10.0.0.1:1080"


class TestStreamProxies(unittest.TestCase):
    """Дедуп прокси отдаёт результат по мере чтения, а не после конца файла."""

    def test_stream_proxies_returns_generator(self):
        result = dedupe_proxies_stream(["1.2.3.4:1080"])
        self.assertIsInstance(result, types.GeneratorType,
                              "дедуп вернул готовый список — значит вход прочитан целиком")

    def test_stream_proxies_matches_list_version(self):
        source = ["1.2.3.4:1080", "socks5://1.2.3.4:1080", "1.2.3.4:1080",
                  "5.6.7.8:1080", "", "  ", "user:pass@9.9.9.9:1080"]
        self.assertEqual(list(dedupe_proxies_stream(source)), dedupe_proxies(source),
                         "потоковый и списочный дедуп разошлись в результате")

    def test_stream_proxies_yields_before_source_is_exhausted(self):
        """Первый прокси должен выйти наружу, не дочитывая вход до конца."""
        consumed = []

        def watched():
            for i in range(10000):
                consumed.append(i)
                yield f"10.0.{i // 256}.{i % 256}:1080"

        stream = dedupe_proxies_stream(watched())
        first = next(stream)
        self.assertTrue(first)
        self.assertLess(len(consumed), 10,
                        f"чтобы отдать первый прокси, прочитано {len(consumed)} строк — "
                        "вход читается целиком, а не потоком")

    def test_stream_proxies_survives_garbage(self):
        for junk in (None, "строка", b"bytes", 123, {}):
            with self.subTest(junk=junk):
                self.assertEqual(list(dedupe_proxies_stream(junk)), [])

    def test_stream_proxies_skips_non_strings(self):
        self.assertEqual(list(dedupe_proxies_stream([None, 1, "1.2.3.4:1080", []])),
                         ["1.2.3.4:1080"])


class TestChunked(unittest.TestCase):
    """Чекер берёт вход порциями и не набивает очередь целым файлом."""

    def test_chunked_accepts_generator(self):
        checker = AsyncProxyChecker(proxy_lines(50), workers=5, timeout=0.1,
                                    mode="smtp")
        self.assertEqual(checker.total, 0,
                         "у генератора спросили длину — значит его прочитали целиком")

    def test_chunked_queue_is_bounded(self):
        """Очередь ограничена, и её размер не зависит от размера входа."""
        checker = AsyncProxyChecker(proxy_lines(1_000_000), workers=10,
                                    timeout=0.1, mode="smtp")

        async def drive():
            # Запускаем только подачу, без воркеров: очередь обязана упереться
            # в свой потолок и остановиться, а не проглотить весь миллион.
            checker._feed_done = False
            checker.queue = asyncio.Queue(
                maxsize=max(1, checker.workers) * checker.QUEUE_HEADROOM)
            feeder = asyncio.create_task(checker._feed(iter(proxy_lines(1_000_000))))
            await asyncio.sleep(0.2)
            size = checker.queue.qsize()
            feeder.cancel()
            return size

        size = asyncio.new_event_loop().run_until_complete(drive())
        cap = 10 * AsyncProxyChecker.QUEUE_HEADROOM
        self.assertLessEqual(size, cap,
                             f"в очереди {size} прокси при потолке {cap} — "
                             "вход заливается в память целиком")

    def test_chunked_still_works_with_plain_list(self):
        checker = AsyncProxyChecker(["1.2.3.4:1080", "5.6.7.8:1080"], workers=2,
                                    timeout=0.1, mode="smtp")
        self.assertEqual(checker.total, 2,
                         "обычный список перестал считаться заранее")

    def test_chunked_worker_waits_for_more_input(self):
        """Пустая очередь при незаконченной подаче — не повод выходить."""
        source = inspect.getsource(AsyncProxyChecker._worker)
        self.assertIn("_feed_done", source,
                      "воркер выходит по пустой очереди — при ленивой подаче "
                      "он завершится раньше, чем вход дочитан")


class TestGuiLoad(unittest.TestCase):
    """Окно не считает строки гигантского файла в главном потоке."""

    def _gui_source(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "ui", "gui.py")
        with io.open(path, encoding="utf-8") as handle:
            return handle.read()

    def test_gui_load_counting_helper_runs_in_thread(self):
        from ui.gui import ValidatorApp
        source = inspect.getsource(ValidatorApp._count_lines_async)
        self.assertIn("threading.Thread", source,
                      "подсчёт строк идёт в главном потоке — окно замрёт")
        self.assertIn("self.after", source,
                      "результат подсчёта не возвращается в поток интерфейса")

    def test_gui_load_no_synchronous_counting_left(self):
        """Ни один обработчик не зовёт count_total_lines напрямую."""
        source = self._gui_source()
        # Контроль: сам помощник в файле есть, значит ищем в нужном месте
        self.assertIn("_count_lines_async", source)
        offenders = [line.strip() for line in source.splitlines()
                     if "count_total_lines()" in line
                     and "total = StreamLoader" not in line
                     and not line.strip().startswith("#")
                     and "Зачем фон" not in line]
        self.assertEqual(offenders, [],
                         "остался синхронный подсчёт строк: " + str(offenders))

    def test_gui_load_shows_progress_placeholder(self):
        """Пока идёт счёт, пользователь видит, что происходит."""
        from ui.gui import ValidatorApp
        source = inspect.getsource(ValidatorApp._count_lines_async)
        self.assertIn("считаю", source,
                      "во время подсчёта подпись пустая — выглядит как зависание")


class TestMemory(unittest.TestCase):
    """Память на большом входе измеряется, а не декларируется."""

    LINES = 200_000
    # Потолок с большим запасом: ленивый путь держит только множество ключей
    # дедупа, и оно не связано с длиной файла линейно по объёму СТРОК.
    CAP_MB = 60

    def _peak_mb(self, work):
        tracemalloc.start()
        try:
            work()
            _current, peak = tracemalloc.get_traced_memory()
            return peak / (1024 * 1024)
        finally:
            tracemalloc.stop()

    def test_memory_streaming_stays_under_cap(self):
        def stream_and_drop():
            seen = 0
            for _ in dedupe_proxies_stream(proxy_lines(self.LINES, unique=False)):
                seen += 1
            return seen

        peak = self._peak_mb(stream_and_drop)
        self.assertLess(peak, self.CAP_MB,
                        f"ленивый путь занял {peak:.1f} МБ на {self.LINES} строк")

    def test_memory_positive_control_materialising_is_heavier(self):
        """Контроль: список из того же входа обязан весить заметно больше.

        Без этой проверки предыдущая была бы зелёной и в том случае, если
        tracemalloc вообще перестал что-либо мерить.
        """
        # Вход с повторами: множество ключей остаётся крошечным, и вся разница
        # между путями — это ровно тот список, который раньше строился в ОЗУ.
        # На УНИКАЛЬНОМ входе разницы почти нет, и это честно: набор ключей
        # дедупа неизбежно растёт вместе с числом разных прокси. Измеряем то,
        # что действительно изменилось, а не то, что красивее выглядит.
        lazy = self._peak_mb(
            lambda: sum(1 for _ in dedupe_proxies_stream(
                proxy_lines(self.LINES, unique=False))))
        eager = self._peak_mb(
            lambda: len(dedupe_proxies(list(proxy_lines(self.LINES, unique=False)))))
        self.assertGreater(
            eager, lazy * 1.5,
            f"материализация заняла {eager:.1f} МБ против {lazy:.1f} МБ у потока — "
            "замер не различает эти два пути, значит ничего не доказывает")

    def test_memory_unique_input_key_set_is_bounded(self):
        """Честная граница: на уникальном входе память держит набор ключей.

        Потоковость снимает стоимость СПИСКА, но не стоимость дедупа. Здесь
        проверяется, что этот остаток хотя бы компактен: ключи хранятся хешами,
        а не кортежами, иначе миллион прокси стоил бы сотни мегабайт.
        """
        peak = self._peak_mb(
            lambda: sum(1 for _ in dedupe_proxies_stream(proxy_lines(self.LINES))))
        per_key_bytes = peak * 1024 * 1024 / self.LINES
        self.assertLess(per_key_bytes, 120,
                        f"один ключ дедупа стоит {per_key_bytes:.0f} байт — "
                        "в памяти лежат строки, а не хеши")

    def test_memory_peak_does_not_scale_with_input(self):
        """Вход вырос в десять раз — пик не обязан расти так же."""
        small = self._peak_mb(
            lambda: sum(1 for _ in dedupe_proxies_stream(
                proxy_lines(20_000, unique=False))))
        large = self._peak_mb(
            lambda: sum(1 for _ in dedupe_proxies_stream(
                proxy_lines(200_000, unique=False))))
        self.assertLess(large, max(small * 3, 5),
                        f"на входе в 10 раз больше пик вырос с {small:.2f} до "
                        f"{large:.2f} МБ — память зависит от объёма файла")


if __name__ == "__main__":
    unittest.main()
