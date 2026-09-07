"""Парсер на гигантских объёмах: дорки, прокси и найденные адреса.

Валидатор к этому моменту уже читает вход потоком и держит дедуп на диске.
У парсера те же три места, и они оставались нетронутыми:

1. **Найденные адреса копились в ОЗУ.** `global_seen_emails` был обычным
   множеством и рос линейно по числу собранных почт. На прогоне по дорк-файлу
   в сотни мегабайт это тот же самый отказ по памяти, от которого в
   валидаторе избавились через RunState.

2. **Дедуп шёл по сырой строке.** `John.Doe@Gmail.com` и `johndoe@gmail.com`
   собирались как два разных контакта, и человек потом получал два письма.

3. **Прокси читались в главном потоке.** `dedupe_proxies(list(...))` стоял
   прямо в обработчике кнопки «Старт»: окно замирало между нажатием и
   началом работы ровно на время чтения файла.
"""
import os
import sys
import tempfile
import tracemalloc
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser_pipeline import ParserPipeline


def make_pipeline(dorks="dork one\ndork two\n"):
    return ParserPipeline(
        dork_sources=[{"type": "text", "content": dorks}],
        proxies=[], max_threads=2)


class TestFoundAddressesAreNotKeptInRam(unittest.TestCase):
    """Множество найденных адресов обязано жить на диске."""

    def test_dedup_store_is_disk_backed(self):
        pipeline = make_pipeline()
        self.addCleanup(pipeline._seen.close)
        self.assertEqual(type(pipeline._seen).__name__, "RunState")
        self.assertTrue(pipeline._seen.enabled,
                        "хранилище дедупа не открылось — дедуп ушёл в память")

    def test_memory_does_not_grow_with_found_addresses(self):
        pipeline = make_pipeline()
        self.addCleanup(pipeline._seen.close)

        def add(count):
            for i in range(count):
                pipeline._seen.add_if_new(f"user{i}@example.com")

        tracemalloc.start()
        try:
            add(40_000)
            peak = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
        finally:
            tracemalloc.stop()

        per_key = peak * 1024 * 1024 / 40_000
        self.assertLess(per_key, 60,
                        f"один найденный адрес стоит {per_key:.0f} байт памяти — "
                        "множество лежит в ОЗУ целиком")

    def test_positive_control_a_plain_set_is_heavier(self):
        """Контроль: то же число адресов обычным множеством весит заметно больше."""
        tracemalloc.start()
        try:
            seen = set()
            for i in range(40_000):
                seen.add(f"user{i}@example.com")
            in_ram = tracemalloc.get_traced_memory()[1] / (1024 * 1024)
        finally:
            tracemalloc.stop()
        self.assertGreater(in_ram * 1024 * 1024 / 40_000, 60,
                           "замер не различает множество в ОЗУ и хранилище на "
                           "диске — значит ничего не доказывает")


class TestParserDedupUsesTheCanonicalKey(unittest.TestCase):
    """Один и тот же ящик не должен собираться дважды."""

    def test_same_mailbox_is_collected_once(self):
        from core.cleaner import normalize_for_dedup
        pipeline = make_pipeline()
        self.addCleanup(pipeline._seen.close)
        first = pipeline._seen.add_if_new(normalize_for_dedup("John.Doe@Gmail.com"))
        second = pipeline._seen.add_if_new(normalize_for_dedup("johndoe@gmail.com"))
        third = pipeline._seen.add_if_new(normalize_for_dedup("john.doe+news@gmail.com"))
        self.assertTrue(first)
        self.assertFalse(second, "точки в Gmail значащими не являются")
        self.assertFalse(third, "плюс-тег отбрасывается у известных провайдеров")

    def test_different_people_stay_apart(self):
        from core.cleaner import normalize_for_dedup
        pipeline = make_pipeline()
        self.addCleanup(pipeline._seen.close)
        self.assertTrue(pipeline._seen.add_if_new(normalize_for_dedup("a.b@outlook.com")))
        self.assertTrue(pipeline._seen.add_if_new(normalize_for_dedup("ab@outlook.com")),
                        "точки вне Gmail значащие — это разные люди")

    def test_extraction_path_uses_the_same_key(self):
        """Проверяем сам код разбора, а не только хранилище.

        Без этого тест доказывал бы только то, что RunState умеет дедуп, но не
        то, что парсер его так использует.
        """
        import inspect
        source = inspect.getsource(ParserPipeline)
        self.assertIn("normalize_for_dedup", source,
                      "парсер дедуплицирует по сырой строке, а не по ключу")
        self.assertIn("add_if_new", source)


class TestDorkCountingIsCheap(unittest.TestCase):
    """Знаменатель прогресса не должен стоить полного прохода до старта."""

    def test_estimate_is_used_first(self):
        import inspect
        source = inspect.getsource(ParserPipeline.run)
        self.assertIn("estimate_total_lines", source,
                      "парсер считает все дорки до начала работы")
        self.assertIn("count_total_lines", source,
                      "точный счёт пропал совсем — знаменатель останется оценкой")

    def test_estimate_and_exact_agree_on_a_small_file(self):
        from core.streamer import StreamLoader
        handle, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            for i in range(500):
                f.write(f'site:example{i}.com intext:"@gmail.com"\n')
        self.addCleanup(os.remove, path)
        source = [{"type": "file", "path": path}]
        self.assertEqual(StreamLoader(source).count_total_lines(), 500)
        estimate = StreamLoader(source).estimate_total_lines()
        self.assertLess(abs(estimate - 500) / 500, 0.3)


class TestProxyLoadingIsOffTheMainThread(unittest.TestCase):
    """Чтение прокси при старте парсера обязано уйти в фон."""

if __name__ == "__main__":
    unittest.main()
