import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.provider import canonical_country, canonical_gender
from core.streamer import StreamLoader

BIG_LINES = 400_000

SAMPLE_NAMES = ("Anna", "John Smith", "Mohammed Ali", "Elena", "Wei Chen",
                "Carlos Ruiz", "Priya", "Ivan Petrov", "Yuki", "Sofia Rossi")
SAMPLE_GENDERS = ("female", "male", "male", "female", "male",
                  "male", "female", "male", "female", "female")
SAMPLE_COUNTRIES = ("US", "UK", "Egypt", "Russia", "China",
                    "Spain", "India", "Russia", "Japan", "Italy")


def make_big_file(kind="emails"):
    handle, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(handle, "w", encoding="utf-8") as f:
        for i in range(BIG_LINES):
            if kind == "emails":
                f.write(f"user{i}@example{i % 97}.com,{SAMPLE_NAMES[i % 10]},"
                        f"{SAMPLE_GENDERS[i % 10]},{SAMPLE_COUNTRIES[i % 10]}\n")
            elif kind == "proxies":
                f.write(f"192.168.{i % 250}.{i % 251}:{1080 + i % 900}\n")
            else:
                f.write(f'site:example{i}.com intext:"@gmail.com" inurl:contact{i}\n')
    return path


class TestCountingIsCheap(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.path = make_big_file("dorks")
        cls.source = [{"type": "file", "path": cls.path}]

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(cls.path)
        except OSError:
            pass

    def test_exact_count_is_correct(self):
        self.assertEqual(StreamLoader(self.source).count_total_lines(), BIG_LINES)

    def test_estimate_is_much_faster_than_exact(self):
        started = time.perf_counter()
        StreamLoader(self.source).estimate_total_lines()
        fast = time.perf_counter() - started

        started = time.perf_counter()
        StreamLoader(self.source).count_total_lines()
        slow = time.perf_counter() - started

        self.assertLess(fast, max(slow, 0.001),
                        f"оценка ({fast*1000:.1f} мс) не быстрее точного счёта "
                        f"({slow*1000:.1f} мс) — значит она тоже читает файл целиком")

    def test_estimate_is_in_the_right_ballpark(self):
        estimate = StreamLoader(self.source).estimate_total_lines()
        error = abs(estimate - BIG_LINES) / BIG_LINES
        self.assertLess(error, 0.5,
                        f"оценка {estimate} против настоящих {BIG_LINES} — "
                        f"ошибка {error*100:.0f}%")

    def test_exact_count_handles_missing_trailing_newline(self):
        handle, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            f.write("a@example.com\nb@example.com")
        self.addCleanup(os.remove, path)
        self.assertEqual(
            StreamLoader([{"type": "file", "path": path}]).count_total_lines(), 2)

    def test_counting_survives_missing_and_broken_sources(self):
        broken = [{"type": "file", "path": "/nope/missing.txt"},
                  {"type": "text", "content": "a@b.com\n\nc@d.com\n"},
                  {"type": "weird"}]
        self.assertEqual(StreamLoader(broken).count_total_lines(), 2)
        self.assertEqual(StreamLoader(broken).estimate_total_lines(), 2)

    def test_empty_input_is_zero_not_a_crash(self):
        self.assertEqual(StreamLoader([]).count_total_lines(), 0)
        self.assertEqual(StreamLoader([]).estimate_total_lines(), 0)


class TestStreamingStaysLazy(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.path = make_big_file("emails")

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(cls.path)
        except OSError:
            pass

    def test_first_email_arrives_fast(self):
        source = [{"type": "file", "path": self.path}]
        started = time.perf_counter()
        first = next(StreamLoader(source).stream_emails())
        elapsed = time.perf_counter() - started
        self.assertEqual(first[0], "user0@example0.com")
        self.assertLess(elapsed, 0.15,
                        f"первая строка пришла через {elapsed*1000:.0f} мс — "
                        "генератор материализует файл")

    def test_extra_columns_are_parsed_not_dropped(self):
        source = [{"type": "file", "path": self.path}]
        _email, data = next(StreamLoader(source).stream_emails())
        self.assertEqual(data.get("name"), SAMPLE_NAMES[0])
        self.assertEqual(data.get("gender"),
                         canonical_gender(SAMPLE_GENDERS[0]))
        self.assertEqual(data.get("country"),
                         canonical_country(SAMPLE_COUNTRIES[0]))
        self.assertEqual(data.get("gender"), "Женский")
        self.assertEqual(data.get("country"), "США")

    def test_plain_list_without_extra_columns_also_works(self):
        handle, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            f.write("solo@example.com\nother@example.com\n")
        self.addCleanup(os.remove, path)
        rows = list(StreamLoader([{"type": "file", "path": path}]).stream_emails())
        self.assertEqual([r[0] for r in rows],
                         ["solo@example.com", "other@example.com"])


if __name__ == "__main__":
    unittest.main()
