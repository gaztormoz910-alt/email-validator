import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import baseops
from core.cleaner import normalize_for_dedup

SAME_MAILBOX = [
    ("johndoe@gmail.com", "John.Doe@Gmail.com"),
    ("john.doe@gmail.com", "johndoe@gmail.com"),
    ("john+news@gmail.com", "john@gmail.com"),
    ("j.o.h.n@googlemail.com", "john@gmail.com"),
    ("USER@Example.COM", "user@example.com"),
    ("  spaced@gmail.com  ", "spaced@gmail.com"),
]

DIFFERENT_MAILBOXES = [
    ("john.doe@outlook.com", "johndoe@outlook.com"),
    ("john.doe@yandex.ru", "johndoe@yandex.ru"),
    ("a.b@corporate.example", "ab@corporate.example"),
    ("john+ops@corporate.example", "john@corporate.example"),
    ("john@gmail.com", "johnn@gmail.com"),
    ("john@gmail.com", "john@gmail.co"),
]


class TestOneKeyForEverything(unittest.TestCase):

    def test_same_mailbox_collapses(self):
        for stored, unsubscribed in SAME_MAILBOX:
            with self.subTest(pair=(stored, unsubscribed)):
                self.assertEqual(normalize_for_dedup(stored),
                                 normalize_for_dedup(unsubscribed))

    def test_different_mailboxes_stay_apart(self):
        for one, other in DIFFERENT_MAILBOXES:
            with self.subTest(pair=(one, other)):
                self.assertNotEqual(normalize_for_dedup(one),
                                    normalize_for_dedup(other))

    def test_subtract_uses_the_same_key(self):
        for stored, unsubscribed in SAME_MAILBOX:
            with self.subTest(pair=(stored, unsubscribed)):
                left = baseops.subtract([stored], [unsubscribed])
                self.assertEqual(left, [],
                                 f"{stored} остался в базе, хотя {unsubscribed} отписался")

    def test_subtract_does_not_eat_different_people(self):
        for one, other in DIFFERENT_MAILBOXES:
            with self.subTest(pair=(one, other)):
                self.assertEqual(baseops.subtract([one], [other]), [one])

    def test_intersect_uses_the_same_key(self):
        for stored, elsewhere in SAME_MAILBOX:
            with self.subTest(pair=(stored, elsewhere)):
                self.assertEqual(baseops.intersect([stored], [elsewhere]), [stored])

    def test_dedupe_uses_the_same_key(self):
        for first, second in SAME_MAILBOX:
            with self.subTest(pair=(first, second)):
                self.assertEqual(baseops.dedupe([first, second]), [first])

    def test_original_spelling_is_returned_not_the_key(self):
        kept = baseops.dedupe(["John.Doe@Gmail.com", "johndoe@gmail.com"])
        self.assertEqual(kept, ["John.Doe@Gmail.com"])


class TestSuppressionFile(unittest.TestCase):

    def _write(self, lines):
        handle, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        self.addCleanup(os.remove, path)
        return path

    def test_keys_from_file_match_the_dedup_key(self):
        path = self._write(["John.Doe@Gmail.com", "# комментарий",
                            "", "second@example.com,Иван,male"])
        keys = baseops.suppression_keys(path)
        self.assertIn(normalize_for_dedup("johndoe@gmail.com"), keys)
        self.assertIn(normalize_for_dedup("second@example.com"), keys)

    def test_export_filter_drops_by_canonical_key(self):
        path = self._write(["John.Doe+promo@Gmail.com"])
        keys = baseops.suppression_keys(path)
        self.assertIn(normalize_for_dedup("johndoe@gmail.com"), keys)
        self.assertNotIn(normalize_for_dedup("otherjohn@gmail.com"), keys)

    def test_missing_file_gives_empty_set_not_a_crash(self):
        self.assertEqual(baseops.suppression_keys("/nope/missing.txt"), set())
        self.assertEqual(baseops.suppression_keys(None), set())
        self.assertEqual(baseops.suppression_keys(123), set())


class TestStreamingExportKeepsTheContract(unittest.TestCase):

    def test_stream_writes_every_row_once(self):
        rows = [{"email": f"u{i}@example.com"} for i in range(2500)]
        target = os.path.join(tempfile.mkdtemp(), "out.txt")

        def writer(handle, chunk):
            for row in chunk:
                handle.write(row["email"] + "\n")

        written, total = baseops.write_chunks_stream(iter(rows), target, 1000, writer)
        self.assertEqual(total, 2500)
        seen = []
        for path in written:
            with open(path, encoding="utf-8") as f:
                seen += [line.strip() for line in f if line.strip()]
        self.assertEqual(len(seen), 2500)
        self.assertEqual(len(set(seen)), 2500)
        self.assertEqual(seen[0], "u0@example.com")
        self.assertEqual(seen[-1], "u2499@example.com")

    def test_single_chunk_keeps_the_requested_filename(self):
        rows = [{"email": "solo@example.com"}]
        target = os.path.join(tempfile.mkdtemp(), "out.txt")

        def writer(handle, chunk):
            for row in chunk:
                handle.write(row["email"] + "\n")

        written, total = baseops.write_chunks_stream(iter(rows), target, 1000, writer)
        self.assertEqual(total, 1)
        self.assertEqual(written, [target],
                         "единственный файл переименован в out_001.txt — "
                         "человек просил out.txt")

    def test_no_chunking_writes_one_file(self):
        rows = [{"email": f"u{i}@example.com"} for i in range(50)]
        target = os.path.join(tempfile.mkdtemp(), "out.txt")

        def writer(handle, chunk):
            for row in chunk:
                handle.write(row["email"] + "\n")

        written, total = baseops.write_chunks_stream(iter(rows), target, 0, writer)
        self.assertEqual((written, total), ([target], 50))

    def test_garbage_arguments_do_not_crash(self):
        for path in (None, "", 123, []):
            with self.subTest(path=path):
                self.assertEqual(baseops.write_chunks_stream([], path, 0, print),
                                 ([], 0))


if __name__ == "__main__":
    unittest.main()
