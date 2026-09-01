"""S6/S7/S8 + U3: бэк не блокируется, не растёт по памяти и продолжается.

Тесты названы так, чтобы гейты выбирали их по -k: retry_schedule, dedup,
resume, no_blocking.
"""

import inspect
import os
import re
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.runstate import RunState, run_id_for, DEFAULT_RETRY_DELAY


def state_in(tmp, run_id="test", **kw):
    return RunState(run_id, path=os.path.join(tmp, "state.sqlite"), **kw)


class TestDedupOnDisk(unittest.TestCase):
    """S7: дедуп больше не держит всю базу в оперативной памяти."""

    def test_dedup_catches_repeats(self):
        with tempfile.TemporaryDirectory() as tmp:
            with state_in(tmp) as st:
                self.assertTrue(st.add_if_new("a@x.com"))
                self.assertFalse(st.add_if_new("a@x.com"))
                self.assertTrue(st.add_if_new("b@x.com"))
                self.assertFalse(st.add_if_new("b@x.com"))

    def test_dedup_catches_repeat_before_batch_reaches_disk(self):
        """Два одинаковых адреса подряд обязаны схлопнуться, не дожидаясь записи."""
        with tempfile.TemporaryDirectory() as tmp:
            with state_in(tmp, flush_every=1000) as st:
                self.assertTrue(st.add_if_new("dup@x.com"))
                self.assertFalse(st.add_if_new("dup@x.com"),
                                 "дубль проскочил, пока пачка не долетела до диска")

    def test_dedup_does_not_grow_python_memory(self):
        """Главное свойство: сто тысяч ключей не превращаются в сто тысяч объектов.

        Меряем не сам процесс (это шумно), а то, что реально росло раньше —
        размер структуры в памяти. У RunState это буфер пачки: он обязан
        оставаться в пределах flush_every, сколько бы ключей ни прошло.
        """
        with tempfile.TemporaryDirectory() as tmp:
            with state_in(tmp, flush_every=256) as st:
                for i in range(100_000):
                    st.add_if_new(f"user{i}@x.com")
                self.assertLessEqual(
                    len(st._pending_seen), 256,
                    "буфер дедупа растёт вместе с базой — память утекает как раньше")
                self.assertEqual(st.seen_count, 100_000)

    def test_dedup_survives_reopen(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.sqlite")
            first = RunState("run-1", path=path)
            first.add_if_new("a@x.com")
            first.close()

            second = RunState("run-1", path=path)
            self.assertFalse(second.add_if_new("a@x.com"),
                             "после переоткрытия дедуп забыл уже виденный адрес")
            second.close()

    def test_dedup_is_scoped_to_its_run(self):
        """Чужой прогон не должен считать наши адреса виденными."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.sqlite")
            a = RunState("run-a", path=path)
            a.add_if_new("shared@x.com")
            a.close()

            b = RunState("run-b", path=path)
            self.assertTrue(b.add_if_new("shared@x.com"),
                            "дедуп протёк между разными прогонами")
            b.close()

    def test_dedup_is_threadsafe(self):
        """Сто потоков на один ключ — новым он обязан оказаться ровно раз."""
        with tempfile.TemporaryDirectory() as tmp:
            with state_in(tmp) as st:
                wins = []
                lock = threading.Lock()

                def worker():
                    if st.add_if_new("race@x.com"):
                        with lock:
                            wins.append(1)

                threads = [threading.Thread(target=worker) for _ in range(100)]
                for t in threads:
                    t.start()
                for t in threads:
                    t.join()
                self.assertEqual(len(wins), 1, f"ключ признан новым {len(wins)} раз")


class TestResume(unittest.TestCase):
    """S8: прерванный прогон продолжается, а не начинается заново."""

    def test_resume_skips_already_done(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.sqlite")
            first = RunState("run-1", path=path)
            for i in range(10):
                first.add_if_new(f"u{i}@x.com")
                first.mark_done(f"u{i}@x.com")
            first.close()

            second = RunState("run-1", path=path, resume=True)
            self.assertEqual(second.resumed_count, 10,
                             "журнал сделанного не подхвачен при возобновлении")
            self.assertTrue(second.is_done("u3@x.com"))
            self.assertFalse(second.is_done("u99@x.com"))
            second.close()

    def test_resume_false_starts_clean(self):
        """Негативный контроль: без resume прогон обязан начаться с нуля."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "state.sqlite")
            first = RunState("run-1", path=path)
            first.add_if_new("u@x.com")
            first.mark_done("u@x.com")
            first.close()

            second = RunState("run-1", path=path, resume=False)
            self.assertEqual(second.resumed_count, 0)
            self.assertFalse(second.is_done("u@x.com"))
            self.assertTrue(second.add_if_new("u@x.com"),
                            "при resume=False старый дедуп не сброшен")
            second.close()

    def test_resume_run_id_is_stable_for_same_sources(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "base.txt")
            open(path, "w", encoding="utf-8").write("a@x.com\n")
            sources = [{"type": "file", "path": path}]
            self.assertEqual(run_id_for(sources), run_id_for(sources))

    def test_resume_run_id_changes_when_file_changes(self):
        """Другая база — другой журнал: чужое «сделано» на неё не распространяется."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "base.txt")
            open(path, "w", encoding="utf-8").write("a@x.com\n")
            before = run_id_for([{"type": "file", "path": path}])
            open(path, "a", encoding="utf-8").write("b@x.com\nc@x.com\n")
            after = run_id_for([{"type": "file", "path": path}])
            self.assertNotEqual(before, after)

    def test_resume_counts_pending_batch(self):
        """Недописанная пачка обязана считаться сделанной — иначе адрес повторится."""
        with tempfile.TemporaryDirectory() as tmp:
            with state_in(tmp, flush_every=1000) as st:
                st.mark_done("fresh@x.com")
                self.assertTrue(st.is_done("fresh@x.com"))
                self.assertEqual(st.done_count(), 1)


class TestRetryDelays(unittest.TestCase):
    """Очередь повторов переехала в конвейер, а выдержки остались здесь.

    Сама очередь (таблица retry и пять методов вокруг неё) из RunState
    вычищена: её не вызывал никто, кроме этих же тестов, — отложенные адреса
    живут в очереди самого конвейера (core/pipeline.py). А константы выдержки
    он берёт отсюда, и они по-прежнему должны быть разными: сбой повторяют
    быстро, серый список — после его выдержки.
    """

    def test_retry_default_delay_is_the_quick_one(self):
        self.assertEqual(DEFAULT_RETRY_DELAY, 90)

    def test_retry_greylist_delay_outlasts_postgrey(self):
        from core.runstate import GREYLIST_RETRY_DELAY
        self.assertGreaterEqual(GREYLIST_RETRY_DELAY, 300,
                                "у postgrey выдержка 300 с — повтор раньше "
                                "получит тот же серый ответ")


class TestNoBlockingWaits(unittest.TestCase):
    """U3: в пайплайне не осталось глухих ожиданий."""

    def _pipeline_source(self):
        path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                            "core", "pipeline.py")
        return open(path, encoding="utf-8").read()

    def test_no_blocking_sleep_longer_than_a_second(self):
        """Любой sleep с константой больше 1 секунды — это зависание интерфейса."""
        source = self._pipeline_source()
        offenders = []
        for match in re.finditer(r"time\.sleep\(\s*([0-9]+(?:\.[0-9]+)?)\s*\)", source):
            if float(match.group(1)) > 1.0:
                line = source[:match.start()].count("\n") + 1
                offenders.append(f"строка {line}: sleep({match.group(1)})")
        self.assertEqual(offenders, [],
                         "остались блокирующие паузы: " + "; ".join(offenders))

    def test_no_blocking_ninety_second_loop_remains(self):
        """Негативный контроль на конкретную прежнюю конструкцию."""
        source = self._pipeline_source()
        self.assertNotIn("for i in range(90)", source,
                         "прежний цикл ожидания на 90 секунд всё ещё на месте")

    def test_no_blocking_detector_would_catch_a_real_offender(self):
        """Позитивный контроль: детектор обязан ловить настоящее нарушение.

        Без этой проверки два теста выше зелены и тогда, когда регулярка
        сломана и не находит вообще ничего.
        """
        sample = "def f():\n    time.sleep(90)\n"
        found = [m for m in re.finditer(r"time\.sleep\(\s*([0-9]+(?:\.[0-9]+)?)\s*\)", sample)
                 if float(m.group(1)) > 1.0]
        self.assertEqual(len(found), 1, "детектор блокирующих пауз не работает")

    def test_no_blocking_pipeline_accepts_resume_flag(self):
        """Возобновление обязано быть доступно снаружи, а не только внутри."""
        from core.pipeline import ValidationPipeline
        for method in (ValidationPipeline.run_pipeline, ValidationPipeline.start):
            with self.subTest(method=method.__name__):
                params = inspect.signature(method).parameters
                self.assertIn("resume", params,
                              f"{method.__name__} не принимает resume")


if __name__ == "__main__":
    unittest.main()
