# -*- coding: utf-8 -*-
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline import ValidationPipeline


def make_pipeline():
    log = []
    done = []
    pipeline = ValidationPipeline(callbacks={
        "on_log": lambda text, kind="info": log.append((kind, text)),
        "on_complete": lambda: done.append(1),
    })
    return pipeline, log, done


def test_stop_clears_the_running_flag_at_once():
    pipeline, _log, _done = make_pipeline()
    pipeline.is_running = True
    pipeline.stop()
    assert pipeline.is_running is False


def test_stop_during_setup_is_not_overridden_by_the_pipeline():
    pipeline, _log, done = make_pipeline()
    pipeline.stop()
    pipeline.run_pipeline(email_sources=[], threads=1)

    assert pipeline.is_running is False, "конвейер взвёл признак вопреки остановке"
    assert done, "окно не узнало, что прогон закончился"


def test_stop_also_lifts_the_pause():
    pipeline, _log, _done = make_pipeline()
    pipeline.is_running = True
    pipeline.is_paused = True
    pipeline.stop()
    assert pipeline.is_paused is False


def test_stop_is_forgotten_by_the_next_run():
    pipeline, _log, _done = make_pipeline()
    pipeline.stop()
    assert pipeline._stop_requested is True

    started = []
    pipeline.setup = lambda **kwargs: None
    pipeline.run_pipeline = lambda *a, **k: started.append(pipeline._stop_requested)

    thread = pipeline.start(email_sources=[], threads=1, timeout=1, fix_typos=False,
                            check_spam=False, deep_ping=False, enable_ai=False)
    thread.join(10)
    assert started == [False], started


def test_stop_during_a_slow_setup_prevents_the_work(monkeypatch):
    pipeline, _log, _done = make_pipeline()

    entered = threading.Event()
    reached_work = []

    def slow_setup(**kwargs):
        entered.set()
        time.sleep(0.35)

    real_run = pipeline.run_pipeline

    def spy_run(*args, **kwargs):
        real_run(*args, **kwargs)
        reached_work.append(pipeline.is_running)

    pipeline.setup = slow_setup
    pipeline.run_pipeline = spy_run

    thread = pipeline.start(email_sources=[], threads=1, timeout=1, fix_typos=False,
                            check_spam=False, deep_ping=False, enable_ai=False)
    assert entered.wait(5), "подготовка не началась"
    pipeline.stop()
    thread.join(10)

    assert reached_work == [False], reached_work
    assert pipeline.is_running is False


def test_a_crashed_worker_never_leaves_the_window_locked():
    pipeline, log, done = make_pipeline()
    pipeline.is_running = True
    pipeline.setup = lambda **kwargs: (_ for _ in ()).throw(RuntimeError("подстава"))

    thread = pipeline.start(email_sources=[], threads=1, timeout=1, fix_typos=False,
                            check_spam=False, deep_ping=False, enable_ai=False)
    thread.join(10)

    assert thread.is_alive() is False
    assert pipeline.is_running is False, "окно осталось запертым после падения"
    assert done, "окно не узнало, что прогон закончился"
    assert any("прервана ошибкой" in text for _kind, text in log), log


def test_a_crash_is_reported_not_swallowed():
    pipeline, log, _done = make_pipeline()
    pipeline.is_running = True
    pipeline.setup = lambda **kwargs: (_ for _ in ()).throw(ValueError("текст ошибки"))

    thread = pipeline.start(email_sources=[], threads=1, timeout=1, fix_typos=False,
                            check_spam=False, deep_ping=False, enable_ai=False)
    thread.join(10)

    text = " ".join(t for _k, t in log)
    assert "ValueError" in text and "текст ошибки" in text, log


def test_start_returns_the_thread_so_the_window_can_watch_it():
    pipeline, _log, _done = make_pipeline()
    pipeline.setup = lambda **kwargs: None
    pipeline.run_pipeline = lambda *a, **k: None

    thread = pipeline.start(email_sources=[], threads=1, timeout=1, fix_typos=False,
                            check_spam=False, deep_ping=False, enable_ai=False)
    assert isinstance(thread, threading.Thread)
    thread.join(10)


def test_window_unlocks_as_soon_as_the_run_stops():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})

    class Busy:
        is_running = True

    api.pipeline = Busy()
    assert api._busy() is True
    assert api.paste({"kind": "emails", "text": "anna@yahoo.com"}).get("error")

    Busy.is_running = False
    assert api._busy() is False
    assert not api.paste({"kind": "emails", "text": "anna@yahoo.com"}).get("error")


def test_window_does_not_stay_locked_after_a_finished_run():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_complete()
    assert api._state == "done"
    assert api._busy() is False
    assert not api.paste({"kind": "emails", "text": "ivan@gmail.com"}).get("error")

def test_window_unlocks_when_the_collection_is_told_to_stop():
    import threading as th

    from ui.webapp import ValidatorApi

    api = ValidatorApi()

    class Collecting:
        def __init__(self):
            self._stop_event = th.Event()

        def is_alive(self):
            return True

    class Idle:
        is_running = False

    api.pipeline = Idle()
    api.parser = Collecting()
    assert api._busy() is True, "идущий сбор обязан запирать ввод"

    api.parser._stop_event.set()
    assert api._busy() is False, "окно осталось запертым после команды «Стоп»"
    assert not api.paste({"kind": "dorks", "text": "site:vk.com"}).get("error")


def test_double_click_on_start_launches_only_one_run():
    import threading as th
    import time as tm

    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})

    launched = []

    def fake_start(**kwargs):
        launched.append(1)

        def worker():
            tm.sleep(0.4)
            api.pipeline.is_running = True
            tm.sleep(0.2)
            api.pipeline.is_running = False

        thread = th.Thread(target=worker, daemon=True)
        thread.start()
        return thread

    api.pipeline.start = fake_start

    assert api.start({})["ok"] is True
    tm.sleep(0.1)
    second = api.start({})
    assert second["ok"] is False
    assert "уже идёт" in second["error"]

    tm.sleep(1.0)
    assert launched == [1], "запущено конвейеров: %d" % len(launched)


def test_double_start_window_is_released_when_the_run_ends():
    import threading as th
    import time as tm

    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})

    launched = []

    def fake_start(**kwargs):
        launched.append(1)
        thread = th.Thread(target=lambda: tm.sleep(0.2), daemon=True)
        thread.start()
        return thread

    api.pipeline.start = fake_start

    assert api.start({})["ok"] is True
    tm.sleep(0.6)
    assert api._busy() is False, "запрет остался после конца прогона"
    assert api.start({})["ok"] is True, "повторный запуск стал невозможен"
    tm.sleep(0.4)
    assert len(launched) == 2


def test_double_start_a_crashed_launch_does_not_lock_the_button():
    import threading as th
    import time as tm

    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})

    def crashing_start(**kwargs):
        def worker():
            try:
                tm.sleep(0.1)
                raise RuntimeError("подстава")
            except RuntimeError:
                pass

        thread = th.Thread(target=worker, daemon=True)
        thread.start()
        return thread

    api.pipeline.start = crashing_start
    assert api.start({})["ok"] is True
    tm.sleep(0.6)
    assert api._busy() is False
