# -*- coding: utf-8 -*-
"""«Стоп» действительно останавливает, а окно после него освобождается.

Жалоба владельца: нажал «Стоп», в шапке написано «Проверка завершена», а
настройки по-прежнему приглушены и ничего нажать нельзя. На его же
скриншоте видно и вторую половину беды: результаты продолжали идти ПОСЛЕ
остановки.

Причина оказалась одна на оба симптома. Признак «идёт прогон» взводится
внутри рабочего потока и уже ПОСЛЕ подготовки, а подготовка идёт долго:
перебор прокси в триста потоков, прогрев модели, загрузка списков. Нажатый
в это время «Стоп» сбрасывал признак, поток доходил до конвейера и спокойно
взводил его обратно.
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.pipeline import ValidationPipeline  # noqa: E402


def make_pipeline():
    log = []
    done = []
    pipeline = ValidationPipeline(callbacks={
        "on_log": lambda text, kind="info": log.append((kind, text)),
        "on_complete": lambda: done.append(1),
    })
    return pipeline, log, done


# ────────────────────────────────────────────── остановка

def test_stop_clears_the_running_flag_at_once():
    pipeline, _log, _done = make_pipeline()
    pipeline.is_running = True
    pipeline.stop()
    assert pipeline.is_running is False


def test_stop_during_setup_is_not_overridden_by_the_pipeline():
    """Главный случай: остановку нажали, пока шла подготовка.

    Раньше конвейер, дойдя до работы, взводил признак обратно — прогон
    продолжался вопреки команде, а окно оставалось запертым до конца.
    """
    pipeline, _log, done = make_pipeline()
    pipeline.stop()
    pipeline.run_pipeline(email_sources=[], threads=1)

    assert pipeline.is_running is False, "конвейер взвёл признак вопреки остановке"
    assert done, "окно не узнало, что прогон закончился"


def test_stop_also_lifts_the_pause():
    """Иначе остановленный на паузе прогон стартует замершим в следующий раз."""
    pipeline, _log, _done = make_pipeline()
    pipeline.is_running = True
    pipeline.is_paused = True
    pipeline.stop()
    assert pipeline.is_paused is False


def test_stop_is_forgotten_by_the_next_run():
    """Положительный контроль: команда остановки не должна быть вечной.

    Без него проверка выше проходила бы и на конвейере, который просто
    никогда не запускается.
    """
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
    """Сквозная проверка: остановка на подготовке не даёт начать работу."""
    pipeline, _log, _done = make_pipeline()

    entered = threading.Event()
    reached_work = []

    def slow_setup(**kwargs):
        entered.set()
        time.sleep(0.35)

    real_run = pipeline.run_pipeline

    def spy_run(*args, **kwargs):
        # Настоящий конвейер сам решает, работать ему или нет, — смотрим
        # именно на его решение, а не на факт вызова.
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


# ────────────────────────────────────────────── падение потока

def test_a_crashed_worker_never_leaves_the_window_locked():
    """Упавший поток раньше уносил с собой признак «идёт прогон».

    Окно запиралось намертво: помогал только перезапуск программы.
    """
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
    """Молча съеденное падение выглядит как «нажал и ничего не произошло»."""
    pipeline, log, _done = make_pipeline()
    pipeline.is_running = True
    pipeline.setup = lambda **kwargs: (_ for _ in ()).throw(ValueError("текст ошибки"))

    thread = pipeline.start(email_sources=[], threads=1, timeout=1, fix_typos=False,
                            check_spam=False, deep_ping=False, enable_ai=False)
    thread.join(10)

    text = " ".join(t for _k, t in log)
    assert "ValueError" in text and "текст ошибки" in text, log


def test_start_returns_the_thread_so_the_window_can_watch_it():
    """Без возврата потока окно не может проверить, жив ли прогон на самом деле."""
    pipeline, _log, _done = make_pipeline()
    pipeline.setup = lambda **kwargs: None
    pipeline.run_pipeline = lambda *a, **k: None

    thread = pipeline.start(email_sources=[], threads=1, timeout=1, fix_typos=False,
                            check_spam=False, deep_ping=False, enable_ai=False)
    assert isinstance(thread, threading.Thread)
    thread.join(10)


# ────────────────────────────────────────────── окно

def test_window_unlocks_as_soon_as_the_run_stops():
    """Сторона окна: запор снимается сразу после остановки."""
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
    """Завершившийся сам по себе прогон тоже освобождает окно."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_complete()
    assert api._state == "done"
    assert api._busy() is False
    assert not api.paste({"kind": "emails", "text": "ivan@gmail.com"}).get("error")

def test_window_unlocks_when_the_collection_is_told_to_stop():
    """Сбор адресов отпускает окно сразу после команды, а не после смерти потока.

    Поток может ещё долго закрывать Tor и отпускать соединения. Всё это
    время окно оставалось бы запертым, хотя команда уже отдана. Источники
    конвейер забирает копией при запуске, так что менять их безопасно.
    """
    import threading as th

    from ui.webapp import ValidatorApi

    api = ValidatorApi()

    class Collecting:
        def __init__(self):
            self._stop_event = th.Event()

        def is_alive(self):
            return True          # поток ещё доигрывает

    class Idle:
        is_running = False

    api.pipeline = Idle()
    api.parser = Collecting()
    assert api._busy() is True, "идущий сбор обязан запирать ввод"

    api.parser._stop_event.set()
    assert api._busy() is False, "окно осталось запертым после команды «Стоп»"
    assert not api.paste({"kind": "dorks", "text": "site:vk.com"}).get("error")


# ────────────────────────────────────────────── двойной запуск

def test_double_click_on_start_launches_only_one_run():
    """Второй щелчок во время подготовки не должен запускать второй конвейер.

    Признак «идёт прогон» взводится поздно — уже внутри рабочего потока и
    после подготовки, а она длится минутами. Всё это время повторный щелчок
    проходил проверку и стартовал ЕЩЁ ОДИН прогон. В логе владельца это
    выглядело как удвоение всех строк, а счётчики показывали один прогон,
    потому что второй запуск очищал хранилище.
    """
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
            tm.sleep(0.4)                    # подготовка
            api.pipeline.is_running = True   # только теперь конвейер объявился
            tm.sleep(0.2)
            api.pipeline.is_running = False

        thread = th.Thread(target=worker, daemon=True)
        thread.start()
        return thread

    api.pipeline.start = fake_start

    assert api.start({})["ok"] is True
    tm.sleep(0.1)                            # владелец жмёт второй раз
    second = api.start({})
    assert second["ok"] is False
    assert "уже идёт" in second["error"]

    tm.sleep(1.0)
    assert launched == [1], "запущено конвейеров: %d" % len(launched)


def test_double_start_window_is_released_when_the_run_ends():
    """Положительный контроль: запрет не может остаться навсегда.

    Иначе «второй запуск невозможен» достигалось бы тем, что и первый больше
    никогда не повторить.
    """
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
    """Упавшая подготовка не должна запирать кнопку до перезапуска программы."""
    import threading as th
    import time as tm

    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})

    def crashing_start(**kwargs):
        def worker():
            # Настоящий поток конвейера ловит своё исключение сам (это уже
            # проверено выше); здесь важно лишь то, что он умер, не объявив
            # себя идущим. Ловим и мы, чтобы не сыпать в вывод чужой шум.
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
