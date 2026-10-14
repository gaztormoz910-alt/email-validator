# -*- coding: utf-8 -*-
"""Журнал активности движка (core/activity.py): по нему окно и консоль
говорят, работает ли софт, ждёт ли по плану, медлит или встал.

Просьба владельца 14.10.2026: «чтобы не создавалось впечатление, как будто
софт завис или даже не включён». Каждый тест ниже привязан к тому, какой
ответ полоса состояния обязана дать в конкретной ситуации, — включая
отрицательные: «встал» обязан называться «встал», а не «работает».

Время здесь подставное и двигается руками: тесты не спят и не зависят от
скорости машины (CI на Windows в разы медленнее — см. project_ci).
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.activity import (ActivityMonitor, Pulse, describe, payload,  # noqa: E402
                           pulse_line, observe_callbacks, raw, fmt_duration,
                           fmt_number, NET_SLOW, NET_STALL, STAGES)


class Часы:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t

    def прошло(self, s):
        self.t += s


def монитор(**kw):
    часы = Часы()
    строки = []
    m = ActivityMonitor(emit=lambda текст, тег: строки.append((тег, текст)),
                        clock=часы, **kw)
    return m, часы, строки


def уровень(m, **kw):
    return describe(m.snapshot(**kw))["level"]


# ══════════════════════════════ форматирование

def test_durations_read_like_the_engine_writes_them():
    assert fmt_duration(0) == "0 с"
    assert fmt_duration(59.4) == "59 с"
    assert fmt_duration(65) == "1 мин 05 с"
    assert fmt_duration(3600 + 2 * 60 + 5) == "1 ч 02 мин"
    assert fmt_duration(None) == "—"


def test_numbers_are_grouped_with_spaces():
    assert fmt_number(1234567) == "1 234 567"
    assert fmt_number(12) == "12"


# ══════════════════════════════ этапы и итог

def test_stage_change_is_written_with_duration_of_the_previous_one():
    m, часы, строки = монитор()
    m.begin()
    m.stage("lists")
    часы.прошло(12)
    m.stage("check")
    assert ("stage", "▶ Обновление списков одноразовых доменов") in строки
    assert ("stage", "✓ Обновление списков одноразовых доменов — 12 с") in строки
    assert ("stage", "▶ Проверка адресов") in строки


def test_launch_stage_is_silent():
    """«Запуск» длится доли секунды — строка про него была бы шумом."""
    m, часы, строки = монитор()
    m.begin()
    часы.прошло(0.2)
    m.stage("cache")
    assert all("Запуск" not in текст for _тег, текст in строки), строки


def test_stage_without_begin_starts_the_run():
    """CLI и тесты зовут setup()/run_pipeline() напрямую, без start()."""
    m, _часы, _строки = монитор()
    m.stage("check")
    assert m.state == "running"
    assert уровень(m) == "ok"


def test_finish_writes_total_time_even_when_clock_starts_at_zero():
    """Отметка 0.0 — законная; раньше «or» превращал её в «сейчас» и
    итог выходил «прогон занял 0 с»."""
    часы = Часы()
    часы.t = 0.0
    строки = []
    m = ActivityMonitor(emit=lambda т, тег: строки.append(т), clock=часы)
    m.begin()
    m.stage("check")
    часы.прошло(262)
    m.finish("done")
    assert строки[-1] == "■ Готово. Весь прогон занял 4 мин 22 с."
    assert describe(m.snapshot())["detail"].startswith("Работа закончена за 4 мин 22 с")


@pytest.mark.parametrize("исход, начало", [
    ("done", "■ Готово."),
    ("stopped", "■ Остановлено по вашей команде"),
    ("failed", "■ Прервано ошибкой"),
    ("blocked", "■ Работа не выполнялась: порт 25 закрыт"),
])
def test_every_outcome_has_its_own_final_line(исход, начало):
    m, часы, строки = монитор()
    m.begin()
    m.stage("check")
    часы.прошло(5)
    m.finish(исход, "порт 25 закрыт" if исход == "blocked" else "")
    assert строки[-1][1].startswith(начало), строки[-1]
    assert уровень(m) == исход


def test_finish_twice_writes_once():
    m, _часы, строки = монитор()
    m.begin()
    m.finish("done")
    m.finish("failed")
    assert sum(1 for _т, s in строки if s.startswith("■")) == 1
    assert m.state == "done"


def test_finish_without_run_does_not_claim_a_duration():
    m, _часы, строки = монитор()
    m.finish("blocked", "нечем")
    assert строки == []
    assert уровень(m) == "blocked"


# ══════════════════════════════ «в работе»

def test_inflight_counts_and_never_goes_negative():
    m, _часы, _строки = монитор()
    m.enter()
    m.enter()
    m.leave()
    assert m.snapshot()["inflight"] == 1
    m.leave()
    m.leave()                       # лишний — не уводит в минус
    assert m.snapshot()["inflight"] == 0


def test_working_releases_on_exception():
    m, _часы, _строки = монитор()
    with pytest.raises(ValueError):
        with m.working():
            assert m.snapshot()["inflight"] == 1
            raise ValueError("сбой проверки")
    assert m.snapshot()["inflight"] == 0


def test_counted_wraps_for_thread_pools():
    m, _часы, _строки = монитор()
    seen = []
    обёрнутая = m.counted(lambda x: seen.append(m.snapshot()["inflight"]) or x * 2)
    assert обёрнутая(21) == 42
    assert seen == [1]
    assert m.snapshot()["inflight"] == 0


# ══════════════════════════════ уровни: «работает», «медлит», «встал»

def test_idle_says_not_started():
    m, _часы, _строки = монитор()
    d = describe(m.snapshot())
    assert d["level"] == "idle" and d["title"] == "Не запущено"


def test_fresh_event_is_working():
    m, часы, _строки = монитор()
    m.stage("check")
    m.progress(5, 100)
    часы.прошло(1)
    d = describe(m.snapshot(alive=True))
    assert d["level"] == "ok" and d["title"] == "Работает"
    assert "проверено 5 из 100 (5%)" in d["detail"]


def test_network_stage_with_busy_threads_is_slow_then_stalled():
    """Занятые потоки + тишина: сначала «медленно» (сервер тянет), а после
    общего дедлайна проверки с запасом — «похоже на зависание»."""
    m, часы, _строки = монитор()
    m.stage("check")
    m.enter()
    часы.прошло(NET_SLOW - 1)
    assert уровень(m) == "ok"
    часы.прошло(2)
    d = describe(m.snapshot())
    assert d["level"] == "slow"
    assert "в работе 1" in d["detail"] and "до 3 мин" in d["detail"]
    часы.прошло(NET_STALL)
    d = describe(m.snapshot())
    assert d["level"] == "stall" and d["title"] == "Похоже на зависание"
    assert "Стоп" in d["detail"]


def test_network_stage_without_busy_threads_says_nobody_waits():
    m, часы, _строки = монитор()
    m.stage("check")
    часы.прошло(STAGES["check"][2] + 1)
    d = describe(m.snapshot())
    assert d["level"] == "slow"
    assert "ни одной проверки в работе" in d["detail"]


def test_quiet_stage_silence_is_called_normal_not_slow():
    """Прогрев модели молчит минутами — это норма, и окно так и говорит."""
    m, часы, _строки = монитор()
    m.stage("ai")
    часы.прошло(120)
    d = describe(m.snapshot())
    assert d["level"] == "ok"
    assert "это нормально" in d["detail"]
    часы.прошло(STAGES["ai"][2])
    assert уровень(m) == "slow"
    часы.прошло(STAGES["ai"][2] * 3)
    assert уровень(m) == "stall"


def test_planned_wait_is_not_a_hang():
    m, часы, _строки = монитор()
    m.stage("retry")
    m.wait(42, "ближайший созреет")
    часы.прошло(300)            # долго, но по плану: срок ставится заново
    m.wait(30, "ближайший созреет")
    d = describe(m.snapshot())
    assert d["level"] == "wait" and d["title"] == "Ждёт по плану"
    assert "ещё 30 с: ближайший созреет" in d["detail"]


def test_wait_with_busy_threads_is_work_with_a_note():
    m, _часы, _строки = монитор()
    m.stage("retry")
    m.enter()
    m.wait(20, "x")
    d = describe(m.snapshot())
    assert d["level"] == "ok" and "следующие созреют через 20 с" in d["detail"]


def test_unwait_ends_the_planned_wait():
    m, _часы, _строки = монитор()
    m.stage("retry")
    m.wait(20, "x")
    m.unwait()
    assert уровень(m) == "ok"


def test_pause_and_stop_have_their_own_words():
    m, _часы, _строки = монитор()
    m.stage("check")
    assert describe(m.snapshot(paused=True))["title"] == "На паузе"
    m.request_stop()
    d = describe(m.snapshot())
    assert d["level"] == "stopping" and d["title"] == "Останавливаю"


def test_dead_worker_is_named_even_with_fresh_events():
    """Поток движка мёртв, а итога нет — это сбой, как бы свежо ни было."""
    m, _часы, _строки = монитор()
    m.stage("check")
    m.beat()
    d = describe(m.snapshot(alive=False))
    assert d["level"] == "dead" and d["title"] == "Движок остановился"


def test_alive_unknown_is_not_dead():
    m, _часы, _строки = монитор()
    m.stage("check")
    assert уровень(m, alive=None) == "ok"


# ══════════════════════════════ скорость и остаток

def test_rate_needs_fifteen_seconds_of_observation():
    m, часы, _строки = монитор()
    m.stage("check")
    m.progress(0, 1000)
    for i in range(1, 11):
        часы.прошло(1)
        m.progress(i * 10, 1000)
    assert m.snapshot()["rate"] is None          # 10 с — ещё рано
    for i in range(11, 31):
        часы.прошло(1)
        m.progress(i * 10, 1000)
    snap = m.snapshot()
    assert snap["rate"] == pytest.approx(600, rel=0.01)   # 10 в секунду
    assert snap["eta"] == pytest.approx((1000 - 300) / 10, rel=0.01)
    assert "~600 адресов/мин" in describe(snap)["detail"]


# ══════════════════════════════ окно и пульс

def test_payload_has_trail_with_active_stage_and_no_silent_stage():
    m, часы, _строки = монитор()
    m.begin()
    m.stage("cache")
    часы.прошло(3)
    m.stage("check")
    часы.прошло(7)
    p = payload(m.snapshot())
    assert [s["label"] for s in p["trail"]] == ["Кэш", "Проверка"]
    assert p["trail"][-1]["active"] is True and p["trail"][-1]["seconds"] == 7
    assert p["stageLabel"] == "Проверка адресов"
    assert {"level", "title", "detail"} <= set(p)


@pytest.mark.parametrize("сдвиг, тег", [(1, "pulse"), (NET_SLOW + 1, "pulse-slow"),
                                        (NET_STALL + 1, "pulse-stall")])
def test_pulse_line_is_tagged_by_alarm(сдвиг, тег):
    m, часы, _строки = монитор()
    m.stage("check")
    m.enter()
    часы.прошло(сдвиг)
    текст, т = pulse_line(m.snapshot())
    assert т == тег
    assert текст.startswith("[ПУЛЬС] ")


def test_pulse_step_writes_on_schedule():
    m, часы, _строки = монитор()
    m.stage("check")
    p = Pulse(m, emit=lambda *a: None, interval=15, clock=часы)
    t, lvl, write = p.step(часы(), "ok")
    assert not write                              # только что писали
    часы.прошло(14)
    t, lvl, write = p.step(t, lvl)
    assert not write
    часы.прошло(1)
    t, lvl, write = p.step(t, lvl)
    assert write and lvl == "ok"                  # ровно по расписанию


def test_pulse_step_raises_alarm_before_schedule_but_not_flickering():
    """Стало медленно через 2 с после пульса: тревога не ждёт 15 с своей
    очереди, но и не пишется чаще раза в 5 с — на границе порога уровень
    может колебаться, и журнал не должен мигать."""
    m, часы, _строки = монитор()
    m.stage("check")
    m.enter()
    часы.прошло(NET_SLOW - 1)                     # ещё «работает»
    p = Pulse(m, emit=lambda *a: None, interval=15, clock=часы)
    t = часы()                                     # пульс только что был
    t, lvl, write = p.step(t, "ok")
    assert not write and lvl == "ok"
    часы.прошло(2)                                 # стало «медленно»
    t2, lvl2, write = p.step(t, lvl)
    assert not write, "тревога через 2 с после пульса — это мигание"
    часы.прошло(4)                                 # 6 с после пульса
    t3, lvl3, write = p.step(t2, lvl2)
    assert write and lvl3 == "slow", "тревога ждала бы своей очереди 15 с"
    часы.прошло(1)
    _t, _l, write = p.step(t3, lvl3)
    assert not write                               # уровень тот же, срок не вышел


def test_pulse_does_not_count_as_activity():
    """Пульс — не событие: иначе «последнее событие» не старело бы дольше
    интервала пульса, и зависание выглядело бы работой."""
    m, часы, _строки = монитор()
    m.stage("check")
    часы.прошло(100)
    до = m.snapshot()["lastEventAge"]
    sink = []
    p = Pulse(m, emit=lambda т, тег: sink.append(т), clock=часы)
    p._send(*pulse_line(p.snapshot()))
    assert sink and m.snapshot()["lastEventAge"] == до


def test_pulse_thread_writes_and_stops_when_run_ends():
    m = ActivityMonitor()
    m.begin()
    m.stage("check")
    sink = []
    p = Pulse(m, emit=lambda т, тег: sink.append((тег, т)), interval=0.05, tick=0.01)
    p.start()
    предел = time.monotonic() + 10
    while not sink and time.monotonic() < предел:
        time.sleep(0.01)
    assert sink, "пульс не написал ни строки"
    m.finish("done")
    p.join(10)
    assert not p.is_alive(), "пульс не остановился после конца прогона"


def test_pulse_thread_reports_dead_engine_once():
    m = ActivityMonitor()
    m.begin()
    m.stage("check")
    sink = []
    p = Pulse(m, emit=lambda т, тег: sink.append((тег, т)), alive=lambda: False,
              interval=60, tick=0.01)
    p.start()
    p.join(10)
    assert not p.is_alive()
    assert len(sink) == 1 and sink[0][0] == "pulse-stall"
    assert "Движок остановился" in sink[0][1]


# ══════════════════════════════ наблюдение за колбэками

def test_observed_callbacks_feed_the_monitor_and_keep_results():
    m, часы, _строки = монитор()
    m.stage("check")
    часы.прошло(50)
    вызовы = []
    cb = {"on_log": lambda т, тег="info": вызовы.append(т),
          "on_progress": lambda a, b: вызовы.append((a, b)),
          "on_proxy_progress": lambda a, b: None,
          "on_revise": lambda *a: 7,
          "on_complete": lambda: "не трогать"}
    исходный_complete = cb["on_complete"]
    observe_callbacks(cb, m)
    assert cb["on_revise"]("d", "Unknown", "") == 7, "возврат колбэка потерян"
    assert cb["on_complete"] is исходный_complete, "этот колбэк не наблюдается"
    cb["on_progress"](3, 9)
    cb["on_proxy_progress"](4, 10)
    snap = m.snapshot()
    assert (snap["current"], snap["total"]) == (3, 9)
    assert (snap["auxCurrent"], snap["auxTotal"]) == (4, 10)
    assert snap["lastEventAge"] == 0
    assert вызовы[-1] == (3, 9)


def test_observe_twice_does_not_double_wrap_and_raw_unwraps():
    m, _часы, _строки = монитор()
    исходный = lambda т, тег="info": None  # noqa: E731
    cb = {"on_log": исходный}
    observe_callbacks(cb, m)
    первая = cb["on_log"]
    observe_callbacks(cb, m)
    assert cb["on_log"] is первая
    assert raw(cb["on_log"]) is исходный
    assert raw(исходный) is исходный


def test_monitor_is_thread_safe_under_contention():
    m = ActivityMonitor()
    m.stage("check")

    def потрудиться():
        for _ in range(2000):
            with m.working():
                m.beat()

    потоки = [threading.Thread(target=потрудиться) for _ in range(8)]
    for п in потоки:
        п.start()
    for п in потоки:
        п.join(30)
    assert m.snapshot()["inflight"] == 0
