# -*- coding: utf-8 -*-
"""Журнал активности: дефекты, найденные проверкой кода 1.3.8 (16.10.2026).

Каждый тест — один подтверждённый сценарий, в котором полоса состояния или
журнал говорили неправду, или сбор адресов вёл себя неверно. Все они падали
на коде до исправления (проверено подстановкой старых строк). Главное из
найденного — ложные тревоги, то есть ровно то, от чего владелец просил
избавиться: «Похоже на зависание … нажмите «Стоп»» после паузы и после
планового ожидания перепроверки, хотя движок работал.
"""
import io
import os
import re
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.activity import (Pulse, describe, payload, pulse_line,  # noqa: E402
                           net_budget, NET_STALL)
from tests.test_activity import монитор, уровень  # noqa: E402
from tests.test_activity_bridge import (_конвейер, _ждать, _старт, _Net,  # noqa: E402
                                        _Поисковик, читать)


def _пульс(m, часы, paused=lambda: False):
    return Pulse(m, emit=lambda т, тег: None, paused=paused, clock=часы)


# ══════════════════════════════ ложные тревоги

def test_first_check_after_a_planned_wait_is_not_a_hang():
    """Перепроверка ждала созревания адреса 5 минут — это план, не молчание."""
    m, часы, _ = монитор()
    m.stage("retry")
    m.beat()                                    # «Отложено на перепроверку…»
    m.wait(300, "ближайший отложенный адрес созреет")
    часы.прошло(150)
    assert уровень(m) == "wait"
    пульс = _пульс(m, часы)
    последний, уровень_пульса = часы.t, "wait"
    часы.прошло(150)
    # Срок вышел, адрес ещё не взят в работу (доли секунды до enter()).
    assert уровень(m) == "ok", describe(m.snapshot())
    m.enter()                                   # созревший адрес ушёл в работу
    m.unwait()
    часы.прошло(1)
    assert уровень(m) == "ok", describe(m.snapshot())
    _t, новый, писать = пульс.step(последний, уровень_пульса)
    assert новый not in ("slow", "stall"), "пульс написал бы ложную тревогу"


def test_resume_after_a_long_pause_is_not_a_hang():
    m, часы, _ = монитор()
    m.stage("check")
    for _ in range(100):
        m.enter()
    m.beat()
    m.set_paused(True)
    часы.прошло(307)
    assert уровень(m) == "paused"
    m.set_paused(False)
    часы.прошло(1)
    assert уровень(m) == "ok", describe(m.snapshot())


def test_resume_is_noticed_even_without_set_paused():
    """Окно и пульс передают флаг паузы в снимок — смена флага сама по себе
    событие. Кто бы ни снял паузу, тишина паузы не засчитывается."""
    m, часы, _ = монитор()
    m.stage("check")
    m.enter()
    m.beat()
    assert уровень(m, paused=True) == "paused"
    часы.прошло(300)
    assert уровень(m, paused=False) == "ok"


def test_pause_where_it_cannot_act_says_so():
    m, _часы, _ = монитор()
    m.stage("proxies")
    d = describe(m.snapshot(paused=True))
    assert d["level"] != "paused", d
    assert "пауза включится, когда начнётся проверка адресов" in d["detail"], d
    m.stage("check")
    assert describe(m.snapshot(paused=True))["level"] == "paused"


def test_stall_threshold_follows_the_configured_timeout():
    """Таймаут 85 с: одна сессия законно идёт 255 с (замер рецензии)."""
    from core.network import NetworkValidator
    deadline = NetworkValidator(timeout=85, proxies=None).address_deadline
    бюджет = net_budget(85, deadline)
    assert бюджет >= 255
    m, часы, _ = монитор()
    m.set_net_budget(бюджет)
    m.stage("check")
    m.enter()
    часы.прошло(255)
    assert уровень(m) == "slow", describe(m.snapshot())
    часы.прошло(бюджет + 61 - 255)
    assert уровень(m) == "stall"
    # Контроль: без бюджета прежний порог.
    m2, часы2, _ = монитор()
    m2.stage("check")
    m2.enter()
    часы2.прошло(NET_STALL + 1)
    assert уровень(m2) == "stall"


def test_default_timeout_keeps_the_old_threshold():
    from core.network import NetworkValidator
    deadline = NetworkValidator(timeout=5, proxies=None).address_deadline
    assert net_budget(5, deadline) + 60 <= NET_STALL


def test_setup_hands_the_budget_to_the_journal():
    src = читать("core", "pipeline_setup.py")
    assert "self.activity.set_net_budget(net_budget(" in src


def test_skipping_rows_checked_last_time_is_movement():
    m, часы, _ = монитор()
    m.stage("check")
    m.progress(0, 2_001_000)
    for секунда in range(1, 241):
        часы.прошло(1)
        m.skipped(секунда * 11_000)
    d = describe(m.snapshot())
    assert d["level"] == "ok", d
    assert "пропущено 2 640 000" in d["detail"], d


def test_eta_ignores_rows_checked_last_time():
    m, часы, _ = монитор()
    m.stage("check")
    m.progress(0, 31_000)
    m.skipped(30_000)
    for секунда in range(1, 23):
        часы.прошло(1)
        m.progress(секунда * 45, 31_000)
    eta = m.snapshot()["eta"]
    assert eta is not None and eta < 5, eta      # осталось 10 адресов
    assert "проверено 990 из 1 000" in describe(m.snapshot())["detail"]
    m.retotal(1000)
    m.progress(995, 31_000)                      # опоздавший старый знаменатель
    s = m.snapshot()
    assert s["total"] == 1000 and s["eta"] < 5, s


def test_interrupted_stage_gets_no_check_mark():
    m, часы, строки = монитор()
    m.stage("check")
    часы.прошло(5)
    m.finish("failed")
    тексты = [т for _тег, т in строки]
    assert "✗ Проверка адресов — оборвано ошибкой через 5 с" in тексты, тексты
    assert not any(т.startswith("✓ Проверка адресов") for т in тексты)
    assert payload(m.snapshot())["trail"][-1]["cut"] is True

    m, часы, строки = монитор()
    m.stage("check")
    m.request_stop()
    часы.прошло(3)
    m.stage("finish")
    часы.прошло(1)
    m.finish("stopped")
    тексты = [т for _тег, т in строки]
    assert "✗ Проверка адресов — остановлено через 3 с" in тексты, тексты
    # Итоги после «Стопа» доводятся до конца — они пройдены честно.
    assert "✓ Подведение итогов — 1 с" in тексты, тексты
    assert [s["cut"] for s in payload(m.snapshot())["trail"]] == [True, False]


def test_window_draws_cut_stage_with_a_cross():
    js = читать("ui", "web", "app.js")
    assert 's.cut ? "✗" : "✓"' in js
    assert ".live__step.is-cut" in читать("ui", "web", "style.css")


# ══════════════════════════════ конвейер проверки

def test_feeder_reports_skipped_rows_and_final_total():
    p, _строки, результаты = _конвейер()
    адреса = ["one@example.com"] * 1200 + ["two@example.com", "three@example.com"]
    p.run_pipeline([{"type": "text", "content": "\n".join(адреса)}], threads=2,
                   fix_typos=True, check_spam=False, deep_ping=True, enable_ai=False)
    s = p.activity.snapshot()
    assert s["skipped"] == 1199, s["skipped"]
    assert s["total"] == 3 and s["skipInTotal"] is False, s
    assert sorted(e for e, _ in результаты) == ["one@example.com", "three@example.com",
                                                "two@example.com"]


class _СетьСоСбоем(_Net):
    """Первый ответ — временный сбой нашей стороны, второй — вердикт."""

    def __init__(self):
        self.спрошено = {}

    def check_email(self, email, **_kw):
        n = self.спрошено[email] = self.спрошено.get(email, 0) + 1
        if n == 1:
            return {"status": "unknown", "reason": "Timeout", "mx_record": "mx.example.com",
                    "mx_records": ["mx.example.com"]}
        return super().check_email(email)


def test_pause_holds_the_retry_stage_too(monkeypatch):
    import core.pipeline as модуль
    monkeypatch.setattr(модуль, "DEFAULT_RETRY_DELAY", 0.0)
    p, _строки, результаты = _конвейер()
    p.network = _СетьСоСбоем()
    p.callbacks["on_phase"] = lambda имя, n=0: (p.pause() if имя == "retry"
                                                 and not p.is_paused else None)
    поток = threading.Thread(target=p.run_pipeline, args=(
        [{"type": "text", "content": "a1@example.com\na2@example.com"}],),
        kwargs=dict(threads=2, fix_typos=True, check_spam=False, deep_ping=True,
                    enable_ai=False), daemon=True)
    поток.start()
    assert _ждать(lambda: p.activity.stage_key == "retry", 30)
    time.sleep(1.5)
    assert результаты == [], "на паузе перепроверка всё равно выдала вердикты"
    assert describe(p.activity.snapshot(paused=p.is_paused))["level"] == "paused"
    p.pause()                                   # «Продолжить»
    поток.join(60)
    assert sorted(s for _e, s in результаты) == ["Valid", "Valid"]


def test_pause_pressed_during_preparation_is_not_lost():
    """Раньше run_pipeline молча сбрасывал паузу, а «Продолжить» её ставил."""
    p, _строки, результаты = _конвейер()
    p.is_paused = True                          # нажато на подготовке
    поток = threading.Thread(target=p.run_pipeline, args=(
        [{"type": "text", "content": "b1@example.com"}],),
        kwargs=dict(threads=1, fix_typos=True, check_spam=False, deep_ping=True,
                    enable_ai=False), daemon=True)
    поток.start()
    time.sleep(1.5)
    assert результаты == [], "пауза с подготовки потерялась"
    p.pause()
    поток.join(60)
    assert [s for _e, s in результаты] == ["Valid"]


def test_relaunch_never_shows_the_old_dead_worker():
    p, _строки, _р = _конвейер()
    мёртвый = threading.Thread(target=lambda: None)
    мёртвый.start()
    мёртвый.join()
    p.__dict__["_worker"] = мёртвый
    виделось = []
    исходный = p.activity.begin

    def begin():
        исходный()
        виделось.append(p._worker_alive())
    p.activity.begin = begin
    можно = threading.Event()
    p.setup = lambda **kw: можно.wait(10)
    поток = _старт(p)
    assert виделось == [None], виделось
    assert p._worker_alive() is True
    можно.set()
    поток.join(60)


# ══════════════════════════════ сбор адресов

class _ДолгийПоисковик(_Поисковик):
    """Выдаёт фрагменты по одному с паузой — дорк ищется долго."""

    def search_generator(self, query):
        for i in range(400):
            time.sleep(0.01)
            yield "x%d %s@example.com" % (i, re.sub(r"\W", "", query))


def _сбор_в_фоне(monkeypatch, текст, поисковик=_ДолгийПоисковик, потоков=2,
                 источник=None):
    import core.parser_pipeline as модуль
    from core.activity import ActivityMonitor

    class _Пусто:
        def __init__(self, *a, **kw):
            pass

    monkeypatch.setattr(модуль, "MLPredictor", _Пусто)
    monkeypatch.setattr(модуль, "NameExtractor", _Пусто)
    monkeypatch.setattr(модуль, "DuckDuckGoEngine", поисковик)
    завершено = []
    p = модуль.ParserPipeline(
        dork_sources=источник or [{"type": "text", "content": текст}],
        proxies=[], max_threads=потоков, timeout=1,
        on_log=lambda т, *a: None,
        on_complete=lambda aborted=False: завершено.append(aborted),
        engine_name="DuckDuckGo Lite", activity=ActivityMonitor(kind="parser"))
    # Фоновый: если сбор всё-таки зависнет, тест обязан упасть на join(),
    # а не держать процесс pytest до конца времён.
    p.daemon = True
    p.start()
    return p, завершено


def test_pause_then_stop_ends_the_parser(monkeypatch):
    p, завершено = _сбор_в_фоне(monkeypatch, "alpha\nbeta\ngamma\ndelta")
    assert _ждать(lambda: p.processed_snippets > 3, 30)
    p.pause()
    time.sleep(0.6)
    p.stop()
    p.join(10)
    assert not p.is_alive(), "сбор завис после «Пауза», затем «Стоп»"
    assert завершено == [True]


def test_feeder_does_not_hang_after_stop_and_releases_the_file(monkeypatch, tmp_path):
    путь = tmp_path / "dorks.txt"
    путь.write_text("\n".join("d%d" % i for i in range(3000)), encoding="utf-8")
    p, завершено = _сбор_в_фоне(monkeypatch, "", потоков=2,
                                источник=[{"type": "file", "path": str(путь)}])
    assert _ждать(lambda: p.processed_snippets > 3, 30)
    p.stop()
    p.join(10)
    assert завершено == [True]
    assert _ждать(lambda: not p.feeder_thread.is_alive(), 5), "фидер повис на полной очереди"
    os.remove(путь)                 # на Windows открытый файл удалить нельзя


def test_feeder_read_error_is_a_failure_not_done(monkeypatch):
    from core.streamer import StreamLoader
    from ui.webapp import ValidatorApi

    def обрыв(self):
        yield "one"
        yield "two"
        raise OSError("диск отвалился")
    monkeypatch.setattr(StreamLoader, "stream_lines", обрыв)
    p, завершено = _сбор_в_фоне(monkeypatch, "", поисковик=_Поисковик)
    p.join(30)
    assert завершено == [True], завершено
    assert "диск отвалился" in p.failed_reason
    окно = ValidatorApi()
    окно.parser = p
    окно.parser_activity.begin()
    окно._finish_parser_activity(True)
    d = describe(окно.parser_activity.snapshot())
    assert d["level"] == "failed" and "диск отвалился" in d["detail"], d


def test_crash_inside_the_parser_completes_once(monkeypatch):
    import core.parser_pipeline as модуль

    class _Сломано:
        def __init__(self, *a, **kw):
            raise RuntimeError("модель не загрузилась")
    monkeypatch.setattr(модуль, "MLPredictor", _Сломано)
    завершено = []
    p = модуль.ParserPipeline(dork_sources=[{"type": "text", "content": "x"}], proxies=[],
                              max_threads=1,
                              on_complete=lambda aborted=False: завершено.append(aborted))
    with pytest.raises(RuntimeError):
        p.run()
    assert завершено == [True] and "модель не загрузилась" in p.failed_reason


class _ЗапускПодКонтролем(threading.Thread):
    """Конвейер сбора, создание которого ждёт команды (как чтение прокси)."""
    можно = None
    запущен = None

    def __init__(self, on_complete=None, activity=None, **_kw):
        super().__init__(daemon=True)
        self._pause_event = threading.Event()
        self._stop_event = threading.Event()
        self.failed_reason = ""
        self._done = on_complete
        type(self).можно.wait(10)

    def run(self):
        type(self).запущен.set()
        self._done(aborted=False)


@pytest.fixture
def окно_сбора(monkeypatch):
    import core.parser_pipeline as модуль
    from ui.webapp import ValidatorApi
    _ЗапускПодКонтролем.можно = threading.Event()
    _ЗапускПодКонтролем.запущен = threading.Event()
    monkeypatch.setattr(модуль, "ParserPipeline", _ЗапускПодКонтролем)
    окно = ValidatorApi()
    окно._sources["dorks"] = [{"type": "text", "content": "x"}]
    окно._sources["pproxy"] = []
    мёртвый = _ПрошлыйСбор()
    мёртвый.start()
    мёртвый.join()
    окно.parser = мёртвый                       # прошлый, завершённый сбор
    return окно


class _ПрошлыйСбор(threading.Thread):
    def __init__(self):
        super().__init__(target=lambda: None, daemon=True)
        self._pause_event = threading.Event()
        self._stop_event = threading.Event()
        self.failed_reason = ""


def test_parser_relaunch_never_flashes_dead(окно_сбора):
    assert окно_сбора.parser_start({})["ok"] is True
    уровни = set()
    for _ in range(10):
        уровни.add(окно_сбора._parser_activity_payload()["level"])
        time.sleep(0.02)
    assert "dead" not in уровни, уровни
    assert окно_сбора.parser_start({}) == {"ok": False, "error": "Сбор уже запускается"}
    _ЗапускПодКонтролем.можно.set()
    assert _ЗапускПодКонтролем.запущен.wait(10)


def test_stop_during_launch_cancels_the_start(окно_сбора):
    assert окно_сбора.parser_start({})["ok"] is True
    окно_сбора.parser_stop({})
    _ЗапускПодКонтролем.можно.set()
    assert _ждать(lambda: окно_сбора.parser_activity.state != "running", 10)
    assert not _ЗапускПодКонтролем.запущен.is_set(), "сбор стартовал вопреки «Стопу»"
    assert describe(окно_сбора.parser_activity.snapshot())["level"] == "stopped"
    assert окно_сбора._parser_state == "done"


# ══════════════════════════════ консоль CLI

def _cli(monkeypatch, tmp_path, класс):
    import cli
    monkeypatch.setattr(cli, "ValidationPipeline", класс)
    база = tmp_path / "base.txt"
    база.write_text("a@example.com\n", encoding="utf-8")
    return cli.main(["validate", "--emails", str(база), "--allow-direct",
                     "-o", str(tmp_path / "out.csv"), "--no-ai"])


def test_cli_failure_names_the_cause_above_the_summary(monkeypatch, tmp_path, capsys):
    from core.pipeline import ValidationPipeline

    class _Падает(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self._stage("check")
            raise ValueError("сломалось в прогоне")

    with pytest.raises(ValueError):
        _cli(monkeypatch, tmp_path, _Падает)
    err = capsys.readouterr().err
    причина = err.find("[DEAD] Проверка прервана ошибкой: ValueError: сломалось в прогоне")
    итог = err.find("■ Прервано ошибкой")
    assert 0 <= причина < итог, err
    assert "✗ Проверка адресов — оборвано ошибкой" in err, err


def test_cli_lines_never_glue_to_progress_under_threads(monkeypatch, tmp_path, capsys):
    from core.pipeline import ValidationPipeline

    class _Многопоточный(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self._stage("check")
            on_log, on_progress = self.callbacks["on_log"], self.callbacks["on_progress"]

            def прогресс():
                for i in range(400):
                    on_progress(i, 400)

            def журнал():
                for i in range(60):
                    on_log("[INFO] строка %d" % i, "info")
            потоки = [threading.Thread(target=прогресс) for _ in range(6)]
            потоки += [threading.Thread(target=журнал) for _ in range(3)]
            for t in потоки:
                t.start()
            for t in потоки:
                t.join()
            self.is_running = False
            self._finish_activity()
            self.callbacks["on_complete"]()

    assert _cli(monkeypatch, tmp_path, _Многопоточный) == 0
    err = capsys.readouterr().err
    склейки = re.findall(r"\(\d+%\)\d\d:\d\d:\d\d", err)
    assert склейки == [], "строк журнала приклеилось к прогрессу: %d" % len(склейки)
    assert err.count("[INFO] строка ") == 180
