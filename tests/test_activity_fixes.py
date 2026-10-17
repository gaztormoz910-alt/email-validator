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


class _МедленныйВывод:
    """Консоль, которая пишет медленно: каждая запись отпускает поток.

    Гонка «строка журнала между проверкой флага и печатью» на обычной
    консоли редка (рецензия: 1 склейка на 9 прогонов), и тест без замедления
    её почти не видел. Здесь окно гонки шире любого планировщика, так что
    без замка склейка — не случайность, а правило."""

    def __init__(self):
        self.части = []
        self._замок = threading.Lock()

    def write(self, текст):
        time.sleep(0.0005)
        with self._замок:
            self.части.append(текст)
        return len(текст)

    def flush(self):
        pass

    def текст(self):
        with self._замок:
            return "".join(self.части)


def test_cli_lines_never_glue_to_progress_under_threads(monkeypatch, tmp_path, capsys):
    from core.pipeline import ValidationPipeline
    консоль = _МедленныйВывод()

    class _Многопоточный(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self._stage("check")
            on_log, on_progress = self.callbacks["on_log"], self.callbacks["on_progress"]

            def прогресс():
                for i in range(150):
                    on_progress(i, 150)

            def журнал():
                for i in range(40):
                    on_log("[INFO] строка %d" % i, "info")
            потоки = [threading.Thread(target=прогресс) for _ in range(4)]
            потоки += [threading.Thread(target=журнал) for _ in range(3)]
            monkeypatch.setattr(sys, "stderr", консоль)
            for t in потоки:
                t.start()
            for t in потоки:
                t.join()
            monkeypatch.setattr(sys, "stderr", sys.__stderr__)
            self.is_running = False
            self._finish_activity()
            self.callbacks["on_complete"]()

    assert _cli(monkeypatch, tmp_path, _Многопоточный) == 0
    err = консоль.текст()
    склейки = re.findall(r"\(\d+%\)\d\d:\d\d:\d\d", err)
    assert склейки == [], "строк журнала приклеилось к прогрессу: %d" % len(склейки)
    assert err.count("[INFO] строка ") == 120


def test_proxy_checker_drops_queued_but_unstarted_after_stop():
    """«Стоп» на переборе: набранные в очередь, но не начатые прокси не
    проверяются — иначе «Стоп» ждал бы ещё восьми кругов таймаута."""
    from core.async_proxy import run_async_checker
    флаг = {"стоп": False}

    def прокси():
        for i in range(100):
            if i == 16:          # очередь двух воркеров (16) уже набрана
                флаг["стоп"] = True
            yield "127.0.0.1:1"
    _живые, проверщик = run_async_checker(
        прокси(), workers=2, timeout=0.5, mode="http", return_checker=True,
        should_stop=lambda: флаг["стоп"])
    assert проверщик.checked_count == 0, проверщик.checked_count


# ══════════════════════════════ вторая рецензия (17.10.2026)

def test_pause_does_not_hide_a_hang_that_began_before_it():
    """Пауза вычитает своё время из тишины, а не обнуляет её: зависание,
    которое было до «Пауза»/«Продолжить», остаётся зависанием."""
    m, часы, _ = монитор()
    m.stage("check")
    часы.прошло(200)                            # никто ничего не делает
    assert уровень(m) == "stall"
    m.set_paused(True)
    assert уровень(m) == "paused"
    часы.прошло(2)
    m.set_paused(False)
    assert уровень(m) == "stall", describe(m.snapshot())


def test_pause_button_on_preparation_does_not_reset_silence():
    m, часы, _ = монитор()
    m.stage("proxies")
    часы.прошло(400)
    assert уровень(m) == "stall"
    assert уровень(m, paused=True) == "stall", "нажатие «Пауза» спрятало зависание"
    часы.прошло(5)
    assert уровень(m, paused=False) == "stall"


def test_pause_on_summary_does_not_promise_a_check():
    m, _часы, _ = монитор()
    m.stage("check")
    m.stage("finish")
    d = describe(m.snapshot(paused=True))
    assert "пауза уже не действует" in d["detail"], d
    assert "включится" not in d["detail"], d


def test_stages_that_complete_after_stop_keep_their_check_mark():
    """Подготовка «Стоп» не слушает и доходит до конца — она пройдена."""
    m, часы, строки = монитор()
    m.stage("lists")
    m.request_stop()
    часы.прошло(30)
    m.stage("filters")
    часы.прошло(2)
    m.finish("stopped")
    тексты = [т for _тег, т in строки]
    assert "✓ Обновление списков одноразовых доменов — 30 с" in тексты, тексты
    assert "✓ Загрузка фильтров спама — 2 с" in тексты, тексты
    assert not any(т.startswith("✗") for т in тексты), тексты


def test_parser_stall_threshold_follows_its_timeout():
    from core.parser_pipeline import ParserPipeline
    m, часы, _ = монитор(kind="parser")
    ParserPipeline(dork_sources=[{"type": "text", "content": "x"}], proxies=[],
                   max_threads=1, timeout=120, activity=m)
    assert m.net_longest == 360
    m.stage("p_search")
    m.enter()
    часы.прошло(300)
    d = describe(m.snapshot())
    assert d["level"] == "slow" and "поисковик" in d["detail"], d
    часы.прошло(121)
    assert уровень(m) == "stall"


def test_pause_then_stop_in_retry_loses_no_address(monkeypatch):
    import core.pipeline as модуль
    monkeypatch.setattr(модуль, "DEFAULT_RETRY_DELAY", 0.0)
    p, строки, результаты = _конвейер()
    p.network = _СетьСоСбоем()
    p.callbacks["on_phase"] = lambda имя, n=0: (p.pause() if имя == "retry"
                                                 and not p.is_paused else None)
    адреса = ["r%d@example.com" % i for i in range(6)]
    поток = threading.Thread(target=p.run_pipeline, args=(
        [{"type": "text", "content": "\n".join(адреса)}],),
        kwargs=dict(threads=2, fix_typos=True, check_spam=False, deep_ping=True,
                    enable_ai=False), daemon=True)
    поток.start()
    assert _ждать(lambda: p.activity.stage_key == "retry", 30)
    time.sleep(1.0)
    p.stop()
    поток.join(60)
    assert sorted(e for e, _s in результаты) == sorted(адреса), "адреса пропали из выдачи"
    assert not any("ПОТЕРЯНО" in т for _тег, т in строки)


class _МедленнаяСеть(_Net):
    def check_email(self, email, **_kw):
        time.sleep(0.2)
        return super().check_email(email)


def test_stop_mid_run_is_not_a_loss_and_frees_the_feeder():
    p, строки, результаты = _конвейер()
    p.network = _МедленнаяСеть()
    до = {t.ident for t in threading.enumerate()}
    база = "\n".join("s%d@example.com" % i for i in range(40))
    поток = threading.Thread(target=p.run_pipeline, args=(
        [{"type": "text", "content": база}],),
        kwargs=dict(threads=2, fix_typos=True, check_spam=False, deep_ping=True,
                    enable_ai=False), daemon=True)
    поток.start()
    assert _ждать(lambda: len(результаты) >= 3, 60)
    p.stop()
    поток.join(60)
    assert not поток.is_alive()
    тексты = [т for _тег, т in строки]
    assert not any("ПОТЕРЯНО" in т for т in тексты), тексты
    assert any(т.startswith("[INFO] Остановлено: показано") for т in тексты), тексты

    def фидеры():
        return [t for t in threading.enumerate()
                if t.ident not in до and "feeder_thread" in t.name and t.is_alive()]
    assert _ждать(lambda: not фидеры(), 5), "фидер повис на полной очереди"


def test_stop_during_preparation_skips_the_rest(monkeypatch):
    import core.pipeline_setup as подготовка
    p, строки, _р = _конвейер()

    class _Списки:
        def download_all(self, log_callback=None):
            p.stop()                            # «Стоп» нажат на этапе списков

    monkeypatch.setattr(подготовка, "BlacklistDownloader", _Списки)
    p.setup(timeout=5, enable_ai=True, proxies=["127.0.0.1:1"], threads=2,
            use_cache=False)
    этапы = [т for тег, т in строки if тег == "stage"]
    assert "▶ Обновление списков одноразовых доменов" in этапы, этапы
    assert "▶ Загрузка фильтров спама" not in этапы, этапы
    assert "▶ Проверка прокси" not in этапы, этапы
    assert p.activity.stage_key == "lists"


def test_proxy_sweep_stops_on_stop():
    from core.proxy_probe import filter_live_proxies
    проверено = {"n": 0}

    def прогресс(c, t):
        проверено["n"] = c

    def прокси():
        for _ in range(5000):
            yield "127.0.0.1:1"
    начало = time.monotonic()
    живые, увидено = filter_live_proxies(
        прокси(), timeout=0.5, threads=4, progress_callback=прогресс,
        should_stop=lambda: проверено["n"] >= 3)
    assert живые == []
    assert увидено < 200, увидено
    assert time.monotonic() - начало < 30


def _сбор_со_стопом(monkeypatch, где):
    import core.parser_pipeline as модуль
    from core.activity import ActivityMonitor
    строки, завершено, перебор = [], [], []
    сбор = {}

    class _Модель:
        def __init__(self, *a, **kw):
            if где == "модель":
                сбор["p"].stop()

    class _Пусто:
        def __init__(self, *a, **kw):
            pass

    monkeypatch.setattr(модуль, "MLPredictor", _Модель)
    monkeypatch.setattr(модуль, "NameExtractor", _Пусто)
    monkeypatch.setattr(модуль, "DuckDuckGoEngine", _Поисковик)
    mon = ActivityMonitor(kind="parser", emit=lambda т, тег: строки.append(т))
    p = модуль.ParserPipeline(
        dork_sources=[{"type": "text", "content": "alpha\nbeta"}],
        proxies=["127.0.0.1:1"], max_threads=2, timeout=1,
        on_log=lambda т, *a: строки.append(т),
        on_complete=lambda aborted=False: завершено.append(aborted), activity=mon)
    сбор["p"] = p

    def проверка(**kw):
        перебор.append(kw)
        if где == "прокси":
            p.stop()
    p.proxy_manager.check_all_proxies = проверка
    p.run()
    return строки, завершено, перебор


def test_parser_stop_while_model_loads_never_searches(monkeypatch):
    строки, завершено, перебор = _сбор_со_стопом(monkeypatch, "модель")
    assert завершено == [True]
    assert перебор == [], "после «Стопа» всё равно перебирались прокси"
    assert "▶ Поиск по доркам" not in строки, строки
    assert any("остановлен до начала поиска" in т for т in строки), строки


def test_parser_stop_during_proxy_check_never_searches(monkeypatch):
    строки, завершено, перебор = _сбор_со_стопом(monkeypatch, "прокси")
    assert завершено == [True]
    assert callable(перебор[0].get("should_stop")), "перебору не передан «Стоп»"
    assert "▶ Поиск по доркам" not in строки, строки


class _ПустойПоисковик(_Поисковик):
    def search_generator(self, query):
        time.sleep(0.05)
        return
        yield


def test_parser_pause_then_stop_takes_no_new_dork(monkeypatch):
    p, завершено = _сбор_в_фоне(monkeypatch, "\n".join("q%d" % i for i in range(300)),
                                поисковик=_ПустойПоисковик, потоков=3)
    assert _ждать(lambda: p.processed_dorks > 5, 30)
    p.pause()
    time.sleep(0.6)                              # начатые дорки доделаны
    было = p.processed_dorks
    p.stop()
    p.join(10)
    assert not p.is_alive()
    assert p.processed_dorks == было, "после «Стопа» взяты новые дорки"
    assert завершено == [True]


def test_cancelled_launch_records_the_outcome_before_releasing_the_flag(окно_сбора):
    видно = []
    исходный = окно_сбора.parser_activity.finish

    def finish(*a, **kw):
        видно.append(окно_сбора.__dict__.get("_parser_launching"))
        return исходный(*a, **kw)
    окно_сбора.parser_activity.finish = finish
    assert окно_сбора.parser_start({})["ok"] is True
    окно_сбора.parser_stop({})
    _ЗапускПодКонтролем.можно.set()
    assert _ждать(lambda: видно, 10)
    assert видно == [True], "флаг «запускается» снят раньше итога — полоса мигнёт «dead»"


def test_cli_ctrl_c_on_summary_marks_it_cut(monkeypatch, tmp_path, capsys):
    from core.pipeline import ValidationPipeline

    class _ПрерванНаИтогах(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self._stage("check")
            self._stage("finish")
            raise KeyboardInterrupt

    _cli(monkeypatch, tmp_path, _ПрерванНаИтогах)
    err = capsys.readouterr().err
    assert "✗ Подведение итогов — остановлено через" in err, err
    assert "✓ Подведение итогов" not in err, err
