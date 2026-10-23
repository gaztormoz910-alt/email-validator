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


@pytest.fixture(autouse=True)
def _ctrl_c_работает():
    """Ctrl+C в этих тестах обязан доходить до CLI, как бы ни запустили pytest.

    Запущенный фоном («pytest &» в скрипте) процесс наследует SIGINT=SIG_IGN,
    и тогда CLI честно не ставит свой обработчик (cli.py уважает унаследованный
    SIG_IGN), а _thread.interrupt_main ничего не делает — тесты упали бы ложно.
    На время теста ставится обычный обработчик, после — прежний."""
    import signal as _signal
    прежний = _signal.getsignal(_signal.SIGINT)
    if прежний == _signal.SIG_IGN:
        _signal.signal(_signal.SIGINT, _signal.default_int_handler)
    try:
        yield
    finally:
        if прежний == _signal.SIG_IGN:
            _signal.signal(_signal.SIGINT, прежний)


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


class _ПерепроверкаВисит(_СетьСоСбоем):
    """Первый ответ — сбой; перепроверка ждёт команды. Так две перепроверки
    заняты, а остальные стоят в очереди пула — ровно то место, где адрес
    раньше пропадал при «Стопе»."""

    def __init__(self):
        super().__init__()
        self.пусти = threading.Event()
        self.висят = 0
        self._замок = threading.Lock()

    def check_email(self, email, **kw):
        if self.спрошено.get(email):
            with self._замок:
                self.висят += 1
            self.пусти.wait(30)
        return super().check_email(email, **kw)


def test_stop_during_retry_returns_queued_addresses(monkeypatch):
    import core.pipeline as модуль
    monkeypatch.setattr(модуль, "DEFAULT_RETRY_DELAY", 0.0)
    p, строки, результаты = _конвейер()
    сеть = p.network = _ПерепроверкаВисит()
    адреса = ["q%d@example.com" % i for i in range(6)]
    поток = threading.Thread(target=p.run_pipeline, args=(
        [{"type": "text", "content": "\n".join(адреса)}],),
        kwargs=dict(threads=2, fix_typos=True, check_spam=False, deep_ping=True,
                    enable_ai=False), daemon=True)
    поток.start()
    assert _ждать(lambda: сеть.висят >= 2, 30), "перепроверка не началась"
    p.stop()                                    # 4 адреса ещё в очереди пула
    сеть.пусти.set()
    поток.join(60)
    assert not поток.is_alive()
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


# ══════════════════════════════ третья рецензия (17.10.2026)

def test_pause_during_a_planned_wait_is_not_a_hang_after_resume():
    """Ожидание по плану до паузы — не тишина, и после «Продолжить» тоже."""
    m, часы, _ = монитор()
    m.stage("retry")
    m.beat()
    m.wait(420, "ближайший отложенный адрес созреет")
    часы.прошло(200)
    m.set_paused(True)
    часы.прошло(800)                             # срок ожидания уже прошёл
    m.set_paused(False)
    часы.прошло(0.1)
    assert уровень(m) == "ok", describe(m.snapshot())


def test_parser_slow_text_promises_no_limit():
    m, часы, _ = монитор(kind="parser")
    m.set_net_budget(45)
    m.stage("p_search")
    m.enter()
    часы.прошло(60)
    d = describe(m.snapshot())
    assert d["level"] == "slow", d
    assert "повторяются через другие прокси" in d["detail"] and " до " not in d["detail"], d


def test_proxy_sweep_stop_line_says_read_not_checked(monkeypatch):
    import core.network as сеть
    p, строки, _р = _конвейер()

    def перебор(proxies, **kw):
        p.stop()
        return [], 7
    monkeypatch.setattr(сеть, "filter_live_proxies", перебор)
    monkeypatch.setattr("core.pipeline_setup.BlacklistDownloader",
                        type("Б", (), {"download_all": lambda self, log_callback=None: None}))
    p.setup(timeout=5, enable_ai=False, proxies=["127.0.0.1:1"], threads=2, use_cache=False)
    тексты = [т for _тег, т in строки]
    assert any("прочитано 7, живых 0" in т for т in тексты), тексты
    assert not getattr(p, "blocked_reason", ""), "остановку объявили блокировкой"


class _СчётнаяСеть(_Net):
    def __init__(self):
        self.вызовов = 0
        self._замок = threading.Lock()

    def check_email(self, email, **_kw):
        with self._замок:
            self.вызовов += 1
        time.sleep(0.1)
        return super().check_email(email)


def test_pause_then_stop_makes_no_new_network_check():
    p, _строки, результаты = _конвейер()
    сеть = p.network = _СчётнаяСеть()
    база = "\n".join("p%d@example.com" % i for i in range(30))
    поток = threading.Thread(target=p.run_pipeline, args=(
        [{"type": "text", "content": база}],),
        kwargs=dict(threads=2, fix_typos=True, check_spam=False, deep_ping=True,
                    enable_ai=False), daemon=True)
    поток.start()
    assert _ждать(lambda: len(результаты) >= 2, 60)
    p.pause()
    time.sleep(0.6)                              # начатые проверки доделаны
    было = сеть.вызовов
    p.stop()
    поток.join(60)
    assert not поток.is_alive()
    assert сеть.вызовов == было, "после «Пауза» → «Стоп» пошли новые проверки"


def test_feeder_read_error_does_not_hang_the_run(monkeypatch):
    from core.streamer import StreamLoader

    def обрыв(self):
        for i in range(3):
            yield "f%d@example.com" % i, {}
        raise OSError("диск отвалился")
    monkeypatch.setattr(StreamLoader, "stream_emails", обрыв)
    p, строки, результаты = _конвейер()
    поток = threading.Thread(target=p.run_pipeline, args=(
        [{"type": "text", "content": "x@example.com"}],),
        kwargs=dict(threads=2, fix_typos=True, check_spam=False, deep_ping=True,
                    enable_ai=False), daemon=True)
    поток.start()
    поток.join(60)
    assert not поток.is_alive(), "прогон завис после обрыва чтения базы"
    assert sorted(e for e, _s in результаты) == ["f0@example.com", "f1@example.com",
                                                "f2@example.com"]
    assert any("Чтение базы оборвалось" in т and "диск отвалился" in т
               for _тег, т in строки)
    assert p.activity.state == "failed"


def test_stop_also_stops_the_profile_refresher():
    p, _строки, _р = _конвейер()
    p.is_running = True
    p._start_profile_refresher(timeout=1, workers=1, interval=600)
    p.stop()
    assert p._refresh_stop.is_set()
    p._refresh_thread.join(5)
    assert not p._refresh_thread.is_alive()


class _ПерепроверкаПадает(_СетьСоСбоем):
    def check_email(self, email, **kw):
        if self.спрошено.get(email):
            raise RuntimeError("сеть сломалась на перепроверке")
        return super().check_email(email, **kw)


def test_crash_in_retry_still_returns_the_address(monkeypatch):
    import core.pipeline as модуль
    monkeypatch.setattr(модуль, "DEFAULT_RETRY_DELAY", 0.0)
    p, строки, результаты = _конвейер()
    p.network = _ПерепроверкаПадает()
    адреса = ["e%d@example.com" % i for i in range(3)]
    p.run_pipeline([{"type": "text", "content": "\n".join(адреса)}], threads=2,
                   fix_typos=True, check_spam=False, deep_ping=True, enable_ai=False)
    assert sorted(e for e, _s in результаты) == адреса, "адрес пропал после сбоя перепроверки"
    assert {s for _e, s in результаты} == {"Unknown"}
    assert not any("ПОТЕРЯНО" in т for _тег, т in строки)


def test_cli_ctrl_c_stops_like_the_window_and_keeps_started_work(monkeypatch, tmp_path, capsys):
    import _thread
    from core.pipeline import ValidationPipeline

    class _Долгий(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self.is_running = True
            self._stage("check")
            threading.Timer(0.3, _thread.interrupt_main).start()
            while self.is_running:                # проверка идёт до «Стопа»
                time.sleep(0.05)
            # начатая до Ctrl+C проверка доделана и выдана
            self.callbacks["on_result"]("a@example.com", "Valid", "250 OK", "mx", {})
            self._finish_activity()
            self.callbacks["on_complete"]()

    код = _cli(monkeypatch, tmp_path, _Долгий)
    assert код == 2, "прерванный прогон вернул код успеха"
    err = capsys.readouterr().err
    assert "Доделываю начатые проверки" in err, err
    assert "■ Остановлено по вашей команде" in err, err
    assert "a@example.com" in (tmp_path / "out.csv").read_text(encoding="utf-8-sig"), (
        "доделанная после Ctrl+C проверка не попала в файл")


def test_duckduckgo_stops_retrying_on_stop(monkeypatch):
    import requests
    import core.parser.engine as движки
    попыток = {"n": 0}

    def пост(self, *a, **kw):
        попыток["n"] += 1
        raise requests.exceptions.Timeout("молчит")
    monkeypatch.setattr(requests.Session, "post", пост)
    monkeypatch.setattr(движки.time, "sleep", lambda s: None)

    class _Прокси:
        timeout = 1

        def get_proxy(self):
            return "socks5://127.0.0.1:1"

        def get_total_count(self):
            return 1

        def mark_fail(self, url):
            pass

        def mark_success(self, url):
            pass
    движок = движки.DuckDuckGoEngine(_Прокси(), on_log=lambda т: None,
                                     is_stopped=lambda: попыток["n"] >= 2)
    assert list(движок.search_generator("site:example.com")) == []
    assert попыток["n"] == 2, попыток


def test_tor_start_gives_up_at_once_on_stop(monkeypatch):
    import core.tor_manager as тор
    запуски = []

    class _Узел:
        def __init__(self, *a, **kw):
            pass

        def start(self, should_stop=None):
            запуски.append(bool(should_stop and should_stop()))
            return False

    monkeypatch.setattr(тор, "TorInstance", _Узел)
    менеджер = object.__new__(тор.TorManager)
    менеджер.log_callback = lambda *a, **k: None
    менеджер.base_dir = менеджер.tor_exe = None
    менеджер.instances = []
    менеджер.check_and_download = lambda: True
    менеджер._kill_orphans = lambda: None
    стоп = threading.Event()
    threading.Timer(0.3, стоп.set).start()
    начало = time.monotonic()
    assert менеджер.start(num_instances=3, should_stop=стоп.is_set) is False
    # Без «Стопа» это разнос 0/6/12 с и выдержка 10 с перед повтором.
    assert time.monotonic() - начало < 3, time.monotonic() - начало


# ══════════════════════════════ четвёртая рецензия (17.10.2026)

def test_cli_second_ctrl_c_still_writes_what_is_collected(monkeypatch, tmp_path, capsys):
    """Второй Ctrl+C — выход сразу, но собранное записано и код 2."""
    import _thread
    import cli
    from core.pipeline import ValidationPipeline
    отпусти = threading.Event()
    выходы = []
    monkeypatch.setattr(cli, "_выйти_сразу", lambda код: выходы.append(код))

    class _Зависший(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self.is_running = True
            self._stage("check")
            self.callbacks["on_result"]("early@example.com", "Valid", "250 OK", "mx", {})
            threading.Timer(0.3, _thread.interrupt_main).start()
            threading.Timer(1.0, _thread.interrupt_main).start()
            отпусти.wait(30)            # начатая проверка висит и после «Стопа»

    try:
        код = _cli(monkeypatch, tmp_path, _Зависший)
    finally:
        отпусти.set()
    assert выходы == [2] and код == 2, (выходы, код)
    assert "early@example.com" in (tmp_path / "out.csv").read_text(encoding="utf-8-sig")
    assert "Выхожу сразу" in capsys.readouterr().err


def test_feeder_read_error_keeps_resume_memory_and_blames_the_check(monkeypatch):
    from core.runstate import RunState
    from core.streamer import StreamLoader
    стёрто = []
    исходный = RunState.clear
    monkeypatch.setattr(RunState, "clear", lambda self: (стёрто.append(1), исходный(self)))

    # Контроль: обычный прогон до конца память стирает.
    p, _строки, _р = _конвейер()
    p.run_pipeline([{"type": "text", "content": "ok1@example.com"}], threads=1,
                   fix_typos=True, check_spam=False, deep_ping=True, enable_ai=False)
    assert стёрто == [1]

    def обрыв(self):
        yield "g0@example.com", {}
        raise OSError("диск отвалился")
    monkeypatch.setattr(StreamLoader, "stream_emails", обрыв)
    p, строки, _р = _конвейер()
    p.run_pipeline([{"type": "text", "content": "x@example.com"}], threads=1,
                   fix_typos=True, check_spam=False, deep_ping=True, enable_ai=False)
    assert стёрто == [1], "после обрыва чтения память продолжения стёрта"
    этапы = [т for тег, т in строки if тег == "stage"]
    assert any(т.startswith("✗ Проверка адресов — оборвано ошибкой") for т in этапы), этапы
    assert any(т.startswith("✓ Подведение итогов") for т in этапы), этапы


def test_pause_during_a_wait_does_not_hide_a_hung_check():
    m, часы, _ = монитор()
    m.stage("retry")
    m.enter()                                    # эта проверка повисла
    m.wait(420, "ближайший отложенный адрес созреет")
    часы.прошло(250)
    assert уровень(m) == "stall"
    m.set_paused(True)
    часы.прошло(5)
    m.set_paused(False)
    assert уровень(m) == "stall", describe(m.snapshot())


def test_stop_skips_profiling_of_unstarted_proxies(monkeypatch):
    import core.proxy_probe as пробы
    вызовы = []
    monkeypatch.setattr(пробы, "probe_proxy_target",
                        lambda *a, **kw: (вызовы.append(a[0]), (False, None, None, "x"))[1])
    итог = пробы.profile_proxies(["127.0.0.1:1", "127.0.0.1:2"], timeout=1, workers=2,
                                 should_stop=lambda: True)
    assert итог == {} and вызовы == []


def test_stop_during_profiles_starts_no_refresher(monkeypatch):
    import core.network as сеть
    import core.pipeline_setup as подготовка
    p, _строки, _р = _конвейер()
    monkeypatch.setattr(подготовка, "BlacklistDownloader",
                        type("Б", (), {"download_all": lambda self, log_callback=None: None}))
    monkeypatch.setattr(сеть, "filter_live_proxies",
                        lambda proxies, **kw: (["127.0.0.1:1"], 1))

    def профили(live, timeout, threads):
        p.stop()                                 # «Стоп» нажат на профилях
        return {"127.0.0.1:1": {"has_ptr": True}}
    p._profile_live_proxies = профили
    p.setup(timeout=5, enable_ai=False, proxies=["127.0.0.1:1"], threads=2, use_cache=False)
    assert "_refresh_thread" not in p.__dict__, "обновление профилей запущено после «Стопа»"


def test_window_says_how_the_run_ended():
    from ui.webapp import ValidatorApi
    логи = []
    окно = ValidatorApi.__new__(ValidatorApi)
    окно._on_log = lambda m, t="info": логи.append(m)
    for исход, слова in (("stopped", "Проверка остановлена"),
                         ("failed", "Проверка прервана ошибкой"),
                         ("done", "Проверка завершена")):
        логи.clear()
        окно.pipeline = type("P", (), {"blocked_reason": "",
                                      "activity": type("A", (), {"state": исход})()})()
        окно._on_complete()
        assert any(слова in m for m in логи), (исход, логи)


def test_tor_stage_cut_by_stop_gets_a_cross():
    m, часы, строки = монитор(kind="parser")
    m.stage("p_tor")
    m.request_stop()
    часы.прошло(4)
    m.finish("stopped")
    assert "✗ Запуск Tor — остановлено через 4 с" in [т for _тег, т in строки]


def test_tor_stopped_start_is_not_reported_as_failure(monkeypatch):
    import core.tor_manager as тор
    логи = []

    class _Узел:
        def __init__(self, *a, **kw):
            pass

        def start(self, should_stop=None):
            return False

    monkeypatch.setattr(тор, "TorInstance", _Узел)
    менеджер = object.__new__(тор.TorManager)
    менеджер.log_callback = lambda *a, **k: None
    менеджер._log = lambda т, *a, **k: логи.append(т)
    менеджер.base_dir = менеджер.tor_exe = None
    менеджер.instances = []
    менеджер.check_and_download = lambda: True
    менеджер._kill_orphans = lambda: None
    assert менеджер.start(num_instances=1, should_stop=lambda: True) is False
    assert not any("[DEAD]" in т for т in логи), логи
    assert any("Запуск Tor остановлен" in т for т in логи), логи


def test_duckduckgo_link_walk_stops_on_stop(monkeypatch):
    import requests
    import core.parser.engine as движки
    заходов = {"n": 0}
    ссылки = "".join('<a href="//duckduckgo.com/l/?uddg=https%%3A%%2F%%2Fsite%d.example%%2F&x=1">r</a>' % i
                     for i in range(5))

    class _Ответ:
        status_code = 200
        text = "<html>duckduckgo results " + ссылки + "</html>"

        def raise_for_status(self):
            pass

    monkeypatch.setattr(requests.Session, "post", lambda self, *a, **kw: _Ответ())

    def заход(*a, **kw):
        заходов["n"] += 1
        raise requests.exceptions.Timeout("сайт молчит")
    monkeypatch.setattr(движки, "_get_verified", заход)
    monkeypatch.setattr(движки.time, "sleep", lambda s: None)

    class _Прокси:
        timeout = 1

        def get_proxy(self):
            return None

        def get_total_count(self):
            return 0

        def mark_fail(self, url):
            pass

        def mark_success(self, url):
            pass
    движок = движки.DuckDuckGoEngine(_Прокси(), on_log=lambda т: None,
                                     is_stopped=lambda: заходов["n"] >= 1)
    list(движок.search_generator("site:example.com"))
    assert заходов["n"] == 1, заходов


# ══════════════════════════════ пятая рецензия (18.10.2026)

def test_profiles_cut_by_stop_give_no_verdict_on_the_pool(monkeypatch):
    import core.network as сеть
    p, строки, _р = _конвейер()
    p.network = type("N", (), {"recall_proxy_profiles": lambda self, live: {}})()
    сводки = []
    p.callbacks["on_proxy_profile"] = lambda s: сводки.append(s)

    def профили(fresh, **kw):
        p.stop()
        return {fresh[0]: {"has_ptr": False, "in_dnsbl": False, "exit_ip": "1.2.3.4",
                           "latency_ms": 10}}
    monkeypatch.setattr(сеть, "profile_proxies", профили)
    p._profile_live_proxies(["a:1", "b:1", "c:1"], 5, 2)
    тексты = [т for _тег, т in строки]
    assert any("Профилирование прервано «Стопом»: снято 1 из 3" in т for т in тексты), тексты
    assert not any(т.startswith("[DEAD]") for т in тексты), тексты
    assert сводки == [], "в окно ушла сводка по части пула"


def test_feeder_error_before_retry_blames_the_check(monkeypatch):
    import core.pipeline as модуль
    from core.streamer import StreamLoader
    monkeypatch.setattr(модуль, "DEFAULT_RETRY_DELAY", 0.0)

    def обрыв(self):
        yield "h0@example.com", {}
        raise OSError("диск отвалился")
    monkeypatch.setattr(StreamLoader, "stream_emails", обрыв)
    p, строки, результаты = _конвейер()
    p.network = _СетьСоСбоем()                   # h0 уходит на перепроверку
    p.run_pipeline([{"type": "text", "content": "x@example.com"}], threads=1,
                   fix_typos=True, check_spam=False, deep_ping=True, enable_ai=False)
    этапы = [т for тег, т in строки if тег == "stage"]
    assert any(т.startswith("✗ Проверка адресов — оборвано ошибкой") for т in этапы), этапы
    assert any(т.startswith("✓ Перепроверка отложенных адресов") for т in этапы), этапы
    assert any(т.startswith("✓ Подведение итогов") for т in этапы), этапы
    assert [e for e, _s in результаты] == ["h0@example.com"]


def test_stage_where_the_run_got_blocked_gets_a_cross():
    m, часы, строки = монитор(kind="parser")
    m.stage("p_tor")
    часы.прошло(90)
    m.finish("blocked", "Tor не поднялся")
    тексты = [т for _тег, т in строки]
    assert "✗ Запуск Tor — дальше не пройти, через 1 мин 30 с" in тексты, тексты
    assert payload(m.snapshot())["trail"][-1]["cut"] is True


def test_tor_stop_is_heard_while_tor_is_silent(monkeypatch, tmp_path):
    import core.tor_manager as тор
    отпусти = threading.Event()

    class _Молчит:
        def __iter__(self):
            отпусти.wait(30)                     # tor не пишет ни строки
            return iter(())

    class _Процесс:
        pid = 0
        stdout = _Молчит()

        def poll(self):
            return None

    monkeypatch.setattr(тор.subprocess, "Popen", lambda *a, **kw: _Процесс())
    узел = тор.TorInstance(0, tmp_path, tmp_path / "tor.exe", lambda *a, **k: None)
    погашен = []
    узел.stop = lambda: погашен.append(1)
    стоп = threading.Event()
    итог = []
    поток = threading.Thread(target=lambda: итог.append(узел.start(should_stop=стоп.is_set)),
                             daemon=True)
    try:
        поток.start()
        time.sleep(0.3)
        стоп.set()
        поток.join(5)
        assert not поток.is_alive(), "«Стоп» не услышан, пока tor молчит"
        assert итог == [False] and погашен == [1]
    finally:
        отпусти.set()


def test_cli_ctrl_c_while_writing_does_not_cut_the_file(monkeypatch, tmp_path, capsys):
    import _thread
    from core import baseops
    from core.pipeline import ValidationPipeline
    исходная = baseops.write_chunks_stream

    def запись(*a, **kw):
        _thread.interrupt_main()                 # Ctrl+C посреди записи
        time.sleep(0.3)
        return исходная(*a, **kw)
    monkeypatch.setattr(baseops, "write_chunks_stream", запись)

    class _Готово(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self._stage("check")
            self.callbacks["on_result"]("w@example.com", "Valid", "250 OK", "mx", {})
            self._finish_activity()
            self.callbacks["on_complete"]()

    код = _cli(monkeypatch, tmp_path, _Готово)
    assert код == 0
    assert "w@example.com" in (tmp_path / "out.csv").read_text(encoding="utf-8-sig")


def test_after_second_ctrl_c_late_results_cannot_be_marked_done(monkeypatch, tmp_path):
    """После второго Ctrl+C замок результатов держится до выхода: проверка,
    закончившаяся во время записи, не выдаётся — значит, и не помечается
    сделанной (отметка идёт только после выдачи)."""
    import _thread
    import cli
    from core.pipeline import ValidationPipeline
    отпусти = threading.Event()
    поздний = threading.Event()
    monkeypatch.setattr(cli, "_выйти_сразу", lambda код: None)

    class _Поздний(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self.is_running = True
            self._stage("check")
            threading.Timer(0.3, _thread.interrupt_main).start()
            threading.Timer(1.0, _thread.interrupt_main).start()
            отпусти.wait(30)
            self.callbacks["on_result"]("late@example.com", "Valid", "250 OK", "mx", {})
            поздний.set()

    try:
        _cli(monkeypatch, tmp_path, _Поздний)
    finally:
        отпусти.set()
    assert not поздний.wait(0.5), "поток прогона выдал результат после снимка"
    assert "late@example.com" not in (tmp_path / "out.csv").read_text(encoding="utf-8-sig")


# ══════════════════════════════ шестая рецензия (18.10.2026)

def test_second_ctrl_c_with_a_failing_write_exits_at_once(monkeypatch, tmp_path):
    """Запись упала после второго Ctrl+C — выход сразу с кодом 1, а не
    вечное ожидание пула, который ждёт удержанный замок результатов."""
    import _thread
    import cli
    from core.pipeline import ValidationPipeline
    отпусти = threading.Event()
    выходы = []
    monkeypatch.setattr(cli, "_выйти_сразу", lambda код: выходы.append(код))

    class _Зависший(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self.is_running = True
            self._stage("check")
            self.callbacks["on_result"]("early@example.com", "Valid", "250 OK", "mx", {})
            threading.Timer(0.3, _thread.interrupt_main).start()
            threading.Timer(1.0, _thread.interrupt_main).start()
            отпусти.wait(30)

    monkeypatch.setattr(cli, "ValidationPipeline", _Зависший)
    база = tmp_path / "base.txt"
    база.write_text("a@example.com\n", encoding="utf-8")
    нет_папки = tmp_path / "нет" / "out.csv"
    try:
        with pytest.raises(OSError):
            cli.main(["validate", "--emails", str(база), "--allow-direct",
                      "-o", str(нет_папки), "--no-ai"])
    finally:
        отпусти.set()
    assert выходы == [1], выходы


def test_parser_blocked_note_points_to_the_journal_not_a_line():
    from ui.webapp import ValidatorApi
    окно = ValidatorApi()
    окно.parser = type("P", (), {"_stop_event": threading.Event(), "failed_reason": ""})()
    окно.parser_activity.begin()
    окно._finish_parser_activity(True)
    d = describe(окно.parser_activity.snapshot())
    assert d["level"] == "blocked"
    assert "в журнале выше" in d["detail"] and "строкой выше" not in d["detail"], d
