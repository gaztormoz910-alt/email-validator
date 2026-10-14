# -*- coding: utf-8 -*-
"""Журнал активности насквозь: настоящий конвейер проверки, настоящий цикл
сбора адресов, мост окна по сокету, консоль CLI и сама страница.

Модуль core/activity.py проверен по отдельности (tests/test_activity.py).
Здесь — что он ПОДКЛЮЧЁН там, где владелец на него смотрит: этапы реально
объявляются по ходу прогона, «в работе» к концу возвращается в ноль, итог
пишется при любом исходе, окно получает состояние каждым опросом, у каждой
строки есть время. И что подключение не тронуло самих вердиктов.
"""
import io
import json
import os
import re
import sys
import threading
import time
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def читать(*части):
    with io.open(os.path.join(КОРЕНЬ, *части), encoding="utf-8") as f:
        return f.read()


# ══════════════════════════════ конвейер проверки

class _Net:
    """Сеть-заглушка: вердикт всегда Valid, сетевых запросов нет."""

    def check_email(self, email, **_kw):
        return {"status": "valid", "reason": "250 OK", "mx_record": "mx.example.com",
                "mx_records": ["mx.example.com"], "has_starttls": True,
                "server_outdated": False}

    def check_dns_health(self, domain, mx_record=""):
        return {"has_spf": True, "has_dmarc": True, "has_dkim": True, "score": 3}

    def check_dnsbl(self, host):
        return False

    def check_ptr(self, host):
        return True

    def all_proxies_dead(self):
        return False

    def has_proxies_configured(self):
        return False

    def take_recent_bans(self):
        return []


_модели = {}


def _общие_модели():
    """Одна пара моделей на весь файл. Замерено: MLPredictor грузится 8 с при
    КАЖДОМ создании, NameExtractor — 10 с в первый раз; по паре на тест это
    две лишние минуты в каждом прогоне набора. Модели здесь только читаются."""
    if not _модели:
        from core.parser.name_extractor import NameExtractor
        from core.parser.ml_predictor import MLPredictor
        _модели["names"] = NameExtractor(enable_osint=False)
        _модели["ml"] = MLPredictor(enable_ml=False)
    return _модели["names"], _модели["ml"]


def _конвейер(модели=True):
    from core.pipeline import ValidationPipeline

    строки, результаты = [], []
    # Результат идёт в ту же ленту, что и журнал (тегом "result"): в окне
    # строку про адрес пишет мост, и порядок «этап, потом адреса» виден только
    # на общей ленте.
    p = ValidationPipeline(callbacks={
        "on_log": lambda т, тег="info": строки.append((тег, str(т))),
        "on_result": lambda e, s, r, mx, d=None: (результаты.append((e, s)),
                                                   строки.append(("result", e))),
        "on_progress": lambda a, b: None,
        "on_complete": lambda: None,
    })
    p.network = _Net()
    if модели:
        p.name_extractor, p.ml_predictor = _общие_модели()
    p.gravatar_checker = type("G", (), {"has_gravatar": lambda s, e: False})()
    p.filter = None
    p.ai = None
    p.cache = None
    p._get_domain_age_days = lambda d: -1
    p._check_http_alive = lambda d: True
    return p, строки, результаты


def test_run_announces_stages_and_returns_inflight_to_zero():
    p, строки, результаты = _конвейер()
    адреса = ["anna.smith@example.com", "bob.jones@example.org", "carl@example.net"]
    p.run_pipeline([{"type": "text", "content": "\n".join(адреса)}], threads=2,
                   fix_typos=True, check_spam=False, deep_ping=True, enable_ai=False)

    этапы = [т for тег, т in строки if тег == "stage"]
    assert "▶ Проверка адресов" in этапы, этапы
    assert any(т.startswith("✓ Проверка адресов — ") for т in этапы), этапы
    assert "▶ Подведение итогов" in этапы, этапы
    assert этапы[-1].startswith("■ Готово."), этапы
    # Этап объявлен ДО первого результата: иначе окно показывало бы адреса
    # под подписью прошлого этапа.
    первая_проверка = next(i for i, (тег, т) in enumerate(строки) if т == "▶ Проверка адресов")
    первый_результат = next(i for i, (тег, т) in enumerate(строки) if тег == "result")
    assert первая_проверка < первый_результат

    снимок = p.activity.snapshot()
    assert снимок["inflight"] == 0, "«в работе» залипло после прогона"
    assert снимок["state"] == "done"
    # Подключение журнала не тронуло вердиктов: всё подано — всё выдано.
    assert sorted(e for e, _s in результаты) == sorted(адреса)
    assert {s for _e, s in результаты} == {"Valid"}


def test_progress_reaches_the_monitor_through_observed_callbacks():
    p, _строки, _р = _конвейер()
    p.run_pipeline([{"type": "text", "content": "x1@example.com\nx2@example.com"}],
                   threads=1, fix_typos=True, check_spam=False, deep_ping=True,
                   enable_ai=False)
    снимок = p.activity.snapshot()
    assert снимок["current"] == 2 and снимок["total"] == 2


def _ждать(условие, предел=30.0):
    конец = time.monotonic() + предел
    while time.monotonic() < конец:
        if условие():
            return True
        time.sleep(0.02)
    return условие()


def _старт(p, **kw):
    return p.start(email_sources=[{"type": "text", "content": "a@example.com"}],
                   threads=1, timeout=1, fix_typos=True, check_spam=False,
                   deep_ping=True, enable_ai=False, **kw)


def test_start_shows_launch_at_once_and_done_at_the_end():
    from core.activity import describe
    p, строки, _р = _конвейер()
    p.setup = lambda **kw: None
    поток = _старт(p)
    # Признак «работает» — синхронно с нажатием, до первой строки движка.
    assert p.activity.state in ("running", "done")
    поток.join(60)
    assert not поток.is_alive()
    assert describe(p.activity.snapshot(alive=p._worker_alive()))["level"] == "done"
    pulse = p.__dict__.get("_pulse")
    assert pulse is not None
    pulse.join(10)
    assert not pulse.is_alive(), "пульс пережил прогон"
    assert [т for тег, т in строки if тег == "stage"][-1].startswith("■ Готово.")


def test_crash_in_preparation_is_reported_as_failed():
    from core.activity import describe
    p, строки, _р = _конвейер()

    def упасть(**kw):
        p._stage("lists")
        raise RuntimeError("сеть пропала")
    p.setup = упасть
    поток = _старт(p)
    поток.join(60)
    d = describe(p.activity.snapshot(alive=p._worker_alive()))
    assert d["level"] == "failed" and d["title"] == "Прервано ошибкой"
    итог = [т for тег, т in строки if тег == "stage"][-1]
    assert итог.startswith("■ Прервано ошибкой"), итог
    assert any("сеть пропала" in т for _тег, т in строки)


def test_blocked_run_is_not_called_stopped_by_you():
    """Порт 25 закрыт: работа не начиналась, но ВЫ ничего не нажимали."""
    from core.activity import describe
    p, строки, _р = _конвейер()

    def закрыто(**kw):
        p._stage("port25")
        p._block_run("порт 25 закрыт")
    p.setup = закрыто
    поток = _старт(p)
    поток.join(60)
    d = describe(p.activity.snapshot())
    assert d["level"] == "blocked", d
    assert "порт 25 закрыт" in d["detail"]
    assert [т for тег, т in строки if тег == "stage"][-1] == "■ Работа не выполнялась: порт 25 закрыт."


def test_stop_during_preparation_says_stopping_then_stopped():
    from core.activity import describe
    p, строки, _р = _конвейер()
    можно = threading.Event()

    def долго(**kw):
        p._stage("proxies")
        можно.wait(30)
    p.setup = долго
    поток = _старт(p)
    assert _ждать(lambda: p.activity.stage_key == "proxies")
    p.stop()
    assert describe(p.activity.snapshot())["level"] == "stopping"
    можно.set()
    поток.join(60)
    assert describe(p.activity.snapshot())["level"] == "stopped"


def test_dead_worker_without_outcome_is_called_dead():
    from core.activity import describe
    p, _строки, _р = _конвейер(модели=False)
    p.activity.begin()
    p.activity.stage("check")
    мёртвый = threading.Thread(target=lambda: None)
    мёртвый.start()
    мёртвый.join()
    p.__dict__["_worker"] = мёртвый
    assert describe(p.activity.snapshot(alive=p._worker_alive()))["level"] == "dead"


# ══════════════════════════════ мост окна

@pytest.fixture(scope="module")
def api():
    from ui.webapp import ValidatorApi
    return ValidatorApi()


def test_state_carries_activity_and_is_json(api):
    s = api.state({})
    a = s["activity"]
    assert a["level"] in ("idle", "done", "stopped", "blocked", "failed")
    assert {"title", "detail", "trail"} <= set(a)
    json.dumps(s)        # окно получает это по сокету — должно сериализоваться


def test_state_reports_working_engine(api):
    api.pipeline.activity.begin()
    api.pipeline.activity.stage("check")
    try:
        a = api.state({})["activity"]
        assert a["level"] == "ok" and a["title"] == "Работает"
        assert a["trail"][-1] == {"label": "Проверка", "seconds": a["trail"][-1]["seconds"],
                                  "active": True}
    finally:
        api.pipeline.activity.finish("done")


def test_every_log_line_has_its_birth_time(api):
    до = time.time()
    api._on_log("[INFO] проба времени", "info")
    после = time.time()
    хвост = api.log_tail()["log"]
    строка = [l for l in хвост if l["text"] == "[INFO] проба времени"][-1]
    assert до <= строка["t"] <= после


def test_activity_travels_over_the_real_socket():
    from ui.webapp import ValidatorApi, start_api_server
    api = ValidatorApi()
    server, port, token = start_api_server(api)
    try:
        req = urllib.request.Request("http://127.0.0.1:%d/api/state" % port,
                                     data=json.dumps({"logSince": 0}).encode(),
                                     headers={"X-Token": token,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=10) as r:
            ответ = json.loads(r.read().decode("utf-8"))
        assert ответ["activity"]["title"] == "Не запущено"
    finally:
        server.shutdown()


# ══════════════════════════════ сбор адресов

def test_parser_callbacks_feed_monitor_and_forward(api):
    cb = api._observed_parser_callbacks()
    api.parser_activity.begin()
    api.parser_activity.stage("p_search")
    cb["on_stats_update"](10, 3, 1, 4, 5)
    cb["on_progress"](7, 20, 35, "Проверка прокси")
    cb["on_log"]("[Система] проба")
    снимок = api.parser_activity.snapshot()
    assert (снимок["current"], снимок["total"], снимок["found"]) == (3, 10, 5)
    assert (снимок["auxCurrent"], снимок["auxTotal"]) == (7, 20)
    assert api._parser_stats["dorksDone"] == 3, "статистика не дошла до окна"
    assert api._parser_progress[3] == "Проверка прокси"
    хвост = api.parser_log_tail()["log"]
    assert хвост[-1]["text"] == "[Система] проба" and isinstance(хвост[-1]["t"], float)
    a = api.parser_state()["activity"]
    assert "дорков 3 из 10" in a["detail"] and "адресов найдено 5" in a["detail"]
    api.parser_activity.finish("done")


@pytest.mark.parametrize("прервано, стоп, уровень", [
    (False, False, "done"), (True, True, "stopped"), (True, False, "blocked")])
def test_parser_outcome(прервано, стоп, уровень):
    from ui.webapp import ValidatorApi
    from core.activity import describe
    a = ValidatorApi()
    a.parser = type("P", (), {"_stop_event": threading.Event()})()
    if стоп:
        a.parser._stop_event.set()
    a.parser_activity.begin()
    a._finish_parser_activity(прервано)
    assert describe(a.parser_activity.snapshot())["level"] == уровень


class _Поисковик:
    """Поддельный поисковик: на дорке «broken» бросает, на остальных отдаёт
    фрагмент с адресом. Сети нет. Адреса латиницей: извлекатель берёт только
    их, и кириллица в тестовом адресе проверяла бы извлекатель, а не сбор."""

    def __init__(self, *a, **kw):
        pass

    def search_generator(self, query):
        if "broken" in query:
            raise RuntimeError("поисковик ответил мусором")
        yield "contacts: %s@example.com" % re.sub(r"\W", "", query)


def _сбор(monkeypatch, текст, медленный_фидер=0.0):
    """Настоящий ParserPipeline.run() с поддельными моделью и поисковиком.
    Возвращает (строки, найдено, монитор, необработанные исключения потоков)."""
    import core.parser_pipeline as модуль
    from core.activity import ActivityMonitor

    class _Пусто:
        def __init__(self, *a, **kw):
            pass

    monkeypatch.setattr(модуль, "MLPredictor", _Пусто)
    monkeypatch.setattr(модуль, "NameExtractor", _Пусто)
    monkeypatch.setattr(модуль, "DuckDuckGoEngine", _Поисковик)
    упавшие = []
    monkeypatch.setattr(threading, "excepthook", lambda args: упавшие.append(args.exc_value))

    строки, найдено = [], []
    mon = ActivityMonitor(kind="parser", emit=lambda т, тег: строки.append((тег, т)))
    завершено = threading.Event()
    p = модуль.ParserPipeline(
        dork_sources=[{"type": "text", "content": текст}],
        proxies=[], max_threads=3, timeout=1,
        on_log=lambda т, *a: строки.append(("info", т)),
        on_result_found=lambda e, d: найдено.append(e),
        on_complete=lambda aborted=False: завершено.set(),
        engine_name="DuckDuckGo Lite", activity=mon)
    if медленный_фидер:
        исходный = p._feed_dorks

        def медленно():
            time.sleep(медленный_фидер)       # файл на холодном диске
            исходный()
        p.feeder_thread = threading.Thread(target=медленно, daemon=True)
    p.run()                      # синхронно: поток самого сбора здесь не нужен
    assert завершено.is_set()
    return строки, найдено, mon, упавшие


def test_parser_run_goes_through_stages_and_releases_inflight(monkeypatch):
    строки, найдено, mon, упавшие = _сбор(monkeypatch, "alpha\nbroken\ngamma\ndelta")
    этапы = [т for тег, т in строки if тег == "stage"]
    assert этапы[0] == "▶ Подготовка сбора" and "▶ Поиск по доркам" in этапы, этапы
    assert mon.snapshot()["inflight"] == 0, "«в работе» залипло — в том числе после сбоя дорка"
    assert sorted(найдено) == ["alpha@example.com", "delta@example.com", "gamma@example.com"]
    assert any("поисковик ответил мусором" in т for _тег, т in строки)
    # Штатный конец сбора — не авария. Раньше каждый поток в конце падал на
    # сигнале конца (None) с TypeError, и в журнал сбоев шло по записи на поток.
    assert упавшие == [], упавшие


def test_parser_workers_wait_for_a_slow_feeder(monkeypatch):
    """Фидер ещё не прочитал первую строку — потоки обязаны ждать, а не
    уходить с пустыми руками (раньше: get_nowait и выход на пустой очереди)."""
    _строки, найдено, mon, упавшие = _сбор(monkeypatch, "one\ntwo\nthree", медленный_фидер=1.0)
    assert sorted(найдено) == ["one@example.com", "three@example.com", "two@example.com"], (
        "потоки ушли раньше, чем фидер положил первый дорк")
    assert mon.snapshot()["inflight"] == 0
    assert упавшие == [], упавшие


def test_parser_without_activity_still_works():
    from core.parser_pipeline import ParserPipeline
    p = ParserPipeline(dork_sources=[{"type": "text", "content": "x"}], proxies=[],
                       max_threads=1)
    assert p.activity.kind == "parser" and p.activity.emit is None


# ══════════════════════════════ консоль CLI

def test_cli_lines_carry_time_and_do_not_glue_to_progress(monkeypatch, tmp_path, capsys):
    import cli
    from core.pipeline import ValidationPipeline

    class _Пробный(ValidationPipeline):
        def setup(self, **kw):
            self._stage("cache")
            self.callbacks["on_log"]("[INFO] подготовка", "info")

        def run_pipeline(self, sources, **kw):
            self._stage("check")
            self.callbacks["on_progress"](1, 2)
            self.callbacks["on_log"]("[INFO] после прогресса", "info")
            self.callbacks["on_progress"](2, 2)
            self.is_running = False
            self._finish_activity()
            self.callbacks["on_complete"]()

    monkeypatch.setattr(cli, "ValidationPipeline", _Пробный)
    база = tmp_path / "base.txt"
    база.write_text("a@example.com\n", encoding="utf-8")
    код = cli.main(["validate", "--emails", str(база), "--allow-direct",
                    "-o", str(tmp_path / "out.csv"), "--no-ai"])
    err = capsys.readouterr().err
    assert код == 0, err
    строки = [s for s in err.split("\n") if s.strip()]
    время = re.compile(r"^\d\d:\d\d:\d\d ")
    журнал = [s for s in строки if not s.startswith("\r") and "/" not in s[:6]]
    assert all(время.match(s) for s in журнал if "подготовка" in s or "после прогресса" in s
               or s.lstrip("\r").startswith(("▶", "✓", "■"))), err
    # Строка журнала после прогресса начинается С НОВОЙ строки, а не хвостом.
    assert not re.search(r"\(\d+%\)\d\d:\d\d:\d\d", err), err
    assert re.search(r"\d\d:\d\d:\d\d ■ Готово\.", err), err


# ══════════════════════════════ страница

def test_page_has_live_strips_on_both_screens():
    html = читать("ui", "web", "index.html")
    for id_ in ("live", "liveTitle", "liveDetail", "liveTrail",
                "pLive", "pLiveTitle", "pLiveDetail", "pLiveTrail"):
        assert 'id="%s"' % id_ in html, id_
    assert html.count('class="live__clock"') == 2


def test_script_renders_activity_time_and_no_link():
    js = читать("ui", "web", "app.js")
    assert 'renderLive("live", s.activity)' in js
    assert 'renderLive("pLive", s.activity)' in js
    assert 'renderNoLink("live", lastStateOk)' in js
    assert 'renderNoLink("pLive", lastParserOk)' in js
    assert "clockOf(line.t)" in js and "setInterval(tickClocks, 1000)" in js


def test_styles_cover_every_level_and_respect_reduced_motion():
    css = читать("ui", "web", "style.css")
    from core.activity import LEVELS
    for уровень in LEVELS + ("nolink",):
        if уровень in ("idle", "stopped"):
            continue          # серые — оформление по умолчанию
        assert '[data-level="%s"]' % уровень in css, уровень
    assert "prefers-reduced-motion" in css
    for класс in (".l-stage", ".l-pulse", ".l-pulse-slow", ".l-pulse-stall", ".log .t"):
        assert класс in css, класс
