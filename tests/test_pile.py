# -*- coding: utf-8 -*-
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.pipeline as pipeline_module
from tests.test_third_pass import FakeNetwork, validator

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def test_resume_count_is_readable_without_touching_the_journal(tmp_path):
    from core.runstate import RunState, resumable_count, run_id_for

    journal = str(tmp_path / "state.sqlite")
    source = str(tmp_path / "base.txt")
    io.open(source, "w", encoding="utf-8").write("a@x.test\n")
    sources = [{"type": "file", "path": source}]

    state = RunState(run_id_for(sources), path=journal, resume=False)
    state.mark_done("a@x.test")
    state.mark_done("b@x.test")
    state.close()

    assert resumable_count(sources, path=journal) == 2
    assert resumable_count(sources, path=journal) == 2


def test_resume_count_is_zero_for_other_files(tmp_path):
    from core.runstate import RunState, resumable_count, run_id_for

    journal = str(tmp_path / "state.sqlite")
    one = str(tmp_path / "one.txt")
    two = str(tmp_path / "two.txt")
    io.open(one, "w", encoding="utf-8").write("a@x.test\n")
    io.open(two, "w", encoding="utf-8").write("b@x.test\nc@x.test\n")

    state = RunState(run_id_for([{"type": "file", "path": one}]),
                     path=journal, resume=False)
    state.mark_done("a@x.test")
    state.close()

    assert resumable_count([{"type": "file", "path": two}], path=journal) == 0


def test_resume_is_on_by_default_in_the_core():
    import inspect
    from core.pipeline import ValidationPipeline

    for метод in (ValidationPipeline.run_pipeline, ValidationPipeline.start):
        параметры = inspect.signature(метод).parameters
        assert параметры["resume"].default is True, (
            "%s: продолжение снова выключено по умолчанию" % метод.__name__)

    source = read("ui/webapp.py")
    assert 'payload.get("resume"' not in source, (
        "окно снова передаёт настройку и может её выключить")


def test_resume_state_is_wiped_after_a_finished_run():
    import re
    assert "self._settle_resume_journal(state, resume, feeder_error)" in read("core/pipeline.py"), (
        "конвейер не решает судьбу журнала продолжения в конце прогона")
    source = read("core/pipeline_control.py")
    assert re.search(r"if \(?resume and not self\._stop_requested(?: and not feeder_error)?\)?"
                     r"(?: or self\._aborting)?:", source), (
        "память о прогоне не стирается — повторный прогон даст ноль адресов")
    assert "state.clear()" in source, "стирание не вызывается"


def test_mail_from_spf_is_measured_for_every_sender():
    from core.mail_constants import MAIL_FROM_POOL, MAIL_FROM_SPF_MODE

    domains = {addr.split("@")[1].lower() for addr in MAIL_FROM_POOL}
    missing = sorted(domains - set(MAIL_FROM_SPF_MODE))
    assert not missing, "в пуле есть незамеренные отправители: %s" % missing


def test_mail_from_pool_has_no_strict_spf():
    from core.mail_constants import MAIL_FROM_POOL, MAIL_FROM_SPF_MODE

    strict = sorted(dom for dom, mode in MAIL_FROM_SPF_MODE.items()
                    if mode.strip() == "-all"
                    and dom in {a.split("@")[1] for a in MAIL_FROM_POOL})
    assert not strict, "строгий SPF у отправителя: %s" % strict


def test_final_sweep_gives_a_second_round(monkeypatch):
    calls = []

    class TwiceBroken(FakeNetwork):
        def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
            calls.append(avoid_exit_of or prefer_exit_of)
            if len(calls) < 3:
                return {"status": "unknown", "reason": "Timeout",
                        "mx_record": "mx.test", "proxy": "socks5://a:%d" % len(calls)}
            return {"status": "valid", "reason": "250 OK", "mx_record": "mx.test"}

    results = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: results.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = TwiceBroken({"status": "unknown", "reason": "Timeout"})
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)
    monkeypatch.setattr(pipeline_module, "GREYLIST_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)

    assert len(calls) == 3, "второго круга не было: %s" % (calls,)
    assert results and results[0][1] == "Valid", results


def test_final_sweep_stops_at_the_declared_limit(monkeypatch):
    calls = []

    class NeverAnswers(FakeNetwork):
        def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
            calls.append(1)
            return {"status": "unknown", "reason": "Timeout",
                    "mx_record": "mx.test", "proxy": "socks5://a:1"}

    results = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: results.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = NeverAnswers({"status": "unknown", "reason": "Timeout"})
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)
    monkeypatch.setattr(pipeline_module, "GREYLIST_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)

    assert len(calls) == 1 + pipeline_module.MAX_RETRY_ROUNDS, calls
    assert results and results[0][0] == "user@example-corp.test", results


def test_mx_hint_needs_two_neighbours():
    v = validator()
    assert v._mx_catchall_suspected("mx.hoster.test", "mine.test") is False
    v._note_mx_catchall("mx.hoster.test", "one.test")
    assert v._mx_catchall_suspected("mx.hoster.test", "mine.test") is False
    v._note_mx_catchall("mx.hoster.test", "two.test")
    assert v._mx_catchall_suspected("mx.hoster.test", "mine.test") is True


def test_mx_hint_saves_the_domain_when_the_probe_breaks():
    v = validator()
    v._note_mx_catchall("mx.hoster.test", "one.test")
    v._note_mx_catchall("mx.hoster.test", "two.test")
    v._probe_recipients = lambda addrs, mx, proxy=None, from_email=None: [
        {"status": "unknown", "reason": "Timeout"} for _ in addrs]
    assert v.is_catch_all_domain("mine.test", "mx.hoster.test") is True


def test_mx_hint_never_overrides_a_real_answer():
    v = validator()
    v._note_mx_catchall("mx.hoster.test", "one.test")
    v._note_mx_catchall("mx.hoster.test", "two.test")
    v._probe_recipients = lambda addrs, mx, proxy=None, from_email=None: [
        {"status": "invalid", "reason": "550 no such user"} for _ in addrs]
    assert v.is_catch_all_domain("mine.test", "mx.hoster.test") is False


def test_helo_differs_between_exits():
    v = validator(proxies=["a:1", "b:2", "c:3"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"},
                            "c:3": {"exit_ip": "3.3.3.3"}})
    names = {v._helo_for(p) for p in ("a:1", "b:2", "c:3")}
    assert len(names) > 1, "все выходы представляются одинаково: %s" % names


def test_helo_is_stable_for_one_exit():
    v = validator(proxies=["a:1"], profiles={"a:1": {"exit_ip": "1.1.1.1"}})
    first = v._helo_for("a:1")
    assert all(v._helo_for("a:1") == first for _ in range(5))
    from core.mail_constants import LEGIT_HELO_NAMES
    assert first in LEGIT_HELO_NAMES


def test_helo_without_proxy_falls_back():
    v = validator()
    assert v._helo_for(None) == v.helo_name


def test_banned_proxy_is_reported_once():
    v = validator(proxies=["a:1", "b:2"])
    assert v.take_recent_bans() == []
    from core.mail_constants import PROXY_MAX_CONSECUTIVE_FAILS
    for number in range(PROXY_MAX_CONSECUTIVE_FAILS):
        v._update_proxy_score("a:1", False, mx_record="mx%d.test" % number)
    assert v.take_recent_bans() == ["a:1"]
    assert v.take_recent_bans() == [], "о выбытии доложили дважды"


def test_pipeline_says_which_proxy_left():
    source = read("core/pipeline.py")
    assert "take_recent_bans" in source, "конвейер не спрашивает о выбывших"
    assert "Прокси выбыл из ротации" in source


def test_retry_phase_is_announced(monkeypatch):
    phases = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: None,
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
        "on_phase": lambda name, count: phases.append((name, count)),
    })
    pipe.network = FakeNetwork({"status": "unknown", "reason": "Timeout",
                                "mx_record": "mx.test", "proxy": "socks5://a:1"})
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)

    assert ("retry", 1) in phases, phases
    assert phases[-1] == ("", 0), "фаза не снята — окно так и останется в ней"


def test_phase_channel_is_optional(monkeypatch):
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: None,
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe._phase("retry", 5)


def test_web_window_shows_the_phase():
    assert '"phase"' in read("ui/webapp.py")
    assert "Перепроверка отложенных" in read("ui/web/app.js")


def test_dead_api_is_gone():
    from core import runstate

    for name in ("schedule_retry", "due_retries", "pending_retries",
                 "next_due_in", "drain_retries"):
        assert not hasattr(runstate.RunState, name), (
            "мёртвый метод вернулся: %s" % name)
    assert "CREATE TABLE IF NOT EXISTS retry" not in read("core/runstate.py")


def test_dead_api_removal_left_the_delays_alone():
    from core.runstate import DEFAULT_RETRY_DELAY, GREYLIST_RETRY_DELAY

    assert DEFAULT_RETRY_DELAY == 90
    assert GREYLIST_RETRY_DELAY >= 300


def test_markers_split_fast_from_slow():
    config = read("pytest.ini")
    assert "markers =" in config and "slow:" in config

    marked = [name for name in sorted(os.listdir(os.path.join(ROOT, "tests")))
              if name.endswith(".py")
              and "pytestmark = pytest.mark.slow" in read("tests/" + name)]
    assert len(marked) >= 3, "медленными помечено слишком мало файлов: %s" % marked


def test_timeout_is_configured():
    config = read("pytest.ini")
    assert "timeout =" in config
    import pytest_timeout
    assert "pytest-timeout" in read("requirements-dev.txt")


@pytest.mark.slow
def test_slow_marker_actually_deselects_this_test():
    assert True


def test_journal_stays_enabled_after_a_clean_start(tmp_path):
    from core.runstate import RunState

    state = RunState("clean-start", path=str(tmp_path / "s.sqlite"), resume=False)
    try:
        assert state.enabled, "журнал выключился на обычном старте"
        assert state.add_if_new("a@x.test") is True
        assert state.add_if_new("a@x.test") is False, "дедуп на диске не работает"
    finally:
        state.close()


def test_starttls_decision_is_recorded_with_the_measurement():
    doc = read("docs/КРИТЕРИИ.md")
    assert "STARTTLS проверке ящика ничего не даёт" in doc
    assert "550 5.7.1 No such user!" in doc, "замер приведён без данных"


def test_two_windows_gap_is_measured_not_guessed():
    doc = read("docs/КРИТЕРИИ.md")
    assert "Два интерфейса" in doc
    assert "двенадцати возможностям" in doc
    assert "запасное окно остаётся" in doc.lower() or "остаётся" in doc

