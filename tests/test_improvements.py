# -*- coding: utf-8 -*-
from исходники import исходник_конвейера
import datetime
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.proxy_profile import readiness_report


def test_readiness_says_nothing_loaded():
    report = readiness_report({})
    assert report["ready"] is False
    assert "домашнего" in report["verdict"]
    assert "Yahoo" in report["verdict"]


def test_readiness_detects_closed_port_25():
    dead = {"p": {"exit_ip": None, "outlook_ok": None,
                  "has_ptr": None, "in_dnsbl": False}}
    report = readiness_report(dead)
    assert report["ready"] is False
    assert "порт 25" in report["verdict"]
    assert "587" in report["verdict"]


def test_readiness_names_what_will_be_unreachable():
    partial = {"p": {"exit_ip": "1.2.3.4", "outlook_ok": False,
                     "yahoo_ok": False, "icloud_ok": False,
                     "has_ptr": False, "in_dnsbl": True}}
    report = readiness_report(partial)
    assert report["ready"] is True
    assert "Yahoo" in report["verdict"]
    closed = [p for p in report["providers"] if not p["ok"]]
    assert closed, "ни один провайдер не отмечен закрытым"
    for item in closed:
        assert item["reason"], "у закрытого провайдера нет объяснения"
    reasons = " ".join(p["reason"] for p in closed)
    assert "PTR" in reasons and "VPS" in " ".join(
        p["reason"] for p in report["providers"])


def test_readiness_is_happy_when_everything_works():
    good = {"p": {"exit_ip": "1.2.3.4", "outlook_ok": True, "yahoo_ok": True,
                  "icloud_ok": True, "has_ptr": True, "in_dnsbl": False}}
    report = readiness_report(good)
    assert report["ready"] is True
    assert all(p["ok"] for p in report["providers"])


def test_readiness_takes_provider_names_from_the_real_source():
    from core.proxy_profile import PROVIDER_FITNESS, _READINESS_ORDER

    assert tuple(PROVIDER_FITNESS) == _READINESS_ORDER


def test_readiness_survives_junk():
    for junk in (None, [], "текст", {"p": None}, {"p": "нет"}):
        report = readiness_report(junk)
        assert isinstance(report, dict) and "ready" in report


def test_vpsscript_builds_a_working_setup():
    from tools.make_vps_proxy import build_script

    script = build_script("validator", "S3cret", 1080)
    assert script.startswith("#!/bin/bash")
    assert "3proxy" in script
    assert 'PROXY_USER="validator"' in script
    assert 'PROXY_PASS="S3cret"' in script
    assert "users $PROXY_USER:CL:$PROXY_PASS" in script
    assert "socks -p$PROXY_PORT" in script and "PROXY_PORT=1080" in script
    assert "systemctl enable 3proxy" in script


def test_vpsscript_checks_port_25_and_ptr():
    from tools.make_vps_proxy import build_script

    script = build_script("u", "p")
    assert "gmail-smtp-in.l.google.com 25" in script
    assert "587" in script and "465" in script
    assert "PTR" in script
    assert "5.7.25" in script or "Yahoo" in script


def test_vpsscript_prints_the_ready_line_for_the_validator():
    from tools.make_vps_proxy import build_script

    script = build_script("validator", "S3cret", 1080)
    assert "socks5://$PROXY_USER:$PROXY_PASS@$IP:$PROXY_PORT" in script
    assert 'PROXY_USER="validator"' in script and 'PROXY_PASS="S3cret"' in script


def test_vpsscript_generates_a_strong_password():
    from tools.make_vps_proxy import strong_password

    first, second = strong_password(), strong_password()
    assert len(first) >= 16 and first != second
    assert first.isalnum()


def test_spamhaus_is_actually_wired_into_the_run():
    source = исходник_конвейера()

    assert "set_spamhaus_resolver" in source, "конвейер не включает Spamhaus"
    assert "spamhaus_resolvers" in source, "адрес резолвера ниоткуда не берётся"


def test_spamhaus_is_enabled_after_the_validator_exists():
    source = исходник_конвейера()

    assert source.index("self.network = NetworkValidator") < \
        source.index("set_spamhaus_resolver")


def test_spamhaus_explains_itself_when_off():
    source = исходник_конвейера()

    assert "127.255.255.254" in source
    assert "settings.json" in source
    assert "spamhaus_refusal_reason" in source


def test_spamhaus_resolvers_read_from_settings():
    from core.settings import spamhaus_resolvers

    value = spamhaus_resolvers()
    assert isinstance(value, list)


def test_invariant_all_results_go_through_one_door():
    source = исходник_конвейера()

    assert source.count("self.callbacks['on_result'](") == 1
    assert source.count("self._emit(") >= 5


def test_invariant_counts_what_actually_left():
    from core.pipeline import ValidationPipeline

    seen = []
    pipeline = ValidationPipeline(callbacks={
        "on_log": lambda text, kind="info": None,
        "on_result": lambda *args: seen.append(args),
        "on_complete": lambda: None,
    })
    for i in range(5):
        pipeline._emit("u%d@gmail.com" % i, "Valid", "250 OK", "mx", {})

    assert pipeline._emitted == 5
    assert len(seen) == 5


def test_invariant_reports_a_loss():
    source = исходник_конвейера()

    assert "ПОТЕРЯНО АДРЕСОВ" in source
    assert "Результатов больше, чем адресов" in source
    assert "сходится" in source


def test_twostage_cheap_checks_run_before_smtp():
    source = исходник_конвейера()

    disposable = source.index("Шаг 1.1: Проверка на одноразовый")
    cache = source.index("Шаг 2: Кэш прошлых прогонов")
    smtp = source.index("Шаг 3: Глубокий SMTP Ping")
    assert disposable < cache < smtp


def test_twostage_saves_real_sessions():
    from core.disposable import is_disposable
    from core.email_syntax import validate_email_syntax

    base = (["user%d@gmail.com" % i for i in range(200)] +
            ["hacker%d@tempmail.com" % i for i in range(60)] +
            ["info%d@corp%d.com" % (i, i) for i in range(60)] +
            [".broken%d@@bad" % i for i in range(40)] +
            ["user%d@gmail.com" % i for i in range(40)])

    seen, filtered, need_smtp = set(), 0, 0
    for email in base:
        if email in seen:
            filtered += 1
            continue
        seen.add(email)
        if not validate_email_syntax(email) or is_disposable(email):
            filtered += 1
            continue
        need_smtp += 1

    assert filtered + need_smtp == len(base)
    assert filtered / len(base) > 0.30, filtered / len(base)


def _stamp(days_ago):
    when = datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)
    return (when - datetime.timedelta(days=days_ago)).strftime("%Y-%m-%d %H:%M")


def test_freshness_marks_a_stale_verdict():
    from ui.webapp import _verdict_age

    fresh = _verdict_age(_stamp(0))
    assert fresh["days"] == 0 and fresh["stale"] is False

    old = _verdict_age(_stamp(40))
    assert old["days"] == 40 and old["stale"] is True


def test_freshness_threshold_comes_from_settings():
    from core.settings import DEFAULTS

    assert "verdict_fresh_days" in DEFAULTS
    assert DEFAULTS["verdict_fresh_days"] > 0


def test_freshness_survives_missing_or_broken_dates():
    from ui.webapp import _verdict_age

    for junk in ("", None, "когда-то", "2026-13-45 99:99", 123):
        assert _verdict_age(junk) == {}


def test_freshness_reaches_the_table():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_result("ivan@gmail.com", "Valid", "250 OK", "mx",
                   {"engagement_score": 80, "validated_at": _stamp(40)})
    row = api.page({"groups": ["valid"]})["rows"][0]
    assert row["age"]["stale"] is True
    assert row["age"]["days"] == 40


def test_segments_split_by_every_field():
    from core.baseops import split_by_segment

    rows = [
        {"email": "a@gmail.com", "data": {"country": "США", "gender": "Мужской"}},
        {"email": "b@yahoo.com", "data": {"country": "Германия", "gender": "Женский"}},
        {"email": "c@gmail.com", "data": {"country": "", "gender": ""}},
    ]
    assert set(split_by_segment(rows, "country")) == {"США", "Германия", ""}
    assert set(split_by_segment(rows, "gender")) == {"Мужской", "Женский", ""}
    assert set(split_by_segment(rows, "provider")) == {"gmail.com", "yahoo.com"}


def test_segments_keep_rows_without_a_value():
    from core.baseops import split_by_segment

    rows = [{"email": "c@gmail.com", "data": {"country": ""}}]
    buckets = split_by_segment(rows, "country")
    assert buckets[""] == rows


def test_segments_lose_nothing():
    from core.baseops import split_by_segment

    rows = [{"email": "u%d@%s" % (i, ["gmail.com", "yahoo.com"][i % 2]),
             "data": {"country": ["США", "", "Индия"][i % 3]}}
            for i in range(60)]
    for key in ("country", "provider"):
        buckets = split_by_segment(rows, key)
        assert sum(len(v) for v in buckets.values()) == len(rows), key


def test_segments_filenames_are_portable():
    from core.baseops import segment_filename

    assert segment_filename("США") == "ssha"
    assert segment_filename("Мужской") == "muzhskoy"
    assert segment_filename("gmail.com") == "gmail-com"
    assert segment_filename("") == "ne-opredeleno"
    assert segment_filename(None) == "ne-opredeleno"
    for value in ("США", "Мужской", "gmail.com", "", "a b/c\\d"):
        name = segment_filename(value)
        assert name and all(c.isalnum() or c == "-" for c in name), name


def test_sharedcache_path_is_configurable():
    from core.settings import DEFAULTS, cache_path

    assert "cache_path" in DEFAULTS
    assert isinstance(cache_path(), str) and cache_path()


def test_sharedcache_defaults_to_the_usual_place():
    from core.cache import DEFAULT_CACHE_PATH
    from core.settings import cache_path, load

    load(refresh=True)
    assert cache_path() == DEFAULT_CACHE_PATH


def test_sharedcache_pipeline_uses_the_setting():
    source = исходник_конвейера()

    assert "from core.settings import cache_path" in source
    assert "ResultCache(path=chosen)" in source


def test_sharedcache_says_when_it_is_shared():
    source = исходник_конвейера()

    assert "Общий кэш" in source


def test_sharedcache_settings_survive_a_broken_file(tmp_path, monkeypatch):
    import core.settings as settings

    broken = tmp_path / "settings.json"
    broken.write_text("{это не json", encoding="utf-8")
    monkeypatch.setattr(settings, "SETTINGS_PATH", str(broken))
    assert settings.load(refresh=True) == settings.DEFAULTS


def test_sharedcache_settings_round_trip(tmp_path, monkeypatch):
    import core.settings as settings

    target = tmp_path / "settings.json"
    monkeypatch.setattr(settings, "SETTINGS_PATH", str(target))
    assert settings.save({"cache_path": "D:/shared/cache.sqlite"}) is True
    assert settings.load(refresh=True)["cache_path"] == "D:/shared/cache.sqlite"
    settings.save({"мусор": 1})
    assert "мусор" not in settings.load(refresh=True)


def test_segments_reach_the_window():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    assert callable(getattr(api, "export_segments", None))
    refused = api.export_segments({"by": "чепуха"})
    assert refused["ok"] is False and "Неизвестный признак" in refused["error"]


def test_segments_button_exists_on_the_page():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "ui", "web", "index.html")
    with io.open(path, encoding="utf-8") as handle:
        html = handle.read()
    assert 'id="segmentBy"' in html
    for value in ("country", "gender", "provider"):
        assert 'value="%s"' % value in html, value


def test_freshness_shown_on_the_page():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "ui", "web", "app.js")
    with io.open(path, encoding="utf-8") as handle:
        js = handle.read()
    assert "function whenTitle(" in js
    assert "вердикт устарел" in js
    assert "is-stale" in js


def test_freshness_stale_style_is_a_warning_not_an_error():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "ui", "web", "style.css")
    with io.open(path, encoding="utf-8") as handle:
        css = handle.read()
    assert ".grid td.is-stale" in css
    assert "var(--warn)" in css.split(".grid td.is-stale")[1][:80]


def test_invariant_pipeline_keeps_every_part_it_needs():
    from core.pipeline import ValidationPipeline

    pipeline = ValidationPipeline(callbacks={
        "on_log": lambda text, kind="info": None,
        "on_result": lambda *args: None,
        "on_complete": lambda: None,
    })
    for part in ("cleaner", "callbacks", "is_running", "is_paused",
                 "_stop_requested", "_emitted", "_emitted_lock",
                 "gravatar_checker", "_domain_age_cache", "_inflight"):
        assert hasattr(pipeline, part), "конвейер собран без %s" % part

    assert pipeline.cleaner.clean_email("  <IVAN@Gmail.com>  ") == "IVAN@gmail.com"


def test_segments_survive_junk():
    from core.baseops import split_by_segment

    for junk in (None, 123, "текст", b"bytes", {}, object()):
        assert split_by_segment(junk, "country") == {}

    mixed = [None, "строка", {"email": "a@b.com", "data": {}}]
    assert split_by_segment(mixed, "country") == {"": [mixed[2]]}
