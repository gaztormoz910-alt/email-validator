# -*- coding: utf-8 -*-
from исходники import исходник_конвейера
import io
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def wait_for_count(api, kind, tries=60):
    for _ in range(tries):
        value = api.sources()[kind]["lines"]
        if value is not None:
            return value
        time.sleep(0.05)
    return api.sources()[kind]["lines"]


def test_loaded_lines_are_reported_for_pasted_text():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "a@gmail.com\nb@mail.ru\nc@yahoo.com"})
    assert wait_for_count(api, "emails") == 3


def test_loaded_lines_add_up_across_sources(tmp_path):
    from ui.webapp import ValidatorApi

    path = tmp_path / "base.txt"
    io.open(path, "w", encoding="utf-8").write("d@gmail.com\ne@gmail.com\n")

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "a@gmail.com\nb@mail.ru"})
    api._sources["emails"].append({"type": "file", "path": str(path)})
    api._recount("emails")
    assert wait_for_count(api, "emails") == 4


def test_loaded_lines_reported_for_every_field():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080\n5.6.7.8:1080"})
    api.paste({"kind": "dorks", "text": 'site:vk.com "@mail.ru"'})
    api.paste({"kind": "pproxy", "text": "9.9.9.9:3128"})
    assert wait_for_count(api, "proxies") == 2
    assert wait_for_count(api, "dorks") == 1
    assert wait_for_count(api, "pproxy") == 1


def test_loaded_lines_reset_to_zero_after_clearing():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "a@gmail.com\nb@gmail.com"})
    assert wait_for_count(api, "emails") == 2
    api.clear({"kind": "emails"})
    assert api.sources()["emails"]["lines"] == 0


def test_loaded_lines_do_not_replace_the_file_count():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "a@gmail.com\nb@gmail.com"})
    wait_for_count(api, "emails")
    info = api.sources()["emails"]
    assert info["count"] == 1
    assert info["lines"] == 2


def test_counting_is_background_and_answers_immediately(tmp_path):
    from ui.webapp import ValidatorApi

    path = tmp_path / "big.txt"
    with io.open(path, "w", encoding="utf-8") as handle:
        for i in range(200_000):
            handle.write("user%d@gmail.com\n" % i)

    api = ValidatorApi()
    api._sources["emails"].append({"type": "file", "path": str(path)})

    started = time.monotonic()
    api._recount("emails")
    answer = api.sources()["emails"]["lines"]
    elapsed = time.monotonic() - started

    assert elapsed < 1.0, "счёт держал вызов %.1f с" % elapsed
    assert answer is None, "пока считаем, наружу идёт «ещё считаю», а не ноль"
    assert wait_for_count(api, "emails", tries=200) == 200_000


def test_counting_while_running_is_not_zero_but_unknown():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._sources["emails"].append({"type": "text", "content": "a@gmail.com"})
    api._recount("emails")
    assert api.sources()["emails"]["lines"] != 0


def test_counting_ignores_a_stale_answer(tmp_path):
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._sources["emails"].append({"type": "text", "content": "a@gmail.com"})
    api._recount("emails")
    wait_for_count(api, "emails")

    api._sources["emails"].append({"type": "text", "content": "b@gmail.com\nc@gmail.com"})
    api._recount("emails")
    assert wait_for_count(api, "emails") == 3


def test_separate_channel_for_proxy_progress():
    import inspect

    from core import pipeline

    source = исходник_конвейера()
    call = source[source.index("live_proxies, total_seen = filter_live_proxies"):]
    call = call[:call.index(")")]
    assert "on_proxy_progress" in source
    assert "self.callbacks['on_progress']" not in call


def test_separate_channel_does_not_move_the_email_bar():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_proxy_progress(16891, 19590)
    state = api.state()
    assert state["progress"] == {"current": 0, "total": 0, "pct": 0}
    assert state["proxyProgress"]["checked"] == 16891
    assert state["proxyProgress"]["seen"] == 19590


def test_separate_channel_is_optional_for_old_callers():
    from core.pipeline import ValidationPipeline

    pipe = ValidationPipeline(callbacks={"on_log": lambda *a: None})
    assert pipe.callbacks.get("on_proxy_progress") is None


def test_not_a_total_has_no_percentage():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_proxy_progress(16891, 19590)
    assert "pct" not in api.state()["proxyProgress"]


def test_not_a_total_is_marked_running_only_during_the_proxy_stage():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_proxy_progress(100, 2799)
    assert api.state()["proxyProgress"]["running"] is False

    api.pipeline.is_running = True
    api.pipeline.activity.stage("proxies")
    assert api.state()["proxyProgress"]["running"] is True

    api.pipeline.activity.stage("check")
    api._on_progress(5, 100)
    assert api.state()["proxyProgress"]["running"] is False
    assert api.state()["progress"]["pct"] == 5

    api.pipeline.activity.stage("proxies")
    assert api.state()["proxyProgress"]["running"] is True
    api.stop()
    assert api.state()["proxyProgress"]["running"] is False


def test_not_a_total_log_line_does_not_look_like_a_fraction():
    import inspect

    from core import proxy_probe

    source = inspect.getsource(proxy_probe)
    assert "Проверено: {c} | Прочитано: {t}" in source
    assert "Проверка... {c}/{t}" not in source


def test_not_a_total_growth_matches_what_the_screenshots_showed():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    for checked, seen in ((16891, 19590), (16981, 19679), (17068, 19767),
                          (17966, 20665), (18406, 21104), (18484, 21182),
                          (18616, 21315), (18655, 21354), (23691, 26390)):
        assert 2698 <= seen - checked <= 2699, (checked, seen)
        api._on_proxy_progress(checked, seen)
        state = api.state()
        assert state["progress"]["current"] == 0, "прокси попали в счёт адресов"
        assert state["proxyProgress"]["checked"] == checked


def test_page_shows_the_line_count():
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    assert "linesLabel" in js
    assert "info.lines" in js
    assert "считаю строки" in js


def test_page_shows_the_proxy_phase_separately():
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    assert "proxyProgress" in js
    assert "Проверяю прокси" in js
    assert "Проверено адресов" in js


def test_page_plural_form_is_correct():
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    assert 'plural(info.lines, "строка", "строки", "строк")' in js


def test_page_polls_until_the_count_arrives():
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    assert "armCountPoll" in js
    assert "setTimeout(refreshSources" in js
    assert "clearTimeout(countPoll)" in js
    assert "data[k].lines === null" in js


def test_page_renders_sources_through_one_door():
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    door = js[js.index("function showSources(data) {"):]
    door = door[:door.index("}") + 1]
    outside = js.replace(door, "")
    bare = [line.strip() for line in outside.splitlines()
            if "renderSources(" in line and "function renderSources" not in line]
    assert bare == [], "мимо общей двери: %s" % bare


def test_page_puts_the_count_first():
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    assert 'setText($(`#${prefix}Title`), info.count ? linesLabel(info) : info.title)' in js
    assert "filesLabel(info)}` + \"\"" not in js
    assert "${filesLabel(info)} · ${info.detail}" in js


def test_page_calls_a_pasted_list_a_source_not_a_file():
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    assert 'plural(info.count, "источник", "источника", "источников")' in js
