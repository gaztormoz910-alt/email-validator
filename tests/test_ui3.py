# -*- coding: utf-8 -*-
import io
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def code(rel):
    import ast

    tree = ast.parse(read(rel))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            node.value.value = ""
    return ast.unparse(tree)


def test_gap_hidden_row_takes_no_space():
    css = read("ui/web/style.css")
    folded = css[css.index(".is-folded"):]
    folded = folded[:folded.index("}") + 1]
    assert "display: none" in folded, folded

    html = read("ui/web/index.html")
    assert 'id="resumeRow"' not in html, (
        "строка продолжения вернулась в окно — её снова можно забыть включить")
    app = read("ui/web/app.js")
    assert "askResume" not in app, "окно снова опрашивает убранную строку"


def test_gap_is_gone_still_exists_for_its_own_case():
    css = read("ui/web/style.css")
    assert "visibility: hidden !important" in css
    assert read("ui/web/app.js").count("is-gone") >= 1


def test_accuracy_default_on_the_page():
    html = read("ui/web/index.html")
    segment = html[html.index('data-country="coverage"') - 120:]
    segment = segment[:segment.index("</div>")]
    assert 'is-active" data-country="accuracy"' in segment, segment
    assert 'is-active" data-country="coverage"' not in segment


def test_accuracy_default_in_the_state():
    app = read("ui/web/app.js")
    assert re.search(r'country:\s*"accuracy"', app), "умолчание состояния не изменено"
    assert not re.search(r'country:\s*"coverage"', app)


def test_accuracy_default_reaches_the_engine():
    app = read("ui/web/app.js")
    assert "country: ui.country" in app, "режим не кладётся в запрос запуска"
    assert '"country"' in read("ui/webapp.py")


def test_narrow_scroll_area_can_actually_scroll():
    css = read("ui/web/style.css")
    block = css[css.index("@media (max-width: 900px)"):]
    block = block[:block.index("@media (max-width: 1100px)")]
    assert "overflow-y: auto" in block, "узкой раскладке не дали прокрутку"
    assert ".work { min-height:" in block, (
        "без своей высоты таблица и лог схлопнутся в полоску")


def test_narrow_scroll_also_for_short_window():
    css = read("ui/web/style.css")
    block = css[css.index("@media (max-height: 620px)"):]
    block = block[:block.index("}", block.index(".work"))]
    assert "overflow-y: auto" in block


def test_narrow_scroll_control_root_still_locked():
    css = read("ui/web/style.css")
    root = css[css.index("html, body {"):]
    root = root[:root.index("}")]
    assert "overflow: hidden" in root
    assert "height: 100vh" in root


def test_recount_notices_a_changed_file(tmp_path):
    from ui.webapp import ValidatorApi

    path = str(tmp_path / "base.txt")
    io.open(path, "w", encoding="utf-8").write("a@x.com\nb@x.com\nc@x.com\n")

    api = ValidatorApi()
    api._sources["emails"] = [{"type": "file", "path": path, "title": "base.txt"}]
    api._recount("emails")
    for _ in range(50):
        if api.sources()["emails"]["lines"] == 3:
            break
        time.sleep(0.05)
    assert api.sources()["emails"]["lines"] == 3

    io.open(path, "w", encoding="utf-8").write("a@x.com\n")
    os.utime(path, (time.time() + 2, time.time() + 2))

    api.sources()
    for _ in range(50):
        if api.sources()["emails"]["lines"] == 1:
            break
        time.sleep(0.05)
    assert api.sources()["emails"]["lines"] == 1, "счётчик остался прежним"


def test_recount_does_not_fire_when_nothing_changed(tmp_path):
    from ui.webapp import ValidatorApi

    path = str(tmp_path / "base.txt")
    io.open(path, "w", encoding="utf-8").write("a@x.com\n" * 10)

    api = ValidatorApi()
    api._sources["emails"] = [{"type": "file", "path": path, "title": "base.txt"}]
    api._recount("emails")
    time.sleep(0.3)

    calls = []
    original = api._recount
    api._recount = lambda kind: calls.append(kind) or original(kind)
    for _ in range(5):
        api.sources()
    assert calls == [], "пересчёт затеян на пустом месте: %s" % calls


def test_proxy_progress_shows_that_work_is_going():
    css = read("ui/web/style.css")
    assert ".progress__track.is-running" in css
    assert "@keyframes progress-sweep" in css

    app = read("ui/web/app.js")
    assert '$("#progressTrack").classList.add("is-running")' in app
    assert '$("#progressTrack").classList.remove("is-running")' in app

    html = read("ui/web/index.html")
    assert 'id="progressTrack"' in html


def test_proxy_progress_does_not_fake_a_percent():
    app = read("ui/web/app.js")
    running = app[app.index("if (px.running)"):]
    running = running[:running.index("} else {")]
    assert 'setText($("#progressPct"), "")' in running, (
        "в фазе прокси показывается процент, которого не существует")


def test_wording_rejected_list_does_not_threaten_the_base():
    filters = code("core/filters.py")
    assert "убить всю базу" not in filters, "прежняя формулировка вернулась"
    assert "не пострадала" in filters
    assert "[DEAD] Список" not in filters, (
        "отклонение списка — не авария, красным его метить не за что")


def test_wording_update_skipped_is_not_an_error():
    parser = code("core/github_parser.py")
    assert "источник испорчен" not in parser
    assert "обновление не взято" in parser
    assert "база не тронута" in parser


def test_wording_control_real_failures_stay_loud():
    pipeline = read("core/pipeline.py")
    assert '"[DEAD] Все прокси выбыли из ротации' in pipeline
    assert "ПОТЕРЯНО АДРЕСОВ" in pipeline
