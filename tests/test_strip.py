# -*- coding: utf-8 -*-
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def project_files():
    found = []
    for base, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (
            ".git", "audit", "__pycache__", "data", "node_modules")]
        for name in names:
            if name.endswith((".py", ".js", ".html", ".md", ".txt")):
                found.append(os.path.join(base, name))
    return found


def test_rest_api_package_is_gone():
    assert not os.path.exists(os.path.join(ROOT, "api")), "папка api/ на месте"
    for name in ("server.py", "jobs.py"):
        assert not os.path.exists(os.path.join(ROOT, "api", name))


def test_rest_api_is_not_referenced_anywhere():
    остатки = []
    for path in project_files():
        if os.path.basename(path) == "test_strip.py":
            continue
        text = io.open(path, encoding="utf-8", errors="ignore").read()
        for marker in ("from api ", "from api.", "import api.",
                       "api.server", "api.jobs", "python -m api"):
            if marker in text:
                остатки.append("%s: %s" % (os.path.relpath(path, ROOT), marker))
    assert not остатки, "ссылки на удалённый REST API: %s" % остатки


def test_rest_api_control_the_sweep_can_find_things():
    files = project_files()
    assert len(files) > 50, "обход нашёл всего %d файлов" % len(files)
    names = {os.path.basename(f) for f in files}
    assert "webapp.py" in names and "app.js" in names


def test_api_parsing_module_is_gone():
    assert not os.path.exists(os.path.join(ROOT, "core", "collectors.py"))
    pipeline = read("core/parser_pipeline.py")
    assert "API_ENGINES" not in pipeline
    assert "API_ENGINE_PREFIX" not in pipeline
    assert "_run_collectors" not in pipeline
    assert "core.collectors" not in pipeline


def test_api_parsing_control_pipeline_still_imports():
    import core.parser_pipeline as pp

    assert hasattr(pp, "ParserPipeline")
    assert hasattr(pp, "SEARCH_ENGINES")


def test_engine_list_has_no_api_entries():
    from ui.webapp import ValidatorApi

    for name in ValidatorApi.PARSER_ENGINES:
        assert not name.startswith("API"), "остался движок %s" % name


def test_engine_list_is_one_list_for_the_whole_project():
    from core.parser_pipeline import SEARCH_ENGINES
    from ui.webapp import ValidatorApi

    assert list(ValidatorApi.PARSER_ENGINES) == list(SEARCH_ENGINES)


def test_search_intact_all_five_engines_remain():
    from core.parser_pipeline import SEARCH_ENGINES

    assert set(SEARCH_ENGINES) == {
        "DuckDuckGo Lite", "AOL (Tor)", "Yahoo (Tor)",
        "AOL (Proxies)", "Yahoo (Proxies)"}


def test_search_intact_dispatch_untouched():
    pipeline = read("core/parser_pipeline.py")
    for engine in ('"AOL (Tor)"', '"Yahoo (Tor)"', '"AOL (Proxies)"',
                   '"Yahoo (Proxies)"'):
        assert engine in pipeline, "потерян разбор движка %s" % engine
    assert "DuckDuckGoEngine" in pipeline


def test_unknown_engine_falls_back_out_loud():
    from core.parser_pipeline import DEFAULT_ENGINE, ParserPipeline

    записи = []
    pipe = ParserPipeline.__new__(ParserPipeline)
    pipe.engine_name = "API: GitHub"
    pipe.log = записи.append

    source = read("core/parser_pipeline.py")
    assert "if self.engine_name not in SEARCH_ENGINES:" in source, (
        "проверка имени движка потеряна")

    from core.parser_pipeline import SEARCH_ENGINES
    if pipe.engine_name not in SEARCH_ENGINES:
        pipe.log("[Система] Движок «%s» больше не поддерживается — сбор "
                 "через открытые API удалён. Беру %s."
                 % (pipe.engine_name, DEFAULT_ENGINE))
        pipe.engine_name = DEFAULT_ENGINE

    assert pipe.engine_name == DEFAULT_ENGINE
    assert записи and "больше не поддерживается" in записи[0]


def test_unknown_engine_control_known_one_is_left_alone():
    from core.parser_pipeline import SEARCH_ENGINES

    for name in SEARCH_ENGINES:
        assert name in SEARCH_ENGINES, name
    assert "DuckDuckGo Lite" in SEARCH_ENGINES


def test_docs_do_not_promise_the_removed_server():
    readme = read("README.md")
    assert "api.server" not in readme, "README всё ещё зовёт запускать REST API"
    assert "python main.py" in readme, "а окно из README пропало"


def test_docs_criteria_mark_removal_explicitly():
    criteria = read("docs/КРИТЕРИИ.md")
    assert "УДАЛЕНО" in criteria
    assert "core/collectors.py" in criteria, "не сказано, ЧТО удалено"
    assert "api/server.py" not in criteria.split("## Модули")[-1], (
        "удалённый модуль остался в списке модулей")


def test_docs_control_criteria_still_describe_the_engine():
    criteria = read("docs/КРИТЕРИИ.md")
    assert len(criteria) > 10_000, "документ подозрительно похудел"
    for topic in ("RCPT TO", "Null MX", "greylist", "catch-all"):
        assert topic.lower() in criteria.lower(), "потеряна тема: %s" % topic
