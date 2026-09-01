# -*- coding: utf-8 -*-
"""Сбор адресов из открытых API вместо выдачи поисковиков.

Поисковик — враждебная среда: капча, лимиты, разная выдача на разных прокси и
разметка, которая меняется без предупреждения. GitHub, npm, PyPI и Hacker News
отдают те же данные структурированным JSON и без капчи.

Сеть здесь не трогается: ответ источника подменяется. Живой прогон был
разовым доказательством (npm — 33 адреса, GitHub — 46, PyPI — 3), а набор
обязан идти на любой машине и без интернета.
"""
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# В пробных ответах домен НЕ example.org: он отсеивается самим сборщиком как
# заведомо непишущий, и данные проб уходили бы в ноль по правильной причине,
# делая проверку холостой.
@pytest.fixture
def answers(monkeypatch):
    """Подменяет ответ источника. Возвращает копилку запрошенных ссылок."""
    from core import collectors

    calls = []
    plan = {}

    def fake_fetch(url, timeout=collectors.TIMEOUT, proxies=None):
        calls.append(url)
        for fragment, payload in plan.items():
            if fragment in url:
                if isinstance(payload, str):
                    return None, payload          # это ошибка
                return payload, ""
        return {}, ""

    monkeypatch.setattr(collectors, "_fetch_json", fake_fetch)
    return {"calls": calls, "plan": plan}


# ═══════════════════════════════ мусор отсеивается

def test_github_placeholder_addresses_are_dropped():
    """GitHub подставляет заглушку вместо настоящего адреса.

    `12345+username@users.noreply.github.com` — технически адрес, но письмо
    туда не дойдёт никуда. Такой контакт в базе хуже отсутствующего: он
    тратит проверку и портит статистику.
    """
    from core.collectors import looks_writable

    assert looks_writable("12345+octocat@users.noreply.github.com") is False
    assert looks_writable("action@github.com") is False
    assert looks_writable("no-reply@shop.com") is False
    assert looks_writable("noreply@shop.com") is False
    assert looks_writable("someone@example.com") is False


def test_real_addresses_survive_the_filter():
    """Обратная сторона: живые адреса не должны попадать под отсев."""
    from core.collectors import looks_writable

    for good in ("ivan@gmail.com", "me@kennethreitz.org",
                 "o'brien@company.co.uk", "nate.prewitt@gmail.com"):
        assert looks_writable(good) is True, good


# ═══════════════════════════════ разбор текста источника

def test_angle_brackets_around_an_address_are_not_a_tag():
    """`Kenneth Reitz <me@kennethreitz.org>` — это форма PyPI, а не разметка.

    Первая версия чистильщика резала всё в угловых скобках и съедала ровно
    ту форму, в которой PyPI отдаёт почту автора: источник возвращал ноль
    адресов при непустом ответе.
    """
    from core.collectors import _harvest

    assert _harvest("Kenneth Reitz <me@kennethreitz.org>") == ["me@kennethreitz.org"]


def test_real_tags_are_still_stripped():
    from core.collectors import _harvest

    assert _harvest("<p>bob@mail.ru</p>") == ["bob@mail.ru"]
    assert _harvest("<i>anna@test.com</i>") == ["anna@test.com"]


def test_html_entities_are_unescaped():
    """Hacker News отдаёт комментарии разметкой, а не текстом."""
    from core.collectors import _harvest

    assert _harvest("anna&#64;test.com") == ["anna@test.com"]


def test_harvest_ignores_junk_in_the_same_text():
    from core.collectors import _harvest

    found = _harvest("пишите ivan@gmail.com, но не no-reply@shop.com")
    assert found == ["ivan@gmail.com"]


# ═══════════════════════════════ источники

def test_npm_takes_authors_and_maintainers(answers):
    from core.collectors import collect

    answers["plan"]["registry.npmjs.org"] = {"objects": [
        {"package": {"author": {"email": "author@devmail.org"},
                     "maintainers": [{"email": "keeper@devmail.org"},
                                     {"email": "12345+bot@users.noreply.github.com"}]}},
    ]}
    found, errors = collect("npm", query="mailer")
    assert found == ["author@devmail.org", "keeper@devmail.org"]
    assert errors == []


def test_pypi_takes_both_email_fields(answers):
    from core.collectors import collect

    answers["plan"]["pypi.org"] = {"info": {
        "author_email": "Kenneth Reitz <me@kennethreitz.org>",
        "maintainer_email": "Nate <nate@devmail.org>",
    }}
    found, _ = collect("pypi", packages=["requests"])
    assert found == ["me@kennethreitz.org", "nate@devmail.org"]


def test_github_reads_commit_authors(answers):
    from core.collectors import collect

    answers["plan"]["search/repositories"] = {"items": [{"full_name": "who/what"}]}
    answers["plan"]["repos/who"] = [
        {"commit": {"author": {"email": "dev@devmail.org"}}},
        {"commit": {"author": {"email": "12345+bot@users.noreply.github.com"}}},
    ]
    found, errors = collect("github", query="language:python")
    assert found == ["dev@devmail.org"]
    assert errors == []


def test_hackernews_reads_comment_text(answers):
    from core.collectors import collect

    answers["plan"]["hn.algolia.com"] = {"hits": [
        {"comment_text": "<p>пишите на hire&#64;devmail.org</p>"},
        {"story_text": "контакт: boss@devmail.org"},
    ]}
    found, _ = collect("hackernews", query="who is hiring")
    assert set(found) == {"hire@devmail.org", "boss@devmail.org"}


# ═══════════════════════════════ ошибки называются, а не глотаются

def test_rate_limit_is_reported_not_hidden(answers):
    """Исчерпанный лимит и пустой ответ выглядят одинаково, если молчать."""
    from core.collectors import collect

    answers["plan"]["registry.npmjs.org"] = "лимит источника исчерпан (HTTP 403)."
    found, errors = collect("npm", query="mailer")
    assert found == []
    assert errors and "403" in errors[0]


def test_unknown_source_is_refused_by_name():
    from core.collectors import collect

    found, errors = collect("одноклассники", query="x")
    assert found == []
    assert "нет такого источника" in errors[0]


def test_bad_parameters_do_not_crash():
    from core.collectors import collect

    found, errors = collect("pypi", query="это не список пакетов")
    assert found == []
    assert errors


# ═══════════════════════════════ дедуп

def test_duplicates_are_collapsed_by_the_canonical_key(answers):
    """Один человек, попавший в два источника, не должен приехать дважды.

    Ключ тот же, что у дедупа базы и у списка отписок: у Gmail точки не
    значат ничего, и `john.doe@` с `johndoe@` — один ящик.
    """
    from core.collectors import collect

    answers["plan"]["registry.npmjs.org"] = {"objects": [
        {"package": {"author": {"email": "john.doe@gmail.com"},
                     "maintainers": [{"email": "johndoe@gmail.com"},
                                     {"email": "other@devmail.org"}]}},
    ]}
    found, _ = collect("npm", query="mailer")
    assert found == ["john.doe@gmail.com", "other@devmail.org"]


# ═══════════════════════════════ окно и конвейер знают о них

def test_window_offers_the_api_sources():
    from ui.webapp import ValidatorApi

    for name in ("API: GitHub", "API: npm", "API: PyPI", "API: Hacker News"):
        assert name in ValidatorApi.PARSER_ENGINES, name


def test_parser_takes_the_api_path():
    """Конвейер сбора узнаёт эти движки и идёт мимо дорков и капчи."""
    import inspect

    from core import parser_pipeline

    source = inspect.getsource(parser_pipeline)
    assert "if self.engine_name.startswith(API_ENGINE_PREFIX):" in source
    assert "self._run_collectors()" in source


def test_parser_deduplicates_api_results_too():
    """Тот же журнал уникальности, что и у поисковиков."""
    import inspect

    from core import parser_pipeline

    source = inspect.getsource(parser_pipeline.ParserPipeline._run_collectors)
    assert "self._seen.add_if_new(normalize_for_dedup(e))" in source


def test_api_endpoint_exposes_collectors():
    """Через REST это тоже доступно — без окна."""
    from api.server import handle

    code, body = handle("/api/collect", {"source": "неизвестный"})
    assert code == 400
    assert "github" in body["error"]


# ═══════════════════════════════ источники, добавленные позже

def test_reddit_collects_from_post_texts(answers):
    from core.collectors import collect

    answers["plan"]["reddit.com/search.json"] = {
        "data": {"children": [
            {"data": {"selftext": "пишите на hire@devmail.org",
                      "title": "ищем разработчика", "author": "someone"}},
            {"data": {"selftext": "без почты вовсе"}},
            {"data": "не словарь"},
        ]}}
    found, errors = collect("reddit", query="hiring")
    assert found == ["hire@devmail.org"]
    assert errors == []


def test_stackexchange_collects_from_question_bodies(answers):
    from core.collectors import collect

    answers["plan"]["api.stackexchange.com"] = {
        "items": [
            {"body": "в логе стоит smtp@devmail.org", "title": "ошибка SMTP"},
            {"body": "тут почты нет"},
            {"not_a_dict": True},
        ]}
    found, errors = collect("stackexchange", query="smtp")
    assert found == ["smtp@devmail.org"]
    assert errors == []


def test_gitlab_collects_from_project_descriptions(answers):
    from core.collectors import collect

    answers["plan"]["gitlab.com/api/v4/projects"] = [
        {"description": "связаться: maintainer@devmail.org", "name": "проект"},
        {"description": "описание без почты"},
        "не словарь",
    ]
    found, errors = collect("gitlab", query="mailer")
    assert found == ["maintainer@devmail.org"]
    assert errors == []


def test_new_sources_report_their_errors_by_name(answers):
    """Отказ источника называется его именем, а не общим «не вышло»."""
    from core.collectors import collect

    for source, fragment, label in (("reddit", "reddit.com", "Reddit"),
                                    ("stackexchange", "api.stackexchange.com",
                                     "Stack Exchange"),
                                    ("gitlab", "gitlab.com", "GitLab")):
        answers["plan"].clear()
        answers["plan"][fragment] = "HTTP 429: лимит"
        found, errors = collect(source, query="x")
        assert found == []
        assert errors and errors[0].startswith(label), errors


def test_all_sources_are_offered_by_the_window():
    """Список движков окна собирается из конвейера, а не переписан руками.

    Раньше имена были продублированы, и добавленный источник в окне не
    появлялся. Список в двух местах расходится всегда — вопрос лишь когда.
    """
    from core.parser_pipeline import API_ENGINES
    from ui.webapp import ValidatorApi

    missing = [name for name in API_ENGINES
               if name not in ValidatorApi.PARSER_ENGINES]
    assert missing == [], missing


def test_source_count_grew_past_the_four_it_started_with():
    """Их стало больше — это и был смысл правки.

    Проверяется число, а не имена: добавят ещё один — проверка не помешает,
    уберут половину — упадёт.
    """
    from core.collectors import SOURCES

    assert len(SOURCES) >= 7, sorted(SOURCES)
    for expected in ("github", "npm", "pypi", "hackernews",
                     "reddit", "stackexchange", "gitlab"):
        assert expected in SOURCES, expected
