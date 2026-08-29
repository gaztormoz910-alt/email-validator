# -*- coding: utf-8 -*-
"""Проверки интерфейса на веб-стеке.

Каждый тест здесь привязан к дефекту, который владелец показал на скриншотах:
обрезанная панель слева, обрезанная кнопка «Сохранить», слипшиеся заголовки
таблицы, чёрная пустота вместо пустого состояния. Проверяется не «красиво ли»,
а ровно те свойства разметки и оформления, из-за отсутствия которых экран
ломался.

Браузер тут не поднимается: правила читаются из файлов, а мост — настоящий,
на живом сокете.
"""
import io
import json
import os
import re
import sys

import urllib.error
import urllib.request

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "ui", "web")


def read(name):
    with io.open(os.path.join(WEB, name), encoding="utf-8") as handle:
        return handle.read()


def rule(css, selector):
    """Тело правила по точному селектору (первое вхождение)."""
    pattern = re.compile(r"(^|\})\s*" + re.escape(selector) + r"\s*\{([^}]*)\}",
                         re.MULTILINE)
    found = pattern.search(css)
    return found.group(2) if found else None


# ──────────────────────────────────────────────────────────── G1: скролл

def test_sidebar_scroll_rule_present():
    """Дефект №1: панель слева обрезалась, до нижних настроек было не добраться."""
    css = read("style.css")
    body = rule(css, ".side__scroll")
    assert body is not None, "нет правила .side__scroll — прокручивать нечего"
    assert "overflow-y: auto" in body, body
    # Без height:100% блок растёт вместе с содержимым и вылезает за экран,
    # а не заводит собственную полосу прокрутки.
    assert "height: 100%" in body, body


def test_sidebar_column_may_shrink_for_scroll():
    """min-height:0 — то, без чего grid не даёт колонке сжаться и скролл мёртв."""
    css = read("style.css")
    body = rule(css, ".side")
    assert body is not None
    assert "min-height: 0" in body, body
    assert "overflow: hidden" in body, body


def test_sidebar_markup_uses_scroll_container():
    assert 'class="side__scroll"' in read("index.html")


# ─────────────────────────────────────────────────────────── G2: панель

def test_toolbar_wraps_instead_of_clipping():
    """Дефект №2: «Сохранить отмеченные» обрезалось до «Cохранить отмеченны»."""
    css = read("style.css")
    body = rule(css, ".pane__bar--wrap")
    assert body is not None, "нет правила переноса — панель снова обрежется"
    assert "flex-wrap: wrap" in body, body

    html = read("index.html")
    assert 'class="pane__bar pane__bar--wrap"' in html, \
        "панель над таблицей не помечена как переносимая"


def test_toolbar_groups_also_wrap():
    """Переносится не только панель целиком, но и группы внутри неё."""
    css = read("style.css")
    for selector in (".pane__actions", ".chips"):
        body = rule(css, selector)
        assert body is not None, selector
        assert "flex-wrap: wrap" in body, (selector, body)


# ─────────────────────────────────────────────────────────── G3: колонки

COLUMNS = ["c-email", "c-verdict", "c-score", "c-prov", "c-reason",
           "c-name", "c-gender", "c-country", "c-when"]


def test_columns_have_fixed_layout():
    """Дефект №3: в шапке читалось «КачествоПочтовик» — заголовки слиплись."""
    css = read("style.css")
    body = rule(css, ".grid")
    assert body is not None
    assert "table-layout: fixed" in body, body


def test_columns_widths_sum_to_exactly_100():
    """При table-layout:fixed сумма не 100% растягивает или рвёт таблицу."""
    css = read("style.css")
    widths = {}
    for name in COLUMNS:
        body = rule(css, ".grid .%s" % name)
        assert body is not None, "нет ширины для колонки %s" % name
        found = re.search(r"width:\s*([\d.]+)%", body)
        assert found, (name, body)
        widths[name] = float(found.group(1))
    assert sum(widths.values()) == pytest.approx(100.0), widths


def test_columns_every_header_declares_its_class():
    """Каждый заголовок помечен своим классом — иначе ширина к нему не приедет."""
    html = read("index.html")
    header = re.search(r"<thead>(.*?)</thead>", html, re.S)
    assert header, "в таблице нет шапки"
    declared = re.findall(r'class="(c-[\w-]+)"', header.group(1))
    assert declared == COLUMNS, declared


def test_columns_cells_clip_with_ellipsis():
    """Длинное значение должно обрезаться многоточием внутри своей колонки."""
    css = read("style.css")
    body = rule(css, ".grid th, .grid td")
    assert body is not None
    assert "text-overflow: ellipsis" in body, body
    assert "overflow: hidden" in body, body
    assert "white-space: nowrap" in body, body


def test_columns_long_values_keep_full_text_in_title():
    """Обрезанное значение бесполезно, если полного нет хотя бы в подсказке."""
    js = read("app.js")
    # Вердикт, дата и пол сокращаются, полный текст уходит в title.
    assert "VERDICT_TEXT" in js and "VERDICT_FULL" in js
    assert "function shortDate" in js
    assert "function shortGender" in js
    assert "title" in js


# ────────────────────────────────────────────────── G4: пустые состояния

def test_empty_state_is_centred():
    """Дефект №4: вместо пустоты с текстом в углу — центрированный блок."""
    css = read("style.css")
    body = rule(css, ".empty")
    assert body is not None
    assert "align-items: center" in body, body
    assert "justify-content: center" in body, body
    assert "text-align: center" in body, body


def test_empty_state_explains_what_comes_next():
    """У каждой вкладки с данными есть заголовок и пояснение, что будет дальше."""
    html = read("index.html")
    for pane in ("results", "proxy"):
        chunk = re.search(
            r'<div class="tabpane[^"]*" data-pane="%s">(.*?)(?=<div class="tabpane|</main>|</section>)'
            % pane, html, re.S)
        assert chunk, pane
        block = chunk.group(1)
        assert 'class="empty"' in block, "у вкладки %s нет пустого состояния" % pane
        found = re.search(r'class="empty"[^>]*>(.*?)</div>', block, re.S)
        assert found, pane
        assert "<b>" in found.group(1), "в пустом состоянии %s нет заголовка" % pane
        assert "<span>" in found.group(1), "в пустом состоянии %s нет пояснения" % pane


def test_empty_pane_exists_for_every_tab():
    """Каждой кнопке вкладки отвечает своя панель — иначе клик ведёт в пустоту."""
    html = read("index.html")
    tabs = re.findall(r'class="tab[^"]*" data-tab="(\w+)"', html)
    panes = re.findall(r'class="tabpane[^"]*" data-pane="(\w+)"', html)
    assert tabs and tabs == panes, (tabs, panes)


# ──────────────────────────────────────────────────────────── G5: мост

@pytest.fixture(scope="module")
def bridge():
    from ui.webapp import ValidatorApi, start_api_server

    api = ValidatorApi()
    server, port, token = start_api_server(api)   # поток он поднимает сам
    yield api, port, token
    server.shutdown()


def http(port, path, token=None, payload=None):
    url = "http://127.0.0.1:%d%s" % (port, path)
    data = json.dumps(payload or {}).encode() if payload is not None else None
    request = urllib.request.Request(url, data=data)
    if token:
        request.add_header("X-Token", token)
    if data is not None:
        request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=10) as response:
        return response.getcode(), response.read()


def test_bridge_serves_the_page_with_a_token(bridge):
    api, port, token = bridge
    code, body = http(port, "/", token=token)
    assert code == 200
    text = body.decode("utf-8")
    assert "<title>" in text
    # Подстановка должна была случиться: заглушка в отданной странице
    # означала бы, что запросы к API уходят без токена.
    assert "__TOKEN__" not in text
    assert token in text


def test_bridge_rejects_a_request_without_a_token(bridge):
    api, port, token = bridge
    with pytest.raises(urllib.error.HTTPError) as caught:
        http(port, "/")
    assert caught.value.code == 403


def test_bridge_rejects_api_call_without_a_token(bridge):
    api, port, token = bridge
    with pytest.raises(urllib.error.HTTPError) as caught:
        http(port, "/api/state", payload={})
    assert caught.value.code == 403


def test_bridge_serves_styles_and_script_without_a_token(bridge):
    """Браузер не добавляет наши заголовки к <link> и <script>.

    Эти два файла статичны и не содержат ни одного пользовательского байта,
    поэтому открыты; всё остальное по-прежнему за токеном.
    """
    api, port, token = bridge
    for path in ("/style.css", "/app.js"):
        code, body = http(port, path)
        assert code == 200 and body, path


def test_bridge_refuses_to_walk_out_of_the_web_folder(bridge):
    api, port, token = bridge
    for path in ("/../webapp.py", "/../../main.py"):
        try:
            code, _ = http(port, path, token=token)
        except urllib.error.HTTPError as error:
            assert error.code in (400, 403, 404), path
        else:
            assert code != 200, path


def test_bridge_hides_private_methods(bridge):
    api, port, token = bridge
    with pytest.raises(urllib.error.HTTPError) as caught:
        http(port, "/api/_on_complete", token=token, payload={})
    assert caught.value.code == 404


# ───────────────────────────────────────────────────────────── G6: данные

def make_api():
    from ui.webapp import ValidatorApi
    return ValidatorApi()


def test_data_counters_come_from_the_same_store():
    from ui.result_store import ResultStore

    api = make_api()
    assert isinstance(api.store, ResultStore)

    api._on_result("live@example.com", "Valid", "250 OK", "mx",
                   {"engagement_score": 90, "name": "Ivan Petrov"})
    api._on_result("dead@example.com", "Invalid/Bounce", "550 no such user", "mx",
                   {"engagement_score": 0})
    api._on_result("maybe@example.com", "Risky", "греylisting", "mx",
                   {"engagement_score": 50})
    api._on_progress(3, 10)

    state = api.state()
    assert state["counts"]["valid"] == 1
    assert state["counts"]["invalid"] == 1
    assert state["counts"]["unknown"] == 1     # Risky живёт здесь
    assert state["counts"]["total"] == 3
    assert state["counts"]["names"] == 1
    assert state["progress"] == {"current": 3, "total": 10, "pct": 30}


def test_data_rows_carry_every_column_the_table_shows():
    api = make_api()
    api._on_result("live@example.com", "Valid", "250 OK", "mx.example.com",
                   {"engagement_score": 88, "provider_name": "Gmail",
                    "name": "Ivan Petrov", "gender": "Мужской",
                    "country": "США", "validated_at": "2026-08-29 22:40"})

    page = api.page({"groups": ["valid"], "page": 1})
    assert page["total"] == 1
    row = page["rows"][0]
    for field in ("email", "status", "group", "reason", "score", "provider",
                  "name", "gender", "country", "when"):
        assert field in row, field
    assert row["email"] == "live@example.com"
    assert row["group"] == "valid"
    assert row["score"] == 88
    assert row["when"] == "2026-08-29 22:40"


def test_data_score_filter_and_paging_work():
    api = make_api()
    for i in range(5):
        api._on_result("u%d@example.com" % i, "Valid", "250 OK", "mx",
                       {"engagement_score": i * 20})

    assert api.page({"groups": ["valid"], "minScore": 0})["total"] == 5
    assert api.page({"groups": ["valid"], "minScore": 50})["total"] == 2  # 60 и 80
    assert api.page({"groups": ["valid"], "minScore": 200})["total"] == 0
    # Номер страницы за пределами набора возвращается к последней, а не к пустоте.
    far = api.page({"groups": ["valid"], "page": 99})
    assert far["page"] == far["pages"]


def test_data_log_survives_a_page_reload():
    """Перезагрузка страницы посреди прогона не должна опустошать терминал."""
    api = make_api()
    api._on_log("[INFO] поехали", "info")
    api._on_log("[VALID] a@b.c -> 250 OK", "valid")

    first = api.state()["log"]
    assert len(first) == 2
    # Страница «перезагрузилась»: очередь уже отдана, но хвост на месте.
    assert api.state()["log"] == []
    tail = api.log_tail()["log"]
    assert [line["text"] for line in tail] == ["[INFO] поехали", "[VALID] a@b.c -> 250 OK"]
    # И тот же текст не приезжает вторым экземпляром ближайшим опросом.
    assert api.state()["log"] == []


def test_data_log_tail_is_bounded():
    """Хвост не растёт бесконечно: на большой базе строк сотни тысяч."""
    api = make_api()
    for i in range(api._history_cap + 500):
        api._on_log("строка %d" % i, "info")
    tail = api.log_tail()["log"]
    assert len(tail) == api._history_cap
    assert tail[-1]["text"] == "строка %d" % (api._history_cap + 499)


# ────────────────────────────────────────────────── G13: сбор адресов

def test_parser_endpoints_exist():
    """Сбор адресов должен уметь то же, что и в прежнем окне."""
    api = make_api()
    for name in ("parser_start", "parser_pause", "parser_stop", "parser_state",
                 "parser_page", "parser_copy", "parser_export", "parser_log_tail"):
        assert callable(getattr(api, name, None)), name


def test_parser_sources_are_kept_apart_from_the_validator():
    """Дорки не должны попадать в прокси, а прокси сбора — в прокси проверки."""
    api = make_api()
    api.paste({"kind": "emails", "text": "a@b.c"})
    api.paste({"kind": "proxies", "text": "1.1.1.1:8080"})
    api.paste({"kind": "dorks", "text": "site:example.com"})
    api.paste({"kind": "pproxy", "text": "2.2.2.2:1080"})

    assert len(api.email_sources) == 1
    assert len(api.proxy_sources) == 1
    assert len(api._sources["dorks"]) == 1
    assert len(api._sources["pproxy"]) == 1

    # Раньше всё, что не «emails», сваливалось в прокси проверки.
    api.clear({"kind": "dorks"})
    assert len(api._sources["dorks"]) == 0
    assert len(api.proxy_sources) == 1


def test_parser_unknown_source_kind_is_refused():
    api = make_api()
    with pytest.raises(ValueError):
        api.paste({"kind": "чепуха", "text": "x"})


def test_parser_needs_dorks_but_not_proxies():
    """У сбора прокси необязательны: DuckDuckGo Lite ходит напрямую."""
    api = make_api()
    assert api.sources()["parserReady"] is False
    assert api.parser_start({})["ok"] is False

    api.paste({"kind": "dorks", "text": "site:example.com"})
    assert api.sources()["parserReady"] is True


def test_parser_refuses_an_unknown_engine():
    api = make_api()
    api.paste({"kind": "dorks", "text": "site:example.com"})
    result = api.parser_start({"engine": "Google"})
    assert result["ok"] is False and "поисковик" in result["error"].lower()


def test_parser_shows_every_engine_the_old_window_had():
    api = make_api()
    engines = api.parser_state()["engines"]
    assert engines == ["DuckDuckGo Lite", "AOL (Tor)", "Yahoo (Tor)",
                       "AOL (Proxies)", "Yahoo (Proxies)"]


def test_parser_reports_the_same_address_once():
    """Один адрес попадается разным запросам — в списке он должен быть один."""
    api = make_api()
    api._parser_result_cb("A@Example.com", "dork1")
    api._parser_result_cb("a@example.com", "dork2")
    api._parser_result_cb("b@example.com", "dork1")

    page = api.parser_page()
    assert page["total"] == 2
    assert [row["email"] for row in page["rows"]] == ["A@Example.com", "b@example.com"]
    assert api.parser_copy()["text"] == "A@Example.com\nb@example.com"


def test_parser_counters_and_progress_reach_the_page():
    api = make_api()
    api._parser_stats_cb(12, 7, 143, 5210, 60)
    api._parser_progress_cb(7, 12, 58, "Парсинг")
    api._parser_result_cb("x@y.z", "dork")

    state = api.parser_state()
    assert state["stats"]["dorksTotal"] == 12
    assert state["stats"]["dorksDone"] == 7
    assert state["stats"]["pages"] == 143
    assert state["stats"]["snippets"] == 5210
    assert state["stats"]["found"] == 1          # считается по списку, не по движку
    assert state["progress"] == {"current": 7, "total": 12, "pct": 58, "label": "Парсинг"}


def test_parser_log_also_survives_a_reload():
    api = make_api()
    api._parser_log("[Система] Инициализация парсера.", "info")
    assert len(api.parser_state()["log"]) == 1
    assert api.parser_state()["log"] == []
    assert len(api.parser_log_tail()["log"]) == 1
    assert api.parser_state()["log"] == []


def test_parser_has_its_own_screen_in_the_markup():
    html = read("index.html")
    assert 'id="viewParser"' in html
    assert 'id="viewValidator"' in html
    tabs = re.findall(r'data-ptab="(\w+)"', html)
    panes = re.findall(r'data-ppane="(\w+)"', html)
    assert tabs and tabs == panes, (tabs, panes)


def test_parser_screen_has_an_empty_state():
    html = read("index.html")
    found = re.search(r'data-ppane="found">(.*?)</div>\s*</div>\s*</div>', html, re.S)
    assert found, "не нашлась панель найденных адресов"
    assert 'id="pGridEmpty"' in html


# ──────────────────────────────────── G14: ни одной кнопки-обманки

def test_wiring_no_button_sends_the_user_to_another_window():
    """Кнопка, которая советует перезапустить программу, — не кнопка."""
    js = read("app.js")
    for phrase in ("--classic", "прежнем окне", "прежнее окно"):
        assert phrase not in js, phrase


def test_wiring_every_api_call_exists_in_python():
    """Опечатка в имени метода даёт 404 и молчащую кнопку."""
    from ui.webapp import ValidatorApi

    js = read("app.js")
    called = sorted(set(re.findall(r'\bapi\(\s*"(\w+)"', js)))
    assert called, "в скрипте не нашлось ни одного вызова"
    missing = [name for name in called
               if not callable(getattr(ValidatorApi, name, None))]
    assert not missing, missing


def test_wiring_every_element_the_script_touches_exists():
    """Скрипт не должен обращаться к узлам, которых в разметке нет."""
    html = read("index.html")
    js = read("app.js")
    ids_html = set(re.findall(r'id="([\w-]+)"', html))
    ids_js = set(re.findall(r'\$\(\s*"#([\w-]+)"', js))
    ids_js |= set(re.findall(r'getElementById\(\s*"([\w-]+)"', js))
    missing = sorted(i for i in ids_js if i not in ids_html)
    assert not missing, missing


def test_wiring_tabs_of_one_screen_do_not_touch_the_other():
    """Голый селектор .tab гасил бы вкладки соседнего экрана."""
    js = read("app.js")
    assert '$$(".tab")' not in js
    assert '$$(".tabpane")' not in js
    assert '$$("#viewValidator .tab")' in js
    assert '$$("#viewParser .tab")' in js
