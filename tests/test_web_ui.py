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


def styles(css, selector):
    """Тела ВСЕХ правил, где селектор стоит сам или в перечислении.

    Одно правило задаёт основу, другое дописывает поведение — брать только
    первое совпадение значит проверять половину оформления.
    """
    out = []
    # Комментарии убираются заранее: они стоят перед селектором и попадают в
    # ту же группу, из-за чего селектор перестаёт совпадать сам с собой.
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    for head, body in re.findall(r"([^{}]+)\{([^}]*)\}", css):
        parts = [part.strip() for part in head.split(",")]
        if selector in parts:
            out.append(body)
    return "\n".join(out)


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
    # Адрес настоящий, а не «a@b.c»: проверка ввода теперь отвергает домены
    # верхнего уровня из одной буквы, каких не существует.
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
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

# ══════════════════════════════════════════════════ Иконки

def test_icons_are_drawn_with_strokes_not_overlapping_fills():
    """Требование 1: «нормальные иконки, а не искажённые».

    Искажение шло от заливки: у самодельного глобуса контуры накладывались
    друг на друга и слипались в кашу. Обводка так не ломается.
    """
    css = read("style.css")
    body = rule(css, "svg")
    assert body is not None
    assert "fill: none" in body, body
    assert "stroke: currentColor" in body, body
    assert "stroke-linecap: round" in body, body
    assert "stroke-linejoin: round" in body, body


def test_icons_have_no_leftover_filled_paths():
    """Ни одной иконки со старой заливкой не осталось.

    Признак самопальной заливки — команда `z` внутри пути, замыкающая
    контур, вместе с дугой `a`: именно так были нарисованы глобус и щит,
    которые слипались.
    """
    html = read("index.html")
    paths = re.findall(r'<path d="([^"]+)"', html)
    assert paths, "в разметке вообще нет иконок"
    guilty = [d for d in paths if d.lower().count("z") >= 2 and "a" in d.lower()]
    assert not guilty, guilty


def test_icons_use_the_same_grid():
    """Все иконки на одной сетке 24×24 — иначе толщина линий гуляет."""
    html = read("index.html")
    boxes = set(re.findall(r'<svg[^>]*viewBox="([^"]+)"', html))
    assert boxes == {"0 0 24 24"}, boxes


def test_icon_box_never_squeezes():
    """Требование 1, вторая половина: иконка не растягивается соседом.

    Внутри флекса картинка сжимается по ширине, но не по высоте — круг
    превращается в овал. flex: none это и лечит.
    """
    css = read("style.css")
    body = rule(css, "svg")
    assert body is not None
    assert "flex: none" in body, body
    # Ширина и высота заданы обе и равны: иначе бокс не квадратный.
    width = re.search(r"width:\s*(\d+)px", body)
    height = re.search(r"height:\s*(\d+)px", body)
    assert width and height and width.group(1) == height.group(1), body


# ══════════════════════════════════════════════════ Запор ввода


LOCKABLE_IDS = [
    "dropEmails", "dropProxies", "dropDorks", "dropPproxy",
    "pasteEmails", "pasteProxies", "pasteDorks", "pastePproxy",
    "clearEmails", "clearProxies", "clearDorks", "clearPproxy",
    "threads", "timeout", "pThreads", "pTimeout",
    "optAi", "optOsint", "optCache", "pEngine",
]


def test_lock_inputs_every_control_is_marked():
    """Требование 2: во время прогона ничего не редактируется.

    Список берётся из разметки, а не из памяти автора: добавить переключатель
    и забыть его запереть — ровно та ошибка, которую эта проверка ловит.
    """
    html = read("index.html")
    for element_id in LOCKABLE_IDS:
        found = re.search(r'<[^>]*id="%s"[^>]*>' % element_id, html)
        assert found, "нет элемента %s" % element_id
        assert "data-lock" in found.group(0), \
            "элемент %s не заперт во время прогона" % element_id

    # Режим страны — две кнопки без id, ищем по своему атрибуту.
    for mode in ("coverage", "accuracy"):
        found = re.search(r'<button[^>]*data-country="%s"[^>]*>' % mode, html)
        assert found and "data-lock" in found.group(0), mode


def test_lock_inputs_no_control_in_the_sidebar_is_forgotten():
    """Каждое поле ввода боковой панели заперто — без списка-исключений.

    Кнопки запуска, паузы и стопа не в счёт: ими прогон и управляют.
    """
    html = read("index.html")
    allowed = {"btnStart", "btnPause", "btnStop",
               "pBtnStart", "pBtnPause", "pBtnStop"}
    for chunk in re.findall(r'<aside class="side"[^>]*>(.*?)</aside>', html, re.S):
        for tag in re.findall(r'<(?:input|select|textarea)[^>]*>', chunk):
            found = re.search(r'id="([\w-]+)"', tag)
            name = found.group(1) if found else tag
            assert "data-lock" in tag, "не заперт: %s" % name
        for tag in re.findall(r'<button[^>]*>', chunk):
            found = re.search(r'id="([\w-]+)"', tag)
            name = found.group(1) if found else ""
            if name in allowed:
                continue
            assert "data-lock" in tag, "не заперта кнопка: %s" % (name or tag)


def test_lock_inputs_script_locks_by_the_marker():
    """Скрипт запирает по метке из разметки, а не по своему списку."""
    js = read("app.js")
    assert 'function setLocked(' in js
    assert '$$("[data-lock]")' in js
    assert "el.disabled = on" in js
    # Зона перетаскивания — не поле ввода, у неё нет disabled: до неё можно
    # дойти табом, поэтому у неё убирается фокус.
    assert "tabIndex" in js


def test_lock_inputs_locking_is_visible():
    """Запертое поле должно выглядеть запертым, иначе это похоже на зависание."""
    css = read("style.css")
    body = rule(css, "[data-lock][disabled],\n[data-lock].is-locked")
    assert body is not None, "нет правила для запертых полей"
    assert "pointer-events: none" in body, body
    assert "opacity" in body, body


def test_lock_allows_tabs_and_reading_results():
    """Требование 2, вторая половина: переключаться и читать — можно.

    Владелец просил оставить именно это: вкладки валидатор/парсер, вкладки
    внутри экрана, фильтры и страницы по уже полученным результатам.
    """
    html = read("index.html")
    must_stay_free = [
        r'<button class="mode[^"]*" data-mode="\w+"',      # валидатор / сбор
        r'<button class="tab[^"]*" data-tab="\w+"',        # вкладки проверки
        r'<button class="tab[^"]*" data-ptab="\w+"',       # вкладки сбора
    ]
    for pattern in must_stay_free:
        found = re.findall(pattern + r'[^>]*>', html)
        assert found, pattern
        for tag in found:
            assert "data-lock" not in tag, "заперто лишнее: %s" % tag

    # Отбор и постраничник тоже остаются живыми.
    for element_id in ("search", "minScore", "pagePrev", "pageNext",
                       "btnCopy", "btnExport", "resetFilters"):
        found = re.search(r'<[^>]*id="%s"[^>]*>' % element_id, html)
        assert found, element_id
        assert "data-lock" not in found.group(0), element_id


def test_lock_allows_facet_lists_stay_open():
    """Списки граней — не поля ввода панели, запирать их нечем и незачем."""
    html = read("index.html")
    for facet in ("facetCountry", "facetGender", "facetProvider"):
        found = re.search(r'<details class="facet" id="%s">' % facet, html)
        assert found, facet


def test_lock_backend_refuses_source_changes_during_a_run():
    """Требование 2, третья половина: запор держится и на стороне питона.

    Блокировка только на странице — рисунок: запрос уходит мимо неё одной
    строкой, и база подменяется прямо посреди чтения.
    """
    api = make_api()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})
    assert len(api.email_sources) == 1

    class Busy:
        is_running = True

    api.pipeline = Busy()
    assert api._busy() is True

    refused = api.paste({"kind": "emails", "text": "anna@yahoo.com"})
    assert refused.get("error"), "вставка прошла во время прогона"
    assert len(api.email_sources) == 1, "источник изменился во время прогона"

    refused = api.clear({"kind": "emails"})
    assert refused.get("error"), "очистка прошла во время прогона"
    assert len(api.email_sources) == 1

    refused = api.choose({"kind": "emails"})
    assert refused.get("error"), "выбор файла прошёл во время прогона"


def test_lock_backend_lets_go_when_the_run_ends():
    """Положительный контроль: без него запор мог бы просто не отпускать."""
    api = make_api()

    class Idle:
        is_running = False

    api.pipeline = Idle()
    assert api._busy() is False
    assert not api.paste({"kind": "emails", "text": "ivan@gmail.com"}).get("error")
    assert len(api.email_sources) == 1


def test_lock_backend_watches_the_parser_by_its_real_interface():
    """Сбор адресов запирает ввод так же, как проверка.

    Признак берётся тот, что есть у НАСТОЯЩЕГО ParserPipeline. Он наследует
    threading.Thread, и своего is_running у него нет: первая версия этой
    проверки спрашивала его — и тест проходил на подставном объекте, пока
    живой сбор не запирал ничего вовсе.
    """
    from core.parser_pipeline import ParserPipeline

    assert callable(getattr(ParserPipeline, "is_alive", None)),         "у сбора адресов больше нет is_alive — признак занятости надо чинить"
    assert not hasattr(ParserPipeline, "is_running"),         "у сбора появился is_running: проверьте, какой признак верный"

    api = make_api()

    class Idle:
        is_running = False

    class RunningParser:
        """Ровно тот признак, что у ParserPipeline: живой поток."""

        def is_alive(self):
            return True

    api.pipeline = Idle()
    api.parser = RunningParser()
    assert api._busy() is True
    assert api.paste({"kind": "dorks", "text": "site:vk.com"}).get("error")

    class FinishedParser:
        def is_alive(self):
            return False

    api.parser = FinishedParser()
    assert api._busy() is False
    assert not api.paste({"kind": "dorks", "text": "site:vk.com"}).get("error")


def test_lock_backend_numbers_from_the_page_are_clamped():
    """Требование 4 «везде во всём софте»: числовые поля тоже проверяются.

    Голый int() падает на «abc» и пропускает 999999 потоков в движок.
    """
    api = make_api()
    assert api._number({"threads": "abc"}, "threads", 100, 1, 500) == 100
    assert api._number({"threads": 999999}, "threads", 100, 1, 500) == 500
    assert api._number({"threads": -5}, "threads", 100, 1, 500) == 1
    assert api._number({}, "threads", 100, 1, 500) == 100
    assert api._number({"threads": None}, "threads", 100, 1, 500) == 100
    assert api._number({"threads": float("nan")}, "threads", 100, 1, 500) == 100
    assert api._number({"threads": "42"}, "threads", 100, 1, 500) == 42


def test_lock_backend_a_junk_payload_never_starts_a_run():
    """Мусор в полях не должен ронять запуск исключением."""
    api = make_api()
    result = api.start({"threads": "abc", "timeout": [], "country": None})
    # Источников нет, поэтому отказ ожидаем — важно, что это отказ, а не
    # проброшенное наружу исключение.
    assert result["ok"] is False and result["error"]


def test_lock_backend_reading_results_is_never_refused():
    """Читать выборку во время прогона можно — это и просил владелец."""
    api = make_api()
    api._on_result("ivan@gmail.com", "Valid", "250 OK", "mx",
                   {"engagement_score": 90, "country": "США"})

    class Busy:
        is_running = True

    api.pipeline = Busy()
    assert api.page({"groups": ["valid"]})["total"] == 1
    assert api.facets({"groups": ["valid"]})["total"] == 1
    assert api.state()["counts"]["valid"] == 1


# ══════════════════════════════════════════════════ Ползунки

def test_slider_track_is_filled_up_to_the_thumb():
    """Требование 3: закрашена не только ручка, но и линия до неё."""
    css = read("style.css")
    body = rule(css, 'input[type="range"]')
    assert body is not None
    assert "linear-gradient" in body, body
    assert "var(--accent)" in body, body
    assert "--fill" in body, body

    thumb = rule(css, 'input[type="range"]::-webkit-slider-thumb')
    assert thumb is not None
    assert "var(--accent)" in thumb, thumb


def test_slider_fill_is_recomputed_on_every_move():
    """Долю считает скрипт: Chromium своего псевдоэлемента для неё не даёт."""
    js = read("app.js")
    assert "function paintRange(" in js
    assert 'setProperty("--fill"' in js
    # Каждый из четырёх ползунков перекрашивается при движении и на старте.
    for name in ("threads", "timeout", "pThreads", "pTimeout"):
        assert re.search(r"%s\.addEventListener\(\"input\"" % name, js), name
    assert "[threads, timeout, pThreads, pTimeout].forEach(paintRange)" in js


# ══════════════════════════════════════════════════ Плейсхолдеры

def test_placeholder_shows_every_accepted_format():
    """Требование 4: в поле вставки перечислены все принимаемые форматы."""
    js = read("app.js")
    assert "PASTE_FORMATS" in js
    assert "Одна запись в строке" not in read("index.html").replace(
        'placeholder="Одна запись в строке"', ""), "старый плейсхолдер остался"

    # Адреса: голый адрес, адрес с полями через разные разделители,
    # заголовок CSV и кириллический адрес.
    assert "ivan@gmail.com" in js
    for separator in (";", ",", "|"):
        assert separator in js
    assert "email;name;gender;country" in js
    assert "иван@почта.рф" in js

    # Прокси: все четыре формата, которые разбирает движок.
    assert "1.2.3.4:8080" in js
    assert "1.2.3.4:8080:логин:пароль" in js
    assert "логин:пароль@1.2.3.4:8080" in js
    assert "socks5://1.2.3.4:1080" in js

    # Запросы: операторы поисковиков.
    assert "site:linkedin.com" in js
    assert "intext:" in js


def test_placeholder_examples_really_parse():
    """Примеры в плейсхолдере обязаны проходить ту самую проверку ввода.

    Иначе получается издевательство: владельцу показывают образец, вставка
    которого тут же отвергается.
    """
    from core.input_guard import detect_kind

    js = read("app.js")
    blocks = re.findall(r'placeholder: \[(.*?)\]\.join', js, re.S)
    assert len(blocks) >= 3, "не нашлись примеры в PASTE_FORMATS"

    expected = ["email", "proxy", "dork"]
    for kind, block in zip(expected, blocks):
        lines = []
        for raw in block.splitlines():
            raw = raw.strip().rstrip(",").strip()
            if len(raw) > 1 and raw[0] in "\"'" and raw[-1] == raw[0]:
                lines.append(raw[1:-1])
        assert lines, block
        for line in lines:
            if line.startswith("email;"):
                continue          # заголовок CSV, не запись
            assert detect_kind(line) == kind, (kind, line, detect_kind(line))


def test_placeholder_explains_the_rules_above_the_field():
    """Кроме примеров есть словами: про разделители, про порт 25."""
    js = read("app.js")
    assert "hint:" in js
    assert "разделитель" in js.lower()
    assert "порт 25" in js
    html = read("index.html")
    assert 'id="pasteHint"' in html


def test_placeholder_refusal_keeps_the_window_open():
    """Отказ не должен закрывать окно и терять набранное."""
    js = read("app.js")
    assert 'querySelector("form").addEventListener("submit"' in js
    assert "event.preventDefault()" in js
    assert 'id="pasteError"' in read("index.html")


# ══════════════════════════════════════════════════ Ничего не сдвигается

def test_reserves_space_hidden_elements_keep_their_place():
    """Требование 5: ничего не съезжает.

    hidden выкидывает элемент из потока, и соседи прыгают. Класс is-gone
    прячет, оставляя место занятым.
    """
    css = read("style.css")
    body = rule(css, ".is-gone")
    assert body is not None, "нет класса, который прячет без сдвига"
    assert "visibility: hidden" in body, body
    assert "display" not in body, "display:none снова уберёт элемент из потока"


def test_reserves_space_no_toggled_element_uses_hidden():
    """Ни один переключаемый по ходу работы элемент не пользуется hidden."""
    html = read("index.html")
    js = read("app.js")

    # В разметке hidden остаётся только у второго экрана целиком: он не
    # соседствует ни с чем, что могло бы съехать.
    leftovers = re.findall(r'<[^>]*\bid="([\w-]+)"[^>]*\shidden[^>]*>', html)
    assert set(leftovers) <= {"viewParser", "toast"}, leftovers

    # И скрипт больше не дёргает .hidden у того, что стоит в потоке.
    guilty = re.findall(r'\$\("#([\w-]+)"\)\.hidden', js)
    assert set(guilty) <= {"viewValidator", "viewParser"}, guilty


def test_reserves_space_for_every_element_that_appears():
    """Под каждый появляющийся элемент место зарезервировано поимённо."""
    css = read("style.css")
    for selector in (".start-hint", ".run-controls",
                     "#logNote", "#pLogNote", "#pFoundNote"):
        body = styles(css, selector)
        assert body, selector
        assert "min-height" in body, (selector, body)


def test_tabular_numbers_do_not_shove_neighbours():
    """Требование 5: растущее число не должно растаскивать плитку.

    В пропорциональном шрифте единица уже семёрки, и счётчик, дойдя от 1111
    до 7777, заметно меняет ширину.
    """
    css = read("style.css")
    for selector in (".tile__num", ".mini b", "output", "#pageLabel",
                     "#pageCount", ".grid .c-score"):
        body = styles(css, selector)
        assert body, "нет правил для %s" % selector
        assert "tabular-nums" in body, (selector, body)


# ══════════════════════════════════════════════════ Фильтры на странице

def test_contract_every_api_call_still_exists():
    """Страница и питон не разъехались после всех правок."""
    from ui.webapp import ValidatorApi

    js = read("app.js")
    called = sorted(set(re.findall(r'\bapi\(\s*"(\w+)"', js)))
    assert called, "скрипт вообще не зовёт мост"
    missing = [name for name in called
               if not callable(getattr(ValidatorApi, name, None))]
    assert not missing, missing


def test_contract_every_element_the_script_touches_exists():
    html = read("index.html")
    js = read("app.js")
    ids_html = set(re.findall(r'id="([\w-]+)"', html))
    ids_js = set(re.findall(r'\$\(\s*"#([\w-]+)"', js))
    ids_js |= set(re.findall(r'getElementById\(\s*"([\w-]+)"', js))
    assert ids_js - ids_html == set(), ids_js - ids_html


def test_contract_filters_reach_every_action():
    """Копирование и выгрузка берут ту же выборку, что и таблица.

    Иначе сохранённый файл не совпадает с тем, что владелец видит на
    экране, — а он по этому файлу шлёт письма.
    """
    js = read("app.js")
    assert "function selection(" in js
    for call in ('api("page", selection', 'api("facets", selection',
                 'api("copy_rows", selection', 'api("export", selection'):
        assert call in js, call


def test_contract_search_is_debounced():
    """Запрос на каждое нажатие клавиши — десяток обращений к базе на слово."""
    js = read("app.js")
    assert "searchTimer" in js
    assert "clearTimeout(searchTimer)" in js


def test_contract_facet_markup_matches_the_script():
    """Разметка граней и имена в скрипте совпадают."""
    html = read("index.html")
    js = read("app.js")
    assert "FACET_TITLE" in js
    for facet in ("Country", "Gender", "Provider"):
        assert 'id="facet%s"' % facet in html, facet
    assert 'class="facet__list"' in html

def test_contract_polling_backs_off_when_the_bridge_is_down():
    """Опрос не должен долбить упавший мост четыре раза в секунду.

    Замечено вживую: браузер перестаёт выдавать сокеты и сыплет
    ERR_INSUFFICIENT_RESOURCES, а вместе с неудачными запросами тонут и
    удачные, когда мост возвращается.
    """
    js = read("app.js")
    for name in ("missed", "skip", "parserMissed", "parserSkip"):
        assert name in js, name
    assert "Math.min(8, missed)" in js
    assert "Math.min(8, parserMissed)" in js

# ══════════════════════════════════════════════════ Закреплённое окно

def test_viewport_root_is_exactly_the_window_height():
    """Корень страницы не выше окна — иначе интерфейсу есть куда уезжать.

    Замерено вживую: корень был на 181 пиксель выше окна, и любой фокус
    внутри утаскивал за собой всю раскладку вместе с шапкой. Полосы
    прокрутки при этом не видно — overflow:hidden прячет её, но саму
    прокрутку не запрещает.
    """
    css = read("style.css")
    # Правило записано перечислением, поэтому спрашиваем каждую часть.
    body = styles(css, "html") + styles(css, "body")
    assert body, "нет базового правила для html и body"
    assert "height: 100vh" in body, body
    assert "max-height: 100vh" in body, body
    assert "overflow: hidden" in body, body
    assert "overscroll-behavior: none" in body, body


def test_viewport_toggle_is_the_checkbox_itself():
    """Переключатель нарисован на самом чекбоксе, а не на прозрачной подложке.

    Прозрачный элемент браузер считает невидимым и честно «прокручивает к
    нему» при фокусе — панель уезжала на 342 пикселя от одного щелчка по
    галочке. Ни position, ни scroll-margin это не лечат.
    """
    css = read("style.css")
    html = read("index.html")

    assert "toggle__track" not in css, "прозрачная подложка вернулась в стили"
    assert "toggle__track" not in html, "прозрачная подложка вернулась в разметку"

    body = styles(css, ".toggle input")
    assert body, "нет правила для самого переключателя"
    assert "appearance: none" in body, body
    # Прозрачности быть не должно: именно она и делала элемент невидимым.
    assert "opacity: 0" not in body, body
    assert "position: absolute" not in body, body

    # Состояния рисуются на нём же, а не на соседнем узле.
    assert styles(css, ".toggle input:checked"), "нет вида включённого состояния"
    assert styles(css, ".toggle input::after"), "нет кружка переключателя"


def test_viewport_launch_and_run_controls_share_one_cell():
    """Настройки идут сразу за запуском, без дыры под кнопкой.

    Место под «Пауза/Стоп» резервировалось пустотой ниже кнопки, и между
    третьим шагом и настройками зияло полторы сотни пикселей — настройки
    оказывались посреди панели. Теперь обе кнопки занимают ту же ячейку.
    """
    html = read("index.html")
    css = read("style.css")

    # Обе кнопки лежат внутри одного блока запуска — на обоих экранах.
    launches = re.findall(r'<div class="launch">(.*?)</div>\s*</div>', html, re.S)
    assert len(launches) == 2, len(launches)
    for block in launches:
        assert "btn--xl" in block, "в блоке запуска нет главной кнопки"
        assert "run-controls" in block, "пауза и стоп вне блока запуска"

    body = styles(css, ".launch")
    assert body and "grid" in body, body
    layer = styles(css, ".launch > *")
    assert layer and "grid-area: 1 / 1" in layer, layer

    # Прежний резерв высоты убран: он и создавал дыру.
    reserve = styles(css, ".run-controls")
    assert "min-height: 40px" not in reserve, reserve


def test_viewport_start_button_hides_while_the_run_controls_show():
    """Иначе кнопки наложатся друг на друга в общей ячейке."""
    js = read("app.js")
    assert 'show($("#btnStart"), !active)' in js
    assert 'show($("#pBtnStart"), !pActive)' in js

# ══════════════════════════════════════════════ Поле вставки и адаптация

def test_fits_textarea_has_a_fixed_size_and_scrolls():
    """Требование: размер поля закреплён, содержимое листается до конца.

    Ручка растягивания в углу выглядела приглашением, но тянуть было
    некуда: растянутое поле вылезало за края окна вместе с кнопками.
    """
    css = read("style.css")
    body = styles(css, ".modal__box textarea")
    assert body, "нет правила для поля вставки"
    assert "resize: none" in body, body
    assert "height:" in body, body
    assert "overflow-y: auto" in body, body


def test_fits_paste_window_never_leaves_the_screen():
    """На низком окне кнопки «Отмена» и «Добавить» должны оставаться доступны."""
    css = read("style.css")
    box = styles(css, ".modal__box")
    assert "max-height" in box, box
    assert "overflow-y: auto" in box, box
    assert "max-height" in styles(css, ".modal"), styles(css, ".modal")


def test_fits_work_area_scrolls_instead_of_the_root():
    """Прокрутка живёт в рабочей области, а не в корне страницы.

    Разница не косметическая: прокрути корень — и шапка с переключателем
    экранов уедет за верхний край. Именно это владелец и показывал.
    """
    css = read("style.css")
    layout = styles(css, ".layout")
    assert "overflow: auto" in layout, layout
    # А корню прокрутка по-прежнему запрещена.
    root = styles(css, "html") + styles(css, "body")
    assert "overflow: hidden" in root, root


def test_fits_work_area_keeps_a_usable_minimum():
    """Ниже этого таблица и лог превращаются в щёлку."""
    css = read("style.css")
    body = styles(css, ".work")
    assert "min-height" in body, body


def test_fits_narrow_layout_unlocks_the_sidebar():
    """В одну колонку панель разворачивается целиком, а листается вся область.

    Тут нужны ОБА послабления сразу. min-height:0 из базового правила нужен
    широкой раскладке, но разрешает панели схлопнуться; а grid вдобавок
    обнуляет автоматический минимум всему, чей overflow не visible — из-за
    чего панель складывалась в полоску в 33 пикселя даже с min-height:auto.
    """
    css = read("style.css")
    narrow = re.search(r"@media \(max-width: 900px\)\s*\{(.*?)\n\}", css, re.S)
    assert narrow, "нет правил для узкого окна"
    block = narrow.group(1)
    assert "grid-template-columns: minmax(0, 1fr)" in block, block
    assert "min-height: auto" in block, block
    assert "overflow: visible" in block, block
    assert "height: auto" in block, block


def test_fits_low_window_unlocks_the_sidebar_too():
    """Ширины на две колонки хватает, а высоты уже нет — тот же приём."""
    css = read("style.css")
    low = re.search(r"@media \(max-height: 620px\)\s*\{(.*?)\n\}", css, re.S)
    assert low, "нет правил для низкого окна"
    block = low.group(1)
    assert "min-height: auto" in block, block
    assert "overflow: visible" in block, block
    assert "align-content: start" in block, block


def test_fits_breakpoints_for_one_selector_go_widest_first():
    """Пороги, спорящие за ОДИН селектор, идут от широкого к узкому.

    Чередование порогов само по себе безвредно: раскладка и плитки сбора
    адресов живут в разных наборах правил и друг другу не мешают. Опасно
    другое — когда один и тот же селектор настраивается дважды и более
    общее правило стоит позже частного: тогда оно его перебивает, и на
    узком экране применяется вариант для широкого.
    """
    css = read("style.css")
    blocks = []
    for found in re.finditer(r"@media \(max-width: (\d+)px\)\s*\{", css):
        width = int(found.group(1))
        depth, i = 1, found.end()
        while i < len(css) and depth:
            if css[i] == "{":
                depth += 1
            elif css[i] == "}":
                depth -= 1
            i += 1
        body = css[found.end():i - 1]
        selectors = set()
        for head in re.findall(r"([^{}]+)\{", body):
            selectors.update(part.strip() for part in head.split(","))
        blocks.append((width, selectors))

    assert blocks, "нет ни одного порога по ширине"
    for a in range(len(blocks)):
        for b in range(a + 1, len(blocks)):
            shared = blocks[a][1] & blocks[b][1]
            if not shared:
                continue
            assert blocks[a][0] >= blocks[b][0], (
                "правило для %dpx стоит раньше более широкого %dpx и будет им "
                "перебито; общие селекторы: %s"
                % (blocks[a][0], blocks[b][0], sorted(shared)))

# ══════════════════════════════════════════ Таблица видна всегда

def test_table_visible_never_collapses_to_nothing():
    """Владелец открыл «Результаты» и увидел пустоту под фильтрами.

    Строк при этом было 78. Виноват flex:1 с min-height:0 — он честно
    отдаёт всё место соседям, и на невысоком окне таблице не доставалось
    НИЧЕГО.
    """
    css = read("style.css")
    body = styles(css, ".tablewrap")
    assert body, "нет правила для области таблицы"
    assert "min-height" in body, body
    found = re.search(r"min-height:\s*(\d+)px", body)
    assert found and int(found.group(1)) >= 200, body


def test_table_visible_log_and_proxy_keep_their_height_too():
    """Лог и профиль прокси схлопывались ровно так же."""
    css = read("style.css")
    for selector in (".log", ".proxy"):
        body = styles(css, selector)
        assert body and "min-height" in body, (selector, body)


def test_table_visible_area_scrolls_on_its_own():
    """Не поместилась — листается, а не обрезается."""
    css = read("style.css")
    body = styles(css, ".tablewrap")
    assert "overflow: auto" in body, body


# ══════════════════════════════════════════ Аватарки

def test_avatar_is_shown_when_enrichment_found_one():
    """Картинка запрашивается только для тех, у кого аватарка найдена.

    Слать хеш для всех подряд значило бы дёргать чужой сервер на каждую
    строку таблицы и заодно рассказывать ему всю базу.
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_result("johnacreps@gmail.com", "Valid", "250 OK", "mx",
                   {"engagement_score": 90, "has_gravatar": True})
    api._on_result("nobody@gmail.com", "Valid", "250 OK", "mx",
                   {"engagement_score": 80, "has_gravatar": False})

    rows = {row["email"]: row for row in api.page({"groups": ["valid"]})["rows"]}
    assert rows["johnacreps@gmail.com"]["avatar"], "аватарка не приехала на страницу"
    assert rows["nobody@gmail.com"]["avatar"] == "", "хеш ушёл без нужды"


def test_avatar_hash_is_what_gravatar_expects():
    """Хеш считается от адреса в нижнем регистре без пробелов."""
    import hashlib

    from ui.webapp import _gravatar_hash

    email = "  JohnACreps@Gmail.com  "
    expected = hashlib.md5(b"johnacreps@gmail.com").hexdigest()
    assert _gravatar_hash(email) == expected


def test_avatar_cell_shows_initials_and_a_stable_colour():
    """У одного адреса цвет кружка всегда один и тот же.

    По нему строку узнаёшь боковым зрением, не читая; случайный цвет на
    каждой перерисовке эту пользу уничтожает.
    """
    js = read("app.js")
    assert "function avatarCell(" in js
    assert "function initials(" in js
    # Цвет выводится из адреса, а не берётся случайно.
    assert "email.charCodeAt(i)" in js
    assert "Math.random" not in js.split("function avatarCell(")[1][:900]
    # Насыщенность и светлота зафиксированы: иначе кружки то невидимы, то
    # кислотные.
    assert "58% 42%" in js


def test_avatar_fallback_when_the_picture_does_not_load():
    """Без сети в каждой строке висела бы битая картинка."""
    js = read("app.js")
    block = js.split("function avatarCell(")[1][:1200]
    assert 'addEventListener("error"' in block, block[:400]
    assert "img.remove()" in block


def test_avatar_fallback_initials_are_readable():
    """Две буквы, а не одна: иначе половина кружков неразличима."""
    js = read("app.js")
    block = js.split("function initials(")[1][:600]
    assert "parts[0][0] + parts[1][0]" in block
    assert "slice(0, 2)" in block


def test_avatar_does_not_break_the_address_column():
    """Адрес рядом с кружком по-прежнему обрезается многоточием."""
    css = read("style.css")
    assert "text-overflow: ellipsis" in styles(css, ".who__mail")
    assert "flex: none" in styles(css, ".ava"), "кружок сожмётся длинным адресом"


# ══════════════════════════════════════════ Файл и поле ввода — одно и то же

def test_source_text_file_lands_in_the_input(tmp_path):
    """Выбранный файл попадает в поле текстом и правится там же."""
    from ui.webapp import ValidatorApi

    base = tmp_path / "base.txt"
    base.write_text("\n".join("user%d@gmail.com" % i for i in range(20)),
                    encoding="utf-8")

    api = ValidatorApi()
    api._pick_files = lambda kind: [str(base)]
    api.choose({"kind": "emails"})

    info = api.sources()["emails"]
    assert info["editable"] is True
    assert "user0@gmail.com" in info["text"]
    assert info["title"] == "base.txt", info


def test_source_text_pasted_text_is_offered_back(tmp_path):
    """Вставленное руками возвращается в поле так же, как содержимое файла."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com\nanna@yahoo.com"})
    info = api.sources()["emails"]
    assert info["editable"] is True
    assert info["text"] == "ivan@gmail.com\nanna@yahoo.com"


def test_source_text_huge_file_is_refused_openly(tmp_path):
    """Гигантский файл в поле не показывается — и об этом сказано прямо.

    Строка на миллионы адресов в текстовом поле вешает окно. Молчаливое
    «поле пустое» было бы хуже отказа: владелец решил бы, что файл не
    загрузился.
    """
    from ui.webapp import ValidatorApi

    big = tmp_path / "huge.txt"
    with io.open(big, "w", encoding="utf-8") as handle:
        for i in range(400_000):
            handle.write("user%d@gmail.com\n" % i)

    api = ValidatorApi()
    assert big.stat().st_size > ValidatorApi.INLINE_LIMIT, "файл вышел маловат"

    api._pick_files = lambda kind: [str(big)]
    api.choose({"kind": "emails"})

    info = api.sources()["emails"]
    assert info["count"] == 1, "файл не подключился"
    assert info["editable"] is False
    assert info["text"] == ""
    # Владельцу это объяснено в логе, а не просто умолчано.
    said = " ".join(line["text"] for line in api.state()["log"])
    assert "в поле ввода не показан" in said, said


def test_source_text_page_opens_the_field_with_what_is_loaded():
    """Поле вставки открывается с уже загруженным, а не пустым."""
    js = read("app.js")
    assert "const sourceText" in js
    assert "area.value = sourceText[kind]" in js
    # И правка заменяет содержимое, а не добавляется к нему.
    assert 'api("clear", { kind: pasteKind })' in js


def test_same_input_file_and_paste_produce_identical_work(tmp_path):
    """Движку всё равно, как данные пришли: вход обязан быть тем же.

    Это и есть требование владельца целиком: «софту должно быть срать, как
    я данные загружаю».
    """
    from ui.webapp import ValidatorApi

    lines = ["ivan@gmail.com", "anna@yahoo.com;Анна;Женский;США",
             "petr@mail.ru,Пётр Смирнов,Мужской,Россия"]
    text = "\n".join(lines)

    base = tmp_path / "base.txt"
    base.write_text(text, encoding="utf-8")

    from_file = ValidatorApi()
    from_file._pick_files = lambda kind: [str(base)]
    from_file.choose({"kind": "emails"})

    from_paste = ValidatorApi()
    from_paste.paste({"kind": "emails", "text": text})

    def payload(api):
        return [dict(source) for source in api.email_sources]

    file_side = payload(from_file)
    paste_side = payload(from_paste)

    assert len(file_side) == len(paste_side) == 1
    assert file_side[0]["type"] == paste_side[0]["type"] == "text"
    assert file_side[0]["content"] == paste_side[0]["content"] == text


def test_same_input_both_paths_pass_the_same_guard(tmp_path):
    """И проверка ввода одинакова: прокси не пролезут ни одним путём."""
    from ui.webapp import ValidatorApi

    proxies = tmp_path / "proxy.txt"
    proxies.write_text("\n".join("1.2.3.%d:8080" % i for i in range(1, 30)),
                       encoding="utf-8")

    api = ValidatorApi()
    api._pick_files = lambda kind: [str(proxies)]
    assert api.choose({"kind": "emails"}).get("error")
    assert len(api.email_sources) == 0

    api2 = ValidatorApi()
    assert api2.paste({"kind": "emails",
                       "text": proxies.read_text(encoding="utf-8")}).get("error")
    assert len(api2.email_sources) == 0
