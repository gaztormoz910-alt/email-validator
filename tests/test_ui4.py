# -*- coding: utf-8 -*-
import ast
import io
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def _page_row(data, email="user@corp.test", status="Valid", reason="250 OK"):
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.store.append(email, status, reason, "mx.corp.test", data)
    page = api.page({})
    assert page["rows"], "строка не доехала до окна"
    return page["rows"][0]


def test_loaded_as_reaches_the_window():
    row = _page_row({"original_email": "user@sky.company.co.uk"})
    assert row["original"] == "user@sky.company.co.uk"


def test_loaded_as_is_drawn_not_dropped():
    app = read("ui/web/app.js")
    assert "row.original" in app, "поле снова не рисуется"
    assert "who__was" in app
    assert "who__was" in read("ui/web/style.css"), "нечем показать"


def test_loaded_as_hidden_when_nothing_changed():
    app = read("ui/web/app.js")
    assert re.search(r'row\.original\s*&&\s*row\.original\s*!==\s*email', app), (
        "условие расхождения потеряно")
    row = _page_row({})
    assert row["original"] == "", "пустое поле стало непустым"


def test_source_visible_in_the_row():
    row = _page_row({"name": "Ivan", "country": "Italy",
                     "name_source": "адрес", "gender_source": "имя",
                     "country_source": "имя"})
    more = row["more"]
    assert more["name_source"] == "адрес"
    assert more["gender_source"] == "имя"
    assert more["country_source"] == "имя"


def test_source_visible_marks_a_guess():
    app = read("ui/web/app.js")
    assert "SOURCE_TEXT" in app
    assert "догадка" in app, "догадка не названа догадкой"
    assert 'detail__src--guess' in app
    css = read("ui/web/style.css")
    assert ".detail__src--guess" in css, "догадка не отличается на вид"


def test_source_visible_control_fact_is_not_a_guess():
    app = read("ui/web/app.js")
    block = app[app.index("const note = sourceNote(source);"):]
    block = block[:block.index("cell.appendChild(src);")]
    assert 'source === "имя"' in block, (
        "меткой догадки помечается что-то кроме предсказания по имени")


def test_detail_card_carries_new_enrichment():
    row = _page_row({
        "company": "Corp", "job_role": "sales", "domain_type": "Corporate",
        "birth_year": "1994", "engagement_grade": "Hot",
        "provider_type": "Corporate", "social_accounts": "github",
        "ai_note": "имя выглядит машинным", "from_cache": True,
    })
    more = row["more"]
    for key, value in (("company", "Corp"), ("job_role", "sales"),
                       ("domain_type", "Corporate"), ("birth_year", "1994"),
                       ("grade", "Hot"), ("provider_type", "Corporate"),
                       ("social", "github")):
        assert more[key] == value, "%s потерялось по дороге" % key
    assert more["ai_note"].startswith("имя выглядит")
    assert more["from_cache"] is True


def test_detail_card_is_rendered():
    app = read("ui/web/app.js")
    assert "function detailRow" in app
    for label in ("Компания", "Должность", "Тип домена", "Год рождения",
                  "Соцсети", "Основание вердикта"):
        assert label in app, "в карточке нет строки «%s»" % label
    assert "is-openable" in app and "detailRow(row" in app
    css = read("ui/web/style.css")
    assert ".detail__grid" in css and "tr.detail" in css


def test_detail_card_asks_nothing_from_the_network():
    app = read("ui/web/app.js")
    body = app[app.index("function detailRow"):]
    body = body[:body.index("\n}")]
    assert "api(" not in body and "fetch(" not in body


def test_export_parity_window_covers_console():
    import cli

    webapp = read("ui/webapp.py")
    block = webapp[webapp.index('writer.writerow(["Email"'):]
    headers = re.findall(r'"([A-Za-z]+)"', block[:block.index("])")])

    def norm(name):
        return name.replace("_", "").lower()

    got = {norm(h) for h in headers}
    aliases = {"score": "score", "grade": "grade",
               "verdictconfidence": "confidence",
               "verdictbasis": "confidencebasis",
               "validatedat": "validatedat", "originalemail": "originalemail"}
    missing = []
    for field in cli.EXPORT_FIELDS:
        key = norm(field)
        key = aliases.get(key, key)
        if key not in got:
            missing.append(field)
    assert not missing, "окно не отдаёт: %s" % ", ".join(missing)


def test_export_parity_header_matches_row_width():
    tree = None
    for node in ast.walk(ast.parse(read("ui/webapp.py"))):
        if isinstance(node, ast.FunctionDef) and node.name == "write_csv":
            tree = node
            break
    assert tree is not None, "не нашёл выгрузку результатов"

    widths = []
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "writerow"):
            continue
        arg = node.args[0] if node.args else None
        if isinstance(arg, ast.List):
            widths.append(len(arg.elts))
        elif (isinstance(arg, ast.Call) and isinstance(arg.func, ast.Name)
                and arg.func.id == "csv_row" and arg.args
                and isinstance(arg.args[0], ast.List)):
            widths.append(len(arg.args[0].elts))
    assert len(widths) >= 2, "не нашёл ни заголовка, ни строки"
    assert len(set(widths)) == 1, "ширина заголовка и строки разошлась: %s" % widths


def test_classic_revise_control_store_can_do_it():
    from ui.result_store import ResultStore

    store = ResultStore()
    for name in ("a", "b"):
        store.append("%s@catchall.test" % name, "Valid", "250 OK",
                     "mx.catchall.test", {})
    store.append("c@honest.test", "Valid", "250 OK", "mx.honest.test", {})

    moved = store.revise_domain("catchall.test", "Unknown", "домен принимает всё")
    assert moved == 2, "пересмотрено %s строк вместо двух" % moved

    from ui.result_store import GROUPS

    rows = {r["email"]: r["status"]
            for r in store.page(groups=GROUPS, page=1, size=50)}
    assert rows["a@catchall.test"] == "Unknown"
    assert rows["c@honest.test"] == "Valid", "задет чужой домен"


def _tuple_of(source, name):
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if (isinstance(node, ast.Assign) and node.targets
                and isinstance(node.targets[0], ast.Name)
                and node.targets[0].id == name
                and isinstance(node.value, ast.Tuple)):
            return [e.value for e in node.value.elts
                    if isinstance(e, ast.Constant)]
    return []


INTERNAL_ONLY = {
    "enrich_sig": "отпечаток настроек обогащения; по нему следующий прогон "
                  "решает, годится ли старый расчёт. Владельцу показывать нечего",
    "ai_suspicious": "булев близнец ai_note; человеку показывается именно "
                     "заметка, а не флаг",
    "has_gravatar": "показывается САМОЙ аватаркой в первой колонке, "
                    "отдельной строкой была бы тавтология",
}


def test_nothing_hidden_reaches_the_main_window():
    keys = set(re.findall(r'data\["([a-z_]+)"\]\s*=', read("core/pipeline.py")))
    keys |= {"company", "job_role", "company_source", "job_role_source"}

    window = read("ui/web/app.js") + read("ui/web/index.html") + read("ui/webapp.py")
    hidden = [k for k in sorted(keys)
              if k not in INTERNAL_ONLY and k not in window]
    assert not hidden, "до основного окна не доезжает: %s" % ", ".join(hidden)


def test_nothing_hidden_control_finds_a_planted_gap():
    keys = {"engagement_score", "выдуманный_ключ_которого_нигде_нет"}
    window = read("ui/webapp.py")
    hidden = [k for k in sorted(keys) if k not in window]
    assert hidden == ["выдуманный_ключ_которого_нигде_нет"], (
        "опись слепа: %s" % hidden)


def test_detail_card_survives_a_repaint():
    app = read("ui/web/app.js")
    assert "opened: new Set()" in app, "нечем помнить раскрытые"
    assert "ui.opened.add(row.email)" in app
    assert "ui.opened.delete(row.email)" in app
    assert "ui.opened.has(row.email)" in app, "помним, но не восстанавливаем"


def test_detail_card_control_closes_when_asked():
    app = read("ui/web/app.js")
    body = app[app.index("const toggle = () =>"):]
    body = body[:body.index("};")]
    assert "remove()" in body and "classList.remove(\"is-open\")" in body


def test_detail_card_is_discoverable():
    html = read("ui/web/index.html")
    assert "hint--rows" in html, "нет подсказки над таблицей"
    hint = html[html.index('class="hint hint--rows"'):]
    hint = hint[:hint.index("</p>")]
    for word in ("компанию", "должность", "тип домена"):
        assert word in hint, "подсказка не называет, что внутри: нет «%s»" % word
    assert ".hint--rows" in read("ui/web/style.css")


