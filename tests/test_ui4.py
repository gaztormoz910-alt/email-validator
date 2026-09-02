# -*- coding: utf-8 -*-
"""Интерфейс обязан показывать то, что умеет движок.

Опись перед правкой показала перевёрнутую картину: самый полный набор полей
выдавала КОНСОЛЬ (25), выгрузка из основного окна отставала на десять, а в
таблице окна было девять колонок. Поле `original` («что было загружено»)
приезжало в окно и молча выбрасывалось — то есть главное требование владельца
в интерфейсе видно не было вовсе.

Здесь проверяется, что это больше не так.
"""
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
    """Одна строка так, как её отдаёт окну ValidatorApi.page()."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.store.append(email, status, reason, "mx.corp.test", data)
    page = api.page({})
    assert page["rows"], "строка не доехала до окна"
    return page["rows"][0]


# ══════════════════════════ U1: видно, что было загружено

def test_loaded_as_reaches_the_window():
    """Исходная строка из файла доезжает до окна в составе строки таблицы."""
    row = _page_row({"original_email": "user@sky.company.co.uk"})
    assert row["original"] == "user@sky.company.co.uk"


def test_loaded_as_is_drawn_not_dropped():
    """И РИСУЕТСЯ. Раньше поле приезжало и выбрасывалось.

    Проверка именно на отрисовку, а не на наличие в JSON: до этой правки
    `row.original` не встречался в app.js ни разу, хотя webapp его слал.
    """
    app = read("ui/web/app.js")
    assert "row.original" in app, "поле снова не рисуется"
    assert "who__was" in app
    assert "who__was" in read("ui/web/style.css"), "нечем показать"


def test_loaded_as_hidden_when_nothing_changed():
    """Контроль: подпись показывается ТОЛЬКО при расхождении строк.

    Иначе она стояла бы под каждым адресом и перестала что-либо означать —
    ровно как «исходный адрес» в выгрузке, если бы его писали всегда.
    """
    app = read("ui/web/app.js")
    assert re.search(r'row\.original\s*&&\s*row\.original\s*!==\s*email', app), (
        "условие расхождения потеряно")
    row = _page_row({})
    assert row["original"] == "", "пустое поле стало непустым"


# ══════════════════════════ U2: виден источник имени, пола, страны

def test_source_visible_in_the_row():
    """Откуда взяты имя, пол и страна — доезжает до окна."""
    row = _page_row({"name": "Ivan", "country": "Italy",
                     "name_source": "адрес", "gender_source": "имя",
                     "country_source": "имя"})
    more = row["more"]
    assert more["name_source"] == "адрес"
    assert more["gender_source"] == "имя"
    assert more["country_source"] == "имя"


def test_source_visible_marks_a_guess():
    """Догадка помечена отдельно от факта.

    «Италия» из файла и «Италия», угаданная по имени, — разные вещи.
    Замерено на 1600 частых именах: строгий режим даёт 50.1% верных при 8.7%
    неверных, «брать лидера всегда» — 66.4% при 33.6%. Если обе выглядят
    одинаково, переключатель «Точность» для владельца невидим.
    """
    app = read("ui/web/app.js")
    assert "SOURCE_TEXT" in app
    assert "догадка" in app, "догадка не названа догадкой"
    assert 'detail__src--guess' in app
    css = read("ui/web/style.css")
    assert ".detail__src--guess" in css, "догадка не отличается на вид"


def test_source_visible_control_fact_is_not_a_guess():
    """Контроль: факт из файла НЕ помечается как догадка."""
    app = read("ui/web/app.js")
    block = app[app.index("const note = sourceNote(source);"):]
    block = block[:block.index("cell.appendChild(src);")]
    assert 'source === "имя"' in block, (
        "меткой догадки помечается что-то кроме предсказания по имени")


# ══════════════════════════ U3: карточка адреса

def test_detail_card_carries_new_enrichment():
    """Компания, должность, тип домена, год рождения, грейд — в окне."""
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
    """Карточка есть в разметке и в стилях, а не только в данных."""
    app = read("ui/web/app.js")
    assert "function detailRow" in app
    for label in ("Компания", "Должность", "Тип домена", "Год рождения",
                  "Соцсети", "Основание вердикта"):
        assert label in app, "в карточке нет строки «%s»" % label
    assert "is-openable" in app and "detailRow(row" in app
    css = read("ui/web/style.css")
    assert ".detail__grid" in css and "tr.detail" in css


def test_detail_card_asks_nothing_from_the_network():
    """Контроль: карточка не ходит за данными — они уже приехали.

    Запрос на каждое раскрытие означал бы обращение к конвейеру на каждый
    клик по строке, то есть окно, которое тормозит тем сильнее, чем больше
    его разглядывают.
    """
    app = read("ui/web/app.js")
    body = app[app.index("function detailRow"):]
    body = body[:body.index("\n}")]
    assert "api(" not in body and "fetch(" not in body


# ══════════════════════════ U4: выгрузка окна не беднее консоли

def test_export_parity_window_covers_console():
    """Окно отдаёт не меньше полей, чем командная строка.

    Раньше было наоборот здравому смыслу: пятнадцать полей в окне против
    двадцати пяти в консоли — чем удобнее поверхность, тем меньше отдаёт.
    """
    import cli

    webapp = read("ui/webapp.py")
    block = webapp[webapp.index('writer.writerow(["Email"'):]
    headers = re.findall(r'"([A-Za-z]+)"', block[:block.index("])")])

    # Имена в выгрузке окна английские и слитные, в консоли — со знаками
    # подчёркивания. Сравниваем по нормализованному виду.
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
    """Контроль: заголовков ровно столько же, сколько значений в строке.

    Расхождение здесь не падает и не логируется — оно молча сдвигает
    колонки, и владелец получает CSV, где «Страна» стоит под «Полом».
    """
    # Смотрим ТОЛЬКО выгрузку результатов: в файле есть и другие writerow —
    # у списка прокси и у сводки, и у них своя ширина, к делу не относящаяся.
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


# ══════════════════════════ U5: классическое окно пересматривает вердикт

def test_classic_revise_is_subscribed():
    """Канал пересмотра подписан ВСЕМИ поверхностями, а не тремя из четырёх.

    Без подписки конвейер получает ноль пересмотренных строк, и домен,
    уличённый в конце прогона как catch-all или тарпитящий, оставляет свои
    «Годен» на экране и в выгрузке.
    """
    for surface in ("ui/webapp.py", "ui/gui.py", "cli.py", "api/jobs.py"):
        assert "on_revise" in read(surface), "%s не слушает пересмотр" % surface


def test_classic_revise_actually_moves_rows():
    """И подписка не пустая: обработчик правит хранилище и перерисовывает."""
    gui = read("ui/gui.py")
    body = gui[gui.index("def safe_revise"):]
    body = body[:body.index("\n    def ", 10)]
    assert "revise_domain" in body, "подписались, но ничего не пересматриваем"
    assert "refresh_validator_tree" in body, "пересмотрели, но не показали"
    assert "force=True" in body, (
        "перерисовка без force ничего не сделает: набор адресов на странице "
        "не изменился, и проверка «показывать ли заново» решит, что нечего")


def test_classic_revise_control_store_can_do_it():
    """Контроль: пересмотр в хранилище действительно работает.

    Хранилище у обоих окон общее, поэтому проверяем его напрямую: если бы
    revise_domain ничего не делал, подписка была бы бессмысленной.
    """
    from ui.result_store import ResultStore

    store = ResultStore()
    for name in ("a", "b"):
        store.append("%s@catchall.test" % name, "Valid", "250 OK",
                     "mx.catchall.test", {})
    store.append("c@honest.test", "Valid", "250 OK", "mx.honest.test", {})

    moved = store.revise_domain("catchall.test", "Unknown", "домен принимает всё")
    assert moved == 2, "пересмотрено %s строк вместо двух" % moved

    # Перечисляем группы явно: по умолчанию страница показывает только
    # «valid», а пересмотренная строка из неё как раз и ушла.
    from ui.result_store import GROUPS

    rows = {r["email"]: r["status"]
            for r in store.page(groups=GROUPS, page=1, size=50)}
    assert rows["a@catchall.test"] == "Unknown"
    assert rows["c@honest.test"] == "Valid", "задет чужой домен"


# ══════════════════════════ U6: колонки классического окна

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


def test_classic_columns_show_confidence_and_loaded():
    """Уверенность и загруженная строка есть и в запасном окне."""
    panels = read("ui/panels.py")
    columns = _tuple_of(panels, "columns")
    assert "confidence" in columns, "нет колонки уверенности"
    assert "loaded" in columns, "нет колонки «загружено как»"
    assert 'heading("confidence"' in panels and 'heading("loaded"' in panels
    assert 'column("confidence"' in panels and 'column("loaded"' in panels

    gui = read("ui/gui.py")
    assert 'data.get("verdict_confidence"' in gui
    assert 'data.get("original_email"' in gui


def test_classic_columns_count_matches_inserted_values():
    """Контроль: колонок ровно столько, сколько значений кладётся в строку.

    Рассинхрон здесь не падает и ничего не пишет в лог — Tk молча теряет
    хвост значений, и вся таблица едет на одну колонку. Это самая дорогая
    ошибка в этой правке и единственная, которую нельзя увидеть чтением.
    """
    columns = _tuple_of(read("ui/panels.py"), "columns")
    assert columns, "не нашёл описание колонок"

    tree = ast.parse(read("ui/gui.py"))
    widths = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "insert"
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "tree"):
            for kw in node.keywords:
                if kw.arg == "values" and isinstance(kw.value, ast.Tuple):
                    widths.append(len(kw.value.elts))
    assert widths, "не нашёл вставку строки в таблицу"
    for width in widths:
        assert width == len(columns), (
            "колонок %d, а значений кладётся %d — таблица поедет"
            % (len(columns), width))


# ══════════════════════════ U7: ничего не спрятано

# Служебные поля, которым в интерфейсе делать нечего. Список поимённый и с
# причиной у каждого: гейт без исключений заставил бы вынести в окно
# отпечаток настроек обогащения ради зелёной галочки.
INTERNAL_ONLY = {
    "enrich_sig": "отпечаток настроек обогащения; по нему следующий прогон "
                  "решает, годится ли старый расчёт. Владельцу показывать нечего",
    "ai_suspicious": "булев близнец ai_note; человеку показывается именно "
                     "заметка, а не флаг",
    "has_gravatar": "показывается САМОЙ аватаркой в первой колонке, "
                    "отдельной строкой была бы тавтология",
}


def test_nothing_hidden_from_every_surface():
    """Каждый ключ движка виден хоть где-то. Опись считается заново."""
    keys = set(re.findall(r'data\["([a-z_]+)"\]\s*=', read("core/pipeline.py")))
    keys |= {"company", "job_role", "company_source", "job_role_source"}

    surfaces = [read(p) for p in ("ui/web/app.js", "ui/web/index.html",
                                 "ui/webapp.py", "ui/gui.py", "ui/panels.py",
                                 "cli.py", "api/jobs.py")]
    hidden = [k for k in sorted(keys)
              if k not in INTERNAL_ONLY and not any(k in s for s in surfaces)]
    assert not hidden, "движок считает, а показать негде: %s" % ", ".join(hidden)


def test_nothing_hidden_reaches_the_main_window():
    """И не «хоть где-то в консоли», а именно в ОСНОВНОМ окне.

    Раньше семнадцать ключей до него не доезжали: обогащение считалось на
    каждом адресе и было видно только тому, кто работает командной строкой.
    """
    keys = set(re.findall(r'data\["([a-z_]+)"\]\s*=', read("core/pipeline.py")))
    keys |= {"company", "job_role", "company_source", "job_role_source"}

    window = read("ui/web/app.js") + read("ui/web/index.html") + read("ui/webapp.py")
    hidden = [k for k in sorted(keys)
              if k not in INTERNAL_ONLY and k not in window]
    assert not hidden, "до основного окна не доезжает: %s" % ", ".join(hidden)


def test_nothing_hidden_control_finds_a_planted_gap():
    """Контроль: опись УМЕЕТ находить дыру.

    Проверка «ничего не спрятано» ничего не стоит, если она не способна
    сказать «спрятано». Подкладываем заведомо невидимый ключ и убеждаемся,
    что его замечают.
    """
    keys = {"engagement_score", "выдуманный_ключ_которого_нигде_нет"}
    window = read("ui/webapp.py")
    hidden = [k for k in sorted(keys) if k not in window]
    assert hidden == ["выдуманный_ключ_которого_нигде_нет"], (
        "опись слепа: %s" % hidden)


def test_detail_card_survives_a_repaint():
    """Карточка, раскрытая во время прогона, не захлопывается сама.

    Таблица перерисовывается раз в секунду, пока идёт проверка, и строки
    пересоздаются целиком. Флаг на самой строке этого не пережил бы, поэтому
    раскрытые адреса помнит состояние страницы.
    """
    app = read("ui/web/app.js")
    assert "opened: new Set()" in app, "нечем помнить раскрытые"
    assert "ui.opened.add(row.email)" in app
    assert "ui.opened.delete(row.email)" in app
    assert "ui.opened.has(row.email)" in app, "помним, но не восстанавливаем"


def test_detail_card_control_closes_when_asked():
    """Контроль: повторный клик всё-таки закрывает карточку.

    Иначе «помним раскрытые» превратилось бы в «раскрыть навсегда».
    """
    app = read("ui/web/app.js")
    body = app[app.index("const toggle = () =>"):]
    body = body[:body.index("};")]
    assert "remove()" in body and "classList.remove(\"is-open\")" in body


def test_detail_card_is_discoverable():
    """Про карточку сказано словами, а не только курсором.

    Раскрытие, о котором никто не знает, ничем не лучше отсутствующего:
    жалоба владельца была ровно про «не видно вообще».
    """
    html = read("ui/web/index.html")
    assert "hint--rows" in html, "нет подсказки над таблицей"
    hint = html[html.index('class="hint hint--rows"'):]
    hint = hint[:hint.index("</p>")]
    for word in ("компанию", "должность", "тип домена"):
        assert word in hint, "подсказка не называет, что внутри: нет «%s»" % word
    assert ".hint--rows" in read("ui/web/style.css")


def test_api_shows_the_same_enrichment():
    """REST API отдаёт то же обогащение, что и окно.

    API — тоже интерфейс, и он отставал от консоли ровно на то же самое:
    интегратор получал вердикт без компании, должности, типа домена и без
    источника догадок.
    """
    jobs = read("api/jobs.py")
    for field in ('"grade"', '"domain_type"', '"birth_year"', '"company"',
                  '"job_role"', '"sources"', '"validated_at"'):
        assert field in jobs, "API не отдаёт %s" % field
    block = jobs[jobs.index('"sources": {'):]
    block = block[:block.index("},")]
    for key in ("name", "gender", "country", "company", "job_role"):
        assert '"%s"' % key in block, "в источниках API нет %s" % key
