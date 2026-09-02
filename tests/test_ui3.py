# -*- coding: utf-8 -*-
"""Шесть замечаний владельца по окну — со скриншотов.

Две из трёх поломок внёс я сам: строку «Продолжить прерванный прогон» я
спрятал классом, который оставляет место (отсюда дыра в панели), а прокрутку
узкой раскладки объявил в комментарии, не дав её на деле.
"""
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
    """Исходник БЕЗ комментариев и докстрок.

    Проверки формулировок ищут ОТСУТСТВИЕ прежней фразы. Искать её в полном
    тексте нельзя: рядом с правкой стоит объяснение, в котором старая фраза
    процитирована дословно, — и проверка падает на собственном комментарии.
    """
    import ast

    tree = ast.parse(read(rel))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            node.value.value = ""
    return ast.unparse(tree)


# ══════════════════════════ U1: зазор в боковой панели

def test_gap_hidden_row_takes_no_space():
    """Строка, которой чаще всего нет, не должна занимать место.

    `is-gone` прячет через visibility — место остаётся. Для строки, которая
    появляется раз в сто прогонов, это постоянная дыра в панели.
    """
    css = read("ui/web/style.css")
    folded = css[css.index(".is-folded"):]
    folded = folded[:folded.index("}") + 1]
    assert "display: none" in folded, folded

    html = read("ui/web/index.html")
    row = html[html.index('id="resumeRow"') - 200:html.index('id="resumeRow"') + 40]
    assert "is-folded" in row, row
    assert "is-gone" not in row, "строка снова прячется с сохранением места"

    app = read("ui/web/app.js")
    assert 'classList.toggle("is-folded", !done)' in app


def test_gap_is_gone_still_exists_for_its_own_case():
    """Контроль: класс is-gone не удалён — он нужен там, где место держат.

    Кнопки запуска и паузы меняются местами во время прогона; если бы они
    исчезали из раскладки, панель прыгала бы на каждый клик.
    """
    css = read("ui/web/style.css")
    assert "visibility: hidden !important" in css
    assert read("ui/web/app.js").count("is-gone") >= 1


# ══════════════════════════ U2: «Точность» по умолчанию

def test_accuracy_default_on_the_page():
    """Кнопка «Точность» активна с самого начала, а не «Заполненность»."""
    html = read("ui/web/index.html")
    segment = html[html.index('data-country="coverage"') - 120:]
    segment = segment[:segment.index("</div>")]
    assert 'is-active" data-country="accuracy"' in segment, segment
    assert 'is-active" data-country="coverage"' not in segment


def test_accuracy_default_in_the_state():
    """И в том, что уходит в конвейер, тоже «accuracy»."""
    app = read("ui/web/app.js")
    assert re.search(r'country:\s*"accuracy"', app), "умолчание состояния не изменено"
    assert not re.search(r'country:\s*"coverage"', app)


def test_accuracy_default_reaches_the_engine():
    """Контроль: значение действительно доезжает до запуска, а не украшает окно."""
    app = read("ui/web/app.js")
    assert "country: ui.country" in app, "режим не кладётся в запрос запуска"
    assert '"country"' in read("ui/webapp.py")


# ══════════════════════════ U3: прокрутка в узком окне

def test_narrow_scroll_area_can_actually_scroll():
    """В одну колонку раскладка обязана прокручиваться целиком.

    Корень прокрутку запрещает (html, body: 100vh + overflow hidden), панель
    разворачивается во всю высоту — и без своей прокрутки у области всё, что
    ниже панели, оказывается за краем экрана навсегда.
    """
    css = read("ui/web/style.css")
    block = css[css.index("@media (max-width: 900px)"):]
    block = block[:block.index("@media (max-width: 1100px)")]
    assert "overflow-y: auto" in block, "узкой раскладке не дали прокрутку"
    assert ".work { min-height:" in block, (
        "без своей высоты таблица и лог схлопнутся в полоску")


def test_narrow_scroll_also_for_short_window():
    """Низкое окно — тот же случай: высоты не хватает, прокрутка нужна."""
    css = read("ui/web/style.css")
    block = css[css.index("@media (max-height: 620px)"):]
    block = block[:block.index("}", block.index(".work"))]
    assert "overflow-y: auto" in block


def test_narrow_scroll_control_root_still_locked():
    """Контроль: корень по-прежнему не прокручивается.

    Иначе фокус в поле начинает утаскивать за собой шапку — ровно то, из-за
    чего запрет и появился.
    """
    css = read("ui/web/style.css")
    root = css[css.index("html, body {"):]
    root = root[:root.index("}")]
    assert "overflow: hidden" in root
    assert "height: 100vh" in root


# ══════════════════════════ U4: счётчик замечает правку файла

def test_recount_notices_a_changed_file(tmp_path):
    """Владелец правит базу в редакторе — счётчик обязан это заметить."""
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

    api.sources()                      # опрос панели замечает правку
    for _ in range(50):
        if api.sources()["emails"]["lines"] == 1:
            break
        time.sleep(0.05)
    assert api.sources()["emails"]["lines"] == 1, "счётчик остался прежним"


def test_recount_does_not_fire_when_nothing_changed(tmp_path):
    """Контроль: нетронутый файл не пересчитывается на каждом опросе.

    Иначе гигабайтный список читался бы заново дважды в секунду, и окно
    легло бы от собственной заботы.
    """
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


# ══════════════════════════ U5: полоса прогресса

def test_proxy_progress_shows_that_work_is_going():
    """Проверка прокси идёт без знаменателя — но полоса не должна лежать."""
    css = read("ui/web/style.css")
    assert ".progress__track.is-running" in css
    assert "@keyframes progress-sweep" in css

    app = read("ui/web/app.js")
    assert '$("#progressTrack").classList.add("is-running")' in app
    assert '$("#progressTrack").classList.remove("is-running")' in app

    html = read("ui/web/index.html")
    assert 'id="progressTrack"' in html


def test_proxy_progress_does_not_fake_a_percent():
    """Контроль: бегущая полоса не притворяется процентом.

    Число «сколько прокси всего» неизвестно, пока файл читается, и рисовать
    из него проценты значило бы врать.
    """
    app = read("ui/web/app.js")
    running = app[app.index("if (px.running)"):]
    running = running[:running.index("} else {")]
    assert 'setText($("#progressPct"), "")' in running, (
        "в фазе прокси показывается процент, которого не существует")


# ══════════════════════════ U6: формулировки

def test_wording_rejected_list_does_not_threaten_the_base():
    """«Убить всю базу» читается как угроза, хотя смысл обратный."""
    filters = code("core/filters.py")
    assert "убить всю базу" not in filters, "прежняя формулировка вернулась"
    assert "не пострадала" in filters
    assert "[DEAD] Список" not in filters, (
        "отклонение списка — не авария, красным его метить не за что")


def test_wording_update_skipped_is_not_an_error():
    """Обновление, которое не взяли, — не «источник испорчен»."""
    parser = code("core/github_parser.py")
    assert "источник испорчен" not in parser
    assert "обновление не взято" in parser
    assert "база не тронута" in parser


def test_wording_control_real_failures_stay_loud():
    """Контроль: настоящие аварии остались красными.

    Смягчив всё подряд, можно было бы утопить сообщение, которое владельцу
    обязательно надо увидеть, — например «все прокси выбыли».
    """
    pipeline = read("core/pipeline.py")
    assert '"[DEAD] Все прокси выбыли из ротации' in pipeline
    assert "ПОТЕРЯНО АДРЕСОВ" in pipeline
