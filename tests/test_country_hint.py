# -*- coding: utf-8 -*-
import io
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ОЖИДАЕМЫЕ_РЕЖИМЫ = {"accuracy", "coverage"}


def читать(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def подписи_из_скрипта(app_js):
    кусок = re.search(r"const COUNTRY_HINT\s*=\s*\{(.*?)\};", app_js, re.S)
    assert кусок, "в app.js нет таблицы COUNTRY_HINT — источник подписи не един"
    пары = re.findall(r'(\w+)\s*:\s*"([^"]+)"', кусок.group(1))
    return dict(пары)


def test_активная_кнопка_совпадает_с_режимом_по_умолчанию():
    html = читать("ui/web/index.html")
    app_js = читать("ui/web/app.js")

    активная = re.search(
        r'<button class="seg__item is-active"[^>]*data-country="(\w+)"', html)
    assert активная, "ни одна кнопка режима не помечена активной"

    по_умолчанию = re.search(r'^\s*country:\s*"(\w+)",\s*$', app_js, re.M)
    assert по_умолчанию, "в app.js не найден режим страны по умолчанию"

    assert активная.group(1) == по_умолчанию.group(1), (
        "подсвечена кнопка «%s», а на сервер уйдёт «%s» — окно показывает "
        "не то, что делает" % (активная.group(1), по_умолчанию.group(1)))


def test_подпись_задана_ровно_в_одном_месте():
    html = читать("ui/web/index.html")
    найдено = re.search(r'id="countryHint"[^>]*>(.*?)</small>', html, re.S)
    assert найдено, "в разметке нет места под подпись (#countryHint)"
    assert not найдено.group(1).strip(), (
        "подпись зашита в разметку: %r. Именно так она и разошлась с "
        "обработчиком — текст должен приходить из одного места"
        % найдено.group(1).strip()[:60])


def test_у_каждого_режима_есть_своя_подпись():
    подписи = подписи_из_скрипта(читать("ui/web/app.js"))
    assert set(подписи) == ОЖИДАЕМЫЕ_РЕЖИМЫ, (
        "режимы в таблице подписей: %s, ожидались: %s"
        % (sorted(подписи), sorted(ОЖИДАЕМЫЕ_РЕЖИМЫ)))
    for режим, текст in подписи.items():
        assert len(текст.strip()) >= 20, (
            "подпись режима «%s» короче двадцати знаков — это не объяснение"
            % режим)


def test_подписи_режимов_разные():
    подписи = подписи_из_скрипта(читать("ui/web/app.js"))
    assert подписи["accuracy"] != подписи["coverage"], (
        "оба режима описаны одинаково — переключатель ничего не объясняет")


def test_подпись_рисуется_при_открытии_окна():
    app_js = читать("ui/web/app.js")
    assert "function renderCountryHint" in app_js, (
        "нет отдельной функции отрисовки подписи")

    assert re.search(r"^renderCountryHint\(\);\s*$", app_js, re.M), (
        "renderCountryHint() не вызывается при загрузке — подпись появится "
        "только после того, как владелец щёлкнет по кнопке, а до этого "
        "момента он будет читать пустоту или чужой текст")


def test_режимы_окна_совпадают_с_режимами_движка():
    import sys
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from core.parser.ml_predictor import COUNTRY_MODES

    html = читать("ui/web/index.html")
    кнопки = set(re.findall(r'<button class="seg__item[^"]*"[^>]*'
                            r'data-country="(\w+)"', html))
    assert кнопки == set(COUNTRY_MODES), (
        "кнопки окна: %s, режимы движка: %s — окно предлагает то, чего "
        "движок не знает" % (sorted(кнопки), sorted(COUNTRY_MODES)))
