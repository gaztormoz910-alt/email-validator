# -*- coding: utf-8 -*-
"""Сколько загружено и что именно считает полоса прогресса.

Разобрано по девяти скриншотам владельца. На всех девяти разница между
«проверено» и «из» держится на 2698-2699 — то есть второе число не итог, а
«сколько прочитано на сейчас», и читатель бежит впереди проверяющего на
постоянный буфер. Считались там прокси, а карточки рядом — про почты, и все с нулями.

Вторая беда с тех же снимков: в окне написано «5 источника» и «13 источника»
— это число ФАЙЛОВ. Сколько адресов и прокси загружено, узнать было негде.
"""
import io
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def wait_for_count(api, kind, tries=60):
    """Счёт идёт в фоне, поэтому ждём его, а не спим наугад."""
    for _ in range(tries):
        value = api.sources()[kind]["lines"]
        if value is not None:
            return value
        time.sleep(0.05)
    return api.sources()[kind]["lines"]


# ═══════════════════════════════ G1: видно, сколько строк загружено

def test_loaded_lines_are_reported_for_pasted_text():
    """«13 источника» не отвечает на вопрос «сколько прокси я загрузил»."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "a@gmail.com\nb@mail.ru\nc@yahoo.com"})
    assert wait_for_count(api, "emails") == 3


def test_loaded_lines_add_up_across_sources(tmp_path):
    """Файл плюс вставка — одно число на всё поле, а не на последний источник."""
    from ui.webapp import ValidatorApi

    path = tmp_path / "base.txt"
    io.open(path, "w", encoding="utf-8").write("d@gmail.com\ne@gmail.com\n")

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "a@gmail.com\nb@mail.ru"})
    api._sources["emails"].append({"type": "file", "path": str(path)})
    api._recount("emails")
    assert wait_for_count(api, "emails") == 4


def test_loaded_lines_reported_for_every_field():
    """Все четыре поля, а не только база: прокси и дорки грузят так же."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080\n5.6.7.8:1080"})
    api.paste({"kind": "dorks", "text": 'site:vk.com "@mail.ru"'})
    api.paste({"kind": "pproxy", "text": "9.9.9.9:3128"})
    assert wait_for_count(api, "proxies") == 2
    assert wait_for_count(api, "dorks") == 1
    assert wait_for_count(api, "pproxy") == 1


def test_loaded_lines_reset_to_zero_after_clearing():
    """Очистка обнуляет число, а не оставляет прежнее."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "a@gmail.com\nb@gmail.com"})
    assert wait_for_count(api, "emails") == 2
    api.clear({"kind": "emails"})
    assert api.sources()["emails"]["lines"] == 0


def test_loaded_lines_do_not_replace_the_file_count():
    """Оба числа нужны: сколько файлов и сколько в них строк."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "a@gmail.com\nb@gmail.com"})
    wait_for_count(api, "emails")
    info = api.sources()["emails"]
    assert info["count"] == 1        # источник один
    assert info["lines"] == 2        # строк в нём две


# ═══════════════════════════════ G2: счёт не вешает окно

def test_counting_is_background_and_answers_immediately(tmp_path):
    """Ответ страницы не ждёт чтения файла.

    count_total_lines() читает файл целиком: на гигабайтном списке это
    десятки секунд. В потоке, который обслуживает страницу, они превратились
    бы в зависшее окно сразу после выбора файла.
    """
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
    """None и 0 — разные ответы.

    Ноль владелец прочитает как «файл пустой» и полезет искать несуществующую
    проблему. «Считаю…» — это честное «пока не знаю».
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._sources["emails"].append({"type": "text", "content": "a@gmail.com"})
    api._recount("emails")
    # Сразу после запуска значение либо уже посчитано, либо ещё None —
    # но нулём при непустом источнике оно не бывает никогда.
    assert api.sources()["emails"]["lines"] != 0


def test_counting_ignores_a_stale_answer(tmp_path):
    """Пока считали, владелец добавил файл — старый ответ записывать нельзя."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._sources["emails"].append({"type": "text", "content": "a@gmail.com"})
    api._recount("emails")
    wait_for_count(api, "emails")

    api._sources["emails"].append({"type": "text", "content": "b@gmail.com\nc@gmail.com"})
    api._recount("emails")
    assert wait_for_count(api, "emails") == 3


# ═══════════════════════════════ G3: прокси и почты — разные каналы

def test_separate_channel_for_proxy_progress():
    """Конвейер отдаёт прогресс прокси не туда же, куда прогресс почт."""
    import inspect

    from core import pipeline

    source = inspect.getsource(pipeline)
    call = source[source.index("live_proxies, total_seen = filter_live_proxies"):]
    call = call[:call.index(")")]
    assert "on_proxy_progress" in source
    assert "self.callbacks['on_progress']" not in call


def test_separate_channel_does_not_move_the_email_bar():
    """Проверка прокси не двигает полосу проверки адресов."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_proxy_progress(16891, 19590)
    state = api.state()
    assert state["progress"] == {"current": 0, "total": 0, "pct": 0}
    assert state["proxyProgress"]["checked"] == 16891
    assert state["proxyProgress"]["seen"] == 19590


def test_separate_channel_is_optional_for_old_callers():
    """Старый набор обратных вызовов без нового ключа не должен падать.

    Пайплайн зовёт его через .get(): вызывающий, который про новый канал не
    знает, просто не увидит прогресс прокси — но прогон не сломается.
    """
    from core.pipeline import ValidationPipeline

    pipe = ValidationPipeline(callbacks={"on_log": lambda *a: None})
    assert pipe.callbacks.get("on_proxy_progress") is None


def test_separate_channel_reaches_both_windows():
    """Оба окна подписаны на новый канал — иначе одно из них снова врёт."""
    web = io.open(os.path.join(ROOT, "ui", "webapp.py"), encoding="utf-8").read()
    classic = io.open(os.path.join(ROOT, "ui", "gui.py"), encoding="utf-8").read()
    assert "on_proxy_progress" in web
    assert "on_proxy_progress" in classic


# ═══════════════════════════════ G4: «прочитано» — не «итог»

def test_not_a_total_has_no_percentage():
    """Процента от неизвестного целого не бывает.

    Пока источник читается, второе число растёт. Делить на него и называть
    результат процентом — значит показывать 86% там, где доля неизвестна.
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_proxy_progress(16891, 19590)
    assert "pct" not in api.state()["proxyProgress"]


def test_not_a_total_is_marked_running_until_emails_start():
    """Пока идёт проверка прокси, окно знает, что показывать надо её."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_proxy_progress(100, 2799)
    assert api.state()["proxyProgress"]["running"] is True

    # Пошли адреса — полоса возвращается к ним.
    api._on_progress(5, 100)
    assert api.state()["proxyProgress"]["running"] is False
    assert api.state()["progress"]["pct"] == 5


def test_not_a_total_log_line_does_not_look_like_a_fraction():
    """`100/2799` читается как доля от известного целого. Это не так."""
    import inspect

    from core import proxy_probe

    source = inspect.getsource(proxy_probe)
    assert "Проверено: {c} | Прочитано: {t}" in source
    assert "Проверка... {c}/{t}" not in source


def test_not_a_total_growth_matches_what_the_screenshots_showed():
    """Воспроизведение картины со снимков: «итог» рос вместе с проверенным.

    Девять снимков подряд: 16891/19590, 16981/19679, 17068/19767 … Разрыв
    держится на 2698-2699 — это постоянный буфер, на который читатель обгоняет
    проверяющего. Растёт не «итог», растёт прочитанное.
    """
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


# ═══════════════════════════════ G5: страница это показывает

def test_page_shows_the_line_count():
    """Проверяется файл страницы, а не намерение."""
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
    """«1 строка», «2 строки», «5 строк» — иначе подпись выглядит машинной."""
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    assert 'plural(info.lines, "строка", "строки", "строк")' in js


# ═══════════════════════════════ G6: классическое окно тоже

def test_classic_too_separates_the_two_progresses():
    classic = io.open(os.path.join(ROOT, "ui", "gui.py"), encoding="utf-8").read()
    assert "safe_proxy_progress" in classic
    assert "Проверяю прокси" in classic
    assert "Проверка адресов..." in classic


def test_classic_too_still_counts_loaded_lines():
    """В прежнем окне счёт строк был и остаётся — из него он и потерялся."""
    classic = io.open(os.path.join(ROOT, "ui", "gui.py"), encoding="utf-8").read()
    assert "_count_lines_async" in classic
    assert "Загружено строк" in classic
