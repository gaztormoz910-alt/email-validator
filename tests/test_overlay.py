# -*- coding: utf-8 -*-
import io
import os
import re
import sys
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def rule_of(css, selector):
    куски = re.findall(r"(?:^|\}|\{)\s*" + re.escape(selector) + r"\s*\{([^}]*)\}",
                       css, re.M)
    return "\n".join(куски)


class _FindEmptyParents(HTMLParser):

    def __init__(self):
        HTMLParser.__init__(self)
        self.стек = []
        self.родители = []

    def handle_starttag(self, tag, attrs):
        классы = dict(attrs).get("class", "")
        if "empty" in классы.split() and self.стек:
            родитель = self.стек[-1][1]
            if родитель:
                self.родители.append(родитель.split()[0])
        if tag not in ("img", "br", "hr", "input", "meta", "link", "path",
                       "circle", "rect", "line", "polyline", "use"):
            self.стек.append((tag, классы))

    def handle_endtag(self, tag):
        for i in range(len(self.стек) - 1, -1, -1):
            if self.стек[i][0] == tag:
                del self.стек[i:]
                break


def containers_with_empty(html):
    parser = _FindEmptyParents()
    parser.feed(html)
    return parser.родители


def test_bounded_grid_wrap_is_positioned():
    css = read("ui/web/style.css")
    тело = rule_of(css, ".grid-wrap")
    assert тело, "правила .grid-wrap нет вовсе — заглушка снова вырвется"
    assert "position: relative" in тело, (
        "у .grid-wrap нет position: relative, заглушка накроет окно: %s" % тело)


def test_bounded_empty_still_absolute():
    css = read("ui/web/style.css")
    тело = rule_of(css, ".empty")
    assert "position: absolute" in тело
    assert "inset: 0" in тело


def test_every_empty_has_a_positioned_parent():
    html = read("ui/web/index.html")
    css = read("ui/web/style.css")

    беда = []
    for контейнер in containers_with_empty(html):
        тело = rule_of(css, "." + контейнер)
        точечно = re.search(r"\." + re.escape(контейнер) +
                            r"\s+\.empty\s*\{[^}]*position:\s*static", css)
        if "position: relative" not in тело and not точечно:
            беда.append(контейнер)
    assert not беда, (
        "заглушка вырвется наружу и накроет окно у контейнеров: %s" % беда)


def test_every_empty_control_the_sweep_sees_the_real_containers():
    html = read("ui/web/index.html")
    найдено = containers_with_empty(html)
    assert len(найдено) >= 2, "разбор нашёл всего %s" % найдено
    assert "grid-wrap" in найдено, "не найден тот самый сломанный контейнер"
    assert "tablewrap" in найдено, "не найдена область результатов валидатора"


def test_still_shown_area_has_height():
    css = read("ui/web/style.css")
    тело = rule_of(css, ".grid-wrap")
    assert "min-height" in тело, "у области нет своей высоты — заглушка схлопнется"
    assert "flex: 1" in тело, "область не занимает свободное место"


def test_still_shown_empty_keeps_its_look():
    html = read("ui/web/index.html")
    блок = html[html.index('id="pGridEmpty"'):]
    блок = блок[:блок.index("</div>")]
    assert "<svg" in блок, "пропал значок"
    assert "Адреса появятся здесь" in блок


def test_validator_intact_tablewrap_unchanged():
    css = read("ui/web/style.css")
    тело = rule_of(css, ".tablewrap")
    assert "position: relative" in тело
    assert "flex: 1" in тело
    assert "min-height: 260px" in тело, "высота области результатов изменена"


def test_validator_intact_proxy_pane_override_survives():
    css = read("ui/web/style.css")
    assert '.tabpane[data-pane="proxy"] .empty' in css
    assert re.search(r'\.tabpane\[data-pane="proxy"\]\s+\.empty\s*\{[^}]*'
                     r'position:\s*static', css)
