# -*- coding: utf-8 -*-
"""Заглушка «здесь пока пусто» не должна накрывать окно и глотать клики.

ГЛАВНАЯ ПОЛОМКА ОКНА, и стоила она одной строки CSS.

Владелец пять раз показывал одно и то же: после перехода на вкладку
«Найденные адреса» интерфейс перестаёт отвечать на клики. Пять раз я не мог
воспроизвести и предлагал другие объяснения — все неверные.

Мешал мой стенд: у браузерной панели был нулевой размер окна
(innerWidth = 0), отсюда ноль кадров отрисовки, таймауты скриншотов и пустые
координаты. Я измерял поломку стенда, а не программу. После явного
resize_window(1440, 900) симптом воспроизвёлся с первой попытки.

Причина, замеренная на живой странице:

    клик по вкладке «Ход сбора» в точке (450, 212) не срабатывает
    document.elementFromPoint(450, 212) -> DIV.empty «Адреса появятся здесь»
    геометрия #pGridEmpty: 1440 x 900 от (0, 0) — ВСЁ ОКНО

У `.empty` стоит `position: absolute; inset: 0`, и он обязан цепляться за
свой контейнер. `.tablewrap` у валидатора объявлен `relative` — там всё
работало. У `.grid-wrap` правила не было вовсе, то есть `static`: цепляться
не за что, и блок растянулся на всё окно прозрачной плёнкой, которая ничего
не рисует и перехватывает каждый клик.

После правки замерено там же: заглушка 1027 x 544 в своей области,
elementFromPoint на вкладке возвращает BUTTON.tab, клик срабатывает.
"""
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
    """ВСЕ тела правил для точного селектора, слитые в одно.

    Именно все, а не первое попавшееся. У `.proxy` правил два — обычное и в
    медиазапросе для узкого окна, — и первая версия этой функции возвращала
    то из них, где нужного свойства нет. Проверка ругалась на исправный
    контейнер, а я чуть не пошёл «чинить» то, что не сломано. В браузере
    применяются оба правила, значит и смотреть надо на оба.
    """
    куски = re.findall(r"(?:^|\}|\{)\s*" + re.escape(selector) + r"\s*\{([^}]*)\}",
                       css, re.M)
    return "\n".join(куски)


class _FindEmptyParents(HTMLParser):
    """Настоящий РОДИТЕЛЬ каждой заглушки, а не «что-то выше по файлу».

    Первая версия этой проверки искала заглушку в четырёх тысячах знаков
    после открывающего тега и записывала в виновные два десятка блоков,
    которые к делу отношения не имеют. Ошибку ловит только настоящий разбор
    со стеком элементов: у absolute-блока значение имеет ровно один предок —
    ближайший позиционированный, и начинается поиск с прямого родителя.
    """

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
        # Пустые теги стек не наращивают.
        if tag not in ("img", "br", "hr", "input", "meta", "link", "path",
                       "circle", "rect", "line", "polyline", "use"):
            self.стек.append((tag, классы))

    def handle_endtag(self, tag):
        for i in range(len(self.стек) - 1, -1, -1):
            if self.стек[i][0] == tag:
                del self.стек[i:]
                break


def containers_with_empty(html):
    """Классы контейнеров, В КОТОРЫХ ЛЕЖИТ заглушка.

    Разбираем разметку, а не перечисляем руками: список, набранный руками,
    устареет на следующей вкладке, и та же ошибка вернётся незамеченной.
    """
    parser = _FindEmptyParents()
    parser.feed(html)
    return parser.родители


# ══════════════════════════ O1: заглушка ограничена своей областью

def test_bounded_grid_wrap_is_positioned():
    """У области найденных адресов есть точка отсчёта для заглушки.

    Без неё абсолютный блок цепляется за окно и накрывает его целиком —
    ровно это владелец и видел пять раз.
    """
    css = read("ui/web/style.css")
    тело = rule_of(css, ".grid-wrap")
    assert тело, "правила .grid-wrap нет вовсе — заглушка снова вырвется"
    assert "position: relative" in тело, (
        "у .grid-wrap нет position: relative, заглушка накроет окно: %s" % тело)


def test_bounded_empty_still_absolute():
    """Контроль: сама заглушка по-прежнему абсолютная.

    Если «починить» её через position: static, она перестанет центрироваться
    в пустой области и уедет вверх — лечение хуже болезни.
    """
    css = read("ui/web/style.css")
    тело = rule_of(css, ".empty")
    assert "position: absolute" in тело
    assert "inset: 0" in тело


# ══════════════════════════ O2: ловим ВЕСЬ класс ошибки

def test_every_empty_has_a_positioned_parent():
    """НИ ОДНА заглушка в разметке не осталась без точки отсчёта.

    Проверка не про один найденный случай, а про класс: следующая вкладка с
    заглушкой в непозиционированном контейнере повторит ту же поломку, и
    искать её будут снова пять заходов.
    """
    html = read("ui/web/index.html")
    css = read("ui/web/style.css")

    беда = []
    for контейнер in containers_with_empty(html):
        тело = rule_of(css, "." + контейнер)
        # Заглушку могли сделать статической точечно — это тоже решение.
        точечно = re.search(r"\." + re.escape(контейнер) +
                            r"\s+\.empty\s*\{[^}]*position:\s*static", css)
        if "position: relative" not in тело and not точечно:
            беда.append(контейнер)
    assert not беда, (
        "заглушка вырвется наружу и накроет окно у контейнеров: %s" % беда)


def test_every_empty_control_the_sweep_sees_the_real_containers():
    """Контроль: разбор разметки находит настоящие контейнеры.

    Проверка выше ничего не стоит, если она смотрит в пустоту.
    """
    html = read("ui/web/index.html")
    найдено = containers_with_empty(html)
    assert len(найдено) >= 2, "разбор нашёл всего %s" % найдено
    assert "grid-wrap" in найдено, "не найден тот самый сломанный контейнер"
    assert "tablewrap" in найдено, "не найдена область результатов валидатора"


# ══════════════════════════ O3: заглушка не схлопнулась

def test_still_shown_area_has_height():
    """Область заглушки не может быть нулевой высоты.

    Если .grid-wrap не растянуть, таблица и заглушка схлопнутся в полоску, и
    надпись «Адреса появятся здесь» станет невидимой. Лечение перекрытия не
    должно отнять смысл у самого блока.
    """
    css = read("ui/web/style.css")
    тело = rule_of(css, ".grid-wrap")
    assert "min-height" in тело, "у области нет своей высоты — заглушка схлопнется"
    assert "flex: 1" in тело, "область не занимает свободное место"


def test_still_shown_empty_keeps_its_look():
    """Контроль: содержимое заглушки на месте — значок, заголовок, пояснение."""
    html = read("ui/web/index.html")
    блок = html[html.index('id="pGridEmpty"'):]
    блок = блок[:блок.index("</div>")]
    assert "<svg" in блок, "пропал значок"
    assert "Адреса появятся здесь" in блок


# ══════════════════════════ O4: валидатор не задет

def test_validator_intact_tablewrap_unchanged():
    """У результатов валидатора всё как было: там ошибки и не было."""
    css = read("ui/web/style.css")
    тело = rule_of(css, ".tablewrap")
    assert "position: relative" in тело
    assert "flex: 1" in тело
    assert "min-height: 260px" in тело, "высота области результатов изменена"


def test_validator_intact_proxy_pane_override_survives():
    """Контроль: точечное правило для вкладки прокси не потеряно.

    Там заглушка намеренно сделана статической — она занимает поток, а не
    накладывается. Снеся это правило заодно, мы сломали бы третью вкладку.
    """
    css = read("ui/web/style.css")
    assert '.tabpane[data-pane="proxy"] .empty' in css
    assert re.search(r'\.tabpane\[data-pane="proxy"\]\s+\.empty\s*\{[^}]*'
                     r'position:\s*static', css)
