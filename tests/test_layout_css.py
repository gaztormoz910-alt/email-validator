# -*- coding: utf-8 -*-
import io
import os
import re
import unittest

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
СТИЛИ = os.path.join(КОРЕНЬ, "ui", "web", "style.css")

ВО_ВСЁ_ОКНО = re.compile(r"^(100%|100vh|100dvh|100svh|100lvh)$", re.I)


def без_комментариев(текст):
    return re.sub(r"/\*.*?\*/", "", текст, flags=re.S)


def правила(css):
    css = без_комментариев(css)
    итог, буфер, глубина, стек = [], "", 0, []
    for ch in css:
        if ch == "{":
            глубина += 1
            стек.append(буфер.strip())
            буфер = ""
        elif ch == "}":
            глубина -= 1
            сел = стек.pop() if стек else ""
            if not сел.startswith("@"):
                итог.append((сел, буфер))
            буфер = ""
        else:
            буфер += ch
    return итог


def нарушения(css):
    найдено = []
    for сел, тело in правила(css):
        if not re.search(r"(^|[\s,>+~])\.layout(?![\w-])", сел):
            continue
        for объявление in тело.split(";"):
            if ":" not in объявление:
                continue
            имя, _, значение = объявление.partition(":")
            имя = имя.strip().lower()
            значение = значение.replace("!important", "").strip()
            if имя in ("height", "max-height") and ВО_ВСЁ_ОКНО.match(значение):
                найдено.append("%s { %s: %s }" % (сел.strip(), имя, значение))
    return найдено


def сколько_правил_layout(css):
    return sum(1 for сел, _ in правила(css)
               if re.search(r"(^|[\s,>+~])\.layout(?![\w-])", сел))


class TestВысотаРабочейОбласти(unittest.TestCase):

    def setUp(self):
        self.css = io.open(СТИЛИ, encoding="utf-8").read()

    def test_разбор_вообще_видит_правила(self):
        сколько = сколько_правил_layout(self.css)
        self.assertGreaterEqual(сколько, 3,
                                "разбор нашёл всего %d правил .layout" % сколько)

    def test_высота_нигде_не_во_всё_окно(self):
        плохие = нарушения(self.css)
        self.assertEqual(плохие, [], "высота рабочей области задана во всё "
                                     "окно — шапка не вычтена: %s" % плохие)

    def test_базовое_правило_вычитает_шапку(self):
        есть = [сел for сел, тело in правила(self.css)
                if ".layout" in сел and "--topbar-h" in тело
                and re.search(r"height\s*:", тело)]
        self.assertTrue(есть, "ни одно правило .layout не вычитает --topbar-h")

    def test_ловит_подсунутый_дефект(self):
        поддельный = """
        .layout { height: calc(100% - var(--topbar-h)); }
        @media (max-width: 900px) {
          .layout { height: 100%; max-height: 100%; overflow-y: auto; }
        }
        """
        плохие = нарушения(поддельный)
        self.assertEqual(len(плохие), 2, "не пойман явный дефект: %s" % плохие)

    def test_не_придирается_к_правильному(self):
        хороший = """
        .layout { height: calc(100% - var(--topbar-h)); }
        @media (max-width: 900px) {
          .layout { max-height: calc(100% - var(--topbar-h)); overflow-y: auto; }
        }
        .side__scroll { height: 100%; }
        """
        self.assertEqual(нарушения(хороший), [])


if __name__ == "__main__":
    unittest.main()
