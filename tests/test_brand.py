# -*- coding: utf-8 -*-
import ast
import io
import os
import subprocess
import sys
import tempfile
import unittest

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, КОРЕНЬ)

ОКНО = os.path.join(КОРЕНЬ, "ui", "webapp.py")
СТРАНИЦА = os.path.join(КОРЕНЬ, "ui", "web", "index.html")
ФАЙЛЫ_СТРАНИЦЫ = ("index.html", "app.js", "style.css")


def читать(путь):
    return io.open(путь, encoding="utf-8").read()


def версия_репозитория():
    return читать(os.path.join(КОРЕНЬ, "VERSION")).strip()


def имя_программы():
    for узел in ast.walk(ast.parse(читать(ОКНО), ОКНО)):
        if (isinstance(узел, ast.Assign) and len(узел.targets) == 1
                and isinstance(узел.targets[0], ast.Name)
                and узел.targets[0].id == "APP_NAME"
                and isinstance(узел.value, ast.Constant)):
            return узел.value.value
    raise AssertionError("APP_NAME в ui/webapp.py не найден")


def заголовок_окна(текст, путь=ОКНО):
    for узел in ast.walk(ast.parse(текст, путь)):
        if (isinstance(узел, ast.Call)
                and isinstance(узел.func, ast.Attribute)
                and узел.func.attr == "create_window"
                and узел.args):
            return узел.args[0]
    return None


def версия_в_заголовке(текст, путь=ОКНО):
    узел = заголовок_окна(текст, путь)
    if узел is None:
        return ["вызова create_window нет вовсе"]
    найдено = []
    for вложенный in ast.walk(узел):
        if (isinstance(вложенный, ast.Call)
                and isinstance(вложенный.func, ast.Name)
                and вложенный.func.id == "app_version"):
            найдено.append("app_version() в заголовке")
        if isinstance(вложенный, ast.Name) and вложенный.id == "app_version":
            найдено.append("имя app_version в заголовке")
    return найдено


def зовёт_журнал_окна(текст, имя_функции, путь=ОКНО):
    дерево = ast.parse(текст, путь)
    for узел in ast.walk(дерево):
        подходит = (isinstance(узел, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and узел.name == имя_функции)
        if not подходит:
            continue
        найдено = []
        for вложенный in ast.walk(узел):
            if (isinstance(вложенный, ast.Call)
                    and isinstance(вложенный.func, ast.Attribute)
                    and вложенный.func.attr == "_on_log"):
                найдено.append("строка %d" % вложенный.lineno)
        return найдено
    raise AssertionError("функция %s не найдена" % имя_функции)


def зовёт_журнал_диска(текст, имя_функции, путь=ОКНО):
    for узел in ast.walk(ast.parse(текст, путь)):
        if (isinstance(узел, (ast.FunctionDef, ast.AsyncFunctionDef))
                and узел.name == имя_функции):
            for вложенный in ast.walk(узел):
                if (isinstance(вложенный, ast.Call)
                        and isinstance(вложенный.func, ast.Name)
                        and вложенный.func.id == "log_crash"):
                    return True
            return False
    raise AssertionError("функция %s не найдена" % имя_функции)


class TestВерсииВОкнеНет(unittest.TestCase):

    def test_в_заголовке_окна_версии_нет(self):
        self.assertEqual(версия_в_заголовке(читать(ОКНО)), [])

    def test_поиск_версии_в_заголовке_умеет_находить(self):
        подсадка = "\n".join([
            "import webview",
            "def run():",
            "    # в примечании про версию — это просто текст",
            '    webview.create_window(f"{APP_NAME} {app_version()}", адрес)',
        ])
        self.assertNotEqual(версия_в_заголовке(подсадка, "<проба>"), [])

    def test_контроль_чистый_заголовок_считается_чистым(self):
        подсадка = "\n".join([
            "import webview",
            "def run():",
            "    webview.create_window(APP_NAME, адрес)",
        ])
        self.assertEqual(версия_в_заголовке(подсадка, "<проба>"), [])

    def test_окно_вообще_не_знает_про_app_version(self):
        self.assertNotIn("app_version", читать(ОКНО))

    def test_на_странице_версии_нет(self):
        версия = версия_репозитория()
        for имя in ФАЙЛЫ_СТРАНИЦЫ:
            текст = читать(os.path.join(КОРЕНЬ, "ui", "web", имя))
            self.assertNotIn(версия, текст, "версия попала в %s" % имя)

    def test_страница_отдаётся_без_подстановки_версии(self):
        разметка = читать(СТРАНИЦА)
        for метка in ("__VERSION__", "{{version}}", "{version}"):
            self.assertNotIn(метка, разметка)


class TestИмяВШапке(unittest.TestCase):

    def test_в_шапке_стоит_имя_программы(self):
        разметка = читать(СТРАНИЦА)
        имя = имя_программы()
        self.assertIn("<b>%s</b>" % имя, разметка,
                      "в шапке не имя программы %r" % имя)

    def test_прежнего_названия_не_осталось(self):
        for имя in ФАЙЛЫ_СТРАНИЦЫ:
            текст = читать(os.path.join(КОРЕНЬ, "ui", "web", имя))
            self.assertNotIn("Email Validator", текст,
                             "прежнее название осталось в %s" % имя)

    def test_заголовок_вкладки_тоже_имя_программы(self):
        self.assertIn("<title>%s</title>" % имя_программы(), читать(СТРАНИЦА))


class TestСамодиагностикаМолчитВОкне(unittest.TestCase):

    МОЛЧУНЫ = ("check_once", "check_rate", "_announce_past_crashes")

    def test_сторож_и_уведомление_не_пишут_в_журнал_окна(self):
        текст = читать(ОКНО)
        for имя in self.МОЛЧУНЫ:
            self.assertEqual(зовёт_журнал_окна(текст, имя), [],
                             "%s снова пишет в журнал окна" % имя)

    def test_поиск_записи_в_журнал_умеет_находить(self):
        подсадка = "\n".join([
            "def check_rate(self):",
            "    # в примечании сказано, что _on_log звать не надо",
            '    self.api._on_log("что-то", "dead")',
        ])
        self.assertNotEqual(
            зовёт_журнал_окна(подсадка, "check_rate", "<проба>"), [])

    def test_след_на_диске_остался(self):
        текст = читать(ОКНО)
        for имя in ("check_once", "check_rate"):
            self.assertTrue(зовёт_журнал_диска(текст, имя),
                            "%s перестала писать в crash.log" % имя)


class TestПятоеМестоСверкиВерсий(unittest.TestCase):

    def test_программа_называет_свою_версию(self):
        файл = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        файл.close()
        try:
            вышло = subprocess.run(
                [sys.executable, "-X", "utf8", "main.py", "--version", файл.name],
                cwd=КОРЕНЬ, capture_output=True, timeout=300)
            self.assertEqual(вышло.returncode, 0,
                             вышло.stderr.decode("utf-8", "replace")[:500])
            сказано = читать(файл.name).strip()
        finally:
            os.unlink(файл.name)
        self.assertEqual(сказано, версия_репозитория())

    def test_сверка_версий_всё_ещё_спрашивает_программу(self):
        текст = читать(os.path.join(КОРЕНЬ, "tools", "check_version.py"))
        self.assertIn("def версия_от_программы", текст,
                      "способ спросить версию у программы исчез")
        self.assertIn("версия_от_программы(exe)", текст,
                      "способ есть, но пятый пункт им не пользуется")
        self.assertIn("5.", текст, "пятого пункта не осталось")

    def test_установленная_копия_проверяется_на_отсутствие_версии(self):
        текст = читать(os.path.join(КОРЕНЬ, "tools", "check_installed.py"))
        self.assertIn("версия not in заголовок", текст,
                      "отсутствие версии в заголовке никем не сторожится")


if __name__ == "__main__":
    unittest.main()
