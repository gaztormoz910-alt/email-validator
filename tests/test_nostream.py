# -*- coding: utf-8 -*-
from исходники import исходник_окна, файлы_окна
import io
import logging
import os
import subprocess
import sys
import tempfile
import unittest

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, КОРЕНЬ)

from core.nullstream import ТихийПоток, ensure_streams


class _БезПотоков:

    def __init__(self, stdout=None, stderr=None):
        self._новый = (stdout, stderr)

    def __enter__(self):
        self._старый = (sys.stdout, sys.stderr)
        sys.stdout, sys.stderr = self._новый
        return self

    def __exit__(self, *_):
        sys.stdout, sys.stderr = self._старый
        return False


class ФильтрКакБыл:

    def __init__(self, поток):
        self.original_stderr = поток

    def write(self, msg):
        self.original_stderr.write(msg)

    def flush(self):
        self.original_stderr.flush()


class TestИсходныйСбойВоспроизводится(unittest.TestCase):

    def test_запись_в_отсутствующий_поток_даёт_ту_самую_ошибку(self):
        with self.assertRaises(AttributeError) as поймано:
            ФильтрКакБыл(None).write("что угодно")
        self.assertIn("'NoneType' object has no attribute 'write'",
                      str(поймано.exception))

    def test_пустой_stderr_сам_по_себе_молчит(self):
        логгер = logging.getLogger("проба.stderr.none")
        логгер.handlers = []
        логгер.propagate = False
        логгер.setLevel(logging.WARNING)
        with _БезПотоков(stdout=None, stderr=None):
            логгер.warning("предупреждение об устаревании")

    def test_сломанный_stderr_роняет_вызывающего(self):
        логгер = logging.getLogger("проба.stderr.сломан")
        логгер.handlers = []
        логгер.propagate = False
        логгер.setLevel(logging.WARNING)
        with _БезПотоков(stdout=None, stderr=ФильтрКакБыл(None)):
            with self.assertRaises(AttributeError) as поймано:
                логгер.warning("предупреждение об устаревании")
        self.assertIn("'NoneType' object has no attribute 'write'",
                      str(поймано.exception))


class TestПотокиЗаводятсяВсегда(unittest.TestCase):

    def test_из_ничего_получаются_пишущие_потоки(self):
        with _БезПотоков():
            сделано = ensure_streams()
            self.assertEqual(сделано, {"stdout": "тихий", "stderr": "тихий"})
            sys.stdout.write("проба")
            sys.stderr.write("проба")
            sys.stdout.flush()

    def test_годные_потоки_не_трогаются(self):
        мой = io.StringIO()
        with _БезПотоков(stdout=мой, stderr=мой):
            сделано = ensure_streams()
            self.assertEqual(сделано, {"stdout": "был", "stderr": "был"})
            self.assertIs(sys.stdout, мой)

    def test_поток_без_write_считается_негодным(self):

        class Пустышка:
            pass

        with _БезПотоков(stdout=Пустышка(), stderr=Пустышка()):
            сделано = ensure_streams()
            self.assertEqual(сделано["stdout"], "тихий")
            sys.stdout.write("проба")

    def test_логгер_после_правки_не_роняет_вызывающего(self):
        логгер = logging.getLogger("проба.stderr.починен")
        логгер.handlers = []
        логгер.propagate = False
        логгер.setLevel(logging.WARNING)
        with _БезПотоков():
            ensure_streams()
            sys.stderr = ФильтрКакБыл(sys.stderr)
            логгер.warning("предупреждение об устаревании")

    def test_поток_с_узкой_кодировкой_перестаёт_падать(self):
        def узкий():
            return io.TextIOWrapper(io.BytesIO(), encoding="cp1252",
                                    newline="")

        контрольный = узкий()
        with self.assertRaises(UnicodeEncodeError):
            контрольный.write("проба вывода")
            контрольный.flush()

        поток = узкий()
        with _БезПотоков(stdout=поток, stderr=поток):
            сделано = ensure_streams()
            self.assertEqual(сделано["stdout"], "был")
            self.assertIs(sys.stdout, поток)
            sys.stdout.write("проба вывода")
            sys.stdout.flush()
        self.assertEqual(поток.errors, "replace")

    def test_поток_без_reconfigure_не_ломает_заведение(self):

        class Простой:
            def write(self, т):
                return len(т)

            def flush(self):
                pass

        простой = Простой()
        with _БезПотоков(stdout=простой, stderr=простой):
            сделано = ensure_streams()
            self.assertEqual(сделано, {"stdout": "был", "stderr": "был"})
            self.assertIs(sys.stdout, простой)

    def test_тихий_поток_ведёт_себя_как_поток(self):
        п = ТихийПоток()
        self.assertEqual(п.write("пять"), 4)
        п.writelines(["а", "б"])
        п.flush()
        self.assertFalse(п.isatty())
        self.assertFalse(п.closed)
        with self.assertRaises(OSError):
            п.fileno()


class TestКакВСобраннойПрограмме(unittest.TestCase):

    def _итог(self, строки):
        файл = tempfile.NamedTemporaryFile(suffix=".txt", delete=False)
        файл.close()
        код_программы = chr(10).join(
            ["import sys", "ПУТЬ = " + repr(файл.name)]
            + строки
            + ["import io",
               "io.open(ПУТЬ, 'w', encoding='utf-8').write(итог)"])
        try:
            вышло = subprocess.run(
                [sys.executable, "-X", "utf8", "-c", код_программы],
                cwd=КОРЕНЬ, capture_output=True, timeout=180)
            прочитано = io.open(файл.name, encoding="utf-8").read()
        finally:
            os.unlink(файл.name)
        return вышло.returncode, прочитано

    def test_до_правки_логгер_ронял_программу(self):
        код, итог = self._итог([
            "import logging",
            "class Ф:",
            "    def __init__(s, п): s.original_stderr = п",
            "    def write(s, m): s.original_stderr.write(m)",
            "    def flush(s): s.original_stderr.flush()",
            "sys.stdout = None",
            "sys.stderr = Ф(None)",
            "л = logging.getLogger('чужая.библиотека')",
            "л.propagate = False",
            "try:",
            "    л.warning('предупреждение об устаревании')",
            "    итог = 'НЕ УПАЛО'",
            "except BaseException as б:",
            "    итог = type(б).__name__ + ': ' + str(б)",
        ])
        self.assertIn("AttributeError", итог,
                      "старый код перестал ломаться — проверка ниже пуста")
        self.assertNotEqual(код, 0,
                            "до правки процесс обязан завершаться с ошибкой")

    def test_после_правки_программа_переживает_отсутствие_потоков(self):
        код, итог = self._итог([
            "sys.stdout = None",
            "sys.stderr = None",
            "import main",
            "import logging",
            "л = logging.getLogger('чужая.библиотека')",
            "л.propagate = False",
            "try:",
            "    л.warning('предупреждение об устаревании')",
            "    итог = ('ok stdout=' + str(hasattr(sys.stdout, 'write'))",
            "            + ' stderr=' + str(hasattr(sys.stderr, 'write')))",
            "except BaseException as б:",
            "    итог = type(б).__name__ + ': ' + str(б)",
        ])
        self.assertEqual(код, 0, "дочерний процесс не доработал")
        self.assertEqual(итог, "ok stdout=True stderr=True",
                         "программа без потоков повела себя не так: " + итог)


def _подмены_потоков(текст, путь):
    import ast
    найдено = []
    дерево = ast.parse(текст, путь)
    for узел in ast.walk(дерево):
        цели = []
        if isinstance(узел, ast.Assign):
            цели = узел.targets
        elif isinstance(узел, (ast.AugAssign, ast.AnnAssign)):
            цели = [узел.target]
        for ц in цели:
            if (isinstance(ц, ast.Attribute) and ц.attr in ("stdout", "stderr")
                    and isinstance(ц.value, ast.Name) and ц.value.id == "sys"):
                найдено.append("строка %d: sys.%s" % (ц.lineno, ц.attr))
        if (isinstance(узел, ast.Call) and isinstance(узел.func, ast.Name)
                and узел.func.id == "setattr" and len(узел.args) >= 2
                and isinstance(узел.args[0], ast.Name)
                and узел.args[0].id == "sys"
                and isinstance(узел.args[1], ast.Constant)
                and узел.args[1].value in ("stdout", "stderr")):
            найдено.append("строка %d: setattr(sys, %r)"
                           % (узел.lineno, узел.args[1].value))
    return найдено


class TestПроверкиНеЧинятУсловие(unittest.TestCase):

    ФАЙЛЫ = ("core/dialogprobe.py", "core/selftest.py")

    def test_ни_проба_ни_самотест_не_трогают_потоки(self):
        for имя in self.ФАЙЛЫ:
            путь = os.path.join(КОРЕНЬ, *имя.split("/"))
            текст = io.open(путь, encoding="utf-8").read()
            плохие = _подмены_потоков(текст, путь)
            self.assertEqual(плохие, [], "%s подменяет потоки: %s"
                             % (имя, плохие))

    def test_поиск_подмен_умеет_находить(self):
        код = chr(10).join([
            "import sys",
            "# в примечании sys.stderr = лог — это просто текст",
            "sys.stdout = лог",
            "setattr(sys, 'stderr', лог)",
        ])
        найдено = _подмены_потоков(код, "<проба>")
        self.assertEqual(len(найдено), 2, найдено)
        self.assertTrue(any("sys.stdout" in с for с in найдено), найдено)
        self.assertTrue(any("setattr" in с for с in найдено), найдено)


class TestЖурналНеРастётБезПредела(unittest.TestCase):

    def _накидать(self, путь, сколько):
        with io.open(путь, "w", encoding="utf-8", newline="") as файл:
            for i in range(сколько):
                файл.write("строка %d " % i + "ч" * 900 + chr(10))

    def test_переросший_журнал_подрезается(self):
        from core import nullstream
        папка = tempfile.mkdtemp()
        путь = os.path.join(папка, "stdout.log")
        self._накидать(путь, nullstream.ПОТОЛОК // 1800 + 200)
        было = os.path.getsize(путь)
        поток = nullstream._файл_журнала(папка)
        поток.close()
        стало = os.path.getsize(путь)
        self.assertGreater(было, nullstream.ПОТОЛОК,
                           "проба не переросла потолок — она ничего не мерит")
        self.assertLessEqual(стало, nullstream.ОСТАВЛЯТЬ)
        текст = io.open(путь, encoding="utf-8", errors="replace").read()
        последняя = nullstream.ПОТОЛОК // 1800 + 199
        self.assertIn("строка %d " % последняя, текст)
        self.assertNotIn("строка 0 ", текст)

    def test_маленький_журнал_не_трогается(self):
        from core import nullstream
        папка = tempfile.mkdtemp()
        путь = os.path.join(папка, "stdout.log")
        self._накидать(путь, 5)
        было = io.open(путь, encoding="utf-8").read()
        поток = nullstream._файл_журнала(папка)
        поток.close()
        self.assertEqual(io.open(путь, encoding="utf-8").read(), было)


def _обращения_к_устаревшему(текст, путь):
    import ast
    устаревшие = {"OPEN_DIALOG", "SAVE_DIALOG", "FOLDER_DIALOG"}
    найдено = []
    for узел in ast.walk(ast.parse(текст, путь)):
        if (isinstance(узел, ast.Attribute)
                and узел.attr in устаревшие
                and isinstance(узел.value, ast.Name)
                and узел.value.id == "webview"):
            найдено.append("строка %d: webview.%s" % (узел.lineno, узел.attr))
    return найдено


def _вызовы_диалога(текст, путь):
    import ast
    найдено = []
    for узел in ast.walk(ast.parse(текст, путь)):
        if not (isinstance(узел, ast.Call)
                and isinstance(узел.func, ast.Attribute)
                and узел.func.attr == "create_file_dialog"):
            continue
        первый = узел.args[0] if узел.args else None
        через = (isinstance(первый, ast.Call)
                 and isinstance(первый.func, ast.Name)
                 and первый.func.id == "_тип_диалога")
        вид = None
        if через and первый.args and isinstance(первый.args[0], ast.Constant):
            вид = первый.args[0].value
        найдено.append({"строка": узел.lineno, "через": через, "вид": вид})
    return найдено


class TestДиалогиНеТрогаютУстаревшееAPI(unittest.TestCase):

    def test_в_окне_нет_устаревших_свойств(self):
        плохие = []
        for путь_модуля, текст in файлы_окна():
            плохие += _обращения_к_устаревшему(текст, путь_модуля)
        self.assertEqual(плохие, [], "остались обращения: %s" % плохие)

    def test_поиск_обращений_умеет_находить(self):
        код = chr(10).join([
            "import webview",
            "def f():",
            "    'docstring про webview.SAVE_DIALOG — просто текст'",
            "    # и webview.FOLDER_DIALOG в примечании тоже текст",
            "    return webview.OPEN_DIALOG",
        ])
        self.assertEqual(_обращения_к_устаревшему(код, "<проба>"),
                         ["строка 5: webview.OPEN_DIALOG"])

    def test_все_четыре_вызова_идут_через_помощник(self):
        вызовы = []
        for путь_модуля, текст in файлы_окна():
            вызовы += _вызовы_диалога(текст, путь_модуля)
        self.assertGreaterEqual(len(вызовы), 4,
                                "вызовов диалога меньше четырёх: %s" % вызовы)
        плохие = [в for в in вызовы if not в["через"]]
        self.assertEqual(плохие, [], "вызовы мимо помощника: %s" % плохие)
        виды = sorted(в["вид"] for в in вызовы)
        self.assertEqual(виды, ["FOLDER", "OPEN", "SAVE", "SAVE"], виды)

    def test_поиск_вызовов_умеет_находить_плохой(self):
        код = chr(10).join([
            "def f(окно):",
            "    окно.create_file_dialog(webview.OPEN_DIALOG)",
            "    окно.create_file_dialog(_тип_диалога('SAVE'))",
        ])
        вызовы = _вызовы_диалога(код, "<проба>")
        self.assertEqual([в["через"] for в in вызовы], [False, True], вызовы)

    def test_тип_диалога_отдаёт_нынешние_константы(self):
        from ui.webapp import _тип_диалога
        import webview
        for имя in ("OPEN", "SAVE", "FOLDER"):
            self.assertEqual(_тип_диалога(имя),
                             getattr(webview.FileDialog, имя))


if __name__ == "__main__":
    unittest.main()
