# -*- coding: utf-8 -*-
"""У собранной программы нет потоков вывода — и она не имеет права падать.

ЧТО ЗДЕСЬ СТОРОЖИТСЯ. Замерено 11.09.2026 на релизе 1.1.8: владелец нажимал
«Выберите файл» и получал `choose: AttributeError: 'NoneType' object has no
attribute 'write'`. Не работали ВСЕ ЧЕТЫРЕ диалога: выбор базы, две выгрузки
и выбор папки.

ЦЕПОЧКА, ИЗМЕРЕННАЯ ЗДЕСЬ ЖЕ (класс TestКакВСобраннойПрограмме воспроизводит
её целиком, в отдельном процессе):

1. `webview.OPEN_DIALOG` — не константа, а СВОЙСТВО МОДУЛЯ: при каждом
   обращении оно пишет предупреждение об устаревании через `logging`.
2. Обработчиков у того логгера нет, поэтому запись идёт через
   `logging.lastResort`, а он берёт `sys.stderr` В МОМЕНТ ЗАПИСИ.
3. У сборки с `console=False` `sys.stderr` равен None — и вот тонкость,
   которую легко описать неверно. САМ ПО СЕБЕ None БЕЗОПАСЕН: `handleError`
   начинается с `if raiseExceptions and sys.stderr:` и при None молча ничего
   не делает. Ронял ДРУГОЙ поток — тот, что ЕСТЬ, но при записи падает.
4. Такой поток создавал сам `main.py`: строка `sys.stderr =
   StderrFilter(sys.stderr)` оборачивала None и давала объект, истинный по
   `if`, но с падающим `write`. `handleError` доходил до `sys.stderr.write`,
   ловил там ТОЛЬКО `OSError`, и `AttributeError` уезжал наружу — тому, кто
   всего лишь позвал функцию. В окне это становилось ответом 500.

Замер, на котором это установлено (отдельный процесс, без перехвата pytest):

    stderr=None          -> НЕ УПАЛО
    stderr=Фильтр(None)  -> AttributeError: 'NoneType' object has no attribute 'write'

К каждой проверке приложен ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — воспроизведение исходного
сбоя. Без него зелёный тест не отличить от теста, который ничего не умеет
находить: именно так прошлая проба диалога была зелёной — она подменяла
потоки под собой и этим убирала условие, которое искала.
"""
import io
import logging
import os
import subprocess
import sys
import tempfile
import unittest

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, КОРЕНЬ)

from core.nullstream import ТихийПоток, ensure_streams  # noqa: E402


class _БезПотоков:
    """Процесс без stdout и stderr — как у сборки с console=False."""

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
    """Дословно то, что было в main.py до правки.

    Вынесен отдельно, потому что нужен двум контролям: здешнему и тому, что
    запускается в дочернем процессе.
    """

    def __init__(self, поток):
        self.original_stderr = поток

    def write(self, msg):
        self.original_stderr.write(msg)

    def flush(self):
        self.original_stderr.flush()


class TestИсходныйСбойВоспроизводится(unittest.TestCase):
    """ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: без правки оно обязано ломаться.

    Если эти тесты перестанут показывать сбой на старом коде, значит
    проверки ниже больше ничего не сторожат.
    """

    def test_запись_в_отсутствующий_поток_даёт_ту_самую_ошибку(self):
        with self.assertRaises(AttributeError) as поймано:
            ФильтрКакБыл(None).write("что угодно")
        self.assertIn("'NoneType' object has no attribute 'write'",
                      str(поймано.exception))

    def test_пустой_stderr_сам_по_себе_молчит(self):
        """Тонкость, без которой чинили бы не то.

        Отсутствие потока НЕ роняет: `handleError` проверяет `sys.stderr` на
        истинность и при None не делает ничего. Если бы дело было только в
        None, сбоя у владельца не было бы вовсе — и причину пришлось бы
        искать заново.
        """
        логгер = logging.getLogger("проба.stderr.none")
        логгер.handlers = []
        логгер.propagate = False
        логгер.setLevel(logging.WARNING)
        with _БезПотоков(stdout=None, stderr=None):
            логгер.warning("предупреждение об устаревании")  # не должно упасть

    def test_сломанный_stderr_роняет_вызывающего(self):
        """А вот ЭТО и был сбой владельца.

        Поток есть, по `if` он истинный, но `write` падает. `handleError`
        ловит внутри себя только `OSError`, поэтому `AttributeError` проходит
        насквозь и достаётся тому, кто всего лишь позвал функцию.

        Обработчик логгеру НЕ ставим намеренно: у чужой библиотеки его тоже
        нет, и запись идёт через `logging.lastResort`, который берёт
        `sys.stderr` в момент записи. Поставленный обработчик захватил бы
        поток заранее и проверял бы не тот путь.
        """
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
    """ensure_streams обязан дать процессу пригодные потоки."""

    def test_из_ничего_получаются_пишущие_потоки(self):
        with _БезПотоков():
            сделано = ensure_streams()
            self.assertEqual(сделано, {"stdout": "тихий", "stderr": "тихий"})
            # Главное: писать теперь можно, и это не падает.
            sys.stdout.write("проба")
            sys.stderr.write("проба")
            sys.stdout.flush()

    def test_годные_потоки_не_трогаются(self):
        """Чужой выбор не переписываем: если поток есть, он и остаётся."""
        мой = io.StringIO()
        with _БезПотоков(stdout=мой, stderr=мой):
            сделано = ensure_streams()
            self.assertEqual(сделано, {"stdout": "был", "stderr": "был"})
            self.assertIs(sys.stdout, мой)

    def test_поток_без_write_считается_негодным(self):
        """Объект есть, а писать нельзя — это то же самое, что его нет."""

        class Пустышка:
            pass

        with _БезПотоков(stdout=Пустышка(), stderr=Пустышка()):
            сделано = ensure_streams()
            self.assertEqual(сделано["stdout"], "тихий")
            sys.stdout.write("проба")

    def test_логгер_после_правки_не_роняет_вызывающего(self):
        """Тот же случай, что в контроле выше, но с заведёнными потоками.

        Фильтр оборачивает уже ГОДНЫЙ поток — и цепочка рвётся на первом же
        звене: писать есть куда, до `handleError` дело не доходит.
        """
        логгер = logging.getLogger("проба.stderr.починен")
        логгер.handlers = []
        логгер.propagate = False
        логгер.setLevel(logging.WARNING)
        with _БезПотоков():
            ensure_streams()
            sys.stderr = ФильтрКакБыл(sys.stderr)
            логгер.warning("предупреждение об устаревании")

    def test_поток_с_узкой_кодировкой_перестаёт_падать(self):
        """Второй способ убить программу печатью — консоль без кириллицы.

        ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ внутри теста: до ensure_streams та же запись
        обязана падать. Иначе «не упало» означало бы, что проверка взяла
        поток, которому кириллица и так по зубам.

        Замерено 11.09.2026: самотест из исходников падал на собственной
        строке — UnicodeEncodeError: 'charmap' codec can't encode characters.
        """
        def узкий():
            # cp1252 кириллицу не умеет — как консоль Windows по умолчанию.
            return io.TextIOWrapper(io.BytesIO(), encoding="cp1252",
                                    newline="")

        # Контроль: без правки — падает.
        контрольный = узкий()
        with self.assertRaises(UnicodeEncodeError):
            контрольный.write("проба вывода")
            контрольный.flush()

        поток = узкий()
        with _БезПотоков(stdout=поток, stderr=поток):
            сделано = ensure_streams()
            self.assertEqual(сделано["stdout"], "был")
            # Поток тот же самый — его не подменили, а научили не падать.
            self.assertIs(sys.stdout, поток)
            sys.stdout.write("проба вывода")
            sys.stdout.flush()
        self.assertEqual(поток.errors, "replace")

    def test_поток_без_reconfigure_не_ломает_заведение(self):
        """Не всякий поток умеет reconfigure — это не повод падать."""

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
        # Дескриптор честно отсутствует: выдуманный номер заставил бы чужую
        # библиотеку писать в чужой файл.
        with self.assertRaises(OSError):
            п.fileno()


class TestКакВСобраннойПрограмме(unittest.TestCase):
    """Сквозная проверка в настоящих условиях сборки: потоков нет.

    Отдельный процесс нужен потому, что pytest подменяет `sys.stdout` и
    `sys.stderr` своими перехватчиками, а проверяется ровно их ОТСУТСТВИЕ.
    Внутри pytest такое условие создать нельзя — оно тут же чинится.
    """

    def _итог(self, строки):
        """Гоняет дочерний python. Возвращает (код возврата, строку итога).

        Итог передаётся через файл, а не через печать: печатать дочернему
        некуда, у него нет потоков — в том и смысл проверки.
        """
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
        """ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ для сквозной проверки ниже.

        Воспроизводит `main.py` ДО правки: потоков нет, и фильтр оборачивает
        пустоту. Без этого контроля зелёный тест ниже ничего бы не значил.
        """
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
        # Файл дописан — значит дочерний дошёл до конца и итог настоящий.
        self.assertIn("AttributeError", итог,
                      "старый код перестал ломаться — проверка ниже пуста")
        # А код возврата у него НЕ нулевой, и это второй симптом той же
        # поломки: замерено 11.09.2026 — 120, то есть CPython не сумел
        # сбросить сломанные потоки при выходе. Программа ломалась дважды.
        self.assertNotEqual(код, 0,
                            "до правки процесс обязан завершаться с ошибкой")

    def test_после_правки_программа_переживает_отсутствие_потоков(self):
        """Настоящий main.py в настоящих условиях сборки.

        Импортируем именно `main` — тот самый модуль, который запускается у
        владельца. Своя копия его строк проверяла бы копию, а не программу.
        """
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
    """Присваивания sys.stdout / sys.stderr — разбором кода, не поиском.

    ЗАЧЕМ СТОРОЖИТСЯ. Проба диалога и самотест оба начинались со строк
    `sys.stdout = лог; sys.stderr = лог`. Намерение было безобидное — вести
    журнал. Следствие оказалось обратным: подменённый поток ЧИНИЛ условие,
    которое проверка искала, и обе проверки были зелёными, пока у владельца
    не открывался ни один диалог.

    Это худший сорт проверки: не «не нашла», а «сделала так, чтобы нечего
    было находить». Поиском по тексту сторожить нельзя — в объяснениях те же
    строки названы НАМЕРЕННО, чтобы рассказать, почему так делать не надо.
    """
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
        # И обход в лоб — через setattr.
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
    """Ни проба диалога, ни самотест не подменяют потоки под собой."""

    ФАЙЛЫ = ("core/dialogprobe.py", "core/selftest.py")

    def test_ни_проба_ни_самотест_не_трогают_потоки(self):
        for имя in self.ФАЙЛЫ:
            путь = os.path.join(КОРЕНЬ, *имя.split("/"))
            текст = io.open(путь, encoding="utf-8").read()
            плохие = _подмены_потоков(текст, путь)
            self.assertEqual(плохие, [], "%s подменяет потоки: %s"
                             % (имя, плохие))

    def test_поиск_подмен_умеет_находить(self):
        """ОБРАТНЫЙ КОНТРОЛЬ: пустой список должен значить «чисто»."""
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
    """У журнала чужих сообщений обязан быть потолок.

    У crash.log он стоял с самого начала, у stdout.log его не было — чужая
    библиотека, пишущая в цикле, за ночь съела бы диск.
    """

    def _накидать(self, путь, сколько):
        with io.open(путь, "w", encoding="utf-8", newline="") as файл:
            for i in range(сколько):
                файл.write("строка %d " % i + "ч" * 900 + chr(10))

    def test_переросший_журнал_подрезается(self):
        from core import nullstream
        папка = tempfile.mkdtemp()
        путь = os.path.join(папка, "stdout.log")
        # С запасом над потолком: 900 «ч» — это 1800 байт в utf-8.
        self._накидать(путь, nullstream.ПОТОЛОК // 1800 + 200)
        было = os.path.getsize(путь)
        поток = nullstream._файл_журнала(папка)
        поток.close()
        стало = os.path.getsize(путь)
        self.assertGreater(было, nullstream.ПОТОЛОК,
                           "проба не переросла потолок — она ничего не мерит")
        self.assertLessEqual(стало, nullstream.ОСТАВЛЯТЬ)
        текст = io.open(путь, encoding="utf-8", errors="replace").read()
        # Свежее осталось, старое выброшено: разбирают всегда последнее.
        последняя = nullstream.ПОТОЛОК // 1800 + 199
        self.assertIn("строка %d " % последняя, текст)
        self.assertNotIn("строка 0 ", текст)

    def test_маленький_журнал_не_трогается(self):
        """Обратная сторона: подрезка не имеет права терять целый журнал."""
        from core import nullstream
        папка = tempfile.mkdtemp()
        путь = os.path.join(папка, "stdout.log")
        self._накидать(путь, 5)
        было = io.open(путь, encoding="utf-8").read()
        поток = nullstream._файл_журнала(папка)
        поток.close()
        self.assertEqual(io.open(путь, encoding="utf-8").read(), было)


def _обращения_к_устаревшему(текст, путь):
    """Настоящие обращения к webview.*_DIALOG — РАЗБОРОМ КОДА, не поиском.

    Поиск по строкам здесь не годится: и в этом файле, и в ui/webapp.py
    старые имена НАМЕРЕННО названы — в объяснении, почему от них ушли, и в
    запасной ветке, которая достаёт их через getattr для старых pywebview.
    Поиск по тексту считал те упоминания за обращения и краснел на чистом
    коде. Разбор видит только настоящий доступ к атрибуту.
    """
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
    """Каждый вызов create_file_dialog: идёт ли он через _тип_диалога.

    Проверка «устаревших имён нет» — отрицательная: она молчит и когда код
    чист, и когда вызовов не осталось вовсе. Эта — положительная: она
    называет КАЖДЫЙ вызов поимённо и видно, сколько их и какие.
    """
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
    """Ни одного обращения к свойствам-ловушкам в рабочем коде."""

    def test_в_окне_нет_устаревших_свойств(self):
        путь = os.path.join(КОРЕНЬ, "ui", "webapp.py")
        текст = io.open(путь, encoding="utf-8").read()
        плохие = _обращения_к_устаревшему(текст, путь)
        self.assertEqual(плохие, [], "остались обращения: %s" % плохие)

    def test_поиск_обращений_умеет_находить(self):
        """ОБРАТНЫЙ КОНТРОЛЬ к проверке выше.

        Пустой список должен означать «в коде чисто», а не «поиск сломан».
        Здесь поиску подсовывают заведомое обращение, и он обязан его найти.
        Заодно видно, что упоминания в тексте документации он НЕ считает —
        именно на них он и ловился, пока смотрел на строки, а не на код.
        """
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
        """ПОЛОЖИТЕЛЬНАЯ проверка: не «плохого нет», а «хорошее есть».

        Сломаны были все четыре диалога: выбор базы, две выгрузки и выбор
        папки. Проверять надо каждый, а не только тот, до которого владелец
        успел дойти.
        """
        путь = os.path.join(КОРЕНЬ, "ui", "webapp.py")
        вызовы = _вызовы_диалога(
            io.open(путь, encoding="utf-8").read(), путь)
        # Если вызовов вдруг не стало, проверка обязана краснеть, а не
        # молчать: пустой список — это сломанный поиск, а не чистый код.
        self.assertGreaterEqual(len(вызовы), 4,
                                "вызовов диалога меньше четырёх: %s" % вызовы)
        плохие = [в for в in вызовы if not в["через"]]
        self.assertEqual(плохие, [], "вызовы мимо помощника: %s" % плохие)
        виды = sorted(в["вид"] for в in вызовы)
        self.assertEqual(виды, ["FOLDER", "OPEN", "SAVE", "SAVE"], виды)

    def test_поиск_вызовов_умеет_находить_плохой(self):
        """ОБРАТНЫЙ КОНТРОЛЬ: вызов мимо помощника обязан быть замечен."""
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
