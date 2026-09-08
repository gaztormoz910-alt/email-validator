# -*- coding: utf-8 -*-
"""Сита, которые ловят целые классы беспорядка, а не отдельные случаи.

Владелец спросил, точно ли в коде нет багов — особенно в юзабилити и во
внутрянке — и попросил найти лишний и мёртвый код. Обещать «багов нет»
нельзя. Что можно — прогнать сита и показать найденное числом, а потом не
дать этому вернуться.

Что нашлось при первом прогоне:

  мёртвый код          10 функций, к которым нигде нет ни одного обращения
  недостижимый код     0
  дубли определений    0
  pyflakes             4 — три повторных импорта и переменная без применения
  падения окна         19 путей: кривой запрос со страницы ронял обработчик
  потоки без демона    0 (первая прикидка дала 4, но это была ошибка grep:
                       daemon=True стоял строкой ниже)

Все проверки идут по ИСХОДНИКУ и без сети — набор должен работать на любой
машине.
"""
import ast
import io
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Каталоги, которые к работе программы отношения не имеют.
SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules", "build",
             "dist", ".unlazy"}

# Где ищем ОПРЕДЕЛЕНИЯ. Тесты и аудит сюда не входят: там определения по
# смыслу одноразовые.
SOURCE_DIRS = ("core", "ui", "api", "tools")

# Имена, которые вызывает не наш код, а чужой каркас. Обращения к ним в
# проекте нет и быть не может — их зовёт http.server, smtplib и unittest.
FRAMEWORK_HOOKS = {
    "do_GET", "do_POST", "log_message",     # http.server
    "_get_socket",                          # smtplib: точка подмены транспорта
    "setUp", "tearDown", "setUpClass", "tearDownClass",
}


def python_files(only=None):
    for base, subs, names in os.walk(ROOT):
        subs[:] = [d for d in subs if d not in SKIP_DIRS]
        rel = os.path.relpath(base, ROOT).replace(os.sep, "/")
        if only and not any(rel == d or rel.startswith(d + "/") for d in only):
            continue
        for name in names:
            if name.endswith(".py"):
                yield os.path.join(base, name)


def find_dead(extra_source=None):
    """Определения без единого обращения во всём проекте.

    Обращением считается вызов, наследование, декоратор, импорт И упоминание
    строкой: getattr(api, "page") и проверки по исходнику — тоже обращения, и
    считать их мёртвыми нельзя.

    extra_source — дополнительный кусок кода, будто он лежит в проекте.
    Нужен положительному контролю: сито, которое ничего не находит, надо
    проверить на заведомо мёртвом.
    """
    import collections

    defined = {}
    sources = []
    for path in python_files(SOURCE_DIRS):
        sources.append((path, io.open(path, encoding="utf-8", errors="replace").read()))
    if extra_source:
        sources.append(("<проба>", extra_source))

    for path, src in sources:
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                defined.setdefault(node.name, []).append((path, node.lineno))

    used = collections.Counter()
    blob = []
    everything = list(python_files())
    for path in everything:
        src = io.open(path, encoding="utf-8", errors="replace").read()
        blob.append(src)
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used[node.id] += 1
            elif isinstance(node, ast.Attribute):
                used[node.attr] += 1
    if extra_source:
        blob.append(extra_source)
        tree = ast.parse(extra_source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                used[node.id] += 1
            elif isinstance(node, ast.Attribute):
                used[node.attr] += 1
    # Страница — тоже вызывающий код. Мост в ui/webapp.py зовёт методы API
    # ПО ИМЕНИ (getattr по строке из запроса), поэтому метод, к которому
    # обращается только app.js, для питоновского сита выглядит мёртвым. Это
    # ошибка сита, а не находка: `api("resume_info")` — настоящий вызов.
    for name in ("app.js", "index.html"):
        path = os.path.join(ROOT, "ui", "web", name)
        if os.path.exists(path):
            blob.append(io.open(path, encoding="utf-8", errors="replace").read())
    text = "\n".join(blob)

    dead = []
    for name, places in sorted(defined.items()):
        if name.startswith("__") or name in FRAMEWORK_HOOKS:
            continue
        # Имя функции в определении узлом Name НЕ является, поэтому любое
        # ненулевое число здесь означает настоящее обращение.
        if used[name] > 0:
            continue
        if ('"%s"' % name) in text or ("'%s'" % name) in text:
            continue
        dead.extend("%s (%s:%d)" % (name, os.path.relpath(p, ROOT), line)
                    for p, line in places)
    return dead


# ═══════════════════════════════ G1: мёртвого кода нет

def test_dead_code_sweep_does_not_trust_the_page_blindly():
    """Контроль: поблажка для страницы не отключила сито целиком.

    Она добавлена ради методов, которые страница зовёт по имени. Если бы
    заодно прощалось любое имя, сито перестало бы находить что-либо.
    """
    probe = "def " + "проба_" + "поблажки" + "():\n    return 1\n"
    dead = find_dead(extra_source=probe)
    assert any("поблажки" in item for item in dead), (
        "сито перестало находить заведомо мёртвое: %s" % dead)


def test_dead_code_is_gone():
    """Ни одного определения без обращений.

    Было десять: старый медленный путь показа таблицы, который заменило
    хранилище; запасной фильтр по скору, чей комментарий обещал работу без
    базы, хотя звать его перестали; три моих собственных метода долгой памяти,
    написанных «на будущее»; и ещё четыре по мелочи.
    """
    dead = find_dead()
    assert dead == [], "мёртвый код: %s" % dead


# ═══════════════════════════════ G2: сито умеет находить

def test_dead_code_sweep_finds_it_when_it_is_there():
    """Положительный контроль.

    Проверка на отсутствие без него не доказывает ничего: сито, сломавшееся
    молча, отвечает «чисто» на любом коде.
    """
    # Имя собирается из кусков НАМЕРЕННО. Сито считает упоминание строкой
    # обращением — getattr(api, "page") и проверки по исходнику тоже
    # обращения, — и контроль, написавший своё имя в кавычках, погасил бы сам
    # себя: пробная функция считалась бы использованной этим самым файлом.
    name = "проба_" + "мёртвой_" + "функции"
    dead = find_dead(extra_source="def %s():\n    return 1\n" % name)
    assert any(name in item for item in dead), dead


def test_dead_code_sweep_does_not_flag_a_used_one():
    """Обратная сторона: вызванная функция мёртвой не считается."""
    dead = find_dead(extra_source=(
        "def проба_вызывается():\n    return 1\n\n\nпроба_вызывается()\n"))
    assert not any("проба_вызывается" in item for item in dead), dead


def test_dead_code_sweep_respects_framework_hooks():
    """do_GET зовёт http.server, а не мы. Он не мёртвый."""
    assert "do_GET" in FRAMEWORK_HOOKS
    dead = find_dead()
    assert not any(item.startswith("do_GET") for item in dead)


# ═══════════════════════════════ G3: статических дефектов нет

STATIC_MARKERS = ("undefined name", "redefinition", "referenced before",
                  "f-string is missing", "assertion is always",
                  "has no effect", "dictionary key", "never used")


def test_static_defects_are_absent():
    """pyflakes по всему коду: неопределённые имена, дубли, мусор.

    Шум от `from ui.colors import *` отфильтрован: имена оттуда настоящие,
    просто pyflakes не может их увидеть.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pyflakes", "core", "ui", "api", "tools",
         "tests", "cli.py", "main.py"],
        cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace")
    found = [line for line in (result.stdout or "").splitlines()
             if any(marker in line for marker in STATIC_MARKERS)
             and "ui.colors" not in line]
    assert found == [], "статические дефекты: %s" % found[:5]


def test_static_check_actually_runs():
    """Отрицательный контроль: pyflakes на заведомо битом коде ругается."""
    import tempfile

    # Файл, а не stdin: pyflakes не читает код из «-», он ищет файл с таким
    # именем и молча отвечает пустотой. Контроль, построенный на этом, всегда
    # «проходил» бы, ничего не проверяя.
    handle = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                         encoding="utf-8")
    handle.write("def f():\n    return это_имя_не_определено\n")
    handle.close()
    try:
        # Кодировку ДОЧЕРНЕГО процесса задаём явно. Имя в образце
        # кириллическое, и на консоли cp1252 pyflakes падает с
        # UnicodeEncodeError, пытаясь его напечатать: stdout приходит пустым,
        # и контроль объявляет провал там, где всё в порядке. То есть без
        # этой строки проверка меряет кодировку консоли, а не работу
        # pyflakes — и зелёная она только там, где PYTHONIOENCODING выставлен
        # руками. Замерено: с cp1252 stdout пуст, в stderr UnicodeEncodeError.
        окружение = dict(os.environ, PYTHONIOENCODING="utf-8")
        result = subprocess.run(
            [sys.executable, "-m", "pyflakes", handle.name],
            cwd=ROOT, capture_output=True, text=True,
            encoding="utf-8", errors="replace", env=окружение)
        assert "undefined name" in (result.stdout or ""), (
            "stdout=%r stderr=%r" % (result.stdout, result.stderr[-400:]))
    finally:
        os.unlink(handle.name)


def test_static_no_unreachable_code():
    """Кода после return, raise, continue и break в одном блоке нет."""
    terminal = (ast.Return, ast.Raise, ast.Continue, ast.Break)
    found = []
    for path in python_files(SOURCE_DIRS):
        try:
            tree = ast.parse(io.open(path, encoding="utf-8", errors="replace").read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            for block in (getattr(node, "body", None),
                          getattr(node, "orelse", None),
                          getattr(node, "finalbody", None)):
                if not isinstance(block, list):
                    continue
                for index, stmt in enumerate(block[:-1]):
                    if isinstance(stmt, terminal):
                        found.append("%s:%d" % (os.path.relpath(path, ROOT),
                                                block[index + 1].lineno))
    assert found == [], "недостижимый код: %s" % found[:5]


def test_static_no_duplicate_definitions():
    """Два определения с одним именем в одной области — второе затирает первое."""
    found = []
    for path in python_files(SOURCE_DIRS):
        try:
            tree = ast.parse(io.open(path, encoding="utf-8", errors="replace").read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            body = getattr(node, "body", None)
            if not isinstance(body, list):
                continue
            seen = {}
            for stmt in body:
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef,
                                     ast.ClassDef)):
                    if stmt.name in seen:
                        found.append("%s:%d %s" % (os.path.relpath(path, ROOT),
                                                   stmt.lineno, stmt.name))
                    seen[stmt.name] = stmt.lineno
    assert found == [], "дубли определений: %s" % found[:5]


# ═══════════════════════════════ G4: окно не падает на кривом запросе

GARBAGE_PAYLOADS = [
    None, {}, {"kind": "нет такого"}, {"kind": None}, {"text": None},
    {"threads": "много", "timeout": -5}, {"page": "abc", "size": 10 ** 9},
    {"groups": "не список"}, {"email": 123}, {"page": -1},
]

# Ходят в сеть или открывают диалог выбора файла — обстреливать нечем.
NEEDS_WORLD = {"choose", "export", "export_segments", "parser_start", "start",
               "save_parser", "open_folder", "pick_suppress"}


def window_methods():
    import inspect

    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    for name, method in inspect.getmembers(api, inspect.ismethod):
        if name.startswith("_") or name in NEEDS_WORLD:
            continue
        yield api, name, method


@pytest.mark.parametrize("payload", GARBAGE_PAYLOADS)
def test_window_survives_a_malformed_request(payload):
    """Страница присылает что угодно, и падать на этом нельзя.

    Мост отвечает на исключение пятисоткой с текстом вроде «ValueError:
    неизвестный вид источника» — показать такое страница не умеет, и для
    владельца это «нажал и ничего». Найдено девятнадцать таких путей.
    """
    import inspect

    crashes = []
    for _api, name, method in window_methods():
        try:
            takes = [p for p in inspect.signature(method).parameters.values()
                     if p.default is inspect.Parameter.empty]
        except (TypeError, ValueError):
            continue
        try:
            method(payload) if takes else method()
        except Exception as exc:            # noqa: BLE001 — это и ловим
            crashes.append("%s -> %s: %s" % (name, type(exc).__name__, str(exc)[:60]))
    assert crashes == [], crashes


def test_window_has_methods_to_check():
    """Отрицательный контроль: обстрел находит методы, а не пустоту."""
    names = [name for _api, name, _m in window_methods()]
    assert len(names) >= 10, names
    for expected in ("paste", "clear", "page", "state", "sources"):
        assert expected in names, expected


# ═══════════════════════════════ G5: отказ остаётся читаемым

def test_refusal_names_the_reason_instead_of_going_silent():
    """Заменить падение молчанием — обмен одной беды на другую.

    Владелец должен видеть причину: пустой ответ так же бесполезен, как
    пятисотка с именем исключения.
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    for payload in ({"kind": "нет такого"}, {}, None):
        answer = api.paste(payload)
        assert answer.get("error"), payload
        assert "поле" in answer["error"].lower(), answer["error"]


def test_refusal_does_not_put_data_in_the_wrong_field():
    """Незнакомое имя не должно приводить к «свалим в первое попавшееся».

    Так адреса однажды уехали в поле прокси — молча.
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "нет такого", "text": "ivan@gmail.com"})
    for bucket in api._sources.values():
        assert bucket == [], "запись попала не в своё поле"


def test_refusal_keeps_working_for_a_correct_request():
    """Обратная сторона: правильный запрос по-прежнему принимается."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    answer = api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    assert not answer.get("error")
    assert answer["emails"]["count"] == 1


# ═══════════════════════════════ G6: программа завершается

def test_daemon_every_background_thread_lets_the_program_exit():
    """Поток без demon и без join держит процесс после закрытия окна.

    Первая прикидка grep-ом дала четыре нарушения, и все четыре оказались
    ошибкой чтения: `daemon=True` стоял следующей строкой, а у потоков Tor
    рядом стоит join. Менять было нечего — проверка заведена, чтобы это
    осталось правдой.
    """
    offenders = []
    for path in python_files(SOURCE_DIRS):
        src = io.open(path, encoding="utf-8", errors="replace").read()
        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue
        joined = ".join()" in src
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            name = getattr(target, "attr", None) or getattr(target, "id", None)
            if name != "Thread":
                continue
            daemon = any(kw.arg == "daemon" and getattr(kw.value, "value", None) is True
                         for kw in node.keywords)
            if not daemon and not joined:
                offenders.append("%s:%d" % (os.path.relpath(path, ROOT), node.lineno))
    assert offenders == [], "поток не даст программе закрыться: %s" % offenders


def test_daemon_check_can_fail():
    """Положительный контроль для проверки выше."""
    tree = ast.parse("import threading\nthreading.Thread(target=f).start()\n")
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and (getattr(n.func, "attr", None) or getattr(n.func, "id", None)) == "Thread"]
    assert calls, "разбор не нашёл запуск потока"
    assert not any(kw.arg == "daemon" for kw in calls[0].keywords)
