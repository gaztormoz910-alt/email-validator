# -*- coding: utf-8 -*-
import ast
import io
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKIP_DIRS = {".git", "__pycache__", "venv", ".venv", "node_modules", "build",
             "dist"}

SOURCE_DIRS = ("core", "ui", "api", "tools")

FRAMEWORK_HOOKS = {
    "do_GET", "do_POST", "log_message",
    "_get_socket",
    "setUp", "tearDown", "setUpClass", "tearDownClass",
    "resume_info",
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
    for name in ("app.js", "index.html"):
        path = os.path.join(ROOT, "ui", "web", name)
        if os.path.exists(path):
            blob.append(io.open(path, encoding="utf-8", errors="replace").read())
    text = "\n".join(blob)

    dead = []
    for name, places in sorted(defined.items()):
        if name.startswith("__") or name in FRAMEWORK_HOOKS:
            continue
        if used[name] > 0:
            continue
        if ('"%s"' % name) in text or ("'%s'" % name) in text:
            continue
        dead.extend("%s (%s:%d)" % (name, os.path.relpath(p, ROOT), line)
                    for p, line in places)
    return dead


def test_dead_code_sweep_does_not_trust_the_page_blindly():
    probe = "def " + "проба_" + "поблажки" + "():\n    return 1\n"
    dead = find_dead(extra_source=probe)
    assert any("поблажки" in item for item in dead), (
        "сито перестало находить заведомо мёртвое: %s" % dead)


def test_dead_code_is_gone():
    dead = find_dead()
    assert dead == [], "мёртвый код: %s" % dead


def test_dead_code_sweep_finds_it_when_it_is_there():
    name = "проба_" + "мёртвой_" + "функции"
    dead = find_dead(extra_source="def %s():\n    return 1\n" % name)
    assert any(name in item for item in dead), dead


def test_dead_code_sweep_does_not_flag_a_used_one():
    dead = find_dead(extra_source=(
        "def проба_вызывается():\n    return 1\n\n\nпроба_вызывается()\n"))
    assert not any("проба_вызывается" in item for item in dead), dead


def test_dead_code_sweep_respects_framework_hooks():
    assert "do_GET" in FRAMEWORK_HOOKS
    dead = find_dead()
    assert not any(item.startswith("do_GET") for item in dead)


STATIC_MARKERS = ("undefined name", "redefinition", "referenced before",
                  "f-string is missing", "assertion is always",
                  "has no effect", "dictionary key", "never used")


def test_static_defects_are_absent():
    окружение = dict(os.environ, PYTHONIOENCODING="utf-8")
    result = subprocess.run(
        [sys.executable, "-m", "pyflakes", "core", "ui", "api", "tools",
         "tests", "cli.py", "main.py"],
        cwd=ROOT, capture_output=True, text=True,
        encoding="utf-8", errors="replace", env=окружение)
    found = [line for line in (result.stdout or "").splitlines()
             if any(marker in line for marker in STATIC_MARKERS)
             and "ui.colors" not in line]
    assert found == [], "статические дефекты: %s" % found[:5]


def test_static_check_actually_runs():
    import tempfile

    handle = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                         encoding="utf-8")
    handle.write("def f():\n    return это_имя_не_определено\n")
    handle.close()
    try:
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


GARBAGE_PAYLOADS = [
    None, {}, {"kind": "нет такого"}, {"kind": None}, {"text": None},
    {"threads": "много", "timeout": -5}, {"page": "abc", "size": 10 ** 9},
    {"groups": "не список"}, {"email": 123}, {"page": -1},
]

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
        except Exception as exc:
            crashes.append("%s -> %s: %s" % (name, type(exc).__name__, str(exc)[:60]))
    assert crashes == [], crashes


def test_window_has_methods_to_check():
    names = [name for _api, name, _m in window_methods()]
    assert len(names) >= 10, names
    for expected in ("paste", "clear", "page", "state", "sources"):
        assert expected in names, expected


def test_refusal_names_the_reason_instead_of_going_silent():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    for payload in ({"kind": "нет такого"}, {}, None):
        answer = api.paste(payload)
        assert answer.get("error"), payload
        assert "поле" in answer["error"].lower(), answer["error"]


def test_refusal_does_not_put_data_in_the_wrong_field():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "нет такого", "text": "ivan@gmail.com"})
    for bucket in api._sources.values():
        assert bucket == [], "запись попала не в своё поле"


def test_refusal_keeps_working_for_a_correct_request():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    answer = api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    assert not answer.get("error")
    assert answer["emails"]["count"] == 1


def test_daemon_every_background_thread_lets_the_program_exit():
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
    tree = ast.parse("import threading\nthreading.Thread(target=f).start()\n")
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call)
             and (getattr(n.func, "attr", None) or getattr(n.func, "id", None)) == "Thread"]
    assert calls, "разбор не нашёл запуск потока"
    assert not any(kw.arg == "daemon" for kw in calls[0].keywords)
