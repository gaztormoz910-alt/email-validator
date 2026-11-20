"""Запуск и работа без ошибок: дефекты, найденные живым прогоном 20.11.2026.

Каждый найден не чтением кода, а работой программы: окно из исходников,
настоящий CLI через прокси, страница окна во встроенном браузере.
Все адреса выдуманы (домен .test).
"""
import io
import os
import re
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def _read(*parts):
    with open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


# ═══════════ прямой прогон из окна, когда прокси не заданы ═══════════════════

def _proxies_passed(sources):
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._sources["proxies"] = list(sources)
    seen = {}

    class _Pipeline:
        def start(self, **kwargs):
            seen.update(kwargs)
            return None

    api.pipeline = _Pipeline()
    api._launch_pipeline({"threads": 5, "timeout": 5})
    return seen["proxies"]


def test_no_proxy_sources_means_direct_run():
    # Пустой генератор истинен: конвейер принимал его за «прокси есть»,
    # перебирал 0 из 0 и стопорил прогон, на который дано согласие.
    proxies = _proxies_passed([])
    assert proxies is None
    assert not proxies


def test_control_proxy_sources_still_stream_lines():
    proxies = _proxies_passed([{"type": "text", "content": "198.51.100.7:1080\n198.51.100.8:1080"}])
    assert list(proxies) == ["198.51.100.7:1080", "198.51.100.8:1080"]


# ═══════════ одна копия базы имён на процесс ═════════════════════════════════

def test_predictor_shares_the_name_dataset():
    from core.parser.ml_predictor import MLPredictor
    from core.parser.name_extractor import get_name_dataset

    shared = get_name_dataset()
    assert shared is not None
    # Своя копия здесь — ещё 1,8 ГБ на процесс.
    assert MLPredictor(enable_ml=False).nd is shared
    assert MLPredictor(enable_ml=False).nd is shared


# ═══════════ CLI не падает на кириллице ══════════════════════════════════════

def test_cli_help_survives_a_latin_only_pipe():
    # Как у человека: вывод в канал, кодовая страница без кириллицы.
    env = dict(os.environ, PYTHONIOENCODING="cp1252")
    done = subprocess.run([sys.executable, "-B", "cli.py", "validate", "--help"], cwd=ROOT,
                          capture_output=True, env=env, timeout=120)
    assert done.returncode == 0, done.stderr.decode("utf-8", "replace")[-800:]
    assert "Traceback" not in done.stderr.decode("utf-8", "replace")
    # Читаемо, а не «?????».
    assert "--emails" in done.stdout.decode("utf-8", "replace")


def _written(encoding):
    from core.nullstream import _не_ронять_на_кодировке

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding=encoding)
    _не_ронять_на_кодировке(stream)
    stream.write("Проверка")
    stream.flush()
    return raw.getvalue()


def test_latin_only_stream_becomes_readable_utf8():
    # Прежде здесь была замена на «?»: не падало, но и прочесть было нельзя.
    assert _written("cp1252").decode("utf-8") == "Проверка"


def test_control_utf8_stream_stays_utf8():
    assert _written("utf-8").decode("utf-8") == "Проверка"


def test_control_cyrillic_codepage_is_left_alone():
    from core.nullstream import _не_ронять_на_кодировке

    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1251")
    _не_ронять_на_кодировке(stream)
    assert stream.encoding == "cp1251"
    stream.write("Проверка\U0001F600")      # смайлика в cp1251 нет — заменится, не упадёт
    stream.flush()
    assert raw.getvalue().decode("cp1251").startswith("Проверка")


# ═══════════ окно: вставка после «Отмены» и опрос сборщика ═══════════════════

def test_paste_submit_trusts_the_pressed_button_not_stale_return_value():
    js = _read("ui", "web", "app.js")
    head = js[js.index("pasteModal.querySelector(\"form\").addEventListener(\"submit\""):][:600]
    assert "pasteModal.returnValue === \"cancel\"" not in head
    assert "event.submitter && event.submitter.value === \"cancel\"" in head
    opening = js[js.index("function openPaste("):][:900]
    assert "pasteModal.returnValue = \"\";" in opening


def test_parser_poll_keeps_one_request_in_flight():
    js = _read("ui", "web", "app.js")
    body = js[js.index("async function parserTick()"):][:200]
    assert "if (parserBusy) return;" in body
    assert "finally { parserBusy = false; }" in body


# ═══════════ проверка установщика: ссылка без имени аккаунта в файлах ════════

def _repo_of(env_owner, env_name, origin):
    import importlib.util

    spec = importlib.util.spec_from_file_location("ci_check", os.path.join(ROOT, "tools", "check_installed.py"))
    module = importlib.util.module_from_spec(spec)
    old = {k: os.environ.get(k) for k in ("GITHUB_REPOSITORY_OWNER", "GITHUB_REPOSITORY_NAME")}
    try:
        for key, value in (("GITHUB_REPOSITORY_OWNER", env_owner), ("GITHUB_REPOSITORY_NAME", env_name)):
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        spec.loader.exec_module(module)
        real_run = module.subprocess.run

        def fake_run(cmd, **kw):
            if cmd[:3] == ["git", "remote", "get-url"]:
                return subprocess.CompletedProcess(cmd, 0, stdout=origin + "\n", stderr="")
            return real_run(cmd, **kw)

        module.subprocess.run = fake_run
        try:
            return module._репозиторий()
        finally:
            module.subprocess.run = real_run
    finally:
        for key, value in old.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.mark.parametrize("origin", [
    "git@github-alias:owner-x/email-validator.git",
    "https://github.com/owner-x/email-validator.git",
    "https://github.com/owner-x/email-validator",
])
def test_release_repo_comes_from_origin(origin):
    assert _repo_of(None, None, origin) == ("owner-x", "email-validator")


def test_environment_wins_over_origin():
    assert _repo_of("ci-owner", "ci-repo", "git@github.com:owner-x/email-validator.git") == ("ci-owner", "ci-repo")


def test_no_placeholder_account_in_installer_check():
    src = _read("tools", "check_installed.py")
    # Заглушка «validator» вела на чужой адрес и давала 404.
    assert not re.search(r'GITHUB_REPOSITORY_OWNER",\s*"validator"', src)
