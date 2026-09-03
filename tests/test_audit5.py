# -*- coding: utf-8 -*-
"""Независимый аудит всего проекта: найденное и починенное.

Каждая проверка здесь стоит за конкретным дефектом, который был найден
разбором или живым запуском, а не «на всякий случай». Порядок — как в
`.unlazy/audit5/GATES.md`.

Самое дорогое из найденного: **очистка адреса ломала кавычки в имени ящика**.
`"very.unusual"@example.com` валиден по RFC 5321 §4.1.2, но счистка краёв
снимала открывающую кавычку и оставляла закрывающую — адрес превращался в
синтаксически битый и получал `invalid` без единого сетевого запроса. Ниже
это проверяется на трёх формах, и отдельно — что прежняя работа счистки
(обратные кавычки, угловые скобки, mailto:) не пострадала.
"""
import io
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


def code(rel):
    """Исходник БЕЗ комментариев и докстрок.

    Проверки ниже ищут отсутствие опасных вызовов. Искать их в полном тексте
    нельзя: рядом с каждой правкой стоит объяснение, в котором убранный вызов
    назван дословно, — и проверка падает на собственном комментарии.
    """
    import ast

    tree = ast.parse(read(rel))
    for node in ast.walk(tree):
        if (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)):
            node.value.value = ""
    return ast.unparse(tree)


# ══════════════════════════ A1: кавычки в имени ящика

@pytest.mark.parametrize("address", [
    '"very.unusual"@example.com',
    '"a@b"@example.com',
    '"john doe"@example.com',
])
def test_quoted_local_part_survives_cleaning(address):
    """Валидный адрес не может стать битым из-за нашей же счистки."""
    from core.cleaner import EmailCleaner
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax(address), "проверяем не тот адрес"
    cleaned = EmailCleaner().clean_email(address)
    assert cleaned, "адрес выброшен целиком"
    assert validate_email_syntax(cleaned), (
        "очистка сделала валидный адрес битым: %r -> %r" % (address, cleaned))


@pytest.mark.parametrize("raw,expected", [
    ("`hjohnuc@gmail.com", "hjohnuc@gmail.com"),
    ("Ivan Petrov <ivan@corp.com>", "ivan@corp.com"),
    # Регистр ИМЕНИ ЯЩИКА сохраняется: по RFC 5321 §2.4 он значащий, и толковать его вправе только сервер назначения. Домен приводится к нижнему — DNS регистр не различает. Прежнее ожидание закрепляло общий .lower(), из-за которого наружу уезжал переписанный адрес.
    # Задача проверки цела: `mailto:` и запятая по-прежнему счищены.
    ("mailto:John.Doe@Gmail.com,", "John.Doe@gmail.com"),
    ("«ivan@corp.com»", "ivan@corp.com"),
])
def test_quoted_fix_did_not_break_ordinary_cleaning(raw, expected):
    """Контроль: счистка мусора по краям работает как прежде.

    Без него «починка» кавычек могла бы просто отключить счистку целиком —
    и вернуть тот самый ложный invalid, ради которого её заводили.
    """
    from core.cleaner import EmailCleaner

    assert EmailCleaner().clean_email(raw) == expected


# ══════════════════════════ A2: сбой DNS не делает вывода о домене

class _Resolver:
    """Резолвер, который на MX падает, а на A отвечает."""

    def __init__(self, mx_error, a_answer=True):
        self.mx_error = mx_error
        self.a_answer = a_answer
        self.asked = []

    def resolve(self, domain, rdtype):
        self.asked.append(rdtype)
        if rdtype == "MX":
            raise self.mx_error
        if self.a_answer:
            return ["1.2.3.4"]
        raise Exception("нет ответа")


def _validator():
    from core.network import NetworkValidator

    return NetworkValidator(timeout=1)


def test_dns_failure_does_not_fall_back_to_a_record():
    """Таймаут на MX — это «не спросили», а не «MX нет».

    Подстановка самого домена в качестве почтового сервера означала бы пробы
    на веб-сервер вместо почтового. Хуже: результат кэшировался на весь
    прогон, поэтому ошибка переживала восстановление связи.
    """
    import dns.exception

    v = _validator()
    v.resolver = _Resolver(dns.exception.Timeout())
    assert v.get_mx_records("corp.test") is None, "сбой выдан за ответ"
    assert v.resolver.asked == ["MX"], (
        "после сбоя всё равно спрашивали A/AAAA: %s" % v.resolver.asked)
    assert "corp.test" not in v.mx_cache, "сбой закэширован"


def test_dns_answer_still_falls_back_to_a_record():
    """Контроль: когда сервер ОТВЕТИЛ «MX нет», фоллбэк обязан работать.

    Иначе «не кэшируем сбои» превратилось бы в «не проверяем домены без MX»,
    а таких доменов с почтой на A-записи полно.
    """
    import dns.resolver

    v = _validator()
    v.resolver = _Resolver(dns.resolver.NoAnswer())
    assert v.get_mx_records("corp.test") == ["corp.test"]
    assert v.mx_cache.get("corp.test") == ["corp.test"], "ответ не закэширован"


# ══════════════════════════ A3-A5: Tor

def test_tor_stop_kills_children_after_clearing_the_handle():
    """Остановка доводится до конца.

    Было: self.process обнулялся МЕЖДУ двумя способами убийства, и второй
    падал на AttributeError внутри голого except. Молча — то есть дочерние
    процессы (lyrebird, snowflake) переживали остановку.
    """
    source = read("core/tor_manager.py")
    stop = source[source.index("    def stop(self):"):]
    stop = stop[:stop.index("    def is_alive")]
    assert "pid = self.process.pid" in stop, "PID не запоминается до обнуления"
    assert stop.index("psutil") < stop.index("self.process = None"), (
        "обнуление снова стоит перед веткой psutil")
    assert "except:" not in stop, "голый except вернулся"


def test_tor_start_does_not_kill_foreign_processes():
    """Запуск глушит только свои процессы, а не каждый tor.exe на машине."""
    source = code("core/tor_manager.py")
    assert "/IM tor.exe" not in source, (
        "вернулся taskkill по имени образа — он убивает и Tor Browser владельца")
    assert "os.system" not in source, "вернулся вызов через оболочку"
    assert "_kill_orphans" in source and "our_tor_pids.json" in source, (
        "нет учёта своих процессов")


def test_tor_orphan_killer_checks_the_process_name(tmp_path, monkeypatch):
    """Контроль: чужой процесс с тем же номером убивать нельзя.

    Номер после перезагрузки достаётся кому угодно, поэтому имя проверяется
    обязательно.
    """
    import core.tor_manager as tm

    killed = []

    class FakeProc:
        def __init__(self, pid):
            self.pid = pid

        def name(self):
            return "notepad.exe"

        def children(self, recursive=False):
            return []

        def kill(self):
            killed.append(self.pid)

    fake_psutil = type("psutil", (), {"Process": FakeProc})
    monkeypatch.setitem(sys.modules, "psutil", fake_psutil)

    manager = tm.TorManager.__new__(tm.TorManager)
    manager.tor_dir = tmp_path
    manager.log_callback = lambda *a, **k: None
    manager._log = lambda *a, **k: None
    (tmp_path / "our_tor_pids.json").write_text("[4242]", encoding="utf-8")

    manager._kill_orphans()
    assert killed == [], "убит чужой процесс с совпавшим номером"


def test_tor_password_is_not_hardcoded():
    """Общий на все установки пароль управляющего порта — это не защита."""
    source = code("core/tor_manager.py")
    assert "parser_secret" not in source
    assert "HashedControlPassword" not in source
    assert "hashed_password" not in source, "поле пароля осталось про запас"
    assert "CookieAuthentication 1" in source, "нечем аутентифицироваться"
    assert "control_auth_cookie" in source, "cookie не читается"


# ══════════════════════════ A6: честные зависимости

def test_dependencies_are_honest():
    """Пакет, который не используется, не должен требоваться к установке."""
    requirements = read("requirements.txt")
    assert "stem" not in requirements, (
        "stem вернулся в зависимости, хотя управляющий порт открывается сокетом")

    source = read("core/tor_manager.py")
    assert "from stem" not in source and "import stem" not in source
    assert "import zipfile" not in source, "мёртвый импорт вернулся"


def test_dependencies_check_still_passes():
    """Контроль: сито зависимостей на месте и проходит.

    Иначе «убрали лишнее» могло бы означать «убрали нужное».
    """
    import subprocess

    done = subprocess.run(
        [sys.executable, os.path.join(ROOT, "audit", "verify_requirements.py")],
        cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert done.returncode == 0, done.stdout + done.stderr
    assert "REQUIREMENTS OK" in (done.stdout or "")


# ══════════════════════════ A7: TLS

def test_tls_is_verified_by_default():
    """Проверка сертификата включена, отключение — только запасной путь."""
    source = code("core/parser/engine.py")
    assert source.count("verify=False") == 1, (
        "verify=False должен остаться ровно один — внутри запасного пути")
    assert "SSLError" in source, "запасной путь не привязан к ошибке сертификата"
    assert "verify=True" in source


def test_tls_fallback_only_on_certificate_error():
    """Живая проба: обычный ответ идёт с проверкой, откат — только на SSLError."""
    import requests

    from core.parser.engine import _get_verified

    class Session:
        def __init__(self, fail_first):
            self.calls = []
            self.fail_first = fail_first

        def get(self, url, **kw):
            self.calls.append(kw.get("verify"))
            if self.fail_first and len(self.calls) == 1:
                raise requests.exceptions.SSLError("self signed certificate")
            return "страница"

    good = Session(fail_first=False)
    _get_verified(good, "https://x", proxies=None, timeout=5, headers={})
    assert good.calls == [True], "первый заход без проверки сертификата"

    mitm = Session(fail_first=True)
    _get_verified(mitm, "https://x", proxies=None, timeout=5, headers={})
    assert mitm.calls == [True, False], "запасной путь не сработал"

    class Broken:
        def get(self, url, **kw):
            raise requests.exceptions.ConnectTimeout("нет связи")

    with pytest.raises(requests.exceptions.ConnectTimeout):
        _get_verified(Broken(), "https://x", proxies=None, timeout=5, headers={})


# ══════════════════════════ A8: уверенность в вердикте

def test_confidence_separates_proof_from_guess():
    """Одно слово «Годен» — и разные основания под ним."""
    from core.verdict import verdict_confidence

    proven, _ = verdict_confidence("valid", "250 OK", {"control_probe": True})
    plain, _ = verdict_confidence("valid", "250 OK", {})
    accept_all, _ = verdict_confidence("catchall", "Catch-All Domain (Unverifiable)")
    assert proven > plain > accept_all, (proven, plain, accept_all)
    assert accept_all <= 20, "домен, принимающий что угодно, не может быть уверенным"


def test_confidence_ranks_invalid_by_evidence():
    """Приговор без сети (нет MX) твёрже неподтверждённого 550."""
    from core.verdict import verdict_confidence

    fact, _ = verdict_confidence("invalid", "No MX/A records (Dead Domain)")
    confirmed, _ = verdict_confidence("invalid", "550 Получателя не существует",
                                      {"confirmed": True})
    single, _ = verdict_confidence("invalid", "550 Получателя не существует")
    assert fact > confirmed > single
    assert single >= 60, "подтверждённый сервером отказ не может быть слабым"


def test_confidence_never_raises_on_junk():
    """Зовут из рабочих потоков: исключение здесь стоило бы адреса."""
    from core.verdict import verdict_confidence

    for status, reason, extras in ((None, None, None), (123, [], "не словарь"),
                                   ("", "", {}), (object(), object(), {})):
        value, basis = verdict_confidence(status, reason, extras)
        assert isinstance(value, int) and 0 <= value <= 100
        assert isinstance(basis, str) and basis


def test_confidence_reaches_the_row_and_the_table():
    """Уверенность обязана дойти до таблицы и выгрузки, а не осесть в коде."""
    pipeline = read("core/pipeline.py")
    assert "verdict_confidence" in pipeline and "verdict_basis" in pipeline

    webapp = read("ui/webapp.py")
    assert '"confidence": data.get("verdict_confidence"' in webapp, (
        "строка таблицы не несёт уверенность")
    assert "ConfidenceBasis" in webapp, "в выгрузке нет колонки основания"

    app_js = read("ui/web/app.js")
    assert "row.confidence" in app_js and "Уверенность" in app_js

    cli = read("cli.py")
    assert '"verdict_confidence"' in cli and '"verdict_basis"' in cli


def test_confidence_is_filled_for_every_verdict_kind():
    """Пустая уверенность — та же ложная уверенность, только молчаливая."""
    from core.verdict import CONFIDENCE_STEPS, verdict_confidence

    kinds = ["valid", "invalid", "risky", "unknown", "catchall", "greylisted",
             "trap", "Valid", "Invalid/Bounce", "Role-based"]
    for kind in kinds:
        value, basis = verdict_confidence(kind, "")
        assert basis, "вердикт %s остался без основания" % kind
        assert 0 <= value <= 100
    assert all(0 <= v <= 100 for v, _ in CONFIDENCE_STEPS.values())


# ══════════════════════════ A9: токен







# ══════════════════════════ A10: README



def test_readme_commands_actually_exist():
    """Каждая обещанная команда должна существовать в коде."""
    assert os.path.exists(os.path.join(ROOT, "main.py"))
    assert os.path.exists(os.path.join(ROOT, "cli.py"))
    assert "--classic" in read("main.py"), "флага --classic нет в точке входа"

    cli = read("cli.py")
    for sub in ("validate", "subtract", "merge", "intersect"):
        assert '"%s"' % sub in cli or "'%s'" % sub in cli, (
            "README обещает команду %s, а в cli.py её нет" % sub)


def test_readme_dependencies_match_requirements():
    """Названные в README пакеты обязаны стоять в requirements."""
    readme = read("README.md")
    requirements = read("requirements.txt")
    assert "pip install -r requirements.txt" in readme
    if "spacy" in readme:
        assert "spacy" in requirements
    # И обратное: README не должен обещать то, что мы убрали.
    assert "stem" not in readme


def test_readme_verdicts_match_the_code():
    """Таблица вердиктов в README не должна расходиться с кодом."""
    readme = read("README.md")
    for status in ("Valid", "Invalid/Bounce", "Risky", "Unknown",
                   "Role-based", "Trap/Disposable"):
        assert status in readme, "README не описывает статус %s" % status

    pipeline = read("core/pipeline.py")
    for status in ("Invalid/Bounce", "Role-based", "Trap/Disposable"):
        assert status in pipeline, (
            "README описывает статус %s, которого нет в конвейере" % status)


def test_readme_test_commands_are_real():
    """Команды прогона тестов из README должны работать здесь и сейчас."""
    readme = read("README.md")
    assert 'python -m pytest -m "not slow"' in readme
    config = read("pytest.ini")
    assert re.search(r"^\s*slow:", config, re.M), (
        "README обещает быстрый круг, а маркера slow нет")


def test_confidence_survives_the_cache(tmp_path):
    """Адрес из кэша обязан приезжать с уверенностью.

    Когда настройки обогащения не менялись, конвейер проходит мимо
    _enrich_and_score — и вердикт из прошлого прогона приезжал без колонки
    уверенности вовсе. Пустая колонка ровно там, где вердикт взят из кэша, —
    это та же ложная уверенность, только молчаливая.
    """
    pipeline = read("core/pipeline.py")
    cache_block = pipeline[pipeline.index("Шаг 2: Кэш прошлых прогонов"):]
    cache_block = cache_block[:cache_block.index("Шаг 3: Глубокий SMTP Ping")]
    assert "verdict_confidence" in cache_block, (
        "путь из кэша не выставляет уверенность")
    assert '"verdict_confidence", "verdict_basis")' in cache_block, (
        "при смене настроек уверенность не пересчитывается")


def test_unverified_status_is_documented_and_confident_about_nothing():
    """Выключенная проверка — честный статус, а не тихий пропуск."""
    from core.verdict import verdict_confidence

    assert "Unverified" in read("core/pipeline.py")
    assert "Unverified" in read("README.md"), "статус есть в коде, но не в README"
    value, basis = verdict_confidence("Unverified", "Skipped Ping")
    assert value == 0, "у непроверенного адреса не может быть уверенности"
    assert basis
