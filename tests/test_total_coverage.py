# -*- coding: utf-8 -*-
"""Полнота проверки: ни один адрес не пропускает применимый к нему критерий.

Требование владельца: каждая почта из базы проходит все возможные критерии,
ни один критерий и ни один адрес не потеряны, и всё это на сотнях тысяч
адресов без падений и без риска для его IP.

Здесь проверяется именно полнота — что критерий применён, а не что он даёт
верный ответ (это дело других файлов).
"""
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def source(*parts):
    with io.open(os.path.join(ROOT, *parts), encoding="utf-8") as handle:
        return handle.read()


def pipeline():
    from core.pipeline import ValidationPipeline

    return ValidationPipeline(callbacks={
        "on_log": lambda text, kind="info": None,
        "on_result": lambda *args: None,
        "on_complete": lambda: None,
    })


# ═══════════════════════════════ полнота обогащения

def test_enrich_all_filtered_addresses_are_not_left_bare():
    """Отсеянный адрес тоже получает имя, пол и страну.

    Раньше он выходил из обработки сразу после вердикта, и в таблице у него
    были пустые колонки — при том что всё это считается локально по самому
    адресу и не стоит ни одного запроса в сеть.
    """
    from core.parser.name_extractor import NameExtractor
    from core.parser.ml_predictor import MLPredictor

    engine = pipeline()
    engine.name_extractor = NameExtractor()
    engine.ml_predictor = MLPredictor()

    data = {"engagement_score": 0, "engagement_grade": "Dead",
            "provider_name": "Disposable", "provider_type": "Disposable",
            "domain_type": "Disposable"}
    engine._enrich_offline("john.smith@tempmail.com", data, "Trap/Disposable", False)

    assert data.get("name"), "имя не извлечено"
    assert data.get("gender"), "пол не определён"
    assert data.get("country"), "страна не определена"


def test_enrich_all_verdict_fields_are_preserved():
    """Обогащение не имеет права переписать вердикт.

    У одноразового домена оценка равна нулю по определению; пересчёт поднял
    бы её и превратил «слать нельзя» в нечто среднее.
    """
    from core.parser.name_extractor import NameExtractor

    engine = pipeline()
    engine.name_extractor = NameExtractor()

    data = {"engagement_score": 0, "engagement_grade": "Dead",
            "provider_name": "Disposable", "provider_type": "Disposable",
            "domain_type": "Disposable"}
    engine._enrich_offline("john.smith@tempmail.com", data, "Trap/Disposable", False)

    assert data["engagement_score"] == 0
    assert data["engagement_grade"] == "Dead"
    assert data["provider_name"] == "Disposable"
    assert data["domain_type"] == "Disposable"


def test_enrich_all_is_wired_into_both_early_exits():
    """Оба ранних выхода зовут обогащение, а не один из них."""
    code = source("core", "pipeline.py")
    assert code.count("_enrich_offline(") >= 3, \
        "обогащение подключено не ко всем ранним выходам"
    # Ровно там, где раньше был голый выход.
    assert '_enrich_offline(email, data, "Trap/Disposable"' in code


def test_enrich_cheap_costs_no_network():
    """Полнота не куплена ценой сети.

    Gravatar, возраст домена и живой сайт спрашиваются только у Valid, Risky
    и Role-based. Ходить за ними ради адреса, которому не будут писать, —
    трата чужого лимита и своего времени, а на большой базе ещё и повод для
    провайдера присмотреться к трафику.
    """
    import inspect

    from core.pipeline import ValidationPipeline

    body = inspect.getsource(ValidationPipeline._enrich_and_score)
    for call in ("has_gravatar(email)", "_get_domain_age_days(domain)",
                 "_check_http_alive(domain)"):
        position = body.index(call)
        guard = body.rfind('status_display in ("Valid", "Risky", "Role-based")',
                           0, position)
        assert guard != -1, "сетевой вызов %s не ограничен статусом" % call


def test_enrich_cheap_never_breaks_the_verdict():
    """Сбой обогащения не имеет права потерять адрес."""
    engine = pipeline()

    class Exploding:
        def extract_name(self, *args, **kwargs):
            raise RuntimeError("подстава")

    engine.name_extractor = Exploding()
    data = {"engagement_score": 0}
    engine._enrich_offline("a@tempmail.com", data, "Trap/Disposable", False)
    assert data["engagement_score"] == 0      # вердикт уцелел


# ═══════════════════════════════ обязательные поля

@pytest.mark.parametrize("status", [
    "Valid", "Invalid/Bounce", "Risky", "Unknown", "Role-based",
    "Trap/Disposable", "Unverified",
])
def test_required_fields_present_for_every_status(status):
    """Пустая строка в таблице — это непроверенный адрес, выданный за проверенный."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api._on_result("ivan@example.com", status, "причина", "mx",
                   {"engagement_score": 42, "validated_at": "2026-08-30 10:00",
                    "provider_name": "Example"})
    rows = api.page({"groups": ["valid", "invalid", "spam", "unknown"]})["rows"]
    assert rows, "адрес со статусом %s пропал из выдачи" % status
    row = rows[0]
    for field in ("email", "status", "group", "reason", "score", "when"):
        assert row.get(field) not in (None, ""), (status, field)


def test_required_fields_validated_at_is_set_before_any_exit():
    """Дата ставится в начале обработки, до всех ранних выходов.

    Иначе отсеянные адреса приходили бы без даты, и было бы не понять, когда
    их проверяли и пора ли перепроверять.
    """
    code = source("core", "pipeline.py")
    stamp = code.index('data["validated_at"]')
    first_exit = code.index('"Disposable Email Domain"')
    assert stamp < first_exit, "дата ставится позже первого выхода"


# ═══════════════════════════════ крупные почтовики

GIANTS = ["gmail.com", "yahoo.com", "aol.com", "outlook.com", "icloud.com"]


@pytest.mark.parametrize("domain", GIANTS)
def test_giants_have_local_part_rules(domain):
    """У каждого гиганта свои правила имени, и они применяются."""
    from core.local_rules import _RULES

    assert domain in _RULES, "нет правил имени для %s" % domain


def test_giants_every_known_domain_has_rules():
    """Правило обязано применяться ко ВСЕМ доменам провайдера, а не к части.

    Поймано этой проверкой: AOL был пропущен целиком, у Yahoo не хватало
    восьми региональных доменов, у Microsoft — passport.com. Критерий
    существовал, но адрес на yahoo.com.mx проверялся на одно правило меньше,
    чем адрес на yahoo.com, — ровно тот случай, когда проверка идёт не по
    всем критериям, хотя выглядит полной.
    """
    from core.local_rules import _RULES
    from core.mail_constants import AOL_DOMAINS, MICROSOFT_DOMAINS, YAHOO_DOMAINS

    have = set(_RULES)
    for label, domains in (("AOL", AOL_DOMAINS), ("Yahoo", YAHOO_DOMAINS),
                           ("Microsoft", MICROSOFT_DOMAINS)):
        missing = sorted(set(domains) - have)
        assert not missing, "%s: домены без правил имени — %s" % (label, missing)


def test_giants_aol_rules_are_real_not_decorative():
    """Правило AOL должно и ловить невозможное, и не трогать живое."""
    from core.local_rules import IMPOSSIBLE, OK, check_local_part

    # Имя длиннее предела: у AOL максимум 32 знака.
    assert check_local_part("a" * 40 + "@aol.com")[0] == IMPOSSIBLE
    # Обычный живой адрес не страдает.
    assert check_local_part("john.smith@aol.com")[0] == OK
    # Начало не с буквы — подозрение, но не приговор: старые ящики бывают.
    assert check_local_part("7john@aol.com")[0] not in (IMPOSSIBLE,)


@pytest.mark.parametrize("domain", GIANTS)
def test_giants_are_classified(domain):
    """Провайдер и тип домена определяются — от них зависит скоринг."""
    from core.provider import classify_domain

    name, kind = classify_domain("someone@" + domain)
    assert name and kind, domain


@pytest.mark.parametrize("domain", GIANTS)
def test_giants_get_the_tarpit_control(domain):
    """Контроль на тарпитинг включается для всех гигантов.

    Именно они начинают принимать любые адреса, когда наш IP под подозрением.
    """
    from core.network import NetworkValidator

    check = NetworkValidator(timeout=2, proxy_dns=False)
    assert check._time_to_recheck(domain) is True, domain


def test_giants_requirements_are_documented_where_they_apply():
    """Особые требования гигантов не забыты и названы явно."""
    code = source("core", "proxy_profile.py")
    # Yahoo и AOL требуют PTR, Outlook и iCloud — чистую репутацию.
    assert "PTR" in code
    for label in ("Yahoo", "Outlook", "iCloud"):
        assert label in code, label


def test_giants_skip_list_is_explained_not_silent():
    """Где критерий неприменим, это сказано с причиной, а не пропущено молча."""
    code = source("core", "network.py")
    position = code.index("skip_catchall = (")
    block = code[position - 400:position + 900]
    assert "catch-all" in block.lower()
    # И для гигантов всё равно есть контроль — прямо здесь же объяснено.
    assert "тарпит" in code.lower() or "перебор" in code.lower()


# ═══════════════════════════════ устойчивость

def test_survives_garbage_in_every_public_check():
    """Мусор на входе не роняет ни одну проверку.

    На базе в сотни тысяч строк попадётся всё: обрезанные строки, чужая
    кодировка, нулевые байты. Падение означает потерянный адрес.
    """
    from core.cleaner import normalize_for_dedup
    from core.disposable import is_disposable
    from core.email_syntax import validate_email_syntax
    from core.heuristics import is_role_based
    from core.local_rules import check_local_part
    from core.provider import classify_domain
    from core.smtp_codes import classify_smtp_response

    junk = [None, 123, [], {}, b"\xff\xfe", "\x00" * 40, " " * 500, object(),
            "a" * 5000, "@@@", "\n\r\t"]
    checks = [validate_email_syntax, is_disposable, is_role_based,
              normalize_for_dedup, check_local_part, classify_domain]
    for value in junk:
        for check in checks:
            try:
                check(value)
            except (AttributeError, TypeError, ValueError, KeyError, IndexError) as exc:
                pytest.fail("%s упал на %r: %s" % (check.__name__, value, exc))
        classify_smtp_response(value, value)


def test_survives_a_worker_crash_without_losing_the_address():
    """Сбой внутри обработки не съедает адрес: он выходит как Unknown."""
    code = source("core", "pipeline.py")
    assert 'self._emit(email, "Unknown", f"Processing error:' in code
    # И поток при этом не умирает, иначе с ним умрут все оставшиеся адреса.
    assert "Without this the whole worker thread would die" in code


def test_survives_counts_every_address():
    """Инвариант «подано = выдано» на месте: потеря видна сразу."""
    code = source("core", "pipeline.py")
    assert "ПОТЕРЯНО АДРЕСОВ" in code
    assert code.count("self.callbacks['on_result'](") == 1, \
        "результат уходит мимо счётчика"


# ═══════════════════════════════ безопасность прогона

def test_safety_warns_before_running_without_proxies():
    """Молчаливый прогон без прокси — это перебор с домашнего адреса.

    Провайдер видит сотни тысяч исходящих соединений на порт 25 и вправе
    счесть это спам-ботом.
    """
    from core.proxy_profile import readiness_report

    report = readiness_report({})
    assert report["ready"] is False
    assert "домашнего" in report["verdict"]


def test_safety_limits_sessions_per_mail_host():
    """К одному почтовику нельзя ломиться всеми потоками сразу.

    Без ограничения триста параллельных сессий к Gmail выглядят атакой, и
    ответом будет блокировка адреса.
    """
    code = source("core", "proxy_pool.py")
    assert "_get_mx_semaphore" in code
    assert "Semaphore" in code


def test_safety_drops_a_proxy_after_repeated_failures():
    """Мёртвый прокси выбывает, а не долбится вечно."""
    from core.mail_constants import PROXY_MAX_CONSECUTIVE_FAILS

    assert 1 <= PROXY_MAX_CONSECUTIVE_FAILS <= 10


def test_safety_rate_limit_answers_are_retried_not_hammered():
    """На «слишком часто» отвечают паузой и другим прокси, а не повтором в лоб."""
    from core.pipeline import _is_transient_failure

    assert _is_transient_failure("unknown", "rate limit") is True
    assert _is_transient_failure("unknown", "421 Service Busy (Rate Limit)") is True


# ═══════════════════════════════ скрипт подъёма прокси

def test_vps_builds_from_source_not_from_a_missing_package():
    """Главный косяк первой версии: пакета 3proxy нет в Ubuntu 22.04/24.04.

    Скрипт падал на первом же шаге с set -e, и владелец получал сервер без
    прокси и без объяснения.
    """
    from tools.make_vps_proxy import build_script

    script = build_script("u", "p")
    assert "apt-get install -y -qq 3proxy" not in script
    assert "make -f Makefile.Linux" in script
    assert "github.com/3proxy/3proxy/archive" in script


def test_vps_checks_root_and_distro():
    from tools.make_vps_proxy import build_script

    script = build_script("u", "p")
    assert 'id -u' in script
    assert "command -v apt-get" in script


def test_vps_verifies_the_service_actually_started():
    """Молча не запустившийся сервис — сервер без прокси и без сообщения."""
    from tools.make_vps_proxy import build_script

    assert "systemctl is-active --quiet 3proxy" in build_script("u", "p")


def test_vps_checks_port_25_and_ptr():
    """Без порта 25 и PTR весь сервер бессмысленен для валидации."""
    from tools.make_vps_proxy import build_script

    script = build_script("u", "p")
    assert "gmail-smtp-in.l.google.com 25" in script
    assert "587" in script and "465" in script
    assert "dig +short -x" in script
    assert "5.7.25" in script


def test_vps_allows_enough_connections_for_the_validator():
    """Валидатор ходит в триста потоков; предел ниже сделал бы прокси узким местом."""
    from tools.make_vps_proxy import MAX_CONNECTIONS, build_script

    assert MAX_CONNECTIONS >= 300
    assert "maxconn %d" % MAX_CONNECTIONS in build_script("u", "p")


def test_vpssafety_opens_ssh_before_enabling_the_firewall():
    """Обратный порядок отрезает доступ к серверу.

    Чинится это только через консоль хостера, а на некоторых тарифах её нет
    вовсе.
    """
    from tools.make_vps_proxy import build_script

    script = build_script("u", "p", ssh_port=2222)
    ssh_rule = script.index('ufw allow "$SSH_PORT"/tcp')
    enable = script.index("ufw --force enable")
    assert ssh_rule < enable, "ufw включается раньше, чем открыт SSH"
    assert "SSH_PORT=2222" in script


def test_vpssafety_password_file_is_not_world_readable():
    """Пароль в конфиге 3proxy лежит открытым текстом — файл обязан быть 600."""
    from tools.make_vps_proxy import build_script

    script = build_script("u", "p")
    assert "chmod 600 /etc/3proxy/3proxy.cfg" in script


def test_vpssafety_script_is_valid_bash():
    """Скрипт, который не разбирается bash, бесполезен целиком."""
    import shutil
    import subprocess
    import tempfile

    from tools.make_vps_proxy import build_script

    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash недоступен в этой системе")

    with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False,
                                     encoding="utf-8", newline="\n") as handle:
        handle.write(build_script("validator", "S3cret", 1080, 2222))
        path = handle.name
    try:
        done = subprocess.run([bash, "-n", path], capture_output=True, text=True)
        assert done.returncode == 0, done.stderr
    finally:
        os.unlink(path)
