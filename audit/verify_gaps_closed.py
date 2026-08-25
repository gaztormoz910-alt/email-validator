#!/usr/bin/env python
"""Оракул: каждый изъян прошлого аудита проверен по коду — и закрытый, и открытый.

Зачем он нужен. Оценка, которая выросла с 82 до 88, обязана объяснить, ЗА ЧТО
именно. Самый лёгкий способ соврать в таком отчёте — объявить изъян закрытым
и повысить балл, не проверив. Здесь каждая строка audit/gap_ledger.json
проверяется вызовом настоящего кода:

  * status="closed" — возможность обязана РАБОТАТЬ. Проверка вызывает её и
    смотрит на результат, а не на наличие функции с подходящим именем.
  * status="open"   — возможности обязано НЕ БЫТЬ. Это защита от обратного
    вранья: занизить оценку, не заметив, что изъян давно закрыт, и оставить
    пользователя без сделанной работы.

Проверка на отсутствие опаснее проверки на наличие: она зелёная и когда
возможности нет, и когда проверка сломалась. Поэтому каждая такая проверка
устроена как измерение положительного контроля рядом — см. комментарии.

Успех печатает GAPS OK: <закрыто>/<открыто> и выходит с нулём.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


def _validator(**kw):
    from core.network import NetworkValidator
    return NetworkValidator(timeout=1, **kw)


# --- проверки закрытых изъянов ----------------------------------------------

def check_invalid_heuristic():
    """Слово «mailbox» без отрицания больше не хоронит ящик, с отрицанием — хоронит."""
    p = _validator()._parse_smtp_response
    spared = p(550, b"mailbox temporarily unavailable, try again later",
               "a@b.com", "b.com")["status"]
    buried = p(550, b"5.1.1 no such user here", "a@b.com", "b.com")["status"]
    # Положительный контроль рядом: если бы разбор перестал хоронить ВООБЩЕ,
    # первая половина прошла бы, а вторая — нет.
    return spared != "invalid" and buried == "invalid"


def check_control_rcpt():
    """У пинга есть управляемая контрольная проба, и по умолчанию она выключена."""
    import inspect
    from core.network import NetworkValidator
    sig = inspect.signature(NetworkValidator._do_single_ping)
    param = sig.parameters.get("control_probe")
    if param is None or param.default is not False:
        return False
    return "control_probe" in inspect.signature(
        NetworkValidator.stealth_smtp_ping).parameters


def check_postmaster_probe():
    """Отвергнутый postmaster@ даёт False, принятый — True, сбой — None."""
    v = _validator()
    answers = {"reject": [{"status": "invalid", "reason": "550"}],
               "accept": [{"status": "valid", "reason": "250"}],
               "fail": [{"status": "unknown", "reason": "Timeout"}]}
    mode = {"v": "reject"}
    v._probe_recipients = lambda addrs, mx, proxy=None, from_email=None: answers[mode["v"]]
    v._pick_best_proxy = lambda **kw: None

    if v.postmaster_is_honored("a.com", "mx") is not False:
        return False
    mode["v"] = "accept"
    if v.postmaster_is_honored("b.com", "mx") is not True:
        return False
    mode["v"] = "fail"
    # Сбой не имеет права кэшироваться как приговор
    return v.postmaster_is_honored("c.com", "mx") is None


def check_country_threshold_switch():
    """Режим страны переключается и реально двигает пороги."""
    import core.parser.ml_predictor as MP
    before = (MP.NAME_COUNTRY_MIN_SHARE, MP.NAME_COUNTRY_MIN_RATIO)
    try:
        MP.set_country_mode("accuracy")
        strict = (MP.NAME_COUNTRY_MIN_SHARE, MP.NAME_COUNTRY_MIN_RATIO)
        MP.set_country_mode("coverage")
        loose = (MP.NAME_COUNTRY_MIN_SHARE, MP.NAME_COUNTRY_MIN_RATIO)
        return strict != loose and strict == MP.COUNTRY_MODES["accuracy"]
    finally:
        MP.NAME_COUNTRY_MIN_SHARE, MP.NAME_COUNTRY_MIN_RATIO = before


def check_weights_calibration():
    """Веса вынесены наружу, а калибровка отказывается работать на малой выборке."""
    import core.scoring as S
    if not isinstance(getattr(S, "DEFAULT_WEIGHTS", None), dict):
        return False
    if S.W("smtp_valid") != S.DEFAULT_WEIGHTS["smtp_valid"]:
        return False
    from tools import calibrate_scoring as C
    # Порог существует и не выключен — иначе «калибровка» была бы шумом
    return getattr(C, "MIN_SAMPLES", 0) >= 20 and getattr(C, "MAX_WEIGHT", 0) > 0


def check_exit_ip_dedup():
    """Десять прокси с одним выходом считаются одним адресом ротации."""
    from core.proxy_profile import rotation_report
    report = rotation_report({f"p{i}:1": {"exit_ip": "1.1.1.1"} for i in range(10)})
    return report["unique_ips"] == 1 and report["duplicates"] == 9


def check_asn_and_geo():
    """Тип адреса определяется по владельцу, и неизвестное не выдумывается."""
    from core.proxy_profile import classify_org
    return (classify_org("DigitalOcean LLC") == "datacenter"
            and classify_org("Comcast Cable Communications") == "residential"
            and classify_org("") == "unknown")


def check_spamhaus():
    """Зона есть, но молчит без своего резолвера — и не выдаёт это за чистоту."""
    import core.network as N
    v = _validator()
    return (N.SPAMHAUS_ZONE not in N.DNSBL_ZONES
            and v._spamhaus_lists("1.2.3.4") is None)


def check_port25_diagnosis():
    """У чекера три исхода, а контрольный порт не совпадает с проверяемым."""
    from core.async_proxy import AsyncProxyChecker
    checker = AsyncProxyChecker(["1.2.3.4:1080"], workers=1, timeout=1, mode="smtp")
    report = checker.diagnosis_report()
    return (set(report) == {"live", "port25_blocked", "dead"}
            and checker.control_port != checker.target_port)


def check_direct_probe_yahoo_icloud():
    import core.network as N
    names = {name for name, _host in N.PROXY_PROBE_TARGETS}
    return {"Yahoo", "iCloud"} <= names


def check_geo_routing():
    """При равном здоровье выигрывает прокси нужной страны, даже будучи медленнее."""
    from core.network import country_code_for_domain
    if country_code_for_domain("web.de") != "DE":
        return False
    v = _validator(proxies=["de:1", "br:2"])
    v.set_proxy_profiles({
        "de:1": {"exit_ip": "1.1.1.1", "asn_country": "DE", "latency_ms": 900},
        "br:2": {"exit_ip": "2.2.2.2", "asn_country": "BR", "latency_ms": 50},
    })
    return {v._pick_best_proxy(want_country="DE") for _ in range(30)} == {"de:1"}


def check_per_proxy_concurrency():
    """У прокси свой слот, у разных прокси — разные, без прокси слота нет."""
    v = _validator(proxies=["p:1", "q:2"])
    v.set_proxy_concurrency(3)
    return (v.proxy_slot("p:1") is v.proxy_slot("p:1")
            and v.proxy_slot("p:1") is not v.proxy_slot("q:2")
            and v.proxy_slot(None) is None)


def check_blocking_pause():
    """В пайплайне нет паузы, способной удержать поток дольше десяти секунд."""
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "_sleepcheck", os.path.join(ROOT, "audit", "verify_no_blocking_sleep.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Детектор сам себя проверяет на заведомо плохом образце — если он сломан,
    # его собственный контроль не пройдёт, и здесь мы это увидим.
    if not module.scan(module.BAD_SAMPLE, "<контроль>"):
        return False
    with open(os.path.join(ROOT, "core", "pipeline.py"), encoding="utf-8") as handle:
        return not module.scan(handle.read(), "pipeline.py")


def check_dedup_in_ram():
    """Дедуп переживает закрытие: ключ лежит на диске, а не в памяти процесса."""
    import tempfile
    from core.runstate import RunState
    path = os.path.join(tempfile.mkdtemp(), "gap_state.sqlite")
    with RunState("run-1", path=path) as state:
        if not state.enabled or not state.add_if_new("a@b.com"):
            return False
        state.flush()
    with RunState("run-1", path=path) as again:
        return again.add_if_new("a@b.com") is False


def check_run_resume():
    """Сделанное помечается и после перезапуска не проверяется заново."""
    import tempfile
    from core.runstate import RunState
    path = os.path.join(tempfile.mkdtemp(), "gap_resume.sqlite")
    with RunState("run-2", path=path) as state:
        state.add_if_new("x@y.com")
        state.mark_done("x@y.com")
        state.flush()
    with RunState("run-2", path=path) as again:
        if not again.is_done("x@y.com"):
            return False
    # Отрицательный контроль: ЧУЖОЙ прогон не имеет права считаться сделанным
    with RunState("run-other", path=path) as other:
        return not other.is_done("x@y.com")


def check_ui_full_scan():
    """Показ страницы стоит порядка страницы, а не всей базы."""
    from ui.result_store import ResultStore

    class Counting(list):
        reads = 0

        def __getitem__(self, item):
            Counting.reads += 1
            return list.__getitem__(self, item)

    store = ResultStore()
    for i in range(30000):
        store.append(f"u{i}@x.com", "Valid", "", "", {})
    Counting.reads = 0
    store._rows = Counting(store._rows)
    rows = store.page(("valid",), page=1, size=100)
    # 30000 строк в базе, но прочитать позволено порядка ста
    return len(rows) == 100 and Counting.reads <= 150


def check_requirements():
    """Файл есть и называет пакеты, которые проект действительно импортирует."""
    path = os.path.join(ROOT, "requirements.txt")
    if not os.path.exists(path):
        return False
    with open(path, encoding="utf-8") as handle:
        text = handle.read().lower()
    return all(name in text for name in ("dnspython", "pysocks", "customtkinter"))


# --- проверки ОТКРЫТЫХ изъянов ----------------------------------------------
#
# Каждая возвращает True, когда изъян ВСЁ ЕЩЁ на месте. Проверять отсутствие
# опаснее, чем наличие, поэтому рядом с каждой стоит утверждение о том, что
# соседняя, заведомо существующая возможность видна — если бы проверка искала
# не там, это утверждение тоже провалилось бы.

def open_mx_cross_check():
    """Сверки ответов разных MX между собой по-прежнему нет."""
    import inspect
    from core.network import NetworkValidator
    source = inspect.getsource(NetworkValidator.stealth_smtp_ping)
    # Контроль: перебор MX в этом методе есть — значит смотрим в нужное место
    if "for mx_record in mx_records" not in source:
        return False
    return "cross" not in source.lower() and "сверк" not in source.lower()


def open_niche_providers():
    """Отдельных путей для Zoho, QQ, 163 и Naver в маршрутизации нет."""
    import core.network as N
    known = set(N.YAHOO_DOMAINS) | set(N.AOL_DOMAINS) | set(N.NEEDS_CLEAN_IP_DOMAINS)
    if "yahoo.com" not in known:          # контроль: множества заполнены
        return False
    return not ({"zoho.com", "qq.com", "163.com", "naver.com"} & known)


def open_private_relay_validation():
    """Private Relay учтён в скоринге и списках, но не в маршрутизации проверки."""
    from core.heuristics import PRIVACY_RELAY_DOMAINS
    import core.network as N
    if "privaterelay.appleid.com" not in PRIVACY_RELAY_DOMAINS:
        return False                       # контроль: список на месте
    routing = set(N.YAHOO_DOMAINS) | set(N.AOL_DOMAINS) | set(N.NEEDS_CLEAN_IP_DOMAINS)
    return "privaterelay.appleid.com" not in routing


def open_osint_breadth():
    """Источник OSINT по-прежнему один — Gravatar."""
    import inspect
    from core.parser.osint import OSINTOperator
    source = inspect.getsource(OSINTOperator)
    if "gravatar" not in source.lower():   # контроль: смотрим в нужный класс
        return False
    return not any(word in source.lower()
                   for word in ("linkedin", "clearbit", "hunter.io", "fullcontact"))


def open_ip_load_budget_enforced():
    """Потолок нагрузки сообщает о превышении, но не мешает брать этот прокси."""
    v = _validator(proxies=["hot:1"])
    v.set_proxy_profiles({"hot:1": {"exit_ip": "1.1.1.1", "latency_ms": 10}})
    v.note_ip_use("hot:1", v._ip_load_soft_cap + 100)
    if "1.1.1.1" not in v.overloaded_ips():
        return False                       # контроль: превышение вообще видно
    # Изъян в том, что перегруженный прокси всё равно выбирается
    return v._pick_best_proxy() == "hot:1"


def open_latency_resampling():
    """Задержка не переснимается на каждом обращении — только фоново."""
    import inspect
    from core.network import NetworkValidator
    source = inspect.getsource(NetworkValidator._choose_from)
    if "_proxy_latency" not in source:     # контроль: задержка вообще участвует
        return False
    return "probe_proxy_target" not in source


def open_whois_proxying():
    """При заданных прокси WHOIS пропускается, а не проксируется."""
    import inspect
    from core.pipeline import ValidationPipeline
    source = inspect.getsource(ValidationPipeline._fetch_domain_age)
    if "rdap" not in source.lower():       # контроль: смотрим в нужный метод
        return False
    return "не проксируется" in source


def open_monoliths():
    """network.py и gui.py по-прежнему монолиты."""
    def lines(rel):
        with open(os.path.join(ROOT, *rel.split("/")), "rb") as handle:
            return handle.read().count(b"\n")
    return lines("core/network.py") > 1500 and lines("ui/gui.py") > 1500


def open_rest_api():
    """REST API для встраивания нет."""
    import importlib.util
    if importlib.util.find_spec("cli") is None:   # контроль: CLI существует
        return False
    for name in ("api.py", "server.py", "rest.py", "app.py"):
        if os.path.exists(os.path.join(ROOT, name)):
            return False
    return True


CLOSED_CHECKS = {
    "invalid_heuristic": check_invalid_heuristic,
    "control_rcpt": check_control_rcpt,
    "postmaster_probe": check_postmaster_probe,
    "country_threshold_switch": check_country_threshold_switch,
    "weights_calibration": check_weights_calibration,
    "exit_ip_dedup": check_exit_ip_dedup,
    "asn_and_geo": check_asn_and_geo,
    "spamhaus": check_spamhaus,
    "port25_diagnosis": check_port25_diagnosis,
    "direct_probe_yahoo_icloud": check_direct_probe_yahoo_icloud,
    "geo_routing": check_geo_routing,
    "per_proxy_concurrency": check_per_proxy_concurrency,
    "blocking_pause": check_blocking_pause,
    "dedup_in_ram": check_dedup_in_ram,
    "run_resume": check_run_resume,
    "ui_full_scan": check_ui_full_scan,
    "requirements": check_requirements,
}

OPEN_CHECKS = {
    "mx_cross_check": open_mx_cross_check,
    "niche_providers": open_niche_providers,
    "private_relay_validation": open_private_relay_validation,
    "osint_breadth": open_osint_breadth,
    "ip_load_budget_enforced": open_ip_load_budget_enforced,
    "latency_resampling": open_latency_resampling,
    "whois_proxying": open_whois_proxying,
    "monoliths": open_monoliths,
    "rest_api": open_rest_api,
}


def main():
    ledger = json.load(open(os.path.join(ROOT, "audit", "gap_ledger.json"),
                            encoding="utf-8"))
    gaps = ledger["gaps"]
    failures = []
    closed = opened = 0

    known = {gap["id"] for gap in gaps}
    covered = set(CLOSED_CHECKS) | set(OPEN_CHECKS)
    if known != covered:
        for gap_id in sorted(known - covered):
            failures.append(f"{gap_id}: заявлен в ledger, но ничем не проверяется")
        for gap_id in sorted(covered - known):
            failures.append(f"{gap_id}: проверка есть, а строки в ledger нет")

    for gap in gaps:
        gap_id = gap["id"]
        status = gap["status"]
        check = (CLOSED_CHECKS if status == "closed" else OPEN_CHECKS).get(gap_id)
        if check is None:
            continue
        try:
            ok = bool(check())
        except Exception as exc:
            failures.append(f"{gap_id}: проверка упала ({type(exc).__name__}: {exc})")
            continue
        if status == "closed":
            closed += 1
            if not ok:
                failures.append(
                    f"{gap_id}: объявлен ЗАКРЫТЫМ, но код этого не подтверждает — "
                    f"«{gap['now']}»")
        else:
            opened += 1
            if not ok:
                failures.append(
                    f"{gap_id}: объявлен ОТКРЫТЫМ, но изъяна в коде уже нет — "
                    "оценка занижена, а работа не засчитана")

    if failures:
        print(f"GAPS MISMATCH ({len(failures)})")
        for line in failures:
            print("  - " + line)
        return 1
    print(f"GAPS OK: закрыто {closed}, осталось открытыми {opened}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
