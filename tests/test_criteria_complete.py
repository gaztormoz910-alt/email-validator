# -*- coding: utf-8 -*-
import io
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_PATH = os.path.join(ROOT, "docs", "КРИТЕРИИ.md")


def builtin_disposable_count():
    import ast

    path = os.path.join(ROOT, "core", "disposable.py")
    tree = ast.parse(io.open(path, encoding="utf-8").read())
    for node in tree.body:
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Name) and target.id == "DISPOSABLE_DOMAINS":
                    return len({e.value for e in node.value.elts})
    raise AssertionError("в core/disposable.py не найден встроенный список")


@pytest.fixture(scope="module")
def doc():
    with io.open(DOC_PATH, encoding="utf-8") as handle:
        return handle.read()


def engine_modules():
    found = []
    for folder in ("core", os.path.join("core", "parser"), "ui", "api"):
        path = os.path.join(ROOT, folder)
        if not os.path.isdir(path):
            continue
        for name in sorted(os.listdir(path)):
            if name.endswith(".py") and not name.startswith("__"):
                found.append((folder + "/" + name).replace(os.sep, "/"))
    return found


def test_modules_are_all_accounted_for(doc):
    missing = [m for m in engine_modules() if m not in doc]
    assert missing == [], "модули не упомянуты в документе: %s" % missing


def test_modules_list_is_not_empty():
    found = engine_modules()
    assert len(found) > 30, len(found)
    assert "core/network.py" in found
    assert "core/scoring.py" in found


def test_scoring_every_signal_is_listed(doc):
    from core.scoring import DEFAULT_WEIGHTS

    missing = [name for name in DEFAULT_WEIGHTS if name not in doc]
    assert missing == [], "сигналы оценки не перечислены: %s" % missing


def test_scoring_weights_in_the_doc_match_the_code(doc):
    from core.scoring import DEFAULT_WEIGHTS

    wrong = []
    for name, weight in DEFAULT_WEIGHTS.items():
        row = re.search(r"`%s`[^|]*\|\s*([+−-]?\d+)\s*\|" % re.escape(name), doc)
        if not row:
            wrong.append("%s: строки в таблице нет" % name)
            continue
        shown = int(row.group(1).replace("−", "-").replace("+", ""))
        if shown != weight:
            wrong.append("%s: в документе %s, в коде %s" % (name, shown, weight))
    assert wrong == [], wrong


def test_scoring_check_can_fail(doc):
    assert "signal_that_does_not_exist" not in doc


def test_email_every_dnsbl_zone_is_listed(doc):
    from core.mail_constants import DNSBL_ZONES, SPAMHAUS_ZONE

    missing = [z for z in list(DNSBL_ZONES) + [SPAMHAUS_ZONE] if z not in doc]
    assert missing == [], "зоны чёрных списков не перечислены: %s" % missing


def test_email_every_provider_with_name_rules_is_listed(doc):
    from core.local_rules import _RULES

    names = sorted({rule.name for rule in _RULES.values()})
    missing = [n for n in names if n not in doc]
    assert missing == [], "провайдеры с правилами имени не перечислены: %s" % missing


def test_email_every_verdict_status_is_listed(doc):
    for status in ("valid", "invalid", "risky", "unknown", "greylisted",
                   "catchall", "Role-based"):
        assert status in doc, status


def test_email_the_hard_won_rules_are_stated(doc):
    for rule in ("MAIL FROM", "5.1.1", "5.7.1", "postmaster", "Null MX",
                 "SMTPUTF8", "punycode", "тарпит", "catch-all",
                 "mail.ru", "500–504", "63 октета"):
        assert rule.lower() in doc.lower(), rule


def test_email_the_asymmetry_rule_is_stated(doc):
    assert "ТОЛЬКО при доказанном отсутствии" in doc


def test_proxy_every_profile_field_is_listed(doc):
    fields = ["exit_ip", "exit_addr", "latency_ms", "has_ptr", "rdns", "rdns_dirty",
              "in_dnsbl", "outlook_ok", "outlook_reason", "asn", "asn_country",
              "asn_org", "ip_type", "yahoo_ok", "icloud_ok"]
    missing = [f for f in fields if f not in doc]
    assert missing == [], "поля профиля прокси не перечислены: %s" % missing


def test_proxy_profile_fields_match_the_code():
    path = os.path.join(ROOT, "core", "proxy_probe.py")
    source = io.open(path, encoding="utf-8").read()
    block = source[source.index("empty = {"):]
    block = block[:block.index("}")]
    in_code = set(re.findall(r'"([a-z_]+)"\s*:', block))
    documented = {"exit_ip", "exit_addr", "latency_ms", "has_ptr", "rdns", "rdns_dirty",
                  "in_dnsbl", "outlook_ok", "outlook_reason", "asn",
                  "asn_country", "asn_org", "ip_type", "yahoo_ok", "icloud_ok"}
    assert in_code - documented == set(), "в коде есть поле, которого нет в списке: %s" % (in_code - documented)


def test_proxy_every_fitness_row_is_listed(doc):
    from core.proxy_profile import PROVIDER_FITNESS

    missing = [row for row in PROVIDER_FITNESS if row not in doc]
    assert missing == [], "строки таблицы пригодности не перечислены: %s" % missing


def test_proxy_the_hard_won_rules_are_stated(doc):
    for rule in ("порт 25", "EHLO", "FCrDNS", "SOCKS5", "SOCKS4",
                 "HTTP CONNECT", "RDAP", "затухание", "выходном"):
        assert rule.lower() in doc.lower(), rule


def test_numbers_in_the_doc_match_the_code(doc):
    import core.mail_constants as MC
    from core.heuristics import ROLE_EXACT
    from core.local_rules import _RULES
    from core.proxy_profile import PROVIDER_FITNESS
    from core.scoring import DEFAULT_WEIGHTS

    expected = {
        "сигналов оценки": (len(DEFAULT_WEIGHTS), r"\*\*(\d+) сигнал"),
        "зон DNSBL": (len(MC.DNSBL_ZONES), r"\*\*(\d+) зон\*\*"),
        "доменов с правилами": (len(_RULES), r"(\d+) домен(?:а|ов)?\*\*"),
        "провайдеров": (len({r.name for r in _RULES.values()}), r"\*\*(\d+) провайдер"),
        "шлюзов": (len(MC.SECURITY_GATEWAY_MX), r"\*\*(\d+) известных\*\*"),
        "одноразовых": (builtin_disposable_count(), r"\*\*(\d+) домен"),
        "строк пригодности": (len(PROVIDER_FITNESS), r"(\d+) строки"),
        "ролевых имён": (len(ROLE_EXACT),
                         r"\*\*(\d+) точн\w+ им\w+\*\*"),
        "селекторов DKIM": (len(MC._DKIM_BY_MX), r"\*\*(\d+) известных связок\*\*"),
        "запасных селекторов": (len(MC._DKIM_FALLBACK), r"\*\*(\d+)\s*\n?\s*запасных селектора\*\*"),
        "MAIL FROM": (len(MC.MAIL_FROM_POOL), r"\*\*Ротация `MAIL FROM`\*\* — (\d+) адрес"),
    }
    wrong = []
    for label, (in_code, pattern) in expected.items():
        found = re.search(pattern, doc)
        if not found:
            wrong.append("%s: числа в документе не нашлось (образец %s)" % (label, pattern))
            continue
        if int(found.group(1)) != in_code:
            wrong.append("%s: в документе %s, в коде %s" % (label, found.group(1), in_code))
    assert wrong == [], wrong


def test_numbers_role_count_matches_the_code(doc):
    from core.heuristics import ROLE_EXACT

    m = re.search(r"\*\*(\d+) точн\w+ им\w+\*\*", doc)
    assert m, "в критериях нет числа ролевых имён"
    assert int(m.group(1)) == len(ROLE_EXACT), (
        "в документе %s, в коде %d" % (m.group(1), len(ROLE_EXACT)))


COMMAND_ERRORS = [
    (500, "5.5.2 Syntax error, command unrecognized"),
    (501, "5.1.3 Bad recipient address syntax"),
    (501, "5.1.1 Bad address"),
    (501, "Syntax error in parameters or arguments"),
    (502, "5.5.1 Command not implemented"),
    (503, "5.5.1 Bad sequence of commands"),
    (504, "5.5.4 Command parameter not implemented"),
]


@pytest.mark.parametrize("code,msg", COMMAND_ERRORS)
def test_command_error_never_buries_a_mailbox(code, msg):
    from core.smtp_codes import classify_smtp_response

    verdict = classify_smtp_response(code, msg)
    assert verdict["status"] != "invalid", (code, msg, verdict)


def test_command_error_does_not_soften_a_real_verdict():
    from core.smtp_codes import classify_smtp_response

    for code in (550, 553):
        verdict = classify_smtp_response(code, "5.1.1 no such user")
        assert verdict["status"] == "invalid", (code, verdict)


def test_quoted_local_is_now_checked_not_just_spared():
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax('"john smith"@example.com') is True

    from core.network import NetworkValidator

    result = NetworkValidator(timeout=2).check_email('"john smith"@example.com')
    assert "Bad Syntax" not in result.get("reason", ""), result


def test_quoted_local_is_recognised_precisely():
    from core.email_syntax import has_quoted_local

    assert has_quoted_local('"john smith"@example.com') is True
    assert has_quoted_local('"a"@b.com') is True
    assert has_quoted_local("john@example.com") is False
    assert has_quoted_local('john"@example.com') is False
    assert has_quoted_local(None) is False


def test_quoted_does_not_open_the_door_to_junk():
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    for junk in ("no-at-sign", "a@@b.com", "@example.com", "a b@example.com"):
        assert v.check_email(junk)["status"] == "invalid", junk


def test_label_longer_than_63_is_rejected():
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax("user@" + "a" * 64 + ".com") is False
    assert validate_email_syntax("user@" + "a" * 250 + ".com") is False


def test_label_of_63_is_still_accepted():
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax("user@" + "a" * 63 + ".com") is True
    assert validate_email_syntax("ivan@gmail.com") is True
    assert validate_email_syntax("ivan@xn--80a1acny.xn--p1ai") is True
