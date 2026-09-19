# -*- coding: utf-8 -*-
"""Список критериев сверяется с кодом, а не с памятью автора.

Обещание «все критерии без исключения» проверяемо только машиной. Документ,
написанный один раз и оставленный жить своей жизнью, через месяц врёт: код
меняется, документ нет. Поэтому здесь проверяется не текст, а СООТВЕТСТВИЕ:
появится новый сигнал оценки или новая зона чёрного списка — проверка упадёт,
пока его не впишут в документ.

Обратная сторона тоже держится: числа в документе сверяются с кодом. Документ,
где написано «7 зон», а в коде их пять, хуже отсутствия документа — он даёт
уверенность вместо знания.
"""
import io
import os
import re
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOC_PATH = os.path.join(ROOT, "docs", "КРИТЕРИИ.md")


def builtin_disposable_count():
    """Сколько одноразовых доменов ВСТРОЕНО в код.

    Живой счётчик для этого не годится: список пополняется внешними файлами
    прямо в памяти, и соседний тест, вызвавший обновление, менял бы число.
    Считаем literal-ы в исходнике — они и есть встроенная база.
    """
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


# ═══════════════════════════════ G1: изучен весь код

def engine_modules():
    """Модули движка — те, из которых собирается проверка."""
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
    """Каждый модуль либо участвует в критериях, либо назван как не участвующий.

    Без этой проверки «изучил весь проект» — просто слова. Молча забытый
    модуль ничем не отличается от неизученного.
    """
    missing = [m for m in engine_modules() if m not in doc]
    assert missing == [], "модули не упомянуты в документе: %s" % missing


def test_modules_list_is_not_empty():
    """Отрицательный контроль: обход находит модули, а не пустоту."""
    found = engine_modules()
    assert len(found) > 30, len(found)
    assert "core/network.py" in found
    assert "core/scoring.py" in found


# ═══════════════════════════════ G2: все сигналы оценки

def test_scoring_every_signal_is_listed(doc):
    """Все 23 сигнала оценки живости названы поимённо.

    Пропущенный сигнал — это балл, который начисляется или снимается, а
    владелец о нём не знает и объяснить оценку не может.
    """
    from core.scoring import DEFAULT_WEIGHTS

    missing = [name for name in DEFAULT_WEIGHTS if name not in doc]
    assert missing == [], "сигналы оценки не перечислены: %s" % missing


def test_scoring_weights_in_the_doc_match_the_code(doc):
    """И веса те же, что в коде: список с чужими числами вводит в заблуждение."""
    from core.scoring import DEFAULT_WEIGHTS

    wrong = []
    for name, weight in DEFAULT_WEIGHTS.items():
        # Строка таблицы вида «| `smtp_valid` … | +55 |» или «| −50 |».
        row = re.search(r"`%s`[^|]*\|\s*([+−-]?\d+)\s*\|" % re.escape(name), doc)
        if not row:
            wrong.append("%s: строки в таблице нет" % name)
            continue
        shown = int(row.group(1).replace("−", "-").replace("+", ""))
        if shown != weight:
            wrong.append("%s: в документе %s, в коде %s" % (name, shown, weight))
    assert wrong == [], wrong


def test_scoring_check_can_fail(doc):
    """Отрицательный контроль: выдуманный сигнал в документе не найдётся."""
    assert "signal_that_does_not_exist" not in doc


# ═══════════════════════════════ G3: все критерии почты

def test_email_every_dnsbl_zone_is_listed(doc):
    from core.mail_constants import DNSBL_ZONES, SPAMHAUS_ZONE

    missing = [z for z in list(DNSBL_ZONES) + [SPAMHAUS_ZONE] if z not in doc]
    assert missing == [], "зоны чёрных списков не перечислены: %s" % missing


def test_email_every_provider_with_name_rules_is_listed(doc):
    """13 провайдеров, у которых проверяются правила имени ящика."""
    from core.local_rules import _RULES

    names = sorted({rule.name for rule in _RULES.values()})
    missing = [n for n in names if n not in doc]
    assert missing == [], "провайдеры с правилами имени не перечислены: %s" % missing


def test_email_every_verdict_status_is_listed(doc):
    """Каждый статус, который валидатор может выдать."""
    for status in ("valid", "invalid", "risky", "unknown", "greylisted",
                   "catchall", "Role-based"):
        assert status in doc, status


def test_email_the_hard_won_rules_are_stated(doc):
    """Правила, каждое из которых было куплено найденным багом.

    Список не должен превратиться в перечень функций: половина ценности — в
    оговорках, из-за отсутствия которых валидатор врал.
    """
    for rule in ("MAIL FROM", "5.1.1", "5.7.1", "postmaster", "Null MX",
                 "SMTPUTF8", "punycode", "тарпит", "catch-all",
                 "mail.ru", "500–504", "63 октета"):
        assert rule.lower() in doc.lower(), rule


def test_email_the_asymmetry_rule_is_stated(doc):
    """Главное правило всей области названо прямо."""
    assert "ТОЛЬКО при доказанном отсутствии" in doc


# ═══════════════════════════════ G4: все критерии прокси

def test_proxy_every_profile_field_is_listed(doc):
    """Каждое поле профиля прокси названо в документе."""
    fields = ["exit_ip", "latency_ms", "has_ptr", "rdns", "rdns_dirty",
              "in_dnsbl", "outlook_ok", "outlook_reason", "asn", "asn_country",
              "asn_org", "ip_type", "yahoo_ok", "icloud_ok"]
    missing = [f for f in fields if f not in doc]
    assert missing == [], "поля профиля прокси не перечислены: %s" % missing


def test_proxy_profile_fields_match_the_code():
    """Список полей выше — не выдумка: столько же их и в самом профиле.

    Проверка смотрит в исходник, потому что снять профиль вживую здесь нельзя:
    для этого нужен рабочий прокси и сеть.
    """
    path = os.path.join(ROOT, "core", "proxy_probe.py")
    source = io.open(path, encoding="utf-8").read()
    block = source[source.index("empty = {"):]
    block = block[:block.index("}")]
    in_code = set(re.findall(r'"([a-z_]+)"\s*:', block))
    documented = {"exit_ip", "latency_ms", "has_ptr", "rdns", "rdns_dirty",
                  "in_dnsbl", "outlook_ok", "outlook_reason", "asn",
                  "asn_country", "asn_org", "ip_type", "yahoo_ok", "icloud_ok"}
    assert in_code - documented == set(), "в коде есть поле, которого нет в списке: %s" % (in_code - documented)


def test_proxy_every_fitness_row_is_listed(doc):
    """Таблица «что этот пул откроет» перенесена целиком."""
    from core.proxy_profile import PROVIDER_FITNESS

    missing = [row for row in PROVIDER_FITNESS if row not in doc]
    assert missing == [], "строки таблицы пригодности не перечислены: %s" % missing


def test_proxy_the_hard_won_rules_are_stated(doc):
    """Оговорки, без которых проверка прокси теряет смысл."""
    for rule in ("порт 25", "EHLO", "FCrDNS", "SOCKS5", "SOCKS4",
                 "HTTP CONNECT", "RDAP", "затухание", "выходном"):
        assert rule.lower() in doc.lower(), rule


# ═══════════════════════════════ G5: числа не разъезжаются с кодом

def test_numbers_in_the_doc_match_the_code(doc):
    """Каждое число, которым документ хвалится, берётся из кода.

    Это и есть механизм, который не даст списку устареть незаметно: добавят
    домен в правила имени — упадёт здесь, а не на живой базе.
    """
    import core.mail_constants as MC
    from core.heuristics import ROLE_EXACT
    from core.local_rules import _RULES
    from core.proxy_profile import PROVIDER_FITNESS
    from core.scoring import DEFAULT_WEIGHTS

    expected = {
        "сигналов оценки": (len(DEFAULT_WEIGHTS), r"\*\*(\d+) сигнал"),
        "зон DNSBL": (len(MC.DNSBL_ZONES), r"\*\*(\d+) зон\*\*"),
        # Окончание берётся по-русски от числа: 81 «домен», 83 «домена»,
        # 85 «доменов». Образец, знавший одну форму, падал не на расхождении
        # с кодом, а на грамматике — и находил в документе ЧУЖОЕ число.
        "доменов с правилами": (len(_RULES), r"(\d+) домен(?:а|ов)?\*\*"),
        "провайдеров": (len({r.name for r in _RULES.values()}), r"\*\*(\d+) провайдер"),
        "шлюзов": (len(MC.SECURITY_GATEWAY_MX), r"\*\*(\d+) известных\*\*"),
        "одноразовых": (builtin_disposable_count(), r"\*\*(\d+) домен"),
        "строк пригодности": (len(PROVIDER_FITNESS), r"(\d+) строки"),
        # Число берётся ИЗ КОДА. Литерал 41 стоял здесь и в проверке
        # ниже, и при расширении списка падали обе — хотя расходились
        # они не с кодом, а со своей же прошлой копией. Образец
        # принимает и «точное имя», и «точных имён»: число меняет форму
        # слова.
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
    """Число ролевых имён в документе равно длине списка в коде.

    Раньше здесь стояло `len(ROLE_EXACT) == 41` — код сверялся с литералом, а
    не документ с кодом, хотя докстринг обещал обратное. Разойтись 41 могло
    только сама с собой, зато расширить список эта проверка запрещала.
    """
    from core.heuristics import ROLE_EXACT

    m = re.search(r"\*\*(\d+) точн\w+ им\w+\*\*", doc)
    assert m, "в критериях нет числа ролевых имён"
    assert int(m.group(1)) == len(ROLE_EXACT), (
        "в документе %s, в коде %d" % (m.group(1), len(ROLE_EXACT)))


# ═══════════════════════════════ G6: 500-504 не выносит приговор

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
    """«Не понял команду» — это про наш диалог, а не про ящик.

    Ловушка была в расширенном коде: `501 5.1.3` попадал в ветку «5.1.x —
    ящика нет» и давал приговор. Между тем 5.1.3 означает «адрес разобрать не
    удалось», а настоящее отсутствие ящика приходит кодом 550.
    """
    from core.smtp_codes import classify_smtp_response

    verdict = classify_smtp_response(code, msg)
    assert verdict["status"] != "invalid", (code, msg, verdict)


def test_command_error_does_not_soften_a_real_verdict():
    """Обратная сторона: 550 с тем же расширенным кодом по-прежнему приговор.

    Ослабить настоящее доказательство, чиня ложное, значило бы обменять одну
    ошибку на противоположную — мёртвые адреса поехали бы в рассылку.
    """
    from core.smtp_codes import classify_smtp_response

    for code in (550, 553):
        verdict = classify_smtp_response(code, "5.1.1 no such user")
        assert verdict["status"] == "invalid", (code, verdict)


# ═══════════════════════════════ G7: адрес в кавычках не хоронится

def test_quoted_local_is_now_checked_not_just_spared():
    """`"john smith"@example.com` законен по RFC 5321 §4.1.2 — и ПРОВЕРЯЕТСЯ.

    Прежнее ожидание этой проверки закрепляло промежуточное решение: адрес
    получал «не проверено» с честной причиной вместо приговора. Это было
    лучше приговора, но хуже проверки, и решение снято: грамматика в
    кавычках разбирается, RCPT строит smtplib (quoteaddr кавычки сохраняет),
    и адрес идёт в сеть наравне с обычным.

    Ожидание переписано СОЗНАТЕЛЬНО, а не подогнано: раз поведение стало
    лучше, проверка обязана закреплять новое, а не сторожить старое.
    """
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax('"john smith"@example.com') is True

    # И до сети такой адрес доходит: отказ, если он будет, приходит от DNS
    # или сервера, а не от нашей регулярки.
    from core.network import NetworkValidator

    result = NetworkValidator(timeout=2).check_email('"john smith"@example.com')
    assert "Bad Syntax" not in result.get("reason", ""), result


def test_quoted_local_is_recognised_precisely():
    """Распознаётся именно кавычки, а не любой странный адрес."""
    from core.email_syntax import has_quoted_local

    assert has_quoted_local('"john smith"@example.com') is True
    assert has_quoted_local('"a"@b.com') is True
    assert has_quoted_local("john@example.com") is False
    assert has_quoted_local('john"@example.com') is False
    assert has_quoted_local(None) is False


def test_quoted_does_not_open_the_door_to_junk():
    """Обратная сторона: настоящий мусор по-прежнему отбраковывается."""
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    for junk in ("no-at-sign", "a@@b.com", "@example.com", "a b@example.com"):
        assert v.check_email(junk)["status"] == "invalid", junk


# ═══════════════════════════════ G8: метка домена не длиннее 63 октетов

def test_label_longer_than_63_is_rejected():
    """RFC 1035 §2.3.4: метки длиннее 63 октетов в DNS не существует.

    Адрес с такой меткой проходил синтаксис и тратил впустую запрос DNS и
    попытку SMTP — на большой базе это заметная доля пустой работы.
    """
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax("user@" + "a" * 64 + ".com") is False
    assert validate_email_syntax("user@" + "a" * 250 + ".com") is False


def test_label_of_63_is_still_accepted():
    """Обратная сторона: ровно 63 — законная метка, отвергать её нельзя."""
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax("user@" + "a" * 63 + ".com") is True
    assert validate_email_syntax("ivan@gmail.com") is True
    assert validate_email_syntax("ivan@xn--80a1acny.xn--p1ai") is True
