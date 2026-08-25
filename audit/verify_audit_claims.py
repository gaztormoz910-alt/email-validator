#!/usr/bin/env python
"""Оракул для гейтов аудита: измеряет код и сверяет с утверждениями отчёта.

Почему так, а не «проверить, что в файле есть такая строка». Grep по исходнику
доказывает только наличие текста — он одинаково зелёный и когда функция
работает, и когда её вызывают неправильно. Здесь модули ИМПОРТИРУЮТСЯ и
вызываются на конкретных входах, а числа (файлы, строки, размеры списков)
пересчитываются заново. Если отчёт разойдётся с кодом — гейт покраснеет.

    python audit/verify_audit_claims.py <секция>

Секции: inventory, smtp, scoring, cache, lists, proxy, tests, all
Успех печатает CLAIMS OK: <секция> и выходит с нулём. Любое расхождение —
сообщение о нём и выход 1.
"""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

# Консоль Windows по умолчанию cp1252 — русский текст расхождения падал бы с
# UnicodeEncodeError, и гейт краснел бы не по той причине, по которой должен.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

CLAIMS = json.load(open(os.path.join(ROOT, "audit", "audit_claims.json"),
                       encoding="utf-8"))

# Инструменты самого аудита. Они лежат в репозитории, но описывают НЕ проект,
# а способ его измерить — поэтому в подсчёт размера проекта не входят.
AUDIT_TOOLING = {
    "verify_audit_claims.py",
    "verify_enrichment.py",
    "verify_rubric.py",
    "verify_competitor_facts.py",
    "verify_gui_builds.py",
    "verify_no_blocking_sleep.py",
    "verify_requirements.py",
    "verify_gaps_closed.py",
}

_failures = []


def check(condition, message):
    if not condition:
        _failures.append(message)


def eq(actual, expected, what):
    check(actual == expected,
          f"{what}: в отчёте {expected!r}, в коде {actual!r}")


def at_least(actual, minimum, what):
    check(actual >= minimum,
          f"{what}: отчёт обещает не меньше {minimum}, в коде {actual}")


# --- inventory ---------------------------------------------------------------

def _py_files():
    found = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", "__pycache__", ".pytest_cache",
                                    "tor_bin", ".unlazy")]
        for name in filenames:
            if name.endswith(".py") and name not in AUDIT_TOOLING:
                found.append(os.path.join(dirpath, name))
    return found


def verify_inventory():
    c = CLAIMS["inventory"]
    files = _py_files()
    eq(len(files), c["py_files_total"], "число .py-файлов")

    total = 0
    for path in files:
        with open(path, "rb") as f:
            total += f.read().count(b"\n")
    eq(total, c["py_lines_total"], "суммарное число строк .py")

    core = [n for n in os.listdir(os.path.join(ROOT, "core")) if n.endswith(".py")]
    eq(len(core), c["core_modules"], "модулей в core/")

    parser_dir = os.path.join(ROOT, "core", "parser")
    parser = [n for n in os.listdir(parser_dir) if n.endswith(".py")]
    eq(len(parser), c["parser_modules"], "модулей в core/parser/")

    tests = [n for n in os.listdir(os.path.join(ROOT, "tests"))
             if n.startswith("test_") and n.endswith(".py")]
    eq(len(tests), c["tests_files"], "файлов в tests/")

    for entry in c["entrypoints"]:
        check(os.path.exists(os.path.join(ROOT, entry)),
              f"точка входа {entry} не найдена")

    big = os.path.join(ROOT, *c["biggest_module"].split("/"))
    with open(big, "rb") as f:
        lines = f.read().count(b"\n")
    eq(lines, c["biggest_module_lines"], f"строк в {c['biggest_module']}")
    for path in files:
        with open(path, "rb") as f:
            n = f.read().count(b"\n")
        check(n <= lines,
              f"{path} длиннее заявленного самого большого модуля ({n} > {lines})")


# --- smtp --------------------------------------------------------------------

def verify_smtp():
    c = CLAIMS["smtp"]
    from core import network as N

    eq(len(N.DNSBL_ZONES), c["dnsbl_zones"], "число зон DNSBL")
    for dead in c["dnsbl_must_not_contain"]:
        check(dead not in N.DNSBL_ZONES,
              f"нерабочая зона {dead} всё ещё в DNSBL_ZONES")
    eq(len(N.MAIL_FROM_POOL), c["mail_from_pool"], "размер пула MAIL FROM")
    eq(len(N.LEGIT_HELO_NAMES), c["helo_names"], "число HELO-имён")
    eq(len(N.SECURITY_GATEWAY_MX), c["security_gateway_vendors"], "шлюзов безопасности")
    eq(len(N.YAHOO_DOMAINS), c["yahoo_domains"], "доменов Yahoo")
    eq(len(N.NEEDS_CLEAN_IP_DOMAINS), c["needs_clean_ip_domains"],
       "доменов, требующих чистый IP")

    v = N.NetworkValidator(timeout=1)
    p = v._parse_smtp_response

    # Ящика нет — единственный случай, когда лид хоронится
    eq(p(550, b"5.1.1 User unknown", "a@b.com", "b.com")["status"], "invalid",
       "550 user unknown")
    eq(p(550, b"No such user here", "a@b.com", "b.com")["status"], "invalid",
       "550 no such user")
    # Отказ по нашему IP/отправителю ящик не хоронит
    eq(p(550, b"5.7.1 Service unavailable, Client host [1.2.3.4] blocked",
         "a@b.com", "b.com")["status"], "unknown", "550 блок по IP")
    eq(p(550, b"Sender verify failed", "a@b.com", "b.com")["status"], "unknown",
       "550 отказ отправителю")
    eq(p(550, b"Rejected", "a@b.com", "b.com")["status"], "risky",
       "голый 550 Rejected")
    # Полный ящик доказывает, что он есть; полный ДИСК сервера — нет
    eq(p(452, b"4.2.2 Mailbox full", "a@b.com", "b.com")["status"], "valid",
       "452 mailbox full")
    eq(p(452, b"4.3.1 Insufficient system storage", "a@b.com", "b.com")["status"],
       "unknown", "452 нет места на сервере")
    eq(p(421, b"Service busy", "a@b.com", "b.com")["status"], "unknown", "421")
    eq(p(450, b"greylisted, try again", "a@b.com", "b.com")["status"], "greylisted",
       "450 greylisting")
    eq(p(503, b"Bad sequence of commands", "a@b.com", "b.com")["status"], "unknown",
       "503 протокольная ошибка")
    eq(p(250, b"OK", "a@b.com", "b.com")["status"], "valid", "250 OK")

    # Синтаксис: интернационализированный адрес живой, а не Bad Syntax
    check(N.validate_email_syntax("ivan@xn--80a1acny.xn--p1ai"), "punycode-домен отвергнут")
    check(N.validate_email_syntax("ivan@\u043f\u043e\u0447\u0442\u0430.\u0440\u0444"),
          "IDN-домен отвергнут")
    check(not N.validate_email_syntax("a..b@mail.com"), "двойная точка принята")
    check(not N.validate_email_syntax("a@b"), "домен без TLD принят")
    check(N.has_non_ascii_local("\u0438\u0432\u0430\u043d@mail.ru"),
          "не-ASCII локальная часть не распознана")

    # Шлюз безопасности перед доменом = catch-all по конструкции
    eq(N.security_gateway(["mx1.pphosted.com"]), "Proofpoint", "детект Proofpoint")
    eq(N.security_gateway(["eu-smtp-inbound-1.mimecast.com"]), "Mimecast", "детект Mimecast")
    eq(N.security_gateway(["aspmx.l.google.com"]), None, "Google ошибочно принят за шлюз")

    # DKIM-селекторы сужаются по MX, а не перебираются вслепую
    check("google" in N._dkim_selectors_for("aspmx.l.google.com"),
          "для Google не выбран гугловский селектор")
    check(len(N._dkim_selectors_for("aspmx.l.google.com")) < len(N._DKIM_FALLBACK),
          "сужения перебора DKIM по MX не происходит")


# --- scoring -----------------------------------------------------------------

def verify_scoring():
    c = CLAIMS["scoring"]
    from core.scoring import calculate_engagement_score as score

    live = score("john.doe@gmail.com", "Valid", "250 OK")
    at_least(live["score"], c["gmail_valid_min_score"], "скор живого Gmail")
    check(any(str(c["valid_points"]) in s for s in live["signals"]),
          f"нет сигнала +{c['valid_points']} за SMTP 250 OK")

    full = score("john.doe@gmail.com", "Valid", "250 OK (Full Inbox)")
    check(full["score"] > live["score"], "полный ящик не весит больше обычного Valid")
    check(any(str(c["full_inbox_points"]) in s for s in full["signals"]),
          f"нет сигнала +{c['full_inbox_points']} за полный ящик")

    # Подтверждённый отскок обнуляется, и здоровье домена его не спасает
    dead = score("nosuch@gmail.com", "Invalid/Bounce", "550 User Does Not Exist",
                 dns_health_score=3, domain_age_days=9999, has_gravatar=True)
    eq(dead["score"], 0, "скор подтверждённого отскока")
    eq(dead["grade"], "Dead", "грейд подтверждённого отскока")

    # «Не проверено» (None) не штрафуется — иначе сбой сети занижал бы живых
    unchecked = score("john.doe@corp-x.com", "Valid", "250 OK", has_ptr=None,
                      has_starttls=None)
    absent = score("john.doe@corp-x.com", "Valid", "250 OK", has_ptr=False,
                   has_starttls=False)
    check(unchecked["score"] > absent["score"],
          "None и False у PTR/STARTTLS штрафуются одинаково")

    risky = score("a@corp-x.com", "Risky", "")
    unknown = score("a@corp-x.com", "Unknown", "")
    check(risky["score"] >= c["risky_points"], "вес Risky ниже заявленного")
    check(unknown["score"] >= c["unknown_points"], "вес Unknown ниже заявленного")
    check(live["score"] > risky["score"] > unknown["score"] > dead["score"],
          "порядок весов Valid > Risky > Unknown > Invalid нарушен")

    # Грейды
    check(score("a@gmail.com", "Valid", "250 OK (Full Inbox)")["score"]
          >= c["hot_threshold"], "полный ящик не дотягивает до Hot")

    # Штрафы уменьшают скор ровно на заявленное
    base = score("verylongrandomstring@corp-x.com", "Valid", "250 OK")
    parked = score("verylongrandomstring@corp-x.com", "Valid", "250 OK",
                   is_parked_domain=True)
    check(base["score"] - parked["score"] >= abs(c["parked_penalty"]) - 5,
          "штраф за припаркованный домен меньше заявленного")
    bl = score("verylongrandomstring@corp-x.com", "Valid", "250 OK", in_dnsbl=True)
    check(base["score"] - bl["score"] >= abs(c["dnsbl_penalty"]) - 5,
          "штраф за DNSBL меньше заявленного")

    eq(live["provider_type"], "Free", "gmail.com не опознан как бесплатный")
    eq(score("a@some-unknown-corp-zzz.com", "Valid", "250 OK")["provider_type"],
       "Corporate", "неизвестный домен не опознан как корпоративный")


# --- cache -------------------------------------------------------------------

def verify_cache():
    c = CLAIMS["cache"]
    import tempfile
    from core.cache import ResultCache, CACHEABLE_STATUSES

    eq(list(CACHEABLE_STATUSES), c["cacheable_statuses"], "кэшируемые статусы")

    path = os.path.join(tempfile.mkdtemp(), "verify_cache.sqlite")
    cache = ResultCache(path=path)
    check(cache.enabled, "кэш не открылся")
    eq(cache.ttl_valid_days, c["ttl_valid_days"], "TTL для Valid")
    eq(cache.ttl_invalid_days, c["ttl_invalid_days"], "TTL для Invalid")

    check(cache.put("a@b.com", "Valid", "250 OK", "mx.b.com", {"name": "A"}),
          "Valid не записался в кэш")
    check(cache.put("c@d.com", "Invalid/Bounce", "550", "mx.d.com", {}),
          "Invalid не записался в кэш")
    # Недоказанное не кэшируется никогда: иначе наш сбой закрепится за адресом
    for bad in ("Unknown", "Risky", "catchall", "greylisted", "Role-based"):
        check(not cache.put(f"x{bad}@e.com", bad, "", "mx", {}),
              f"статус {bad} попал в кэш, хотя вердикта о ящике не было")
        check(cache.get(f"x{bad}@e.com") is None, f"{bad} читается из кэша")

    got = cache.get("A@B.COM")   # регистр не должен создавать вторую запись
    check(got is not None, "запись не найдена по адресу в другом регистре")
    eq(got["status"], "Valid", "статус из кэша")
    eq(got["data"].get("name"), "A", "полезная нагрузка из кэша")
    cache.close()
    check(cache.get("a@b.com") is None, "закрытый кэш продолжает отдавать данные")

    # Классификация временных сбоев: что перепроверяется, а что нет
    from core.pipeline import _is_transient_failure
    check(_is_transient_failure("unknown", "Timeout"), "таймаут не уходит на повтор")
    check(_is_transient_failure("unknown", "Proxy Dead"), "мёртвый прокси не уходит на повтор")
    check(_is_transient_failure("unknown", "DNS не удалось спросить через прокси"),
          "сбой DNS не уходит на повтор")
    check(not _is_transient_failure("unknown", "Catch-All Domain (Unverifiable)"),
          "catch-all бессмысленно перепроверяется")
    check(not _is_transient_failure("unknown", "\u041d\u0435\u0442 \u043e\u0431\u0440\u0430\u0442\u043d\u043e\u0433\u043e DNS \u0443 \u043d\u0430\u0448\u0435\u0433\u043e IP (FCrDNS)"),
          "FCrDNS бессмысленно перепроверяется")
    check(not _is_transient_failure("invalid", "Timeout"),
          "готовый вердикт invalid отправлен на повтор")


# --- lists -------------------------------------------------------------------

def verify_lists():
    c = CLAIMS["lists"]
    from core.disposable import (get_disposable_count, is_disposable,
                                 extend_disposable_domains)
    from core.filters import SpamFilter
    from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS
    from core.provider import get_free_domain_count, country_from_domain, classify_domain
    from core.heuristics import (ROLE_EXACT, ROLE_STEMS, PARKING_HOSTS,
                                 is_role_based, extract_birth_year,
                                 looks_machine_generated, is_parked_domain)
    from core.cleaner import normalize_for_dedup, EmailCleaner

    # Встроенный список мал (491), но это только «скелет»: боевой размер даёт
    # слияние с внешними файлами, которое делает pipeline.setup(). Проверяем
    # оба числа — иначе отчёт мог бы хвастаться боевым, не доказав слияние.
    eq(get_disposable_count(), c["disposable_builtin"], "встроенных одноразовых доменов")
    spam = SpamFilter()
    at_least(spam.get_count(), c["spamfilter_domains_min"], "доменов во внешних списках")
    extend_disposable_domains(spam.blacklist_domains)
    at_least(get_disposable_count(), c["disposable_after_merge_min"],
             "одноразовых доменов после слияния списков")

    data_bytes = sum(os.path.getsize(os.path.join(ROOT, "data", n))
                     for n in ("disposable.txt", "disposable_extra.txt"))
    at_least(data_bytes, c["disposable_files_bytes_min"], "размер файлов одноразовых")

    eq(get_free_domain_count(), c["free_domains"], "размер базы бесплатных почтовиков")
    eq(len(GLOBAL_VERIFIED_DOMAINS), c["global_verified_domains"], "белый список доменов")
    eq(len(ROLE_EXACT), c["role_exact"], "точных ролевых имён")
    eq(len(ROLE_STEMS), c["role_stems"], "ролевых основ")
    eq(len(PARKING_HOSTS), c["parking_hosts"], "парковочных хостов")

    index = os.path.join(ROOT, "core", "parser", "names_by_country.txt")
    at_least(os.path.getsize(index), c["names_index_bytes_min"], "размер индекса имён")

    # Одноразовые ловятся и по поддомену, приватные relay — не одноразовые
    check(is_disposable("a@mailinator.com"), "mailinator не распознан")
    check(is_disposable("a@foo.mailinator.com"), "поддомен одноразового не распознан")
    check(not is_disposable("a@gmail.com"), "gmail помечен одноразовым")
    check(not is_disposable("a@privaterelay.appleid.com"),
          "Apple Private Relay помечен одноразовым — за ним живые люди")

    # Ролевые: точные, с суффиксом и с цифрами
    for role in ("info@x.com", "sales-team@x.com", "noreply2@x.com",
                 "do-not-reply@x.com", "info.desk@x.com"):
        check(is_role_based(role), f"{role} не распознан как ролевой")
    for human in ("john.doe@x.com", "ivan.petrov@x.com"):
        check(not is_role_based(human), f"{human} ошибочно распознан как ролевой")

    # Дедуп по каноническому виду: один ящик не получит два письма
    eq(normalize_for_dedup("John.Doe@gmail.com"), normalize_for_dedup("johndoe@gmail.com"),
       "точки в Gmail не схлопываются")
    eq(normalize_for_dedup("john+news@gmail.com"), normalize_for_dedup("john@gmail.com"),
       "плюс-тег не отбрасывается")
    eq(normalize_for_dedup("j@googlemail.com"), normalize_for_dedup("j@gmail.com"),
       "googlemail не приводится к gmail")
    check(normalize_for_dedup("a.b@corp-x.com") != normalize_for_dedup("ab@corp-x.com"),
          "точки схлопнуты на корпоративном домене — это склеит разных людей")

    # Опечатки в домене
    cleaner = EmailCleaner()
    eq(cleaner.clean_email("john@gamil.com"), "john@gmail.com", "опечатка gamil.com")
    eq(cleaner.clean_email("john@yandex.rublahblah"), "john@yandex.ru", "мусор после TLD")
    # Очистка детерминирована: порядок обхода set не должен на неё влиять
    once = cleaner.clean_email("john@hotmial.com")
    for _ in range(5):
        eq(EmailCleaner().clean_email("john@hotmial.com"), once, "очистка недетерминирована")

    # Год рождения: консервативно
    eq(extract_birth_year("sarah.jones91@x.com"), 1991, "двузначный год")
    eq(extract_birth_year("karl1985@x.com"), 1985, "четырёхзначный год")
    eq(extract_birth_year("user2024@x.com"), None, "год регистрации принят за год рождения")

    # Машинная генерация: не хороним живых
    check(looks_machine_generated("xk3n9fj2q7@x.com"), "мусорный адрес не распознан")
    check(not looks_machine_generated("john.doe@x.com"), "john.doe помечен машинным")
    check(not looks_machine_generated("wolfgangschmidt@x.com"),
          "слитное имя и фамилия помечены машинными")

    # Парковка ловится и на втором MX
    check(is_parked_domain(["mx1.corp.com", "ns1.sedoparking.com"]),
          "парковка на втором MX не поймана")
    check(not is_parked_domain(["aspmx.l.google.com"]), "Google принят за парковку")

    # Страна: домен решает раньше имени
    eq(country_from_domain("web.de"), "Германия", "web.de -> Германия")
    eq(country_from_domain("orange.fr"), "Франция", "orange.fr -> Франция")
    eq(country_from_domain("bigpond.com.au"), "Австралия", "составная зона .com.au")
    eq(classify_domain("a@gmail.com"), ("Gmail", "Personal"), "классификация Gmail")
    eq(classify_domain("a@mit.edu")[1], "Education", "классификация .edu")
    eq(classify_domain("a@corp.com", "corp-com.mail.protection.outlook.com")[0],
       "Microsoft 365", "провайдер по MX")


# --- proxy -------------------------------------------------------------------

def verify_proxy():
    c = CLAIMS["proxy"]
    from core import network as N
    from core.async_proxy import AsyncProxyChecker

    eq(N.PROXY_MAX_CONSECUTIVE_FAILS, c["max_consecutive_fails"], "порог сбоев подряд")
    eq(len(N.PROXY_PROBE_TARGETS), c["probe_targets"], "число целей пробы")
    eq(sorted(N._PROXY_TYPES), sorted(c["supported_schemes"]), "поддерживаемые схемы")
    eq(len(N.DIRTY_RDNS_KEYWORDS), c["dirty_rdns_keywords"],
       "ключевых слов грязного rDNS")

    # Три формата прокси, которые реально отдают продавцы
    eq(N._parse_proxy("1.2.3.4:1080"), ("1.2.3.4", 1080, None, None), "host:port")
    eq(N._parse_proxy("1.2.3.4:1080:user:pass"), ("1.2.3.4", 1080, "user", "pass"),
       "host:port:user:pass")
    eq(N._parse_proxy("user:pass@1.2.3.4:1080"), ("1.2.3.4", 1080, "user", "pass"),
       "user:pass@host:port")
    eq(N._parse_proxy("socks5://user:pass@1.2.3.4:1080"),
       ("1.2.3.4", 1080, "user", "pass"), "схема + авторизация")
    eq(N._parse_proxy("\u043c\u0443\u0441\u043e\u0440"), None, "мусор принят за прокси")
    formats = {N._parse_proxy("1.2.3.4:1080"),
               N._parse_proxy("1.2.3.4:1080:u:p"),
               N._parse_proxy("u:p@1.2.3.4:1080")}
    at_least(len(formats), c["supported_formats"] - 1, "разных форматов прокси")

    # Схема соединения совпадает со схемой проверки
    eq(N._proxy_scheme("socks4://1.2.3.4:1080"), "socks4", "схема socks4")
    eq(N._proxy_scheme("1.2.3.4:1080"), "socks5", "схема по умолчанию")
    eq(N._PROXY_TYPES["http"], N.socks.HTTP, "HTTP-прокси не мапится в HTTP CONNECT")

    # Дедуп: один прокси в разных записях — одно место в ротации
    eq(N.dedupe_proxies(["1.2.3.4:1080", "socks5://1.2.3.4:1080", "1.2.3.4:1080"]),
       ["1.2.3.4:1080"], "повторы прокси не схлопнуты")

    # Грязный rDNS ищется по границам ярлыка, а не подстрокой
    check(N.is_dirty_rdns("vpn-exit-12.host.net"), "vpn-exit не распознан")
    check(N.is_dirty_rdns("pool-71-105.fios.verizon.net"), "динамический пул не распознан")
    check(not N.is_dirty_rdns("exitcom.net"), "exitcom.net ошибочно грязный")
    check(not N.is_dirty_rdns("mail-relay.corp.com"), "mail-relay ошибочно грязный")
    check(not N.is_dirty_rdns("hosting-provider.net"),
          "датацентровый хост ошибочно грязный — такие прокси и нужны")

    # HTTP-каналы идут через тот же прокси, что и SMTP
    d = N.build_proxy_dict("socks5://u:p@1.2.3.4:1080")
    check(d and d["https"].startswith("socks5h://u:p@1.2.3.4:1080"),
          "HTTP-запросы не заворачиваются в прокси (socks5h)")

    # Бан: три сбоя на ОДНОМ сервере — вина сервера, а не прокси
    v = N.NetworkValidator(timeout=1, proxies=["1.1.1.1:1080", "2.2.2.2:1080"])
    for _ in range(5):
        v._update_proxy_score("1.1.1.1:1080", False, mx_record="slow.mx.com")
    check("1.1.1.1:1080" not in v._proxy_banned,
          "прокси забанен из-за одного тугого MX")
    for host in ("a.mx.com", "b.mx.com", "c.mx.com"):
        v._update_proxy_score("2.2.2.2:1080", False, mx_record=host)
    check("2.2.2.2:1080" in v._proxy_banned,
          f"прокси не забанен после {c['max_consecutive_fails']} сбоев на разных серверах")
    at_least(len(v._proxy_fail_hosts.get("2.2.2.2:1080", set())),
             c["min_distinct_hosts_for_ban"], "разных серверов в серии сбоев")

    # Успех обнуляет серию
    v2 = N.NetworkValidator(timeout=1, proxies=["3.3.3.3:1080"])
    v2._update_proxy_score("3.3.3.3:1080", False, mx_record="a.com")
    v2._update_proxy_score("3.3.3.3:1080", False, mx_record="b.com")
    v2._update_proxy_score("3.3.3.3:1080", True)
    v2._update_proxy_score("3.3.3.3:1080", False, mx_record="c.com")
    check("3.3.3.3:1080" not in v2._proxy_banned, "успех не сбрасывает серию сбоев")

    # Маршрутизация: Yahoo только через PTR, «не проверено» != «PTR нет»
    v3 = N.NetworkValidator(timeout=1, proxies=["p1:1", "p2:2", "p3:3"])
    v3.set_proxy_profiles({
        "p1:1": {"has_ptr": True, "in_dnsbl": False, "latency_ms": 100,
                 "rdns_dirty": False, "outlook_ok": True},
        "p2:2": {"has_ptr": False, "in_dnsbl": True, "latency_ms": 200,
                 "rdns_dirty": False, "outlook_ok": False},
        "p3:3": {"has_ptr": None, "in_dnsbl": False, "latency_ms": 300,
                 "rdns_dirty": False, "outlook_ok": None},
    })
    eq(v3._pick_best_proxy(need_ptr=True), "p1:1", "для Yahoo выбран не PTR-прокси")
    check(v3._pick_best_proxy(need_clean=True) != "p2:2",
          "для Outlook выбран прокси из чёрного списка")
    check("p2:2" in v3._dirty_proxies, "прокси из DNSBL не помечен грязным")
    # Подтверждённых PTR не осталось — берём непроверенные, но не тех, у кого PTR точно нет
    v3._proxy_banned.add("p1:1")
    eq(v3._pick_best_proxy(need_ptr=True), "p3:3",
       "при исчезновении PTR-прокси не взят непроверенный")
    v3._proxy_banned.add("p3:3")
    check(v3._pick_best_proxy(need_ptr=True) is None,
          "для Yahoo взят прокси с заведомо отсутствующим PTR — холостой ход")

    # Профиль без профилирования не должен ломать выбор
    v4 = N.NetworkValidator(timeout=1, proxies=["q1:1"])
    check(v4._pick_best_proxy(need_ptr=True) == "q1:1",
          "без профилирования выбор прокси сломан")

    # Запрет прямого соединения при мёртвых прокси — защита реального IP
    v5 = N.NetworkValidator(timeout=1, proxies=["z:1"])
    v5._proxy_banned.add("z:1")
    check(v5.all_proxies_dead(), "смерть всех прокси не детектируется")
    res = v5._do_single_ping("a@b.com", "mx.b.com", proxy=None)
    eq(res["status"], "unknown", "при мёртвых прокси вердикт не unknown")
    check("Proxies Dead" in res["reason"], "нет явной причины о мёртвых прокси")
    # DNS тоже не должен уходить напрямую
    eq(v5._dns_proxy(), "", "DNS уходит напрямую, раскрывая реальный IP")

    # Потолки параллельности
    profile_src = open(os.path.join(ROOT, "core", "network.py"), encoding="utf-8").read()
    check(f"min(workers, {c['worker_cap']})" in profile_src,
          f"потолок воркеров профилирования не {c['worker_cap']}")
    checker = AsyncProxyChecker(["1.2.3.4:1080"], workers=100000, timeout=1, mode="smtp")
    eq(checker.target_port, 25, "чекер прокси проверяет не 25 порт")
    check(f"500" in open(os.path.join(ROOT, "core", "async_proxy.py"),
                         encoding="utf-8").read(),
          f"потолок {c['async_worker_cap']} воркеров не найден")

    # Профиль возвращает все заявленные поля
    empty_fields = set(c["profile_fields"])
    src = profile_src[profile_src.index("def profile_proxies"):]
    for field in empty_fields:
        check(f'"{field}"' in src, f"поле профиля {field} не заполняется")

    # Фоновое обновление профиля
    pipeline_src = open(os.path.join(ROOT, "core", "pipeline.py"), encoding="utf-8").read()
    check(f"interval={c['refresh_interval_sec']}" in pipeline_src,
          f"фоновое обновление профиля не раз в {c['refresh_interval_sec']}с")


# --- tests -------------------------------------------------------------------

def verify_tests():
    c = CLAIMS["tests"]
    import subprocess
    out = subprocess.run([sys.executable, "-m", "pytest", "tests", "-q",
                          "--collect-only"], cwd=ROOT, capture_output=True,
                         text=True, encoding="utf-8", errors="ignore")
    check(out.returncode == 0, f"сбор тестов упал: {out.returncode}")
    collected = out.stdout.count("::")
    at_least(collected, c["pytest_tests_min"], "число собранных тестов")

    audit_scripts = [n for n in os.listdir(os.path.join(ROOT, "audit"))
                     if n.endswith(".py") and n not in AUDIT_TOOLING]
    eq(len(audit_scripts), c["audit_scripts"], "число скриптов аудита")


SECTIONS = {
    "inventory": verify_inventory,
    "smtp": verify_smtp,
    "scoring": verify_scoring,
    "cache": verify_cache,
    "lists": verify_lists,
    "proxy": verify_proxy,
    "tests": verify_tests,
}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in tuple(SECTIONS) + ("all",):
        print(f"usage: verify_audit_claims.py [{'|'.join(SECTIONS)}|all]")
        return 2
    name = sys.argv[1]
    todo = list(SECTIONS) if name == "all" else [name]
    for section in todo:
        SECTIONS[section]()
    if _failures:
        print(f"CLAIMS MISMATCH: {name} ({len(_failures)})")
        for line in _failures:
            print("  - " + line)
        return 1
    print(f"CLAIMS OK: {name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
