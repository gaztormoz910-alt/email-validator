# -*- coding: utf-8 -*-
"""Находки аудита: то, что молча снижало точность проверки.

Главная — прокси не доходили до конвейера вовсе. Окно передавало ему список
ИСТОЧНИКОВ (словарей вида {"type": "text", "content": ...}), а он ждёт поток
строк «1.2.3.4:8080». Ни одна такая запись прокси не является, поэтому
проверка честно отвечала «Найдено рабочих прокси: 0 из 0» — при полутора
тысячах загруженных.

Последствие прямое: прогон шёл с домашнего адреса владельца. Yahoo и AOL
отказывают такому без FCrDNS, Outlook — по репутации, и почти вся база
уходит в RISKY. Со стороны это выглядит как «валидатор врёт», хотя врал не
он: ему просто не дали то, чем проверять.

Прежнее окно на CustomTkinter читало источники через StreamLoader и подавало
строки. При переезде интерфейса на веб-стек этот шаг потерялся.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network import dedupe_proxies_stream  # noqa: E402
from core.streamer import StreamLoader  # noqa: E402
from ui.webapp import ValidatorApi  # noqa: E402


SOURCES = [
    {"type": "text", "content": "1.2.3.4:8080\n5.6.7.8:3128", "title": "a.txt"},
    {"type": "text", "content": "socks5://9.9.9.9:1080", "title": "b.txt"},
]


# ─────────────────────────────────────────── прокси доходят до проверки

def test_proxies_sources_are_not_fed_to_the_checker_raw():
    """Словари прокси не являются — проверка получила бы ноль.

    Это и есть воспроизведение исходного дефекта: подаём то, что подавало
    окно, и убеждаемся, что на выходе пусто.
    """
    straight = list(dedupe_proxies_stream(SOURCES))
    assert straight == [], "источники вдруг стали разбираться как прокси"


def test_proxies_reach_the_checker_as_lines():
    """А через StreamLoader — доходят все до одного."""
    lines = list(dedupe_proxies_stream(StreamLoader(SOURCES).stream_lines()))
    assert lines == ["1.2.3.4:8080", "5.6.7.8:3128", "socks5://9.9.9.9:1080"], lines


def test_proxies_window_hands_the_pipeline_strings_not_dicts():
    """Окно обязано подавать конвейеру строки. Проверяется то, что реально уходит.

    Тест смотрит на аргумент, с которым позвали конвейер: именно там дефект и
    жил, а обе стороны по отдельности были исправны.
    """
    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080\n5.6.7.8:3128"})

    captured = {}

    def fake_start(**kwargs):
        captured.update(kwargs)

        class Done:
            def join(self):
                return None
        return Done()

    api.pipeline.start = fake_start
    assert api.start({})["ok"] is True

    proxies = list(captured["proxies"])
    assert proxies, "конвейеру не досталось ни одного прокси"
    for item in proxies:
        assert isinstance(item, str), "конвейеру ушёл %r вместо строки" % (item,)
    assert proxies == ["1.2.3.4:8080", "5.6.7.8:3128"], proxies


def test_proxies_from_a_file_reach_the_pipeline_too(tmp_path):
    """Файл и вставка обязаны работать одинаково — на прокси тоже."""
    listing = tmp_path / "proxy.txt"
    listing.write_text("\n".join("1.2.3.%d:8080" % i for i in range(1, 40)),
                       encoding="utf-8")

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api._pick_files = lambda kind: [str(listing)]
    api.choose({"kind": "proxies"})

    captured = {}

    def fake_start(**kwargs):
        captured.update(kwargs)

        class Done:
            def join(self):
                return None
        return Done()

    api.pipeline.start = fake_start
    api.start({})

    proxies = list(captured["proxies"])
    assert len(proxies) == 39, len(proxies)
    assert all(isinstance(p, str) for p in proxies)


def test_proxies_are_read_lazily_not_materialised():
    """Список прокси бывает на миллионы строк — читать его целиком нельзя."""
    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})

    captured = {}

    def fake_start(**kwargs):
        captured.update(kwargs)

        class Done:
            def join(self):
                return None
        return Done()

    api.pipeline.start = fake_start
    api.start({})
    assert not isinstance(captured["proxies"], (list, tuple)), \
        "прокси материализованы в память вместо ленивого чтения"


def test_proxies_empty_source_stays_empty():
    """Положительный контроль: пустой список не превращается в строки из ниоткуда."""
    assert list(dedupe_proxies_stream(StreamLoader([]).stream_lines())) == []


# ─────────────────────────── проверки, подтверждающие остальную часть аудита

def test_audit_classifier_holds_real_provider_replies():
    """Разбор ответов сервера проверен настоящими ответами почтовиков."""
    from core.smtp_codes import classify_smtp_response as classify

    cases = [
        (250, "2.1.5 OK", "valid"),
        (550, "5.1.1 The email account that you tried to reach does not exist.", "invalid"),
        (550, "5.7.1 No such user!", "invalid"),              # Yandex: смысл в тексте
        (550, "5.7.1 Service unavailable, Client host [1.2.3.4] blocked using Spamhaus",
         "unknown"),                                          # репутация, не ящик
        (452, "4.2.2 over quota", "valid"),                    # ящик есть и активен
        (452, "4.3.1 Insufficient system storage", "unknown"),  # место на СЕРВЕРЕ
        (552, "5.3.4 Message size exceeds fixed limit", "unknown"),
        (553, "5.1.8 Sender address rejected", "unknown"),      # отказ ОТПРАВИТЕЛЮ
    ]
    for code, text, want in cases:
        got = classify(code, text)["status"]
        assert got == want, (code, text, want, got)


def test_audit_scoring_obeys_the_priority_of_proof():
    """Вердикт сервера весит больше всех прочих сигналов вместе взятых."""
    from core.scoring import calculate_engagement_score as score

    def value(**kwargs):
        return score(email="ivan@gmail.com", **kwargs)["score"]

    bare_proof = value(smtp_status="Valid", smtp_reason="250 OK")
    everything_but_proof = value(
        smtp_status="Unknown", smtp_reason="timeout", has_gravatar=True,
        dns_health_score=100, domain_age_days=9000, has_ptr=True,
        has_starttls=True, name_extracted="Ivan Petrov")
    assert bare_proof > everything_but_proof, (bare_proof, everything_but_proof)

    # Доказанный Invalid обнуляет всё, каким бы хорошим ни был домен.
    assert value(smtp_status="Invalid/Bounce",
                 smtp_reason="550 5.1.1 does not exist",
                 has_gravatar=True, dns_health_score=100,
                 domain_age_days=9000) == 0

    # «Не проверено» не штрафуется наравне с «точно нет».
    unchecked = value(smtp_status="Valid", smtp_reason="250 OK",
                      has_ptr=None, has_starttls=None)
    known_bad = value(smtp_status="Valid", smtp_reason="250 OK",
                      has_ptr=False, has_starttls=False)
    assert unchecked >= known_bad, (unchecked, known_bad)


def test_audit_dedup_follows_provider_rules():
    """Точки схлопывает только Gmail; на чужом домене они значащие."""
    from core.cleaner import normalize_for_dedup as key

    assert key("john.doe@gmail.com") == key("johndoe@gmail.com")
    assert key("john+news@gmail.com") == key("john@gmail.com")
    assert key("j@googlemail.com") == key("j@gmail.com")

    assert key("john.doe@outlook.com") != key("johndoe@outlook.com")
    assert key("john.doe@corp.com") != key("johndoe@corp.com")
    assert key("john+tag@corp.com") != key("john@corp.com")


def test_audit_mailru_family_is_not_exempt_from_catch_all():
    """Mail.ru отвечает 250 на любой выдуманный адрес.

    Попади он в список «проверять на catch-all не нужно», все его
    несуществующие ящики уехали бы в Valid.
    """
    # Спрашиваем ПОВЕДЕНИЕ, а не текст исходника. Раньше проверка читала
    # символы вокруг строки `skip_catchall = (`, и когда список гигантов
    # переехал в одно место на модуль, она упала — при целом инварианте.
    # Поведенческая проверка вдобавок ловит случай, которого текстовая не
    # видит вовсе: список на месте, а условие перестало им пользоваться.
    from core.network import NetworkValidator

    nv = NetworkValidator(proxies=[])
    for domain in ("mail.ru", "bk.ru", "inbox.ru", "list.ru"):
        assert nv._is_never_catchall(domain) is False, \
            "%s снова освобождён от проверки на catch-all" % domain
    # Положительный контроль: у настоящих гигантов освобождение на месте.
    for domain in ("gmail.com", "yandex.ru", "icloud.com",
                   "yahoo.com", "outlook.com", "aol.com"):
        assert nv._is_never_catchall(domain) is True, domain
