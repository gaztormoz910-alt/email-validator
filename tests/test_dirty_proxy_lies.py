# -*- coding: utf-8 -*-
"""Ложь, которую порождает грязный прокси.

Вопрос владельца: могут ли прокси с плохой репутацией давать ложные
результаты — например, на Gmail.

Могут, и самым неприятным способом. Столкнувшись с перебором адресов с
подозрительного IP, крупные почтовики перестают отвечать честно и начинают
принимать ЛЮБОГО получателя: так они не дают выяснить, какие ящики
существуют. Для валидатора это худший из возможных ответов — сплошные
«Годен», ни один из которых ничего не значит, а узнаётся правда уже по
отскокам после рассылки.

До этой правки защиты не было вовсе: у гигантов и детектор catch-all, и
контрольная проба были выключены по соображению «Gmail не бывает catch-all».
Соображение верное — но только для чистого исходящего адреса.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network import NetworkValidator  # noqa: E402
from core.smtp_codes import classify_smtp_response  # noqa: E402


def validator():
    return NetworkValidator(timeout=2, proxy_dns=False)


# ═════════════════════════════ контроль у гигантов

def test_giants_are_control_probed_at_all():
    """У гигантов контрольная проба больше не выключена наглухо."""
    check = validator()
    assert check._time_to_recheck("gmail.com") is True, \
        "первая же проверка домена обязана быть контрольной"


def test_first_check_of_a_domain_is_always_controlled():
    """Если сервер уже тарпитит, узнать надо на первом адресе.

    Проверка «каждый двадцать пятый» без этого условия обнаружила бы обман
    только на двадцать шестом адресе, а первые двадцать пять уехали бы в
    «Годен».
    """
    check = validator()
    assert check._time_to_recheck("gmail.com") is True     # проверка №1
    for _ in range(24):                                     # проверки №2..25
        check._time_to_recheck("gmail.com")
    # Двадцать шестая приходит со счётчиком 25 — снова контрольная.
    assert check._time_to_recheck("gmail.com") is True


def test_control_probe_stays_cheap():
    """Проба стоит один лишний RCPT, но на миллионной базе и он заметен."""
    check = validator()
    hits = sum(1 for _ in range(500) if check._time_to_recheck("gmail.com"))
    assert hits <= 25, hits
    # И при этом не исчезает совсем.
    assert hits >= 15, hits


def test_domains_are_counted_separately():
    """Счётчик у каждого домена свой: иначе редкий домен никогда не проверят."""
    check = validator()
    assert check._time_to_recheck("gmail.com") is True
    assert check._time_to_recheck("yahoo.com") is True
    assert check._time_to_recheck("outlook.com") is True


def test_empty_domain_is_not_probed():
    assert validator()._time_to_recheck("") is False
    assert validator()._time_to_recheck(None) is False


# ═════════════════════════════ как это называется

def test_tarpit_is_not_called_catch_all():
    """Гигант, принявший выдуманный адрес, — это не catch-all.

    Разница не в словах: «домен catch-all» отправит владельца чистить базу, а
    чинить надо прокси. Формулировка обязана называть настоящую причину.
    """
    import io as _io

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "core", "network.py")
    with _io.open(path, encoding="utf-8") as handle:
        source = _io.StringIO(handle.read()).read()

    assert "наш IP под" in source
    assert "нужен чистый прокси" in source


def test_tarpit_domains_are_reported():
    """Список пойманных доменов доступен для отчёта."""
    check = validator()
    assert check.tarpit_domains() == []
    check._tarpit_domains.add("gmail.com")
    assert check.tarpit_domains() == ["gmail.com"]


def test_owner_is_told_to_fix_proxies_not_the_base():
    """Предупреждение обязано указывать на прокси, а не на базу."""
    import io as _io

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "core", "pipeline.py")
    with _io.open(path, encoding="utf-8") as handle:
        source = handle.read()

    assert "НЕДОКАЗУЕМЫ" in source
    # Проверяем короткими кусками. Длинная фраза в исходнике разбита на
    # несколько строковых литералов, и склейка через пробелы оставляет между
    # ними кавычки — проверка целой фразы ломалась бы на переносе.
    assert "чистый прокси" in source
    assert "ни при чём" in source


# ═══════════════════ прочая ложь грязного прокси — уже разобранная

@pytest.mark.parametrize("code,text,why", [
    (421, "4.7.0 Try again later", "Gmail придерживает подозрительный IP"),
    (421, "4.7.0 [1.2.3.4] Our system has detected an unusual rate of "
          "unsolicited mail originating from your IP address",
     "прямая жалоба Gmail на наш адрес"),
    (450, "4.2.1 The user you are trying to contact is receiving mail at a rate "
          "that prevents additional messages from being delivered",
     "ограничение скорости, не ящик"),
    (550, "5.7.1 [1.2.3.4] Our system has detected that this message is likely "
          "unsolicited mail", "репутация, не ящик"),
    (550, "5.7.1 Service unavailable, Client host [1.2.3.4] blocked using "
          "Spamhaus", "чёрный список"),
])
def test_dirty_ip_answers_never_become_a_death_sentence(code, text, why):
    """Ни один отказ по репутации не хоронит адрес.

    Это вторая половина той же беды: грязный прокси заставляет сервер
    отказывать НАМ, а неаккуратный валидатор запишет отказ на счёт ящика и
    выбросит живой контакт.
    """
    assert classify_smtp_response(code, text)["status"] != "invalid", why


def test_gmail_honest_refusal_still_convicts():
    """Положительный контроль: честный отказ Gmail остаётся приговором.

    Иначе «репутация не хоронит» достигалось бы тем, что не хоронит ничто, и
    мёртвые адреса поехали бы в рассылку.
    """
    verdict = classify_smtp_response(
        550, "5.1.1 The email account that you tried to reach does not exist.")
    assert verdict["status"] == "invalid"


def test_rate_limit_is_retried_not_buried():
    """Придержанный адрес обязан попасть в повтор, а не в вердикт."""
    from core.pipeline import _is_transient_failure

    assert _is_transient_failure("unknown", "421 Service Busy (Rate Limit)") is True
    assert _is_transient_failure("unknown", "our ip blocked") is True
    # А вот отсутствие FCrDNS повторять бессмысленно: ответ не изменится.
    assert _is_transient_failure("unknown", "обратного DNS у нашего IP нет") is False
