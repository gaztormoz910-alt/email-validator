# -*- coding: utf-8 -*-
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network import NetworkValidator
from core.smtp_codes import classify_smtp_response


def validator():
    return NetworkValidator(timeout=2, proxy_dns=False)


def test_giants_are_control_probed_at_all():
    check = validator()
    assert check._time_to_recheck("gmail.com") is True, \
        "первая же проверка домена обязана быть контрольной"


def test_first_check_of_a_domain_is_always_controlled():
    check = validator()
    assert check._time_to_recheck("gmail.com") is True
    for _ in range(24):
        check._time_to_recheck("gmail.com")
    assert check._time_to_recheck("gmail.com") is True


def test_control_probe_stays_cheap():
    check = validator()
    hits = sum(1 for _ in range(500) if check._time_to_recheck("gmail.com"))
    assert hits <= 25, hits
    assert hits >= 15, hits


def test_domains_are_counted_separately():
    check = validator()
    assert check._time_to_recheck("gmail.com") is True
    assert check._time_to_recheck("yahoo.com") is True
    assert check._time_to_recheck("outlook.com") is True


def test_empty_domain_is_not_probed():
    assert validator()._time_to_recheck("") is False
    assert validator()._time_to_recheck(None) is False


def test_tarpit_is_not_called_catch_all():
    import io as _io

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "core", "network.py")
    with _io.open(path, encoding="utf-8") as handle:
        source = _io.StringIO(handle.read()).read()

    assert "наш IP под" in source
    assert "нужен чистый прокси" in source


def test_tarpit_domains_are_reported():
    check = validator()
    assert check.tarpit_domains() == []
    check._tarpit_domains.add("gmail.com")
    assert check.tarpit_domains() == ["gmail.com"]


def test_owner_is_told_to_fix_proxies_not_the_base():
    import io as _io

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "core", "pipeline.py")
    with _io.open(path, encoding="utf-8") as handle:
        source = handle.read()

    assert "НЕДОКАЗУЕМЫ" in source
    assert "чистый прокси" in source
    assert "ни при чём" in source


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
    assert classify_smtp_response(code, text)["status"] != "invalid", why


def test_gmail_honest_refusal_still_convicts():
    verdict = classify_smtp_response(
        550, "5.1.1 The email account that you tried to reach does not exist.")
    assert verdict["status"] == "invalid"


def test_rate_limit_is_retried_not_buried():
    from core.pipeline import _is_transient_failure

    assert _is_transient_failure("unknown", "421 Service Busy (Rate Limit)") is True
    assert _is_transient_failure("unknown", "our ip blocked") is True
    assert _is_transient_failure("unknown", "обратного DNS у нашего IP нет") is False
