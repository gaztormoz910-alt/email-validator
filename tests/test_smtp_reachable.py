# -*- coding: utf-8 -*-
from исходники import исходник_конвейера
import inspect
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_exists_the_whole_smtp_dialogue():
    from core.network import NetworkValidator

    for name in ("check_email", "stealth_smtp_ping", "_do_single_ping",
                 "is_catch_all_domain", "postmaster_is_honored",
                 "_parse_smtp_response"):
        assert callable(getattr(NetworkValidator, name, None)), name


def test_exists_real_socket_on_port_25():
    source = inspect.getsource(
        __import__("core.network", fromlist=["x"]))
    assert "server.connect(mx_record, 25)" in source


def test_exists_rcpt_to_is_the_probe():
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    assert "server.rcpt(email)" in source
    assert "server.mail(from_addr)" in source


def test_exists_verdicts_come_from_the_server_answer():
    from core.smtp_codes import classify_smtp_response

    assert classify_smtp_response(250, "2.1.5 OK")["status"] == "valid"
    assert classify_smtp_response(
        550, "5.1.1 no such user")["status"] == "invalid"
    assert classify_smtp_response(
        550, "5.7.1 blocked by policy")["status"] == "unknown"


def test_exists_pipeline_actually_calls_it():
    source = исходник_конвейера()
    assert "res = self.network.check_email(email)" in source


def test_direct_run_is_allowed_without_proxies():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    sources = api.sources()
    assert sources["ready"] is True
    assert sources["direct"] is True


def test_direct_run_hint_names_who_will_not_answer():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    hint = api.sources()["hint"]
    for name in ("Gmail", "Яндекс", "Yahoo", "AOL", "Outlook", "iCloud"):
        assert name in hint, hint


def test_direct_run_is_not_direct_when_proxies_are_loaded():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})
    sources = api.sources()
    assert sources["direct"] is False
    assert sources["hint"] == "Всё готово — можно запускать"


def test_direct_run_still_needs_addresses():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    answer = api.start({})
    assert answer["ok"] is False
    assert "адреса" in answer["error"]


def test_consent_is_required_before_running_direct():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    answer = api.start({})
    assert answer["ok"] is False
    assert answer.get("direct") is True
    assert "домашнего IP" in answer["error"]


def test_consent_given_lets_the_run_start():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    started = api.start({"allowDirect": True})
    try:
        assert started["ok"] is True
    finally:
        api.stop()


def test_consent_is_asked_by_the_window_too():
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    assert "res.direct" in js
    assert "window.confirm" in js
    assert "allowDirect" in js


def test_consent_warning_reaches_the_log():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.start({"allowDirect": True})
    try:
        text = " ".join(line["text"] for line in api.log_tail()["log"])
        assert "домашнего IP" in text
    finally:
        api.stop()


def test_enough_stops_the_sweep_when_the_quota_is_reached():
    from core import proxy_probe

    calls = {"fed": 0}

    def fake_checker(proxies, workers, timeout, mode, progress_callback):
        live = []
        for item in proxies:
            calls["fed"] += 1
            live.append(item)
            progress_callback(len(live), len(live), len(live))
        return live

    from core import async_proxy

    original = async_proxy.run_async_checker
    async_proxy.run_async_checker = lambda **kw: fake_checker(
        kw["proxies"], kw["workers"], kw["timeout"], kw["mode"],
        kw["progress_callback"])
    try:
        source = ("10.0.0.%d:8080" % i for i in range(1, 500))
        live, seen = proxy_probe.filter_live_proxies(
            source, timeout=1, threads=4, enough=25)
    finally:
        async_proxy.run_async_checker = original

    assert len(live) >= 25
    assert calls["fed"] < 100, "перебор не остановился: подано %d" % calls["fed"]


def test_enough_zero_checks_everything():
    from core import proxy_probe

    def fake_checker(proxies, workers, timeout, mode, progress_callback):
        live = []
        for item in proxies:
            live.append(item)
            progress_callback(len(live), len(live), len(live))
        return live

    from core import async_proxy

    original = async_proxy.run_async_checker
    async_proxy.run_async_checker = lambda **kw: fake_checker(
        kw["proxies"], kw["workers"], kw["timeout"], kw["mode"],
        kw["progress_callback"])
    try:
        source = ("10.0.0.%d:8080" % i for i in range(1, 60))
        live, seen = proxy_probe.filter_live_proxies(
            source, timeout=1, threads=4, enough=0)
    finally:
        async_proxy.run_async_checker = original

    assert seen == 59, seen


def test_opt_in_default_is_check_everything():
    from core.settings import DEFAULTS

    assert DEFAULTS["proxy_enough"] == 0


def test_opt_in_pipeline_reads_the_setting():
    source = исходник_конвейера()
    assert 'setting("proxy_enough", 0)' in source
    assert "enough=max(0, enough)" in source


def test_says_how_the_proxy_sweep_ended():
    source = исходник_конвейера()
    assert "живых %d из %d" in source


def test_says_what_zero_live_proxies_means():
    source = исходник_конвейера()
    assert "Вердиктов не будет" in source
    assert "make_vps_proxy" in source


def test_says_when_there_are_too_few():
    source = исходник_конвейера()
    assert "Живых прокси всего" in source


RELAYS = [
    "duck.com", "relay.firefox.com", "privaterelay.appleid.com",
    "mozmail.com", "icloud.com",
    "simplelogin.com", "simplelogin.io", "simplelogin.co", "simplelogin.fr",
    "aleeas.com", "slmail.me", "8shield.net",
    "dralias.com", "silomails.com", "slmails.com", "8alias.com", "pass2mail.com",
    "anonaddy.com", "anonaddy.me", "addy.io",
    "passmail.net", "passmail.com", "passinbox.com", "passfwd.com",
    "33mail.com", "burnermail.io", "erine.email",
    "sneakemail.com", "getburner.email",
    "mailsire.com", "hideaddress.net", "secret.fyi", "hash.fyi",
    "opayq.com", "blurme.net", "blurmail.net",
]


@pytest.mark.parametrize("domain", RELAYS)
def test_relay_survives_an_external_blacklist(domain):
    from core.disposable import extend_disposable_domains, is_disposable

    extend_disposable_domains([domain])
    assert is_disposable("user@" + domain) is False


def test_relay_guard_does_not_break_real_disposables():
    from core.disposable import extend_disposable_domains, is_disposable

    extend_disposable_domains(["some-temp-domain-for-the-test.example"])
    assert is_disposable("user@some-temp-domain-for-the-test.example") is True
    assert is_disposable("user@mailinator.com") is True
    assert is_disposable("user@sub.mailinator.com") is True


def test_relay_guard_lists_exactly_what_the_comment_promised():
    from core.disposable import NEVER_DISPOSABLE

    assert set(NEVER_DISPOSABLE) == set(RELAYS)


def test_relay_list_is_one_object_for_both_checks():
    from core.disposable import NEVER_DISPOSABLE
    from core.heuristics import PRIVACY_RELAY_DOMAINS

    assert PRIVACY_RELAY_DOMAINS is NEVER_DISPOSABLE


def test_relay_is_actually_in_the_shipped_blacklist():
    path = os.path.join(ROOT, "data", "disposable_more.txt")
    if not os.path.exists(path):
        pytest.skip("файл внешнего списка отсутствует")
    listed = {line.strip().lower()
              for line in io.open(path, encoding="utf-8", errors="replace")}
    assert "duck.com" in listed, "в списке больше нет duck.com — проверка холостая"
