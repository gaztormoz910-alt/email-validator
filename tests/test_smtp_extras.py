# -*- coding: utf-8 -*-
from исходники import исходник_конвейера
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class FakeServer:

    def __init__(self, extensions=("smtputf8",), rcpt=(250, b"2.1.5 OK"),
                 mail=(250, b"2.1.0 Ok"), vrfy=None):
        self.extensions = {e.lower() for e in extensions}
        self._rcpt = rcpt
        self._mail = mail
        self._vrfy = vrfy
        self.command_encoding = "ascii"
        self.mail_options = None
        self.rcpt_seen = []
        self.vrfy_seen = []

    def has_extn(self, name):
        return name.lower() in self.extensions

    def mail(self, sender, options=None):
        self.mail_options = list(options or [])
        return self._mail

    def rcpt(self, recipient, options=None):
        self.rcpt_seen.append(recipient)
        return self._rcpt

    def verify(self, address):
        self.vrfy_seen.append(address)
        if self._vrfy is None:
            raise RuntimeError("VRFY выключен")
        return self._vrfy


def validator():
    from core.network import NetworkValidator

    return NetworkValidator(timeout=2)


def test_utf8_is_requested_when_the_server_offers_it():
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    assert 'server.has_extn("smtputf8")' in source
    assert 'mail_options = ["SMTPUTF8"]' in source
    assert 'server.command_encoding = "utf-8"' in source


def test_utf8_command_encoding_is_switched():
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    order = source.index('server.command_encoding = "utf-8"')
    call = source.index("mail_code, mail_msg = server.mail(from_addr, options=mail_options)")
    assert order < call, "кодировку переключают уже после отправки команды"


def test_utf8_without_the_extension_is_unproven_not_dead():
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    assert 'сервер не объявил "\n                                   "SMTPUTF8' in source \
        or "не объявил" in source
    block = source[source.index("if has_non_ascii_local(email):"):]
    block = block[:block.index("mail_code")]
    assert '"status": "unknown"' in block
    assert "invalid" not in block


def test_utf8_syntax_still_accepts_the_address():
    from core.email_syntax import has_non_ascii_local, validate_email_syntax

    assert validate_email_syntax("иван@почта.рф") is True
    assert has_non_ascii_local("иван@почта.рф") is True


QUOTED_OK = [
    '"john smith"@example.com',
    '"a@b"@example.com',
    '"quoted"@example.com',
]


@pytest.mark.parametrize("email", QUOTED_OK)
def test_quoted_address_passes_syntax(email):
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax(email) is True


def test_quoted_escaped_quote_is_allowed():
    from core.email_syntax import validate_email_syntax

    assert validate_email_syntax('"a\\"b"@example.com') is True


def test_quoted_broken_forms_are_still_rejected():
    from core.email_syntax import validate_email_syntax

    for junk in ('"unclosed@example.com', '"a"b"@example.com',
                 'a b@example.com', '"a"@', '"a"@@b.com'):
        assert validate_email_syntax(junk) is False, junk


def test_quoted_address_is_harvested_from_a_base_line():
    from core.email_syntax import harvest_pattern

    found = harvest_pattern(wide=True).search('"john smith"@example.com;Иван')
    assert found is not None
    assert found.group(0) == '"john smith"@example.com'


def test_quoted_form_is_not_harvested_from_web_text():
    from core.email_syntax import harvest_pattern

    text = 'нашлось "john smith"@example.com'
    assert harvest_pattern(wide=False).search(text) is None
    assert harvest_pattern(wide=True).search(text).group(0) == '"john smith"@example.com'


def test_quoted_web_mode_still_finds_ordinary_addresses():
    from core.email_syntax import harvest_pattern

    found = harvest_pattern(wide=False).search('пишите john.doe@example.com сегодня')
    assert found.group(0) == "john.doe@example.com"


def test_quoted_address_is_no_longer_refused_by_the_checker():
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    assert "RCPT с ней отправить нельзя" not in source


def test_quoted_address_survives_smtplib_quoting():
    from smtplib import quoteaddr

    assert quoteaddr('"john smith"@example.com') == '<"john smith"@example.com>'


def test_vrfy_gives_a_verdict_when_rcpt_did_not():
    v = validator()
    server = FakeServer(vrfy=(250, b"2.1.5 <a@b.com> User exists"))
    verdict = v._ask_vrfy(server, "a@b.com", "b.com")
    assert verdict["status"] == "valid"
    assert verdict["reason"].startswith("VRFY:")


def test_vrfy_can_bury_an_address_too():
    v = validator()
    server = FakeServer(vrfy=(550, b"5.1.1 No such user"))
    assert v._ask_vrfy(server, "a@b.com", "b.com")["status"] == "invalid"


def test_vrfy_252_is_not_a_verdict():
    v = validator()
    server = FakeServer(vrfy=(252, b"Cannot VRFY user, but will accept message"))
    assert v._ask_vrfy(server, "a@b.com", "b.com") is None


def test_vrfy_disabled_server_does_not_break_anything():
    v = validator()
    server = FakeServer(vrfy=None)
    assert v._ask_vrfy(server, "a@b.com", "b.com") is None


def test_vrfy_ambiguous_answer_stays_ambiguous():
    v = validator()
    server = FakeServer(vrfy=(550, b"5.7.1 Service unavailable, client blocked"))
    assert v._ask_vrfy(server, "a@b.com", "b.com") is None


def test_vrfy_is_only_asked_when_there_is_no_verdict():
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    block = source[source.index("result = self._parse_smtp_response(code, message"):]
    block = block[:block.index("# Контрольный вопрос")]
    assert 'if result["status"] == "unknown":' in block
    assert "self._ask_vrfy(server, email, domain)" in block


def test_spamhaus_refusal_code_is_recognised():
    v = validator()
    v._spamhaus_codes = ["127.255.255.254"]
    reason = v.spamhaus_refusal_reason()
    assert "127.255.255.254" in reason
    assert "публичные DNS" in reason


def test_spamhaus_silence_is_told_apart_from_refusal():
    v = validator()
    v._spamhaus_codes = []
    assert "не ответила вовсе" in v.spamhaus_refusal_reason()


def test_spamhaus_wrong_answer_is_named_with_the_code():
    v = validator()
    v._spamhaus_codes = ["127.0.0.10"]
    reason = v.spamhaus_refusal_reason()
    assert "127.0.0.10" in reason


def test_spamhaus_missing_resolver_is_a_loud_line():
    source = исходник_конвейера()
    block = source[source.index("elif not resolvers and self.network:"):]
    block = block[:block.index("if proxy_profiles")]
    assert "autodetect_spamhaus_resolver()" in block, "даже не попробовали"
    assert '"dead"' in block, "сказано тоном обычной информации"
    assert "ни один резолвер из" in block
    assert "spamhaus_resolvers" in block


def test_spamhaus_reason_is_used_by_the_pipeline():
    source = исходник_конвейера()
    assert "self.network.spamhaus_refusal_reason()" in source


def test_utf8_reaches_the_session_instead_of_being_refused_upfront():
    import inspect

    from core import network

    source = inspect.getsource(network.NetworkValidator.check_email)
    assert "has_non_ascii_local(email)" not in source, (
        "не-ASCII адрес снова разворачивают на подходе")

    ping = inspect.getsource(network.NetworkValidator._do_single_ping)
    assert "has_non_ascii_local(email)" in ping
    assert 'server.has_extn("smtputf8")' in ping


def test_utf8_live_answer_comes_from_the_server(monkeypatch):
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    seen = {}

    def fake_ping(email, mx_records, control_probe=False, **kwargs):
        seen["email"] = email
        return {"status": "unknown",
                "reason": "Не-ASCII имя ящика, а сервер не объявил SMTPUTF8 — проверить нечем"}

    monkeypatch.setattr(v, "get_mx_records", lambda d: ["mx.example"])
    monkeypatch.setattr(v, "is_catch_all_domain", lambda d, mx: False)
    monkeypatch.setattr(v, "stealth_smtp_ping", fake_ping)
    monkeypatch.setattr(v, "mx_hosts_alive", lambda mx: None)
    result = v.check_email("иван@почта.рф")

    assert seen.get("email"), "адрес до сессии не доехал"
    assert result["status"] in ("unknown", "risky")
    assert "SMTPUTF8" in result["reason"]


def test_spamhaus_autodetect_finds_a_resolver_that_serves_the_zone():
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    tried = []

    def fake_set(resolvers):
        tried.append(resolvers[0])
        return resolvers[0] == "9.9.9.9"

    v.set_spamhaus_resolver = fake_set
    assert v.autodetect_spamhaus_resolver(
        ["1.1.1.1", "8.8.8.8", "9.9.9.9"]) == "9.9.9.9"
    assert tried == ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def test_spamhaus_autodetect_gives_up_quietly():
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    v.set_spamhaus_resolver = lambda resolvers: False
    assert v.autodetect_spamhaus_resolver(["1.1.1.1", "8.8.8.8"]) is None


def test_spamhaus_autodetect_survives_a_broken_resolver_list():
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)

    def explode(resolvers):
        raise RuntimeError("сеть отвалилась")

    v.set_spamhaus_resolver = explode
    assert v.autodetect_spamhaus_resolver(["1.1.1.1"]) is None


def test_spamhaus_pipeline_tries_autodetect_before_giving_up():
    import inspect

    from core import pipeline

    source = исходник_конвейера()
    assert "autodetect_spamhaus_resolver()" in source
    assert "подключён сам через системный" in source


def test_spamhaus_system_resolvers_are_read_from_the_system():
    from core.dns_checks import system_resolvers

    found = system_resolvers()
    assert isinstance(found, list)
    assert all(isinstance(x, str) for x in found)
