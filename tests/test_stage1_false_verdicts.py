# -*- coding: utf-8 -*-
"""Ложные вердикты E6–E13 из аудита 03.11.2026 (.unlazy/rivals/ОТЧЁТ.md).

Каждый дефект — тест, который падал на коде до правки (b6b428e), и рядом
контроль: случай, где прежний вердикт был верным и обязан таким остаться.
Без контроля правка «не хоронить» легко превращается в «не хоронить никого»,
а это потеря того, ради чего валидатор существует.

Все адреса и домены выдуманы (зона .test зарезервирована RFC 2606).
"""
import argparse

import dns.message
import dns.rcode
import dns.rdatatype
import pytest

from core.smtp_codes import classify_smtp_response


def _status(code, message):
    return classify_smtp_response(code, message)["status"]


# ═══════════════ E6: отказ ОТПРАВИТЕЛЮ со словами «user unknown» ═══════════

def test_e6_sender_rejected_user_unknown_is_not_invalid():
    # Postfix со сверкой отправителя: «user unknown» здесь про НАШ MAIL FROM.
    assert _status(550, "5.1.0 <mailer@ours.example>: Sender address rejected: "
                        "User unknown in local recipient table") == "unknown"


def test_e6_bad_sender_code_5_1_7_is_not_invalid():
    # RFC 3463: X.1.7 — плохой адрес ОТПРАВИТЕЛЯ, а «invalid address» рядом
    # раньше читалось как приговор получателю.
    assert _status(550, "5.1.7 Invalid address") == "unknown"


def test_e6_control_recipient_user_unknown_stays_invalid():
    assert _status(550, "5.1.1 <anna@corp.test>: Recipient address rejected: "
                        "User unknown in local recipient table") == "invalid"


def test_e6_control_recipient_named_beside_sender_hint_stays_invalid():
    # Подсказка про отправителя в отказе ПОЛУЧАТЕЛЮ приговор не снимает.
    assert _status(550, "5.1.1 Recipient address rejected: user unknown; "
                        "invalid sender hint ignored") == "invalid"


# ═══════ E7: «mailbox unavailable», «unrouteable» при коде не про ящик ═══════

@pytest.mark.parametrize("code, message", [
    (550, "5.3.0 Requested action not taken: mailbox unavailable"),
    (550, "5.4.4 Unrouteable address"),
    (554, "5.6.0 Recipient rejected: message undeliverable"),
])
def test_e7_ambiguous_phrase_with_system_route_content_code_is_not_invalid(code, message):
    assert _status(code, message) == "risky"


@pytest.mark.parametrize("code, message", [
    # Outlook.com на мёртвый ящик; Exim без расширенного кода.
    (550, "5.5.0 Requested action not taken: mailbox unavailable"),
    (550, "Unrouteable address"),
    (550, "5.1.1 The email account that you tried to reach does not exist"),
])
def test_e7_control_known_dead_answers_stay_invalid(code, message):
    assert _status(code, message) == "invalid"


# ═══════════════ E8: «5.1.1 User unknown … over quota» ═══════════════════════

def test_e8_user_unknown_over_quota_check_is_invalid_not_full():
    assert _status(550, "5.1.1 User unknown (over quota check)") == "invalid"


def test_e8_no_enhanced_code_proof_beats_quota_word():
    assert _status(550, "No such user here (quota exceeded check)") == "invalid"


@pytest.mark.parametrize("code, message", [
    (552, "5.2.2 The email account that you tried to reach is over quota"),
    (452, "4.2.2 Mailbox full"),
    (550, "Mailbox is full"),
])
def test_e8_control_full_mailbox_stays_full(code, message):
    assert _status(code, message) == "full"


# ═══════════ E9: память «не catch-all» вместо свежего контроля ═══════════════

class _Memory:
    def __init__(self, remembered):
        self.remembered = remembered

    def catchall_get(self, domain):
        return self.remembered

    def catchall_put(self, domain, value):
        pass


def _validator(remembered=None, control_answer=None):
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=1)
    v.memory = _Memory(remembered)
    answers = []

    def probe(emails, mx_record, proxy=None):
        answers.append(list(emails))
        return [dict(control_answer or {"status": "unknown",
                                        "reason": "421 Service Busy"})
                for _ in emails]

    v._probe_recipients = probe
    v.asked_probes = answers
    return v


def test_e9_remembered_not_catchall_does_not_confirm_valid():
    v = _validator(remembered=False)
    assert v.is_catch_all_domain("corp.test", "mx.corp.test") is False
    result = v._confirm_acceptance(
        "corp.test", {"status": "valid", "reason": "250 OK",
                      "control_rcpt": "inconclusive"}, ["mx.corp.test"])
    assert result["status"] == "unconfirmed", result
    assert v.asked_probes, "свежий контроль отдельной сессией не спросили"


def test_e9_control_fresh_rejection_of_fake_keeps_valid():
    v = _validator(remembered=False)
    v.is_catch_all_domain("corp.test", "mx.corp.test")
    result = v._confirm_acceptance(
        "corp.test", {"status": "valid", "reason": "250 OK",
                      "control_rcpt": "rejected"}, ["mx.corp.test"])
    assert result["status"] == "valid", result


def test_e9_control_fresh_control_session_rejects_fake_keeps_valid():
    v = _validator(remembered=False, control_answer={
        "status": "invalid", "reason": "550 5.1.1 User unknown"})
    v.is_catch_all_domain("corp.test", "mx.corp.test")
    result = v._confirm_acceptance(
        "corp.test", {"status": "valid", "reason": "250 OK",
                      "control_rcpt": "inconclusive"}, ["mx.corp.test"])
    assert result["status"] == "valid", result


def test_e9_remembered_not_catchall_does_not_disprove_catchall_for_revision():
    # Пересмотр вердиктов читает catchall_cache как «опровергнуто в ЭТОМ
    # прогоне»; месячная память этого не доказывает.
    v = _validator(remembered=False)
    v.is_catch_all_domain("corp.test", "mx.corp.test")
    assert v.catchall_cache.get("corp.test") is not False


def test_e9_control_remembered_catchall_still_downgrades():
    v = _validator(remembered=True)
    assert v.is_catch_all_domain("corp.test", "mx.corp.test") is True
    assert v.catchall_cache.get("corp.test") is True


# ═══════════ E10: пересмотр ролевых строк и строк без файла ══════════════════

def _store(tmp_path, on_disk=True):
    from ui.result_store import ResultStore

    # Каталог вместо файла базы — SQLite открыть не может, строки живут в ОЗУ.
    return ResultStore(path=None if on_disk else str(tmp_path))


def _fill(store):
    store.append("info@tarpit.test", "Role-based", "250 OK", "mx.tarpit.test", {})
    store.append("anna@tarpit.test", "Valid", "250 OK", "mx.tarpit.test", {})
    store.append("boris@other.test", "Valid", "250 OK", "mx.other.test", {})


def _statuses(store):
    return {row["email"]: row["status"]
            for row in store.page(groups=["valid", "invalid", "spam", "unknown"],
                                  size=100)}


def test_e10_role_based_row_is_revised_with_valid():
    store = _store(None)
    try:
        _fill(store)
        assert store.revise_domain("tarpit.test", "Unknown", "тарпитинг") == 2
        statuses = _statuses(store)
        assert statuses["info@tarpit.test"] == "Unknown"
        assert statuses["anna@tarpit.test"] == "Unknown"
        assert statuses["boris@other.test"] == "Valid"
        assert store.counts()["spam"] == 0
    finally:
        store.close()


def test_e10_rows_living_only_in_memory_are_revised(tmp_path):
    store = _store(tmp_path, on_disk=False)
    try:
        assert store._conn is None, "контроль среды: база не должна открыться"
        _fill(store)
        assert store.revise_domain("tarpit.test", "Unknown", "тарпитинг") == 2
        statuses = _statuses(store)
        assert statuses["anna@tarpit.test"] == "Unknown"
        assert statuses["boris@other.test"] == "Valid"
        assert store.counts()["valid"] == 1
    finally:
        store.close()


def test_e10_control_note_only_keeps_status():
    store = _store(None)
    try:
        _fill(store)
        store.revise_domain("tarpit.test", None, "все ответили 250")
        statuses = _statuses(store)
        assert statuses["anna@tarpit.test"] == "Valid"
        assert statuses["info@tarpit.test"] == "Role-based"
    finally:
        store.close()


# ═══════════ E11: bounces без --hard-only — только жёсткие отскоки ══════════

class _FakeCache:
    written = []

    def import_bounces(self, emails, detail=""):
        _FakeCache.written = list(emails)
        return len(emails)

    def bounced_domains(self, min_count=3):
        return []

    def close(self):
        pass


def _bounces(tmp_path, monkeypatch, lines, hard_only=None):
    import cli
    import core.cache

    report = tmp_path / "bounces.txt"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    monkeypatch.setattr(core.cache, "ResultCache", _FakeCache)
    _FakeCache.written = []
    args = argparse.Namespace(report=str(report), hard_only=hard_only,
                              dry_run=False, note="", domain_min=3)
    cli.cmd_bounces(args)
    return set(_FakeCache.written)


_REPORT = [
    "anna@corp.test 550 5.1.1 <anna@corp.test>: Recipient address rejected: User unknown",
    "bob@corp.test 452 4.2.2 Mailbox full",
    "carl@corp.test 550 5.7.1 Service unavailable; client host blocked using Spamhaus",
    "dina@corp.test",
]


def test_e11_without_hard_only_soft_and_codeless_lines_are_not_written(tmp_path, monkeypatch):
    assert _bounces(tmp_path, monkeypatch, _REPORT) == {"anna@corp.test"}


def test_e11_control_hard_only_word_is_owner_decision(tmp_path, monkeypatch):
    # Владелец сам назвал метку жёсткого отскока — берётся ровно по ней.
    lines = ["anna@corp.test hard", "dina@corp.test hard", "bob@corp.test soft"]
    assert _bounces(tmp_path, monkeypatch, lines, hard_only="hard") == {
        "anna@corp.test", "dina@corp.test"}


# ═══════════ E12: wildcard-домен без MX — не «Dead Domain» ═══════════════════

class _WildResolver:
    def __init__(self, wildcard):
        self.wildcard = wildcard

    def resolve(self, name, rdtype):
        import dns.resolver

        if rdtype == "MX":
            raise dns.resolver.NoAnswer()
        if self.wildcard:
            return ["192.0.2.10"]     # любое имя резолвится
        raise dns.resolver.NXDOMAIN()


def test_e12_wildcard_without_mx_is_not_dead():
    v = _validator()
    v.resolver = _WildResolver(wildcard=True)
    assert v.get_mx_records("corp.test") is None
    assert "wildcard" in (v.mx_doubt_reason("corp.test") or "")


def test_e12_control_no_mx_no_a_no_aaaa_is_still_dead():
    v = _validator()
    v.resolver = _WildResolver(wildcard=False)
    assert v.get_mx_records("corp.test") == []


# ═══════════ E13: «домена нет» без DoH — не приговор ════════════════════════

def _proxied(doh_rcode=None, tcp_rcode=dns.rcode.NXDOMAIN):
    """Резолвер через прокси: DoH отвечает doh_rcode (None — не ответил),
    обычный DNS через прокси — tcp_rcode. Сеть не трогается."""
    from core.dns_resolver import ProxiedResolver

    def answer(query, rcode):
        if rcode is None:
            return None
        response = dns.message.make_response(query)
        response.set_rcode(rcode)
        return response

    class Stub(ProxiedResolver):
        def _ask_doh(self, url, query, proxy):
            return answer(query, doh_rcode)

        def _ask_tcp(self, nameserver, query, proxy):
            return answer(query, tcp_rcode)

    # Провайдер без exclude: второй дорожки нет, отвечает прежняя.
    return Stub(["192.0.2.53"], timeout=1,
                proxy_provider=lambda: "socks5://192.0.2.1:1080")


def test_e13_unverified_nxdomain_is_not_dead_domain():
    v = _validator()
    v.resolver = _proxied(doh_rcode=None, tcp_rcode=dns.rcode.NXDOMAIN)
    assert v.get_mx_records("gone.test") is None
    assert "DoH" in (v.mx_doubt_reason("gone.test") or "")


# conftest подменяет mx_hosts_alive на «None» для всех тестов; без метки
# тест прошёл бы и на старом коде.
@pytest.mark.настоящий_mx_hosts_alive
def test_e13_unverified_mx_host_nxdomain_is_not_a_verdict():
    v = _validator()
    v.resolver = _proxied(doh_rcode=None, tcp_rcode=dns.rcode.NXDOMAIN)
    assert v.mx_hosts_alive(["mx.gone.test"]) is None


def test_e13_unverified_no_records_at_all_is_not_dead_domain():
    v = _validator()
    v.resolver = _proxied(doh_rcode=None, tcp_rcode=dns.rcode.NOERROR)
    assert v.get_mx_records("empty.test") is None


# conftest подменяет mx_hosts_alive на «None» для всех тестов; без метки
# тест прошёл бы и на старом коде.
@pytest.mark.настоящий_mx_hosts_alive
def test_e13_control_doh_confirmed_nxdomain_is_dead():
    v = _validator()
    v.resolver = _proxied(doh_rcode=dns.rcode.NXDOMAIN)
    assert v.get_mx_records("gone.test") == []
    assert v.mx_hosts_alive(["mx.gone.test"]) is False
