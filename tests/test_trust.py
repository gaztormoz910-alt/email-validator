# -*- coding: utf-8 -*-
from исходники import исходник_файла
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.pipeline as pipeline_module
from tests.test_third_pass import FakeNetwork

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    return исходник_файла(rel, ROOT)


@pytest.mark.parametrize("address", [
    "user@gmial.com",
    "user@gmai.com",
    "user@hotmial.com",
    "user@yaho.com",
])
def test_loaded_address_domain_is_not_swapped(address):
    from core.cleaner import EmailCleaner

    cleaned = EmailCleaner().clean_email(address)
    assert cleaned == address, (
        "очистка подменила домен: %r -> %r" % (address, cleaned))


@pytest.mark.parametrize("raw,expected", [
    ("user@gmail.comtelefoon", "user@gmail.com"),
    ("user@corp.com-jobs", "user@corp.com"),
    ("user@mail.ruXXX", "user@mail.ru"),
    ("user@yandex.rublah", "user@yandex.ru"),
])
def test_loaded_address_glued_garbage_is_still_repaired(raw, expected):
    from core.cleaner import EmailCleaner

    assert EmailCleaner().clean_email(raw) == expected


def test_loaded_address_suggestion_is_separate_from_the_address():
    from core.cleaner import EmailCleaner

    cleaner = EmailCleaner()
    assert cleaner.suggest_domain_fix("user@gmial.com") == "user@gmail.com"
    assert cleaner.suggest_domain_fix("user@gmail.com") is None
    assert cleaner.suggest_domain_fix("user@corp-example.com") is None
    for junk in (None, "", "без собаки", "a@b@c", 42):
        assert cleaner.suggest_domain_fix(junk) is None


class _DomainAware(FakeNetwork):

    def __init__(self, live_domains):
        FakeNetwork.__init__(self, {"status": "unknown", "reason": "x"})
        self.live = set(live_domains)
        self.asked = []

    def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
        self.asked.append(email)
        domain = email.rsplit("@", 1)[1].lower()
        if domain in self.live:
            return {"status": "valid", "reason": "250 OK", "mx_record": "mx.test"}
        return {"status": "invalid", "reason": "No MX/A records (Dead Domain)",
                "mx_record": "N/A"}


def _run(content, network, monkeypatch, fix_typos=True):
    results = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: results.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = network
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)
    monkeypatch.setattr(pipeline_module, "GREYLIST_RETRY_DELAY", 0.0)
    pipe.run_pipeline([{"type": "text", "content": content}], threads=1,
                      fix_typos=fix_typos, check_spam=False, deep_ping=True,
                      enable_ai=False, enable_osint=False)
    return results, network


def test_typo_fallback_checks_the_loaded_domain_first(monkeypatch):
    net = _DomainAware({"gmail.com"})
    results, net = _run("user@gmial.com", net, monkeypatch)

    assert net.asked[0] == "user@gmial.com", (
        "первым спросили не загруженный адрес: %s" % net.asked)
    assert results, "адрес пропал"
    email, status, reason, data = (results[0][0], results[0][1],
                                   results[0][2], results[0][4])
    assert email == "user@gmial.com", "адрес подменён на подсказку: %s" % email
    assert status == "Invalid/Bounce", status
    assert "опечатку" in reason, reason
    assert data.get("suggested_email") == "user@gmail.com", (
        "подсказка не сохранена: %s" % data.get("suggested_email"))
    assert data.get("suggested_status") == "valid", data.get("suggested_status")


def test_typo_fallback_control_the_suggestion_is_actually_checked(monkeypatch):
    net = _DomainAware({"gmail.com"})
    _results, net = _run("user@gmial.com", net, monkeypatch)
    assert "user@gmail.com" in net.asked, (
        "похожий домен не спрашивали: %s" % net.asked)


def test_typo_fallback_never_touches_a_live_domain(monkeypatch):
    net = _DomainAware({"gmial.com", "gmail.com"})
    results, net = _run("user@gmial.com", net, monkeypatch)

    assert net.asked == ["user@gmial.com"], (
        "полезли к похожему домену, хотя загруженный жив: %s" % net.asked)
    assert results[0][0] == "user@gmial.com"


def test_typo_fallback_keeps_invalid_when_both_are_dead(monkeypatch):
    net = _DomainAware(set())
    results, net = _run("user@gmial.com", net, monkeypatch)

    assert results[0][0] == "user@gmial.com"
    assert results[0][1] == "Invalid/Bounce"


def test_original_email_reaches_every_surface():
    webapp = read("ui/webapp.py")
    assert '"OriginalEmail"' in webapp, "нет колонки в выгрузке окна"
    assert 'data.get("original_email", "")' in webapp
    assert '"original": data.get("original_email"' in webapp, "нет в строке таблицы"

    cli = read("cli.py")
    assert '"original_email"' in cli and "EXPORT_FIELDS" in cli


def test_original_email_is_absent_when_nothing_changed(monkeypatch):
    net = _DomainAware({"corp.test"})
    results, _ = _run("user@corp.test", net, monkeypatch)
    assert results[0][4].get("original_email", "") == ""


@pytest.mark.parametrize("code,message,expected", [
    (550, b"5.1.3 Bad destination mailbox address syntax", "risky"),
    (550, b"5.1.2 Bad destination system address", "risky"),
    (550, b"5.1.1 no such user", "invalid"),
    (550, b"5.1.10 RESOLVER.ADR.RecipientNotFound", "invalid"),
])
def test_enhanced_codes_prove_only_what_they_prove(code, message, expected):
    from core.smtp_codes import classify_smtp_response

    assert classify_smtp_response(code, message)["status"] == expected


@pytest.mark.parametrize("code,message", [
    (550, b"5.2.2 Sorry, the user is over quota"),
    (550, b"5.7.1 Sorry, the recipient's mailbox is full"),
    (552, b"5.2.2 Over quota"),
    (452, b"4.2.2 over quota"),
])
def test_full_mailbox_is_recognised_as_full(code, message):
    from core.smtp_codes import classify_smtp_response

    assert classify_smtp_response(code, message)["status"] == "full"


@pytest.mark.parametrize("code,message", [
    (452, b"4.3.1 Insufficient system storage"),
    (552, b"5.3.4 Message size exceeds fixed limit"),
])
def test_full_mailbox_does_not_swallow_foreign_cases(code, message):
    from core.smtp_codes import classify_smtp_response

    assert classify_smtp_response(code, message)["status"] == "unknown"


def test_probe_exit_matches_the_main_check():
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=1, proxies=["dirty:1", "clean:2", "ptr:3"])
    v.set_proxy_profiles({
        "dirty:1": {"exit_ip": "1.1.1.1", "in_dnsbl": True},
        "clean:2": {"exit_ip": "2.2.2.2", "in_dnsbl": False},
        "ptr:3": {"exit_ip": "3.3.3.3", "in_dnsbl": False, "ptr": "mail.x.test"},
    })
    assert v._probe_proxy_for("outlook.com") != "dirty:1", (
        "проба по домену, режущему по репутации, идёт грязным выходом")
    assert v._probe_proxy_for("corp-example.test") is not None


def test_probe_exit_is_used_by_both_probes():
    source = read("core/network.py")
    assert source.count("_probe_proxy_for(domain)") >= 2, (
        "одна из проб по-прежнему берёт выход без требований")


def test_revision_moves_valid_out_of_the_send_column(tmp_path):
    from ui.result_store import ResultStore

    store = ResultStore(path=str(tmp_path / "rows.sqlite"))
    try:
        store.append("a@catchall.test", "Valid", "250 OK", "mx", {})
        store.append("b@catchall.test", "Valid", "250 OK", "mx", {})
        store.append("c@honest.test", "Valid", "250 OK", "mx", {})
        assert store.counts()["valid"] == 3

        moved = store.revise_domain("catchall.test", "Unknown",
                                    "домен принимает любой адрес")
        assert moved == 2, moved
        counts = store.counts()
        assert counts["valid"] == 1, "строки остались в колонке «Годен»"
        assert counts["unknown"] == 2

        rows = store.page(groups=["unknown"])
        assert all("любой адрес" in r["reason"] for r in rows), rows
    finally:
        store.close()


def test_revision_can_annotate_without_changing_the_status(tmp_path):
    from ui.result_store import ResultStore

    store = ResultStore(path=str(tmp_path / "rows.sqlite"))
    try:
        store.append("a@corp.test", "Valid", "250 OK", "mx", {})
        moved = store.revise_domain("corp.test", None, "под подозрением")
        assert moved == 1
        assert store.counts()["valid"] == 1, "статус тронули, а не должны были"
        assert "под подозрением" in store.page(groups=["valid"])[0]["reason"]
    finally:
        store.close()


def test_revision_reaches_every_surface():
    assert "on_revise" in read("ui/webapp.py")
    assert "on_revise" in read("cli.py")
    assert "def _revise" in read("core/pipeline.py")
    assert "proven_catchall_domains" in read("core/network.py")


def test_second_opinion_said_when_there_was_none():
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=1)
    v.country_for_domain = lambda domain, mx_host="": ""
    v._do_single_ping = lambda *a, **k: {"status": "invalid",
                                         "reason": "550 нет ящика"}
    v._confirm_invalid_on_other_mx = lambda *a, **k: None

    result = v.stealth_smtp_ping("user@single.test", ["mx.single.test"])
    assert result["status"] == "invalid"
    assert "второго мнения не было" in result["reason"], result["reason"]


def test_second_opinion_silent_when_it_did_happen():
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=1)
    v.country_for_domain = lambda domain, mx_host="": ""
    v._do_single_ping = lambda *a, **k: {"status": "invalid",
                                         "reason": "550 нет ящика"}
    v._confirm_invalid_on_other_mx = lambda *a, **k: True

    result = v.stealth_smtp_ping("user@single.test", ["mx.single.test"])
    assert "второго мнения не было" not in result["reason"]
    assert result.get("second_opinion") == "agreed"


def test_blacklist_guard_covers_known_providers():
    from core.filters import BLACKLIST_SENTINELS

    assert len(BLACKLIST_SENTINELS) > 100, len(BLACKLIST_SENTINELS)
    for live in ("gmail.com", "seznam.cz", "bk.ru", "wp.pl", "t-online.de",
                 "rambler.ru", "zoho.com"):
        assert live in BLACKLIST_SENTINELS, "не защищён живой провайдер: %s" % live


def test_blacklist_guard_does_not_protect_disposables():
    from core.filters import BLACKLIST_SENTINELS

    for junk in ("mailinator.com", "10minutemail.com", "guerrillamail.com"):
        assert junk not in BLACKLIST_SENTINELS, junk


def test_blacklist_file_with_a_live_provider_is_refused(tmp_path):
    from core.filters import SpamFilter

    (tmp_path / "list.txt").write_text("mailinator.com\nseznam.cz\n",
                                       encoding="utf-8")
    spam = SpamFilter(data_dir=str(tmp_path))
    assert "seznam.cz" not in spam.blacklist_domains, (
        "живой провайдер попал в чёрный список")
    assert spam.rejected_files, "отбраковка не отмечена"
    assert spam.rejected_files[0][0] == "list.txt"


def test_nxdomain_closes_the_question_in_one_query():
    import dns.resolver

    from core.network import NetworkValidator

    class Resolver:
        def __init__(self):
            self.asked = []

        def resolve(self, domain, rdtype):
            self.asked.append(rdtype)
            raise dns.resolver.NXDOMAIN()

    v = NetworkValidator(timeout=1)
    v.resolver = Resolver()
    assert v.get_mx_records("nope.test") == []
    assert v.resolver.asked == ["MX"], v.resolver.asked


def test_nxdomain_control_no_answer_still_asks_further():
    import dns.resolver

    from core.network import NetworkValidator

    class Resolver:
        def __init__(self):
            self.asked = []

        def resolve(self, domain, rdtype):
            self.asked.append((rdtype, domain))
            if rdtype == "MX":
                raise dns.resolver.NoAnswer()
            raise dns.resolver.NXDOMAIN()

    v = NetworkValidator(timeout=1)
    v.resolver = Resolver()
    assert v.get_mx_records("corp.test") == []
    свои = [т for т, имя in v.resolver.asked if имя == "corp.test"]
    assert свои == ["MX", "A", "AAAA"], v.resolver.asked
    чужие = [имя for _т, имя in v.resolver.asked if имя != "corp.test"]
    assert чужие and all(и.endswith(".corp.test") for и in чужие), чужие
