# -*- coding: utf-8 -*-
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.pipeline as pipeline_module
from core.local_rules import IMPOSSIBLE, OK, UNLIKELY, check_local_part


def validator(proxies=None, profiles=None):
    from core.network import NetworkValidator

    made = NetworkValidator(timeout=2, proxies=proxies or [])
    if profiles:
        made.set_proxy_profiles(profiles)
    made.country_for_domain = lambda domain, mx_host="": ""
    return made


class FakeNetwork:

    def __init__(self, first, second=None):
        self.first = first
        self.second = second or {"status": "valid", "reason": "250 OK",
                                 "mx_record": "mx.test"}
        self.calls = []

    def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
        if prefer_exit_of:
            self.calls.append((email, ("prefer", prefer_exit_of)))
        else:
            self.calls.append((email, avoid_exit_of))
        return dict(self.first) if len(self.calls) == 1 else dict(self.second)

    def get_live_proxy_count(self):
        return 2

    def has_proxies_configured(self):
        return True

    def all_proxies_dead(self):
        return False

    def get_mx_records(self, domain):
        return ["mx.test"]


def run_one(first, second=None, monkeypatch=None):
    net = FakeNetwork(first, second)
    results = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: results.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = net
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None

    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)
    monkeypatch.setattr(pipeline_module, "GREYLIST_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=2, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)
    return net, results


def test_retry_avoids_the_exit_that_just_failed(monkeypatch):
    net, results = run_one({"status": "unknown", "reason": "Timeout",
                            "mx_record": "mx.test", "proxy": "socks5://a:1"},
                           monkeypatch=monkeypatch)
    assert len(net.calls) == 2, "повтора не было вовсе: %s" % (net.calls,)
    assert net.calls[0][1] is None, "первый заход не должен ничего избегать"
    assert net.calls[1][1] == "socks5://a:1", (
        "повтор не знает, какой выход только что не смог: %s" % (net.calls,))
    assert results and results[0][1] == "Valid", (
        "вердикт повтора не дошёл до выдачи: %s" % (results,))


def test_retry_after_greylisting_keeps_the_same_exit(monkeypatch):
    net, _ = run_one({"status": "greylisted", "reason": "451 greylisted",
                      "mx_record": "mx.test", "proxy": "socks5://b:2"},
                     monkeypatch=monkeypatch)
    assert len(net.calls) == 2
    assert net.calls[1][1] == ("prefer", "socks5://b:2"), net.calls


def test_retry_without_a_known_proxy_asks_as_before(monkeypatch):
    net, _ = run_one({"status": "unknown", "reason": "Timeout",
                      "mx_record": "mx.test"},
                     monkeypatch=monkeypatch)
    assert len(net.calls) == 2
    assert net.calls[1][1] is None


def test_ping_reports_which_proxy_answered():
    v = validator(proxies=["a:1"], profiles={"a:1": {"exit_ip": "1.1.1.1"}})
    v._do_single_ping = lambda *a, **k: {"status": "unknown", "reason": "Timeout"}
    result = v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"])
    assert result.get("proxy") == "a:1", result


def test_ping_without_proxies_reports_no_proxy():
    v = validator()
    v._do_single_ping = lambda *a, **k: {"status": "unknown", "reason": "Timeout"}
    result = v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"])
    assert "proxy" not in result


def test_single_exit_still_gets_checked():
    v = validator(proxies=["a:1"], profiles={"a:1": {"exit_ip": "1.1.1.1"}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    result = v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"],
                                 avoid_exit_of="a:1")
    assert seen == ["a:1"], "проверка не состоялась вовсе: %s" % (seen,)
    assert result["status"] == "valid"
    assert "Proxies Dead" not in result.get("reason", "")


def test_two_exits_do_honour_the_ban():
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"], avoid_exit_of="a:1")
    assert seen == ["b:2"], seen


def probe_recorder(v, answers):
    calls = []

    def fake_probe(addresses, mx_record, proxy=None, from_email=None):
        calls.append(list(addresses))
        return [dict(a) for a in answers][:len(addresses)]

    v._probe_recipients = fake_probe
    return calls


def test_abuse_answers_when_postmaster_probe_fails():
    v = validator()
    calls = probe_recorder(v, [{"status": "unknown", "reason": "Timeout"},
                               {"status": "invalid", "reason": "550 no such user"}])
    assert v.postmaster_is_honored("wall.test", "mx.wall.test") is False
    assert calls == [["postmaster@wall.test", "abuse@wall.test"]], calls


def test_abuse_can_also_clear_the_server():
    v = validator()
    probe_recorder(v, [{"status": "unknown", "reason": "Proxy Dead"},
                       {"status": "valid", "reason": "250 OK"}])
    assert v.postmaster_is_honored("ok.test", "mx.ok.test") is True


def test_postmaster_still_decides_first():
    v = validator()
    probe_recorder(v, [{"status": "invalid", "reason": "550"},
                       {"status": "valid", "reason": "250 OK"}])
    assert v.postmaster_is_honored("first.test", "mx.first.test") is False

    other = validator()
    probe_recorder(other, [{"status": "valid", "reason": "250 OK"},
                           {"status": "invalid", "reason": "550"}])
    assert other.postmaster_is_honored("second.test", "mx.second.test") is True


def test_both_mandatory_addresses_cost_one_session():
    v = validator()
    calls = probe_recorder(v, [{"status": "unknown"}, {"status": "unknown"}])
    assert v.postmaster_is_honored("quiet.test", "mx.quiet.test") is None
    assert len(calls) == 1, "домен опрошен дважды: %s" % (calls,)


def test_failed_probe_is_not_remembered():
    v = validator()
    probe_recorder(v, [{"status": "unknown"}, {"status": "unknown"}])
    assert v.postmaster_is_honored("later.test", "mx.later.test") is None
    probe_recorder(v, [{"status": "valid"}, {"status": "valid"}])
    assert v.postmaster_is_honored("later.test", "mx.later.test") is True


@pytest.mark.parametrize("email,why", [
    ("a" * 35 + "@gmail.com", "предел Gmail взят со страницы помощи, не с сервера"),
    ("a" * 40 + "@aol.com", "то же самое у AOL"),
    ("a" * 25 + "@icloud.com", "и у iCloud"),
    (".".join("johndoesmithjunior") + "@gmail.com",
     "точки Gmail не значат ничего: это имя из восемнадцати знаков"),
])
def test_length_no_longer_buries_without_a_server(email, why):
    assert check_local_part(email)[0] != IMPOSSIBLE, why


def test_empty_name_is_the_only_thing_impossible():
    assert check_local_part("@gmail.com")[0] == IMPOSSIBLE
    assert check_local_part("x" * 31 + "@gmail.com")[0] == UNLIKELY
    assert check_local_part("john.smith@gmail.com")[0] == OK


def test_long_gmail_name_reaches_the_server_and_survives_silence():
    v = validator()
    v.get_mx_records = lambda domain: ["mx.gmail.test"]
    v.is_catch_all_domain = lambda domain, mx: False
    v.check_dns_health = lambda domain: {"score": 0, "has_spf": False,
                                         "has_dmarc": False, "has_dkim": False}
    asked = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        asked.append(email)
        return {"status": "unknown", "reason": "Timeout"}

    v._do_single_ping = fake_ping
    result = v.check_email("a" * 35 + "@gmail.com")
    assert asked, "адрес по-прежнему хоронится без единого запроса"
    assert result["status"] != "invalid", result
    assert "длиннее" in result["reason"], (
        "подозрение потерялось — оно должно понижать доверие: %s" % result)


def test_the_server_still_decides_the_long_name():
    v = validator()
    v.get_mx_records = lambda domain: ["mx.gmail.test"]
    v.is_catch_all_domain = lambda domain, mx: False
    v._do_single_ping = lambda *a, **k: {"status": "valid", "reason": "250 OK"}
    result = v.check_email("a" * 35 + "@gmail.com")
    assert result["status"] == "valid", result


def test_facts_without_a_server_are_still_invalid():
    v = validator()
    v.get_mx_records = lambda domain: []
    assert v.check_email("user@no-mx.test")["status"] == "invalid"
    assert v.check_email("a b@gmail.com")["status"] == "invalid"


REPUTATION = ("5.7.1 550 Отказ по политике/репутации IP "
              "(ящик может существовать)")


def test_reputation_refusal_is_retried(monkeypatch):
    net, results = run_one({"status": "unknown", "reason": REPUTATION,
                            "mx_record": "mx.test", "proxy": "socks5://dirty:1"},
                           monkeypatch=monkeypatch)
    assert len(net.calls) == 2, "отказ по репутации остался без повтора"
    assert net.calls[1][1] == "socks5://dirty:1"
    assert results[0][1] == "Valid"


def test_reputation_refusal_upgraded_to_risky_is_retried_too(monkeypatch):
    net, _ = run_one({"status": "risky",
                      "reason": REPUTATION + " [DNS: SPF=✓, DMARC=✓, DKIM=✗]",
                      "mx_record": "mx.test", "proxy": "socks5://dirty:1"},
                     monkeypatch=monkeypatch)
    assert len(net.calls) == 2, "risky по нашей же вине остался без повтора"


def test_a_real_verdict_is_never_retried(monkeypatch):
    net, results = run_one({"status": "invalid", "reason": "550 5.1.1 нет ящика",
                            "mx_record": "mx.test", "proxy": "socks5://a:1"},
                           monkeypatch=monkeypatch)
    assert len(net.calls) == 1, "вердикт сервера ушёл на повтор: %s" % (net.calls,)
    assert results[0][1] == "Invalid/Bounce"


def test_retry_prefers_a_clean_exit():
    v = validator(proxies=["dirty:1", "dirty:2", "clean:3"],
                  profiles={"dirty:1": {"exit_ip": "1.1.1.1", "in_dnsbl": True},
                            "dirty:2": {"exit_ip": "2.2.2.2", "in_dnsbl": True},
                            "clean:3": {"exit_ip": "3.3.3.3", "in_dnsbl": False}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"],
                        avoid_exit_of="dirty:1")
    assert seen == ["clean:3"], seen


def test_clean_preference_is_soft_not_a_refusal():
    v = validator(proxies=["dirty:1", "dirty:2"],
                  profiles={"dirty:1": {"exit_ip": "1.1.1.1", "in_dnsbl": True},
                            "dirty:2": {"exit_ip": "2.2.2.2", "in_dnsbl": True}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    result = v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"],
                                 avoid_exit_of="dirty:1")
    assert seen == ["dirty:2"], seen
    assert result["status"] == "valid"


def test_cache_forgets_verdicts_the_rule_no_longer_makes(tmp_path):
    import sqlite3

    from core.cache import ResultCache

    path = str(tmp_path / "cache.sqlite")
    cache = ResultCache(path=path)
    assert cache.enabled
    cache.put("long@gmail.com", "Invalid/Bounce",
              "Имя не может существовать — Gmail: имя длиннее 30 символов.", "N/A")
    cache.put("dead@nowhere.test", "Invalid/Bounce",
              "No MX/A records (Dead Domain)", "N/A")
    cache.put("live@gmail.com", "Valid", "250 OK", "mx.gmail.test")
    cache.close()

    reopened = ResultCache(path=path)
    try:
        assert reopened.get("long@gmail.com") is None, (
            "отменённый приговор всё ещё выдаётся из кэша")
        assert reopened.get("dead@nowhere.test") is not None
        assert reopened.get("live@gmail.com") is not None
    finally:
        reopened.close()

    with sqlite3.connect(path) as con:
        left = con.execute("SELECT COUNT(*) FROM results").fetchone()[0]
    assert left == 2, left


def test_leftover_keeps_the_real_reason(monkeypatch):
    results = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: results.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })

    class StopsAfterFirst(FakeNetwork):
        def check_email(self, email, avoid_exit_of=None):
            answer = FakeNetwork.check_email(self, email, avoid_exit_of)
            pipe.is_running = False
            return answer

    pipe.network = StopsAfterFirst({"status": "unknown", "reason": REPUTATION,
                                    "mx_record": "mx.test",
                                    "proxy": "socks5://dirty:1"})
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)

    assert results, "адрес пропал вовсе"
    email, status, reason = results[0][0], results[0][1], results[0][2]
    assert email == "user@example-corp.test"
    assert status == "Unknown"
    assert "репутации" in reason, reason
    assert "перепроверка не выполнена" in reason.lower(), reason
    assert "greylisted" not in reason.lower(), reason


def test_sender_is_stable_for_a_domain():
    from core.mail_constants import MAIL_FROM_POOL, mail_from_for

    for domain in ("gmail.com", "corp.example", "почта.рф", "web.de"):
        first = mail_from_for(domain)
        assert first in MAIL_FROM_POOL
        assert all(mail_from_for(domain) == first for _ in range(5)), domain


def test_sender_still_rotates_across_domains():
    from core.mail_constants import MAIL_FROM_POOL, mail_from_for

    domains = ["d%02d.example" % n for n in range(60)]
    used = {mail_from_for(d) for d in domains}
    assert len(used) == len(MAIL_FROM_POOL), used


def test_sender_survives_junk_input():
    from core.mail_constants import MAIL_FROM_POOL, mail_from_for

    for junk in (None, "", 42, [], {}, "@", "\x00"):
        assert mail_from_for(junk) in MAIL_FROM_POOL


def test_ping_honours_the_requested_exit():
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"], prefer_exit_of="a:1")
    assert seen == ["a:1"], seen


def test_requested_exit_that_died_falls_back():
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    v._proxy_banned.add("a:1")
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"], prefer_exit_of="a:1")
    assert seen == ["b:2"], seen
