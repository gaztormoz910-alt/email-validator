# -*- coding: utf-8 -*-
import os
import sys
import threading
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.message
import dns.rcode
import dns.resolver
import pytest

from core.confirmation import LIAR_EXIT_REASON
from core.dns_checks import MX_DOUBT_UNVERIFIED, MX_DOUBT_WILDCARD
from core.dns_resolver import (DNSUnavailable, ProxiedResolver,
                               UnverifiedNXDOMAIN, UnverifiedNoAnswer)
from core.network import NetworkValidator
from core.smtp_codes import classify_smtp_response
from core.verdict_revision import VerdictRevisionMixin

DOM = "corpmail.test"
MX = "mx1.corpmail.test"
P1 = "socks5://198.51.100.1:1080"
P3 = "socks5://198.51.100.3:1080"
P5 = "socks5://198.51.100.5:1080"
LIAR, HONEST, HONEST2 = "203.0.113.66", "203.0.113.77", "203.0.113.88"
НЕТ_ЯЩИКА = classify_smtp_response(550, b"5.1.1 User unknown")
ПРИНЯЛ = {"status": "valid", "reason": "250 OK"}


def сеть(proxies=(P1, P3, P5)):
    профили = {P1: {"exit_ip": LIAR}, P3: {"exit_ip": HONEST}, P5: {"exit_ip": HONEST2}}
    n = NetworkValidator(timeout=2, proxies=list(proxies))
    n.set_proxy_profiles({p: профили[p] for p in proxies})
    n._choose_from = lambda pool, want_country="": sorted(pool)[0]
    n.country_for_domain = lambda domain, mx="": ""
    n._remember_catchall = lambda *a, **k: None
    n.memory = None
    return n


def выдуманный_по_выходу(n, лжецы):
    спрошено = []

    def probe(addresses, mx_record, proxy=None, from_email=None):
        спрошено.append(proxy)
        ответ = ПРИНЯЛ if n.exit_ip_of(proxy) in лжецы else НЕТ_ЯЩИКА
        return [dict(ответ) for _ in addresses]

    n._probe_recipients = probe
    return спрошено


class _Сервер:
    def rcpt(self, _addr):
        return 250, b"2.1.5 OK"

    def verify(self, _addr):
        return 250, b"OK"


def test_fake_accepted_by_one_exit_catches_the_exit_not_the_domain():
    n = сеть()
    выдуманный_по_выходу(n, {LIAR})
    res = {"status": "valid", "reason": "250 OK", "proxy": P1}
    n._control_in_session(_Сервер(), DOM, res, proxy=P1, mx=MX)
    assert res["status"] == "unknown" and res["reason"] == LIAR_EXIT_REASON
    assert (LIAR, DOM) in n.tarpit_pairs()
    assert n.catchall_cache.get(DOM) is not True
    assert n._fake_rejected_via(DOM, P3) is True
    assert LIAR in n.caught_exits_on(DOM)


def test_fake_accepted_by_two_exits_is_catchall():
    n = сеть()
    выдуманный_по_выходу(n, {LIAR, HONEST})
    res = {"status": "valid", "reason": "250 OK", "proxy": P1}
    n._control_in_session(_Сервер(), DOM, res, proxy=P1, mx=MX)
    assert res["status"] == "catchall"
    assert n.catchall_cache.get(DOM) is True
    assert (LIAR, DOM) not in n.tarpit_pairs()


@pytest.mark.parametrize("как", ["один выход", "без MX", "VRFY"])
def test_without_a_second_opinion_the_old_verdict_stands(как):
    n = сеть((P1,)) if как == "один выход" else сеть()
    спрошено = выдуманный_по_выходу(n, {LIAR})
    res = {"status": "valid", "reason": "250 OK", "proxy": P1}
    n._control_in_session(_Сервер(), DOM, res, via_vrfy=(как == "VRFY"), proxy=P1,
                          mx=None if как == "без MX" else MX)
    assert res["status"] == "catchall"
    if как != "один выход":
        assert спрошено == []


def test_attempt_loop_reasks_through_another_exit_after_the_catch():
    n = сеть()
    выдуманный_по_выходу(n, {LIAR})
    спрошено = []

    def ping(email, mx_record, proxy=None, control_probe=False, **_k):
        спрошено.append(proxy)
        res = dict(ПРИНЯЛ, proxy=proxy)
        if control_probe:
            сервер = _Сервер() if n.exit_ip_of(proxy) == LIAR else types.SimpleNamespace(
                rcpt=lambda _a: (550, b"5.1.1 User unknown"))
            n._control_in_session(сервер, DOM, res, proxy=proxy, mx=mx_record)
        return res

    n._do_single_ping = ping
    итог = n.stealth_smtp_ping("anna@" + DOM, [MX], control_probe=True)
    assert спрошено == [P1, P3]
    assert итог["status"] == "valid" and итог["proxy"] == P3
    assert итог.get("control_rcpt") == "rejected"


def test_triple_probe_liar_exit_does_not_make_the_domain_catchall():
    n = сеть()
    выдуманный_по_выходу(n, {LIAR})
    assert n.is_catch_all_domain(DOM, MX) is False
    assert (LIAR, DOM) in n.tarpit_pairs()
    assert n.catchall_cache[DOM] is False


def test_triple_probe_catchall_confirmed_by_second_exit():
    n = сеть()
    выдуманный_по_выходу(n, {LIAR, HONEST})
    assert n.is_catch_all_domain(DOM, MX) is True
    assert (LIAR, DOM) not in n.tarpit_pairs()


def пинг_по_выходу(n, лжецы, спрошено):
    def ping(email, mx_record, proxy=None, **_k):
        спрошено.append(proxy)
        return dict(ПРИНЯЛ if n.exit_ip_of(proxy) in лжецы else НЕТ_ЯЩИКА)
    n._do_single_ping = ping


def сверить(n, first_proxy=P3, почему=None):
    import time
    return n._confirm_invalid_on_other_mx(
        "anna@" + DOM, MX, [MX], False, False, "", time.monotonic() + 60,
        first_proxy=first_proxy, почему=почему)


def test_liar_contradicting_a_refusal_is_discarded():
    n = сеть()
    выдуманный_по_выходу(n, {LIAR})
    спрошено = []
    пинг_по_выходу(n, {LIAR}, спрошено)
    assert сверить(n) is True
    assert спрошено == [P1, P5]
    assert (LIAR, DOM) in n.tarpit_pairs()


def test_honest_contradiction_still_saves_the_address():
    n = сеть()
    выдуманный_по_выходу(n, set())
    спрошено = []
    пинг_по_выходу(n, {LIAR}, спрошено)
    assert сверить(n) is False
    assert (LIAR, DOM) not in n.tarpit_pairs()


def test_caught_exit_is_not_asked_to_confirm_at_all():
    n = сеть()
    n.mark_exit_caught(LIAR, DOM)
    спрошено = []
    пинг_по_выходу(n, {LIAR}, спрошено)
    assert сверить(n) is True
    assert спрошено == [P5]


def test_liar_and_no_third_exit_means_no_confirmation():
    n = сеть((P1, P3))
    выдуманный_по_выходу(n, {LIAR})
    спрошено = []
    пинг_по_выходу(n, {LIAR}, спрошено)
    почему = {}
    assert сверить(n, почему=почему) is None
    assert "третьего" in почему["текст"]


class _Pipeline(VerdictRevisionMixin):
    def __init__(self, net):
        self.network = net
        self.logs = []
        self.callbacks = {"on_log": lambda text, tag: self.logs.append(text)}


class _Ctx:
    def __init__(self):
        self.lock = threading.Lock()
        self.domain_stats = {DOM: {"total": 3, "valid": 2}}


def test_first_exit_lying_gets_a_fresh_check_once():
    n = сеть()
    выдуманный_по_выходу(n, {LIAR})
    позвали = []
    n.check_email = lambda email, **_k: позвали.append(email) or dict(НЕТ_ЯЩИКА, proxy=P3)
    p, ctx = _Pipeline(n), _Ctx()
    res = {"status": "valid", "reason": "250 OK", "proxy": P1, "mx_records": [MX]}
    свежий = p._recheck_if_first_exit_lies("anna@" + DOM, res, ctx, DOM)
    assert свежий["status"] == "invalid" and свежий["retried_without_liar"] is True
    assert позвали == ["anna@" + DOM]
    assert (LIAR, DOM) in n.tarpit_pairs()
    assert ctx.domain_stats[DOM] == {"total": 2, "valid": 1}
    ещё = dict(свежий, status="valid", proxy=P1, mx_records=[MX])
    assert p._recheck_if_first_exit_lies("anna@" + DOM, ещё, ctx, DOM) is None
    assert позвали == ["anna@" + DOM]


def test_first_exit_honest_keeps_the_honest_dispute():
    n = сеть()
    выдуманный_по_выходу(n, set())
    n.check_email = lambda email, **_k: pytest.fail("свежая проверка без лжеца")
    p = _Pipeline(n)
    res = {"status": "valid", "reason": "250 OK", "proxy": P3, "mx_records": [MX]}
    assert p._recheck_if_first_exit_lies("anna@" + DOM, res) is None


def test_fresh_check_stopped_is_not_used():
    n = сеть()
    выдуманный_по_выходу(n, {LIAR})
    n.check_email = lambda email, **_k: {"status": "unknown", "aborted": True}
    p = _Pipeline(n)
    res = {"status": "valid", "reason": "250 OK", "proxy": P1, "mx_records": [MX]}
    assert p._recheck_if_first_exit_lies("anna@" + DOM, res) is None


def test_settle_uses_the_fresh_answer_and_counts_the_address_once():
    from core.settle import SettleMixin

    class Конвейер(SettleMixin, VerdictRevisionMixin):
        confirm_valid = True

        def __init__(self, net):
            self.network = net
            self.выдано = []
            self.callbacks = {"on_log": lambda text, tag: None}

        def _second_opinion_on_valid(self, email, res):
            return None if res.get("retried_without_liar") else False

        def _enrich_and_score(self, *a, **k):
            pass

        def _emit(self, email, status, reason, mx, data):
            self.выдано.append(status)

    n = сеть()
    выдуманный_по_выходу(n, {LIAR})
    n.check_email = lambda email, **_k: dict(НЕТ_ЯЩИКА, proxy=P3, mx_records=[MX])
    p = Конвейер(n)
    ctx = types.SimpleNamespace(lock=threading.Lock(), domain_stats={},
                                state=types.SimpleNamespace(mark_done=lambda k: None))
    res = {"status": "valid", "reason": "250 OK", "proxy": P1, "mx_records": [MX]}
    p._settle("anna@" + DOM, {}, False, res, False, ctx)
    assert p.выдано == ["Invalid/Bounce"]
    assert ctx.domain_stats[DOM] == {"total": 1, "valid": 0}


def резолвер(прокси, отвечает):
    def provider(exclude=()):
        for p in прокси:
            if p not in exclude:
                return p
        return ""

    r = ProxiedResolver(["192.0.2.53"], 1, proxy_provider=provider)
    спрошено = []

    def ask_doh(url, query, proxy):
        спрошено.append(proxy)
        if proxy not in отвечает:
            return None
        ответ = dns.message.make_response(query)
        ответ.set_rcode(dns.rcode.NXDOMAIN)
        return ответ

    r._ask_doh = ask_doh
    return r, спрошено


def test_verified_nxdomain_found_through_another_proxy_and_remembered():
    r, спрошено = резолвер([P1, P3, P5], {P5})
    with pytest.raises(dns.resolver.NXDOMAIN) as поймано:
        r.resolve_verified("dead.test", "MX")
    assert type(поймано.value) is dns.resolver.NXDOMAIN
    assert P5 in спрошено and спрошено.index(P5) > 0
    del спрошено[:]
    with pytest.raises(dns.resolver.NXDOMAIN):
        r.resolve_verified("dead2.test", "MX")
    assert спрошено[0] == P5


def test_no_doh_answer_anywhere_is_unavailable_not_dead():
    r, _ = резолвер([P1, P3], set())
    with pytest.raises(DNSUnavailable):
        r.resolve_verified("dead.test", "MX")


def test_resolve_verified_never_goes_direct():
    r = ProxiedResolver(["192.0.2.53"], 1, proxy_provider=None)
    with pytest.raises(DNSUnavailable):
        r.resolve_verified("dead.test", "MX")


class _Резолвер:

    def __init__(self, заверено):
        self.заверено = заверено

    def resolve(self, qname, rdtype="A"):
        raise UnverifiedNXDOMAIN() if rdtype == "MX" else UnverifiedNoAnswer()

    def resolve_verified(self, qname, rdtype="A"):
        ответ = self.заверено.get(rdtype)
        if isinstance(ответ, BaseException) or (isinstance(ответ, type)
                                                and issubclass(ответ, BaseException)):
            raise ответ
        return ответ


def mx_сеть(заверено, wildcard=False):
    n = NetworkValidator(timeout=2)
    n.resolver = _Резолвер(заверено)
    n._is_wildcard_domain = lambda domain: wildcard
    return n


def test_unverified_dead_domain_confirmed_by_doh_is_dead():
    n = mx_сеть({"MX": dns.resolver.NXDOMAIN})
    assert n.get_mx_records("dead.test") == []


def test_unverified_dead_domain_without_doh_stays_unverified():
    n = mx_сеть({"MX": DNSUnavailable})
    assert n.get_mx_records("dead.test") is None
    assert n.mx_doubt_reason("dead.test") == MX_DOUBT_UNVERIFIED


def test_doh_finds_mx_that_proxy_dns_denied():
    запись = types.SimpleNamespace(preference=10, exchange="mx.alive.test.")
    n = mx_сеть({"MX": [запись]})
    assert n.get_mx_records("alive.test") == ["mx.alive.test"]


def test_doh_no_mx_but_a_record_falls_back_to_the_domain():
    n = mx_сеть({"MX": dns.resolver.NoAnswer, "A": ["192.0.2.10"]})
    assert n.get_mx_records("nomx.test") == ["nomx.test"]


def test_doh_no_mx_and_wildcard_stays_unverified_as_wildcard():
    n = mx_сеть({"MX": dns.resolver.NoAnswer, "A": ["192.0.2.10"]}, wildcard=True)
    assert n.get_mx_records("wild.test") is None
    assert n.mx_doubt_reason("wild.test") == MX_DOUBT_WILDCARD


def test_doh_nothing_at_all_is_dead():
    n = mx_сеть({"MX": dns.resolver.NoAnswer, "A": dns.resolver.NoAnswer,
                 "AAAA": dns.resolver.NoAnswer})
    assert n.get_mx_records("empty.test") == []


def test_unverified_answer_from_the_verified_path_never_kills_the_domain():
    for заверено in ({"MX": UnverifiedNXDOMAIN},
                     {"MX": dns.resolver.NoAnswer, "A": UnverifiedNoAnswer,
                      "AAAA": UnverifiedNoAnswer}):
        n = mx_сеть(заверено)
        assert n.get_mx_records("maybe.test") is None, заверено


def test_attempt_passes_mx_to_session_control():
    from исходники import исходник_сети
    assert "proxy=proxy, mx=mx_record)" in исходник_сети()
