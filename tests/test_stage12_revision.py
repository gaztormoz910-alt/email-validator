# -*- coding: utf-8 -*-
import os
import sys
import threading
import types

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest

from core.settle import SettleMixin
from core.smtp_codes import WEAK_REJECT_REASON, classify_smtp_response
from core.verdict_revision import VerdictRevisionMixin
from tests.test_canary_repeat import A, EXITS, _Network, _Pipeline
from tests.test_liar_exit_resolution import (DOM, HONEST, HONEST2, LIAR, MX, P1, P3,
                                             P5, сеть)

ГИГАНТ = "gmail.com"


class _СетьСГигантом(_Network):
    def _is_never_catchall(self, domain):
        return domain == ГИГАНТ


def _годен(p, n, proxy, домен):
    res = {"proxy": proxy, "mx_records": ["mx." + домен]}
    email = "u%d.%s@%s" % (n, EXITS[proxy].rsplit(".", 1)[-1], домен)
    p._fly_canary(email, res)
    p._note_valid_exit(email, res)
    return email


def test_final_canary_covers_the_tail_on_a_clean_giant():
    net = _СетьСГигантом({"203.0.113.10": "invalid"})
    p = _Pipeline(net)
    адреса = [_годен(p, n, A, ГИГАНТ) for n in range(1, 6)]
    assert p._spared_valid([ГИГАНТ], set()) == {адреса[0]}
    assert p._final_canaries([]) == 1
    assert p._spared_valid([ГИГАНТ], set()) == set(адреса)


def test_final_canary_catches_a_late_liar_on_a_clean_giant():
    net = _СетьСГигантом({"203.0.113.10": "invalid"})
    p = _Pipeline(net)
    for n in range(1, 6):
        _годен(p, n, A, ГИГАНТ)
    net.answers["203.0.113.10"] = "valid"
    переспрошены = []
    p._recheck_revoked = lambda домены: переспрошены.append(set(домены)) or (0, 0)
    p._final_canaries([])
    assert p.canary.is_compromised("203.0.113.10", ГИГАНТ)
    assert ГИГАНТ in p.canary.compromised_domains()
    assert переспрошены and ГИГАНТ in переспрошены[0]
    assert p._spared_valid([ГИГАНТ], p.canary.lying_pairs()) == set()


def test_ordinary_clean_domain_still_gets_no_final_canary():
    net = _СетьСГигантом({"203.0.113.10": "invalid"})
    p = _Pipeline(net)
    for n in range(1, 6):
        _годен(p, n, A, "mailhost.test")
    спрошено = len(net.asked)
    assert p._final_canaries([]) == 0
    assert len(net.asked) == спрошено


def test_no_final_canary_on_a_giant_after_stop():
    net = _СетьСГигантом({"203.0.113.10": "invalid"})
    p = _Pipeline(net)
    for n in range(1, 6):
        _годен(p, n, A, ГИГАНТ)
    net.stopped = True
    спрошено = len(net.asked)
    assert p._final_canaries([]) == 0 and len(net.asked) == спрошено


ЯВНОЕ_НЕТ = classify_smtp_response(550, b"5.1.1 User unknown")
СПОРНОЕ_НЕТ = classify_smtp_response(550, b"5.5.0 Requested action not taken: mailbox unavailable")


class _Тройка(VerdictRevisionMixin):
    def __init__(self, net):
        self.network = net
        self.logs = []
        self.callbacks = {"on_log": lambda text, tag: self.logs.append(text)}


def _сеть3(третьему, postmaster=True, гигант=False):
    n = сеть()
    n._is_never_catchall = lambda d: гигант
    n.postmaster_is_honored = lambda d, mx: postmaster
    спрошено = []

    def ping(email, mx, proxy=None, control_probe=False):
        спрошено.append(proxy)
        return dict(третьему, proxy=proxy)

    n._do_single_ping = ping
    n.спрошено = спрошено
    return n


def _спор(второй=ЯВНОЕ_НЕТ):
    return {"status": "valid", "reason": "250 OK", "proxy": P1, "mx_records": [MX],
            "second_opinion_answer": dict(второй, proxy=P3)}


def test_third_exit_confirms_explicit_no_and_the_first_exit_is_marked():
    n = _сеть3(ЯВНОЕ_НЕТ)
    p = _Тройка(n)
    ctx = types.SimpleNamespace(lock=threading.Lock(),
                                domain_stats={DOM: {"total": 1, "valid": 1}})
    итог = p._third_opinion("anna@" + DOM, _спор(), ctx, DOM)
    assert итог["status"] == "invalid" and итог["proxy"] == P5
    assert n.спрошено == [P5]
    assert (LIAR, DOM) in n.tarpit_pairs()
    assert ctx.domain_stats[DOM] == {"total": 0, "valid": 0}


def test_third_exit_accepting_keeps_unknown():
    n = _сеть3({"status": "valid", "reason": "250 OK"})
    assert _Тройка(n)._third_opinion("anna@" + DOM, _спор()) is None
    assert not n.tarpit_pairs()


@pytest.mark.parametrize("второй, третий", [
    (СПОРНОЕ_НЕТ, ЯВНОЕ_НЕТ),
    (ЯВНОЕ_НЕТ, СПОРНОЕ_НЕТ),
    ({"status": "unknown", "reason": "Timeout"}, ЯВНОЕ_НЕТ),
    (ЯВНОЕ_НЕТ, {"status": "unknown", "reason": "Timeout"}),
])
def test_only_explicit_no_from_both_counts(второй, третий):
    assert WEAK_REJECT_REASON in СПОРНОЕ_НЕТ["reason"]
    n = _сеть3(третий)
    assert _Тройка(n)._third_opinion("anna@" + DOM, _спор(второй)) is None


def test_server_rejecting_postmaster_is_not_believed():
    n = _сеть3(ЯВНОЕ_НЕТ, postmaster=False)
    assert _Тройка(n)._third_opinion("anna@" + DOM, _спор()) is None


def test_giant_needs_no_postmaster_check():
    n = _сеть3(ЯВНОЕ_НЕТ, postmaster=False, гигант=True)
    assert _Тройка(n)._third_opinion("anna@" + DOM, _спор())["status"] == "invalid"


def test_no_third_exit_no_verdict():
    n = _сеть3(ЯВНОЕ_НЕТ)
    n.set_proxy_profiles({P1: {"exit_ip": LIAR}, P3: {"exit_ip": HONEST}})
    n.proxies = [P1, P3]
    assert _Тройка(n)._third_opinion("anna@" + DOM, _спор()) is None
    assert n.спрошено == []


def test_pick_third_avoids_both_exits_and_caught_ones():
    n = сеть()
    assert n._pick_third(DOM, False, False, P1, P3) == P5
    n.mark_exit_caught(HONEST2, DOM)
    assert n._pick_third(DOM, False, False, P1, P3) is None


def test_second_answer_is_taken_once_and_not_hoarded():
    n = сеть()
    n._do_single_ping = lambda email, mx, proxy=None, control_probe=False: dict(ЯВНОЕ_НЕТ)
    p = _Тройка(n)
    res = {"status": "valid", "proxy": P1, "mx_records": [MX]}
    assert p._second_opinion_on_valid("anna@" + DOM, res) is False
    assert res["second_opinion_answer"]["status"] == "invalid"
    assert res["second_opinion_answer"]["proxy"] in (P3, P5)
    assert not n.__dict__.get("_second_answers")


def test_settle_turns_an_honest_dispute_into_invalid_via_third_exit():
    class Конвейер(SettleMixin, VerdictRevisionMixin):
        confirm_valid = True

        def __init__(self, net):
            self.network = net
            self.выдано = []
            self.callbacks = {"on_log": lambda text, tag: None}

        def _second_opinion_on_valid(self, email, res):
            res["second_opinion_answer"] = dict(ЯВНОЕ_НЕТ, proxy=P3)
            return False

        def _recheck_if_first_exit_lies(self, *a, **k):
            return None

        def _enrich_and_score(self, *a, **k):
            pass

        def _emit(self, email, status, reason, mx, data):
            self.выдано.append((status, reason))

    n = _сеть3(ЯВНОЕ_НЕТ)
    p = Конвейер(n)
    ctx = types.SimpleNamespace(lock=threading.Lock(), domain_stats={},
                                state=types.SimpleNamespace(mark_done=lambda k: None))
    p._settle("anna@" + DOM, {}, False, {"status": "valid", "reason": "250 OK", "proxy": P1,
                                         "mx_records": [MX]}, False, ctx)
    assert [s for s, _ in p.выдано] == ["Invalid/Bounce"]
    assert "второй и третий" in p.выдано[0][1]
    assert ctx.domain_stats[DOM] == {"total": 1, "valid": 0}
