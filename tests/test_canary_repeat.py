import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.canary import CanaryWatch
from core.verdict_revision import VerdictRevisionMixin

DOM = "mailhost.test"
A = "socks5://198.51.100.10:1080"
B = "socks5://198.51.100.20:1080"
OTHER = "socks5://198.51.100.99:1080"
EXITS = {A: "203.0.113.10", B: "203.0.113.20", OTHER: "203.0.113.99"}


class _Network:

    def __init__(self, answers, reroute=None):
        self.answers = answers
        self.reroute = reroute or {}
        self.asked = []
        self.stopped = False

    def exit_ip_of(self, proxy):
        return EXITS.get(proxy, "")

    def aborted(self):
        return self.stopped

    def stealth_smtp_ping(self, email, mx, prefer_exit_of=None, **kw):
        used = self.reroute.get(prefer_exit_of, prefer_exit_of)
        self.asked.append(used)
        return {"status": self.answers.get(EXITS.get(used), "invalid"), "proxy": used}


class _Pipeline(VerdictRevisionMixin):
    def __init__(self, net):
        self.network = net
        self.canary = CanaryWatch()
        self.logs = []
        self.callbacks = {"on_log": lambda text, tag: self.logs.append(text)}

    def valid(self, n, proxy):
        res = {"proxy": proxy, "mx_records": ["mx." + DOM]}
        email = "u%d.%s@%s" % (n, EXITS[proxy].rsplit(".", 1)[-1], DOM)
        self._fly_canary(email, res)
        self._note_valid_exit(email, res)
        return email


def test_canary_repeats_every_twenty_valids():
    w = CanaryWatch()
    fired = []
    for n in range(1, 46):
        w.note_valid("203.0.113.10", DOM)
        if w.should_probe("203.0.113.10", DOM):
            fired.append(n)
            w.record("203.0.113.10", DOM, "invalid")
    assert fired == [1, 21, 41]


def test_valid_after_last_honest_probe_is_not_vouched():
    p = _Pipeline(_Network({"203.0.113.10": "invalid"}))
    emails = [p.valid(n, A) for n in range(1, 6)]
    spared = p._spared_valid([DOM], set())
    assert spared == {emails[0]}


def test_repeat_probe_vouches_for_everything_before_it():
    p = _Pipeline(_Network({"203.0.113.10": "invalid"}))
    emails = [p.valid(n, A) for n in range(1, 22)]
    assert p._spared_valid([DOM], set()) == set(emails)


def test_exit_that_starts_lying_loses_all_its_valids():
    net = _Network({"203.0.113.10": "invalid"})
    p = _Pipeline(net)
    for n in range(1, 21):
        p.valid(n, A)
    net.answers["203.0.113.10"] = "valid"
    p.valid(21, A)
    assert p.canary.is_compromised("203.0.113.10", DOM)
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == set()


def test_probe_through_another_exit_is_not_counted():
    p = _Pipeline(_Network({"203.0.113.99": "invalid"}, reroute={A: OTHER}))
    email = p.valid(1, A)
    assert not p.canary.vouched("203.0.113.10", DOM)
    assert email not in p._spared_valid([DOM], set())


def test_control_lie_through_another_exit_is_not_pinned_on_this_one():
    p = _Pipeline(_Network({"203.0.113.99": "valid"}, reroute={A: OTHER}))
    p.valid(1, A)
    assert not p.canary.is_compromised("203.0.113.10", DOM)


def test_final_canary_covers_the_tail_on_a_compromised_domain():
    net = _Network({"203.0.113.10": "invalid", "203.0.113.20": "valid"})
    p = _Pipeline(net)
    a_emails = [p.valid(n, A) for n in range(1, 6)]
    p.valid(1, B)
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == {a_emails[0]}
    assert p._final_canaries([]) == 1
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == set(a_emails)


def test_final_canary_can_catch_a_late_liar():
    net = _Network({"203.0.113.10": "invalid", "203.0.113.20": "valid"})
    p = _Pipeline(net)
    for n in range(1, 6):
        p.valid(n, A)
    p.valid(1, B)
    net.answers["203.0.113.10"] = "valid"
    p._final_canaries([])
    assert p.canary.is_compromised("203.0.113.10", DOM)
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == set()


def test_control_no_final_canary_on_an_honest_domain_or_after_stop():
    net = _Network({"203.0.113.10": "invalid"})
    p = _Pipeline(net)
    for n in range(1, 6):
        p.valid(n, A)
    asked = len(net.asked)
    assert p._final_canaries([]) == 0
    net.stopped = True
    assert p._final_canaries([DOM]) == 0
    assert len(net.asked) == asked


def test_pipeline_runs_final_canaries_before_by_exit_revision():
    import inspect

    from core import pipeline
    src = inspect.getsource(pipeline)
    final = src.index("self._final_canaries(trapped)")
    assert final < src.index("лжецы = set(self.network.tarpit_pairs())")


class _SingleSessionNetwork(_Network):

    def __init__(self, answers):
        _Network.__init__(self, answers)
        self.single = []

    def _do_single_ping(self, email, mx_record, proxy=None, **kw):
        self.single.append(proxy)
        return {"status": self.answers.get(EXITS.get(proxy), "invalid")}

    def stealth_smtp_ping(self, *a, **kw):
        raise AssertionError("канарейка не должна идти с перебором выходов и сверкой второго MX")


def test_canary_uses_one_session_through_exactly_that_proxy():
    net = _SingleSessionNetwork({"203.0.113.10": "invalid"})
    p = _Pipeline(net)
    email = p.valid(1, A)
    assert net.single == [A]
    assert p.canary.vouched("203.0.113.10", DOM)
    assert email in p._spared_valid([DOM], set())


def test_failed_probe_does_not_vouch_and_is_retried():
    net = _SingleSessionNetwork({"203.0.113.10": "unknown"})
    p = _Pipeline(net)
    first = p.valid(1, A)
    assert not p.canary.vouched("203.0.113.10", DOM)
    assert first not in p._spared_valid([DOM], set())
    net.answers["203.0.113.10"] = "invalid"
    p.valid(2, A)
    assert net.single == [A, A]
    assert p.canary.vouched("203.0.113.10", DOM)
