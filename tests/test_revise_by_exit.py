"""Отзыв «Годен» по выходу, а не по всему домену (решение владельца 20.11.2026).

Было: один уличённый выход снимал «Годен» со всего домена в прогоне. На живом
прогоне через прокси владельца части без пойманного выхода давали 30–32
«Годен» из 40, части с пойманным — 0–2.

Стало: уцелевает только «Годен», чей выход ИЗВЕСТЕН, на этом домене в этом
прогоне ПРОВЕРЕН канарейкой (отверг выдуманный адрес) и не пойман ни
канарейкой, ни тарпитингом. Здесь проверяется и это, и каждое «не уцелеет».
Адреса и выходы выдуманы (домен .test, адреса из документационных сетей).
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.canary import CanaryWatch                     # noqa: E402
from core.verdict_revision import VerdictRevisionMixin  # noqa: E402

HONEST = "socks5://198.51.100.10:1080"   # выход 203.0.113.10, канарейку отверг
LIAR = "socks5://198.51.100.20:1080"     # выход 203.0.113.20, канарейку принял
SAME_EXIT = "socks5://198.51.100.21:1080"  # другой прокси, тот же выход, что у лжеца
UNPROFILED = "socks5://198.51.100.30:1080"  # выход неизвестен
UNPROBED = "socks5://198.51.100.40:1080"    # выход 203.0.113.40, канарейка не дошла
TARPIT = "socks5://198.51.100.50:1080"      # выход 203.0.113.50: отверг канарейку, потом пойман

EXITS = {HONEST: "203.0.113.10", LIAR: "203.0.113.20", SAME_EXIT: "203.0.113.20",
         UNPROBED: "203.0.113.40", TARPIT: "203.0.113.50"}


class _Network:
    def exit_ip_of(self, proxy):
        return EXITS.get(proxy, "")


class _Pipeline(VerdictRevisionMixin):
    def __init__(self):
        self.network = _Network()
        self.canary = CanaryWatch()
        self.logs = []
        self.callbacks = {"on_log": lambda text, tag: self.logs.append(text)}


def _scene():
    p = _Pipeline()
    dom = "mailhost.test"
    for proxy, email in ((HONEST, "a@" + dom), (LIAR, "b@" + dom), (SAME_EXIT, "c@" + dom),
                         (UNPROFILED, "d@" + dom), (UNPROBED, "e@" + dom), (TARPIT, "f@" + dom),
                         (HONEST, "g@other.test")):
        p._note_valid_exit(email, {"proxy": proxy})
    p.canary.record("203.0.113.10", dom, "invalid")     # честен
    p.canary.record("203.0.113.20", dom, "valid")       # врёт
    p.canary.record("203.0.113.50", dom, "invalid")     # честен на канарейке…
    # Непрофилированный прокси канарейка проверила по строке подключения и сочла
    # честным — но его выход неизвестен: он мог делить IP с уличённым.
    p.canary.record(UNPROFILED.lower(), dom, "invalid")
    liars = p.canary.lying_pairs() | {("203.0.113.50", dom)}   # …но пойман тарпитингом
    return p, dom, liars


def test_only_vouched_honest_exit_keeps_valid():
    p, dom, liars = _scene()
    assert p._spared_valid([dom], liars) == {"a@" + dom}


def test_liar_and_its_shared_exit_lose_valid():
    p, dom, liars = _scene()
    spared = p._spared_valid([dom], liars)
    assert "b@" + dom not in spared
    # Другая строка подключения, но тот же выходной IP — для почтовика тот же отправитель.
    assert "c@" + dom not in spared


def test_unknown_unprobed_and_tarpitted_exits_lose_valid():
    p, dom, liars = _scene()
    spared = p._spared_valid([dom], liars)
    assert "d@" + dom not in spared      # выход неизвестен
    assert "e@" + dom not in spared      # канарейка до него не дошла
    assert "f@" + dom not in spared      # отверг канарейку, но пойман тарпитингом


def test_other_domains_are_not_touched():
    p, dom, liars = _scene()
    assert "g@other.test" not in p._spared_valid([dom], liars)


def test_without_canary_nothing_is_spared():
    p, dom, liars = _scene()
    p.canary = None
    assert p._spared_valid([dom], liars) == set()


def test_vouched_needs_a_finished_honest_probe():
    w = CanaryWatch()
    assert not w.vouched("203.0.113.1", "mailhost.test")          # не проверен
    # Таймаут или «не проверено» — проба не удалась: за выход не ручается
    # (до 21.11.2026 ручался, и при отзыве по выходу это сохраняло «Годен»).
    for inconclusive in ("unknown", "greylisted", "", None):
        w.record("203.0.113.1", "mailhost.test", inconclusive)
        assert not w.vouched("203.0.113.1", "mailhost.test"), inconclusive
    w.record("203.0.113.1", "mailhost.test", "invalid")
    assert w.vouched("203.0.113.1", "mailhost.test")              # отверг выдуманный — честен
    w.record("203.0.113.2", "mailhost.test", "catchall")
    assert not w.vouched("203.0.113.2", "mailhost.test")          # врёт


def test_revise_passes_spare_and_falls_back_for_old_handlers():
    p, dom, liars = _scene()
    seen = []

    def new_handler(domains, status, note, spare):
        seen.append(("new", set(spare)))
        return 1

    def old_handler(domains, status, note):
        seen.append(("old", None))
        return 1

    p.callbacks["on_revise"] = new_handler
    p._revise([dom], "Unknown", "канарейка", spare={"a@" + dom})
    p.callbacks["on_revise"] = old_handler
    p._revise([dom], "Unknown", "канарейка", spare={"a@" + dom})
    assert seen == [("new", {"a@" + dom}), ("old", None)]


def test_store_keeps_spared_rows_valid():
    from ui.result_store import ResultStore

    store = ResultStore()
    for email in ("a@mailhost.test", "b@mailhost.test"):
        store.append(email, "Valid", "250 OK", "mx.mailhost.test", {})
    moved = store.revise_domain("mailhost.test", "Unknown", "канарейка", {"a@mailhost.test"})
    assert moved == 1
    rows = {r["email"]: r["status"] for r in store.page(groups=("valid", "unknown"), page=1, size=10)}
    assert rows == {"a@mailhost.test": "Valid", "b@mailhost.test": "Unknown"}
    counts = store.counts()
    assert (counts["valid"], counts["unknown"]) == (1, 1)


def test_control_store_without_spare_revises_whole_domain():
    from ui.result_store import ResultStore

    store = ResultStore()
    for email in ("a@mailhost.test", "b@mailhost.test"):
        store.append(email, "Valid", "250 OK", "mx.mailhost.test", {})
    assert store.revise_domain("mailhost.test", "Unknown", "канарейка") == 2


def test_settle_records_the_exit_of_every_valid():
    import inspect

    from core import settle
    src = inspect.getsource(settle)
    block = src[src.index("self._fly_canary(email, res)"):][:120]
    assert "self._note_valid_exit(email, res)" in block


def test_cli_keeps_spared_rows_valid():
    import threading

    from cli import revise_rows

    rows = [{"email": "a@mailhost.test", "status": "Valid", "reason": "250 OK"},
            {"email": "b@mailhost.test", "status": "Valid", "reason": "250 OK"},
            {"email": "c@other.test", "status": "Valid", "reason": "250 OK"}]
    moved = revise_rows(rows, threading.Lock(), ["mailhost.test"], "Unknown", "канарейка",
                        {"a@mailhost.test"})
    assert moved == 1
    assert [r["status"] for r in rows] == ["Valid", "Unknown", "Valid"]


def test_control_cli_without_spare_revises_whole_domain():
    import threading

    from cli import revise_rows

    rows = [{"email": "a@mailhost.test", "status": "Valid", "reason": "250 OK"},
            {"email": "b@mailhost.test", "status": "Valid", "reason": "250 OK"}]
    assert revise_rows(rows, threading.Lock(), ["mailhost.test"], "Unknown", "канарейка") == 2


def test_tarpit_and_pipeline_pass_exits_through():
    import inspect

    from core import network, pipeline
    net = inspect.getsource(network)
    mark = net[net.index("self._tarpit_domains.add(domain)"):][:200]
    assert "self._tarpit_pairs.add((" in mark
    run = inspect.getsource(pipeline)
    assert run.count("spare=уцелели") == 2
