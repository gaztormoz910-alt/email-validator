# -*- coding: utf-8 -*-
"""Три недоработки, названные аудитом 21.11.2026, и их исправления.

1. Гонка в поручительстве канарейки: честная проба ручалась за номер «Годен»,
   прочитанный в момент ЗАПИСИ ответа, а не запуска, — за хвост, которого не
   видела. И первая проба пары не занималась на время полёта: каждый «Годен»
   того же выхода пускал ещё одну.
2. «Под вопросом»-отсрочка («550 … try again later», «4.x.x» при 5xx)
   засчитывалась как отказ выдуманному адресу — и «доказывала», что домен не
   catch-all, а выход честен.
3. Отметка «выдуманный адрес отвергнут» была одна на домен: «Годен» выхода B
   подтверждался отказом, полученным через выход A.

У каждой проверки дефекта есть контрольная: честный случай не сломан.
Адреса, домены и выходы выдуманы.
"""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.canary import CanaryWatch                     # noqa: E402
from core.confirmation import rejects_fake              # noqa: E402
from core.network import NetworkValidator               # noqa: E402
from core.smtp_codes import classify_smtp_response      # noqa: E402
from core.verdict_revision import VerdictRevisionMixin  # noqa: E402

DOM = "corp-mail.test"
MX = ["mx1.corp-mail.test"]
A = "socks5://198.51.100.10:1080"   # выход 203.0.113.10
B = "socks5://198.51.100.20:1080"   # выход 203.0.113.20
EXITS = {A: "203.0.113.10", B: "203.0.113.20"}
E = "203.0.113.10"

ОТСРОЧКИ = [(550, b"5.7.1 Service unavailable, try again later"),
            (550, b"4.2.0 Mailbox temporarily unavailable")]
ОТКАЗЫ = [(550, b""), (550, b"5.1.1 User unknown")]
НЕТ_ЯЩИКА = classify_smtp_response(550, b"5.1.1 User unknown")


# ═══════════════════════════════════════ 2. отсрочка — не отказ выдуманному

def test_deferral_with_permanent_code_is_not_a_refusal():
    for code, text in ОТСРОЧКИ:
        v = classify_smtp_response(code, text)
        # Предпосылка: разбор кладёт это в «под вопросом», а «под вопросом»
        # входит в набор отказов. Без неё проверка ниже ничего бы не значила.
        assert v["status"] == "risky", (code, text, v)
        assert rejects_fake(v, text) is False, (code, text, v)


def test_bare_and_explicit_refusals_still_count():
    for code, text in ОТКАЗЫ:
        v = classify_smtp_response(code, text)
        assert rejects_fake(v, text) is True, (code, text, v)


class _Server:
    def __init__(self, code, text):
        self.answer = (code, text)

    def rcpt(self, _addr):
        return self.answer


def test_in_session_deferral_does_not_exclude_catchall():
    n = NetworkValidator(timeout=5)
    for code, text in ОТСРОЧКИ:
        res = {"status": "valid", "reason": "250 OK", "proxy": A}
        n._control_in_session(_Server(code, text), DOM, res, proxy=A)
        assert res["control_rcpt"] == "inconclusive", (text, res)
    assert n._fake_rejected_via(DOM, A) is False
    assert DOM not in n.catchall_cache


def test_in_session_refusal_excludes_catchall_for_that_exit():
    n = NetworkValidator(timeout=5)
    res = {"status": "valid", "reason": "250 OK", "proxy": A}
    n._control_in_session(_Server(550, b"5.1.1 User unknown"), DOM, res, proxy=A)
    assert res["control_rcpt"] == "rejected"
    assert n._fake_rejected_via(DOM, A) is True
    assert n._fake_rejected_via(DOM, B) is False


def test_triple_probe_deferral_proves_nothing(monkeypatch):
    n = NetworkValidator(timeout=5)
    n.memory = None
    отсрочка = classify_smtp_response(*ОТСРОЧКИ[0])
    monkeypatch.setattr(n, "_probe_proxy_for", lambda d: A)
    monkeypatch.setattr(n, "_probe_recipients",
                        lambda fakes, mx, proxy=None: [dict(отсрочка)] * len(fakes))
    monkeypatch.setattr(n, "_remember_catchall", lambda *a, **k: None)
    n.is_catch_all_domain(DOM, MX[0])
    assert n._fake_rejected_via(DOM, A) is False
    assert DOM not in n.catchall_cache


# ═══════════════════════════════════ 3. отметка «не catch-all» — по выходу

def test_triple_probe_rejection_vouches_only_for_its_exit(monkeypatch):
    n = NetworkValidator(timeout=5)
    n.memory = None
    monkeypatch.setattr(n, "_probe_proxy_for", lambda d: A)
    monkeypatch.setattr(n, "_probe_recipients",
                        lambda fakes, mx, proxy=None: [dict(НЕТ_ЯЩИКА)] * len(fakes))
    monkeypatch.setattr(n, "_remember_catchall", lambda *a, **k: None)
    assert n.is_catch_all_domain(DOM, MX[0]) is False
    assert n._fake_rejected_via(DOM, A) is True
    assert n._fake_rejected_via(DOM, B) is False


def test_valid_via_b_not_confirmed_by_rejection_via_a(monkeypatch):
    n = NetworkValidator(timeout=5)
    n._note_fake_rejected(DOM, A)
    спрошено = []

    def сорвалась(fakes, mx, proxy=None):
        спрошено.append(proxy)
        return [{"status": "unknown", "reason": "таймаут"}]

    monkeypatch.setattr(n, "_probe_recipients", сорвалась)
    res = n._confirm_acceptance(DOM, {"status": "valid", "reason": "250 OK", "proxy": B}, MX)
    assert res["status"] == "unconfirmed", res
    # Контроль спрошен ВЫХОДОМ «Годен», а не взят у чужого.
    assert спрошено == [B]


def test_valid_via_a_confirmed_by_own_rejection_without_new_session(monkeypatch):
    n = NetworkValidator(timeout=5)
    n._note_fake_rejected(DOM, A)

    def лишняя(*_a, **_k):
        raise AssertionError("лишняя сессия: отказ этого выхода уже есть")

    monkeypatch.setattr(n, "_probe_recipients", лишняя)
    res = n._confirm_acceptance(DOM, {"status": "valid", "reason": "250 OK", "proxy": A}, MX)
    assert res["status"] == "valid", res


def test_own_session_through_other_exit_does_not_confirm(monkeypatch):
    n = NetworkValidator(timeout=5)
    monkeypatch.setattr(n, "has_proxies_configured", lambda: True)
    monkeypatch.setattr(n, "_probe_proxy_for", lambda d: A)
    monkeypatch.setattr(n, "_probe_recipients",
                        lambda fakes, mx, proxy=None: [dict(НЕТ_ЯЩИКА)])
    # «Годен» пришёл прямым соединением, контроль ушёл через A.
    res = n._confirm_acceptance(DOM, {"status": "valid", "reason": "250 OK"}, MX)
    assert res["status"] == "unconfirmed", res
    # Отказ не пропал — он записан за тем выходом, который его получил.
    assert n._fake_rejected_via(DOM, A) is True
    assert n._fake_rejected_via(DOM, None) is False


def test_own_session_through_same_exit_confirms(monkeypatch):
    n = NetworkValidator(timeout=5)
    monkeypatch.setattr(
        n, "_probe_recipients",
        lambda fakes, mx, proxy=None: [dict(НЕТ_ЯЩИКА) if proxy == B
                                       else {"status": "unknown", "reason": "чужой выход"}])
    res = n._confirm_acceptance(DOM, {"status": "valid", "reason": "250 OK", "proxy": B}, MX)
    assert res["status"] == "valid", res


def test_own_session_deferral_does_not_confirm(monkeypatch):
    n = NetworkValidator(timeout=5)
    отсрочка = classify_smtp_response(*ОТСРОЧКИ[0])
    monkeypatch.setattr(n, "_probe_recipients",
                        lambda fakes, mx, proxy=None: [dict(отсрочка)])
    res = n._confirm_acceptance(DOM, {"status": "valid", "reason": "250 OK", "proxy": B}, MX)
    assert res["status"] == "unconfirmed", res
    assert n._fake_rejected_via(DOM, B) is False


# ═══════════════════════════════════════ 1. поручительство по номеру запуска

def test_honest_probe_vouches_up_to_its_launch_number():
    w = CanaryWatch()
    w.note_valid(E, DOM)
    первая = w.claim_probe(E, DOM)
    assert первая == 1
    for _ in range(25):                  # №2–26 пришли, пока проба летит
        w.note_valid(E, DOM)
    # Номер занятости перезаписан (так делает и завершающая проба).
    вторая = w.claim_now(E, DOM)
    assert вторая == 26
    w.record(E, DOM, "invalid", covers=первая)
    assert w.honest_upto(E, DOM) == 1, "проба ручается за хвост, которого не видела"
    w.record(E, DOM, "invalid", covers=вторая)
    assert w.honest_upto(E, DOM) == 26


def test_probe_in_flight_blocks_a_second_one():
    w = CanaryWatch()
    w.note_valid(E, DOM)
    assert w.claim_probe(E, DOM) == 1
    w.note_valid(E, DOM)
    assert w.claim_probe(E, DOM) is None, "вторая проба, пока первая летит"
    w.record(E, DOM, "invalid", covers=1)
    for _ in range(19):
        w.note_valid(E, DOM)             # всего 21: двадцать новых с пробы №1
    assert w.claim_probe(E, DOM) == 21


def test_release_frees_only_its_own_claim():
    w = CanaryWatch()
    w.note_valid(E, DOM)
    assert w.claim_probe(E, DOM) == 1
    w.release(E, DOM, 99)                # чужой номер — не снимает
    w.note_valid(E, DOM)
    assert w.claim_probe(E, DOM) is None
    w.release(E, DOM, 1)
    # Первая проба не состоялась — пара не «проверена», пускаем снова.
    assert w.claim_probe(E, DOM) == 2


class _SingleNet:
    """Сеть канарейки с одной сессией (_do_single_ping), как настоящая."""

    def __init__(self, answer, gate=None):
        self.answer = answer
        self.gate = gate
        self.asked = 0
        self.lock = threading.Lock()

    def exit_ip_of(self, proxy):
        return EXITS.get(proxy, "")

    def aborted(self):
        return False

    def _do_single_ping(self, email, mx, proxy=None):
        with self.lock:
            self.asked += 1
        if self.gate is not None:
            self.gate.wait(5)
        if isinstance(self.answer, Exception):
            raise self.answer
        return dict(self.answer)


class _Pipeline(VerdictRevisionMixin):
    def __init__(self, net):
        self.network = net
        self.canary = CanaryWatch()
        self.callbacks = {"on_log": lambda text, tag: None}

    def valid(self, n, proxy=A):
        res = {"proxy": proxy, "mx_records": list(MX)}
        email = "u%d@%s" % (n, DOM)
        улика = self._fly_canary(email, res)
        self._note_valid_exit(email, res)
        return улика


def test_canary_deferral_does_not_vouch_for_exit():
    for code, text in ОТСРОЧКИ:
        p = _Pipeline(_SingleNet(classify_smtp_response(code, text)))
        assert p.valid(1) is False
        assert p.canary.vouched(E, DOM) is False, text
        assert p.canary.honest_upto(E, DOM) == -1


def test_canary_refusal_vouches_for_exit():
    p = _Pipeline(_SingleNet(НЕТ_ЯЩИКА))
    assert p.valid(1) is False
    assert p.canary.vouched(E, DOM) is True
    assert p.canary.honest_upto(E, DOM) == 1


def test_failed_canary_releases_pair_for_next_valid():
    p = _Pipeline(_SingleNet(OSError("обрыв")))
    p.valid(1)
    p.network.answer = НЕТ_ЯЩИКА
    p.valid(2)
    assert p.network.asked == 2, "после сорвавшейся пробы пара осталась занятой"
    assert p.canary.honest_upto(E, DOM) == 2


def test_parallel_valids_fly_one_canary():
    ворота = threading.Event()
    p = _Pipeline(_SingleNet(НЕТ_ЯЩИКА, gate=ворота))
    первый = threading.Thread(target=p.valid, args=(1,))
    первый.start()
    for _ in range(100):                 # дождаться, пока первая проба взлетит
        if p.network.asked:
            break
        threading.Event().wait(0.01)
    assert p.network.asked == 1
    прочие = [threading.Thread(target=p.valid, args=(n,)) for n in range(2, 8)]
    for t in прочие:
        t.start()
    for t in прочие:
        t.join(5)
    assert p.network.asked == 1, "пока первая летит, пущены ещё %d" % (p.network.asked - 1)
    ворота.set()
    первый.join(5)
    # Ручается за №1 — за то, что было на момент её запуска, а не за №2–7.
    assert p.canary.honest_upto(E, DOM) == 1


def _запустить_и_дождаться(p, n):
    поток = threading.Thread(target=p.valid, args=(n,))
    поток.start()
    for _ in range(300):
        if p.network.asked:
            break
        threading.Event().wait(0.01)
    assert p.network.asked == 1
    return поток


def test_valid_that_launched_the_probe_is_covered_by_it():
    """Номер адреса — с МОМЕНТА его «Годен», а не после полёта его пробы.

    Проба летит синхронно, в потоке адреса, и номер прежде читался уже после
    её возвращения — раздутым «Годен», пришедшими за время полёта. Честная
    проба ручается ровно за номер запуска, и адрес, сам её пустивший, терял
    защиту: живой прогон 21.11.2026 — 11 «Неизвестно» из 40 вместо 2.
    """
    ворота = threading.Event()
    p = _Pipeline(_SingleNet(НЕТ_ЯЩИКА, gate=ворота))
    первый = _запустить_и_дождаться(p, 1)
    p.valid(2)                           # пришёл, пока проба №1 летит
    ворота.set()
    первый.join(5)
    уцелели = p._spared_valid([DOM], set())
    assert "u1@%s" % DOM in уцелели, "адрес не покрыт собственной честной пробой"
    # №2 получен во время полёта — проба №1 за него не ручается.
    assert "u2@%s" % DOM not in уцелели


def test_final_canary_covers_valids_that_arrived_during_flight():
    ворота = threading.Event()
    p = _Pipeline(_SingleNet(НЕТ_ЯЩИКА, gate=ворота))
    первый = _запустить_и_дождаться(p, 1)
    p.valid(2)
    ворота.set()
    первый.join(5)
    assert p._final_canaries([DOM]) == 1
    assert p._spared_valid([DOM], set()) == {"u1@%s" % DOM, "u2@%s" % DOM}
