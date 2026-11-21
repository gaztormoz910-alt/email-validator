# -*- coding: utf-8 -*-
"""Увод домена с пойманного выхода и переспрос отозванных «Годен» (21.11.2026).

Прежде пара «выход + домен», пойманная канарейкой или тарпитингом, шла только
в отзыв в конце прогона: выбор прокси её не обходил, и домен продолжал ходить
через лжеца. Живой прогон: все 46 отозванных «Годен» из 300 — с одного выхода,
за которым стояли 6 прокси пула. Теперь пойманный выход для этого домена не
выбирается нигде, а «Годен», прошедшие через него до поимки, переспрашиваются
честным выходом той же лестницей. Адреса, домены и выходы выдуманы.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest  # noqa: E402

from core.canary import CanaryWatch                     # noqa: E402
from core.network import NetworkValidator               # noqa: E402
from core.smtp_codes import classify_smtp_response      # noqa: E402
from core.verdict_revision import VerdictRevisionMixin  # noqa: E402

DOM = "bigmail.test"
OTHER = "othermail.test"
MX = ["mx1.bigmail.test"]
P1 = "socks5://198.51.100.1:1080"   # выход лжеца
P2 = "socks5://198.51.100.2:1080"   # тот же выход лжеца (десять входов — один выход)
P3 = "socks5://198.51.100.3:1080"   # честный выход
P4 = "socks5://198.51.100.0:1080"   # профиль без выхода — первый по алфавиту
LIAR, HONEST = "203.0.113.66", "203.0.113.77"
НЕТ_ЯЩИКА = classify_smtp_response(550, b"5.1.1 User unknown")


def сеть():
    n = NetworkValidator(timeout=2, proxies=[P1, P2, P3, P4])
    n.set_proxy_profiles({P1: {"exit_ip": LIAR}, P2: {"exit_ip": LIAR},
                          P3: {"exit_ip": HONEST}, P4: {}})
    # Выбор детерминированный: первый по алфавиту из того, что осталось.
    n._choose_from = lambda pool, want_country="": sorted(pool)[0]
    n.country_for_domain = lambda domain, mx="": ""
    # Переспрос по умолчанию без сети: тест, которому он нужен, подменяет ответ.
    n.check_email = lambda email, **_k: {"status": "unknown", "reason": "тест без сети"}
    return n


def запретить_сессии(n):
    def ping(*_a, **_k):
        raise AssertionError("сессия через сеть, хотя её быть не должно")
    n._do_single_ping = ping


# ═══════════════════════════════════════════════ увод с пойманного выхода

def test_caught_exit_is_skipped_only_on_its_domain():
    n = сеть()
    with n._proxy_score_lock:
        n._proxy_banned.add(P4)
    assert n._pick_for_domain(DOM) == (P1, False)      # контроль: до поимки P1
    n.mark_exit_caught(LIAR, DOM)
    assert n._pick_for_domain(DOM) == (P3, False)
    # На другом домене тот же выход честен — его не трогаем.
    assert n._pick_for_domain(OTHER) == (P1, False)


def test_tarpit_pair_is_avoided_too():
    n = сеть()
    with n.catchall_lock:
        n._tarpit_pairs.add((LIAR, DOM))
    assert n._pick_for_domain(DOM) == (P3, False)


def test_unprofiled_proxy_is_last_resort_on_compromised_domain():
    n = сеть()
    assert n._pick_for_domain(DOM) == (P4, False)      # контроль: обычно он первый
    n.mark_exit_caught(LIAR, DOM)
    assert n._pick_for_domain(DOM) == (P3, False)      # на разоблачённом — последний
    with n._proxy_score_lock:
        n._proxy_banned.add(P3)
    # Безымянный выход может быть тем же лжецом — но другого живого нет.
    assert n._pick_for_domain(DOM) == (P4, False)


def test_only_caught_alive_means_unknown_without_a_session():
    n = сеть()
    n.mark_exit_caught(LIAR, DOM)
    with n._proxy_score_lock:
        n._proxy_banned.update({P3, P4})
    assert n._pick_for_domain(DOM) == (None, True)
    запретить_сессии(n)
    res = n.stealth_smtp_ping("anna@" + DOM, MX)
    assert res["status"] == "unknown"
    assert "уличены" in res["reason"]


def test_empty_pool_is_not_reported_as_caught():
    n = сеть()
    n.mark_exit_caught(LIAR, DOM)
    with n._proxy_score_lock:
        n._proxy_banned.update({P1, P2, P3, P4})
    assert n._pick_for_domain(DOM) == (None, False)


def test_main_check_goes_through_honest_exit_after_catch():
    n = сеть()
    n.mark_exit_caught(LIAR, DOM)
    спрошено = []

    def ping(email, mx, proxy=None, **_k):
        спрошено.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    n._do_single_ping = ping
    res = n.stealth_smtp_ping("anna@" + DOM, MX)
    assert res["status"] == "valid" and спрошено == [P3]


def test_greylist_retry_does_not_return_to_caught_exit():
    n = сеть()
    assert n.proxy_still_usable(P1, DOM) == P1          # контроль: до поимки
    n.mark_exit_caught(LIAR, DOM)
    assert n.proxy_still_usable(P1, DOM) is None
    assert n.proxy_still_usable(P1, OTHER) == P1
    спрошено = []

    def ping(email, mx, proxy=None, **_k):
        спрошено.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    n._do_single_ping = ping
    n.stealth_smtp_ping("anna@" + DOM, MX, prefer_exit_of=P1)
    assert спрошено == [P3]


def test_second_opinion_never_asks_a_caught_exit():
    n = сеть()
    n.mark_exit_caught(LIAR, DOM)
    спрошено = []

    def ping(email, mx, proxy=None, **_k):
        спрошено.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    n._do_single_ping = ping
    assert n.confirm_valid_from_other_exit("anna@" + DOM, MX, first_proxy=P3) is True
    assert спрошено == [P4]
    # Кроме лжеца сверять не с кем — «сверить не с чем», а не эхо лжеца.
    with n._proxy_score_lock:
        n._proxy_banned.add(P4)
    запретить_сессии(n)
    assert n.confirm_valid_from_other_exit("anna@" + DOM, MX, first_proxy=P3) is None


def test_probe_proxy_avoids_caught_exit_but_never_goes_direct():
    n = сеть()
    n.mark_exit_caught(LIAR, DOM)
    assert n._probe_proxy_for(DOM) == P3
    with n._proxy_score_lock:
        n._proxy_banned.update({P3, P4})
    # Живы только пойманные: проба идёт прежним выбором, а не прямым соединением.
    assert n._probe_proxy_for(DOM) in (P1, P2)


def test_direct_connection_caught_means_unknown():
    n = NetworkValidator(timeout=2)
    n.country_for_domain = lambda domain, mx="": ""
    n.mark_exit_caught("прямое соединение", DOM)
    запретить_сессии(n)
    assert n.stealth_smtp_ping("anna@" + DOM, MX)["status"] == "unknown"


# ═══════════════════════════════════ канарейка сообщает сети о поимке

class _Pipeline(VerdictRevisionMixin):
    def __init__(self, net):
        self.network = net
        self.canary = CanaryWatch()
        self.logs = []
        self.callbacks = {"on_log": lambda text, tag: self.logs.append(text)}

    def valid(self, email, proxy):
        res = {"status": "valid", "proxy": proxy, "mx_records": list(MX)}
        self._fly_canary(email, res)
        self._note_valid_exit(email, res)


def канарейка_по_выходу(n, лжецы):
    """Канарейка: выход из лжецов принимает выдуманный адрес, прочие отвергают."""
    def ping(email, mx, proxy=None, **_k):
        if n.exit_ip_of(proxy) in лжецы:
            return {"status": "valid", "reason": "250 OK"}
        return dict(НЕТ_ЯЩИКА)
    n._do_single_ping = ping


def test_canary_catch_steers_the_domain_away():
    n = сеть()
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.valid("anna@" + DOM, P1)
    assert LIAR in n.caught_exits_on(DOM)
    assert n._pick_for_domain(DOM)[0] == P3


# ═══════════════════════════════════════════════ переспрос отозванных

def переспрос(n, ответ, позвали=None):
    def check_email(email, **_k):
        if позвали is not None:
            позвали.append(email)
        return dict(ответ, mx_records=list(MX))
    n.check_email = check_email


def test_revoked_valid_rechecked_through_honest_exit_survives():
    n = сеть()
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.valid("anna@" + DOM, P1)                 # «Годен» лжеца — до поимки
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == set()   # контроль
    позвали = []
    переспрос(n, {"status": "valid", "reason": "250 OK", "proxy": P3}, позвали)
    p._final_canaries([DOM])
    assert позвали == ["anna@" + DOM]
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == {"anna@" + DOM}
    assert any("Переспрошено" in строка for строка in p.logs)


def test_recheck_refusal_does_not_restore_valid():
    n = сеть()
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.valid("anna@" + DOM, P1)
    переспрос(n, dict(НЕТ_ЯЩИКА, proxy=P3))
    p._final_canaries([DOM])
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == set()


def test_recheck_through_unprofiled_exit_does_not_restore_valid():
    n = сеть()
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.valid("anna@" + DOM, P1)
    переспрос(n, {"status": "valid", "reason": "250 OK", "proxy": P4})
    p._final_canaries([DOM])
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == set()


def test_recheck_needs_second_opinion_when_it_is_on():
    n = сеть()
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.confirm_valid = True
    p.valid("anna@" + DOM, P1)
    переспрос(n, {"status": "valid", "reason": "250 OK", "proxy": P3})
    n.confirm_valid_from_other_exit = lambda *a, **k: False
    p._final_canaries([DOM])
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == set()
    # Контроль: второе мнение согласно — адрес уцелевает.
    n.confirm_valid_from_other_exit = lambda *a, **k: True
    p._final_canaries([DOM])
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == {"anna@" + DOM}


def test_recheck_exit_caught_by_its_own_canary_does_not_restore_valid():
    n = сеть()
    канарейка_по_выходу(n, {LIAR, HONEST})     # врёт и «честный»
    p = _Pipeline(n)
    p.valid("anna@" + DOM, P1)
    переспрос(n, {"status": "valid", "reason": "250 OK", "proxy": P3})
    p._final_canaries([DOM])
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == set()


def test_recheck_asks_the_address_as_written():
    n = сеть()
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.valid("Anna.Smith@" + DOM, P1)
    позвали = []
    переспрос(n, {"status": "valid", "reason": "250 OK", "proxy": P3}, позвали)
    p._final_canaries([DOM])
    assert позвали == ["Anna.Smith@" + DOM]
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == {"anna.smith@" + DOM}


def test_recheck_skips_spared_addresses_and_stop():
    n = сеть()
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.valid("bob@" + DOM, P3)                  # честный выход, проба после — уцелеет
    p.valid("anna@" + DOM, P1)
    позвали = []
    переспрос(n, {"status": "valid", "reason": "250 OK", "proxy": P3}, позвали)
    n.abort_event.set()
    p._final_canaries([DOM])
    assert позвали == []                       # «Стоп» — ни одной сессии
    n.abort_event.clear()
    p._final_canaries([DOM])
    assert позвали == ["anna@" + DOM]          # уцелевший не переспрашивается


@pytest.mark.parametrize("ответ", [
    {"status": "greylisted", "reason": "451 позже"},
    {"status": "unknown", "reason": "таймаут"},
    {"status": "valid", "reason": "250 OK", "proxy": P3, "aborted": True},
])
def test_recheck_without_a_clean_answer_does_not_restore_valid(ответ):
    n = сеть()
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.valid("anna@" + DOM, P1)
    переспрос(n, ответ)
    p._final_canaries([DOM])
    assert p._spared_valid([DOM], p.canary.lying_pairs()) == set()


# ═══════════════ переспрос через опору домена; сорвавшаяся завершающая проба

P5 = "socks5://198.51.100.5:1080"   # второй честный выход, с историей проб
HONEST2 = "203.0.113.88"


def test_recheck_goes_through_the_most_trusted_honest_exit():
    n = NetworkValidator(timeout=2, proxies=[P1, P3, P5])
    n.set_proxy_profiles({P1: {"exit_ip": LIAR}, P3: {"exit_ip": HONEST},
                          P5: {"exit_ip": HONEST2}})
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.canary = CanaryWatch(repeat=1)           # каждый «Годен» — своя проба
    p.valid("x@" + DOM, P3)                    # P3 честен до №1
    p.valid("y@" + DOM, P5)
    p.valid("z@" + DOM, P5)                    # P5 честен до №2 — опора
    p.valid("anna@" + DOM, P1)                 # лжец пойман
    просили = []

    def check_email(email, prefer_exit_of=None, **_k):
        просили.append(prefer_exit_of)
        return {"status": "valid", "reason": "250 OK", "proxy": prefer_exit_of or P3,
                "mx_records": list(MX)}

    n.check_email = check_email
    p._final_canaries([DOM])
    assert просили == [P5]
    assert "anna@" + DOM in p._spared_valid([DOM], p.canary.lying_pairs())


def test_recheck_without_trusted_exit_lets_the_pool_choose():
    n = сеть()
    канарейка_по_выходу(n, {LIAR})
    p = _Pipeline(n)
    p.valid("anna@" + DOM, P1)                 # кроме лжеца проб не было
    просили = []

    def check_email(email, prefer_exit_of=None, **_k):
        просили.append(prefer_exit_of)
        return {"status": "valid", "reason": "250 OK", "proxy": P3, "mx_records": list(MX)}

    n.check_email = check_email
    p._final_canaries([DOM])
    assert просили == [None]


def канарейка_с_ответами(n, ответы):
    """Канарейка честного выхода отвечает по очереди: 'сорвалась' или 'нет ящика'."""
    очередь = list(ответы)
    спрошено = []

    def ping(email, mx, proxy=None, **_k):
        спрошено.append(proxy)
        ответ = очередь.pop(0) if очередь else "нет ящика"
        if ответ == "сорвалась":
            return {"status": "unknown", "reason": "Timeout"}
        return dict(НЕТ_ЯЩИКА)

    n._do_single_ping = ping
    return спрошено


def test_failed_final_canary_is_retried_once():
    n = сеть()
    спрошено = канарейка_с_ответами(n, ["сорвалась", "сорвалась", "нет ящика"])
    p = _Pipeline(n)
    p.valid("anna@" + DOM, P3)                 # первая проба сорвалась
    assert p._final_canaries([DOM]) == 1
    assert len(спрошено) == 3                  # первая, завершающая, её повтор
    assert p._spared_valid([DOM], set()) == {"anna@" + DOM}


def test_final_canary_retry_is_bounded():
    n = сеть()
    спрошено = канарейка_с_ответами(n, ["сорвалась"] * 10)
    # Непокрытый адрес уйдёт в переспрос — ответ без сети, как в прочих тестах.
    переспрос(n, {"status": "unknown", "reason": "таймаут"})
    p = _Pipeline(n)
    p.valid("anna@" + DOM, P3)
    p._final_canaries([DOM])
    assert len(спрошено) == 3                  # один повтор, не до бесконечности
    assert p._spared_valid([DOM], set()) == set()
