# -*- coding: utf-8 -*-
"""Второе мнение о приговоре и два источника потерянных ответов.

Три находки, каждая проверена замером, а не рассуждением.

**Приговор подтверждался только другим MX.** У yandex.ru, mail.ru и почти
всей корпоративной почты MX ОДИН — подтверждать было нечем, и второе мнение
не спрашивалось вовсе. Вдобавок прокси для второго мнения выбирался обычным
способом, то есть мог оказаться тем же самым: адрес, отвергнутый ПО РЕПУТАЦИИ
нашего IP, сам себя и подтверждал. Отказ по репутации выглядит для нас точно
так же, как «ящика нет».

**Половина обратных адресов имела Null MX.** Замерено: у example.com,
example.net и example.org MX пустой (RFC 7505) — домен объявляет «почту не
принимаю». RFC 7505 §4 велит отвергать такого отправителя кодом 550. Gmail и
Яндекс их пропускают (тоже замерено), строгий сервер — нет, и тогда до
вопроса о ящике дело не доходит.

**Повтор после серого списка шёл через 90 секунд.** У postgrey выдержка по
умолчанию пять минут: повтор раньше неё получает тот же серый ответ.
"""
import inspect
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def validator(profiles=None, proxies=None):
    from core.network import NetworkValidator

    made = NetworkValidator(timeout=2, proxies=proxies or [])
    if profiles:
        made.set_proxy_profiles(profiles)
    return made


# ═══════════════════════════════ G1: второе мнение с другого выхода

def test_other_ip_confirms_when_the_domain_has_a_single_mx():
    """Домен с одним MX был слепой зоной: сверять было не с чем.

    Теперь второе мнение спрашивается у ТОГО ЖЕ сервера, но с другого
    выходного адреса — и этого достаточно, чтобы отличить «ящика нет» от
    «наш IP не нравится».
    """
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    asked = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        asked.append((mx, proxy))
        return {"status": "invalid", "reason": "550 нет ящика"}

    v._do_single_ping = fake_ping
    answer = v._confirm_invalid_on_other_mx(
        "user@single.example", "mx.single.example", ["mx.single.example"],
        False, False, "", deadline=float("inf"), first_proxy="a:1")

    assert answer is True, "второе мнение не спрошено"
    assert asked, "до второго запроса дело не дошло"
    assert asked[0][1] == "b:2", "спросили не у другого выхода: %s" % asked


def test_other_ip_disagreement_saves_the_address():
    """Второй выход принял адрес — хоронить нельзя."""
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    v._do_single_ping = lambda *a, **k: {"status": "valid", "reason": "250 OK"}
    answer = v._confirm_invalid_on_other_mx(
        "user@single.example", "mx.single.example", ["mx.single.example"],
        False, False, "", deadline=float("inf"), first_proxy="a:1")
    assert answer is False


def test_other_ip_still_prefers_another_server_when_there_is_one():
    """Две оси лучше одной: если второй MX есть, спрашиваем у него."""
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    asked = []
    v._do_single_ping = lambda email, mx, proxy=None, **k: (
        asked.append((mx, proxy)) or {"status": "invalid", "reason": "550"})
    v._confirm_invalid_on_other_mx(
        "user@big.example", "mx1.big.example",
        ["mx1.big.example", "mx2.big.example"],
        False, False, "", deadline=float("inf"), first_proxy="a:1")
    assert asked[0][0] == "mx2.big.example"
    assert asked[0][1] == "b:2"


def test_other_ip_reaches_the_verdict_path():
    """Прокси первого ответа действительно доезжает до подтверждения.

    Проверка именно связи: сам механизм можно написать безупречно и не
    подключить — так уже было со SMTPUTF8.
    """
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    assert "first_proxy=proxy" in source
    assert "avoid_exit_of=first_proxy" in source


# ═══════════════════════════════ G2: у себя же не спрашиваем

def test_same_ip_is_never_asked_for_a_second_opinion():
    """Прокси, отвергнутый по репутации, не подтверждает сам себя."""
    v = validator(proxies=["a:1", "a2:1"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "a2:1": {"exit_ip": "1.1.1.1"}})
    # Оба прокси делят ОДИН выходной адрес — для почтовика это один
    # отправитель, и второго мнения здесь взяться неоткуда.
    assert v._pick_best_proxy(avoid_exit_of="a:1") is None


def test_same_ip_means_no_confirmation_at_all():
    """Спросить не у кого — значит None, а не молчаливое согласие."""
    v = validator(proxies=["a:1", "a2:1"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "a2:1": {"exit_ip": "1.1.1.1"}})
    v._do_single_ping = lambda *a, **k: pytest.fail("полезли спрашивать у себя же")
    answer = v._confirm_invalid_on_other_mx(
        "user@single.example", "mx.single.example", ["mx.single.example"],
        False, False, "", deadline=float("inf"), first_proxy="a:1")
    assert answer is None


def test_same_ip_exclusion_is_by_exit_not_by_string():
    """Отсев идёт по ВЫХОДНОМУ адресу: десять входов в один выход — один IP."""
    v = validator(proxies=["a:1", "b:2", "c:3"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "1.1.1.1"},
                            "c:3": {"exit_ip": "9.9.9.9"}})
    for _ in range(20):
        assert v._pick_best_proxy(avoid_exit_of="a:1") == "c:3"


def test_same_ip_without_a_profile_falls_back_to_the_string():
    """Профиля нет — обходим хотя бы тот же самый прокси."""
    v = validator(proxies=["a:1", "b:2"])
    for _ in range(20):
        assert v._pick_best_proxy(avoid_exit_of="a:1") == "b:2"


# ═══════════════════════════════ G3: молчание ≠ согласие

def test_silence_of_the_second_opinion_is_not_agreement():
    """«Не дозвонились» не усиливает приговор.

    Выдать молчание за несогласие — значит похоронить адрес по двум ответам,
    из которых настоящий только один.
    """
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    for status in ("unknown", "greylisted", "risky"):
        v._do_single_ping = lambda *a, **k: {"status": status, "reason": "тишина"}
        answer = v._confirm_invalid_on_other_mx(
            "user@single.example", "mx.single.example", ["mx.single.example"],
            False, False, "", deadline=float("inf"), first_proxy="a:1")
        assert answer is None, status


def test_silence_after_the_deadline_is_not_agreement():
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    v._do_single_ping = lambda *a, **k: pytest.fail("полезли в сеть после дедлайна")
    answer = v._confirm_invalid_on_other_mx(
        "user@single.example", "mx.single.example", ["mx.single.example"],
        False, False, "", deadline=0.0, first_proxy="a:1")
    assert answer is None


def test_silence_leads_to_risky_not_invalid_when_answers_differ():
    """Расхождение ответов оставляет адрес живым и называет причину."""
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    assert "Второй ответ противоречит первому" in source
    block = source[source.index("Второй ответ противоречит первому") - 400:]
    block = block[:400]
    assert '"status": "risky"' in block


# ═══════════════════════════════ G4: подтверждение не транжирится

def test_thrift_confirmation_is_only_for_invalid():
    """На valid второе мнение не тратится: живой ящик уже доказан."""
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    order = source.index('if result["status"] == "valid":')
    confirm = source.index("_confirm_invalid_on_other_mx(")
    assert order < confirm, "подтверждение стоит раньше возврата valid"


def test_thrift_no_proxies_means_no_extra_session():
    """Без прокси второго выхода нет — и лишнего подключения тоже."""
    v = validator()
    v._do_single_ping = lambda *a, **k: pytest.fail("лишняя сессия без прокси")
    answer = v._confirm_invalid_on_other_mx(
        "user@single.example", "mx.single.example", ["mx.single.example"],
        False, False, "", deadline=float("inf"), first_proxy=None)
    assert answer is None


def test_thrift_single_mx_without_proxy_is_not_confirmed():
    """Ни другого сервера, ни другого выхода — сверять нечем, и мы не пытаемся."""
    v = validator()
    calls = []
    v._do_single_ping = lambda *a, **k: calls.append(1) or {"status": "invalid"}
    v._confirm_invalid_on_other_mx(
        "user@single.example", "mx.single.example", ["mx.single.example"],
        False, False, "", deadline=float("inf"), first_proxy=None)
    assert calls == []


# ═══════════════════════════════ G5: обратный адрес принимает почту

def test_sender_pool_has_no_null_mx_domains():
    """Домен, объявивший Null MX, не может быть нашим обратным адресом.

    RFC 7505 §4: такого отправителя сервер ДОЛЖЕН отвергнуть кодом 550, и
    тогда до вопроса о ящике дело не дойдёт вовсе.
    """
    from core.mail_constants import MAIL_FROM_POOL

    reserved = {"example.com", "example.net", "example.org", "example.edu",
                "invalid", "localhost", "test"}
    bad = [addr for addr in MAIL_FROM_POOL
           if addr.rsplit("@", 1)[-1].lower() in reserved]
    assert bad == [], "отправители с Null MX: %s" % bad


def test_sender_pool_is_still_a_rotation():
    """Ротация осталась ротацией: один адрес на всю базу — это подпись."""
    from core.mail_constants import MAIL_FROM_POOL

    assert len(MAIL_FROM_POOL) >= 4
    assert len(set(MAIL_FROM_POOL)) == len(MAIL_FROM_POOL)
    for addr in MAIL_FROM_POOL:
        assert "@" in addr and addr.rsplit("@", 1)[-1].count(".") >= 1


def test_sender_pool_domains_look_like_real_mailboxes():
    """Домены пула — настоящие почтовики, а не выдумка.

    Список сверяется с известными: если однажды сюда попадёт домен без
    почты, проверка это покажет, не выходя в сеть.
    """
    from core.mail_constants import MAIL_FROM_POOL

    known = {"mail.com", "email.com", "usa.com", "gmx.com", "post.com",
             "writeme.com", "consultant.com", "inbox.com"}
    unknown = [addr for addr in MAIL_FROM_POOL
               if addr.rsplit("@", 1)[-1].lower() not in known]
    assert unknown == [], "домен вне проверенного списка: %s" % unknown


# ═══════════════════════════════ G6: выдержка серых списков

def test_greylist_delay_is_long_enough_to_matter():
    """У postgrey выдержка пять минут; повтор раньше неё бесполезен."""
    from core.runstate import GREYLIST_RETRY_DELAY

    assert GREYLIST_RETRY_DELAY >= 300, GREYLIST_RETRY_DELAY


def test_greylist_delay_is_separate_from_the_transient_one():
    """Временный сбой и серый список — разные вещи и разные выдержки.

    Смешать их значит либо тормозить повтор после таймаута, либо не
    дожидаться выдержки серого списка.
    """
    from core.runstate import DEFAULT_RETRY_DELAY, GREYLIST_RETRY_DELAY

    assert GREYLIST_RETRY_DELAY > DEFAULT_RETRY_DELAY
    assert DEFAULT_RETRY_DELAY <= 120, "повтор после сбоя стал слишком долгим"


def test_greylist_delay_is_actually_used_by_the_pipeline():
    """Константа, которую никто не передаёт, ничего не меняет."""
    source = inspect.getsource(__import__("core.pipeline", fromlist=["x"]))
    assert "delay=GREYLIST_RETRY_DELAY" in source
    # А временный сбой по-прежнему уходит с обычной выдержкой. Якорь берётся
    # по ВЫЗОВУ, а не по определению функции: имя встречается дважды, и
    # первое вхождение — это её объявление далеко от нужного места.
    block = source[source.index("if _is_transient_failure(raw_status"):]
    block = block[:400]
    assert "defer(email, data, is_role)" in block
