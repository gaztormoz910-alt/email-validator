# -*- coding: utf-8 -*-
import datetime
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import dns.resolver
import pytest

import core.cache as cache_module
from core.dns_resolver import DNSUnavailable, UnverifiedNXDOMAIN
from core.network import NetworkValidator
from core.runstate import run_id_for
from core.settle import SettleMixin
from tests.test_audit6_fixes import (Принимает, Сценарий, _Обработчик, _Сервер,
                                     валидатор, прогон)


@pytest.fixture
def поднять():
    import threading
    серверы = []

    def сделать(сценарий):
        сервер = _Сервер(("127.0.0.1", 0), _Обработчик)
        сервер.сценарий = сценарий
        threading.Thread(target=сервер.serve_forever, daemon=True).start()
        серверы.append(сервер)
        return сервер.server_address[1]

    yield сделать
    for сервер in серверы:
        сервер.shutdown()
        сервер.server_close()


def _через(monkeypatch, дней):
    сейчас = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=дней)
    monkeypatch.setattr(cache_module, "_utc_now", lambda: сейчас)


def test_valid_from_cache_lives_seven_days(monkeypatch, tmp_path):
    c = cache_module.ResultCache(path=str(tmp_path / "c.sqlite"))
    assert c.ttl_valid_days == 7 and c.ttl_invalid_days == 90
    c.put("anna.ivanova@corpmail.ru", "Valid", "250 OK", "mx.corpmail.ru", {})
    c.put("petr.nosuch@corpmail.ru", "Invalid/Bounce", "550 5.1.1 Получателя не существует",
          "mx.corpmail.ru", {})
    _через(monkeypatch, 6)
    assert c.get("anna.ivanova@corpmail.ru")["status"] == "Valid"
    _через(monkeypatch, 8)
    assert c.get("anna.ivanova@corpmail.ru") is None
    _через(monkeypatch, 60)
    assert c.get("petr.nosuch@corpmail.ru")["status"] == "Invalid/Bounce"
    c.close()


class _Резолвер:
    def __init__(self, заверенный):
        self.заверенный = заверенный
        self.заверяли = []

    def resolve(self, qname, rdtype="A"):
        raise UnverifiedNXDOMAIN()

    def resolve_verified(self, qname, rdtype="A", proxies=8):
        self.заверяли.append((qname, rdtype))
        if isinstance(self.заверенный, BaseException) or (
                isinstance(self.заверенный, type) and issubclass(self.заверенный, BaseException)):
            raise self.заверенный
        return self.заверенный


@pytest.mark.настоящий_mx_hosts_alive
@pytest.mark.parametrize("заверенный, итог", [
    (dns.resolver.NXDOMAIN(), False),
    (UnverifiedNXDOMAIN(), None),
    (DNSUnavailable("нет DoH"), None),
    (["192.0.2.25"], True),
])
def test_unverified_mx_host_nxdomain_is_confirmed_by_doh(заверенный, итог):
    n = NetworkValidator(proxies=[])
    n.resolver = _Резолвер(заверенный)
    assert n.mx_hosts_alive(["old-firm-ru.mail.protection.outlook.com"]) is итог
    assert n.resolver.заверяли[0] == ("old-firm-ru.mail.protection.outlook.com", "A")


@pytest.mark.настоящий_mx_hosts_alive
def test_resolver_without_doh_keeps_unknown():
    class Старый:
        def resolve(self, qname, rdtype="A"):
            raise UnverifiedNXDOMAIN()

    n = NetworkValidator(proxies=[])
    n.resolver = Старый()
    assert n.mx_hosts_alive(["mx.old-firm.ru"]) is None


def test_trap_word_dead_mailbox_is_invalid_not_trap(monkeypatch, поднять):
    v = валидатор(monkeypatch, поднять(Принимает("anna.ivanova")))
    итог = прогон(monkeypatch, v, ["spamtrap@trapfirm.ru"])
    assert итог["spamtrap@trapfirm.ru"][0] == "Invalid/Bounce"


def test_trap_word_live_mailbox_is_still_a_trap(monkeypatch, поднять):
    сервер = Принимает("spamtrap")
    v = валидатор(monkeypatch, поднять(сервер))
    итог = прогон(monkeypatch, v, ["spamtrap@trapfirm.ru"])
    статус, причина, _ = итог["spamtrap@trapfirm.ru"]
    assert статус == "Trap/Disposable" and "spamtrap" in причина and "сервер:" in причина
    assert any(z.startswith("RCPT spamtrap@") for z in сервер.журнал)


def test_trap_word_catchall_server_is_a_trap(monkeypatch, поднять):
    v = валидатор(monkeypatch, поднять(Сценарий()))
    итог = прогон(monkeypatch, v, ["honeypot@trapfirm.ru"])
    assert итог["honeypot@trapfirm.ru"][0] == "Trap/Disposable"


def test_ordinary_name_with_trap_letters_is_not_touched(monkeypatch, поднять):
    v = валидатор(monkeypatch, поднять(Принимает("trapeznikov")))
    итог = прогон(monkeypatch, v, ["trapeznikov@trapfirm.ru"])
    assert итог["trapeznikov@trapfirm.ru"][0] == "Valid"


class _Лестница(SettleMixin):
    def __init__(self):
        self.выдано = []

    def _emit_trap(self, email, data, reason, provider_type, basis_status, enable_ai, mx="N/A"):
        self.выдано.append(("Trap/Disposable", reason))

    def _emit(self, email, status, reason, mx, data):
        self.выдано.append((status, reason))


def test_without_deep_check_the_trap_is_immediate():
    p = _Лестница()
    данные = {}
    assert p._trap_by_name("spamtrap@trapfirm.ru", данные, False, deep_ping=False) is True
    assert p.выдано and p.выдано[0][0] == "Trap/Disposable" and "trap_word" not in данные


def test_with_deep_check_the_word_waits_for_the_server():
    p = _Лестница()
    данные = {}
    assert p._trap_by_name("spamtrap@trapfirm.ru", данные, False, deep_ping=True) is False
    assert данные["trap_word"] == "spamtrap" and p.выдано == []


def test_unanswered_trap_word_stays_a_trap_at_the_end():
    p = _Лестница()
    p._emit_unresolved("spamtrap@trapfirm.ru", "Timeout", {"trap_word": "spamtrap"}, False)
    p._emit_unresolved("anna@trapfirm.ru", "Timeout", {}, False)
    assert [s for s, _ in p.выдано] == ["Trap/Disposable", "Unknown"]


def test_journal_key_changes_when_a_same_size_file_is_replaced(tmp_path):
    файл = tmp_path / "base.txt"
    файл.write_bytes(b"anna@corpmail.ru\n")
    os.utime(файл, ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000))
    первый = run_id_for([{"path": str(файл)}])
    assert run_id_for([{"path": str(файл)}]) == первый
    файл.write_bytes(b"petr@corpmail.ru\n")
    os.utime(файл, ns=(1_700_000_100_000_000_000, 1_700_000_100_000_000_000))
    assert os.path.getsize(файл) == len("anna@corpmail.ru\n")
    assert run_id_for([{"path": str(файл)}]) != первый


def _конвейер(monkeypatch, сеть, кэш=None):
    import core.pipeline as pipeline_module
    выдано = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: выдано.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = сеть
    pipe.cache = кэш
    pipe.filter = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    pipe._enrich_offline = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)
    return pipe, выдано


def test_cached_valid_is_not_used_for_a_trap_word(monkeypatch):
    from tests.test_third_pass import FakeNetwork

    class Кэш:
        def get(self, email):
            return {"status": "Valid", "reason": "250 OK", "mx": "mx.test",
                    "data": {}, "checked_at": "2026-11-20T00:00:00+00:00", "age_days": 2}

        def close(self):
            pass

    сеть = FakeNetwork({"status": "valid", "reason": "250 OK", "mx_record": "mx.test"})
    pipe, выдано = _конвейер(monkeypatch, сеть, Кэш())
    pipe.run_pipeline([{"type": "text", "content": "spamtrap@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=True,
                      deep_ping=True, enable_ai=False, enable_osint=False, resume=False)
    assert сеть.calls, "сервер не спрошен — ответ взят из кэша"
    assert выдано and выдано[0][1] == "Trap/Disposable", выдано


def test_stopped_before_the_server_answered_stays_a_trap(monkeypatch):
    from tests.test_third_pass import REPUTATION, FakeNetwork

    pipe = None

    class СтопПослеПервого(FakeNetwork):
        def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
            ответ = FakeNetwork.check_email(self, email, avoid_exit_of)
            pipe.is_running = False
            return ответ

    сеть = СтопПослеПервого({"status": "unknown", "reason": REPUTATION,
                             "mx_record": "mx.test", "proxy": "socks5://dirty:1"})
    pipe, выдано = _конвейер(monkeypatch, сеть)
    pipe.run_pipeline([{"type": "text", "content": "spamtrap@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=True,
                      deep_ping=True, enable_ai=False, enable_osint=False, resume=False)
    assert выдано and выдано[0][1] == "Trap/Disposable", выдано
    assert "так и не ответил" in выдано[0][2]
