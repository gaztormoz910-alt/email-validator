# -*- coding: utf-8 -*-
import os
import smtplib
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.network as network_module
import core.pipeline as pipeline_module
from core.behind_gateway import M365_SUFFIX, m365_hosts_for
from tests.test_audit6_fixes import Сценарий, _Обработчик, _Сервер

ДОМЕН = "gw-firm.ru"
ШЛЮЗ = "mx1.gw-firm.pphosted.com"
УЗЕЛ = "gw-firm-ru." + M365_SUFFIX
DBEB = (550, "5.4.1 Recipient address rejected: Access denied. AS(201806281)")


class Microsoft(Сценарий):

    def __init__(self, *живые, всех=False, никого=False):
        Сценарий.__init__(self)
        self.живые, self.всех, self.никого = set(живые) | {"postmaster", "abuse"}, всех, никого

    def rcpt(self, отправитель, получатель, сессия):
        if self.никого:
            return 550, "5.7.51 TenantInboundAttribution; Rejecting. Not from your gateway"
        if self.всех or получатель.split("@")[0] in self.живые:
            return 250, "2.1.5 Recipient OK"
        return DBEB


@pytest.fixture
def поднять():
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


def валидатор(monkeypatch, порты, живые_узлы=(УЗЕЛ,)):
    monkeypatch.setattr(network_module, "filter_mx_hosts",
                        lambda hosts, resolve=None: (list(hosts), []))
    v = network_module.NetworkValidator(timeout=5)
    v.memory = None
    спрошенные_узлы = []

    class Туда(smtplib.SMTP):
        def connect(self, host="localhost", port=0, source_address=None):
            return smtplib.SMTP.connect(self, "127.0.0.1", порты[host])

    v._make_smtp_connection = lambda proxy=None: Туда(timeout=v.timeout)
    v.get_mx_records = lambda domain: [ШЛЮЗ]
    v.check_dns_health = lambda domain, mx_record="": {
        "score": 0, "has_spf": False, "has_dmarc": False, "has_dkim": False}
    v.country_for_domain = lambda domain, mx_host="": ""
    v._mx_delay = lambda mx_host: 0.0

    def жив(hosts):
        спрошенные_узлы.extend(hosts)
        return all(h in живые_узлы for h in hosts)

    v.mx_hosts_alive = жив
    v.спрошенные_узлы = спрошенные_узлы
    return v


def test_host_names():
    assert m365_hosts_for("Contoso.COM") == ["contoso-com." + M365_SUFFIX]
    assert m365_hosts_for("a.b.co.uk") == ["a-b-co-uk." + M365_SUFFIX]
    assert m365_hosts_for("my-firm.com") == ["my-firm-com." + M365_SUFFIX,
                                             "myfirm-com." + M365_SUFFIX]
    for мусор in ("", "localhost", "[192.0.2.1]", "пример.рф", "a..b", None):
        assert m365_hosts_for(мусор) == []


def test_gateway_catchall_becomes_valid_when_m365_knows_the_mailbox(monkeypatch, поднять):
    шлюз, ms = Сценарий(), Microsoft("anna.ivanova")
    v = валидатор(monkeypatch, {ШЛЮЗ: поднять(шлюз), УЗЕЛ: поднять(ms)})
    итог = v.check_email("Anna.Ivanova@" + ДОМЕН)
    assert итог["status"] == "valid", итог
    assert итог["mx_record"] == УЗЕЛ and итог["mx_records"] == [УЗЕЛ]
    assert "Proofpoint" in итог["reason"] and итог["behind_gateway"] == "Proofpoint"
    rcpt = [z for z in ms.журнал if z.startswith("RCPT")]
    assert len(rcpt) == 2 and rcpt[0].startswith("RCPT anna.ivanova@") and rcpt[1].endswith(" 550")
    assert "anna.ivanova@" + ДОМЕН in v.behind_gateway_valid()
    assert ДОМЕН in v.behind_gateway_domains()


def test_m365_rejection_is_never_a_verdict(monkeypatch, поднять):
    v = валидатор(monkeypatch, {ШЛЮЗ: поднять(Сценарий()), УЗЕЛ: поднять(Microsoft())})
    итог = v.check_email("petr.sidorov@" + ДОМЕН)
    assert итог["status"] == "catchall"
    assert "не приговор" in итог["reason"]
    assert not v.behind_gateway_valid()


def test_m365_that_accepts_everything_proves_nothing(monkeypatch, поднять):
    v = валидатор(monkeypatch, {ШЛЮЗ: поднять(Сценарий()), УЗЕЛ: поднять(Microsoft(всех=True))})
    assert v.check_email("anna.ivanova@" + ДОМЕН)["status"] == "catchall"
    assert not v.behind_gateway_valid()


def test_m365_closed_to_everyone_but_the_gateway(monkeypatch, поднять):
    v = валидатор(monkeypatch, {ШЛЮЗ: поднять(Сценарий()), УЗЕЛ: поднять(Microsoft(никого=True))})
    итог = v.check_email("anna.ivanova@" + ДОМЕН)
    assert итог["status"] == "catchall" and "не приговор" not in итог["reason"]


def test_no_m365_host_no_session(monkeypatch, поднять):
    ms = Microsoft("anna.ivanova")
    v = валидатор(monkeypatch, {ШЛЮЗ: поднять(Сценарий()), УЗЕЛ: поднять(ms)}, живые_узлы=())
    assert v.check_email("anna.ivanova@" + ДОМЕН)["status"] == "catchall"
    assert УЗЕЛ in v.спрошенные_узлы and ms.журнал == []


def test_honest_gateway_is_not_bypassed(monkeypatch, поднять):
    class ЧестныйШлюз(Сценарий):
        def rcpt(self, отправитель, получатель, сессия):
            if получатель.split("@")[0] in ("anna.ivanova", "postmaster", "abuse"):
                return 250, "2.1.5 Ok"
            return 550, "5.1.1 User unknown"

    ms = Microsoft("anna.ivanova")
    v = валидатор(monkeypatch, {ШЛЮЗ: поднять(ЧестныйШлюз()), УЗЕЛ: поднять(ms)})
    итог = v.check_email("anna.ivanova@" + ДОМЕН)
    assert итог["status"] == "valid" and итог["mx_record"] == ШЛЮЗ
    assert ms.журнал == [] and not v.behind_gateway_valid()


def test_with_proxies_a_clean_exit_is_required(monkeypatch):
    v = network_module.NetworkValidator(timeout=2, proxies=["socks5://198.51.100.9:1080"])
    v.mx_hosts_alive = lambda hosts: True
    спрошено = []
    v._pick_for_domain = lambda domain, need_ptr, need_clean, want, avoid: (
        спрошено.append(need_clean) or None, False)
    v._probe_recipients = lambda *a, **k: pytest.fail("без чистого выхода сессии нет")
    res = {"status": "catchall", "reason": "Catch-All: почтовый шлюз Proofpoint принимает любой адрес"}
    assert v._ask_behind_gateway(ДОМЕН, "anna@" + ДОМЕН, res, "Proofpoint") is res
    assert спрошено == [True]


def test_catchall_revision_spares_m365_proven_valid(monkeypatch, поднять):
    шлюз, ms = Сценарий(), Microsoft("anna.ivanova")
    v = валидатор(monkeypatch, {ШЛЮЗ: поднять(шлюз), УЗЕЛ: поднять(ms)})
    итог = {}

    def on_result(email, status, reason, mx_, data):
        итог[email] = [status, reason]

    def on_revise(domains, new_status, note, spare=None):
        n = 0
        for email, (status, reason) in list(итог.items()):
            if spare and email.lower() in spare:
                continue
            if status == "Valid" and any(email.endswith("@" + d) for d in domains):
                итог[email] = [new_status or status, reason + " | " + note]
                n += 1
        return n

    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)
    monkeypatch.setattr(pipeline_module, "GREYLIST_RETRY_DELAY", 0.0)
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **k: None, "on_result": on_result,
        "on_progress": lambda *a: None, "on_complete": lambda: None,
        "on_revise": on_revise})
    pipe.network = v
    pipe.cache = None
    pipe.filter = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **k: None
    pipe._enrich_offline = lambda *a, **k: None
    адреса = ["anna.ivanova@" + ДОМЕН, "petr.sidorov@" + ДОМЕН]
    pipe.run_pipeline([{"type": "text", "content": "\n".join(адреса)}], threads=1,
                      fix_typos=False, check_spam=True, deep_ping=True,
                      enable_ai=False, enable_osint=False, resume=False)
    assert ДОМЕН in v.proven_catchall_domains()
    assert итог["anna.ivanova@" + ДОМЕН][0] == "Valid", итог
    assert итог["petr.sidorov@" + ДОМЕН][0] == "Unknown", итог
