# -*- coding: utf-8 -*-
"""Исправления по аудиту 27.09.2026: ложные «Годен» закрыты и не вернутся.

Каждый тест здесь написан против поведения, которое аудит ВОСПРОИЗВЁЛ на
настоящем коде (.unlazy/audit6/АУДИТ.md, сценарии R1–R8), и падает на коде
до исправления. Рядом с каждым правилом стоит контроль, на котором правило
срабатывать НЕ должно: иначе «исправление» могло бы оказаться простым
отключением проверки.

Почтовый сервер здесь поддельный и живёт на 127.0.0.1: SMTP-диалог,
контрольная проба, тройная проба catch-all, VRFY, канарейка и круг
перепроверки — настоящие, подменены только адрес соединения и ответ DNS.
"""
import os
import smtplib
import socketserver
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.network as network_module          # noqa: E402
import core.pipeline as pipeline_module        # noqa: E402
from core.smtp_codes import classify_smtp_response   # noqa: E402

НЕТ_ЯЩИКА = (550, "5.1.1 The email account that you tried to reach does not exist.")


# ═══════════════════════════════════════════ поддельный почтовый сервер

class Сценарий(object):
    """Что отвечает сервер. rcpt(отправитель, получатель, сессия) -> (код, текст)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.журнал = []

    def rcpt(self, отправитель, получатель, сессия):
        return 250, "2.1.5 Ok"

    def vrfy(self, адрес):
        return 502, "5.5.1 VRFY command is disabled"


class _Обработчик(socketserver.StreamRequestHandler):
    def _ответ(self, код, текст):
        self.wfile.write(("%d %s\r\n" % (код, текст)).encode("utf-8"))
        self.wfile.flush()

    def handle(self):
        сц = self.server.сценарий
        сессия = {"rcpt_count": 0, "sender": ""}
        self._ответ(220, "mx.audit-fake.net ESMTP")
        while True:
            try:
                сырая = self.rfile.readline(4096)
            except OSError:
                return
            if not сырая:
                return
            строка = сырая.decode("utf-8", "replace").strip()
            верх = строка.upper()
            if верх.startswith("EHLO"):
                self.wfile.write(b"250-mx.audit-fake.net\r\n250 SIZE 10240000\r\n")
                self.wfile.flush()
            elif верх.startswith("HELO"):
                self._ответ(250, "mx.audit-fake.net")
            elif верх.startswith("MAIL FROM"):
                сессия["sender"] = строка.split(":", 1)[1].strip().strip("<>").split(">")[0]
                сессия["rcpt_count"] = 0
                self._ответ(250, "2.1.0 Ok")
            elif верх.startswith("RCPT TO"):
                адрес = строка.split(":", 1)[1].strip()
                адрес = адрес[адрес.find("<") + 1:адрес.find(">")] if "<" in адрес else адрес
                сессия["rcpt_count"] += 1
                код, текст = сц.rcpt(сессия["sender"], адрес.lower(), сессия)
                with сц.lock:
                    сц.журнал.append("RCPT %s %d" % (адрес.lower(), код))
                self._ответ(код, текст)
            elif верх.startswith("VRFY"):
                адрес = строка[4:].strip().strip("<>").lower()
                код, текст = сц.vrfy(адрес)
                with сц.lock:
                    сц.журнал.append("VRFY %s %d" % (адрес, код))
                self._ответ(код, текст)
            elif верх.startswith("QUIT"):
                self._ответ(221, "2.0.0 Bye")
                return
            else:
                self._ответ(250, "2.0.0 Ok")


class _Сервер(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


@pytest.fixture
def поднять():
    """Фабрика серверов; все закрываются после теста."""
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


def валидатор(monkeypatch, порт, mx="mx.audit-fake.net"):
    """Настоящий NetworkValidator, которому подменены только TCP и DNS."""
    monkeypatch.setattr(network_module, "filter_mx_hosts",
                        lambda hosts, resolve=None: (list(hosts), []))
    v = network_module.NetworkValidator(timeout=5)
    v.memory = None

    class Туда(smtplib.SMTP):
        def connect(self, host="localhost", port=0, source_address=None):
            return smtplib.SMTP.connect(self, "127.0.0.1", порт)

    v._make_smtp_connection = lambda proxy=None: Туда(timeout=v.timeout)
    v.get_mx_records = lambda domain: [mx]
    v.check_dns_health = lambda domain, mx_record="": {
        "score": 0, "has_spf": False, "has_dmarc": False, "has_dkim": False}
    v.country_for_domain = lambda domain, mx_host="": ""
    v._mx_delay = lambda mx_host: 0.0
    return v


def прогон(monkeypatch, v, адреса, fix_typos=False):
    """Весь конвейер на адресах. {адрес: (статус, причина, данные)} после пересмотра."""
    итог = {}

    def on_result(email, status, reason, mx_, data):
        итог[email] = [status, reason, dict(data)]

    def on_revise(domains, new_status, note):
        n = 0
        for email, (status, reason, data) in list(итог.items()):
            if status == "Valid" and any(email.endswith("@" + d) for d in domains):
                итог[email] = [new_status or status, reason + " | " + note, data]
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
    pipe.run_pipeline([{"type": "text", "content": "\n".join(адреса)}], threads=2,
                      fix_typos=fix_typos, check_spam=True, deep_ping=True,
                      enable_ai=False, enable_osint=False, resume=False)
    return {k: tuple(v_) for k, v_ in итог.items()}


class Принимает(Сценарий):
    """Честный сервер: живы только названные имена (плюс postmaster и abuse)."""

    def __init__(self, *живые):
        Сценарий.__init__(self)
        self.живые = set(живые) | {"postmaster", "abuse"}

    def rcpt(self, отправитель, получатель, сессия):
        if получатель.split("@")[0] in self.живые:
            return 250, "2.1.5 Ok"
        return НЕТ_ЯЩИКА


class ЛовецЗаСерымСписком(Сценарий):
    """postgrey + catch-all: новая пара «отправитель, получатель» — 450, повтор — 250."""

    def __init__(self, честный=False):
        Сценарий.__init__(self)
        self.видел = set()
        self.честный = честный

    def rcpt(self, отправитель, получатель, сессия):
        with self.lock:
            новый = (отправитель, получатель) not in self.видел
            self.видел.add((отправитель, получатель))
        if новый:
            return 450, "4.2.0 <%s>: Recipient address rejected: Greylisted" % получатель
        if self.честный and получатель.split("@")[0] not in ("anna.ivanova", "postmaster", "abuse"):
            return НЕТ_ЯЩИКА
        return 250, "2.1.5 Ok"


class ОдинПолучатель(Сценарий):
    """catch-all, не пускающий второй RCPT в сессию."""

    def rcpt(self, отправитель, получатель, сессия):
        if сессия["rcpt_count"] > 1:
            return 452, "4.5.3 Error: too many recipients"
        return 250, "2.1.5 Ok"


# ═════════════════════════════ D1, D11, D6, D12, D13: разбор ответов серверов

@pytest.mark.parametrize("code,text", [
    (452, "4.2.2 The recipient's inbox is out of storage space."),
    (552, "5.2.2 The recipient's inbox is out of storage space and inactive."),
    (552, "5.2.2 Mailbox size limit exceeded"),
    (452, "4.2.2 Mailbox full"),
])
def test_full_mailbox_is_never_valid(code, text):
    """Переполненный ящик: письмо не дойдёт. Раньше это был «Годен» с +70."""
    verdict = classify_smtp_response(code, text)
    assert verdict["status"] == "full", verdict
    assert "переполнен" in verdict["reason"]


def test_server_storage_is_still_not_about_the_mailbox():
    """Контроль: место кончилось на СЕРВЕРЕ — это не «ящик переполнен»."""
    verdict = classify_smtp_response(452, "4.3.1 Insufficient system storage")
    assert verdict["status"] == "unknown"


def test_gmail_inactive_account_is_disabled():
    verdict = classify_smtp_response(
        550, "5.2.1 The email account that you tried to reach is inactive.")
    assert verdict["status"] == "disabled"


def test_recipient_rate_limit_is_not_disabled():
    """Gmail пишет лимит приёма тем же 5.2.1 — ящик живой, а не отключён."""
    verdict = classify_smtp_response(
        550, "5.2.1 The user you are trying to contact is receiving email at a "
             "rate that prevents additional messages.")
    assert verdict["status"] == "unknown"
    assert "лимит приёма" in verdict["reason"]


def test_microsoft_365_directory_block_means_no_mailbox():
    verdict = classify_smtp_response(
        550, "5.4.1 Recipient address rejected: Access denied. AS(201806281)")
    assert verdict["status"] == "invalid"


def test_same_phrase_under_policy_code_is_not_a_verdict():
    """Контроль: у Postfix «Access denied» приходит с 5.7.1 — это политика."""
    verdict = classify_smtp_response(
        554, "5.7.1 <x@corp.ru>: Recipient address rejected: Access denied")
    assert verdict["status"] == "unknown"


def test_no_ptr_is_not_greylisting_and_is_not_retried():
    verdict = classify_smtp_response(
        451, "4.7.23 The sending IP address for this message doesn't have a PTR record.")
    assert verdict["status"] == "unknown"
    assert "обратного DNS" in verdict["reason"]
    # Повтор тем же выходом бессмыслен — адрес не уходит ждать семь минут.
    assert not pipeline_module._is_transient_failure(verdict["status"], verdict["reason"])


def test_banned_sending_ip_is_named_reputation_not_sender():
    verdict = classify_smtp_response(
        550, "5.7.606 Access denied, banned sending IP [203.0.113.7]. To request "
             "removal from this list please visit https://sender.office.com/")
    assert verdict["status"] == "unknown"
    assert "репутации" in verdict["reason"]


def test_aol_digit_first_is_named_as_first_character():
    from core.local_rules import check_local_part
    _verdict, reason = check_local_part("1ivan@aol.com")
    # Слово «начинается» есть и в общей подсказке правила, поэтому
    # проверяется сама причина: первый символ, а не «недопустимые символы».
    assert reason.startswith("AOL: имя начинается символом"), reason
    assert "недопустимые" not in reason, reason


# ═══════════════════════════ D2, D3, D10: «Годен» только при исключённом catch-all

def test_catchall_behind_greylisting_is_caught_on_retry(monkeypatch, поднять):
    """Аудит R2: раньше выдуманный адрес получал «Годен»."""
    v = валидатор(monkeypatch, поднять(ЛовецЗаСерымСписком()))
    первый = v.check_email("nobody.realname7@grey-catchall.ru")
    assert первый["status"] == "greylisted"
    второй = v.check_email("nobody.realname7@grey-catchall.ru")
    assert второй["status"] == "catchall", второй


def test_honest_greylisted_server_still_confirms_on_retry(monkeypatch, поднять):
    """Контроль: серый список на ЧЕСТНОМ сервере не мешает «Годен» на повторе."""
    v = валидатор(monkeypatch, поднять(ЛовецЗаСерымСписком(честный=True)))
    assert v.check_email("anna.ivanova@grey-honest.ru")["status"] == "greylisted"
    assert v.check_email("anna.ivanova@grey-honest.ru")["status"] == "valid"


def test_catchall_hiding_behind_one_recipient_per_session(monkeypatch, поднять):
    """Аудит R4: контроль в той же сессии получал 452 и молчал."""
    v = валидатор(monkeypatch, поднять(ОдинПолучатель()))
    assert v.check_email("nobody.realname7@onercpt.ru")["status"] == "catchall"


def test_session_limit_550_is_not_proof_of_honesty(monkeypatch, поднять):
    """«550 5.5.3 Too many recipients» на второй RCPT — не отказ выдуманному.

    Разбор ответов читает его как голый отказ, и засчитать его как «сервер
    отверг выдуманный адрес» значило бы выдать «Годен» на catch-all. Тот же
    ответ в тройной пробе раньше записывал домен в «не catch-all» на месяц.
    """
    class ЛимитПятьсот(Сценарий):
        def rcpt(self, отправитель, получатель, сессия):
            if сессия["rcpt_count"] > 1:
                return 550, "5.5.3 Too many recipients"
            return 250, "2.1.5 Ok"

    v = валидатор(monkeypatch, поднять(ЛимитПятьсот()))
    assert v.check_email("nobody.realname7@limit550.ru")["status"] == "catchall"


def test_rejects_fake_rules():
    from core.confirmation import rejects_fake
    assert rejects_fake(classify_smtp_response(550, "5.1.1 User unknown"))
    assert rejects_fake(classify_smtp_response(550, "Rejected"))
    assert not rejects_fake(classify_smtp_response(550, "5.5.3 Too many recipients"))
    assert not rejects_fake(classify_smtp_response(450, "4.2.0 Greylisted"))
    assert not rejects_fake(classify_smtp_response(550, "5.7.1 Service unavailable, Client host blocked"))


def test_control_that_never_answers_gives_unconfirmed(monkeypatch, поднять):
    """Выдуманный адрес всё время получает «позже» — «Годен» недоказуем."""
    class Молчит(Сценарий):
        def rcpt(self, отправитель, получатель, сессия):
            if получатель.startswith("anna.ivanova@"):
                return 250, "2.1.5 Ok"
            return 450, "4.7.1 Try again later"

    v = валидатор(monkeypatch, поднять(Молчит()))
    assert v.check_email("anna.ivanova@silent.ru")["status"] == "unconfirmed"


def test_vrfy_answer_is_checked_with_vrfy(monkeypatch, поднять):
    """Аудит R5: отказ по RCPT «подтверждал» ответ VRFY."""
    class VrfyВсем(Сценарий):
        def rcpt(self, отправитель, получатель, сессия):
            return 550, "5.7.1 <%s>: Recipient address rejected: Access denied" % получатель

        def vrfy(self, адрес):
            return 250, "2.1.5 <%s>" % адрес

    v = валидатор(monkeypatch, поднять(VrfyВсем()))
    assert v.check_email("nobody.realname7@vrfy.ru")["status"] == "catchall"


def test_honest_server_is_confirmed_in_one_session(monkeypatch, поднять):
    """Контроль: обычный честный сервер даёт «Годен» без лишних сессий."""
    сценарий = Принимает("anna.ivanova")
    v = валидатор(monkeypatch, поднять(сценарий))
    итог = v.check_email("anna.ivanova@honest.ru")
    assert итог["status"] == "valid"
    assert итог.get("control_rcpt") == "rejected"


def test_retry_pass_calls_canary_and_second_opinion(monkeypatch, поднять):
    """Аудит D3: «Годен» из круга перепроверки получает те же две защиты.

    Честный сервер с серым списком: в основном проходе адрес ждёт выдержки,
    «Годен» он получает уже в круге перепроверки — и там обязаны вызываться
    и второе мнение, и канарейка. До исправления не вызывалось ни то, ни другое.
    """
    v = валидатор(monkeypatch, поднять(ЛовецЗаСерымСписком(честный=True)))
    вызовы = {"канарейка": [], "второе мнение": []}
    monkeypatch.setattr(pipeline_module.ValidationPipeline, "_fly_canary",
                        lambda self, email, res: вызовы["канарейка"].append(email))
    monkeypatch.setattr(pipeline_module.ValidationPipeline, "_second_opinion_on_valid",
                        lambda self, email, res: вызовы["второе мнение"].append(email))
    итог = прогон(monkeypatch, v, ["anna.ivanova@grey-honest-retry.ru"])
    assert итог["anna.ivanova@grey-honest-retry.ru"][0] == "Valid"
    assert вызовы["канарейка"] == ["anna.ivanova@grey-honest-retry.ru"]
    assert вызовы["второе мнение"] == ["anna.ivanova@grey-honest-retry.ru"]


def test_one_recipient_catchall_through_retry_is_not_valid(monkeypatch, поднять):
    """Аудит R4 через круг перепроверки: раньше выдуманный адрес получал «Годен»."""
    class СбойВпервые(ОдинПолучатель):
        def __init__(self):
            ОдинПолучатель.__init__(self)
            self.видел = set()

        def rcpt(self, отправитель, получатель, сессия):
            with self.lock:
                новый = получатель not in self.видел
                self.видел.add(получатель)
            if новый:
                return 451, "4.3.0 Temporary lookup failure"
            return ОдинПолучатель.rcpt(self, отправитель, получатель, сессия)

    v = валидатор(monkeypatch, поднять(СбойВпервые()))
    итог = прогон(monkeypatch, v, ["nobody.realname7@onercpt-retry.ru"])
    assert итог["nobody.realname7@onercpt-retry.ru"][0] == "Unknown"


def test_settle_is_one_path_for_both_passes():
    """Лестница после вердикта одна: основной проход и перепроверка зовут её."""
    import inspect
    source = inspect.getsource(pipeline_module.ValidationPipeline.run_pipeline)
    assert source.count("self._settle(") == 2


# ═══════════════════════════ D7, D14, N36: шлюзы, парковка, пересылка

def test_honest_security_gateway_gives_valid(monkeypatch, поднять):
    """Аудит R8: за честным Mimecast живой ящик уходил в «Неясно»."""
    v = валидатор(monkeypatch, поднять(Принимает("anna.ivanova")),
                  mx="eu-smtp-inbound-1.mimecast.com")
    assert v.check_email("anna.ivanova@gw.ru")["status"] == "valid"
    assert v.check_email("petr.nosuch@gw.ru")["status"] == "invalid"


def test_gateway_that_accepts_everything_is_still_catchall(monkeypatch, поднять):
    v = валидатор(monkeypatch, поднять(Сценарий()), mx="eu-smtp-inbound-1.mimecast.com")
    итог = v.check_email("anna.ivanova@gw-all.ru")
    assert итог["status"] == "catchall"
    assert "Mimecast" in итог["reason"]


@pytest.mark.parametrize("mx,why", [
    ("mx156.sedoparking.com", "парковки"),
    ("mx1.improvmx.com", "ImprovMX"),
    ("route1.mx.cloudflare.net", "Cloudflare"),
])
def test_parked_or_forwarding_mx_is_not_valid(monkeypatch, поднять, mx, why):
    v = валидатор(monkeypatch, поднять(Принимает("anna.ivanova")), mx=mx)
    итог = v.check_email("anna.ivanova@some-corp.ru")
    assert итог["status"] == "unconfirmed"
    assert why in итог["reason"]


def test_parked_domain_is_not_sent_to_pointless_retry(monkeypatch, поднять):
    """Парковку повтор не изменит — адрес не ждёт двух выдержек по семь минут."""
    v = валидатор(monkeypatch, поднять(Принимает("anna.ivanova")), mx="mx156.sedoparking.com")
    вызовы = []
    настоящий = v.check_email

    def считать(email, **kw):
        вызовы.append(email)
        return настоящий(email, **kw)

    v.check_email = считать
    итог = прогон(monkeypatch, v, ["anna.ivanova@parked-corp.ru"])
    assert итог["anna.ivanova@parked-corp.ru"][0] == "Unconfirmed"
    assert вызовы == ["anna.ivanova@parked-corp.ru"]


def test_forwarding_detection_boundaries():
    from core.confirmation import forwarding_service
    assert forwarding_service(["eforward3.registrar-servers.com"])
    assert forwarding_service(["fwd1.porkbun.com"])
    # Контроль: собственная почта Porkbun и хостинг Namecheap — не пересылка.
    assert forwarding_service(["mx1.porkbun.com"]) == ""
    assert forwarding_service(["mx1.privateemail.com"]) == ""
    assert forwarding_service(["mail.myimprovmx.com.evil.ru"]) == ""


# ═══════════════════════════ D1, D8, D11: статусы в выдаче

def test_pipeline_statuses_for_full_disabled_and_roles(monkeypatch, поднять):
    class Смесь(Принимает):
        def rcpt(self, отправитель, получатель, сессия):
            имя = получатель.split("@")[0]
            if имя == "ivan.petrov":
                return 452, "4.2.2 The recipient's inbox is out of storage space."
            if имя == "olga.smirnova":
                return 550, "5.2.1 The email account that you tried to reach is inactive."
            return Принимает.rcpt(self, отправитель, получатель, сессия)

    d = "mix-corp.ru"
    v = валидатор(monkeypatch, поднять(Смесь("anna.ivanova")))
    итог = прогон(monkeypatch, v, ["ivan.petrov@" + d, "olga.smirnova@" + d,
                                   "info@" + d, "abuse@" + d, "anna.ivanova@" + d])
    assert итог["ivan.petrov@" + d][0] == "Mailbox Full"
    assert итог["olga.smirnova@" + d][0] == "Disabled"
    # Мёртвый ролевой — «Мёртв», а не «Role-based» (аудит R3).
    assert итог["info@" + d][0] == "Invalid/Bounce"
    assert итог["info@" + d][2].get("role_address") is True
    # Контроль: живой ролевой по-прежнему «Role-based», то есть «Не слать».
    assert итог["abuse@" + d][0] == "Role-based"
    assert итог["anna.ivanova@" + d][0] == "Valid"
    assert итог["anna.ivanova@" + d][2].get("role_address") is False


def test_new_statuses_land_in_do_not_send_group():
    from ui.result_store import group_of
    assert group_of("Mailbox Full") == "spam"
    assert group_of("Disabled") == "spam"
    assert group_of("Unconfirmed") == "unknown"
    assert group_of("Valid") == "valid"


# ═══════════════════════════ N25, N31, D9: одноразовые по MX, ловушки, опечатки

def test_disposable_by_mx_and_its_guard(monkeypatch):
    from core import disposable
    assert disposable.disposable_mx_owner(["mail.mailinator.com"]) == "mailinator.com"
    # Даже если в скачанный список попал почтовик-гигант, его серверы — не
    # одноразовые: на них живут тысячи настоящих компаний.
    monkeypatch.setattr(disposable, "DISPOSABLE_DOMAINS",
                        set(disposable.DISPOSABLE_DOMAINS) | {"outlook.com", "google.com"})
    assert disposable.disposable_mx_owner(["corp-ru.mail.protection.outlook.com"]) == ""
    assert disposable.disposable_mx_owner(["aspmx.l.google.com"]) == ""


def test_pipeline_catches_disposable_by_mx_without_smtp(monkeypatch, поднять):
    сценарий = Принимает("anna.ivanova")
    v = валидатор(monkeypatch, поднять(сценарий), mx="mail.mailinator.com")
    итог = прогон(monkeypatch, v, ["anna.ivanova@fresh-temp.xyz"])
    assert итог["anna.ivanova@fresh-temp.xyz"][0] == "Trap/Disposable"
    assert not сценарий.журнал, "одноразовый не должен уходить в SMTP"


@pytest.mark.parametrize("email,hit", [
    ("spamtrap@corp.ru", True), ("spam.trap@corp.ru", True),
    ("honey.pot@corp.ru", True), ("trap@corp.ru", True),
    ("trapeznikov@corp.ru", False), ("honeycomb@corp.ru", False),
    ("strap@corp.ru", False),
])
def test_trap_words_are_whole_words(email, hit):
    from core.heuristics import trap_word_in_local
    assert bool(trap_word_in_local(email)) is hit


def test_typo_hint_appears_when_typo_domain_accepts_everything(monkeypatch, поднять):
    v = валидатор(monkeypatch, поднять(Сценарий()))
    итог = прогон(monkeypatch, v, ["ivan.petrov@gamil.com"], fix_typos=True)
    статус, причина, данные = итог["ivan.petrov@gamil.com"]
    assert статус == "Unknown"
    assert "gmail.com" in причина
    assert данные.get("suggested_email") == "ivan.petrov@gmail.com"


def test_confirmed_valid_on_a_typo_map_domain_is_left_alone(monkeypatch, поднять):
    """Контроль: в словаре опечаток есть настоящие домены (mai.ru — МАИ).
    Честный сервер, отвергший выдуманный адрес, даёт «Годен» без подсказки."""
    v = валидатор(monkeypatch, поднять(Принимает("ivan.petrov")))
    итог = прогон(monkeypatch, v, ["ivan.petrov@mai.ru"], fix_typos=True)
    статус, причина, данные = итог["ivan.petrov@mai.ru"]
    assert статус == "Valid"
    assert not данные.get("suggested_email")


# ═══════════════════════════ D4, D5: порт 25 и второе мнение без прокси

def test_port25_probe_verdicts():
    from core.port25 import probe_port25
    закрыт = lambda host, port, t: (True, port != 25)          # noqa: E731
    нет_сети = lambda host, port, t: (False, False)             # noqa: E731
    открыт = lambda host, port, t: (True, True)                 # noqa: E731
    assert probe_port25(knock=закрыт)["verdict"] == "closed"
    assert probe_port25(knock=нет_сети)["verdict"] == "unknown"
    assert probe_port25(knock=открыт)["verdict"] == "open"


def _труба(логи):
    return pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda m, t="info": логи.append(m), "on_result": lambda *a: None,
        "on_progress": lambda *a: None, "on_complete": lambda: None})


def test_closed_port25_stops_a_direct_run(monkeypatch):
    import core.port25 as port25
    monkeypatch.setattr(port25, "probe_port25",
                        lambda *a, **k: {"verdict": "closed", "tried": 4})
    логи = []
    pipe = _труба(логи)
    pipe._check_port25_direct()
    assert pipe.blocked_reason and pipe._stop_requested
    assert any("порт 25" in m for m in логи)


def test_open_port25_lets_the_run_go_and_says_about_second_opinion(monkeypatch):
    import core.port25 as port25
    monkeypatch.setattr(port25, "probe_port25",
                        lambda *a, **k: {"verdict": "open", "tried": 4})
    логи = []
    pipe = _труба(логи)
    pipe._stop_requested = False
    pipe.blocked_reason = ""
    pipe._check_port25_direct()
    assert not pipe._stop_requested
    assert any("второе мнение" in m for m in логи)


def test_window_does_not_call_a_blocked_run_completed():
    """Окно не пишет «Проверка завершена» про прогон, который не начинался."""
    from ui.webapp import ValidatorApi
    логи = []
    api = ValidatorApi.__new__(ValidatorApi)
    api._on_log = lambda m, t="info": логи.append(m)
    api.pipeline = type("P", (), {"blocked_reason": "порт 25 закрыт"})()
    api._on_complete()
    assert any("не выполнялась" in m for m in логи)
    assert not any("Проверка завершена" in m for m in логи)
    логи.clear()
    api.pipeline = type("P", (), {"blocked_reason": ""})()
    api._on_complete()
    assert any("Проверка завершена" in m for m in логи)


def test_no_live_proxies_does_not_fall_back_to_direct(monkeypatch):
    """Прокси заданы, ни один не ожил — прогон стоит, а не идёт с домашнего IP."""
    import core.network as net
    from core.github_parser import BlacklistDownloader
    monkeypatch.setattr(BlacklistDownloader, "download_all", lambda self, **k: None)
    monkeypatch.setattr(net, "filter_live_proxies", lambda proxies, **k: ([], 1))
    monkeypatch.setattr(pipeline_module.ValidationPipeline, "_profile_live_proxies",
                        lambda self, *a, **k: {}, raising=False)
    логи = []
    pipe = _труба(логи)
    pipe.setup(timeout=2, proxies=["socks5://203.0.113.7:1080"], threads=1,
               use_cache=False)
    assert pipe._stop_requested
    assert pipe.blocked_reason


def test_valid_without_second_opinion_says_so():
    from core.verdict import verdict_confidence
    _value, basis = verdict_confidence("valid", "250 OK",
                                       {"valid_second_opinion": "unavailable"})
    assert "второго мнения" in basis


# ═══════════════════════════ скоринг и кэш

def test_full_mailbox_scores_no_liveness():
    from core.scoring import calculate_engagement_score as score
    полный = score("ivan@corp.ru", "Mailbox Full", "452 Ящик переполнен")["score"]
    живой = score("ivan@corp.ru", "Valid", "250 OK")["score"]
    assert полный < живой
    старый = score("ivan@corp.ru", "Valid", "452 Ящик существует и переполнен")["score"]
    assert старый < живой
    assert score("ivan@corp.ru", "Disabled", "")["score"] == 0


def test_cache_forgets_valid_given_to_full_mailboxes(tmp_path):
    from core.cache import ResultCache
    путь = str(tmp_path / "cache.sqlite")
    cache = ResultCache(path=путь)
    cache.put("full@corp.ru", "Valid", "452 Ящик существует и переполнен", "mx")
    cache.put("live@corp.ru", "Valid", "250 OK", "mx")
    cache.close()
    cache = ResultCache(path=путь)
    assert cache.get("full@corp.ru") is None
    assert cache.get("live@corp.ru") is not None
    cache.close()


def test_role_column_is_exported_by_both_surfaces():
    import cli
    assert "role_address" in cli.EXPORT_FIELDS
    with open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "ui", "webapp.py"), encoding="utf-8") as handle:
        assert '"RoleAddress"' in handle.read()
