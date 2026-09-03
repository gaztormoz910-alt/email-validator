# -*- coding: utf-8 -*-
"""У сервера спрашивают ЗАГРУЖЕННЫЙ адрес, и вердикт — про него.

Владелец описал схему и спросил, так ли работает валидатор:

    берёт загруженную почту -> меняет домен и придумывает случайную ->
    проверяет придуманную -> про загруженную говорит «валидна», хотя её саму
    не проверял

Половина описания — правда: выдуманные адреса программа действительно шлёт, и
идут они РАНЬШЕ загруженного. Вторая половина — нет: вердикт берётся из
ответа на его собственный адрес, а ответ на выдуманный умеет только понизить
вердикт и никогда не выдаёт «Годен».

Подмена домена, которая делала его описание полностью верным, существовала до
3 сентября (`geometrixx.info` -> `geometrixx.in`) и исправлена. Эти проверки
стоят, чтобы она не вернулась молча.

Подделан здесь только сам почтовый сервер. Разбор ответов, контрольная проба
и решение о вердикте — настоящие: подменив их, тест мерил бы себя.
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.canary import CANARY_MARK              # noqa: E402
from core.network import NetworkValidator        # noqa: E402

ЗАГРУЖЕНО = "sachinjaiswal.ca@corp-example.test"


class _Сервер(object):
    """Почтовик, записывающий каждую команду RCPT TO."""

    def __init__(self, журнал, правило):
        self.журнал = журнал
        self.правило = правило
        self.command_encoding = "ascii"

    def connect(self, host, port):
        return 220, b"ESMTP ready"

    def ehlo(self, name):
        return 250, b"ok"

    def helo(self, name):
        return 250, b"ok"

    def has_extn(self, name):
        return False

    def mail(self, addr, options=None):
        return 250, b"2.1.0 Sender OK"

    def rcpt(self, email):
        код, текст = self.правило(email)
        self.журнал.append(email)
        return код, текст.encode("utf-8")

    def verify(self, email):
        return 252, b"cannot VRFY"

    def quit(self):
        return 221, b"bye"

    def close(self):
        pass


def _прогнать(правило, адрес=ЗАГРУЖЕНО):
    журнал = []
    nv = NetworkValidator(proxies=[])
    nv._mx_delay = lambda mx: 0.0
    nv.country_for_domain = lambda domain, mx_host="": ""
    nv.check_dns_health = lambda d, mx_record="": {"score": 0}
    nv.get_mx_records = lambda d: ["mx.corp-example.test"]
    nv._make_smtp_connection = lambda proxy=None: _Сервер(журнал, правило)
    return nv.check_email(адрес), журнал


ЧЕСТНЫЙ = lambda e: ((250, "2.1.5 Recipient OK") if e == ЗАГРУЖЕНО
                     else (550, "5.1.1 No such user"))
НЕТ_ЯЩИКА = lambda e: ((250, "2.1.5 OK")
                       if e.split("@")[0] in ("postmaster", "abuse")
                       else (550, "5.1.1 No such user"))
ВСЁ_ПОДРЯД = lambda e: (250, "2.1.5 Recipient OK")


# ══════════════════════ W1: спрашивают именно его ═══════════════════════

def test_asked_the_loaded_address_itself():
    """Загруженный адрес уходит в RCPT TO байт в байт."""
    for правило in (ЧЕСТНЫЙ, НЕТ_ЯЩИКА, ВСЁ_ПОДРЯД):
        _итог, журнал = _прогнать(правило)
        assert ЗАГРУЖЕНО in журнал, (
            "загруженный адрес не спрашивали вовсе: %s" % журнал)


def test_asked_domain_is_not_swapped():
    """Домен в отправленной команде — тот же, что загружен.

    Именно это было дефектом: `geometrixx.info` уходил как `geometrixx.in`,
    и вердикт получался настоящий, но про чужой ящик.
    """
    _итог, журнал = _прогнать(ЧЕСТНЫЙ)
    наши = [а for а in журнал if not _выдуманный(а)]
    assert наши, "среди отправленного нет ни одного нашего адреса"
    for адрес in наши:
        assert адрес.split("@")[1] == ЗАГРУЖЕНО.split("@")[1], адрес


def test_asked_mailbox_name_is_not_rewritten():
    """Имя ящика тоже не переписывается — ни регистр, ни точки."""
    смешанный = "John.Smith@corp-example.test"
    _итог, журнал = _прогнать(
        lambda e: (250, "2.1.5 OK") if e == смешанный else (550, "5.1.1 no"),
        адрес=смешанный)
    assert смешанный in журнал, журнал


def _выдуманный(адрес):
    """Наш ли это адрес или проба. Пробы — случайные строки и канарейки."""
    имя = адрес.split("@")[0]
    return (CANARY_MARK in адрес
            or имя in ("postmaster", "abuse")
            or (имя not in (ЗАГРУЖЕНО.split("@")[0], "John.Smith")))


# ══════════════════════ W2: вердикт из ответа на него ═══════════════════

def test_verdict_follows_the_answer_about_the_loaded_address():
    """Сервер принял наш адрес и отверг выдуманный — вердикт valid."""
    итог, _журнал = _прогнать(ЧЕСТНЫЙ)
    assert итог["status"] == "valid", итог


def test_verdict_invalid_only_when_the_server_denies_our_mailbox():
    """Сервер отверг наш адрес, служебный принял — вердикт invalid."""
    итог, _журнал = _прогнать(НЕТ_ЯЩИКА)
    assert итог["status"] == "invalid", итог


def test_verdict_a_made_up_answer_can_only_lower_it():
    """Сервер принимает ВСЁ — «Годен» не выдаётся.

    Ответ про наш адрес здесь ровно тот же, что про выдуманный, и значит не
    доказывает ничего. Вердикт обязан упасть до catchall (в окне — «не
    доказано»), а не подняться до Valid.
    """
    итог, журнал = _прогнать(ВСЁ_ПОДРЯД)
    assert итог["status"] == "catchall", итог
    assert ЗАГРУЖЕНО in журнал, "и при этом его всё равно спросили"


def test_verdict_control_a_made_up_answer_never_creates_a_valid():
    """Контроль: «Годен» не появляется, если НАШ адрес отвергнут.

    Даже когда все выдуманные адреса приняты, отказ по нашему остаётся
    отказом. Обратное означало бы, что вердикт берётся не из его ответа.
    """
    итог, _журнал = _прогнать(
        lambda e: (550, "5.1.1 No such user") if e == ЗАГРУЖЕНО
        else (250, "2.1.5 OK"))
    assert итог["status"] != "valid", итог


def test_verdict_server_that_denies_postmaster_cannot_condemn():
    """Сервер, отвергающий обязательный postmaster@, не выносит приговор.

    RFC 5321 §4.5.1 требует этот ящик у каждого домена. Сервер, который его
    не знает, отвечает не про ящики — и его 550 про наш адрес недоказателен.
    """
    итог, _журнал = _прогнать(lambda e: (550, "5.1.1 No such user"))
    assert итог["status"] == "risky", итог


# ══════════════════════ W3: строка в выдаче — про него ══════════════════

def test_row_carries_the_loaded_address():
    """От строки в файле до строки результата адрес не меняется."""
    from core.cleaner import EmailCleaner
    from core.streamer import StreamLoader

    исходные = ["sachinjaiswal.ca@gmail.com", "John.Smith@Corp-Example.com",
                "user@sky.company.co.uk", "a@geometrixx.info"]
    загружено = [e for e, _ in StreamLoader(
        [{"type": "text", "content": "\n".join(исходные) + "\n"}]).stream_emails()]
    cleaner = EmailCleaner()

    расхождения = []
    for исходный, после in zip(исходные, загружено):
        итог = cleaner.correct_and_normalize(после)
        if (итог or "").lower() != исходный.lower():
            расхождения.append("%s -> %s" % (исходный, итог))
    assert not расхождения, "адрес изменился по пути: %s" % расхождения


def test_row_control_the_trace_script_agrees():
    """Контроль: распечатка из .unlazy/whatisasked существует и совпадает.

    Она — то, что владелец читает глазами. Разойдясь с тестами, она стала бы
    красивой неправдой.
    """
    import io as _io

    путь = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        ".unlazy", "whatisasked", "trace.py")
    if not os.path.exists(путь):
        return          # ledger не обязан жить в репозитории
    текст = _io.open(путь, encoding="utf-8").read()
    assert "LOADED-ADDRESS-IS-THE-ONE-ASKED" in текст
    # И она не должна утверждать, будто выдуманные идут ПОСЛЕ: они идут до.
    assert "Выдуманные адреса спрашиваются ПОСЛЕ" not in текст, (
        "распечатка противоречит собственному выводу")


# ══════════════════════ «Проверен как» перестала быть пустой ════════════

def test_checked_as_is_actually_filled_now():
    """Поле, которое окно показывает, кто-то наконец заполняет.

    Строка «Проверен как» была в карточке адреса с самого начала, читалась
    окном и НЕ записывалась нигде — то есть всегда пустая. Владелец не мог
    убедиться своими глазами, что проверяют его адрес, и спрашивал дважды.
    """
    источник = io.open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "core", "pipeline.py"), encoding="utf-8").read()
    assert 'data["checked_as"]' in источник, "поле по-прежнему никто не пишет"
    # Обе ветки проверки: первая попытка и повтор после отложенного адреса.
    assert источник.count('data["checked_as"]') >= 2, (
        "заполняется только одна ветка — в другой строка останется пустой")


def test_checked_as_uses_the_same_function_as_the_probe():
    """Показываемое значение собирается ТОЙ ЖЕ функцией, что и отправляемое.

    Две копии правила «как собрать адрес для провода» разошлись бы молча, и
    строка показывала бы не то, что ушло, — обманывая ровно там, где её
    завели ради доверия.
    """
    сеть = io.open(os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "core", "network.py"), encoding="utf-8").read()
    assert "def probe_form" in сеть
    assert "probe_email = self.probe_form(email)" in сеть, (
        "проверка собирает адрес своим способом, а окно — другим")


def test_checked_as_shows_the_loaded_address_unchanged():
    """Для обычного адреса показывается ровно он же."""
    assert NetworkValidator.probe_form(ЗАГРУЖЕНО) == ЗАГРУЖЕНО


def test_checked_as_control_punycode_is_the_one_difference():
    """Контроль: единственное законное отличие — punycode у домена.

    `ivan@почта.рф` и `ivan@xn--80a1acny.xn--p1ai` — один и тот же ящик: SMTP
    не умеет не-ASCII в домене, и на проводе уходит второе. Имя ящика при
    этом не трогается.
    """
    вышло = NetworkValidator.probe_form("иван@почта.рф")
    assert вышло == "иван@xn--80a1acny.xn--p1ai", вышло
    assert вышло.split("@")[0] == "иван", "имя ящика переписано"
    # Регистр домена приводится к нижнему — DNS его не различает.
    assert NetworkValidator.probe_form("John.Smith@Corp.COM") == "John.Smith@corp.com"

