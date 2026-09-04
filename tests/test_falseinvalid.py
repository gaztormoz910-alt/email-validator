# -*- coding: utf-8 -*-
"""Живой адрес не должен объявляться мёртвым до единого запроса в сеть.

Три пункта из корзины «ложный INVALID» плюс несогласованность, найденная по
ходу. Все четыре решаются на слое синтаксиса, то есть ДО обращения к серверу,
и потому особенно вредны: сервер даже не спрашивается.

    john(note)@example.com      отвергался   RFC 5322 §3.2.2 разрешает
    john(заметка)@example.com   принимался   та же строка, другой алфавит
    user@[192.168.1.1]          отвергался   RFC 5321 §4.1.3 разрешает
    user@[IPv6:2001:db8::1]     отвергался   там же

Половина проверок здесь — ОБРАТНЫЕ. Принять законное легко; трудно принять
его, не начав заодно принимать мусор и не переписав чужой живой адрес.
"""
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.cleaner import EmailCleaner                      # noqa: E402
from core.email_syntax import validate_email_syntax        # noqa: E402
from core.inputnorm import strip_comments                  # noqa: E402
from core.network import NetworkValidator                  # noqa: E402

CLEANER = EmailCleaner()


# ───────────────────────── комментарии в скобках ─────────────────────────

@pytest.mark.parametrize("исходный,ожидаемый", [
    ("john(note)@example.com", "john@example.com"),
    ("(note)john@example.com", "john@example.com"),
    ("john@(note)example.com", "john@example.com"),
    ("john@example.com(note)", "john@example.com"),
    ("(a)john(b)@(c)example.com(d)", "john@example.com"),
])
def test_cfws_comment_is_stripped(исходный, ожидаемый):
    """Комментарий — не часть ящика. Проверять надо настоящий адрес."""
    assert strip_comments(исходный) == ожидаемый


def test_cfws_address_becomes_valid_syntax():
    """Итог правки: адрес с комментарием больше не хоронится синтаксисом."""
    assert CLEANER.correct_and_normalize("john(note)@example.com") == "john@example.com"
    assert validate_email_syntax(CLEANER.correct_and_normalize("john(note)@example.com"))


def test_cfws_same_answer_for_cyrillic():
    """Несогласованность, найденная по ходу: латиница и кириллица расходились.

    До правки `john(note)@example.com` отвергался, а `john(заметка)@…`
    ПРИНИМАЛСЯ — не-ASCII имя уходило по ветке SMTPUTF8, где грамматика
    dot-atom не применялась вовсе. Один и тот же случай решался по-разному
    в зависимости от алфавита внутри скобок.
    """
    латиница = strip_comments("john(note)@example.com")
    кириллица = strip_comments("john(заметка)@example.com")
    assert латиница == "john@example.com"
    assert кириллица == "john@example.com"


def test_cfws_parens_inside_atom_are_left_alone():
    """ОБРАТНЫЙ КОНТРОЛЬ: скобки в середине имени — не комментарий.

    RFC 5322 разрешает комментарий по краям local-part и домена, но не
    внутри атома. Трогать такое нельзя: это чужой адрес, а не наш мусор.
    """
    for целый in ("a(b)c@example.com", "jo(hn@example.com", "john)note(@x.com"):
        assert strip_comments(целый) == целый


def test_cfws_unbalanced_parens_are_left_alone():
    """ОБРАТНЫЙ КОНТРОЛЬ: несбалансированные скобки не трогаем."""
    for целый in ("john(note@example.com", "john)@example.com",
                  "john((a)@example.com"):
        assert strip_comments(целый) == целый


def test_cfws_quoted_local_keeps_its_parens():
    """ОБРАТНЫЙ КОНТРОЛЬ: внутри кавычек скобки — обычные знаки имени."""
    в_кавычках = '"a(b)c"@example.com'
    assert strip_comments(в_кавычках) == в_кавычках


def test_cfws_does_not_touch_ordinary_addresses():
    """ОБРАТНЫЙ КОНТРОЛЬ: обычный адрес не меняется ни на байт."""
    for обычный in ("ivan@gmail.com", "john.smith@corp.co.uk",
                    "user+tag@example.com", "a%b@corp.com",
                    "иван@почта.рф", '"very.unusual"@example.com'):
        assert strip_comments(обычный) == обычный


# ───────────────────────── домен-литералы ─────────────────────────

@pytest.mark.parametrize("адрес", [
    "user@[192.168.1.1]",
    "user@[93.184.216.34]",
    "user@[IPv6:2001:db8::1]",
    "user@[IPv6:::1]",
])
def test_literal_is_valid_syntax(адрес):
    """RFC 5321 §4.1.3: адрес в квадратных скобках — законный домен."""
    assert validate_email_syntax(адрес), "законный домен-литерал отвергнут"


def test_literal_survives_the_cleaner():
    """Очистка краёв срезала закрывающую скобку и ломала адрес.

    В списке мусорных краёв есть `[` и `]`, и `user@[192.168.1.1]`
    превращался в `user@[192.168.1.1` — то есть в ложный Invalid,
    сделанный нашими же руками.
    """
    assert CLEANER.correct_and_normalize("user@[93.184.216.34]") == "user@[93.184.216.34]"


def test_literal_ipv6_survives_the_cleaner():
    """У шестой версии есть буквы, а очистка приводит домен к нижнему регистру.

    Проверяется отдельно от четвёртой намеренно: `[IPv6:2001:DB8::1]` после
    приведения становится `[ipv6:2001:db8::1]`, и если разбор литерала
    окажется чувствителен к регистру, адрес снова уедет в ложный Invalid —
    но уже только для шестой версии, то есть незаметно.
    """
    вышло = CLEANER.correct_and_normalize("user@[IPv6:2001:DB8::1]")
    assert validate_email_syntax(вышло), "после очистки литерал IPv6 сломался: %r" % вышло
    assert вышло.startswith("user@["), вышло


@pytest.mark.parametrize("мусор", [
    "user@[999.1.1.1]",
    "user@[not-an-ip]",
    "user@[192.168.1]",
    "user@[]",
    "user@[192.168.1.1",
    "user@192.168.1.1]",
])
def test_literal_garbage_is_still_rejected(мусор):
    """ОБРАТНЫЙ КОНТРОЛЬ: скобки не делают законным что попало."""
    assert not validate_email_syntax(мусор), "мусор принят как домен-литерал"


# ───────────────────────── защита от похода внутрь сети ─────────────────────

class _Сервер(object):
    """Поддельный почтовик, принимающий всё. Нужен, чтобы поймать сам факт
    подключения: если валидатор сюда дошёл — значит защита не сработала."""
    command_encoding = "ascii"

    def __init__(self, куда):
        self.куда = куда

    def connect(self, host, port):
        self.куда.append(host)
        return 220, b"mx.test ESMTP"

    def ehlo(self, n):
        return 250, b"ok"

    def helo(self, n):
        return 250, b"ok"

    def has_extn(self, n):
        return False

    def mail(self, a, options=None):
        return 250, b"ok"

    def rcpt(self, e):
        return 250, b"2.1.5 OK"

    def verify(self, e):
        return 252, b"no"

    def quit(self):
        return 221, b"bye"

    def close(self):
        pass


def _проба(адрес):
    """Возвращает (куда подключились, вердикт)."""
    куда = []
    nv = NetworkValidator(proxies=[])
    nv._mx_delay = lambda mx: 0.0
    nv.country_for_domain = lambda d, mx_host="": ""
    nv.check_dns_health = lambda d, mx_record="": {"score": 0}
    nv._make_smtp_connection = lambda proxy=None: _Сервер(куда)
    итог = nv.check_email(адрес)
    return куда, итог.get("status"), итог.get("reason") or ""


@pytest.mark.parametrize("адрес", [
    "user@[192.168.1.1]",
    "user@[127.0.0.1]",
    "user@[10.0.0.1]",
    "user@[169.254.1.1]",
    "user@[IPv6:::1]",
])
def test_ssrf_private_literal_is_never_probed(адрес):
    """ГЛАВНЫЙ КОНТРОЛЬ ВСЕГО ПУНКТА.

    Принять литералы легко. Открыть ими же дыру, которую закрыли вчера, —
    ещё легче: `user@[192.168.1.1]` заставил бы валидатор постучаться в
    нашу собственную сеть по указанию постороннего.

    Подключения быть не должно, а вердикт — «не проверено», НЕ «мёртвый»:
    у домена может быть настоящая внутренняя почта.
    """
    куда, статус, _ = _проба(адрес)
    assert куда == [], "валидатор подключился к внутреннему адресу: %s" % куда
    assert статус == "unknown", "вердикт %r вместо «не проверено»" % статус


# ───────────── загрузчик: адрес не должен подменяться по дороге ─────────────

def _загрузить(строка):
    from core.streamer import StreamLoader
    return [e for e, _ in StreamLoader(
        [{"type": "text", "content": строка + "\n"}]).stream_emails()]


def test_loader_keeps_ipv6_literal_whole():
    """Разделитель по умолчанию — двоеточие, а оно есть внутри IPv6.

    Найдено сквозной проверкой уже ПОСЛЕ того, как модульные тесты на
    литералы были зелёными: разбор строк вида `почта:пароль` резал
    `user@[IPv6:2001:db8::1]`, и до проверки доезжало `user@[ipv6`.
    """
    вышло = _загрузить("user@[IPv6:2001:DB8::1]")
    assert len(вышло) == 1, вышло
    assert вышло[0].startswith("user@[") and вышло[0].endswith("]"), вышло[0]
    assert validate_email_syntax(вышло[0]), "литерал доехал сломанным: %r" % вышло[0]


def test_loader_never_reports_about_a_neighbouring_mailbox():
    """Кусок из середины строки — это ДРУГОЙ ящик, а не найденный адрес.

    Образец поиска находил в `a(b)c@example.com` подстроку `c@example.com`,
    и дальше проверялся именно он: владелец получил бы вердикт о ящике,
    которого не загружал. Испорченная строка обязана доехать целиком, чтобы
    синтаксис честно назвал её битой.
    """
    вышло = _загрузить("a(b)c@example.com")
    assert вышло == ["a(b)c@example.com"], (
        "загрузчик подменил адрес: %s" % вышло)
    assert not validate_email_syntax(вышло[0]), (
        "битая строка обязана отвергаться синтаксисом, а не проверяться")


@pytest.mark.parametrize("строка,ожидаемый", [
    ("Ivan Petrov <ivan@corp.com>", "ivan@corp.com"),
    ("Мария Иванова <maria@corp.ru>;", "maria@corp.ru"),
    ('"ivan@corp.com",', "ivan@corp.com"),
    ("ivan@gmail.com:parol123", "ivan@gmail.com"),
    ("ivan@gmail.com", "ivan@gmail.com"),
])
def test_loader_still_unwraps_ordinary_forms(строка, ожидаемый):
    """ОБРАТНЫЙ КОНТРОЛЬ: обычные обёртки по-прежнему снимаются.

    Правило «брать целиком, если перед адресом не обёртка» легко ужесточить
    так, что перестанут разбираться выгрузки почтовиков и пары
    `почта:пароль`. Здесь проверяется, что этого не случилось.
    """
    assert _загрузить(строка) == [ожидаемый]


def test_ssrf_public_literal_is_probed():
    """ОБРАТНЫЙ КОНТРОЛЬ: публичный литерал проверять можно и нужно.

    Без него предыдущая проверка зеленела бы оттого, что литералы просто
    не работают вовсе.
    """
    куда, статус, _ = _проба("user@[93.184.216.34]")
    assert куда, "к публичному литералу не подключились вовсе"
    # Подключений может быть несколько — тройная проба catch-all идёт своим
    # соединением. Важно не их число, а то, что все они ушли КУДА НАДО.
    assert set(куда) == {"93.184.216.34"}, "ушли не туда: %s" % куда
    assert статус in ("valid", "catchall"), "вердикт %r" % статус
