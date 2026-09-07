# -*- coding: utf-8 -*-
"""Девять пробелов, найденных сверкой с 236 чужими критериями.

Каждый был замерен на этом коде ДО правки, и у каждого здесь стоит
отрицательный контроль: проверка «стало лучше» ничего не стоит, если вместе
с починкой сломалось что-то соседнее.

    ложный VALID   4.7  MX на приватный IP — доказано прогоном: вердикт valid
                   4.4  MX прямо на IP-адрес
                   4.22 wildcard-DNS
    тихая потеря   1.12 второй адрес в строке исчезал молча
    ложный INVALID 8.8  ya.ru и yandex.ru не схлопывались
                   1.9  две формы Unicode считались разными
                   1.8  полноширинные знаки отвергались
                   3.25 полноширинная точка, наоборот, принималась
                   1.3  невидимый знак ВНУТРИ адреса переживал очистку
                   1.13 URL-кодировка не раскрывалась
                   1.14 HTML-сущности не раскрывались

ОБЩЕЕ ПРАВИЛО ЗАХОДА, и оно проверяется отдельно: наружу уходит то, что
владелец загрузил. Приведение входа чинит только невидимое, полноширинное и
форму, которую требует сам протокол, — то есть строка после него адресует
ТОТ ЖЕ ящик.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cleaner import EmailCleaner, normalize_for_dedup     # noqa: E402
from core.email_syntax import validate_email_syntax            # noqa: E402
from core.inputnorm import (fold_fullwidth, normalize_input,    # noqa: E402
                            split_addresses, strip_invisible, to_nfc)
from core.mxguard import (filter_mx_hosts, is_ip_literal,       # noqa: E402
                          resolves_to_private)
from core.network import NetworkValidator                      # noqa: E402
from core.streamer import StreamLoader                         # noqa: E402


def загрузить(текст):
    return [e for e, _ in StreamLoader(
        [{"type": "text", "content": текст + "\n"}]).stream_emails()]


# ══════════════════════ G1: MX на приватный адрес ═══════════════════════

ВНУТРЕННИЕ = ["127.0.0.1", "10.0.0.5", "192.168.1.50", "172.16.0.1",
              "169.254.1.1", "0.0.0.0", "::1", "fc00::1"]


def test_mx_private_every_internal_range_is_refused():
    """Ловится КЛАСС адресов, а не один пример.

    Список исключений устарел бы на первой же чужой сети; здесь проверяются
    все диапазоны, из которых наружу почта не ходит.
    """
    пропущенные = [а for а in ВНУТРЕННИЕ
                   if not resolves_to_private("mx.test", resolve=lambda h: [а])]
    assert not пропущенные, "внутренние адреса пропущены: %s" % пропущенные


def test_mx_private_the_hole_is_closed_end_to_end():
    """Сквозная проверка: туда больше не подключаемся и valid не выдаём.

    Именно этот сценарий давал `valid` до правки — замерено прогоном.
    """
    # Зона .com, а не .test: по зарезервированной зоне валидатор
    # выносит приговор раньше, и до проверки MX дело не дошло бы.
    цель = "kto-ugodno@zloy-domen-t.com"
    куда = []

    class Сервер(object):
        command_encoding = "ascii"

        def connect(self, host, port):
            куда.append(host)
            return 220, b"ESMTP"

        def ehlo(self, n):
            return 250, b"ok"

        def helo(self, n):
            return 250, b"ok"

        def has_extn(self, n):
            return False

        def mail(self, a, options=None):
            return 250, b"ok"

        def rcpt(self, e):
            return (250, b"2.1.5 OK") if e == цель else (550, b"5.1.1 no")

        def verify(self, e):
            return 252, b"no"

        def quit(self):
            return 221, b"bye"

        def close(self):
            pass

    nv = NetworkValidator(proxies=[])
    nv._mx_delay = lambda mx: 0.0
    nv.country_for_domain = lambda d, mx_host="": ""
    nv.check_dns_health = lambda d, mx_record="": {"score": 0}
    nv.get_mx_records = lambda d: ["192.168.1.50"]
    nv._make_smtp_connection = lambda proxy=None: Сервер()

    итог = nv.check_email(цель)
    assert куда == [], "всё ещё подключаемся внутрь сети: %s" % куда
    assert итог["status"] != "valid", итог
    assert итог["status"] == "unknown", итог


def test_mx_private_control_a_normal_host_is_untouched():
    """Контроль: обычный MX не отбрасывается.

    Предохранитель, режущий живые домены, хуже дыры, которую он закрывает.
    """
    годные, отвергнутые = filter_mx_hosts(
        ["mx.corp.test"], resolve=lambda h: ["93.184.216.34"])
    assert годные == ["mx.corp.test"], (годные, отвергнутые)


def test_mx_private_control_resolver_failure_does_not_condemn():
    """Контроль: сбой резолвера НЕ объявляет хост внутренним.

    Иначе наша собственная неудача выбрасывала бы живые домены — ровно та
    ошибка, от которой защищает весь остальной код.
    """
    def падает(host):
        raise OSError("резолвер молчит")

    assert resolves_to_private("mx.corp.test", resolve=падает) is False


def test_mx_private_rejected_hosts_are_named():
    """Отброшенное НАЗЫВАЕТСЯ, а не исчезает молча.

    Молчаливое отбрасывание выглядело бы как «у домена нет MX», то есть
    превратило бы дыру безопасности в ложный Invalid.
    """
    _годные, отвергнутые = filter_mx_hosts(
        ["10.0.0.1"], resolve=lambda h: [])
    assert отвергнутые and отвергнутые[0][0] == "10.0.0.1"
    assert len(отвергнутые[0][1]) > 30, "причина не названа словами"


# ══════════════════════ G2: MX прямо на IP ══════════════════════════════

def test_mx_is_ip_literal_is_refused():
    """MX обязан быть ИМЕНЕМ хоста (RFC 2181 §10.3)."""
    for адрес in ("93.184.216.34", "2001:db8::1", "[192.168.1.1]"):
        assert is_ip_literal(адрес) is True, адрес


def test_mx_is_ip_control_hostnames_are_not_mistaken_for_ips():
    """Контроль: имя хоста за адрес не принимается.

    Особая осторожность с именами из цифр: `1.2.3.mx.corp.test` — имя.
    """
    for имя in ("mx.gmail.com", "aspmx.l.google.com", "1.2.3.mx.corp.test",
                "mail.192.168.corp.test"):
        assert is_ip_literal(имя) is False, имя


# ══════════════════════ G3: wildcard-DNS ════════════════════════════════

def test_wildcard_is_detected_and_a_fallback_refused():
    """У домена, где резолвится ЛЮБОЕ имя, A-запись ничего не доказывает."""
    # Класс ищется по наличию метода, а не по имени: имя может смениться, и
    # тест, привязанный к нему, упал бы на переименовании, а не на дефекте.
    объект = _носитель_dns(отвечает_всем=True)
    assert объект._is_wildcard_domain("wild.test") is True


def test_wildcard_control_a_normal_domain_is_not_wildcard():
    """Контроль: у обычного домена выдуманное имя не резолвится."""
    объект = _носитель_dns(отвечает_всем=False)
    assert объект._is_wildcard_domain("corp.test") is False


def test_wildcard_control_resolver_failure_is_not_wildcard():
    """Контроль: сбой резолвера не объявляет домен подстановочным."""
    объект = _носитель_dns(отвечает_всем=False, падает=True)
    assert объект._is_wildcard_domain("corp.test") is False


def _носитель_dns(отвечает_всем, падает=False):
    """Объект с методом _is_wildcard_domain и подставным резолвером."""
    import core.dns_checks as модуль

    класс = None
    for имя in dir(модуль):
        значение = getattr(модуль, имя)
        if isinstance(значение, type) and hasattr(значение, "_is_wildcard_domain"):
            класс = значение
            break
    assert класс is not None, "не найден класс с _is_wildcard_domain"

    носитель = класс.__new__(класс)

    class Резолвер(object):
        def resolve(self, имя, тип):
            if падает:
                raise OSError("молчит")
            if отвечает_всем:
                return ["93.184.216.34"]
            raise LookupError("нет такого имени")

    носитель.resolver = Резолвер()
    return носитель


# ══════════════════════ G4: все адреса из строки ════════════════════════

def test_many_per_line_collapses_to_one_person():
    """РЕШЕНИЕ ИЗМЕНЕНО ВЛАДЕЛЬЦЕМ 06.09.2026.

    Прежнее правило («второй адрес больше не пропадает») решало настоящую
    задачу — адрес действительно терялся молча. Но у него была цена, которую
    видно только на живой базе: несколько адресов в ОДНОЙ строке — это один
    человек, и он получал столько писем, сколько у него ящиков. Дедуп их не
    схлопывает, адреса-то разные. ЗАМЕРЕНО на файле владельца: 2 898 таких
    строк и 4 350 лишних писем.

    Теперь из строки выходит один адрес, приоритетный. Что именно считается
    приоритетным и почему — tests/test_dedup_glue.py.
    """
    for строка in ("a@x.com, b@y.com",
                   "a@x.com b@y.com c@z.com",
                   "a@x.com;b@y.com"):
        вышло = загрузить(строка)
        assert len(вышло) == 1, "%r -> %s" % (строка, вышло)


def test_many_per_line_keeps_the_provable_address():
    """Обратный контроль: схлопывание — это ВЫБОР, а не «берём первый».

    Без него проверка выше была бы зелёной и в том случае, если бы код
    просто отбрасывал всё, кроме первого куска.
    """
    assert загрузить("corp@precon.com, personal@gmail.com") == [
        "personal@gmail.com"]


def test_many_per_line_control_a_single_address_stays_single():
    """Контроль: обычная строка по-прежнему даёт ровно один адрес."""
    assert загрузить("ivan@gmail.com") == ["ivan@gmail.com"]


def test_many_per_line_control_display_name_is_not_split():
    """Контроль: «Имя <адрес>» не разрезается на куски.

    Здесь адрес один, и разбор обязан отдать его целиком, а не выковырять
    из скобок половину.
    """
    assert загрузить("Ivan Petrov <a@x.com>") == ["a@x.com"]


# ══════════════════════ G5: алиасы Яндекса ══════════════════════════════

def test_yandex_alias_domains_collapse():
    """Все домены Яндекса — один ящик."""
    ключ = normalize_for_dedup("ivan@yandex.ru")
    for домен in ("ya.ru", "yandex.com", "yandex.by", "yandex.kz",
                  "yandex.ua", "narod.ru"):
        assert normalize_for_dedup("ivan@" + домен) == ключ, домен


def test_yandex_alias_control_dots_stay_significant():
    """Контроль: точки у Яндекса значащие, в отличие от Gmail.

    Схлопнув их, мы склеили бы двух разных людей, и один перестал бы
    получать письма вовсе.
    """
    assert normalize_for_dedup("ivan.p@ya.ru") != normalize_for_dedup("ivanp@ya.ru")
    assert normalize_for_dedup("ivan.p@gmail.com") == normalize_for_dedup("ivanp@gmail.com")


def test_yandex_alias_control_mailru_domains_are_different_mailboxes():
    """Контроль: bk.ru, list.ru и inbox.ru — РАЗНЫЕ ящики.

    На них регистрируются отдельно, и один логин принадлежит разным людям.
    Схлопнув их «за компанию», мы потеряли бы три четверти таких контактов.
    """
    ключи = {normalize_for_dedup("ivan@" + д)
             for д in ("mail.ru", "bk.ru", "list.ru", "inbox.ru")}
    assert len(ключи) == 4, ключи


# ══════════════════════ G6: формы Unicode ═══════════════════════════════

СОСТАВНОЙ = "jos" + chr(0x65) + chr(0x301) + "@gmail.com"
ГОТОВЫЙ = "jos" + chr(0xE9) + "@gmail.com"


def test_nfc_two_spellings_are_one_mailbox():
    """Два написания одного ящика дают один ключ."""
    assert СОСТАВНОЙ != ГОТОВЫЙ, "проба выродилась: строки и так равны"
    assert normalize_for_dedup(СОСТАВНОЙ) == normalize_for_dedup(ГОТОВЫЙ)


def test_nfc_control_the_loaded_string_is_not_rewritten_beyond_the_form():
    """Контроль: наружу уходит адрес, а не что-то другое.

    NFC — форма записи, которую требует RFC 6532 §3.1 для международных
    адресов. Она меняет байты, но не ящик: `é` остаётся `é`.
    """
    вышло = to_nfc(СОСТАВНОЙ)
    assert вышло == ГОТОВЫЙ
    assert вышло.split("@")[1] == "gmail.com", "домен не тронут"


def test_nfc_control_ascii_addresses_are_byte_identical():
    """Контроль: обычный адрес после приведения не меняется ни на байт."""
    for адрес in ("ivan@gmail.com", "John.Smith@corp.test", "a+tag@x.com"):
        assert normalize_input(адрес) == адрес, адрес


# ══════════════════════ G7: полноширинные знаки ═════════════════════════

def test_fullwidth_address_is_accepted_now():
    """Живой gmail в японской раскладке больше не хоронится."""
    вход = "ｉｖａｎ＠ｇｍａｉｌ．ｃｏｍ"
    assert fold_fullwidth(вход) == "ivan@gmail.com"
    assert загрузить(вход) == ["ivan@gmail.com"]
    assert validate_email_syntax(normalize_input(вход)) is True


def test_fullwidth_dot_in_domain_is_folded():
    """Полноширинная точка становится обычной.

    Раньше она ПРИНИМАЛАСЬ синтаксисом, а DNS такого домена не находил —
    адрес уезжал в «мёртвый домен» вместо подсказки про опечатку.
    """
    вход = "ivan@gmail" + chr(0xFF0E) + "com"
    assert fold_fullwidth(вход) == "ivan@gmail.com"


def test_fullwidth_control_other_non_ascii_is_untouched():
    """Контроль: кириллица, умляуты и прочее не-ASCII не трогаются.

    Они ЗНАЧАЩИЕ. Правило узкое — только диапазон, который однозначно
    отображается в ASCII.
    """
    for адрес in ("иван@почта.рф", "müller@bücher.de", "日本@example.jp"):
        assert fold_fullwidth(адрес) == адрес, адрес


# ══════════════════════ G8: невидимые знаки ═════════════════════════════

def test_invisible_inside_the_address_is_stripped():
    """Невидимое снимается по ВСЕЙ строке, а не только по краям."""
    for код in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x202E, 0x00AD, 0x2066):
        вход = "iv" + chr(код) + "an@gmail.com"
        assert strip_invisible(вход) == "ivan@gmail.com", hex(код)
        assert загрузить(вход) == ["ivan@gmail.com"], hex(код)


def test_invisible_control_visible_characters_survive():
    """Контроль: видимые знаки не трогаются.

    Слишком широкая чистка резала бы законные адреса — дефис, точка и плюс
    входят в atext по RFC 5322 §3.2.3.
    """
    for адрес in ("a-b.c+tag@x-y.com", "иван@почта.рф", "a_b@x.com"):
        assert strip_invisible(адрес) == адрес, адрес


# ══════════════════════ G9: URL и HTML кодировка ════════════════════════

def test_decode_url_and_html_entities():
    """Адрес, скопированный со страницы или из журнала, читается."""
    assert normalize_input("ivan%40gmail.com") == "ivan@gmail.com"
    assert normalize_input("ivan&#64;gmail.com") == "ivan@gmail.com"
    assert загрузить("ivan%40gmail.com") == ["ivan@gmail.com"]


def test_decode_control_a_legal_percent_is_not_touched():
    """Контроль: `%` входит в atext по RFC 5322 §3.2.3.

    `a%b@corp.com` — нормальный ящик. Раскрыв его, мы адресовали бы ДРУГОЙ.
    """
    assert normalize_input("a%b@corp.com") == "a%b@corp.com"
    assert normalize_input("100%25@corp.com") == "100%25@corp.com"


def test_decode_control_decoding_only_when_it_yields_one_at_sign():
    """Контроль: раскрытие идёт, только если получился ОДИН адрес.

    Строка без собаки, где раскрытие дало бы две, — это не адрес, и
    угадывать за владельца нечего.
    """
    assert normalize_input("a%40b%40c.com") == "a%40b%40c.com"


# ══════════════════════ сквозной контроль ═══════════════════════════════

def test_nothing_is_rewritten_that_should_not_be():
    """Обычные адреса проходят весь вход БЕЗ единого изменения.

    Главный контроль всего захода. Владелец запрещал переписывать его
    данные, и девять правок трогают именно вход — место, где легче всего
    незаметно испортить всю базу.
    """
    обычные = [
        "sachinjaiswal.ca@gmail.com", "John.Smith@corp-example.com",
        "a-b.c+tag@x-y.co.uk", "user@sky.company.co.uk",
        "a%b@corp.com", "иван@почта.рф", "12345678@qq.com",
        "o'brien@corp.test", "a_b@x.com", "postmaster@gmail.com",
    ]
    изменённые = [а for а in обычные if normalize_input(а) != а]
    assert not изменённые, "приведение переписало обычные адреса: %s" % изменённые


def test_cleaner_still_repairs_glue_and_never_swaps_domains():
    """Контроль: прежние правила очистки целы.

    Приведение входа встало ПЕРЕД очисткой, и сломать её этим было бы легко.
    """
    cleaner = EmailCleaner()
    for адрес in ("user@sky.company.co.uk", "b@aol.company.com",
                  "a@geometrixx.info", "d@list.ru-company.com"):
        assert cleaner.correct_and_normalize(адрес) == адрес, адрес
    assert cleaner.correct_and_normalize("u@gmail.comtelefoon") == "u@gmail.com"
    assert cleaner.correct_and_normalize("z@corp.com-jobs") == "z@corp.com"
