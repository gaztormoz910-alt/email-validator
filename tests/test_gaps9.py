# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cleaner import EmailCleaner, normalize_for_dedup
from core.email_syntax import validate_email_syntax
from core.inputnorm import (fold_fullwidth, normalize_input,
                            split_addresses, strip_invisible, to_nfc)
from core.mxguard import (filter_mx_hosts, is_ip_literal,
                          resolves_to_private)
from core.network import NetworkValidator
from core.streamer import StreamLoader


def загрузить(текст):
    return [e for e, _ in StreamLoader(
        [{"type": "text", "content": текст + "\n"}]).stream_emails()]


ВНУТРЕННИЕ = ["127.0.0.1", "10.0.0.5", "192.168.1.50", "172.16.0.1",
              "169.254.1.1", "0.0.0.0", "::1", "fc00::1"]


def test_mx_private_every_internal_range_is_refused():
    пропущенные = [а for а in ВНУТРЕННИЕ
                   if not resolves_to_private("mx.test", resolve=lambda h: [а])]
    assert not пропущенные, "внутренние адреса пропущены: %s" % пропущенные


def test_mx_private_the_hole_is_closed_end_to_end():
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
    годные, отвергнутые = filter_mx_hosts(
        ["mx.corp.test"], resolve=lambda h: ["93.184.216.34"])
    assert годные == ["mx.corp.test"], (годные, отвергнутые)


def test_mx_private_control_resolver_failure_does_not_condemn():
    def падает(host):
        raise OSError("резолвер молчит")

    assert resolves_to_private("mx.corp.test", resolve=падает) is False


def test_mx_private_rejected_hosts_are_named():
    _годные, отвергнутые = filter_mx_hosts(
        ["10.0.0.1"], resolve=lambda h: [])
    assert отвергнутые and отвергнутые[0][0] == "10.0.0.1"
    assert len(отвергнутые[0][1]) > 30, "причина не названа словами"


def test_mx_is_ip_literal_is_refused():
    for адрес in ("93.184.216.34", "2001:db8::1", "[192.168.1.1]"):
        assert is_ip_literal(адрес) is True, адрес


def test_mx_is_ip_control_hostnames_are_not_mistaken_for_ips():
    for имя in ("mx.gmail.com", "aspmx.l.google.com", "1.2.3.mx.corp.test",
                "mail.192.168.corp.test"):
        assert is_ip_literal(имя) is False, имя


def test_wildcard_is_detected_and_a_fallback_refused():
    объект = _носитель_dns(отвечает_всем=True)
    assert объект._is_wildcard_domain("wild.test") is True


def test_wildcard_control_a_normal_domain_is_not_wildcard():
    объект = _носитель_dns(отвечает_всем=False)
    assert объект._is_wildcard_domain("corp.test") is False


def test_wildcard_control_resolver_failure_is_not_wildcard():
    объект = _носитель_dns(отвечает_всем=False, падает=True)
    assert объект._is_wildcard_domain("corp.test") is False


def _носитель_dns(отвечает_всем, падает=False):
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


def test_many_per_line_collapses_to_one_person():
    for строка in ("a@x.com, b@y.com",
                   "a@x.com b@y.com c@z.com",
                   "a@x.com;b@y.com"):
        вышло = загрузить(строка)
        assert len(вышло) == 1, "%r -> %s" % (строка, вышло)


def test_many_per_line_keeps_the_provable_address():
    assert загрузить("corp@precon.com, personal@gmail.com") == [
        "personal@gmail.com"]


def test_many_per_line_control_a_single_address_stays_single():
    assert загрузить("ivan@gmail.com") == ["ivan@gmail.com"]


def test_many_per_line_control_display_name_is_not_split():
    assert загрузить("Ivan Petrov <a@x.com>") == ["a@x.com"]


def test_yandex_alias_domains_collapse():
    ключ = normalize_for_dedup("ivan@yandex.ru")
    for домен in ("ya.ru", "yandex.com", "yandex.by", "yandex.kz",
                  "yandex.ua", "narod.ru"):
        assert normalize_for_dedup("ivan@" + домен) == ключ, домен


def test_yandex_alias_control_dots_stay_significant():
    assert normalize_for_dedup("ivan.p@ya.ru") != normalize_for_dedup("ivanp@ya.ru")
    assert normalize_for_dedup("ivan.p@gmail.com") == normalize_for_dedup("ivanp@gmail.com")


def test_yandex_alias_control_mailru_domains_are_different_mailboxes():
    ключи = {normalize_for_dedup("ivan@" + д)
             for д in ("mail.ru", "bk.ru", "list.ru", "inbox.ru")}
    assert len(ключи) == 4, ключи


СОСТАВНОЙ = "jos" + chr(0x65) + chr(0x301) + "@gmail.com"
ГОТОВЫЙ = "jos" + chr(0xE9) + "@gmail.com"


def test_nfc_two_spellings_are_one_mailbox():
    assert СОСТАВНОЙ != ГОТОВЫЙ, "проба выродилась: строки и так равны"
    assert normalize_for_dedup(СОСТАВНОЙ) == normalize_for_dedup(ГОТОВЫЙ)


def test_nfc_control_the_loaded_string_is_not_rewritten_beyond_the_form():
    вышло = to_nfc(СОСТАВНОЙ)
    assert вышло == ГОТОВЫЙ
    assert вышло.split("@")[1] == "gmail.com", "домен не тронут"


def test_nfc_control_ascii_addresses_are_byte_identical():
    for адрес in ("ivan@gmail.com", "John.Smith@corp.test", "a+tag@x.com"):
        assert normalize_input(адрес) == адрес, адрес


def test_fullwidth_address_is_accepted_now():
    вход = "ｉｖａｎ＠ｇｍａｉｌ．ｃｏｍ"
    assert fold_fullwidth(вход) == "ivan@gmail.com"
    assert загрузить(вход) == ["ivan@gmail.com"]
    assert validate_email_syntax(normalize_input(вход)) is True


def test_fullwidth_dot_in_domain_is_folded():
    вход = "ivan@gmail" + chr(0xFF0E) + "com"
    assert fold_fullwidth(вход) == "ivan@gmail.com"


def test_fullwidth_control_other_non_ascii_is_untouched():
    for адрес in ("иван@почта.рф", "müller@bücher.de", "日本@example.jp"):
        assert fold_fullwidth(адрес) == адрес, адрес


def test_invisible_inside_the_address_is_stripped():
    for код in (0x200B, 0x200C, 0x200D, 0xFEFF, 0x202E, 0x00AD, 0x2066):
        вход = "iv" + chr(код) + "an@gmail.com"
        assert strip_invisible(вход) == "ivan@gmail.com", hex(код)
        assert загрузить(вход) == ["ivan@gmail.com"], hex(код)


def test_invisible_control_visible_characters_survive():
    for адрес in ("a-b.c+tag@x-y.com", "иван@почта.рф", "a_b@x.com"):
        assert strip_invisible(адрес) == адрес, адрес


def test_decode_url_and_html_entities():
    assert normalize_input("ivan%40gmail.com") == "ivan@gmail.com"
    assert normalize_input("ivan&#64;gmail.com") == "ivan@gmail.com"
    assert загрузить("ivan%40gmail.com") == ["ivan@gmail.com"]


def test_decode_control_a_legal_percent_is_not_touched():
    assert normalize_input("a%b@corp.com") == "a%b@corp.com"
    assert normalize_input("100%25@corp.com") == "100%25@corp.com"


def test_decode_control_decoding_only_when_it_yields_one_at_sign():
    assert normalize_input("a%40b%40c.com") == "a%40b%40c.com"


def test_nothing_is_rewritten_that_should_not_be():
    обычные = [
        "vikramsethi.ca@gmail.com", "John.Smith@corp-example.com",
        "a-b.c+tag@x-y.co.uk", "user@sky.company.co.uk",
        "a%b@corp.com", "иван@почта.рф", "12345678@qq.com",
        "o'brien@corp.test", "a_b@x.com", "postmaster@gmail.com",
    ]
    изменённые = [а for а in обычные if normalize_input(а) != а]
    assert not изменённые, "приведение переписало обычные адреса: %s" % изменённые


def test_cleaner_still_repairs_glue_and_never_swaps_domains():
    cleaner = EmailCleaner()
    for адрес in ("user@sky.company.co.uk", "b@aol.company.com",
                  "a@geometrixx.info", "d@list.ru-company.com"):
        assert cleaner.correct_and_normalize(адрес) == адрес, адрес
    assert cleaner.correct_and_normalize("u@gmail.comtelefoon") == "u@gmail.com"
    assert cleaner.correct_and_normalize("z@corp.com-jobs") == "z@corp.com"
