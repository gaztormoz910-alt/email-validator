"""Длины адреса считаются в БАЙТАХ, а не в символах.

RFC 5321 §4.5.3.1 задаёт пределы в октетах: локальная часть до 64, домен до
255, всё вместе до 320. Разница не теоретическая: кириллическое имя из сорока
букв укладывается в лимит по символам и вылетает по байтам, а строка из
трёхсот кириллических букв — это шестьсот октетов, то есть вдвое больше
допустимого.

Раньше здесь стоял `len(email)`, то есть счёт СИМВОЛОВ, и:

* слишком длинный интернационализированный адрес проходил проверку синтаксиса,
  чтобы получить отказ уже от сервера;
* проверки локальной части и домена по отдельности не было вовсе — она
  держалась только на регулярке, которая ничего не знает про punycode-длину.

Отдельный файл, потому что это единственный вердикт, который ставится вообще
без обращения к сети, и ошибка в нём тише всех прочих.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.email_syntax import (MAX_DOMAIN_BYTES, MAX_EMAIL_BYTES,
                               MAX_LOCAL_BYTES, has_non_ascii_local,
                               to_ascii_domain, validate_email_syntax)


class TestByteLimits(unittest.TestCase):
    def test_ascii_address_within_limits_passes(self):
        self.assertTrue(validate_email_syntax("john.doe@example.com"))

    def test_local_part_at_the_byte_limit_passes(self):
        local = "a" * MAX_LOCAL_BYTES
        self.assertTrue(validate_email_syntax(f"{local}@example.com"))

    def test_local_part_one_byte_over_fails(self):
        local = "a" * (MAX_LOCAL_BYTES + 1)
        self.assertFalse(validate_email_syntax(f"{local}@example.com"))

    def test_cyrillic_local_part_is_measured_in_bytes(self):
        """Тридцать три кириллические буквы — 66 октетов, то есть перебор.

        По символам они укладываются в лимит 64, и старая проверка их
        пропускала. Это и есть та самая разница между символами и байтами.
        """
        local = "и" * 33                      # 66 байт в UTF-8
        self.assertGreater(len(local.encode("utf-8")), MAX_LOCAL_BYTES)
        self.assertLess(len(local), MAX_LOCAL_BYTES)
        self.assertFalse(validate_email_syntax(f"{local}@example.com"))

    def test_cyrillic_local_part_within_byte_limit_passes(self):
        """Положительный контроль: тот же адрес короче — обязан пройти.

        Без него предыдущая проверка была бы зелёной и в том случае, если
        кириллица режется целиком — то есть ровно из-за той ошибки, от
        которой этот файл и защищает.
        """
        local = "и" * 20                      # 40 байт
        self.assertTrue(validate_email_syntax(f"{local}@example.com"))

    def test_whole_address_over_320_bytes_fails(self):
        # 200 кириллических букв = 400 байт: по символам меньше 320, по байтам больше
        local = "я" * 60
        domain = "пример" * 20 + ".рф"
        address = f"{local}@{domain}"
        self.assertLess(len(address), MAX_EMAIL_BYTES)
        self.assertGreater(len(address.encode("utf-8")), MAX_EMAIL_BYTES)
        self.assertFalse(validate_email_syntax(address))

    def test_domain_over_255_bytes_in_punycode_fails(self):
        # Каждая метка до 63 символов; собираем длинный, но синтаксически
        # правильный домен, чей punycode-вид перебирает лимит.
        label = "a" * 60
        domain = ".".join([label] * 5) + ".com"
        self.assertGreater(len(domain.encode("utf-8")), MAX_DOMAIN_BYTES)
        self.assertFalse(validate_email_syntax(f"user@{domain}"))


class TestInternationalAddressesSurvive(unittest.TestCase):
    """Не-ASCII не означает «адрес неправильный» — это главный смысл файла."""

    LIVE = [
        "иван@почта.рф",
        "müller@bücher.de",
        "θεοδώρα@παράδειγμα.δοκιμή",
        "用户@例子.广告",
        "user@münchen.de",
        "josé@españa.es",
    ]

    def test_international_addresses_are_valid(self):
        for address in self.LIVE:
            with self.subTest(address=address):
                self.assertTrue(validate_email_syntax(address),
                                f"{address} признан битым — это ложный invalid")

    def test_idn_domain_converts_to_punycode(self):
        self.assertEqual(to_ascii_domain("почта.рф"), "xn--80a1acny.xn--p1ai")
        self.assertEqual(to_ascii_domain("bücher.de"), "xn--bcher-kva.de")
        self.assertEqual(to_ascii_domain("example.com"), "example.com")

    def test_non_ascii_local_is_detected(self):
        self.assertTrue(has_non_ascii_local("иван@example.com"))
        self.assertFalse(has_non_ascii_local("ivan@почта.рф"))
        self.assertFalse(has_non_ascii_local("ivan@example.com"))


class TestBrokenAddressesStillFail(unittest.TestCase):
    """Ослабление лимитов не должно пропускать настоящий мусор."""

    BROKEN = [
        "", "   ", "@", "a@", "@b.com", "a@b", "a b@example.com",
        "a..b@example.com", ".a@example.com", "a.@example.com",
        "a@@example.com", "a@b@c.com", "a@.example.com", "a@example..com",
        "a@example.com.", "\x00@example.com",
    ]

    def test_broken_addresses_are_rejected(self):
        for address in self.BROKEN:
            with self.subTest(address=address):
                self.assertFalse(validate_email_syntax(address))

    def test_garbage_types_do_not_crash(self):
        for junk in (None, 0, [], {}, b"a@b.com", object(), 3.5):
            with self.subTest(junk=junk):
                self.assertFalse(validate_email_syntax(junk))


if __name__ == "__main__":
    unittest.main()
