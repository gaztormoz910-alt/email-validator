"""Правила имени пользователя и спасение живых адресов от ложного invalid.

Гейты выбирают по -k: rules, junk, no_false_invalid, providers.

Главное, что здесь проверяется, — АСИММЕТРИЯ ошибок. Пропустить мёртвый адрес
в Risky неприятно, но поправимо; пометить живой адрес мёртвым — значит выкинуть
контакт навсегда. Поэтому почти все проверки ниже требуют, чтобы правило
понижало доверие, а не выносило приговор.

Данные для проверок взяты из трёх файлов владельца в data/testdata: это те же
адреса, которые он загружал в сервис конкурента, и их видно на скриншотах.
"""
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cleaner import EmailCleaner, strip_wrapping_junk, normalize_for_dedup
from core.local_rules import (check_local_part, has_rules, provider_of,
                              rule_count, IMPOSSIBLE, UNLIKELY, OK)
from core.network import (validate_email_syntax, NEEDS_CLEAN_IP_DOMAINS,
                          NICHE_FREE_DOMAINS)

TESTDATA = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "data", "testdata")


def owner_lines(name):
    path = os.path.join(TESTDATA, name)
    with io.open(path, encoding="utf-8", errors="ignore") as handle:
        return [line.strip() for line in handle if line.strip()]


class TestRules(unittest.TestCase):
    """Классификация имени: невозможное, сомнительное и обычное."""

    def test_rules_cover_major_providers(self):
        self.assertGreaterEqual(rule_count(), 50,
                                "правил слишком мало, чтобы они что-то решали")
        for domain in ("gmail.com", "yahoo.com", "icloud.com", "mail.ru",
                       "outlook.com", "zoho.com", "qq.com", "163.com", "naver.com"):
            with self.subTest(domain=domain):
                self.assertTrue(has_rules(domain))
                self.assertTrue(provider_of(domain))

    def test_rules_only_one_thing_is_impossible(self):
        """Без сети хороним ТОЛЬКО то, где исключений не бывает."""
        empty = check_local_part("@gmail.com")
        self.assertEqual(empty[0], IMPOSSIBLE, "пустое имя должно быть невозможным")

        # Длина сюда БОЛЬШЕ НЕ ОТНОСИТСЯ. Предел взят с нынешней страницы
        # помощи провайдера, а не из ответа сервера, и приговором служить не
        # может: одна неточность в таблице выбрасывала живые контакты целым
        # провайдером сразу.
        too_long = check_local_part("x" * 31 + "@gmail.com")
        self.assertEqual(too_long[0], UNLIKELY,
                         "имя длиннее предела — повод усомниться, а не хоронить")

    def test_rules_gmail_dots_do_not_count_towards_length(self):
        """У Gmail точки ничего не значат — и в длину входить не должны.

        j.o.h.n.d.o.e.s.m.i.t.h@gmail.com — это имя johndoesmith из
        одиннадцати знаков, записанное через точки. Письмо на него дойдёт.
        Меря длину по написанию, валидатор объявлял такой адрес мёртвым.
        """
        dotted = ".".join("johndoesmithjunior") + "@gmail.com"
        self.assertGreater(len(dotted.split("@")[0]), 30)
        self.assertEqual(check_local_part(dotted)[0], OK)

    def test_rules_short_name_is_only_unlikely(self):
        """Короткое имя — не приговор: старые аккаунты заводились до правила."""
        verdict, reason = check_local_part("ca@gmail.com")
        self.assertEqual(verdict, UNLIKELY,
                         "короткое имя Gmail объявлено невозможным — так можно "
                         "выбросить живой аккаунт эпохи беты")
        self.assertIn("6", reason)

    def test_rules_odd_characters_are_only_unlikely(self):
        """Подчёркивание у Gmail сейчас не выдают, но legacy-аккаунты живы."""
        verdict, _ = check_local_part("john_doe@gmail.com")
        self.assertEqual(verdict, UNLIKELY,
                         "адрес с подчёркиванием объявлен невозможным — это "
                         "ложный приговор живому legacy-аккаунту")

    def test_rules_normal_addresses_are_untouched(self):
        for email in ("john.doe@gmail.com", "sarah.jones91@outlook.com",
                      "ivan.petrov@mail.ru", "a.b.c@yandex.ru"):
            with self.subTest(email=email):
                self.assertEqual(check_local_part(email)[0], OK,
                                 f"обычный адрес {email} получил придирку")

    def test_rules_unknown_domain_is_never_judged(self):
        """Про чужой домен правил нет — и выдумывать их нельзя."""
        for email in ("a@corp-x.com", "x@sberbank.ru", "q@tesla.com"):
            with self.subTest(email=email):
                self.assertEqual(check_local_part(email), (OK, ""))

    def test_rules_plus_tag_is_judged_by_base_name(self):
        """john+news@ адресует ящик john@ — судить надо по нему."""
        self.assertEqual(check_local_part("johndoe+news@gmail.com")[0], OK)
        self.assertEqual(check_local_part("ca+tag@gmail.com")[0], UNLIKELY)

    def test_rules_survive_garbage(self):
        for junk in (None, 123, "", "no-at-sign", "a@b@c", [], {}):
            with self.subTest(junk=junk):
                verdict, reason = check_local_part(junk)
                self.assertIn(verdict, (OK, UNLIKELY, IMPOSSIBLE))
                self.assertIsInstance(reason, str)


class TestJunk(unittest.TestCase):
    """Мусор вокруг адреса счищается и не превращается в ложный invalid."""

    def test_junk_backtick_from_owner_file_is_repaired(self):
        """Из файла владельца: `hjohnuc@gmail.com конкурент считает живым."""
        raw = "`hjohnuc@gmail.com"
        # Обратная кавычка входит в atext RFC 5322 §3.2.3, поэтому синтаксис
        # такую строку пропускает — и правильно делает: приговор без сети
        # неисправим. Отсекает её правило Gmail (у него в имени только
        # латиница, цифры и точки), а до этого чистильщик просто убирает
        # мусорный символ и адрес становится нормальным.
        from core.local_rules import check_local_part, OK
        self.assertNotEqual(check_local_part(raw)[0], OK,
                            "правило Gmail обязано заметить чужой символ")
        cleaned = EmailCleaner().clean_email(raw)
        self.assertEqual(cleaned, "hjohnuc@gmail.com")
        self.assertTrue(validate_email_syntax(cleaned),
                        "адрес не спасён — живой контакт уйдёт в invalid")

    def test_junk_common_wrappers(self):
        cases = {
            "mailto:john.doe@gmail.com": "john.doe@gmail.com",
            "<john.doe@gmail.com>": "john.doe@gmail.com",
            '"john.doe@gmail.com"': "john.doe@gmail.com",
            "(john.doe@gmail.com),": "john.doe@gmail.com",
            "john.doe@gmail.com;": "john.doe@gmail.com",
            "﻿john.doe@gmail.com": "john.doe@gmail.com",
            "Ivan Petrov <ivan@corp.com>": "ivan@corp.com",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(strip_wrapping_junk(raw), expected)

    def test_junk_trailing_dot_is_repaired(self):
        """Из файла владельца: конкурент помечает такие Bad format, мы чиним."""
        for raw in ("andrewyin1994@gmail.com.", "ronganli.dev@gmail.com."):
            with self.subTest(raw=raw):
                cleaned = EmailCleaner().clean_email(raw)
                self.assertTrue(cleaned and validate_email_syntax(cleaned),
                                f"{raw} не восстановлен")
                self.assertFalse(cleaned.endswith("."))

    def test_junk_does_not_break_normal_addresses(self):
        """Негативный контроль: обычный адрес счистка не трогает."""
        for email in ("john.doe@gmail.com", "a+b@gmail.com", "x_y@corp.com",
                      "ivan@xn--80a1acny.xn--p1ai"):
            with self.subTest(email=email):
                self.assertEqual(strip_wrapping_junk(email), email.lower())

    def test_junk_survives_garbage(self):
        for junk in (None, 123, [], {}, b"x"):
            with self.subTest(junk=junk):
                self.assertEqual(strip_wrapping_junk(junk), "")


class TestNoFalseInvalid(unittest.TestCase):
    """На реальных файлах владельца ни один адрес не хоронится по синтаксису."""

    FILES = ("test_base.txt", "test_1.txt", "test.txt")

    def test_no_false_invalid_on_owner_files(self):
        cleaner = EmailCleaner()
        buried = []
        checked = 0
        for name in self.FILES:
            for raw in owner_lines(name):
                cleaned = cleaner.clean_email(raw)
                if not cleaned:
                    buried.append(f"{name}: {raw!r} -> очистка вернула пусто")
                    continue
                checked += 1
                if not validate_email_syntax(cleaned):
                    buried.append(f"{name}: {raw!r} -> {cleaned!r} не прошёл синтаксис")
        self.assertGreater(checked, 80, "проверено подозрительно мало адресов")
        self.assertEqual(buried, [],
                         "адреса из живых файлов владельца получают ложный invalid: "
                         + str(buried[:5]))

    def test_no_false_invalid_impossible_verdicts_are_rare(self):
        """Правило не имеет права хоронить заметную часть реальной базы."""
        cleaner = EmailCleaner()
        impossible = []
        total = 0
        for name in self.FILES:
            for raw in owner_lines(name):
                cleaned = cleaner.clean_email(raw)
                if not cleaned:
                    continue
                total += 1
                if check_local_part(cleaned)[0] == IMPOSSIBLE:
                    impossible.append(cleaned)
        self.assertEqual(impossible, [],
                         "правило объявило невозможными реальные адреса: "
                         + str(impossible[:5]))
        self.assertGreater(total, 80)

    def test_no_false_invalid_positive_control(self):
        """Контроль: заведомо битый адрес всё-таки обязан отбраковываться.

        Без этой проверки предыдущие две были бы зелёными и в том случае,
        когда синтаксическая проверка вообще перестала работать.
        """
        # Только НЕИСПРАВИМОЕ. Двойная точка сюда не годится: очистка чинит
        # её намеренно (karl....motiv -> karl.motiv), и это не брак, а ремонт.
        # Длина в контроле — РОВНО по RFC 5321 §4.5.3.1.1 (64 октета на имя
        # ящика), а не по таблице провайдера: правило провайдера приговором
        # больше не служит, и держать его здесь значило бы проверять контролем
        # то, чего код намеренно не делает.
        for bad in ("@gmail.com", "no-at-sign", "a@b", "a@", "@",
                    "x" * 65 + "@gmail.com", "ivan@почта", "a b@gmail.com"):
            with self.subTest(bad=bad):
                cleaned = EmailCleaner().clean_email(bad)
                rejected = (not cleaned
                            or not validate_email_syntax(cleaned)
                            or check_local_part(cleaned)[0] == IMPOSSIBLE)
                self.assertTrue(rejected, f"заведомо битый {bad!r} прошёл как годный")


class TestProviders(unittest.TestCase):
    """Нишевые почтовики и приватные relay обслуживаются осознанно."""

    def test_providers_private_relay_needs_clean_ip(self):
        """Private Relay сидит на инфраструктуре iCloud и режет так же."""
        self.assertIn("privaterelay.appleid.com", NEEDS_CLEAN_IP_DOMAINS,
                      "Private Relay проверяется грязным прокси — отказ по "
                      "репутации будет выглядеть как проблема ящика")

    def test_providers_niche_are_routed_with_clean_ip(self):
        for domain in ("qq.com", "163.com", "126.com", "naver.com", "foxmail.com"):
            with self.subTest(domain=domain):
                self.assertIn(domain, NEEDS_CLEAN_IP_DOMAINS,
                              f"{domain} строг к чужим IP, но ходит через любой прокси")

    def test_providers_niche_are_not_corporate(self):
        from core.provider import is_free_mail_domain
        for domain in ("zoho.com", "qq.com", "163.com", "naver.com"):
            with self.subTest(domain=domain):
                self.assertIn(domain, NICHE_FREE_DOMAINS)
                self.assertTrue(is_free_mail_domain(domain),
                                f"{domain} считается корпоративным и получает "
                                "бонус, которого нет у gmail.com")

    def test_providers_niche_have_local_rules(self):
        for domain in ("zoho.com", "qq.com", "163.com", "naver.com"):
            with self.subTest(domain=domain):
                self.assertTrue(has_rules(domain))

    def test_providers_gmail_still_needs_no_clean_ip(self):
        """Негативный контроль: Gmail отвечает честно любому IP, и это не менялось."""
        self.assertNotIn("gmail.com", NEEDS_CLEAN_IP_DOMAINS)


if __name__ == "__main__":
    unittest.main()
