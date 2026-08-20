"""Тесты классификации SMTP-ответов.

Главный инвариант: живой ящик НИКОГДА не должен попасть в "invalid" из-за проблем
с нашей стороны (репутация прокси, отказ отправителю, ошибка авторизации, кривой
ответ сервера). Ошибаться безопаснее в сторону risky/unknown, чем хоронить лид.
"""
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.network import NetworkValidator


class TestSMTPResponseParsing(unittest.TestCase):
    def setUp(self):
        self.v = NetworkValidator(timeout=3)

    def parse(self, code, msg):
        return self.v._parse_smtp_response(code, msg, "user@corp.com", "corp.com")

    # --- Должны оставаться VALID ---

    def test_250_is_valid(self):
        self.assertEqual(self.parse(250, b"2.1.5 OK")["status"], "valid")

    def test_full_mailbox_is_valid(self):
        # Переполненный ящик = ящик существует и активно используется
        self.assertEqual(self.parse(452, b"4.2.2 Mailbox full")["status"], "valid")
        self.assertEqual(self.parse(552, b"5.2.2 Over quota")["status"], "valid")

    # --- Должны оставаться INVALID (настоящие bounce) ---

    def test_user_does_not_exist_is_invalid(self):
        for m in [b"5.1.1 User unknown",
                  b"5.1.1 <a@b.com>: Recipient address rejected: User unknown",
                  b"550 No such user here",
                  b"550 5.1.1 The email account that you tried to reach does not exist",
                  b"550 Invalid recipient",
                  b"550 Mailbox unavailable"]:
            with self.subTest(msg=m):
                self.assertEqual(self.parse(550, m)["status"], "invalid")

    # --- НЕ должны становиться INVALID (главный фикс) ---

    def test_our_ip_blocked_is_not_invalid(self):
        for m in [b"550 Your IP is blocked",
                  b"550 Client host rejected due to reputation",
                  b"550 Blocked by spamhaus",
                  b"554 Your IP is blacklisted"]:
            with self.subTest(msg=m):
                self.assertNotEqual(self.parse(550 if b"550" in m else 554, m)["status"], "invalid")

    def test_sender_rejection_is_not_invalid(self):
        # Отказ ОТПРАВИТЕЛЮ ничего не говорит о получателе
        for m in [b"550 Sender verify failed",
                  b"550 Unable to relay",
                  b"550 Relaying denied",
                  b"550 SPF check failed",
                  b"550 Authentication required",
                  b"550 Sender address not permitted"]:
            with self.subTest(msg=m):
                self.assertNotEqual(self.parse(550, m)["status"], "invalid")

    def test_bare_550_is_not_invalid(self):
        # Голый "550 Rejected" через прокси — чаще отказ по IP, чем мёртвый ящик
        self.assertNotEqual(self.parse(550, b"550 Rejected")["status"], "invalid")

    def test_protocol_and_auth_5xx_are_not_invalid(self):
        # Ни один из этих кодов не означает "получателя не существует"
        for code in (500, 501, 502, 503, 504, 521, 530, 535, 571):
            with self.subTest(code=code):
                self.assertNotEqual(self.parse(code, b"Error")["status"], "invalid")

    def test_unknown_5xx_is_not_invalid(self):
        self.assertNotEqual(self.parse(599, b"Weird permanent error")["status"], "invalid")

    def test_temporary_4xx_is_not_invalid(self):
        for code in (421, 450, 451, 452):
            with self.subTest(code=code):
                self.assertNotEqual(self.parse(code, b"Try again later")["status"], "invalid")

    def test_account_disabled_is_risky_not_invalid(self):
        self.assertEqual(self.parse(550, b"550 Account disabled")["status"], "risky")


if __name__ == '__main__':
    unittest.main()
