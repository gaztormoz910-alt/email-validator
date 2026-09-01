"""Тесты второго прохода по временным отказам.

Смысл: Unknown бывает двух видов. Одно дело «сервер сказал, что не знает» —
это вердикт. Другое дело «у нас сдох прокси / словили лимит» — это сбой НАШЕЙ
стороны, и повтор другим прокси через паузу часто даёт однозначный ответ.
Повторять надо только второе, иначе прогон растянется впустую.
"""
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.pipeline import _is_transient_failure


class TestTransientDetection(unittest.TestCase):
    RETRY = [
        "Timeout",
        "Proxy Dead",
        "Server Disconnected",
        "SMTP Connect Error",
        "421 Service Busy (Rate Limit)",
        "450 Rate Limited (Retry Later)",
        "450 Temp Unavailable",
        "452 Temp Error",
        "550 Our IP Blocked (Email May Exist)",
        "554 Our IP Blacklisted (Email May Exist)",
        "All Proxies Dead (прямое соединение запрещено)",
        "Timeout: адрес проверялся дольше 60с",
    ]

    NO_RETRY_REASONS = [
        "Catch-All Domain (Unverifiable)",
        "550 Нет обратного DNS у нашего IP (FCrDNS) — Yahoo/AOL не пускают",
    ]

    def test_transient_failures_are_retried(self):
        missed = [r for r in self.RETRY if not _is_transient_failure("unknown", r)]
        self.assertEqual(missed, [], f"не помечены как временные: {missed}")

    def test_permanent_unknowns_are_not_retried(self):
        for reason in self.NO_RETRY_REASONS:
            with self.subTest(reason=reason):
                self.assertFalse(_is_transient_failure("unknown", reason))

    def test_verdicts_are_not_retried(self):
        # Вердикт уже есть — повторять нечего, иначе прогон удвоится впустую.
        # greylisted тоже не здесь: у него своя очередь и своя выдержка.
        for status in ("valid", "invalid", "catchall", "greylisted"):
            with self.subTest(status=status):
                self.assertFalse(_is_transient_failure(status, "Timeout"))

    def test_risky_from_our_own_failure_is_retried(self):
        """risky бывает двух видов, и это РАЗНЫЕ вещи.

        Отказ по репутации нашего IP приходит как unknown, но шаг
        «DNS-здоровье» повышает его до risky у любого домена с SPF или
        DMARC — то есть почти у всякого. Про ящик при этом не сказано
        ничего, и повтор с другого выходного адреса нужен ровно так же.
        Пока сюда пускали только unknown, самые восстановимые отказы не
        повторялись никогда.
        """
        assert _is_transient_failure(
            "risky", "5.7.1 550 Отказ по политике/репутации IP "
                     "(ящик может существовать) [DNS: SPF=✓, DMARC=✓, DKIM=✗]")
        # А risky, добытый ответом сервера, повторять нечего: это уже суждение
        # о ящике, а не о нашем прокси.
        self.assertFalse(_is_transient_failure(
            "risky", "Второй ответ противоречит первому: адрес отвергли с "
                     "одного выхода и приняли с другого."))

    def test_unrecognised_reason_is_not_retried(self):
        # Незнакомая причина — не гадаем, повтор стоит времени
        self.assertFalse(_is_transient_failure("unknown", "какая-то новая причина"))

    def test_degenerate_input(self):
        for reason in ("", None):
            with self.subTest(reason=reason):
                self.assertFalse(_is_transient_failure("unknown", reason))


if __name__ == '__main__':
    unittest.main()
