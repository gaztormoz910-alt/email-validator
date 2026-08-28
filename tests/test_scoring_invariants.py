"""Три правила скоринга, нарушение которых портит базу молча.

Скор — единственное число, по которому владелец решает, кому писать. Ошибка
здесь не видна ни в логе, ни в статусе: адрес остаётся Valid, но получает
grade «Dead» и выпадает из выгрузки по порогу.

Правила, за которыми следит этот файл:

1. **Вердикт SMTP весит больше всех прочих сигналов вместе.** Он —
   единственное прямое доказательство; всё остальное про ДОМЕН и СЕРВЕР, а у
   бесплатных провайдеров этих баллов взять неоткуда.
2. **«Не проверено» не штрафуется.** `None` («спросить не удалось») и `False`
   («записи точно нет») — разные вещи, и схлопывать их значит наказывать
   адрес за сбой на нашей стороне.
3. **Подтверждённый Invalid обнуляет всё.** Живой gmail.com не делает
   несуществующий ящик на нём хоть сколько-нибудь живым.

Плюс отдельная проверка на словарь имён статусов: движок говорит `valid`,
окно показывает `Valid`, и скоринг обязан понимать оба. Пока он понимал
только второй, любой вызов из REST API или консоли молча давал ноль.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.scoring import DEFAULT_WEIGHTS, calculate_engagement_score

ALIVE = "a@gmail.com"


def score(**kwargs):
    kwargs.setdefault("email", ALIVE)
    return calculate_engagement_score(**kwargs)


class TestSmtpVerdictOutweighsEverything(unittest.TestCase):
    def test_smtp_valid_beats_all_domain_signals_combined(self):
        only_smtp = score(smtp_status="valid")["score"]
        only_domain = score(
            smtp_status="unknown", has_gravatar=True, dns_health_score=3,
            domain_age_days=4000, name_extracted="John Smith",
            has_ptr=True, has_starttls=True)["score"]
        self.assertGreater(
            only_smtp, only_domain - DEFAULT_WEIGHTS["smtp_unknown"],
            "сигналы домена перевешивают прямое доказательство от сервера")

    def test_confirmed_live_mailbox_is_not_cold(self):
        """Подтверждённый живой Gmail без прочих сигналов не должен быть «Dead»."""
        result = score(smtp_status="valid")
        self.assertGreaterEqual(result["score"], 50)
        self.assertNotIn(result["grade"], ("Dead", "Cold"))

    def test_full_inbox_scores_above_plain_ok(self):
        """Переполненный ящик доказывает не только существование, но и жизнь."""
        plain = score(smtp_status="valid", smtp_reason="2.1.5 250 OK")["score"]
        full = score(smtp_status="valid",
                     smtp_reason="4.2.2 452 Ящик существует и переполнен")["score"]
        self.assertGreater(full, plain)

    def test_full_inbox_recognised_in_both_wordings(self):
        """Причина бывает и на английском (старый кэш), и на русском."""
        for reason in ("250 OK (Full Inbox)", "452 OK (Mailbox Full)",
                       "5.2.2 Over quota", "5.2.2 552 Ящик существует и переполнен",
                       "4.2.2 452 Ящик существует и переполнен"):
            with self.subTest(reason=reason):
                self.assertEqual(
                    score(smtp_status="valid", smtp_reason=reason)["score"],
                    DEFAULT_WEIGHTS["smtp_valid_full_inbox"])


class TestUncheckedIsNotPunished(unittest.TestCase):
    def test_unknown_ptr_costs_nothing(self):
        unchecked = score(smtp_status="valid", has_ptr=None)["score"]
        confirmed_absent = score(smtp_status="valid", has_ptr=False)["score"]
        self.assertGreater(
            unchecked, confirmed_absent,
            "«PTR проверить не удалось» штрафуется наравне с «PTR точно нет»")

    def test_unknown_domain_age_costs_nothing(self):
        unknown = score(smtp_status="valid", domain_age_days=-1)["score"]
        young = score(smtp_status="valid", domain_age_days=10)["score"]
        self.assertGreater(unknown, young)


class TestConfirmedInvalidZeroesEverything(unittest.TestCase):
    def test_perfect_domain_does_not_save_a_dead_mailbox(self):
        result = score(smtp_status="invalid", has_gravatar=True,
                       dns_health_score=3, domain_age_days=4000,
                       name_extracted="John Smith", has_ptr=True,
                       has_starttls=True)
        self.assertEqual(result["score"], 0)
        self.assertEqual(result["grade"], "Dead")

    def test_display_wording_behaves_the_same(self):
        engine = score(smtp_status="invalid", has_gravatar=True)
        window = score(smtp_status="Invalid/Bounce", has_gravatar=True)
        self.assertEqual(engine["score"], window["score"])
        self.assertEqual(engine["score"], 0)


class TestStatusVocabulariesAgree(unittest.TestCase):
    """Движок и окно называют один вердикт по-разному — понимать надо оба."""

    PAIRS = [("valid", "Valid"), ("invalid", "Invalid/Bounce"),
             ("risky", "Risky"), ("unknown", "Unknown")]

    def test_same_score_for_both_names(self):
        for engine, window in self.PAIRS:
            with self.subTest(pair=(engine, window)):
                self.assertEqual(score(smtp_status=engine)["score"],
                                 score(smtp_status=window)["score"])

    def test_engine_wording_is_not_silently_zero(self):
        """Контроль: до починки вердикт движка давал ноль на всех статусах."""
        self.assertGreater(score(smtp_status="valid")["score"], 0)
        self.assertGreater(score(smtp_status="risky")["score"], 0)
        self.assertGreater(score(smtp_status="unknown")["score"], 0)

    def test_unknown_vocabulary_does_not_become_valid(self):
        """Чужое имя статуса не имеет права молча стать «живым»."""
        result = score(smtp_status="совершенно другое слово")
        self.assertLess(result["score"], DEFAULT_WEIGHTS["smtp_valid"])

    def test_garbage_status_does_not_crash(self):
        for junk in (None, 0, [], {}, 3.5, b"valid"):
            with self.subTest(junk=junk):
                result = score(smtp_status=junk)
                self.assertIsInstance(result["score"], int)
                self.assertGreaterEqual(result["score"], 0)
                self.assertLessEqual(result["score"], 100)


class TestScoreStaysInRange(unittest.TestCase):
    def test_every_combination_is_bounded(self):
        combos = [
            dict(smtp_status="valid", has_gravatar=True, dns_health_score=3,
                 domain_age_days=9000, name_extracted="A B", has_ptr=True,
                 has_starttls=True),
            dict(smtp_status="invalid", is_disposable=True, in_dnsbl=True,
                 is_role_based=True, server_outdated=True, has_ptr=False,
                 has_starttls=False, has_live_website=False,
                 machine_generated=True, is_parked_domain=True),
            dict(smtp_status="unknown", is_disposable=True, in_dnsbl=True),
            dict(smtp_status="risky", domain_age_days=1),
        ]
        for kwargs in combos:
            with self.subTest(kwargs=sorted(kwargs)):
                result = score(**kwargs)
                self.assertGreaterEqual(result["score"], 0)
                self.assertLessEqual(result["score"], 100)


if __name__ == "__main__":
    unittest.main()
