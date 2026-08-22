"""Тесты эвристик «живой человек или машина» (энтропия + припаркованные домены).

Главный инвариант: НИ ОДИН реальный человеческий адрес не должен быть
помечен как машинный. Пропустить бота не страшно, оболгать живого — страшно.
"""
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.heuristics import looks_machine_generated, is_parked_domain, local_part_entropy


class TestMachineGenerated(unittest.TestCase):
    HUMAN = [
        "ivan.petrov@mail.com", "john.doe@gmail.com", "anna_maria@corp.com",
        "jsmith@acme.com", "alexander@gmail.com", "m.rodriguez@corp.es",
        "kovbinb@gmail.com", "olga1985@mail.ru", "support@company.com",
        "konstantin@mail.ru", "bogdankovbin@gmail.com", "grzegorzb@wp.pl",
        "christopher@gmail.com", "vladimirsky@yandex.ru", "mariacarmen@corp.es",
        "nguyenvanminh@gmail.com", "dmitrybrykin@mail.ru", "ekaterina1990@bk.ru",
        "info@company.com", "webmaster@site.org", "hanspeter@gmx.de",
    ]

    BOTS = [
        "xk3n9fj2q4@gmail.com", "a7f3k2m9x1@mail.com", "qwerty12345@mail.ru",
        "zxcvbnmasd@gmail.com", "k4m2x9f7q3b1@corp.com", "xkfjmqrstv@mail.com",
        "p9w3z8k1n5@mail.com",
    ]

    def test_no_false_positives_on_real_people(self):
        wrong = [e for e in self.HUMAN if looks_machine_generated(e)]
        self.assertEqual(wrong, [], f"Живые адреса помечены как машинные: {wrong}")

    def test_catches_machine_generated(self):
        missed = [e for e in self.BOTS if not looks_machine_generated(e)]
        self.assertEqual(missed, [], f"Не пойманы машинные адреса: {missed}")

    def test_short_locals_never_flagged(self):
        # Короткие адреса не судим: слишком мало сигнала
        for e in ["ao@bk.ru", "jhn@x.com", "ivan@mail.ru", "john@x.com"]:
            with self.subTest(e=e):
                self.assertFalse(looks_machine_generated(e))

    def test_separators_mean_human_format(self):
        self.assertFalse(looks_machine_generated("x.k.3.n.9@gmail.com"))

    def test_degenerate_input(self):
        for bad in ["", None, "notanemail", "@gmail.com"]:
            looks_machine_generated(bad)  # не должно бросать

    def test_entropy_basic(self):
        self.assertEqual(local_part_entropy(""), 0.0)
        self.assertEqual(local_part_entropy("aaaa"), 0.0)          # нет разнообразия
        self.assertGreater(local_part_entropy("abcdefgh"), 2.5)    # все разные


class TestParkedDomain(unittest.TestCase):
    def test_parked_hosts_detected(self):
        for mx in ["ns1.sedoparking.com", "mx.bodis.com", "park.afternic.com"]:
            with self.subTest(mx=mx):
                self.assertTrue(is_parked_domain(mx))

    def test_real_mx_not_flagged(self):
        for mx in ["aspmx.l.google.com", "mail.acme.com",
                   "acme-com.mail.protection.outlook.com", "mx.yandex.net"]:
            with self.subTest(mx=mx):
                self.assertFalse(is_parked_domain(mx))

    def test_missing_mx_is_not_parked(self):
        self.assertFalse(is_parked_domain(""))
        self.assertFalse(is_parked_domain("N/A"))
        self.assertFalse(is_parked_domain(None))


class TestScoringIntegration(unittest.TestCase):
    def setUp(self):
        from core.scoring import calculate_engagement_score
        self.score = calculate_engagement_score

    def test_machine_generated_penalised(self):
        clean = self.score(email="ivan.petrov@corp.com", smtp_status="Valid")
        bot = self.score(email="xk3n9fj2q4@corp.com", smtp_status="Valid",
                         machine_generated=True)
        self.assertLess(bot["score"], clean["score"])
        self.assertIn("-20", " ".join(bot["signals"]))

    def test_parked_domain_penalised(self):
        r = self.score(email="a@forsale.com", smtp_status="Valid", is_parked_domain=True)
        self.assertIn("-30", " ".join(r["signals"]))

    def test_defaults_do_not_penalise(self):
        # Без явных флагов новые штрафы применяться не должны
        r = self.score(email="a@corp.com", smtp_status="Valid")
        joined = " ".join(r["signals"])
        self.assertNotIn("сгенерированный машиной", joined)
        self.assertNotIn("припаркован", joined)



class TestPrivacyRelayNotMachine(unittest.TestCase):
    """Приватные relay-сервисы принадлежат РЕАЛЬНЫМ людям.

    Apple Private Relay включён у миллионов по умолчанию и выдаёт случайную
    локальную часть. Раньше энтропия штрафовала такие адреса на -20, хотя
    core/disposable.py специально не считает эти сервисы одноразовыми.
    """

    RELAY = [
        "dq5xr2mkpz@privaterelay.appleid.com",
        "k8jf3nzqwt@privaterelay.appleid.com",
        "x7kq2mn9@relay.firefox.com",
        "abc123xyz@anonaddy.me",
        "q9w8e7r6@duck.com",
        "zx9k2m@simplelogin.io",
    ]

    def test_relay_addresses_are_never_machine_generated(self):
        for e in self.RELAY:
            with self.subTest(email=e):
                self.assertFalse(looks_machine_generated(e))

    def test_bots_on_normal_domains_still_caught(self):
        # Исключение действует только для relay-доменов, не для всех подряд
        self.assertTrue(looks_machine_generated("dq5xr2mkpz@gmail.com"))

if __name__ == '__main__':
    unittest.main()
