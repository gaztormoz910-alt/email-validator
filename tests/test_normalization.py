"""Тесты нормализации адресов и классификации провайдера (п.28, 34, 35, 38 чек-листа)."""
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.cleaner import normalize_for_dedup
from core.provider import classify_domain


class TestDedupNormalization(unittest.TestCase):
    def assertSameMailbox(self, a, b):
        self.assertEqual(normalize_for_dedup(a), normalize_for_dedup(b),
                         f"{a} и {b} должны считаться одним ящиком")

    def assertDifferentMailbox(self, a, b):
        self.assertNotEqual(normalize_for_dedup(a), normalize_for_dedup(b),
                            f"{a} и {b} — РАЗНЫЕ ящики, склеивать нельзя")

    def test_gmail_ignores_dots(self):
        self.assertSameMailbox("john.doe@gmail.com", "johndoe@gmail.com")
        self.assertSameMailbox("j.o.h.n@gmail.com", "john@gmail.com")

    def test_gmail_plus_tag_stripped(self):
        self.assertSameMailbox("john+news@gmail.com", "john@gmail.com")
        self.assertSameMailbox("john.doe+shop@gmail.com", "johndoe@gmail.com")

    def test_googlemail_is_gmail(self):
        self.assertSameMailbox("john@googlemail.com", "john@gmail.com")
        self.assertSameMailbox("j.doe@googlemail.com", "jdoe@gmail.com")

    def test_case_insensitive(self):
        self.assertSameMailbox("John.Doe@Gmail.COM", "johndoe@gmail.com")

    def test_plus_tag_stripped_for_known_providers(self):
        self.assertSameMailbox("user+tag@outlook.com", "user@outlook.com")
        self.assertSameMailbox("user+tag@yahoo.com", "user@yahoo.com")
        self.assertSameMailbox("user+tag@icloud.com", "user@icloud.com")

    # --- Что склеивать НЕЛЬЗЯ ---

    def test_dots_matter_outside_gmail(self):
        # У Microsoft и остальных точки — значащие символы
        self.assertDifferentMailbox("john.doe@outlook.com", "johndoe@outlook.com")
        self.assertDifferentMailbox("john.doe@corp.com", "johndoe@corp.com")

    def test_plus_not_stripped_for_corporate(self):
        # На своём домене "+" может быть частью настоящего логина
        self.assertDifferentMailbox("user+tag@acme-corp.com", "user@acme-corp.com")

    def test_different_users_stay_different(self):
        self.assertDifferentMailbox("john@gmail.com", "jane@gmail.com")
        self.assertDifferentMailbox("john@gmail.com", "john@yahoo.com")

    def test_degenerate_input_does_not_crash(self):
        for bad in ["", None, "notanemail", "@gmail.com", "+tag@gmail.com"]:
            normalize_for_dedup(bad)  # не должно бросать исключение


class TestProviderClassification(unittest.TestCase):
    def test_free_providers(self):
        self.assertEqual(classify_domain("a@gmail.com"), ("Gmail", "Personal"))
        self.assertEqual(classify_domain("a@outlook.com"), ("Outlook", "Personal"))
        self.assertEqual(classify_domain("a@yahoo.com"), ("Yahoo", "Personal"))
        self.assertEqual(classify_domain("a@mail.ru"), ("Mail.ru", "Personal"))

    def test_isp_detected(self):
        self.assertEqual(classify_domain("a@comcast.net")[1], "ISP")

    def test_education_detected(self):
        self.assertEqual(classify_domain("a@mit.edu")[1], "Education")
        self.assertEqual(classify_domain("a@ox.ac.uk")[1], "Education")

    def test_government_detected(self):
        self.assertEqual(classify_domain("a@nasa.gov")[1], "Government")

    def test_corporate_default(self):
        self.assertEqual(classify_domain("a@acme-corp.com"), ("Corporate", "Corporate"))

    def test_mx_reveals_hosting_provider(self):
        # Свой домен на инфраструктуре Google/Microsoft
        self.assertEqual(
            classify_domain("a@acme.com", "aspmx.l.google.com"),
            ("Google Workspace", "Corporate"))
        self.assertEqual(
            classify_domain("a@acme.com", "acme-com.mail.protection.outlook.com"),
            ("Microsoft 365", "Corporate"))

    def test_degenerate_input(self):
        self.assertEqual(classify_domain(""), ("Unknown", "Unknown"))
        self.assertEqual(classify_domain("notanemail"), ("Unknown", "Unknown"))


if __name__ == '__main__':
    unittest.main()
