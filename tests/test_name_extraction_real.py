import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser.name_extractor import NameExtractor

_extractor = None


def extractor():
    global _extractor
    if _extractor is None:
        _extractor = NameExtractor()
    return _extractor


class TestNoFalseNames(unittest.TestCase):

    JUNK = [
        "qqq482615@gmail.com",
        "qv5871@gmail.com",
        "2018oregonrn@gmail.com",
        "info@company.com",
        "admin@example.com",
        "support@example.com",
        "noreply@example.com",
        "webmaster@example.com",
    ]

    def test_junk_yields_no_name(self):
        for address in self.JUNK:
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address) or "", "",
                                 "мусор попал в колонку «Имя»")


class TestNamesAreNotLost(unittest.TestCase):

    KNOWN = {
        "justinbrody57@gmail.com": "Justin Brody",
        "suelovesfrogs7@gmail.com": "Sue",
        "leo.fontanieu@gmail.com": "Leo Fontanieu",
        "rachaeldakoalagirl@gmail.com": "Rachael",
        "johnoakreps@gmail.com": "John Oakreps",
        "janedoe@gmail.com": "Jane Doe",
        "minpark@gmail.com": "Min Park",
        "salim.bvk88@gmail.com": "Salim",
        "michaelbauer4321@gmail.com": "Michael Bauer",
        "richardpike2006@gmail.com": "Richard Pike",
        "joshualuna517@gmail.com": "Joshua Luna",
        "stevenliang030@gmail.com": "Steven Liang",
        "gauravkolwar@gmail.com": "Gaurav Kolwar",
        "alvaromendaluz@gmail.com": "Alvaro Mendaluz",
        "harshavemuri29@gmail.com": "Harsha Vemuri",
        "kennethmdizon@gmail.com": "Kenneth M Dizon",
        "sebastienmorvat@gmail.com": "Sebastien Morvat",
        "pavansaimuddam@gmail.com": "Pavan Saimuddam",
        "justincolewhitlock@gmail.com": "Justin Cole Whitlock",
        "swathinaidu062001@gmail.com": "Swathi Naidu",
        "jeronimo.alcott@gmail.com": "Jeronimo Alcott",
        "chris.montoya417@gmail.com": "Chris Montoya",
    }

    def test_known_names_are_extracted(self):
        for address, expected in self.KNOWN.items():
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address), expected)


class TestPhraseWordBeforeTheName(unittest.TestCase):

    def test_leading_phrase_word_is_dropped(self):
        for address, expected in (("theadamvelardes@gmail.com", "Adam Velardes"),
                                  ("livemarko@gmail.com", "Marko")):
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address) or "", expected)


class TestExplicitSeparatorsAreRespected(unittest.TestCase):

    CASES = {
        "john.smith@example.com": "John Smith",
        "j.smith@example.com": "J Smith",
        "bo.johansson@example.com": "Bo Johansson",
        "ed.harris@example.com": "Ed Harris",
        "jo.baker@example.com": "Jo Baker",
        "jonathan.k.ward2@gmail.com": "Jonathan K Ward",
        "nikhil.ram.sethi@gmail.com": "Nikhil Ram Sethi",
        "leo.fontanieu@gmail.com": "Leo Fontanieu",
        "george.lam77@gmail.com": "George Lam",
    }

    def test_separated_parts_stay_separate(self):
        for address, expected in self.CASES.items():
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address), expected)


class TestMultipartNamesSurvive(unittest.TestCase):

    def test_vietnamese_three_part_name(self):
        self.assertEqual(extractor().extract_name("minhanhtran07@gmail.com"),
                         "Minh Anh Tran")

    def test_positive_control_fake_three_part_is_collapsed(self):
        self.assertEqual(extractor().extract_name("johnoakreps@gmail.com"),
                         "John Oakreps")


class TestBusinessWordsTrimmedNotFatal(unittest.TestCase):

    def test_trailing_business_word_is_dropped(self):
        self.assertEqual(extractor().extract_name("laura.ribeiro.tech@gmail.com"),
                         "Laura Ribeiro")

    def test_business_address_still_yields_nothing(self):
        for address in ("info.tech@company.com", "sales.group@company.com",
                        "support.services@company.com"):
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address) or "", "")


class TestFusedSlavicAddressesSurvive(unittest.TestCase):

    def test_fused_names(self):
        cases = {
            "zogbinanatol1@gmail.com": "",
            "zogbina@gmail.com": "",
            "kvanatol351@gmail.com": "",
        }
        for address, expected in cases.items():
            with self.subTest(address=address):
                self.assertEqual(extractor().extract_name(address) or "", expected)


class TestGarbageInput(unittest.TestCase):
    def test_broken_input_does_not_crash(self):
        for junk in (None, "", "   ", "@", "a@", "@b.com", 0, [], {},
                     "a" * 500 + "@b.com", "\x00@b.com", b"a@b.com"):
            with self.subTest(junk=junk):
                result = extractor().extract_name(junk)
                self.assertIn(type(result).__name__, ("str", "NoneType"))


if __name__ == "__main__":
    unittest.main()
