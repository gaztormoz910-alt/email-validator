import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser.name_extractor import NameExtractor
from core.parser.ml_predictor import get_country_mode, set_country_mode

_cache = {}


def extractor(osint):
    if osint not in _cache:
        _cache[osint] = NameExtractor(enable_osint=osint)
    return _cache[osint]


class FakeProfile:

    def __init__(self, name):
        self.name = name

    def get_profile(self, email):
        return {"name": self.name, "location": "", "accounts": []} if self.name else {}


class _Mode(unittest.TestCase):

    MODE = "accuracy"

    def setUp(self):
        was = get_country_mode()
        self.addCleanup(set_country_mode, was)
        set_country_mode(self.MODE)

    def with_profile(self, email, name):
        ex = extractor(True)
        ex.osint_operator = FakeProfile(name)
        return ex.extract_name(email) or ""

    def plain(self, email):
        return extractor(False).extract_name(email) or ""


class TestProfileNameIsChecked(_Mode):

    def test_fixed_profile_handle_with_digits_is_not_a_name(self):
        self.assertEqual(self.with_profile("zxqtrw@example.com", "zxq77"), "")

    def test_fixed_profile_in_other_script_yields_to_the_address(self):
        self.assertEqual(self.with_profile("kevin.moore1988@example.com", "王小明"),
                         "Kevin Moore")

    def test_fixed_profile_handle_splits_into_name_and_surname(self):
        self.assertEqual(self.with_profile("lucas1990@example.com", "lucasmoreira"),
                         "Lucas Moreira")

    def test_fixed_profile_handle_without_support_in_address(self):
        self.assertEqual(self.with_profile("patel4521@example.com", "moviebuff"), "")

    def test_fixed_company_profile_is_not_a_name(self):
        self.assertEqual(self.with_profile("jasonbrown@example.com", "ACME TECH"),
                         "Jason Brown")

    def test_fixed_spam_profile_is_not_a_name(self):
        self.assertEqual(self.with_profile("priya.sharma@example.com", "DelhiEscortsPriya"),
                         "Priya Sharma")

    def test_fixed_mixed_script_profile_is_not_a_name(self):
        self.assertEqual(self.with_profile("jane.wilson@example.com", "JΛNE"), "Jane Wilson")

    def test_fixed_fallback_does_not_return_raw_login(self):
        self.assertEqual(self.with_profile("zzqx2018@example.com", "zzqx2018"), "")

    def test_kept_real_profile_name(self):
        self.assertEqual(self.with_profile("maria.lopez@example.com", "Maria Lopez"),
                         "Maria Lopez")

    def test_kept_profile_login_falls_back_to_the_address(self):
        self.assertEqual(self.with_profile("tomhardy@example.com", "tomhardy"), "Tom Hardy")


class TestAddressNameIsChecked(_Mode):

    def test_fixed_initial_before_the_first_name(self):
        self.assertEqual(self.plain("kpriya16@example.com"), "Priya")

    def test_fixed_decoration_letter_after_the_name(self):
        self.assertEqual(self.plain("brianx2000@example.com"), "Brian")

    def test_fixed_two_letter_initials_of_another_culture(self):
        self.assertEqual(self.plain("du.rajesh@example.com"), "Rajesh")

    def test_fixed_phrase_after_the_name(self):
        self.assertEqual(self.plain("priyaontour@example.com"), "Priya")
        self.assertEqual(self.plain("mikesayshello@example.com"), "Mike")

    def test_fixed_web_word_after_the_name(self):
        self.assertEqual(self.plain("laura.mendes.com@example.com"), "Laura Mendes")

    def test_fixed_fused_name_between_separators(self):
        self.assertEqual(self.plain("rahulsingh.qwrt@example.com"), "Rahul Singh")

    def test_fixed_names_found_by_the_name_index_not_by_english(self):
        self.assertEqual(self.plain("vasilisaorlova@example.com"), "Vasilisa Orlova")

    def test_fixed_keyboard_junk_and_doubled_letters(self):
        for email, expected in (("paulzx@example.com", "Paul"), ("annakk@example.com", "Anna"),
                                ("kamalxyz@example.com", "Kamal"),
                                ("jessicaqz@example.com", "Jessica")):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), expected)

    def test_fixed_role_word_and_initial_after_the_name(self):
        self.assertEqual(self.plain("ravi.k.office@example.com"), "Ravi")

    def test_kept_ordinary_names(self):
        for email, expected in (("irinasmirnova@example.com", "Irina Smirnova"),
                                ("john.smith@example.com", "John Smith"),
                                ("anatolypetrov@example.com", "Anatoly Petrov"),
                                ("raj.patel.tech@example.com", "Raj Patel")):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), expected)

    def test_kept_phrases_and_shops_stay_empty(self):
        for email in ("bethechange77@example.com", "mycarstore@example.com",
                      "theorist@example.com", "sales.team@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")


class TestCoverageModeDropsCertainJunk(_Mode):

    MODE = "coverage"

    def test_fixed_coverage_drops_doubled_letters(self):
        self.assertEqual(self.plain("priyaxx99@example.com"), "Priya")

    def test_fixed_coverage_does_not_name_a_phrase(self):
        self.assertEqual(self.plain("bethechange77@example.com"), "")

    def test_fixed_coverage_keeps_a_plausible_guess_without_the_letter(self):
        self.assertEqual(self.plain("ozoltan85@example.com"), "Zoltan")

    def test_fixed_coverage_does_not_name_the_start_of_a_nick(self):
        for email in ("belodx@example.com", "sadekjh@example.com",
                      "bimokzz77@example.com", "morikzz@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_fixed_coverage_does_not_cut_a_letter_off_a_known_word(self):
        for email in ("dsouza85@example.com", "dcosta77@example.com", "okelly@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_kept_coverage_guesses_next_to_the_rules_above(self):
        for email, expected in (("priyaxx99@example.com", "Priya"),
                                ("opeter@example.com", "Peter"),
                                ("johnbirchly@example.com", "John Birchly")):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), expected)

    def test_fixed_coverage_one_word_is_a_confirmed_name_or_nothing(self):
        for email in ("gonzalez85@example.com", "king77@example.com",
                      "anliewww@example.com", "amaral85@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_kept_coverage_initial_with_a_surname(self):
        self.assertEqual(self.plain("m.garcia@example.com"), "M Garcia")


class TestReviewFindings(_Mode):

    def test_fixed_known_surname_is_not_cut_into_a_name(self):
        for email in ("gonzalez85@example.com", "ramirez1990@example.com",
                      "takahashi@example.com", "rodriguez@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_fixed_whole_name_from_the_base(self):
        self.assertEqual(self.plain("damilola85@example.com"), "Damilola")
        self.assertEqual(self.plain("funmilayo12@example.com"), "Funmilayo")

    def test_fixed_vowel_letter_before_a_name_is_one_word(self):
        self.assertEqual(self.plain("amaral85@example.com"), "")

    def test_fixed_job_word_before_a_strong_name(self):
        self.assertEqual(self.plain("engineer.priya@example.com"), "Priya")

    def test_kept_english_phrase_is_not_a_name(self):
        for email in ("iloveyou@example.com", "thebestever@example.com",
                      "angeleyes@example.com", "silverfox@example.com",
                      "hakunamatata@example.com", "arsenal@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_kept_word_before_a_name_is_a_nickname(self):
        for email in ("IronMan@example.com", "BigBoss@example.com", "BlueSky@example.com",
                      "blue.sky@example.com", "web.master@example.com", "MrBean@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_kept_initial_with_a_surname_keeps_the_initial(self):
        for email, expected in (("m.garcia@example.com", "M Garcia"),
                                ("tnguyen@example.com", "T Nguyen"),
                                ("j.lee@example.com", "J Lee")):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), expected)

    def test_kept_two_names_glued_in_the_base(self):
        for email, expected in (("zhangwei@example.com", "Zhang Wei"),
                                ("ahmedali@example.com", "Ahmed Ali"),
                                ("anilkumar@example.com", "Anil Kumar"),
                                ("francescabianchi@example.com", "Francesca Bianchi")):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), expected)


if __name__ == "__main__":
    unittest.main()
