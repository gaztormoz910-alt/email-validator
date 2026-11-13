"""Правила проверки имени (core/parser/name_quality.py) на подставных словарях.

Мир здесь выдуманный и маленький: десяток имён, их места в «базе», пара
английских слов и стран. Так каждое правило проверяется само по себе и
быстро — без базы на 138 млн записей, которая грузится восемь секунд, — и
видно, что решает именно правило, а не случайность большого словаря.
Имена и адреса выдуманы: данных владельца здесь нет.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser.name_quality import NameQuality, letters_only

# Имена «индекса популярных имён».
FIRST = {"john", "anna", "priya", "rahul", "zoltan", "ezoltan", "rajesh", "du", "bo",
         "eric", "alex", "ivor", "kevin", "maria", "laura", "sue", "mike", "anatol",
         "li", "wei", "chen", "jeri", "sam", "mora", "kamal", "kumar", "garcia", "lara",
         "man", "bean", "tata", "gonza", "silver", "sky"}
# (место как имя, место как фамилия) в «базе на 138 млн».
RANKS = {
    "john": (1, 50), "anna": (1, 116), "priya": (5, 3000), "rahul": (3, 2000),
    "zoltan": (30, 5000), "ezoltan": (1618, 1083), "rajesh": (20, 400), "du": (500, 300),
    "bo": (30, 900), "eric": (6, 53), "alex": (10, 190), "ivor": (40, 600),
    "kevin": (4, 600), "maria": (1, 16), "laura": (2, 500), "sue": (51, 221),
    "mike": (20, 800), "anatol": (90, 379), "li": (6, 1), "wei": (8, 32),
    "chen": (1, 1), "jeri": (400, None), "jeric": (60, None), "sam": (11, 78),
    "mora": (300, 200), "kamal": (32, 19), "kumar": (12, 1),
    "smith": (580, 1), "gupta": (1453, 9), "patel": (89, 2), "johansson": (1405, 2),
    "oliveira": (59, 3), "moreira": (900, 30), "kava": (6719, 1411), "orlova": (None, 400),
    "kowalska": (1998, 3), "garcia": (48, 1), "lara": (103, 56), "zhang": (5, 2),
    "zhangwei": (7789, 1387), "damilola": (201, 198), "haku": (None, 977),
    "nama": (1887, 678), "tata": (284, 389), "man": (1500, 900), "bean": (974, 841),
    "gonzalez": (None, 3), "gonza": (300, None), "silver": (649, 1092), "fox": (1383, 89),
    "sky": (300, 2000),
}
# Доля самого частого пола у слова как имени: у имени он есть, у вписанной в
# поле имени фамилии — нет (Garcia 63/37).
GENDER = {"zoltan": 0.99, "garcia": 0.63, "lara": 0.97, "kumar": 0.95, "anna": 0.99,
          "priya": 0.93, "damilola": 0.71}
ENGLISH = {"ship", "love", "loves", "junk", "glance", "objects", "now", "bike", "free",
           "form", "bleach", "sports", "iron", "silver", "fox", "blue", "sky", "you"}
COUNTRIES = {"du": ("BR", "CN"), "rajesh": ("IN",), "bo": ("SE", "DK"), "johansson": ("SE",),
             "li": ("CN", "FR"), "wei": ("CN", "TW"), "chen": ("CN", "TW"),
             "priya": ("IN",), "zoltan": ("HU",), "ezoltan": ("HU",)}
# Частоты корпуса сегментатора: частые слова и один «ник», который сам
# встречается в корпусе как строка (так, как «iloveyou» в настоящем).
COUNTS = {"theorist": 400000, "glance": 15000000, "i": 3000000000, "love": 200000000,
          "you": 3000000000, "john": 200000000, "smith": 60000000, "iloveyou": 36000,
          "silver": 74000000, "fox": 24000000, "gonzalez": 3000000}


def world(**overrides):
    params = dict(is_first=lambda w: w in FIRST,
                  name_ranks=lambda w: RANKS.get(w, (None, None)),
                  english_words=ENGLISH,
                  countries_for=lambda w: COUNTRIES.get(w, ()),
                  word_counts=COUNTS,
                  gender_share=lambda w: GENDER.get(w))
    params.update(overrides)
    return NameQuality(**params)


class TestProfile(unittest.TestCase):

    def setUp(self):
        self.q = world()

    def test_not_a_person_is_rejected(self):
        for raw in ("sunil07", "user@mail", "JΛNE", "DelhiEscortsRiya", "ACME TECH",
                    "star enterprises", "!!!", "http://x.y", "a_b"):
            with self.subTest(raw=raw):
                self.assertIsNone(self.q.profile_tokens(raw))

    def test_titles_are_taken_off(self):
        # Титул снимает finalize, а не profile_tokens: по нему же судится,
        # ник ли это (рецензия 08.11.2026). В колонку он не попадает.
        self.assertEqual(self.q.profile_name("Mr John Smith", "jsmith"), ("John Smith", ""))
        self.assertEqual(self.q.profile_name("Dr. Maria Lopez", "mlopez"), ("Maria Lopez", ""))

    def test_login_is_not_a_name(self):
        self.assertEqual(self.q.profile_name("johnsmith", "johnsmith"), ("", ""))

    def test_other_script_is_deferred(self):
        self.assertEqual(self.q.profile_name("王小明", "kevin.moore"), ("", "王小明"))

    def test_single_known_first_name_is_accepted(self):
        self.assertEqual(self.q.profile_name("kevin", "kev1990"), ("Kevin", ""))

    def test_handle_must_split_cleanly_and_lean_on_the_address(self):
        self.assertEqual(self.q.profile_name("johnsmith", "jsmith1980"), ("John Smith", ""))
        self.assertEqual(self.q.profile_name("moviebuff", "patel4521"), ("", ""))

    def test_full_name_keeps_its_case(self):
        self.assertEqual(self.q.profile_name("Maria Lopez", "mlopez"), ("Maria Lopez", ""))


class TestPieces(unittest.TestCase):

    def setUp(self):
        self.q = world()

    def test_certain_junk(self):
        for token in ("www", "xyz", "jj", "bcdf", "q" * 15, "tech"):
            with self.subTest(token=token):
                self.assertTrue(self.q.hard_junk(token))
        self.assertFalse(self.q.hard_junk("anna"))

    def test_unknown_surname_shape(self):
        self.assertTrue(self.q.structural_ok("rogbin"))
        for token in ("kumarbcdf", "ujkr", "freeform", "jenlovesea", "amyxk"):
            with self.subTest(token=token):
                self.assertFalse(self.q.structural_ok(token))

    def test_surname_needs_the_base(self):
        self.assertTrue(self.q.surname_ok("smith"))
        self.assertFalse(self.q.surname_ok("rogbin"))    # база не знает
        self.assertFalse(self.q.surname_ok("junk"))      # слово, не фамилия

    def test_weak_first_that_is_a_surname_at_home(self):
        self.assertTrue(self.q.surname_leaning("kowalska"))
        self.assertTrue(self.q.surname_leaning("patel"))
        self.assertFalse(self.q.surname_leaning("kumar"))
        self.assertFalse(self.q.surname_leaning("kamal"))


class TestSeparators(unittest.TestCase):
    """Границы поставил человек: их не режем, но мусор снимаем."""

    def setUp(self):
        self.q = world()

    def name(self, *parts):
        return self.q.finalize(list(parts), True)

    def test_letter_next_to_a_first_name_goes(self):
        self.assertEqual(self.name("k", "zoltan"), ["zoltan"])
        self.assertEqual(self.name("ivor", "x"), ["ivor"])

    def test_letter_next_to_a_surname_stays(self):
        self.assertEqual(self.name("j", "smith"), ["j", "smith"])

    def test_surname_written_into_the_name_field_keeps_its_initial(self):
        # Garcia индекс знает «именем», но пола у него нет и фамилией он выше:
        # «m.garcia» — это M Garcia, а не «Garcia» на месте имени.
        self.assertEqual(self.name("m", "garcia"), ["m", "garcia"])

    def test_gendered_name_next_to_an_initial_stays_a_name(self):
        # Lara — частая фамилия где-то в мире, но у неё есть пол: «s.lara» —
        # это Lara («инициал + имя»), а не «S Lara».
        self.assertEqual(self.name("s", "lara"), ["lara"])

    def test_two_letter_initials_of_another_culture(self):
        self.assertEqual(self.name("du", "rajesh"), ["rajesh"])
        self.assertEqual(self.name("bo", "johansson"), ["bo", "johansson"])
        self.assertEqual(self.name("li", "wei"), ["li", "wei"])

    def test_phrase_role_and_month_words(self):
        self.assertEqual(self.name("rakesh", "now"), [])
        self.assertEqual(self.name("laura", "ribeiro", "tech"), ["laura", "ribeiro"])
        self.assertEqual(self.name("jan", "feb"), [])

    def test_word_before_a_weak_name_is_a_nickname(self):
        # «IronMan»: слово впереди и слабое имя — прозвище, а не «Man».
        self.assertEqual(self.name("iron", "man"), [])

    def test_word_before_a_dictionary_name_is_a_nickname(self):
        # «blue.sky»: Sky база знает частым именем, но это и словарное слово.
        self.assertEqual(self.name("blue", "sky"), [])

    def test_word_before_a_strong_name_is_dropped(self):
        # Перед частым именем слово — род занятий или приставка.
        self.assertEqual(self.name("iron", "anna"), ["anna"])

    def test_title_with_a_weak_name_is_a_nickname(self):
        self.assertEqual(self.name("mr", "bean"), [])
        self.assertEqual(self.name("mr", "john"), ["john"])

    def test_unknown_surname_next_to_unknown_name_is_kept(self):
        # «moein.farsadzadeh»: точку поставил человек, оба куска похожи на
        # имя и фамилию — разметку не пересуживаем.
        self.assertEqual(self.name("rogbin", "farsadzadeh"), ["rogbin", "farsadzadeh"])


class TestFused(unittest.TestCase):
    """Слитная строка: границы угадываем мы, и строгость к догадке выше."""

    def setUp(self):
        self.q = world()

    def name(self, *pairs):
        return self.q.finalize([p for p, _ in pairs], False, [k for _, k in pairs])

    def test_initial_before_a_strong_first_name(self):
        self.assertEqual(self.name(("k", "initial"), ("zoltan", "first")), ["zoltan"])

    def test_vowel_initial_before_a_known_one_word_reading(self):
        # «e|zoltan»: слитно это слово, которое база знает (фамилия Ezoltan).
        # Прежнее исключение отдавало «Zoltan» там, где человек написал
        # фамилию; теперь гласная перед согласной — одно слово, как и везде.
        self.assertEqual(self.name(("e", "initial"), ("zoltan", "first")), [])

    def test_surname_after_an_initial_keeps_the_initial(self):
        self.assertEqual(self.name(("m", "initial"), ("garcia", "first")), ["m", "garcia"])

    def test_rare_short_surnames_cannot_lead(self):
        # «haku|nama|tata» складывалось в «Haku Nama Tata».
        self.assertEqual(self.name(("haku", "surname"), ("nama", "surname"),
                                   ("tata", "first")), [])

    def test_stub_before_the_name_means_no_name(self):
        self.assertEqual(self.name(("zv", "junk"), ("anatol", "first")), [])

    def test_phrase_after_the_name(self):
        self.assertEqual(self.name(("sue", "first"), ("loves", "word"), ("junk", "word")),
                         ["sue"])

    def test_business_word_needs_the_person_first(self):
        self.assertEqual(self.name(("kava", "surname"), ("mora", "first"),
                                   ("sports", "word")), [])

    def test_decoration_letter(self):
        self.assertEqual(self.name(("ivor", "first"), ("x", "initial")), ["ivor"])

    def test_unknown_surname_next_to_a_strong_name(self):
        self.assertEqual(self.name(("rogbin", "structural"), ("anatol", "first")),
                         ["rogbin", "anatol"])

    def test_english_word_right_after_the_name(self):
        self.assertEqual(self.name(("mike", "first"), ("bike", "word")), [])

    def test_name_made_only_of_common_words_is_a_nickname(self):
        # «silver|fox»: Silver — слабое имя, оба куска — частые слова.
        self.assertEqual(self.name(("silver", "first"), ("fox", "surname")), [])
        self.assertEqual(self.name(("john", "first"), ("smith", "surname")), ["john", "smith"])

    def test_truncated_name_is_not_used(self):
        # «jeri|c» — это Jeric: имя вместе со следующей буквой само имя.
        self.assertEqual(self.name(("jeri", "first"), ("c", "initial")), [])


class TestEvidence(unittest.TestCase):
    """Улики, которые судят строку целиком (core/parser/name_evidence.py)."""

    def setUp(self):
        self.q = world()

    def test_english_reading_uses_common_words_only(self):
        # «iloveyou» как строка в корпусе есть, но редка: прочтение — i|love|you.
        self.assertEqual(self.q.english_reading("iloveyou"), frozenset({1, 5}))
        self.assertEqual(self.q.english_reading("johnsmith"), frozenset({4}))
        self.assertIsNone(self.q.english_reading("rogbinzarg"))

    def test_parse_that_cuts_an_english_word_is_misaligned(self):
        self.assertTrue(self.q.misaligned("iloveyou", [("ilo", "first"), ("veyou", "structural")]))
        self.assertFalse(self.q.misaligned("johnsmith", [("john", "first"), ("smith", "surname")]))
        # У инициала граница не проверяется: «m|garcia» — запись «И. Фамилия».
        # silver|fox — прочтение из словаря; граница 1 у буквы не сверяется,
        # а та же граница не у буквы («silve|rfox») — сверяется.
        self.assertFalse(self.q.misaligned("silverfox", [("s", "initial"), ("ilverfox", "structural")]))
        self.assertTrue(self.q.misaligned("silverfox", [("silve", "first"), ("rfox", "surname")]))
        # Но кусок, который прочтение начинает словом фразы, — совпадение
        # букв, где бы ни стояла граница: «i|loveyou», «thebe|steve» (J17).
        self.assertTrue(self.q.misaligned("iloveyou", [("i", "initial"), ("loveyou", "structural")]))

    def test_whole_string_name_from_the_base(self):
        # Damilola — 201-е место: кусок с таким рангом не подтверждён, а
        # строка целиком — подтверждена.
        self.assertFalse(self.q.first_ok("damilola"))
        self.assertTrue(self.q.whole_first("damilola"))
        self.assertFalse(self.q.whole_first("kowalska"))   # фамилия по преимуществу

    def test_two_names_glued_in_one_record_are_split(self):
        # «zhangwei» база знает слабой фамилией; это Zhang и Wei.
        self.assertTrue(self.q._joined_names("zhangwei"))
        self.assertEqual([p for p, _ in self.q.segment("zhangwei")], ["zhang", "wei"])
        self.assertFalse(self.q._joined_names("annamaria"))   # имя + имя — одно имя

    def test_surname_reading_next_to_an_initial(self):
        self.assertTrue(self.q.reads_as_surname("garcia"))    # пола нет, фамилия выше
        self.assertFalse(self.q.reads_as_surname("lara"))     # пол есть — имя
        self.assertFalse(self.q.reads_as_surname("zoltan"))
        self.assertTrue(self.q.reads_as_surname("chen"))      # восточноазиатская фамилия

    def test_fallback_does_not_cut_an_explained_string(self):
        # «gonzalez» — известная фамилия целиком; «Gonza» в её начале —
        # совпадение букв.
        self.assertEqual(self.q.anchor_fallback("gonzalez"), [])


class TestSegmentation(unittest.TestCase):

    def setUp(self):
        self.q = world()

    def name_of(self, letters):
        pieces = self.q.segment(letters)
        return self.q.finalize([p for p, _ in pieces], False, [k for _, k in pieces])

    def test_name_and_surname(self):
        self.assertEqual(self.name_of("johnsmith"), ["john", "smith"])
        self.assertEqual(self.name_of("mariaorlova"), ["maria", "orlova"])

    def test_junk_after_the_name(self):
        self.assertEqual(self.name_of("annakk"), ["anna"])
        self.assertEqual(self.name_of("ericxyz"), ["eric"])

    def test_phrase_and_plain_word(self):
        self.assertTrue(self.q.phrase_only("glanceobjects"))
        self.assertFalse(self.q.phrase_only("johnsmith"))
        self.assertTrue(self.q.is_plain_word("theorist"))
        self.assertFalse(self.q.is_plain_word("anna"))

    def test_long_input_is_not_parsed(self):
        self.assertEqual(self.q.segment("a" * 41), [])

    def test_repeated_parse_is_the_same(self):
        # Разборы помнятся (память без неё стоила 50 мс на строку): второй
        # вызов обязан вернуть то же и не отдать наружу список из памяти.
        first = self.q.segment("johnsmith")
        first.append(("x", "junk"))
        self.assertEqual(self.q.segment("johnsmith"), [("john", "first"), ("smith", "surname")])

    def test_letters_only(self):
        self.assertEqual(letters_only("Jo-hn_1"), "john")


class TestCoverageGuess(unittest.TestCase):

    def setUp(self):
        self.q = world()

    def test_certain_junk_goes_from_a_guess(self):
        self.assertEqual(self.q.clean_guess(["Priya", "Www"]), ["Priya"])
        self.assertEqual(self.q.clean_guess(["Kava", "Orlova", "Www"]), ["Kava", "Orlova"])
        self.assertEqual(self.q.clean_guess(["K", "Zoltan"]), ["Zoltan"])
        self.assertEqual(self.q.clean_guess(["Bleach"]), [])

    def test_one_word_is_a_confirmed_name_or_nothing(self):
        # Решение владельца 13.11.2026. Прежде здесь стояло обратное:
        # clean_guess(["Anlie", "Www"]) == ["Anlie"] — одно неподтверждённое
        # слово шло в колонку догадкой. Фамилия и прозвище — так же пусто.
        self.assertEqual(self.q.clean_guess(["Anlie", "Www"]), [])
        self.assertEqual(self.q.clean_guess(["Gonzalez"]), [])
        self.assertEqual(self.q.clean_guess(["Sky"]), [])
        self.assertEqual(self.q.clean_guess(["Zoltan"]), ["Zoltan"])

    def test_letter_cut_off_a_word_the_base_knows_is_not_an_initial(self):
        # «ezoltan» в этом мире — слово базы (1083-я фамилия): «e|zoltan» от
        # сегментатора режет его, и имени тут нет. «ozoltan» база не знает —
        # догадка остаётся. Через разделитель границу поставил человек.
        self.assertEqual(self.q.clean_guess(["e", "zoltan"], fused=True), [])
        self.assertEqual(self.q.clean_guess(["o", "zoltan"], fused=True), ["zoltan"])
        self.assertEqual(self.q.clean_guess(["e", "zoltan"]), ["zoltan"])
        self.assertTrue(self.q.joined_word_guess(["e", "zoltan"]))
        self.assertFalse(self.q.joined_word_guess(["e", "zoltan", "smith"]))

    def test_unconfirmed_start_of_a_nick_before_a_fragment_is_not_a_name(self):
        # «kava» и «orlova» индекс имён не знает; обломок без гласных после
        # них значит, что строку разрезать не удалось. Два слова взяты, чтобы
        # решало именно это правило, а не правило одного слова. Между
        # разделителями границу поставил человек. Подтверждённое имя
        # («priya») остаётся; веб-хвост и слишком длинный хвост — не обломки.
        self.assertEqual(self.q.clean_guess(["kava", "orlova", "dx"], fused=True), [])
        self.assertEqual(self.q.clean_guess(["kava", "orlova", "dx"]), ["kava", "orlova"])
        self.assertEqual(self.q.clean_guess(["priya", "xx"], fused=True), ["priya"])
        self.assertEqual(self.q.clean_guess(["kava", "orlova", "www"], fused=True),
                         ["kava", "orlova"])
        self.assertEqual(self.q.clean_guess(
            ["kava", "orlova", "fitnesssaratogaspringsclub"], fused=True), ["kava", "orlova"])
        self.assertTrue(self.q.is_fragment("dx"))
        self.assertFalse(self.q.is_fragment("www"))


class TestBrokenKnowledge(unittest.TestCase):

    def test_failing_dictionary_does_not_drop_the_address(self):
        def broken(word):
            raise RuntimeError("словарь недоступен")
        q = world(is_first=broken, name_ranks=broken, countries_for=broken,
                  gender_share=broken)
        self.assertIsInstance(q.finalize(["anna", "smith"], True), list)
        self.assertIsInstance(q.segment("annasmith"), list)
        self.assertEqual(q.profile_name("anna", "anna1"), ("", ""))
        self.assertFalse(q.reads_as_surname("garcia"))


if __name__ == "__main__":
    unittest.main()
