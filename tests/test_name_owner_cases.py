"""Имя в колонке — проверенное, а не «что попалось» (жалоба владельца, 06.11.2026).

Владелец выделил на своём прогоне строки, где обогатитель поставил в колонку
«Имя» ник из профиля Gravatar с цифрами, иероглифы для латинского адреса,
ник одним словом без опоры в адресе, букву на месте имени («K Anita»),
букву-украшение («Paul X») и инициалы чужой культуры («Du Rajesh»). Здесь те
же виды ошибок на ВЫДУМАННЫХ адресах: настоящие адреса владельца в
отслеживаемые файлы не попадают — эта строка уезжает в собранную программу и
видна любому, кто её разберёт.

Ниже — и находки независимой рецензии правки (07.11.2026): прежняя версия
разбора называла именем фразу («Ilo» из `iloveyou`), резала известную
фамилию («Gonza»), ставила фамилию на место имени («Garcia» у `m.garcia`) и
дробила имя целиком («Dami Lola»).

Тест с именем test_fixed_* закрепляет новое поведение: на коде до правки он
падает (гейт .unlazy/enrich-stop/check_names.py red проверяет это на выгрузке
последнего коммита), а test_kept_* — то, что работало и раньше и не должно
сломаться.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser.name_extractor import NameExtractor
from core.parser.ml_predictor import get_country_mode, set_country_mode

_cache = {}


def extractor(osint):
    """Один экземпляр на вид: конструктор грузит базу на 138 млн имён."""
    if osint not in _cache:
        _cache[osint] = NameExtractor(enable_osint=osint)
    return _cache[osint]


class FakeProfile:
    """Подставной Gravatar: одно имя на любой адрес, без сети."""

    def __init__(self, name):
        self.name = name

    def get_profile(self, email):
        return {"name": self.name, "location": "", "accounts": []} if self.name else {}


class _Mode(unittest.TestCase):
    """Режим «Точность» на время теста — тот, что включён в окне владельца.

    Режим — глобальная настройка модуля; оставленный включённым, он молча
    поменял бы поведение всех тестов, которые пойдут следом.
    """

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
    """Имя из профиля Gravatar больше не берётся без проверки."""

    def test_fixed_profile_handle_with_digits_is_not_a_name(self):
        self.assertEqual(self.with_profile("zxqtrw@example.com", "zxq77"), "")

    def test_fixed_profile_in_other_script_yields_to_the_address(self):
        # Иероглифы для латинского адреса: для письма на латинице адрес даёт
        # более пригодное имя, а профиль остаётся запасом.
        self.assertEqual(self.with_profile("kevin.moore1988@example.com", "王小明"),
                         "Kevin Moore")

    def test_fixed_profile_handle_splits_into_name_and_surname(self):
        self.assertEqual(self.with_profile("lucas1990@example.com", "lucasmoreira"),
                         "Lucas Moreira")

    def test_fixed_profile_handle_without_support_in_address(self):
        # Ник «moviebuff» не опирается на адрес, а сам адрес — одна фамилия.
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
        # Запасной путь раньше отдавал сырую строку анкеты в обход проверки
        # на логин, которую та же строка только что не прошла.
        self.assertEqual(self.with_profile("zzqx2018@example.com", "zzqx2018"), "")

    def test_kept_real_profile_name(self):
        self.assertEqual(self.with_profile("maria.lopez@example.com", "Maria Lopez"),
                         "Maria Lopez")

    def test_kept_profile_login_falls_back_to_the_address(self):
        self.assertEqual(self.with_profile("tomhardy@example.com", "tomhardy"), "Tom Hardy")


class TestAddressNameIsChecked(_Mode):
    """Имя из самого адреса: каждый кусок подтверждён, мусор уходит."""

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
    """«Заполненность» оставляет догадки, но не заведомый мусор."""

    MODE = "coverage"

    def test_fixed_coverage_drops_doubled_letters(self):
        self.assertEqual(self.plain("priyaxx99@example.com"), "Priya")

    def test_fixed_coverage_does_not_name_a_phrase(self):
        self.assertEqual(self.plain("bethechange77@example.com"), "")

    def test_fixed_coverage_keeps_a_plausible_guess_without_the_letter(self):
        # Неподтверждённая, но правдоподобная догадка — компромисс режима; буква
        # рядом с именем уходит и здесь. На коде до правки — «O Zoltan»: этот
        # тест назывался test_kept_*, хотя тогда не проходил (рецензия).
        self.assertEqual(self.plain("ozoltan85@example.com"), "Zoltan")

    def test_fixed_coverage_does_not_name_the_start_of_a_nick(self):
        # Жалоба владельца 13.11.2026: в «Заполненности» ник давал имя-обломок.
        # Сегментатор режет ник на произносимое начало и обломок без гласных,
        # а начало ничем не подтверждено. До правки: «Belo», «Sadek», «Bimok»,
        # «Mori».
        for email in ("belodx@example.com", "sadekjh@example.com",
                      "bimokzz77@example.com", "morikzz@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_fixed_coverage_does_not_cut_a_letter_off_a_known_word(self):
        # База знает строку целиком (D'Souza, D'Costa, O'Kelly): буква — её
        # первая буква, а не инициал. До правки: «D Souza», «D Costa», «O Kelly».
        for email in ("dsouza85@example.com", "dcosta77@example.com", "okelly@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_kept_coverage_guesses_next_to_the_rules_above(self):
        # Контроль: правила не косят всё подряд. Подтверждённое имя перед
        # обломком остаётся; строку «opeter» база слитно не знает, и догадка
        # «Peter» остаётся; догадка из двух слов с именем впереди — компромисс
        # режима (решение владельца 14.11.2026: без имени впереди — пусто).
        for email, expected in (("priyaxx99@example.com", "Priya"),
                                ("opeter@example.com", "Peter"),
                                ("johnbirchly@example.com", "John Birchly")):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), expected)

    def test_fixed_coverage_one_word_is_a_confirmed_name_or_nothing(self):
        # Решение владельца 13.11.2026. До него этот тест назывался
        # test_kept_coverage_keeps_a_lone_surname_guess и закреплял обратное:
        # «Заполненность» отдавала одиночную фамилию («Gonzalez»), прозвище
        # («King») и неподтверждённое слово («Anlie») догадкой.
        for email in ("gonzalez85@example.com", "king77@example.com",
                      "anliewww@example.com", "amaral85@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_kept_coverage_initial_with_a_surname(self):
        # Запись «И. Фамилия» — не одно слово, и буква остаётся, как и раньше.
        self.assertEqual(self.plain("m.garcia@example.com"), "M Garcia")


class TestReviewFindings(_Mode):
    """Находки рецензии правки: что прежняя версия разбора делала неверно."""

    def test_fixed_known_surname_is_not_cut_into_a_name(self):
        # Строка целиком — известная фамилия; имя в её начале — совпадение
        # букв: прежняя версия отдавала «Gonza», «Rami», «Taka Hashi», а код
        # до правки — одну фамилию на месте имени.
        for email in ("gonzalez85@example.com", "ramirez1990@example.com",
                      "takahashi@example.com", "rodriguez@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_fixed_whole_name_from_the_base(self):
        # Damilola и Funmilayo база знает именами целиком (201-е и 205-е
        # места), а куски «Dami», «Lola» — совпадение.
        self.assertEqual(self.plain("damilola85@example.com"), "Damilola")
        self.assertEqual(self.plain("funmilayo12@example.com"), "Funmilayo")

    def test_fixed_vowel_letter_before_a_name_is_one_word(self):
        # «amaral»: слитно это португальская фамилия Amaral, а не «A. Maral».
        self.assertEqual(self.plain("amaral85@example.com"), "")

    def test_fixed_job_word_before_a_strong_name(self):
        self.assertEqual(self.plain("engineer.priya@example.com"), "Priya")

    def test_kept_english_phrase_is_not_a_name(self):
        # Прежняя версия: «Ilo», «Thebe Steve», «Ange Leyes», «Silver Fox»,
        # «Haku Nama Tata». Код до правки здесь был пуст — и должен остаться.
        for email in ("iloveyou@example.com", "thebestever@example.com",
                      "angeleyes@example.com", "silverfox@example.com",
                      "hakunamatata@example.com", "arsenal@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_kept_word_before_a_name_is_a_nickname(self):
        # Прежняя версия: «Man», «Boss», «Sky», «Master», «Bean».
        for email in ("IronMan@example.com", "BigBoss@example.com", "BlueSky@example.com",
                      "blue.sky@example.com", "web.master@example.com", "MrBean@example.com"):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), "")

    def test_kept_initial_with_a_surname_keeps_the_initial(self):
        # Прежняя версия снимала инициал и ставила фамилию на место имени.
        for email, expected in (("m.garcia@example.com", "M Garcia"),
                                ("tnguyen@example.com", "T Nguyen"),
                                ("j.lee@example.com", "J Lee")):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), expected)

    def test_kept_two_names_glued_in_the_base(self):
        # База знает эти строки целиком слабой фамилией или именем; прежняя
        # версия теряла их или отдавала «Anilkumar».
        for email, expected in (("zhangwei@example.com", "Zhang Wei"),
                                ("ahmedali@example.com", "Ahmed Ali"),
                                ("anilkumar@example.com", "Anil Kumar"),
                                ("francescabianchi@example.com", "Francesca Bianchi")):
            with self.subTest(email=email):
                self.assertEqual(self.plain(email), expected)


if __name__ == "__main__":
    unittest.main()
