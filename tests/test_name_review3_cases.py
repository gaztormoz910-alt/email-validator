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

    def __init__(self):
        self.names = {}

    def get_profile(self, email):
        name = self.names.get(email)
        return {"name": name, "location": "", "accounts": []} if name else {}


class _Cases(unittest.TestCase):
    MODE = "accuracy"

    def setUp(self):
        was = get_country_mode()
        self.addCleanup(set_country_mode, was)
        set_country_mode(self.MODE)

    def check_address(self, rows):
        ex = extractor(False)
        for local, expected in rows:
            with self.subTest(local=local):
                self.assertEqual(ex.extract_name(local + "@example.com") or "", expected)

    def check_profile(self, rows):
        ex = extractor(True)
        fake = FakeProfile()
        ex.osint_operator = fake
        for local, profile, expected in rows:
            with self.subTest(local=local, profile=profile):
                email = local + "@example.com"
                fake.names[email] = profile
                self.assertEqual(ex.extract_name(email) or "", expected)

REAL_FIXED = (
    ("mdeepika21", "Deepika"),
    ("s.priya", "Priya"),
    ("k.zoltan", "Zoltan"),
    ("kzoltan", "Zoltan"),
    ("dallen", "Allen"),
    ("jallen", "Allen"),
    ("asmith", "A Smith"),
    ("jsmith", "J Smith"),
    ("pgupta", "P Gupta"),
    ("du.rajesh", "Rajesh"),
    ("an.nguyen", "An Nguyen"),
    ("muralinair", "Murali Nair"),
    ("deepanair", "Deepa Nair"),
    ("revathinair", "Revathi Nair"),
    ("fatimam", "Fatima"),
    ("attilam", "Attila"),
    ("johnsmith", "John Smith"),
    ("damilola85", "Damilola"),
    ("maryasdf", "Mary"),
    ("tomasdf", "Tom"),
    ("engineer.priya", "Priya"),
    ("itsjohn", "John"),
    ("alexgamer", "Alex"),
    ("mikegamer", "Mike"),
    ("JohnGamer", "John"),
    ("mike.gamer", "Mike"),
    ("kpriya16", "Priya"),
    ("sowmyak", "Sowmya"),
)

REAL_KEPT = (
    ("f.yilmaz", "F Yilmaz"),
    ("m.santos", "M Santos"),
    ("d.robinson", "D Robinson"),
    ("j.davis", "J Davis"),
    ("d.nair", "D Nair"),
    ("r.thakur", "R Thakur"),
    ("a.abe", "A Abe"),
    ("h.arslan", "H Arslan"),
    ("e.dogan", "E Dogan"),
    ("m.nagy", "M Nagy"),
    ("j.wilson", "J Wilson"),
    ("j.lewis", "J Lewis"),
    ("a.mansour", "A Mansour"),
    ("j.jackson", "J Jackson"),
    ("j.harris", "J Harris"),
    ("m.sahin", "M Sahin"),
    ("a.polat", "A Polat"),
    ("s.othman", "S Othman"),
    ("j.dias", "J Dias"),
    ("m.garcia", "M Garcia"),
    ("j.lee", "J Lee"),
    ("anguyen", "A Nguyen"),
    ("atanaka", "A Tanaka"),
    ("rrodriguez", "R Rodriguez"),
    ("fyilmaz", "F Yilmaz"),
    ("ahorvath", "A Horvath"),
    ("ajuhasz", "A Juhasz"),
    ("ebalogh", "E Balogh"),
    ("emarkovic", "E Markovic"),
    ("yshimizu", "Y Shimizu"),
    ("aribeiro", "A Ribeiro"),
    ("rsanchez", "R Sanchez"),
    ("etaylor", "E Taylor"),
    ("idemir", "I Demir"),
    ("harslan", "H Arslan"),
    ("mramos", "M Ramos"),
    ("ivarga", "I Varga"),
    ("huong.do", "Huong Do"),
    ("linh.ho", "Linh Ho"),
    ("tam.vu", "Tam Vu"),
    ("thao.vu", "Thao Vu"),
    ("vu.tam", "Vu Tam"),
    ("vy.le", "Vy Le"),
    ("minjun.oh", "Minjun Oh"),
    ("seojun.oh", "Seojun Oh"),
    ("t.vu", "T Vu"),
    ("h.ma", "H Ma"),
    ("x.wu", "X Wu"),
    ("y.xu", "Y Xu"),
    ("na.liu", "Na Liu"),
    ("lu.chen", "Lu Chen"),
    ("guy.cruz", "Guy Cruz"),
    ("heathersmith", "Heather Smith"),
    ("burakdemir", "Burak Demir"),
    ("jingli", "Jing Li"),
    ("hungly", "Hung Ly"),
    ("meszarossandor", "Meszaros Sandor"),
    ("sangeethaiyer", "Sangeetha Iyer"),
    ("chandrankavitha", "Chandran Kavitha"),
    ("chandranramesh", "Chandran Ramesh"),
    ("muralichandran", "Murali Chandran"),
    ("chandrananand", "Chandran Anand"),
    ("revathimenon", "Revathi Menon"),
    ("salehibrahim", "Saleh Ibrahim"),
    ("ismailcetin", "Ismail Cetin"),
    ("haticecetin", "Hatice Cetin"),
    ("john.smith", "John Smith"),
    ("mikejones87", "Mike Jones"),
    ("zhang.wei", "Zhang Wei"),
    ("zhangwei", "Zhang Wei"),
    ("anilkumar", "Anil Kumar"),
    ("purvamehta", "Purva Mehta"),
    ("m.kumar", "M Kumar"),
    ("angel.lopez", "Angel Lopez"),
    ("prince.adewale", "Prince Adewale"),
    ("martin85", "Martin"),
    ("tanakahiroshi", "Tanaka Hiroshi"),
    ("kowalskijan", "Kowalski Jan"),
    ("zoltankovacs", "Zoltan Kovacs"),
    ("surabhimehta", "Surabhi Mehta"),
)

JUNK_FIXED = (
    ("allahuakbar", ""),
    ("grandmajoan", ""),
    ("mikebiker", ""),
    ("MisterNice", ""),
    ("king.of.kings", ""),
    ("WonderWoman", ""),
    ("SilverSurfer", ""),
    ("RedDragon", ""),
    ("insha.allah", ""),
    ("mamama", ""),
    ("lapochka", ""),
    ("SilverFox", ""),
    ("silver.fox", ""),
    ("hakuna.matata", ""),
    ("IamRich", ""),
    ("sexyking", ""),
    ("babyrich", ""),
    ("x-man", ""),
    ("t-rex", ""),
    ("lilangel", ""),
    ("sunshine", ""),
    ("lucky123", ""),
    ("honey123", ""),
    ("queen99", ""),
    ("king77", ""),
    ("prince77", ""),
    ("princess", ""),
    ("kitty99", ""),
    ("rocky99", ""),
    ("sunny88", ""),
    ("angel2000", ""),
    ("sweety2000", ""),
    ("candycrush", ""),
    ("jaihind", ""),
    ("winniethepooh", ""),
    ("merabharat", ""),
    ("kingarthur", ""),
    ("kingkong", ""),
    ("donkey.kong", ""),
    ("jai.hind", ""),
    ("jai.shree.ram", ""),
    ("pagal.ladka", ""),
    ("chhota.bheem", ""),
    ("garcia", ""),
    ("nguyen", ""),
    ("wang", ""),
    ("zhang", ""),
    ("yilmaz", ""),
    ("ivanпетров", ""),
)

JUNK_KEPT = (
    ("iloveu", ""),
    ("iloveyu", ""),
    ("ilovey", ""),
    ("iloveyouu", ""),
    ("iloveyouuu", ""),
    ("iloveyou", ""),
    ("minecraft", ""),
    ("mrnice", ""),
    ("iamking", ""),
    ("imking", ""),
    ("inshallah", ""),
    ("snowwhite", ""),
    ("lonewolf", ""),
    ("chhotabheem", ""),
    ("MrNice", ""),
    ("mr.nice", ""),
    ("foo.bar", ""),
    ("TheRock", ""),
    ("itsnice", ""),
    ("justnice", ""),
    ("iamrich", ""),
    ("theking", ""),
    ("mywonder", ""),
    ("drsky", ""),
    ("onlylone", ""),
    ("itssnow", ""),
    ("realrock", ""),
    ("more", ""),
    ("seven", ""),
    ("even", ""),
    ("given", ""),
    ("mine", ""),
    ("zayka", ""),
    ("canim", ""),
    ("pyaar", ""),
    ("babushka", ""),
    ("mamacita", ""),
    ("galatasaray", ""),
    ("lalala", ""),
    ("love4ever", ""),
    ("mummy", ""),
    ("lonewolf88", ""),
    ("thebesteve", ""),
    ("thebestever", ""),
    ("mrsky", ""),
    ("thesky", ""),
    ("mysky", ""),
    ("itsman", ""),
    ("hakunamatata", ""),
    ("the.king", ""),
    ("mr.sky", ""),
    ("its.nice", ""),
    ("im.lucky", ""),
    ("just.rich", ""),
    ("my.angel", ""),
    ("real.sky", ""),
    ("the_king", ""),
    ("mr-sky", ""),
    ("dr.nice", ""),
    ("sir.rich", ""),
    ("only.lucky", ""),
    ("TheKing", ""),
    ("MrSky", ""),
    ("ItsNice", ""),
    ("ImLucky", ""),
    ("JustRich", ""),
    ("DrNice", ""),
    ("OnlyLucky", ""),
    ("an0nym0us", ""),
    ("lovenice", ""),
    ("coolking", ""),
    ("bestrich", ""),
    ("heysky", ""),
    ("hellolucky", ""),
    ("привет", ""),
    ("мама", ""),
    ("магазин", ""),
    ("honeybee", ""),
    ("greenlantern", ""),
    ("IronMan", ""),
    ("BigBoss", ""),
    ("BlueSky", ""),
    ("blue.sky", ""),
    ("web.master", ""),
    ("MrBean", ""),
    ("angeleyes", ""),
)

PROFILE_FIXED = (
    ("john.smith", "Crypto King", "John Smith"),
    ("priya.sharma", "Minecraft", "Priya Sharma"),
    ("maria.garcia", "Lone Wolf", "Maria Garcia"),
    ("tomlee", "Snow White", "Tom Lee"),
    ("rahul.verma", "King Khan", "Rahul Verma"),
    ("zp001", "Mr. Bean", ""),
    ("zp002", "Mr Nice", ""),
    ("zp003", "The Rock", ""),
    ("zp004", "Te Amo", ""),
    ("zp005", "Mi Vida", ""),
    ("zp006", "Allahu Akbar", ""),
    ("zp007", "Rock Star", ""),
    ("zp009", "Loan Offer", ""),
    ("zp010", "Red Bull", ""),
    ("zp011", "Lone Ranger", ""),
    ("zp012", "Lucky Winner", ""),
    ("zp013", "Hello Kitty Fan", ""),
    ("zp014", "Candy Crush", ""),
    ("zp015", "Clash Royale", ""),
    ("zp016", "Foo Bar", ""),
    ("zp017", "Carpe Diem", ""),
    ("zp019", "Darth Vader", ""),
    ("zp020", "Minecraft", ""),
    ("zp021", "Nice", ""),
    ("zp022", "Wonder", ""),
    ("zp023", "Ninja", ""),
    ("zp025", "More", ""),
    ("annasilva", "The Boss", "Anna Silva"),
    ("zp028", "Kumar Traders", ""),
)

PROFILE_KEPT = (
    ("theadamvelardes", "Adam Velardes", "Adam Velardes"),
    ("zp024", "Maria Lopez", "Maria Lopez"),
    ("rajpatel", "Raj Patel", "Raj Patel"),
    ("zp026", "Sowmya", "Sowmya"),
    ("zp027", "Ahmed", "Ahmed"),
)

COVERAGE_REAL_FIXED = (
    ("mdeepika21", "Deepika"),
    ("s.priya", "Priya"),
    ("k.zoltan", "Zoltan"),
    ("kzoltan", "Zoltan"),
    ("dallen", "Allen"),
    ("jallen", "Allen"),
    ("jsmith", "J Smith"),
    ("du.rajesh", "Rajesh"),
    ("an.nguyen", "An Nguyen"),
    ("muralinair", "Murali Nair"),
    ("deepanair", "Deepa Nair"),
    ("revathinair", "Revathi Nair"),
    ("fatimam", "Fatima"),
    ("attilam", "Attila"),
    ("johnsmith", "John Smith"),
    ("maryasdf", "Mary"),
    ("tomasdf", "Tom"),
    ("engineer.priya", "Priya"),
    ("itsjohn", "John"),
    ("alexgamer", "Alex"),
    ("mikegamer", "Mike"),
    ("JohnGamer", "John"),
    ("mike.gamer", "Mike"),
    ("kpriya16", "Priya"),
    ("sowmyak", "Sowmya"),
)

COVERAGE_REAL_KEPT = (
    ("f.yilmaz", "F Yilmaz"),
    ("m.santos", "M Santos"),
    ("d.robinson", "D Robinson"),
    ("j.davis", "J Davis"),
    ("d.nair", "D Nair"),
    ("r.thakur", "R Thakur"),
    ("a.abe", "A Abe"),
    ("h.arslan", "H Arslan"),
    ("e.dogan", "E Dogan"),
    ("m.nagy", "M Nagy"),
    ("j.wilson", "J Wilson"),
    ("j.lewis", "J Lewis"),
    ("a.mansour", "A Mansour"),
    ("j.jackson", "J Jackson"),
    ("j.harris", "J Harris"),
    ("m.sahin", "M Sahin"),
    ("a.polat", "A Polat"),
    ("s.othman", "S Othman"),
    ("j.dias", "J Dias"),
    ("m.garcia", "M Garcia"),
    ("j.lee", "J Lee"),
    ("anguyen", "A Nguyen"),
    ("atanaka", "A Tanaka"),
    ("rrodriguez", "R Rodriguez"),
    ("fyilmaz", "F Yilmaz"),
    ("ahorvath", "A Horvath"),
    ("ajuhasz", "A Juhasz"),
    ("ebalogh", "E Balogh"),
    ("emarkovic", "E Markovic"),
    ("yshimizu", "Y Shimizu"),
    ("aribeiro", "A Ribeiro"),
    ("rsanchez", "R Sanchez"),
    ("etaylor", "E Taylor"),
    ("idemir", "I Demir"),
    ("harslan", "H Arslan"),
    ("mramos", "M Ramos"),
    ("asmith", "A Smith"),
    ("ivarga", "I Varga"),
    ("pgupta", "P Gupta"),
    ("huong.do", "Huong Do"),
    ("linh.ho", "Linh Ho"),
    ("tam.vu", "Tam Vu"),
    ("thao.vu", "Thao Vu"),
    ("vu.tam", "Vu Tam"),
    ("vy.le", "Vy Le"),
    ("minjun.oh", "Minjun Oh"),
    ("seojun.oh", "Seojun Oh"),
    ("t.vu", "T Vu"),
    ("h.ma", "H Ma"),
    ("x.wu", "X Wu"),
    ("y.xu", "Y Xu"),
    ("na.liu", "Na Liu"),
    ("lu.chen", "Lu Chen"),
    ("guy.cruz", "Guy Cruz"),
    ("heathersmith", "Heather Smith"),
    ("burakdemir", "Burak Demir"),
    ("jingli", "Jing Li"),
    ("hungly", "Hung Ly"),
    ("meszarossandor", "Meszaros Sandor"),
    ("sangeethaiyer", "Sangeetha Iyer"),
    ("chandrankavitha", "Chandran Kavitha"),
    ("chandranramesh", "Chandran Ramesh"),
    ("muralichandran", "Murali Chandran"),
    ("chandrananand", "Chandran Anand"),
    ("revathimenon", "Revathi Menon"),
    ("salehibrahim", "Saleh Ibrahim"),
    ("ismailcetin", "Ismail Cetin"),
    ("haticecetin", "Hatice Cetin"),
    ("john.smith", "John Smith"),
    ("mikejones87", "Mike Jones"),
    ("zhang.wei", "Zhang Wei"),
    ("zhangwei", "Zhang Wei"),
    ("anilkumar", "Anil Kumar"),
    ("damilola85", "Damilola"),
    ("purvamehta", "Purva Mehta"),
    ("m.kumar", "M Kumar"),
    ("angel.lopez", "Angel Lopez"),
    ("prince.adewale", "Prince Adewale"),
    ("martin85", "Martin"),
    ("tanakahiroshi", "Tanaka Hiroshi"),
    ("kowalskijan", "Kowalski Jan"),
    ("zoltankovacs", "Zoltan Kovacs"),
    ("surabhimehta", "Surabhi Mehta"),
)

COVERAGE_PROFILE_FIXED = (
    ("john.smith", "Crypto King", "John Smith"),
    ("priya.sharma", "Minecraft", "Priya Sharma"),
    ("maria.garcia", "Lone Wolf", "Maria Garcia"),
    ("tomlee", "Snow White", "Tom Lee"),
    ("rahul.verma", "King Khan", "Rahul Verma"),
    ("annasilva", "The Boss", "Anna Silva"),
)

COVERAGE_PROFILE_KEPT = (
    ("theadamvelardes", "Adam Velardes", "Adam Velardes"),
    ("zp024", "Maria Lopez", "Maria Lopez"),
    ("rajpatel", "Raj Patel", "Raj Patel"),
    ("zp026", "Sowmya", "Sowmya"),
    ("zp027", "Ahmed", "Ahmed"),
)


class TestAccuracy(_Cases):

    def test_fixed_real_names(self):
        self.check_address(REAL_FIXED)

    def test_kept_real_names(self):
        self.check_address(REAL_KEPT)

    def test_fixed_junk_is_not_a_name(self):
        self.check_address(JUNK_FIXED)

    def test_kept_junk_stays_empty(self):
        self.check_address(JUNK_KEPT)

    def test_fixed_profile_names(self):
        self.check_profile(PROFILE_FIXED)

    def test_kept_profile_names(self):
        self.check_profile(PROFILE_KEPT)


class TestCoverage(_Cases):

    MODE = "coverage"

    def test_fixed_real_names(self):
        self.check_address(COVERAGE_REAL_FIXED)

    def test_kept_real_names(self):
        self.check_address(COVERAGE_REAL_KEPT)

    def test_fixed_profile_names(self):
        self.check_profile(COVERAGE_PROFILE_FIXED)

    def test_kept_profile_names(self):
        self.check_profile(COVERAGE_PROFILE_KEPT)


if __name__ == "__main__":
    unittest.main()
