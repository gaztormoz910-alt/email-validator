# -*- coding: utf-8 -*-
import unicodedata

_VOWELS = frozenset("aeiouy")

WEB_WORDS = frozenset({
    "com", "net", "org", "ru", "info", "online", "www", "gov", "edu", "mail",
    "email", "web", "site", "http", "https", "biz", "data",
})
ROLE_WORDS = frozenset({
    "admin", "support", "sales", "service", "services", "team", "office", "contact",
    "help", "news", "media", "press", "marketing", "noreply", "test", "demo", "user",
    "billing", "jobs", "careers", "webmaster", "postmaster", "official", "booking",
    "bookings", "orders", "reception", "enquiries", "inquiries", "generation",
    "gamer", "gaming", "games", "coder", "artist", "designer", "photography",
    "photographer", "blogger", "vlogger", "youtuber", "streamer", "creator",
    "music", "musician", "traveller", "traveler", "player",
    "developer", "development", "business", "illustrator", "illustration",
    "illustrations", "fotografia", "fotografie", "foto", "fotos", "photo", "collab",
    "collabs", "colab", "audio", "video", "videos", "mgmt", "recruiter", "recruiting",
    "hiring", "inquiry", "writer", "author", "editor", "realtor", "coach", "trainer",
    "fanpage", "work", "resume", "usa", "model", "modeling", "freelance", "freelancer",
    "portfolio", "personal", "private", "contacto", "contato", "kontakt", "talent",
    "seo", "ugc", "smm", "content", "contents", "exteriors", "interiors", "guitars",
    "golf", "bakes",
})

_TAIL_ROLE_WORDS = frozenset({
    "art", "arts", "dev", "law", "pro", "jr", "sr", "md", "phd", "cpa", "esq", "dds",
    "rn", "hr", "pr", "tv", "fm",
    "uk", "us", "ca", "au", "nz", "za", "ae", "qa", "ph", "sg", "bd", "pk", "lk", "ke",
    "gh", "eg", "tr", "ir", "ru", "br", "mx", "fr", "nl", "dk", "pl", "cz", "pt", "gr",
    "ie", "jp", "kr", "cn", "tw", "hk", "vn", "ga", "ny", "tx", "fl", "nc",
})

BUSINESS_WORDS = frozenset({
    "traders", "trader", "exports", "imports", "industries", "industry",
    "properties", "photos", "college", "university", "school", "academy",
    "company", "inc", "llc", "ltd", "corp", "group", "services", "solutions",
    "holdings", "management", "studio", "studios", "productions", "designs",
    "realty", "realestate", "consulting", "logistics", "auto", "motors", "clinic",
    "dental", "medical", "hospital", "church", "bible", "ministries", "daily",
    "update", "agency", "tech", "technologies", "software", "hardware", "store",
    "shop", "shopping", "boutique", "market", "mart", "farm", "farms", "stables",
    "foundation", "trust", "charity", "club", "association", "society", "institute",
    "center", "centre", "network", "system", "systems", "global", "international",
    "national", "regional", "county", "bank", "credit", "insurance", "capital",
    "investment", "investments", "wealth", "finance", "financial", "accounting",
    "tax", "legal", "law", "attorney", "attorneys", "lawyers", "firm", "firms",
    "partners", "associates", "trade", "trading", "enterprise", "enterprises",
    "repair", "spa", "parfum", "transport", "patiententransport", "medizinertest",
    "sports", "sport", "fitness", "gym", "gymnastics", "clothing", "installations",
    "installation", "rental", "rentals", "travel", "tours", "hotel", "hotels",
    "restaurant", "cafe", "salon", "beauty", "fashion", "photography", "films",
    "records", "events", "pharma", "handel",
    "brows", "lashes", "nails", "makeup", "tattoo", "tattoos", "bankruptcy",
    "engineering", "tarot", "distillery", "recruitment", "staffing", "landscapes",
    "landscaping", "plumbing", "construction", "roofing", "cleaning", "catering",
    "bakery", "cakery", "motel", "garage", "collectibles", "collective",
    "entertainment", "publishing", "bookclub", "yoga", "pilates", "wellness",
    "therapy", "veterinary", "pharmacy", "swimwear", "apparel", "jewelry", "jewellery",
    "cosmetics", "skincare", "homes", "property", "estates", "mortgage", "loans",
    "crypto", "holidays", "charters", "employment", "placement", "treasurer",
    "sponsorship", "community", "programs", "equipment", "supply", "supplies",
    "outfitters", "outdoor", "kitchen", "foods", "brewery", "winery", "vineyard",
    "architect", "architects", "architecture", "excavating", "technology",
    "hijab", "hijabs", "abaya", "abayas", "sarees", "kurtis",
})

_SPAM_PARTS = ("escort", "porn", "casino", "viagra", "betting", "xxx", "onlyfans",
               "forex")

_TITLES = frozenset({"mr", "mrs", "ms", "miss", "dr", "prof", "sir", "madam",
                     "rechtsanwalt", "herr", "frau"})

_PHRASE_WORDS = frozenset({
    "hi", "hey", "hello", "says", "say", "im", "iam", "here", "there", "now",
    "ontour", "tour", "real", "the", "my", "love", "loves", "lover", "fan", "boy",
    "girl", "guy", "baby", "cute", "cool", "sexy", "lil", "mister", "ship", "world",
    "life", "only", "just", "best", "star", "smile", "happy", "crazy", "is", "am",
    "on", "of", "and", "in", "at", "to", "you", "mit", "live", "its",
    "und", "with", "from", "for", "your", "be", "we", "us", "do", "go", "so",
})

_NICK_WORDS = frozenset({
    "king", "queen", "prince", "princess", "lord", "lady", "boss", "chief", "babe",
    "lucky", "sweet", "pretty", "lovely", "rock", "rocky", "sky", "snow", "storm",
    "red", "silver", "gold", "golden", "dark", "shadow", "wolf", "lion", "tiger",
    "dragon", "man", "super", "hero", "legend", "wonder", "magic", "royal", "nice",
    "hot", "rebel", "ninja", "warrior", "guy",
    "rich", "lone", "angel", "sunny", "honey", "candy", "kitty", "sweety", "sweetie",
    "sunshine", "star", "cutie", "darling", "sugar", "cookie", "bunny", "baby",
    "mummy", "mommy", "mama", "papa", "daddy", "cool", "cute", "crazy", "wild",
    "happy", "smile", "dream", "lover", "beauty",
    "more", "seven", "even", "given", "mine", "ever", "humble",
})

_NOT_NAME_WORDS = frozenset({
    "zayka", "zaika", "kotik", "solnyshko", "malysh", "kisa", "kiska", "lapochka",
    "babushka", "dedushka", "mamochka", "mamacita", "papito", "habibi", "habibti",
    "canim", "askim", "bebegim", "pyaar", "pyar", "jaan", "yaar", "pagal", "ladka",
    "ladki", "chhota", "chhoti", "munda", "kudi", "mera", "meri", "tera", "teri",
    "desi", "inshallah", "mashallah", "allahu", "subhanallah", "bismillah",
    "alhamdulillah", "amor", "amo", "vida", "corazon", "bonita", "guapa", "carpe",
    "diem", "galatasaray", "fenerbahce", "besiktas", "anonymous", "vamos", "betaji",
})

_KNOWN_PHRASES = frozenset({
    "snowwhite", "kingkong", "donkeykong", "candycrush", "clashroyale", "darthvader",
    "carpediem", "hakunamatata", "greenlantern", "winniethepooh", "winniepooh",
    "hellokitty", "redbull", "lonewolf", "loneranger", "silverfox", "silversurfer",
    "wonderwoman", "ironman", "spiderman", "batman", "superman", "kingarthur",
    "rockstar", "honeybee", "jaihind", "jaishreeram", "jaimatadi", "merabharat",
    "pagalladka", "chhotabheem", "allahuakbar", "inshaallah", "radheradhe",
    "harharmahadev", "trex", "xman", "teamo", "mivida", "luckywinner", "loanoffer",
    "clashofclans", "callofduty", "leagueoflegends", "worldofwarcraft", "gameofthrones",
    "lordoftherings", "harrypotter", "starwars", "madmax", "supermario", "sweetheart",
})

_PLACEHOLDER_WORDS = frozenset({"foo", "foobar", "baz", "qux", "quux", "lorem", "ipsum",
                                "dummy", "xxxx", "asdfgh"})

_NICK_PREFIXES = frozenset({
    "the", "my", "its", "im", "iam", "mr", "dr", "ms", "real", "only", "just", "lil",
    "hey", "hi", "hello", "love", "cute", "cool", "sexy", "crazy", "best", "happy",
    "baby", "big", "mister", "miss", "sir"})

_I_VERB_PREFIXES = ("ilove", "iluv", "ilike", "iheart", "imiss", "ineed", "iwant", "ihate")

_MONTHS = frozenset({"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep",
                     "sept", "oct", "nov", "dec"})

_KEYBOARD_JUNK = ("xyz", "qwe", "asd", "zxc", "qwerty", "asdf", "wasd", "abc", "abcd")

_PHRASE_INSIDE = ("love", "says", "here", "there", "girl", "baby", "cute", "cool",
                  "sexy", "world", "life", "only", "just", "best", "star", "smile",
                  "happy", "crazy", "your", "ontour", "real")

_WORD_ONSETS = frozenset("""
    bh bl br ch cl cr cz dh dj dr dw dz fl fr gh gl gn gr gw hr jh kh kl kn kr kw
    ll lh mb mc mn mr nd ng nj nk ph pl pr ps rh sc sh sk sl sm sn sp sq sr st sv
    sw sz th tr ts tw tz vl vr wh wr zb zd zh zl zn zs zv zw
""".split())

_DECORATION_LETTERS = frozenset("xzq")

_RARE_TAIL_LETTERS = frozenset("xqzj")

_CHINESE_SHORT_SURNAMES = frozenset({
    "li", "xu", "ma", "lu", "su", "wu", "hu", "he", "yu", "du", "ye", "fu", "gu",
    "qi", "ge", "mo", "bi", "ji", "xi", "yi", "ai", "ou", "ng", "ho", "lo", "au",
    "ko", "to",
})

_CHINESE_NAME_COUNTRIES = frozenset({"CN", "TW", "HK", "SG", "MO", "MY"})

_EAST_ASIAN_SHORT_SURNAMES = _CHINESE_SHORT_SURNAMES | frozenset({
    "vu", "do", "le", "ly", "ha", "ta", "la", "oh", "go", "an", "no", "ra", "na",
    "ju"})


MAX_TOKEN_LEN = 14

MAX_SEGMENT_INPUT = 40

PLAIN_WORD_COUNT = 100000


def fold(text):
    if not isinstance(text, str):
        return ""
    if text.isascii():
        return text.lower()
    return "".join(ch for ch in unicodedata.normalize("NFKD", text)
                   if not unicodedata.combining(ch)).lower()


def scripts_of(text):
    if isinstance(text, str) and text.isascii():
        return {"LATIN"} if any(ch.isalpha() for ch in text) else set()
    out = set()
    for ch in text if isinstance(text, str) else "":
        if ch.isalpha():
            name = unicodedata.name(ch, "")
            head = name.split(" ")[0] if name else "?"
            out.add("CJK" if head in ("CJK", "HIRAGANA", "KATAKANA", "HANGUL") else head)
    return out


def is_latin(text):
    return scripts_of(text) <= {"LATIN"}


def has_vowel(token):
    return bool(set(fold(token)) & _VOWELS)


def letters_only(text):
    return "".join(ch for ch in fold(text) if ch.isalpha())


def max_consonant_run(token):
    run = best = 0
    for ch in fold(token):
        if ch.isalpha() and ch not in _VOWELS:
            run += 1
            best = max(best, run)
        else:
            run = 0
    return best


def trailing_consonants(token):
    count = 0
    for ch in reversed(fold(token)):
        if ch.isalpha() and ch not in _VOWELS:
            count += 1
        else:
            break
    return count


def consistent_with_address(tokens, local_letters, min_len=3):
    if not isinstance(local_letters, str):
        return False
    for token in tokens or []:
        t = letters_only(token)
        if len(t) >= min_len and t in local_letters:
            return True
    return False


def display_case(token):
    if not isinstance(token, str) or not token:
        return ""
    if token.islower() or token.isupper():
        return token.title()
    return token
