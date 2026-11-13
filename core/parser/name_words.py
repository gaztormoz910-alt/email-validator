# -*- coding: utf-8 -*-
"""Слова и буквы, по которым судят о куске имени: перечни и текстовые помощники.

Отделены от правил (core/parser/name_quality.py), потому что это знание о
словах, а не решения: веб-хвосты, служебные роли, род деятельности, слова
фраз, месяцы, титулы, клавиатурный мусор и свёртка текста без диакритики.
Правила берут их отсюда и сами ничего в них не меняют.

Примеры в комментариях выдуманы: адресов владельца в коде нет.
"""
import unicodedata

# Гласные латиницы. Кусок без них длиной от двух букв — обломок («bcdf»,
# «qwrt», «ghrzq»), а не имя: таких имён и фамилий не бывает.
_VOWELS = frozenset("aeiouy")

# Веб-хвосты и служебные роли ящика. Именем не бывают ни при каком источнике.
WEB_WORDS = frozenset({
    "com", "net", "org", "ru", "info", "online", "www", "gov", "edu", "mail",
    "email", "web", "site", "http", "https", "biz",
})
ROLE_WORDS = frozenset({
    "admin", "support", "sales", "service", "services", "team", "office", "contact",
    "help", "news", "media", "press", "marketing", "noreply", "test", "demo", "user",
    "billing", "jobs", "careers", "webmaster", "postmaster", "official", "booking",
    "bookings", "orders", "reception", "enquiries", "inquiries", "generation",
    # Занятие или увлечение рядом с именем: «alexgamer», «mike.gamer» — это
    # Alex и Mike, а не «Alex Gamer» (рецензия 08.11.2026). Art и Dev здесь
    # нет намеренно: так зовут людей.
    "gamer", "gaming", "games", "coder", "artist", "designer", "photography",
    "photographer", "blogger", "vlogger", "youtuber", "streamer", "creator",
    "music", "musician", "traveller", "traveler", "player",
})

# Род деятельности: рядом с ним адрес чаще всего не человека, а фирмы.
# Тот же перечень, что был в разборе адреса, плюс то, что всплыло на прогоне
# владельца («sports», «clothing», «gymnastics», «spa», «parfum»).
BUSINESS_WORDS = frozenset({
    # «Kumar Traders» в профиле — лавка, а не человек (рецензия 08.11.2026).
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
})

# Части слов, которые выдают спам или рекламу в ПРОФИЛЕ. Ищутся подстрокой:
# такое пишут слитно, вроде «CityEscortsAnna».
_SPAM_PARTS = ("escort", "porn", "casino", "viagra", "betting", "xxx", "onlyfans",
               "forex")

# Титулы и звания: снимаются с имени, а не хоронят его.
_TITLES = frozenset({"mr", "mrs", "ms", "miss", "dr", "prof", "sir", "madam",
                     "rechtsanwalt", "herr", "frau"})

# Слова фраз, из которых складывают ники: «arjunsayshello», «katieontour»,
# «nehaimhere», «iammarkjones», «bethechange». Имени в них нет, и в фамилию
# их склеивать нельзя. Коротких слов, которые одновременно настоящие имена
# (An, As, He), здесь нет намеренно: «an.nguyen» — это Ан Нгуен.
_PHRASE_WORDS = frozenset({
    "hi", "hey", "hello", "says", "say", "im", "iam", "here", "there", "now",
    "ontour", "tour", "real", "the", "my", "love", "loves", "lover", "fan", "boy",
    "girl", "guy", "baby", "cute", "cool", "sexy", "lil", "mister", "ship", "world",
    "life", "only", "just", "best", "star", "smile", "happy", "crazy", "is", "am",
    "on", "of", "and", "in", "at", "to", "you", "mit", "live", "its",
    "und", "with", "from", "for", "your", "be", "we", "us", "do", "go", "so",
})

# Слова-прозвища. Одно такое «имя» — ник, а не имя, всегда: «king77»,
# «princess», «angel2000», «iamking», «mr.nice», «TheRock» (рецензия
# 08.11.2026). Индекс имён и база знают их именами — Prince 10-е, Angel 5-е,
# Lucky 15-е место, — но это анкеты, где вписано прозвище, и обращение
# «Здравствуйте, Princess» почти всегда неверно. Рядом с фамилией имя
# остаётся: «angel.lopez», «prince.adewale». Частые настоящие имена-слова
# (Grace, Rose, Mark, Joy, Hope, Faith, Will) здесь нет намеренно.
# Сюда же — частые слова, которые база знает «именем» по шуму анкет: more,
# seven, even, given, mine, ever («more85» давал «More»).
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

# Слова, с которыми строка — не имя вовсе, где бы они ни стояли: ласковые
# слова и лозунги других языков латиницей («zayka», «canim», «mamacita»,
# «inshallah», «jaihind»), из которых разбор вырезал «имена» («Z Ayka»,
# «C Anim»; рецензия 08.11.2026). Слова, которые одновременно
# имена (Raja, Rani, Sona, Babu, Hind, Bheem), здесь нет намеренно.
_NOT_NAME_WORDS = frozenset({
    "zayka", "zaika", "kotik", "solnyshko", "malysh", "kisa", "kiska", "lapochka",
    "babushka", "dedushka", "mamochka", "mamacita", "papito", "habibi", "habibti",
    "canim", "askim", "bebegim", "pyaar", "pyar", "jaan", "yaar", "pagal", "ladka",
    "ladki", "chhota", "chhoti", "munda", "kudi", "mera", "meri", "tera", "teri",
    "desi", "inshallah", "mashallah", "allahu", "subhanallah", "bismillah",
    "alhamdulillah", "amor", "amo", "vida", "corazon", "bonita", "guapa", "carpe",
    "diem", "galatasaray", "fenerbahce", "besiktas", "anonymous", "vamos", "betaji",
})

# Известные фразы, герои и марки, которые разбор принимал за имя и фамилию:
# «Snow White», «King Kong», «Candy Crush» (рецензия 08.11.2026). Сверяется
# строка букв подряд идущих кусков, без пробелов.
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

# Заглушки программистов: адрес с ними — пример или тест, а не человек
# («foo.bar» давал «Foo Bar»).
_PLACEHOLDER_WORDS = frozenset({"foo", "foobar", "baz", "qux", "quux", "lorem", "ipsum",
                                "dummy", "xxxx", "asdfgh"})

# Приставки ников, которые прочтение находит в начале «имени»: «the|be»
# внутри «thebe» (thebesteve). Предлогов (to, in, on) здесь нет: «to|mar»
# внутри Tomar — это фамилия (рецензия 08.11.2026).
_NICK_PREFIXES = frozenset({
    "the", "my", "its", "im", "iam", "mr", "dr", "ms", "real", "only", "just", "lil",
    "hey", "hi", "hello", "love", "cute", "cool", "sexy", "crazy", "best", "happy",
    "baby", "big", "mister", "miss", "sir"})

# «Я + глагол» в начале ника: «iloveyu», «imissu», «ihatemondays». Имён с
# таким началом нет, а «Ilo» из «ilove…» разбор доставал.
_I_VERB_PREFIXES = ("ilove", "iluv", "ilike", "iheart", "imiss", "ineed", "iwant", "ihate")

# Месяцы. «augnov» — это август-ноябрь, а не «Aug Nov». Одиночное «Jan» или
# «Mar» остаётся именем: так зовут людей.
_MONTHS = frozenset({"jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep",
                     "sept", "oct", "nov", "dec"})

# Клавиатурные хвосты ников: «amandaxyz», «annaqwe». Мусор, а не фамилия.
_KEYBOARD_JUNK = ("xyz", "qwe", "asd", "zxc", "qwerty", "asdf", "wasd", "abc", "abcd")

# Слова фраз, которых не бывает внутри неизвестной базе фамилии:
# «jen|lovesea», «das|loth|girl». Короче четырёх букв и «live», «tour»,
# «ship», «with» здесь нет: они встречаются внутри фамилий (Oliveira,
# Latour, Shipley, Withers).
_PHRASE_INSIDE = ("love", "says", "here", "there", "girl", "baby", "cute", "cool",
                  "sexy", "world", "life", "only", "just", "best", "star", "smile",
                  "happy", "crazy", "your", "ontour", "real")

# Украшение, а не инициал: «paulx», «brownx», «ninaz». Буква «x» на конце
# ника — это стиль, по ней к человеку не обратишься.
_DECORATION_LETTERS = frozenset("xzq")

# Редкие буквы в хвосте: «amyxk», «joyqz», «ewaxk» — приклеенный мусор, а не
# фамилия, которую не знает база.
_RARE_TAIL_LETTERS = frozenset("xqzj")

# Короткие китайские фамилии. Индекс популярных имён знает «lu», «ma», «su»
# как имена латинских стран, и без этого перечня «lu.chen» терял бы фамилию
# по правилу «двухбуквенное имя чужой страны впереди — это инициалы».
_CHINESE_SHORT_SURNAMES = frozenset({
    "li", "xu", "ma", "lu", "su", "wu", "hu", "he", "yu", "du", "ye", "fu", "gu",
    "qi", "ge", "mo", "bi", "ji", "xi", "yi", "ai", "ou", "ng", "ho", "lo", "au",
    "ko", "to",
})

# Страны, где «lu chen» — запись китайского имени, а не инициалы.
_CHINESE_NAME_COUNTRIES = frozenset({"CN", "TW", "HK", "SG", "MO", "MY"})

# Двухбуквенные фамилии Китая, Вьетнама и Кореи: «huong.do», «tam.vu»,
# «minjun.oh», «t.vu», «na.liu». Без перечня между разделителями они
# считались словом или обломком, и в колонке оставалось одно имя или пусто
# (рецензия 08.11.2026). Na — корейская фамилия и частое китайское имя.
_EAST_ASIAN_SHORT_SURNAMES = _CHINESE_SHORT_SURNAMES | frozenset({
    "vu", "do", "le", "ly", "ha", "ta", "la", "oh", "go", "an", "no", "ra", "na",
    "ju"})


# Длиннее этого кусок — слитая фраза или набор символов, а не одно имя.
MAX_TOKEN_LEN = 14

# Длиннее этого слитную строку не разбираем: это уже не имя, а фраза или
# случайный набор, и перебор вариантов стоит дороже пользы.
MAX_SEGMENT_INPUT = 40

# Слово целиком — английское, если его частота в корпусе сегментатора не
# ниже этой: «theorist» (411 тыс.), «writer». Имена и фамилии из базы это
# правило не задевает — они проверяются раньше.
PLAIN_WORD_COUNT = 100000


def fold(text):
    """Нижний регистр без диакритики: «Müller» -> «muller». Для сверки, не для показа."""
    if not isinstance(text, str):
        return ""
    # Короткий путь: у ASCII нет ни диакритики, ни составных знаков. Разбор
    # слитной строки зовёт fold сотни раз на адрес, и таблица Юникода на
    # каждую букву была главной тратой времени (профиль 07.11.2026).
    if text.isascii():
        return text.lower()
    return "".join(ch for ch in unicodedata.normalize("NFKD", text)
                   if not unicodedata.combining(ch)).lower()


def scripts_of(text):
    """Набор алфавитов, которыми написаны буквы строки: {'LATIN'}, {'CJK'}, ..."""
    if isinstance(text, str) and text.isascii():
        # Буквы ASCII — латиница; ответ тот же, без таблицы Юникода.
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
    """Только буквы, в нижнем регистре и без диакритики."""
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
    """Есть ли у имени опора в самом адресе: хотя бы один кусок от трёх букв.

    Профиль Gravatar привязан к адресу, но пишут в него что угодно: у
    адреса из имени и цифр там бывает «moviebuff» или чужой логин. Ник, ни один
    кусок которого не встречается в имени ящика, — не проверенное имя, а
    просто строка из чужой анкеты.
    """
    if not isinstance(local_letters, str):
        return False
    for token in tokens or []:
        t = letters_only(token)
        if len(t) >= min_len and t in local_letters:
            return True
    return False


def display_case(token):
    """Регистр для показа: «deb» -> «Deb», «JOHN» -> «John», «McDonald» как есть."""
    if not isinstance(token, str) or not token:
        return ""
    if token.islower() or token.isupper():
        return token.title()
    return token
