import re
import os
import functools
import wordsegment
import threading
from .osint import OSINTOperator
from .names_index import is_known_name, countries_for
from .name_quality import (NameQuality, letters_only, is_latin, LEANING_FIRST_RANK,
                           LEANING_SURNAME_TOP, LEANING_STRONG_FIRST, SPLIT_FIRST_RANK)
from .name_words import scripts_of, consistent_with_address, _KEYBOARD_JUNK, _NOT_NAME_WORDS
from .translit import variants as translit_variants

_nd = None
_nd_lock = threading.Lock()

# Слова, которые именем быть не могут ни при каких обстоятельствах.
#
# Список нужен потому, что индекс популярных имён собран из реальных баз, а в
# реальных базах встречается всё: «the» есть как вьетнамское имя, «as» — как
# скандинавское, «live» кто-то записал в анкете. Формально они там есть, но в
# локальной части адреса `theadamvelardes` или `livemarko` это не имя
# человека, а кусок фразы.
#
# Список закрытый и короткий намеренно: это служебные слова языка —
# артикли, местоимения, предлоги, союзы, вспомогательные и самые частые
# глаголы. Всё остальное решает индекс. Обратная логика — «считать не-именем
# всё, что есть в словаре» — уже была и стоила потерянных имён у каждого
# третьего адреса.
#
# Слов, которые одновременно служебные и распространённые имена (may, will,
# grant, hope, faith, rose), здесь нет: они разбираются раньше, по белому
# списку name_exceptions.
_NEVER_A_NAME = {
    "the", "a", "an", "and", "or", "but", "if", "then", "than", "so", "because",
    "this", "that", "these", "those", "such", "same", "other", "another",
    "is", "are", "was", "were", "be", "been", "being", "am", "do", "does",
    "did", "done", "have", "has", "had", "having",
    "would", "shall", "should", "can", "could", "might", "must", "ought",
    "i", "you", "he", "she", "it", "we", "they", "me", "him", "her", "us",
    "them", "my", "your", "his", "its", "our", "their", "mine", "yours",
    "of", "in", "on", "at", "to", "for", "with", "from", "by", "about",
    "into", "onto", "over", "under", "after", "before", "between", "through",
    "during", "without", "within", "against", "among", "around", "across",
    "not", "no", "nor", "yes", "all", "any", "some", "each", "every", "both",
    "few", "many", "much", "more", "most", "less", "least", "own", "very",
    "too", "just", "only", "also", "even", "still", "already", "always",
    "never", "often", "sometimes", "again", "once", "twice",
    "here", "there", "where", "when", "why", "how", "what", "which", "who",
    "whom", "whose", "while", "until", "since", "although", "though",
    "live", "get", "got", "make", "made", "go", "goes", "went", "gone",
    "come", "came", "see", "saw", "seen", "know", "knew", "known", "think",
    "thought", "take", "took", "taken", "want", "wanted", "use", "used",
    "give", "gave", "given", "find", "found", "tell", "told", "ask", "asked",
    "work", "works", "call", "called", "try", "tried", "need", "needed",
    "feel", "felt", "become", "leave", "left", "put", "keep", "kept", "let",
    "begin", "seem", "help", "talk", "turn", "start", "show", "hear", "play",
    "run", "move", "like", "live", "believe", "hold", "bring", "happen",
    "write", "provide", "sit", "stand", "lose", "pay", "meet", "include",
    "continue", "set", "learn", "change", "lead", "understand", "watch",
    "follow", "stop", "create", "speak", "read", "allow", "add", "spend",
    "grow", "open", "walk", "win", "offer", "remember", "love", "consider",
    "appear", "buy", "wait", "serve", "die", "send", "expect", "build",
    "stay", "fall", "cut", "reach", "kill", "remain",
    "new", "old", "big", "small", "good", "bad", "best", "worst", "great",
    "little", "long", "short", "high", "low", "next", "last", "first",
    "same", "different", "important", "public", "able", "free", "real",
    "sure", "true", "false", "full", "empty", "hot", "cold", "fast", "slow",
    "one", "two", "three", "four", "five", "six", "seven", "eight", "nine",
    "ten", "hundred", "thousand", "million",
    "www", "mail", "email", "user", "test", "demo", "example", "sample",
    "account", "profile", "login", "password", "home", "site", "web", "net",
}

def get_name_dataset():
    global _nd
    if _nd is None:
        with _nd_lock:
            if _nd is None:
                try:
                    from names_dataset import NameDataset
                    _nd = NameDataset()
                except ImportError:
                    _nd = None
    return _nd


@functools.lru_cache(maxsize=262144)
def name_ranks(word):
    """(лучший ранг как ИМЯ, лучший ранг как ФАМИЛИЯ) в базе на 138 млн.

    Таблицы базы читаются напрямую, мимо её search(): поиск стоит 41 мкс,
    прямой доступ — 0,05 (замерено 07.11.2026). Строгий разбор спрашивает
    базу о каждом куске слитной строки — сотни раз на адрес, — и через
    search() это тормозило бы прогон.

    Ранг — место в стране, где имя чаще всего. Само «есть в базе» ничего не
    значит (там есть и 'aaa'), поэтому правила смотрят на ранг.
    """
    if not isinstance(word, str) or not word:
        return None, None
    nd = get_name_dataset()
    if nd is None:
        return None, None
    key = word.strip().title()

    def best(table):
        info = table.get(key) if isinstance(table, dict) else None
        if not info:
            return None
        ranks = [r for r in (info.get("rank") or {}).values() if r]
        return min(ranks) if ranks else None

    return best(getattr(nd, "first_names", None)), best(getattr(nd, "last_names", None))


@functools.lru_cache(maxsize=65536)
def surname_leaning(word):
    """Имя, которое в СВОЕЙ главной стране чаще фамилия: Kowalska, Sharma.

    Сравнение по лучшим рангам вообще путало страны: у Paras лучший ранг
    имени и лучший ранг фамилии могли прийти из разных стран, и сильное
    индийское имя записывалось в фамилии. Здесь берётся страна, где слово
    чаще всего ИМЯ, и в ней же смотрится его место среди фамилий.
    """
    if not isinstance(word, str) or not word:
        return False
    nd = get_name_dataset()
    if nd is None:
        return False
    key = word.strip().title()
    firsts = getattr(nd, "first_names", None)
    lasts = getattr(nd, "last_names", None)
    if not isinstance(firsts, dict) or not isinstance(lasts, dict):
        return False
    first = {c: r for c, r in ((firsts.get(key) or {}).get("rank") or {}).items() if r}
    if not first:
        return False
    country, rank = min(first.items(), key=lambda item: item[1])
    surnames = {c: r for c, r in ((lasts.get(key) or {}).get("rank") or {}).items() if r}
    # Фамилия из первой десятки, которая как имя не входит и в полсотню,
    # — фамилия: Patel (2-я фамилия базы, 89-е имя), Singh. Kumar (12-е
    # имя), Kim (10-е), Khan (2-е) остаются именами — их так и зовут.
    if surnames and min(surnames.values()) <= LEANING_SURNAME_TOP and rank > LEANING_STRONG_FIRST:
        return True
    if rank <= LEANING_FIRST_RANK:
        return False
    last = surnames.get(country)
    return bool(last) and last < rank


@functools.lru_cache(maxsize=65536)
def gender_share(word):
    """Доля самого частого пола у слова как имени в базе (0.5–1.0) или None.

    Признак имени, независимый от рангов: см. GENDERED_SHARE в
    core/parser/name_evidence.py.
    """
    if not isinstance(word, str) or not word:
        return None
    nd = get_name_dataset()
    firsts = getattr(nd, "first_names", None) if nd is not None else None
    if not isinstance(firsts, dict):
        return None
    shares = [v for v in ((firsts.get(word.strip().title()) or {}).get("gender") or {}).values()
              if isinstance(v, (int, float))]
    return max(shares) if shares else None


def split_name(full_name):
    """Разбивает готовое имя на имя и фамилию.

    Возвращает (first, last). Одно слово — только имя, фамилия пустая: это
    честнее, чем записать единственный токен в обе колонки.

    Средние части отбрасываются намеренно. У «Minh Anh Tran» фамилия
    Nguyen — последняя, у «Nikhil Ram Sethi» тоже последняя; вставлять Ngoc
    и Yash в отдельную колонку значит выдумывать структуру, которой в исходной
    строке нет. Первый токен и последний — это ровно то, что строка
    действительно содержит.

    Порядок «имя фамилия» здесь допущение, и оно верно для латиницы, из
    которой этот разбор и делается. Для китайских и венгерских записей
    порядок обратный, и различить их по строке нельзя — поэтому в выгрузке
    рядом остаётся колонка с полным именем.
    """
    if not isinstance(full_name, str):
        return "", ""
    parts = [piece for piece in full_name.replace(",", " ").split() if piece]
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[-1]


def строгий_режим_имён():
    """Включён ли режим «Точность». Переключатель ОДИН на имя и страну.

    Владелец жмёт одну кнопку и ждёт, что вырастет качество, а не одна
    колонка из двух. Пока режим действовал только на страну, нажатая
    «Точность» оставляла в колонке «Имя» «Kava Terasports», «Sskam At» и
    «Anlie Www» — и подписывала их «из самого адреса — факт».

    Импорт внутри функции намеренно: ml_predictor тянет за собой словарь
    стран, а этот модуль грузится и там, где страна не нужна вовсе.
    """
    try:
        from .ml_predictor import get_country_mode
        return get_country_mode() == "accuracy"
    except Exception:
        # Режим неизвестен — работаем как раньше. Молча УЖЕСТОЧИТЬ разбор
        # из-за сбоя импорта нельзя: половина базы осталась бы без имён.
        return False


class NameExtractor:
    def __init__(self, enable_osint=False, proxy_provider=None):
        # Load wordsegment corpus into memory (only happens once per process)
        wordsegment.load()
        self.enable_osint = enable_osint
        # proxy_provider обязателен, если заданы прокси: без него OSINT-запрос
        # к Gravatar уходил с реального IP пользователя на каждом адресе,
        # у которого не удалось разобрать имя.
        self.osint_operator = OSINTOperator(proxy_provider=proxy_provider) if enable_osint else None
        # Профиль последнего OSINT-запроса — по одному на поток
        self._osint_local = threading.local()
        
        # Load the 138 million names dataset
        self.nd = get_name_dataset()
        
        # Load English words dictionary
        self.english_words = set()
        try:
            dict_path = os.path.join(os.path.dirname(__file__), "..", "english_words.txt")
            with open(dict_path, "r", encoding="utf-8") as f:
                self.english_words = {line.strip().lower() for line in f if line.strip()}
        except Exception:
            pass
            
        # Exception list for English words that are extremely common real names
        self.name_exceptions = {
            "mark", "will", "may", "april", "june", "august", "hope", "faith", "joy", 
            "grace", "rose", "lily", "christian", "miles", "chase", "grant", "hunter", 
            "mason", "carter", "parker", "peter", "john", "paul", "george", "adam", 
            "david", "scott", "frank", "jack", "harry", "nick", "chris", "alex", "sam", 
            "max", "robin", "brook", "dawn", "eve", "glen", "jean", "kelly", "page",
            "penny", "ray", "victor", "art", "cliff", "crystal", "earl", "guy", "jasper",
            "james", "robert", "mary", "patricia", "michael", "linda", "william",
            "elizabeth", "barbara", "richard", "susan", "joseph", "jessica", "sarah",
            "thomas", "karen", "charles", "lisa", "matthew", "betty", "anthony",
            "donald", "sandra", "ashley", "dorothy", "steven", "kimberly", "andrew",
            "emily", "joshua", "donna", "kenneth", "michelle", "kevin", "carol", "brian",
            "amanda", "melissa", "edward", "deborah", "jeffrey", "jeff", "smith", "fisher",
            "taylor", "brown", "williams", "jones", "miller", "davis", "garcia", "rodriguez",
            "wilson", "martinez", "anderson", "thomas", "hernandez", "moore", "martin",
            "jackson", "thompson", "white", "lopez", "lee", "gonzalez", "harris", "clark",
            "lewis", "robinson", "walker", "perez", "hall", "young", "allen", "sanchez",
            "wright", "king", "scott", "green", "baker", "adams", "nelson", "hill", "ramirez",
            "campbell", "mitchell", "roberts", "carter", "phillips", "evans", "turner",
            "torres", "parker", "collins", "edwards", "stewart", "flores", "morris", "nguyen",
            "murphy", "rivera", "cook", "rogers", "morgan", "peterson", "cooper", "reed",
            "bailey", "bell", "gomez", "kelly", "howard", "ward", "cox", "diaz", "richardson",
            "wood", "watson", "brooks", "bennett", "gray", "james", "reyes", "cruz", "hughes",
            "price", "myers", "long", "foster", "sanders", "ross", "morales", "powell",
            "sullivan", "russell", "ortiz", "jenkins", "gutierrez", "perry", "butler", "barnes"
        }

        # Строгая проверка кусков имени (core/parser/name_quality.py). Ей
        # отдаются те же знания, что и прежнему разбору: индекс популярных
        # имён, база фамилий, английский словарь и перечень имён-слов.
        self.quality = NameQuality(
            is_first=is_known_name, name_ranks=name_ranks,
            english_words=self.english_words, countries_for=countries_for,
            english_surnames=self.name_exceptions,
            word_counts=getattr(wordsegment, "UNIGRAMS", None),
            leaning=surname_leaning, gender_share=gender_share)

    def _is_generic_word(self, word):
        """Returns True if the word is a generic dictionary word and not a common name."""
        w = word.lower()
        bad_roles = {
            "admin", "info", "support", "sales", "contact", "help", "office", "marketing", 
            "webmaster", "postmaster", "hello", "noreply", "no-reply", "news", "update",
            "service", "team", "billing", "press", "media", "jobs", "careers"
        }
        if w in bad_roles:
            return True

        # Явный белый список имён-которые-и-слова: mark, may, grace, rose.
        if w in self.name_exceptions:
            return False

        # Служебные слова языка. Закрытый список из полутора сотен штук —
        # артикли, местоимения, предлоги, вспомогательные и самые частые
        # глаголы. Это единственное, что действительно не может быть именем.
        if w in _NEVER_A_NAME:
            return True

        # А вот дальше решает ИНДЕКС ПОПУЛЯРНЫХ ИМЁН, а не словарь.
        #
        # Здесь была самая дорогая ошибка всего разбора: «слово есть в
        # английском словаре и не входит в наш список исключений — значит не
        # имя». Под это правило попадали justin, leo, sue, hunter, dean, faith
        # и ещё тысячи настоящих имён, потому что список исключений писался
        # руками и в нём полторы сотни строк. На живой базе владельца из-за
        # этого терялись имена у каждого третьего адреса: justinbrody57 и
        # suelovesfrogs7 отдавали пустоту, хотя имя в них написано открытым
        # текстом.
        #
        # Индекс на 43 306 отобранных имён отвечает на тот же вопрос честно и
        # не требует ручного сопровождения. Спрашиваем именно его, а не базу
        # на 138 млн: в базе такого размера находится почти любое сочетание
        # букв, и её «да» ничего не различает.
        if is_known_name(w):
            return False

        return w in self.english_words

    def _has_business_words(self, words_list):
        """Returns True if any word in the list strongly indicates a business/organization."""
        business_keywords = {
            "properties", "photos", "college", "university", "school", "academy", 
            "company", "inc", "llc", "group", "services", "solutions", "holdings", 
            "management", "studios", "productions", "designs", "realty", "realestate", 
            "consulting", "logistics", "auto", "motors", "clinic", "dental", "medical", 
            "hospital", "church", "bible", "ministries", "plenty", "daily", "news", 
            "update", "press", "media", "agency", "tech", "technologies", "software",
            "hardware", "store", "shop", "boutique", "market", "mart", "farm", "farms",
            "stables", "foundation", "trust", "charity", "club", "association", "society",
            "institute", "center", "centre", "network", "system", "systems", "global",
            "international", "national", "regional", "local", "county", "city", "town",
            "state", "republic", "union", "bank", "credit", "insurance", "capital",
            "investment", "investments", "wealth", "finance", "financial", "accounting",
            "tax", "legal", "law", "attorney", "attorneys", "lawyers", "firm", "firms",
            "partners", "associates", "brothers", "sons", "daughters", "family"
        }
        for w in words_list:
            if w.lower() in business_keywords:
                return True
        return False

    def _is_valid_name(self, word, role="any"):
        """Есть ли слово в базе имён (138M записей).

        role='first' — только как ИМЯ, role='last' — только как ФАМИЛИЯ,
        'any' — как что угодно.

        Роли важны. Проверка «встречается хоть кем-то где-то в мире» слишком
        широкая: под неё попадает даже 'aaa'. А ещё она мешает поймать
        оверсегментацию, когда фамилия разваливается на куски, каждый из
        которых где-то является именем.

        Транслит перебирается: dmitriy / dmitry / dmitri — одно имя, но база
        знает эти написания по-разному.
        """
        if not word or not isinstance(word, str):
            return False

        word_clean = word.strip()
        if len(word_clean) < 2:
            return False

        # Быстрый путь: локальный индекс популярных имён отвечает мгновенно,
        # тогда как поиск по базе на 138 млн записей стоит заметно дороже.
        # Как фамилию индекс не подтверждает — в нём только имена.
        if role in ("any", "first") and is_known_name(word_clean):
            return True

        if not self.nd:
            return False

        keys = ("first_name", "last_name") if role == "any" else (role + "_name",)

        for variant in translit_variants(word_clean.lower()):
            try:
                res = self.nd.search(variant.title())
            except Exception:
                continue
            if res and any(res.get(key) for key in keys):
                return True

        return False

    # Короче этого куски от сегментатора считаем обломками, а не словами.
    # Четыре буквы — потому что реальных имён и фамилий короче почти нет
    # (Ann, Kim, Lee — исключения, но они и не разваливаются), а обломки
    # английского сегментатора на неанглийских фамилиях как раз такие.
    _SEGMENT_MIN = 4

    def _repair_oversegmentation(self, parts):
        """Склеивает обломки, на которые английский сегментатор рвёт чужие фамилии.

        Зачем. wordsegment обучен на английском корпусе и слова «rogbin» не
        знает, поэтому режет `rogbinpetr` на ['rog','bin','petr'] — и
        адрес человека превращался в «Rog Bin Petr». Проверить склейку по
        базе имён нельзя: базы на 138 млн записей «rogbin» тоже не знает,
        зато знает и «rog», и «bin» по отдельности — на такой выборке
        найдётся почти любое трёхбуквенное сочетание, и подтверждение
        ничего не значит.

        Поэтому решает не база, а ДЛИНА: кусок короче четырёх букв — почти
        наверняка обломок, и его надо приклеить к соседу. Одиночная буква
        рядом с полноценным словом — исключение: это инициал (j.smith,
        rogbin p), и склеивать её нельзя.

        Пример выдуманный, но поведение на нём замерено тем же кодом, что и
        на исходном случае из жизни: разбиение, склейка и итоговое имя
        совпадают. Настоящий адрес здесь стоять не может — эта строка
        уезжает в собранную программу и видна любому, кто её разберёт.

        ['rog','bin','petr']        -> ['rogbin','petr']
        ['rog','bin','p']           -> ['rogbin','p']
        ['mohammed','lah','lali']   -> ['mohammed','lahlali']
        ['j','smith']               -> ['j','smith']      (инициал не тронут)
        ['robert','anderson']       -> без изменений
        """
        if not parts or len(parts) < 2:
            return parts

        merged = []
        buf = ""
        for index, part in enumerate(parts):
            buf += part
            following = parts[index + 1] if index + 1 < len(parts) else ""
            is_last = not following

            # Инициал: ОДНА буква рядом с полноценным словом или в самом конце.
            #
            # Ровно одна, не две. Двухбуквенный кусок в начале слитной строки —
            # это не инициал, а обломок: `savithrek` сегментатор делит на
            # ['pa','vithrek'], и «Sa Vithrek» уходило в колонку «Имя» как
            # имя живого человека. Инициалы люди пишут через разделитель
            # (`j.smith`), а там починка вообще не запускается.
            if len(buf) == 1 and (is_last or len(following) >= self._SEGMENT_MIN):
                merged.append(buf)
                buf = ""
                continue

            # Короткий кусок, который ЗНАЕТ индекс популярных имён, — не
            # обломок, а настоящее имя. Вьетнамские Hai и Ngoc, корейские и
            # китайские слоги короткие по своей природе, и склеивать их
            # значит ломать правильный разбор. Спрашиваем именно индекс на
            # 43 306 отобранных имён, а не базу на 138 млн: в базе такого
            # размера находится почти любое трёхбуквенное сочетание, включая
            # обломок «rog», и её ответ здесь ничего не различает.
            # Двухбуквенный ПЕРВЫЙ кусок — обломок, даже если индекс его знает:
            # в индексе есть и «pa», и «da», и «jy». Дальше по строке короткие
            # куски законны (вьетнамские Hai, Ngoc), а в начале слитной записи
            # человек своё имя двумя буквами не пишет.
            if len(buf) == 2 and not merged and not is_last:
                continue

            # Короткий кусок, который ЗНАЕТ индекс популярных имён, — не
            # обломок, а настоящее имя. Вьетнамские Hai и Ngoc, корейские и
            # китайские слоги короткие по своей природе, и склеивать их
            # значит ломать правильный разбор. Спрашиваем именно индекс на
            # 43 306 отобранных имён, а не базу на 138 млн: в базе такого
            # размера находится почти любое трёхбуквенное сочетание, включая
            # обломок «rog», и её ответ здесь ничего не различает.
            if len(buf) < self._SEGMENT_MIN and is_known_name(buf):
                merged.append(buf)
                buf = ""
                continue

            if len(buf) >= self._SEGMENT_MIN or is_last:
                merged.append(buf)
                buf = ""

        if buf:
            if merged:
                merged[-1] += buf
            else:
                merged.append(buf)
        return merged

    def _merge_oversegmented_tail(self, parts):
        """Склеивает фамилию, которую разбило на куски.

        `mohammedlahlali` сегментатор делит на ['mohammed', 'lah', 'lali'] —
        и получается «Mohammed Lah Lali». Каждый кусок по отдельности где-то
        в мире является именем, поэтому старая проверка «есть в базе» это
        пропускала. Проверяем ролями: если хвостовые куски не годятся как
        фамилии, а их склейка годится — склеиваем.
        """
        if len(parts) < 3 or not self.nd:
            return parts
        head, tail = parts[0], parts[1:]
        merged = "".join(tail)
        if len(merged) < 4 or not self._is_valid_name(merged, role="last"):
            return parts

        # Признак развала: куски короткие. База имён огромна, и в ней найдётся
        # фамилия почти на любые три буквы — 'Lah' и 'Lali' там есть обе.
        # Поэтому решает не «есть ли кусок в базе», а его длина.
        if all(len(part) <= 4 for part in tail):
            return [head, merged]

        # Ни один хвостовой кусок не годится в фамилии, а склейка годится
        if not any(self._is_valid_name(part, role="last") for part in tail):
            return [head, merged]

        return parts

    # Сколько кусков разрешено оставить в хвосте, когда каждый из них —
    # настоящее имя. Два: «Minh Anh Tran» бывает, «Hai Ngoc Van Nguyen» —
    # уже почти наверняка разваленная сегментатором строка.
    _MAX_CONFIRMED_TAIL = 2

    def _collapse_tail(self, parts, from_separators=False):
        """Сводит хвост к ОДНОЙ фамилии, если он не состоит из настоящих имён.

        Зачем. Сегментатор разбирает слитную фамилию на английские слова:
        `rachaeldakoalagirl` -> ['rachael','da','koala','girl'],
        `johnoakreps` -> ['john','oak','reps'], `suelovesfrogs` ->
        ['sue','loves','junk']. Раньше на такое стояло правило «кусков больше
        трёх — сдаёмся», и адрес отдавал ПУСТОТУ, хотя имя в нём написано
        открытым текстом: терялся не только хвост, но и найденное имя.

        Здесь хвост склеивается в одну фамилию — «Rachael Dakoalagirl»,
        «John Oakreps», «Sue Lovesfrogs». Это ровно та реконструкция, которую
        делает человек, читая адрес глазами.

        Настоящие многосоставные имена при этом не ломаются: если КАЖДЫЙ
        хвостовой кусок знает индекс популярных имён и он не короче трёх букв,
        куски остаются как есть — вьетнамское «Minh Anh Tran» переживает
        разбор целиком.

        Спрашивается индекс на 43 тысячи имён, а не база на 138 млн: в базе
        такого размера находится почти любое буквосочетание, и «acre» с «ps»
        она подтвердит наравне с «nguyen».
        """
        if len(parts) < 3:
            return parts
        # Разделители поставил человек: `jonathan.k.ward` — это имя, инициал и
        # фамилия, а не разваленная строка. Склейка давала «Jonathan Kward».
        if from_separators:
            return parts[:3]
        head, tail = parts[0], parts[1:]
        if (len(tail) <= self._MAX_CONFIRMED_TAIL
                and all(len(part) >= 3 and is_known_name(part) for part in tail)):
            return parts
        return [head, "".join(tail)]

    # Больше этого числа кусков — уже не разваленное имя, а фраза или
    # набор символов: сегментатор режет `bestdealsonline2024` на пять слов, и
    # склеивать их в фамилию бессмысленно.
    _MAX_SEGMENTS = 5

    def _finalize_guess(self, parts, from_separators=False):
        """Прежний разбор кусков — догадка режима «Заполненность». Список кусков или [].

        Работает только тогда, когда строгий разбор (_address_name) имени не
        нашёл, и только в режиме «Заполненность»: это его компромисс «больше
        имён ценой точности», и неподтверждённое «Kava Terasports» здесь
        допустимо. Заведомый мусор из результата убирает clean_guess.

        from_separators=True означает, что куски пришли из ЯВНЫХ разделителей
        (`leo.fontanieu`, `j_smith`), а не от сегментатора. Границы в этом
        случае поставил сам человек, и чинить их нельзя — см. ниже.
        """
        if not parts:
            return []
        if len(parts) > self._MAX_SEGMENTS:
            return []
        # Деловое слово ОТБРАСЫВАЕТСЯ, если оно стоит не первым и без него
        # остаётся человеческая запись.
        #
        # `laura.ribeiro.tech@gmail.com` — это Laura Ribeiro, которая
        # приписала к личному адресу род занятий. Раньше слово «tech» роняло
        # весь разбор, и имя терялось целиком. А вот `info.tech@company.com`
        # по-прежнему отбрасывается: там деловое слово не одно и имени нет.
        if self._has_business_words(parts):
            head_is_business = self._has_business_words(parts[:1])
            trimmed = [p for p in parts if not self._has_business_words([p])]
            if head_is_business or len(trimmed) < 2:
                return []
            parts = trimmed

        # Починка развала — только для кусков ОТ СЕГМЕНТАТОРА.
        #
        # Точка в `leo.fontanieu` поставлена человеком, и склеивать по ней
        # нечего. А склейка происходила: «leo» короче четырёх букв, и если бы
        # индекс его не знал, вышло бы «Leofontanieu». Для имён вроде Bo, Ed,
        # Jo — а их в базах много — так и выходило.
        if not from_separators:
            parts = self._repair_oversegmentation(parts)
        parts = self._merge_oversegmented_tail(parts)
        parts = self._collapse_tail(parts, from_separators)

        first_part = parts[0]
        # Инициал вместо имени (j.smith) — судим по второму куску
        is_initial = len(first_part) == 1 and len(parts) > 1
        name_to_check = parts[1] if is_initial else first_part
        role = "last" if is_initial else "first"

        if self._is_generic_word(name_to_check):
            return []

        # ОДИНОКИЙ КОРОТКИЙ КУСОК обязан быть подтверждён индексом.
        #
        # `qqq482615@gmail.com` превращался в имя «Fff»: цифры отбрасываются,
        # остаётся один кусок из трёх букв, и база на 138 млн записей его
        # подтверждает — там найдётся почти любое трёхбуквенное сочетание.
        # Живому человеку в колонке «Имя» доставалось «Fff».
        #
        # Настоящие короткие имена (Ann, Kim, Lee, Joe, Eva, Max) индекс знает,
        # поэтому они проходят. Обломки и инициалы — нет.
        if len(parts) == 1 and len(first_part) < self._SEGMENT_MIN:
            if not is_known_name(first_part):
                return []

        if self.nd and not self._is_valid_name(name_to_check, role=role):
            # Имя может быть записано как фамилия и наоборот — даём второй шанс
            if not self._is_valid_name(name_to_check, role="any"):
                # Дальше — два послабления, оба про одно: база имён не знает
                # фамилий, записанных латиницей с других алфавитов, и
                # требовать от неё подтверждения значит терять живых людей.

                # Первое: подтверждение ЛЮБЫМ куском, а не обязательно
                # первым. Порядок «имя фамилия» и «фамилия имя» в адресах
                # встречается любой.
                others = [p for p in parts if p != name_to_check]
                confirmed = any(self._is_valid_name(p, role="any") for p in others)

                # Второе: человеческая СТРУКТУРА без подтверждения словарём.
                # `rogbinpetr1` -> Rogbin Petr, `rogbinp` -> Rogbin P:
                # фамилии «rogbin» нет ни в базе на 138 млн, ни в индексе, но
                # два куска, где хотя бы один полноценное слово, а второй
                # слово или инициал, — это запись человека, а не мусор.
                # Одиночный обломок («fff») сюда не проходит: там кусок один
                # и он короткий.
                structural = (len(parts) >= 2
                              and any(len(p) >= self._SEGMENT_MIN for p in parts))

                if not confirmed and not structural:
                    return []

        # Режима «Точность» здесь больше нет: в нём эта догадка не
        # спрашивается вовсе, а строгость живёт в _address_name. Прежняя
        # проверка «хоть один кусок знает индекс» пропускала имя с обломком
        # без гласных и инициал на месте имени — у них один кусок индексу
        # известен.
        return parts

    # ── строгий разбор адреса ───────────────────────────────────────────

    def _split_fused_part(self, part, crowded=False, others=()):
        """Режет слитный кусок между разделителями, только если разрез бесспорный.

        crowded — в адресе есть ещё хотя бы один кусок, похожий на имя: человек
        уже сам разделил имя и фамилию, и резать его куски заново — значит
        спорить с ним. На настоящих базах 13.11.2026 так резались фамилии
        после точки: `ivan.dorlov` отдавало «Ivan D Orlov» (Orlov —
        известная фамилия). В таком адресе кусок режется только в
        двух случаях: фамилия повторена соседним куском («markjones.jones»)
        или кусок начинается с пары согласных, с которой слова не начинаются
        («gshukla», «jsmith» — буква и фамилия).

        `markjones.jones` — человек поставил точку, но первую половину
        написал слитно; `rameshkumar.l` — тоже. Режем, только когда куски —
        частые имена от четырёх букв (Mark|Jones, Ramesh|Kumar), частое
        имя с частой фамилией (John|Smith), инициал перед частой фамилией
        (P|Gupta) или частое имя с коротким обломком (Anna|kk). Иначе кусок
        остаётся как его написал человек: база фамилий знает почти любой
        обломок, и без этого имя между точками рвалось на мнимые куски
        («Имя Обломок Фамилия», прогон владельца, 07.11).
        """
        quality = self.quality
        token = letters_only(part)
        if len(token) < 5 or not is_latin(token):
            return None
        if quality.kind_of(token, True) in ("first", "surname"):
            return None
        pieces = quality.segment(token)
        if len(pieces) < 2:
            return None

        def strong(piece):
            rank = quality.first_rank(piece)
            return (len(piece) >= 4 and quality.is_anchor(piece)
                    and rank is not None and rank <= SPLIT_FIRST_RANK)

        def top_surname(piece):
            _, last = name_ranks(piece)
            return len(piece) >= 4 and quality.surname_ok(piece) and last is not None and last <= 500

        words = [p for p, _ in pieces]
        if crowded:
            if len(words) != 2:
                return None
            head, tail = words
            twin = any(letters_only(other) == tail for other in others if other is not part)
            # Без повтора — только частое имя и частая фамилия от пяти букв
            # каждое: «carlos|garcia» режется, «elsa|nova» (Elsa — четыре буквы) — нет.
            _, tail_rank = name_ranks(tail)
            sure = (len(head) >= 5 and (quality.first_rank(head) or 9999) <= 300
                    and (len(tail) >= 5 or (tail_rank or 9999) <= 50))
            if strong(head) and top_surname(tail) and (twin or sure):
                return [(head, "first"), (tail, "surname")]
            if len(head) == 1 and top_surname(tail) and quality.odd_onset(token):
                return [(head, "initial"), (tail, "surname")]
            if strong(head) and len(tail) <= 2 and quality.hard_junk(tail):
                return [(head, "first"), (tail, "")]
            return None
        if all(strong(p) for p in words):
            return [(p, "first") for p in words]
        if len(words) == 2:
            head, tail = words
            if strong(head) and top_surname(tail):
                return [(head, "first"), (tail, "surname")]
            if len(head) == 1 and top_surname(tail):
                return [(head, "initial"), (tail, "surname")]
            if strong(head) and len(tail) <= 2 and quality.hard_junk(tail):
                return [(head, "first"), (tail, "")]
        return None

    def _address_name(self, email):
        """Имя из самого адреса, где КАЖДЫЙ кусок подтверждён. Строка или "".

        Одинаково в обоих режимах: подтверждённое имя лучше догадки и в
        «Заполненности». Границы, поставленные человеком (точка,
        подчёркивание, CamelCase), — факт о его адресе ("адрес"); границы,
        которые угадали мы, — догадка ("разбор"), и называть её фактом
        владельцу нельзя.
        """
        username = email.split('@')[0].strip()
        username_clean = re.sub(r'\d+', '', username)
        if len(username_clean) < 3:
            return ""
        if len(scripts_of(username_clean)) > 1:
            # «ivanпетров»: смесь алфавитов — украшение, а не имя; профиль
            # такую смесь отвергает, адрес отвергает так же (рецензия
            # 08.11.2026, J20).
            return ""
        quality = self.quality
        strict = строгий_режим_имён()
        # Цифры вместо букв внутри слова: «an0nym0us» — это anonymous, а не
        # «Anny Mus» (рецензия 08.11.2026, J18).
        leet = re.sub(r'(?<=[a-z])[013457](?=[a-z])',
                      lambda m: "oieast"["013457".index(m.group(0))], username.lower())
        if leet != username.lower():
            leet_letters = letters_only(re.sub(r'\d+', '', leet))
            if (leet_letters in _NOT_NAME_WORDS or quality.is_plain_word(leet_letters)
                    or quality.phrase_only(leet_letters)):
                return ""
        kept, source = [], ""
        if any(sep in username_clean for sep in ['.', '_', '-']):
            parts, kinds, guessed = [], [], False
            raws = [raw for raw in re.split(r'[._-]+', username_clean) if raw.strip()]
            named = sum(1 for raw in raws
                        if quality.kind_of(raw, True) in ("first", "surname", "structural"))
            for raw in raws:
                split = self._split_fused_part(raw, crowded=named >= 2, others=raws)
                if split:
                    for piece, kind in split:
                        parts.append(piece)
                        kinds.append(kind)
                    guessed = True
                else:
                    parts.append(raw)
                    kinds.append(quality.kind_of(raw, True))
            kept = quality.finalize(parts, True, kinds)
            source = "разбор" if guessed else "адрес"
        else:
            camel = re.findall(r'[A-Z][a-z]+', username_clean)
            if len(camel) >= 2 and ''.join(camel) == username_clean:
                kept = quality.finalize(camel, True)
                source = "адрес"
            else:
                letters = letters_only(username_clean) if is_latin(username_clean) \
                    else username_clean.lower()
                # Клавиатурный хвост ника снимается до разбора: «maryasdf» —
                # это Mary, а разбор отдавал «Marya» (рецензия 08.11.2026).
                # Только хвосты от четырёх букв: «asd» — это и конец «lucasd»
                # (Lucas D), и из него выходил «Luc».
                for junk in sorted(_KEYBOARD_JUNK, key=len, reverse=True):
                    if len(junk) >= 4 and letters.endswith(junk) and len(letters) - len(junk) >= 3:
                        letters = letters[:-len(junk)]
                        break
                # Строка, в которой имени нет вовсе (лозунг, лепет, фраза).
                if quality.not_a_name_string(letters):
                    kept = []
                # Строка целиком — имя базы, которого индекс не знает
                # («damilola»): дробить её на «Dami Lola» нельзя.
                elif quality.whole_first(letters):
                    kept = [letters]
                else:
                    kept = self._fused_name(letters, strict)
                    # Слово-занятие в хвосте, которое бывает и именем («dev»,
                    # «art», «law»): вторая попытка без него. Берётся, только
                    # если первая не дала ничего или её последний кусок — само
                    # это слово либо неизвестный базе кусок с ним на конце;
                    # «robertstewart» кончается на «art», но Stewart — фамилия.
                    cut = quality.tail_role_cut(letters)
                    if cut and (not kept or quality.tail_is_role(kept[-1])):
                        retry = self._fused_name(cut, strict)
                        # Вторая попытка не должна менять само имя: «katie|
                        # minioncpa» без хвоста резалось в «Kati Emin Ion».
                        if retry and (not kept or retry[0].lower() == kept[0].lower()):
                            kept = retry
                source = "разбор"
        if not kept:
            return ""
        # «Точность»: угаданное имя — только из кусков, которые база знает
        # (решение владельца 14.11.2026, см. confirmed_name).
        if strict and source == "разбор" and not quality.confirmed_name(kept):
            return ""
        self._osint_local.name_source = source
        return " ".join(part.title() for part in kept)

    def _fused_name(self, letters, strict):
        """Имя из слитной строки букв: куски или []. Границы тут — догадка."""
        quality = self.quality
        # Строка целиком — английское слово или фраза из слов («theorist»,
        # «glanceobjects», «bethechange»): имени в ней нет, а найденное
        # внутри — совпадение букв. Но фраза поверх уверенного имени — сама
        # совпадение: «heat|her|smith» внутри Heather Smith, «fat|im|am»
        # внутри Fatima (RN-4, RN-8).
        if quality.is_plain_word(letters) or (
                quality.phrase_only(letters)
                and not any(k == "first" and quality.confident_first(p)
                            for p, k in quality.segment(letters))):
            return []
        pieces = quality.split_initial(letters, quality.segment(letters))
        pieces = quality.split_short_surname(letters, pieces)
        # Редкая фамилия, раздробленная на слабые осколки, — целиком.
        pieces = quality.merge_oversplit(pieces)
        # Спорное начало («its|amy» или «it|samy») — гадание. В «Точности»
        # честнее пусто; «Заполненность» принимает догадку, и лучшее
        # прочтение там вернее прежнего сегментатора («Itsamy Hussain»).
        ambiguous = strict and quality.ambiguous_lead(letters, pieces)
        # Разбор режет английское слово посередине («ilo|veyou»,
        # «ange|leyes»): имя там — совпадение букв, в обоих режимах.
        misread = (quality.misaligned(letters, pieces)
                   or quality.asian_tail_ambiguous(letters, pieces))
        kept = []
        if pieces and not ambiguous and not misread:
            kept = quality.finalize([p for p, _ in pieces], False, [k for _, k in pieces])
        if not kept and not ambiguous:
            kept = quality.anchor_fallback(letters)
        return kept

    def _guess_name(self, email):
        """Прежний разбор адреса — запасной путь режима «Заполненность».

        Зовётся, только когда строгий разбор имени не нашёл. Из его догадки
        убирается заведомый мусор (clean_guess): веб-слова, обломки без
        гласных, буквы-украшения, инициалы рядом с именем.
        """
        username = email.split('@')[0].strip()
        username_clean = re.sub(r'\d+', '', username)
        if len(username_clean) < 3:
            return ""
        parts, from_separators = [], False
        if any(sep in username_clean for sep in ['.', '_', '-']):
            clean_parts = [part.title() for part in re.split(r'[._-]', username_clean)
                           if part.strip()]
            if clean_parts:
                # Границы поставил человек точками или подчёркиваниями —
                # чинить их нельзя.
                parts = self._finalize_guess(clean_parts, from_separators=True)
                from_separators = True
        if not from_separators:
            camel_case_parts = re.findall(r'[A-Z][a-z]+', username_clean)
            if len(camel_case_parts) >= 2 and ''.join(camel_case_parts) == username_clean:
                # CamelCase — тоже явная разметка автора адреса.
                parts = self._finalize_guess(camel_case_parts, from_separators=True)
                from_separators = True
            else:
                # Слово или фраза из слов («bethechange», «procompressor») — не
                # имя ни в каком режиме: догадка тут гадала бы по буквам слов.
                letters = letters_only(username_clean)
                if (self.quality.is_plain_word(letters) or self.quality.phrase_only(letters)
                        or self.quality.not_a_name_string(letters)):
                    return ""
                segmented = wordsegment.segment(username_clean.lower())
                if segmented:
                    parts = self._finalize_guess(segmented)
        # Границы от сегментатора — догадка, и чистке надо это знать: у
        # догадки есть заведомо ложные формы, которых нет у разметки человека.
        parts = self.quality.clean_guess(parts, fused=not from_separators)
        if not parts:
            return ""
        self._osint_local.name_source = "адрес" if from_separators else "разбор"
        return " ".join(part.title() for part in parts)

    def extract_name(self, email):
        """Имя владельца адреса. Профиль важнее догадки, догадка важнее пустоты.

        Порядок источников тут решает больше, чем сам разбор, и до починки он
        был перевёрнут: профиль Gravatar спрашивался ТОЛЬКО когда из адреса
        ничего не вышло. То есть работал на остатках, а на всех остальных
        адресах владелец получал догадку, даже когда рядом лежал факт.

        Замерено живьём на базе владельца: `theadamvelardes@gmail.com` —
        разбор адреса даёт «Thea Damvelardes», а профиль отдаёт настоящее
        «Adam Velardes». Разделить строку правильно тут нельзя в принципе:
        границу «thead|amvelardes» знает только сам человек, и он её указал —
        в профиле.

        Профиль спрашивается по сети, поэтому только при включённом
        обогащении: тумблер в окне и означает «готов платить временем за
        настоящие данные». Выключен — работает прежний разбор без единого
        запроса.
        """
        if not isinstance(email, str) or not email or '@' not in email:
            return None

        # Сначала факт. last_profile() при этом заполняется для всех — из
        # него берутся ещё локация и соцсети, и второй раз ходить незачем.
        # Имя из профиля ПРОВЕРЯЕТСЯ: ник («sunil07», «moviebuff»), фирма и
        # спам именем не считаются, сколько бы их ни писали в анкету.
        confirmed = self._profile_name(email)
        if confirmed:
            return self._address_over_profile(email, confirmed) or confirmed

        # Затем адрес, где каждый кусок подтверждён, — в обоих режимах.
        name = self._address_name(email)
        if name:
            return name

        # «Заполненность»: прежняя догадка, очищенная от заведомого мусора.
        # «Точность» догадку не берёт: там пусто честнее.
        if not строгий_режим_имён():
            name = self._guess_name(email)
            if name:
                return name

        # Последним — имя из профиля другим алфавитом («王小明»): лучше оно,
        # чем ничего, но хуже латиницы из адреса для письма на латинице.
        return self._fallback_osint(email)

    def _address_over_profile(self, email, profile_name):
        """Имя из адреса, если адрес с разметкой человека спорит с профилем, иначе "".

        `john.smith` с профилем «Crypto King», `rahul.verma` с профилем
        «King Khan»: оба — факты, но адрес с точками человек написал о себе
        сам, а в анкету пишут прозвище (рецензия 08.11.2026, J15). Профиль
        с опорой в адресе («Adam Velardes» у `theadamvelardes`) и профиль у
        слитного адреса не спорят ни с чем — там адрес границ не знает.
        """
        local = email.split("@")[0].strip()
        clean = re.sub(r"\d+", "", local)
        marked = (any(sep in clean for sep in "._-")
                  or (len(re.findall(r"[A-Z][a-z]+", clean)) >= 2))
        if not marked:
            return ""
        if consistent_with_address(profile_name.split(), letters_only(clean).lower(), min_len=2):
            return ""
        name = self._address_name(email)
        if not name:
            self._osint_local.name_source = "профиль"
            return ""
        return name

    def last_name_source(self):
        """Откуда взялось имя при последнем разборе В ЭТОМ ПОТОКЕ.

        "профиль" — публичный профиль, факт;
        "адрес"   — границы поставил сам человек, факт о его адресе;
        "разбор"  — границы угадал сегментатор, это ДОГАДКА.

        Хранение потоковое по той же причине, что и у last_profile:
        воркеров сотни, общий атрибут они бы перетирали друг у друга.
        """
        return getattr(self._osint_local, "name_source", "") or ""

    def last_profile(self):
        """Профиль Gravatar, полученный этим потоком при последнем разборе.

        Один запрос отдаёт и имя, и локацию, и привязанные соцсети — незачем
        ходить за ними второй раз. Хранение потоковое: воркеров сотни, общий
        атрибут они бы перетирали друг у друга.
        """
        return getattr(self._osint_local, "profile", {}) or {}

    def _profile_name(self, email):
        """Проверенное имя из публичного профиля — или пусто. Заодно запоминает профиль.

        Запрос ровно один на адрес: результат кладётся в потоковую ячейку, и
        _fallback_osint им же и пользуется, если разбор адреса ничего не дал.

        Проверка — NameQuality.profile_name. Логин за имя не считается:
        Gravatar отдаёт его, когда человек имени не указывал вовсе
        (`johnoakreps@gmail.com` -> «johnoakreps»). Ник с цифрами, ник одним
        словом без опоры в адресе, фирма, спам и смесь алфавитов — тоже не
        имя. Имя другим алфавитом откладывается: оно идёт в колонку, только
        если адрес не дал ничего.
        """
        self._osint_local.profile = {}
        self._osint_local.asked = True
        self._osint_local.name_source = ""
        self._osint_local.deferred = ""
        if not (self.enable_osint and self.osint_operator):
            return ""
        try:
            profile = self.osint_operator.get_profile(email)
        except Exception:
            return ""
        if not profile:
            return ""
        self._osint_local.profile = profile
        name = (profile.get("name") or "").strip() if isinstance(profile, dict) else ""
        if not name:
            return ""
        local_part = email.split("@")[0].strip()
        try:
            accepted, deferred = self.quality.profile_name(name, local_part)
        except Exception:
            # Проверка сломалась — имя из анкеты НЕ берём: непроверенное имя
            # хуже пустого, а адрес ещё может дать своё.
            accepted, deferred = "", ""
        self._osint_local.deferred = deferred
        if accepted:
            self._osint_local.name_source = "профиль"
        return accepted

    def _fallback_osint(self, email):
        """Запасной путь: разбор адреса ничего не дал.

        Профиль здесь уже спрошен в начале extract_name — второй запрос
        делать нельзя, это удвоило бы сетевую нагрузку на всю базу.
        Отдаётся только ПРОВЕРЕННОЕ имя: раньше здесь возвращалась сырая
        строка анкеты, и ники вроде «sunnybank2019» обходили проверку на
        логин, которую _profile_name им только что устроил.
        """
        if not getattr(self._osint_local, "asked", False):
            accepted = self._profile_name(email)
            if accepted:
                return accepted
        deferred = getattr(self._osint_local, "deferred", "") or ""
        self._osint_local.name_source = "профиль" if deferred else ""
        return deferred
