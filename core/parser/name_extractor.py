import re
import os
import wordsegment
import threading
from .osint import OSINTOperator
from .names_index import is_known_name
from .translit import variants as translit_variants

_nd = None
_nd_lock = threading.Lock()

# Слова, которые именем быть не могут ни при каких обстоятельствах.
#
# Список нужен потому, что индекс популярных имён собран из реальных баз, а в
# реальных базах встречается всё: «the» есть как вьетнамское имя, «as» — как
# скандинавское, «live» кто-то записал в анкете. Формально они там есть, но в
# локальной части адреса `theadamoliveras` или `livenicko` это не имя
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
        # этого терялись имена у каждого третьего адреса: justinkyle89 и
        # suelovesjunk3 отдавали пустоту, хотя имя в них написано открытым
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

        Зачем. wordsegment обучен на английском корпусе и слова «tsybin» не
        знает, поэтому режет `tsybinbogdan` на ['tsy','bin','bogdan'] — и
        адрес владельца превращался в «Tsy Bin Bogdan». Проверить склейку по
        базе имён нельзя: базы на 138 млн записей «tsybin» тоже не знает,
        зато знает и «tsy», и «bin» по отдельности — на такой выборке
        найдётся почти любое трёхбуквенное сочетание, и подтверждение
        ничего не значит.

        Поэтому решает не база, а ДЛИНА: кусок короче четырёх букв — почти
        наверняка обломок, и его надо приклеить к соседу. Одиночная буква
        рядом с полноценным словом — исключение: это инициал (j.smith,
        tsybin b), и склеивать её нельзя.

        ['tsy','bin','bogdan']      -> ['tsybin','bogdan']
        ['tsy','bin','b']           -> ['tsybin','b']
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
            # это не инициал, а обломок: `pavithrav` сегментатор делит на
            # ['pa','vithrav'], и «Pa Vithrav» уходило в колонку «Имя» как
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
            # обломок «tsy», и её ответ здесь ничего не различает.
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
            # обломок «tsy», и её ответ здесь ничего не различает.
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
    # настоящее имя. Два: «Hai Ngoc Nguyen» бывает, «Hai Ngoc Van Nguyen» —
    # уже почти наверняка разваленная сегментатором строка.
    _MAX_CONFIRMED_TAIL = 2

    def _collapse_tail(self, parts, from_separators=False):
        """Сводит хвост к ОДНОЙ фамилии, если он не состоит из настоящих имён.

        Зачем. Сегментатор разбирает слитную фамилию на английские слова:
        `rachaeldaslothgirl` -> ['rachael','da','sloth','girl'],
        `johnacreps` -> ['john','acre','ps'], `suelovesjunk` ->
        ['sue','loves','junk']. Раньше на такое стояло правило «кусков больше
        трёх — сдаёмся», и адрес отдавал ПУСТОТУ, хотя имя в нём написано
        открытым текстом: терялся не только хвост, но и найденное имя.

        Здесь хвост склеивается в одну фамилию — «Rachael Daslothgirl»,
        «John Acreps», «Sue Lovesjunk». Это ровно та реконструкция, которую
        делает человек, читая адрес глазами.

        Настоящие многосоставные имена при этом не ломаются: если КАЖДЫЙ
        хвостовой кусок знает индекс популярных имён и он не короче трёх букв,
        куски остаются как есть — вьетнамское «Hai Ngoc Nguyen» переживает
        разбор целиком.

        Спрашивается индекс на 43 тысячи имён, а не база на 138 млн: в базе
        такого размера находится почти любое буквосочетание, и «acre» с «ps»
        она подтвердит наравне с «nguyen».
        """
        if len(parts) < 3:
            return parts
        # Разделители поставил человек: `jonathan.y.tom` — это имя, инициал и
        # фамилия, а не разваленная строка. Склейка давала «Jonathan Ytom».
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

    def _finalize(self, parts, email, from_separators=False):
        """Общая проверка разобранных кусков имени для всех трёх стратегий.

        from_separators=True означает, что куски пришли из ЯВНЫХ разделителей
        (`leo.duquesnel`, `j_smith`), а не от сегментатора. Границы в этом
        случае поставил сам человек, и чинить их нельзя — см. ниже.
        """
        if not parts:
            return self._fallback_osint(email)
        if len(parts) > self._MAX_SEGMENTS:
            return self._fallback_osint(email)
        # Деловое слово ОТБРАСЫВАЕТСЯ, если оно стоит не первым и без него
        # остаётся человеческая запись.
        #
        # `laura.oliveira.tech@gmail.com` — это Laura Oliveira, которая
        # приписала к личному адресу род занятий. Раньше слово «tech» роняло
        # весь разбор, и имя терялось целиком. А вот `info.tech@company.com`
        # по-прежнему отбрасывается: там деловое слово не одно и имени нет.
        if self._has_business_words(parts):
            head_is_business = self._has_business_words(parts[:1])
            trimmed = [p for p in parts if not self._has_business_words([p])]
            if head_is_business or len(trimmed) < 2:
                return self._fallback_osint(email)
            parts = trimmed

        # Починка развала — только для кусков ОТ СЕГМЕНТАТОРА.
        #
        # Точка в `leo.duquesnel` поставлена человеком, и склеивать по ней
        # нечего. А склейка происходила: «leo» короче четырёх букв, и если бы
        # индекс его не знал, вышло бы «Leoduquesnel». Для имён вроде Bo, Ed,
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
            return self._fallback_osint(email)

        # ОДИНОКИЙ КОРОТКИЙ КУСОК обязан быть подтверждён индексом.
        #
        # `fff089739@gmail.com` превращался в имя «Fff»: цифры отбрасываются,
        # остаётся один кусок из трёх букв, и база на 138 млн записей его
        # подтверждает — там найдётся почти любое трёхбуквенное сочетание.
        # Живому человеку в колонке «Имя» доставалось «Fff».
        #
        # Настоящие короткие имена (Ann, Kim, Lee, Joe, Eva, Max) индекс знает,
        # поэтому они проходят. Обломки и инициалы — нет.
        if len(parts) == 1 and len(first_part) < self._SEGMENT_MIN:
            if not is_known_name(first_part):
                return self._fallback_osint(email)

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
                # `tsybinbogdan1` -> Tsybin Bogdan, `tsybinb` -> Tsybin B:
                # фамилии «tsybin» нет ни в базе на 138 млн, ни в индексе, но
                # два куска, где хотя бы один полноценное слово, а второй
                # слово или инициал, — это запись человека, а не мусор.
                # Одиночный обломок («fff») сюда не проходит: там кусок один
                # и он короткий.
                structural = (len(parts) >= 2
                              and any(len(p) >= self._SEGMENT_MIN for p in parts))

                if not confirmed and not structural:
                    return self._fallback_osint(email)

        return " ".join(part.title() for part in parts)

    def extract_name(self, email):
        """
        Extracts and formats a potential name from an email address using Phase 1 & 2 heuristics.
        Returns the formatted name or None if extraction fails.
        """
        if not isinstance(email, str) or not email or '@' not in email:
            return None

        username = email.split('@')[0].strip()
        username_clean = re.sub(r'\d+', '', username)
        
        if len(username_clean) < 3:
            return self._fallback_osint(email)

        # ----------------------------------------------------
        # Phase 1: Check for common separators (john.doe)
        # ----------------------------------------------------
        if any(sep in username_clean for sep in ['.', '_', '-']):
            parts = re.split(r'[._-]', username_clean)
            clean_parts = [part.title() for part in parts if part.strip()]
            
            if clean_parts:
                # Границы поставил человек точками или подчёркиваниями —
                # чинить их нельзя.
                return self._finalize(clean_parts, email, from_separators=True)
                
        # ----------------------------------------------------
        # Phase 1.5: Check for CamelCase (JohnDoe)
        # ----------------------------------------------------
        camel_case_parts = re.findall(r'[A-Z][a-z]+', username_clean)
        if len(camel_case_parts) >= 2 and ''.join(camel_case_parts) == username_clean:
            # CamelCase — тоже явная разметка автора адреса.
            return self._finalize(camel_case_parts, email, from_separators=True)
            
        # ----------------------------------------------------
        # Phase 2: Word segmentation for merged names (robertanderson)
        # ----------------------------------------------------
        segmented = wordsegment.segment(username_clean.lower())
        
        if segmented:
            return self._finalize(segmented, email)
            
        return self._fallback_osint(email)
        
    def last_profile(self):
        """Профиль Gravatar, полученный этим потоком при последнем разборе.

        Один запрос отдаёт и имя, и локацию, и привязанные соцсети — незачем
        ходить за ними второй раз. Хранение потоковое: воркеров сотни, общий
        атрибут они бы перетирали друг у друга.
        """
        return getattr(self._osint_local, "profile", {}) or {}

    def _fallback_osint(self, email):
        self._osint_local.profile = {}
        if self.enable_osint and self.osint_operator:
            profile = self.osint_operator.get_profile(email)
            if profile:
                self._osint_local.profile = profile
                if profile.get("name"):
                    return profile["name"]
        return ""
