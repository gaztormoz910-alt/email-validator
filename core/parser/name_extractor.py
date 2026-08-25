import re
import os
import wordsegment
import threading
from .osint import OSINTOperator
from .names_index import is_known_name
from .translit import variants as translit_variants

_nd = None
_nd_lock = threading.Lock()

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
            
        # Check against dictionary, ignoring our whitelist of names that are also dictionary words
        if w in self.english_words and w not in self.name_exceptions:
            return True
            
        return False

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

    def _finalize(self, parts, email):
        """Общая проверка разобранных кусков имени для всех трёх стратегий."""
        if not parts:
            return self._fallback_osint(email)
        if len(parts) > 3:
            return self._fallback_osint(email)
        if self._has_business_words(parts):
            return self._fallback_osint(email)

        parts = self._merge_oversegmented_tail(parts)

        first_part = parts[0]
        # Инициал вместо имени (j.smith) — судим по второму куску
        is_initial = len(first_part) == 1 and len(parts) > 1
        name_to_check = parts[1] if is_initial else first_part
        role = "last" if is_initial else "first"

        if self._is_generic_word(name_to_check):
            return self._fallback_osint(email)

        if self.nd and not self._is_valid_name(name_to_check, role=role):
            # Имя может быть записано как фамилия и наоборот — даём второй шанс
            if not self._is_valid_name(name_to_check, role="any"):
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
                return self._finalize(clean_parts, email)
                
        # ----------------------------------------------------
        # Phase 1.5: Check for CamelCase (JohnDoe)
        # ----------------------------------------------------
        camel_case_parts = re.findall(r'[A-Z][a-z]+', username_clean)
        if len(camel_case_parts) >= 2 and ''.join(camel_case_parts) == username_clean:
            return self._finalize(camel_case_parts, email)
            
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
