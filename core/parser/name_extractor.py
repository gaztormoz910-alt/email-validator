import re
import os
import functools
import wordsegment
import threading
from .osint import OSINTOperator
from .names_index import is_known_name, countries_for
from .name_quality import (NameQuality, letters_only, is_latin, LEANING_FIRST_RANK,
                           LEANING_SURNAME_TOP, LEANING_STRONG_FIRST, SPLIT_FIRST_RANK,
                           STRONG_FIRST_RANK)
from .name_words import scripts_of, consistent_with_address, _KEYBOARD_JUNK, _NOT_NAME_WORDS
from .translit import variants as translit_variants

_nd = None
_nd_lock = threading.Lock()

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
    if surnames and min(surnames.values()) <= LEANING_SURNAME_TOP and rank > LEANING_STRONG_FIRST:
        return True
    if rank <= LEANING_FIRST_RANK:
        return False
    last = surnames.get(country)
    return bool(last) and last < rank


@functools.lru_cache(maxsize=65536)
def gender_share(word):
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
    if not isinstance(full_name, str):
        return "", ""
    parts = [piece for piece in full_name.replace(",", " ").split() if piece]
    if not parts:
        return "", ""

    def initial(piece):
        return len(piece.strip(".")) <= 1

    lead = 0
    while lead < len(parts) and initial(parts[lead]):
        lead += 1
    words = [piece for piece in parts[lead:] if not initial(piece)] \
        if lead < len(parts) else []
    if not words:
        return "", ""
    if lead and len(words) == 1:
        return "", words[0]
    if initial(parts[-1]):
        return parts[lead], ""
    parts = parts[lead:]
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], parts[-1]


def строгий_режим_имён():
    try:
        from .ml_predictor import get_country_mode
        return get_country_mode() == "accuracy"
    except Exception:
        return False


class NameExtractor:
    def __init__(self, enable_osint=False, proxy_provider=None):
        wordsegment.load()
        self.enable_osint = enable_osint
        self.osint_operator = OSINTOperator(proxy_provider=proxy_provider) if enable_osint else None
        self._osint_local = threading.local()
        
        self.nd = get_name_dataset()
        
        self.english_words = set()
        try:
            dict_path = os.path.join(os.path.dirname(__file__), "..", "english_words.txt")
            with open(dict_path, "r", encoding="utf-8") as f:
                self.english_words = {line.strip().lower() for line in f if line.strip()}
        except Exception:
            pass
            
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

        self.quality = NameQuality(
            is_first=is_known_name, name_ranks=name_ranks,
            english_words=self.english_words, countries_for=countries_for,
            english_surnames=self.name_exceptions,
            word_counts=getattr(wordsegment, "UNIGRAMS", None),
            leaning=surname_leaning, gender_share=gender_share)

    def _is_generic_word(self, word):
        w = word.lower()
        bad_roles = {
            "admin", "info", "support", "sales", "contact", "help", "office", "marketing", 
            "webmaster", "postmaster", "hello", "noreply", "no-reply", "news", "update",
            "service", "team", "billing", "press", "media", "jobs", "careers"
        }
        if w in bad_roles:
            return True

        if w in self.name_exceptions:
            return False

        if w in _NEVER_A_NAME:
            return True

        if is_known_name(w):
            return False

        return w in self.english_words

    def _has_business_words(self, words_list):
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
        if not word or not isinstance(word, str):
            return False

        word_clean = word.strip()
        if len(word_clean) < 2:
            return False

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

    _SEGMENT_MIN = 4

    def _repair_oversegmentation(self, parts):
        if not parts or len(parts) < 2:
            return parts

        merged = []
        buf = ""
        for index, part in enumerate(parts):
            buf += part
            following = parts[index + 1] if index + 1 < len(parts) else ""
            is_last = not following

            if len(buf) == 1 and (is_last or len(following) >= self._SEGMENT_MIN):
                merged.append(buf)
                buf = ""
                continue

            if len(buf) == 2 and not merged and not is_last:
                continue

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
        if len(parts) < 3 or not self.nd:
            return parts
        head, tail = parts[0], parts[1:]
        merged = "".join(tail)
        if len(merged) < 4 or not self._is_valid_name(merged, role="last"):
            return parts

        if all(len(part) <= 4 for part in tail):
            return [head, merged]

        if not any(self._is_valid_name(part, role="last") for part in tail):
            return [head, merged]

        return parts

    _MAX_CONFIRMED_TAIL = 2

    def _collapse_tail(self, parts, from_separators=False):
        if len(parts) < 3:
            return parts
        if from_separators:
            return parts[:3]
        head, tail = parts[0], parts[1:]
        if (len(tail) <= self._MAX_CONFIRMED_TAIL
                and all(len(part) >= 3 and is_known_name(part) for part in tail)):
            return parts
        return [head, "".join(tail)]

    _MAX_SEGMENTS = 5

    def _finalize_guess(self, parts, from_separators=False):
        if not parts:
            return []
        if len(parts) > self._MAX_SEGMENTS:
            return []
        if self._has_business_words(parts):
            head_is_business = self._has_business_words(parts[:1])
            trimmed = [p for p in parts if not self._has_business_words([p])]
            if head_is_business or len(trimmed) < 2:
                return []
            parts = trimmed

        if not from_separators:
            parts = self._repair_oversegmentation(parts)
        parts = self._merge_oversegmented_tail(parts)
        parts = self._collapse_tail(parts, from_separators)

        first_part = parts[0]
        is_initial = len(first_part) == 1 and len(parts) > 1
        name_to_check = parts[1] if is_initial else first_part
        role = "last" if is_initial else "first"

        if self._is_generic_word(name_to_check):
            return []

        if len(parts) == 1 and len(first_part) < self._SEGMENT_MIN:
            if not is_known_name(first_part):
                return []

        if self.nd and not self._is_valid_name(name_to_check, role=role):
            if not self._is_valid_name(name_to_check, role="any"):

                others = [p for p in parts if p != name_to_check]
                confirmed = any(self._is_valid_name(p, role="any") for p in others)

                structural = (len(parts) >= 2
                              and any(len(p) >= self._SEGMENT_MIN for p in parts))

                if not confirmed and not structural:
                    return []

        return parts


    def _split_fused_part(self, part, crowded=False, others=()):
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
        username = email.split('@')[0].strip()
        username_clean = re.sub(r'\d+', '', username)
        if len(username_clean) < 3:
            return ""
        if len(scripts_of(username_clean)) > 1:
            return ""
        quality = self.quality
        strict = строгий_режим_имён()
        leet = re.sub(r'(?<=[a-z])[013457](?=[a-z])',
                      lambda m: "oieast"["013457".index(m.group(0))], username.lower())
        if leet != username.lower():
            leet_letters = letters_only(re.sub(r'\d+', '', leet))
            if (leet_letters in _NOT_NAME_WORDS or quality.is_plain_word(leet_letters)
                    or quality.phrase_only(leet_letters)):
                return ""
        kept, source = [], ""
        fused = False
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
                for junk in sorted(_KEYBOARD_JUNK, key=len, reverse=True):
                    if len(junk) >= 4 and letters.endswith(junk) and len(letters) - len(junk) >= 3:
                        letters = letters[:-len(junk)]
                        break
                if quality.not_a_name_string(letters):
                    kept = []
                elif quality.whole_first(letters):
                    kept = [letters]
                else:
                    kept = self._fused_name(letters, strict)
                    cut = quality.tail_role_cut(letters)
                    if cut and (not kept or quality.tail_is_role(kept[-1])):
                        retry = self._fused_name(cut, strict)
                        if retry and (not kept or retry[0].lower() == kept[0].lower()):
                            kept = retry
                source = "разбор"
                fused = True
        if not kept:
            return ""
        if strict and source == "разбор" and not quality.confirmed_name(kept):
            return ""
        if strict and fused and not self._three_pieces_ok(kept):
            return ""
        if (not strict and source == "разбор" and not quality.confirmed_name(kept)
                and not self._guess_head_ok(kept)):
            self._osint_local.guess_refused = True
            return ""
        self._osint_local.name_source = source
        return " ".join(part.title() for part in kept)

    def _fused_name(self, letters, strict):
        quality = self.quality
        if quality.is_plain_word(letters) or (
                quality.phrase_only(letters)
                and not any(k == "first" and quality.confident_first(p)
                            for p, k in quality.segment(letters))):
            return []
        pieces = quality.split_initial(letters, quality.segment(letters))
        pieces = quality.split_short_surname(letters, pieces)
        pieces = quality.merge_oversplit(pieces)
        ambiguous = strict and quality.ambiguous_lead(letters, pieces)
        misread = (quality.misaligned(letters, pieces)
                   or quality.asian_tail_ambiguous(letters, pieces))
        kept = []
        if pieces and not ambiguous and not misread:
            kept = quality.finalize([p for p, _ in pieces], False, [k for _, k in pieces])
        if not kept and not ambiguous:
            kept = quality.anchor_fallback(letters)
        return kept

    _SYLLABLE_COUNTRIES = frozenset({"CN", "TW", "HK", "VN", "SG", "MY", "KR"})

    def _three_pieces_ok(self, kept):
        if len(kept) != 3 or len(kept[1]) <= 1:
            return True
        quality = self.quality
        words = [part.lower() for part in kept]
        if all(len(word) <= 5 and quality._countries(word) & self._SYLLABLE_COUNTRIES
               for word in words):
            return True
        middle_first, _ = quality._ranks(words[1])
        last_first, last_surname = quality._ranks(words[2])
        middle_given = (len(words[1]) >= 3 and middle_first is not None
                        and middle_first <= STRONG_FIRST_RANK)
        surname_end = (len(words[2]) >= 4 and last_surname is not None
                       and last_surname <= 1000
                       and (last_first is None or last_surname < last_first))
        return middle_given and surname_end

    def _guess_head_ok(self, parts):
        if len(parts) < 2:
            return True
        quality = self.quality
        words = [part.lower() for part in parts]
        if quality.kind_of(words[0], True) == "first":
            return True
        rank = quality.first_rank(words[0])
        return (rank is not None and rank <= STRONG_FIRST_RANK
                and all(len(word) >= 2 for word in words)
                and quality.confirmed_name(words))

    def _guess_name(self, email):
        username = email.split('@')[0].strip()
        username_clean = re.sub(r'\d+', '', username)
        if len(username_clean) < 3:
            return ""
        parts, from_separators = [], False
        if any(sep in username_clean for sep in ['.', '_', '-']):
            clean_parts = [part.title() for part in re.split(r'[._-]', username_clean)
                           if part.strip()]
            if clean_parts:
                parts = self._finalize_guess(clean_parts, from_separators=True)
                from_separators = True
        if not from_separators:
            camel_case_parts = re.findall(r'[A-Z][a-z]+', username_clean)
            if len(camel_case_parts) >= 2 and ''.join(camel_case_parts) == username_clean:
                parts = self._finalize_guess(camel_case_parts, from_separators=True)
                from_separators = True
            else:
                letters = letters_only(username_clean)
                if (self.quality.is_plain_word(letters) or self.quality.phrase_only(letters)
                        or self.quality.not_a_name_string(letters)):
                    return ""
                segmented = wordsegment.segment(username_clean.lower())
                if segmented:
                    parts = self._finalize_guess(segmented)
        parts = self.quality.clean_guess(parts, fused=not from_separators)
        if not parts:
            return ""
        if not self._guess_head_ok(parts):
            return ""
        self._osint_local.name_source = "адрес" if from_separators else "разбор"
        return " ".join(part.title() for part in parts)

    def extract_name(self, email):
        if not isinstance(email, str) or not email or '@' not in email:
            return None

        confirmed = self._profile_name(email)
        if confirmed:
            return self._address_over_profile(email, confirmed) or confirmed

        self._osint_local.guess_refused = False
        name = self._address_name(email)
        if name:
            return name

        if not строгий_режим_имён() and not getattr(self._osint_local, "guess_refused", False):
            name = self._guess_name(email)
            if name:
                return name

        return self._fallback_osint(email)

    def _address_over_profile(self, email, profile_name):
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
        return getattr(self._osint_local, "name_source", "") or ""

    def last_profile(self):
        return getattr(self._osint_local, "profile", {}) or {}

    def _profile_name(self, email):
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
            accepted, deferred = "", ""
        self._osint_local.deferred = deferred
        if accepted:
            self._osint_local.name_source = "профиль"
        return accepted

    def _fallback_osint(self, email):
        if not getattr(self._osint_local, "asked", False):
            accepted = self._profile_name(email)
            if accepted:
                return accepted
        deferred = getattr(self._osint_local, "deferred", "") or ""
        self._osint_local.name_source = "профиль" if deferred else ""
        return deferred
