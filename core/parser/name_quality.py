# -*- coding: utf-8 -*-
import re

from .name_words import (
    BUSINESS_WORDS, ROLE_WORDS, WEB_WORDS, _CHINESE_NAME_COUNTRIES,
    _CHINESE_SHORT_SURNAMES, _DECORATION_LETTERS, _KEYBOARD_JUNK, _MONTHS,
    _PHRASE_INSIDE, _PHRASE_WORDS, _RARE_TAIL_LETTERS, _SPAM_PARTS, _TITLES, _VOWELS,
    _NICK_WORDS, _PLACEHOLDER_WORDS, _NOT_NAME_WORDS, _KNOWN_PHRASES,
    _EAST_ASIAN_SHORT_SURNAMES,
    fold, scripts_of, is_latin, has_vowel, letters_only, max_consonant_run,
    trailing_consonants, consistent_with_address, display_case)
from .name_words import MAX_TOKEN_LEN, MAX_SEGMENT_INPUT, PLAIN_WORD_COUNT
from .name_split import SplitMixin
from .name_evidence import (EvidenceMixin, PHRASE_WORD_COUNT, CONCAT_SURNAME_RANK,
                            CONCAT_FIRST_RANK, GENDERED_SHARE)


MAX_STRUCTURAL_FUSED = 10

MAX_TOKENS = 3


MAX_CONSONANT_RUN = 5

ENGLISH_SURNAME_TOP = 150
ENGLISH_SURNAME_NAMELIKE = 1000
SHORT_SURNAME_TOP = 1000
NON_LATIN_TOP = 5000
NON_LATIN_FIRST_TOP = 1000


LEADING_WEAK_SURNAME = 1000

INITIAL_SURNAME_TOP = 5000

STRONG_FIRST_RANK = 500

SPLIT_FIRST_RANK = 2000

PIECE_COST = 3.5
INITIAL_COST = 1.5
FIRST_WEIGHT = ((300, 1.4), (2000, 1.1))
FIRST_WEIGHT_LOW = 0.8
SURNAME_WEIGHT = ((500, 1.2), (5000, 0.9))
SURNAME_WEIGHT_LOW = 0.6
LONG_SURNAME_LEN = 8
LONG_SURNAME_WEIGHT = 0.95
SHORT_FIRST_FACTOR = 0.85
SHORT_SURNAME_FACTOR = 0.5
TWO_LETTER_FIRST = 0.8
STRUCTURAL_WEIGHT = 0.35
PHRASE_WEIGHT = 0.9
ROLE_WEIGHT = 1.0
ENGLISH_WEIGHT = 1.0
JUNK_WEIGHT = -0.3
JUNK_COST = 2.0

DATASET_FIRST_TOP = 50
DATASET_FIRST_TOP_LONG = 200

TRUNCATION_FIRST_RANK = 300
TRUNCATION_SURNAME_RANK = 20000

LEADING_WORD_SURNAME_TOP = 100

WORDLIKE_FIRST_RANK = 1000

LEANING_FIRST_RANK = 500
LEANING_SURNAME_TOP = 10
LEANING_STRONG_FIRST = 50

SHORT_FIRST_MAX_RANK = 600

LONE_FIRST_RANK = 1000

NICK_FIRST_RANK = 300
NICK_GENDER_SHARE = 0.7

AMBIGUITY_MARGIN = 1.5


LEADING_SURNAME_TOP = 500
LEADING_SURNAME_LEN = 6


_MEMO_LIMIT = 200000


class NameQuality(SplitMixin, EvidenceMixin):

    def __init__(self, is_first, name_ranks, english_words, countries_for=None,
                 english_surnames=(), word_counts=None, leaning=None, gender_share=None):
        self._is_first_raw = is_first
        self._ranks_raw = name_ranks
        self.english_words = frozenset(english_words or ())
        self._countries_for = countries_for or (lambda word: ())
        self.english_surnames = frozenset(english_surnames or ())
        self._word_counts = word_counts if isinstance(word_counts, dict) else {}
        self._leaning_raw = leaning
        self._gender_raw = gender_share
        self._options_memo = {}
        self._segment_memo = {}
        self._reading_memo = {}

    @staticmethod
    def _remember(memo, key, value):
        if len(memo) >= _MEMO_LIMIT:
            memo.clear()
        memo[key] = value
        return value


    def _is_first(self, word):
        try:
            return bool(self._is_first_raw(word))
        except Exception:
            return False

    def _ranks(self, word):
        try:
            first, last = self._ranks_raw(word)
            return first, last
        except Exception:
            return None, None

    def _gender_share(self, word):
        if self._gender_raw is None:
            return None
        try:
            share = self._gender_raw(word)
        except Exception:
            return None
        return share if isinstance(share, (int, float)) else None

    def _countries(self, word):
        try:
            return set(self._countries_for(word) or ())
        except Exception:
            return set()


    def is_business(self, token):
        return fold(token).strip(".'-") in BUSINESS_WORDS

    def _is_role(self, token):
        t = fold(token).strip(".'-")
        return t in BUSINESS_WORDS or t in ROLE_WORDS or t in WEB_WORDS

    def is_phrase(self, token):
        return fold(token).strip(".'-") in _PHRASE_WORDS

    def hard_junk(self, token):
        t = fold(token).strip(".'-")
        if not t:
            return True
        if t in WEB_WORDS or t in ROLE_WORDS or t in BUSINESS_WORDS:
            return True
        if len(t) > MAX_TOKEN_LEN:
            return True
        if is_latin(t) and len(t) >= 2 and not has_vowel(t):
            return True
        if t in _KEYBOARD_JUNK:
            return True
        if len(t) >= 2 and len(set(t)) == 1:
            return True
        return False

    def first_rank(self, token):
        return self._ranks(fold(token))[0]

    def first_ok(self, token, min_len=3):
        t = fold(token)
        if len(t) < min_len or self.hard_junk(t) or t in _PHRASE_WORDS:
            return False
        if is_latin(t):
            if self._is_first(t):
                return True
            if len(t) < 4:
                return False
            first, last = self._ranks(t)
            limit = DATASET_FIRST_TOP if len(t) == 4 else DATASET_FIRST_TOP_LONG
            return (first is not None and first <= limit
                    and (last is None or first <= 2 * last))
        first, _ = self._ranks(token)
        if first is None or first > NON_LATIN_FIRST_TOP:
            return False
        share = self._gender_share(token)
        return share is None or share >= GENDERED_SHARE

    def surname_leaning(self, token):
        t = fold(token)
        if self._leaning_raw is not None:
            try:
                return bool(self._leaning_raw(t))
            except Exception:
                return False
        first, last = self._ranks(t)
        if first is None or last is None:
            return False
        if last <= LEANING_SURNAME_TOP and first > LEANING_STRONG_FIRST:
            return True
        return first > LEANING_FIRST_RANK and last < first

    def is_anchor(self, token):
        t = fold(token)
        return len(t) >= 3 and self.first_ok(t, 3) and not self.surname_leaning(t)

    def _nicknamey(self, token):
        t = fold(token)
        if t in _NICK_WORDS:
            return True
        if t not in self.english_words:
            return False
        share = self._gender_share(t)
        if share is not None and share < NICK_GENDER_SHARE:
            return True
        rank = self.first_rank(t)
        return rank is None or rank > NICK_FIRST_RANK

    def strong_first(self, token):
        if not self.is_anchor(token):
            return False
        rank = self.first_rank(token)
        return rank is not None and rank <= STRONG_FIRST_RANK

    def surname_ok(self, token):
        t = fold(token)
        if len(t) < 3 or self.hard_junk(t) or t in _PHRASE_WORDS:
            return False
        if is_latin(t) and not has_vowel(t):
            return False
        first, last = self._ranks(t if is_latin(t) else token)
        if last is None:
            return False
        if not is_latin(t):
            return last <= NON_LATIN_TOP
        if len(t) == 3 and last > SHORT_SURNAME_TOP:
            return False
        if t in self.english_words and not self._is_first(t):
            if t in self.english_surnames or last <= ENGLISH_SURNAME_TOP:
                return True
            return (last <= ENGLISH_SURNAME_NAMELIKE and first is not None
                    and first <= ENGLISH_SURNAME_NAMELIKE)
        if last > 500 and any(word in t for word in _PHRASE_INSIDE):
            return False
        return True

    def wordlike_first(self, token):
        t = fold(token)
        if t in self.english_surnames:
            return False
        if t not in self.english_words:
            if self._word_counts.get(t, 0) < PHRASE_WORD_COUNT:
                return False
            _, last = self._ranks(t)
            if last is not None and last <= WORDLIKE_FIRST_RANK:
                return False
        rank = self.first_rank(t)
        return rank is None or rank > WORDLIKE_FIRST_RANK

    def structural_ok(self, token, fused=True):
        t = fold(token)
        if not (4 <= len(t) <= MAX_TOKEN_LEN) or self.hard_junk(t):
            return False
        if t in _PHRASE_WORDS or not self.name_shaped(t) or self.web_glued(t):
            return False
        if not fused and not self.cluster_shaped(t):
            return False
        if not is_latin(t):
            return all(ch.isalpha() for ch in token) and len(scripts_of(token)) == 1
        if not has_vowel(t) or max_consonant_run(t) >= MAX_CONSONANT_RUN:
            return False
        if fused and trailing_consonants(t) >= 3:
            return False
        if t in self.english_words and not self._is_first(t):
            return False
        if self._compound_of_words(t):
            return False
        if any(word in t for word in _PHRASE_INSIDE):
            return False
        if any(junk in t for junk in _KEYBOARD_JUNK if len(junk) >= 3):
            return False
        tail = t[-2:]
        if (fused and len(tail) == 2 and all(ch not in _VOWELS for ch in tail)
                and any(ch in _RARE_TAIL_LETTERS for ch in tail)):
            return False
        return True

    def is_plain_word(self, letters):
        s = letters_only(letters)
        if len(s) < 4 or self._is_first(s):
            return False
        if s in self.english_words:
            return not self.surname_ok(s)
        if len(s) >= 5 and self.surname_ok(s[1:]):
            _, rest = self._ranks(s[1:])
            if rest is not None and rest <= 500:
                return False
        count = self._word_counts.get(s)
        if count is None or count < PLAIN_WORD_COUNT:
            return False
        first, last = self._ranks(s)
        if first is not None and first <= 5000 and (self._gender_share(s) or 0) >= 0.9:
            return False
        return last is None or last > 3000

    def kind_of(self, token, from_separators):
        t = fold(token).strip(".'-")
        if not t:
            return ""
        if len(t) == 1:
            return "initial" if t.isalpha() else ""
        if t in _TITLES:
            return ""
        if self.hard_junk(t):
            return "word" if (self.is_business(t) or t in ROLE_WORDS) else ""
        if t in _PHRASE_WORDS:
            return "first" if from_separators and self._phrase_name(t) else "word"
        if self.first_ok(t, min_len=2 if from_separators else 3):
            if len(t) >= 3 and self.surname_leaning(t) and self.surname_ok(t):
                return "surname"
            return "first"
        if self.is_plain_word(t):
            return "word"
        if self.surname_ok(t):
            return "surname"
        if self.structural_ok(t, fused=not from_separators):
            return "structural"
        if t in self.english_words:
            return "word"
        return ""


    @staticmethod
    def _tier(rank, table, low):
        if rank is None:
            return low
        for limit, weight in table:
            if rank <= limit:
                return weight
        return low

    def _options(self, piece):
        memo = self._options_memo.get(piece)
        if memo is not None:
            return memo
        return self._remember(self._options_memo, piece, self._options_raw(piece))

    def _options_raw(self, piece):
        n = len(piece)
        if n == 1:
            return [("initial", -INITIAL_COST)]
        out = []
        if piece in _TITLES:
            return [("word", PHRASE_WEIGHT * n - PIECE_COST),
                    ("junk", JUNK_WEIGHT * n - JUNK_COST)]
        if self.hard_junk(piece):
            if self.is_business(piece) or piece in ROLE_WORDS or piece in WEB_WORDS:
                out.append(("word", ROLE_WEIGHT * n - PIECE_COST))
            out.append(("junk", JUNK_WEIGHT * n - JUNK_COST))
            return out
        if piece in _PHRASE_WORDS:
            out.append(("word", PHRASE_WEIGHT * n - PIECE_COST))
        else:
            first, last = self._ranks(piece)
            if n == 2 and self._is_first(piece):
                out.append(("first", TWO_LETTER_FIRST * n - PIECE_COST))
            elif n >= 3 and self.first_ok(piece, 3) and (
                    n > 3 or (first is not None and first <= SHORT_FIRST_MAX_RANK)) and not (
                    n >= 6 and (first is None or first > CONCAT_FIRST_RANK)
                    and self._joined_names(piece)):
                weight = (FIRST_WEIGHT_LOW if self.surname_leaning(piece)
                          else self._tier(first, FIRST_WEIGHT, FIRST_WEIGHT_LOW))
                if n == 3:
                    weight *= SHORT_FIRST_FACTOR
                out.append(("first", weight * n - PIECE_COST))
            surname = n >= 3 and self.surname_ok(piece) and not (
                n >= 6 and (last is None or last > CONCAT_SURNAME_RANK)
                and self._joined_names(piece))
            if surname:
                weight = self._tier(last, SURNAME_WEIGHT, SURNAME_WEIGHT_LOW)
                if n >= LONG_SURNAME_LEN:
                    weight = max(weight, LONG_SURNAME_WEIGHT)
                if n == 3:
                    weight *= SHORT_SURNAME_FACTOR
                out.append(("surname", weight * n - PIECE_COST))
            if (piece in self.english_words and not self._is_first(piece)
                    and not surname):
                out.append(("word", ENGLISH_WEIGHT * n - PIECE_COST))
            if self.structural_ok(piece):
                out.append(("structural", STRUCTURAL_WEIGHT * n - PIECE_COST))
        out.append(("junk", JUNK_WEIGHT * n - JUNK_COST))
        return out

    def segment(self, letters):
        return self.segment_scored(letters)[1]

    def segment_scored(self, letters):
        s = letters_only(letters) if is_latin(letters) else letters
        memo = self._segment_memo.get(s)
        if memo is not None:
            return memo[0], list(memo[1])
        score, pieces = self._segment_raw(s)
        self._remember(self._segment_memo, s, (score, tuple(pieces)))
        return score, list(pieces)

    def _segment_raw(self, s):
        n = len(s)
        if not n or n > MAX_SEGMENT_INPUT:
            return 0.0, []
        if not is_latin(s):
            return 0.0, [(s, self.kind_of(s, False))]
        best = [[None, None] for _ in range(n + 1)]
        best[0][0] = (0.0, ())
        options = self._options_memo
        for i in range(n):
            for after_initial in (0, 1):
                state = best[i][after_initial]
                if state is None:
                    continue
                base, tokens = state
                for j in range(i + 1, min(n, i + MAX_TOKEN_LEN) + 1):
                    piece = s[i:j]
                    choices = options.get(piece)
                    if choices is None:
                        choices = self._options(piece)
                    for kind, score in choices:
                        is_initial = kind == "initial"
                        if is_initial and after_initial:
                            continue
                        total = base + score
                        cand = tokens + ((piece, kind),)
                        slot = 1 if is_initial else 0
                        cur = best[j][slot]
                        if (cur is None or total > cur[0] + 1e-9
                                or (abs(total - cur[0]) <= 1e-9 and len(cand) < len(cur[1]))):
                            best[j][slot] = (total, cand)
        finals = [st for st in best[n] if st is not None]
        if not finals:
            return 0.0, []
        winner = max(finals, key=lambda st: (st[0], -len(st[1])))
        return winner[0], list(winner[1])

    def ambiguous_lead(self, letters, pieces=None):
        s = letters_only(letters)
        if not s:
            return False
        best_score, best = self.segment_scored(s)
        if pieces is not None:
            best = pieces
        best_name = self.finalize([p for p, _ in best], False, [k for _, k in best])
        if not best_name:
            return False
        kinds_of_best = dict(best)
        if (len(best_name) == 2 and kinds_of_best.get(best_name[0]) == "initial"
                and kinds_of_best.get(best_name[1]) == "surname"):
            _, last = self._ranks(fold(best_name[1]))
            if last is not None and last <= 100:
                return False
        leads = sorted((w for w in (_PHRASE_WORDS | _TITLES)
                        if len(w) >= 2 and s.startswith(w) and len(s) > len(w) + 2),
                       key=len, reverse=True)
        for lead in leads:
            rest_score, rest = self.segment_scored(s[len(lead):])
            if not rest:
                continue
            forced_score = PHRASE_WEIGHT * len(lead) - PIECE_COST + rest_score
            if forced_score < best_score - AMBIGUITY_MARGIN:
                continue
            forced = [(lead, "word")] + rest
            forced_name = self.finalize([p for p, _ in forced], False,
                                        [k for _, k in forced])
            if forced_name and fold(best_name[0]) != fold(forced_name[0]):
                return True
        return False

    def anchor_fallback(self, letters):
        s = letters_only(letters)
        if not is_latin(s):
            for k in range(len(s) - 3, 2, -1):
                if self.is_anchor(s[:k]) and self.surname_ok(s[k:]):
                    return [s[:k], s[k:]]
            return []
        best = self.segment(s)
        if any(self.is_anchor(p) for p, k in best if k in ("first", "surname")):
            return []
        if best and all(k in ("first", "surname", "word") for _, k in best):
            return []
        for k in range(min(len(s), MAX_TOKEN_LEN), 3, -1):
            head = s[:k]
            if not self.is_anchor(head) or self.wordlike_first(head):
                continue
            rank = self.first_rank(head)
            if rank is None or rank > 1000:
                continue
            rest = s[k:]
            pieces = [(head, "first")] + (self.segment(rest) if rest else [])
            if self.misaligned(s, pieces):
                continue
            name = self.finalize([p for p, _ in pieces], False, [kd for _, kd in pieces])
            if not name:
                continue
            if len(name) == 1 and (rank > STRONG_FIRST_RANK or head in self.english_words):
                continue
            return name
        return []

    def _longer_name(self, head, tail, surname=False):
        head = fold(head)
        tail = fold(tail)
        for k in range(1, min(3, len(tail)) + 1):
            candidate = head + tail[:k]
            first, last = self._ranks(candidate)
            if first is not None and first <= TRUNCATION_FIRST_RANK:
                return True
            if surname and last is not None and last <= TRUNCATION_SURNAME_RANK:
                return True
        return False

    def _truncate_at(self, items):
        for index in range(len(items) - 1):
            part, kind = items[index]
            nxt, nkind = items[index + 1]
            if kind == "initial" and nkind == "first":
                first, _ = self._ranks(fold(part) + fold(nxt))
                if first is not None and first <= TRUNCATION_FIRST_RANK:
                    return index
                continue
            if kind not in ("first", "surname"):
                continue
            if nkind == "surname" and self.surname_ok(nxt):
                _, last = self._ranks(fold(nxt))
                if last is not None and last <= INITIAL_SURNAME_TOP:
                    continue
            if nkind == "first" and len(fold(nxt)) > 3:
                continue
            if (kind == "first" and self._longer_name(part, nxt)
                    and not self.keeps_boundary(part, nxt, nkind)):
                return index
            if (kind == "first" and nkind == "initial" and fold(nxt) in _VOWELS
                    and not any(k in ("first", "surname", "structural")
                                for _, k in items[index + 2:])):
                longer, longer_last = self._ranks(fold(part) + fold(nxt))
                own = self.first_rank(part)
                if (index + 2 < len(items)
                        or (longer is not None and (own is None or longer <= 20 * own))
                        or (longer_last is not None and longer_last <= INITIAL_SURNAME_TOP)):
                    return index
            if nkind == "initial":
                last_piece = all(k in ("initial", "", "weak") for _, k in items[index + 1:])
                if last_piece and self._longer_name(part, nxt, surname=True):
                    return index
                if kind == "first":
                    joined = fold(part) + fold(nxt)
                    longer, _ = self._ranks(joined)
                    own = self.first_rank(part)
                    if (longer is not None and longer <= TRUNCATION_SURNAME_RANK
                            and (own is None or longer <= 20 * own)):
                        return index
        return None


    def _fused_lead_ok(self, items):
        index = 0
        while index < len(items) and items[index][1] == "word" and (
                self.is_phrase(items[index][0]) or fold(items[index][0]) in _TITLES):
            index += 1
        if index >= len(items):
            return False
        part, kind = items[index]
        nxt = items[index + 1] if index + 1 < len(items) else ("", "")
        if kind == "surname" and fold(part) in self.english_words:
            _, last = self._ranks(fold(part))
            return last is not None and last <= LEADING_WORD_SURNAME_TOP
        if kind in ("first", "surname", "structural"):
            return True
        if kind == "initial":
            letter = fold(part)
            following = fold(nxt[0])
            vowel_letter = letter in _VOWELS
            vowel_next = following[:1] in _VOWELS
            if nxt[1] == "first" and self.strong_first(nxt[0]):
                if vowel_letter == vowel_next:
                    return True
                return not vowel_letter and not self.joined_known(part, nxt[0])
            if nxt[1] == "surname":
                return not (vowel_letter and not vowel_next
                            and self.joined_known(part, nxt[0]))
            return False
        return False

    def finalize(self, parts, from_separators, kinds=None):
        items = []
        titled = False
        for index, part in enumerate(parts or []):
            if not isinstance(part, str) or not part.strip():
                continue
            kind = kinds[index] if kinds else self.kind_of(part, from_separators)
            if fold(part).strip(".'-") in _TITLES:
                if from_separators:
                    titled = True
                    continue
                kind = "word"
            items.append((part, "" if kind == "junk" else kind))
        items, titled_tail = self.drop_tail_role(items)
        titled = titled or titled_tail
        if not items:
            return []
        if any(fold(p).strip(".'-") in _PLACEHOLDER_WORDS for p, _ in items):
            return []
        if any(fold(p).strip(".'-") in _NOT_NAME_WORDS for p, _ in items):
            return []
        squashed = [letters_only(fold(p)) for p, _ in items]
        for i in range(len(squashed)):
            for j in range(i + 2, len(squashed) + 1):
                if "".join(squashed[i:j]) in _KNOWN_PHRASES:
                    return []
        had_words = titled or len(items) > 1

        if sum(1 for p, _ in items if fold(p) in _MONTHS) >= 2:
            return []

        name_kinds = ("first", "surname", "structural")
        business = any(self.is_business(p) for p, _ in items)

        if from_separators:
            items = self._short_surnames(items)
            loose = sum(1 for p, k in items if k in ("initial", "") or len(fold(p)) <= 2)
            if loose >= 3 and not (items[0][1] == "first" and len(fold(items[0][0])) >= 4):
                return []
            items = [(p, "word" if k == "first" and len(fold(p)) >= 3
                      and self.wordlike_first(p) else k) for p, k in items]
            lead_at = next((i for i, (p, k) in enumerate(items) if k not in ("", "weak") and not (
                k == "word" and (self.is_phrase(p) or self._is_role(p)
                                 or fold(p) in _TITLES))), None)
            if lead_at is not None and items[lead_at][1] == "word":
                after = next(((p, k) for p, k in items[lead_at + 1:]
                              if k in ("first", "surname", "structural")), None)
                if after is None or not (after[1] == "first" and self.strong_first(after[0])
                                         and not self._nicknamey(after[0])):
                    return []
            named = [(p, k) for p, k in items if k in ("first", "surname", "structural")]
            if (titled and len(named) == 1 and named[0][1] == "first"
                    and (not self.strong_first(named[0][0])
                         or self._nicknamey(named[0][0]))):
                return []
            items = self._initial_context(items, separators=True)
            if business and not self.business_name_ok(items):
                return []
        else:
            relabeled = []
            for index, (part, kind) in enumerate(items):
                short_tail = (kind in ("word", "") and len(fold(part)) == 2
                              and index == len(items) - 1
                              and fold(part) in _EAST_ASIAN_SHORT_SURNAMES)
                if (kind == "first" and len(fold(part)) <= 2) or short_tail:
                    near = [items[j][0] for j in (index - 1, index + 1)
                            if 0 <= j < len(items) and items[j][1] == "first"
                            and len(fold(items[j][0])) >= 3]
                    chinese = (fold(part) in _CHINESE_SHORT_SURNAMES and any(
                        self._countries(fold(p)) & _CHINESE_NAME_COUNTRIES for p in near))
                    prev_countries = (self._countries(fold(items[index - 1][0]))
                                      if index > 0 else set())
                    asian_name = (not prev_countries or bool(prev_countries & _CHINESE_NAME_COUNTRIES)
                                  or prev_countries <= {"CA", "DE"})
                    tail_surname = (fold(part) in _EAST_ASIAN_SHORT_SURNAMES
                                    and index == len(items) - 1 and index > 0
                                    and items[index - 1][1] == "first"
                                    and len(fold(items[index - 1][0])) >= 3 and asian_name)
                    if tail_surname:
                        kind = "surname"
                    elif kind == "first":
                        kind = "first" if chinese else "weak"
                elif kind in ("first", "surname") and len(fold(part)) >= 3:
                    kind = "first" if self.is_anchor(part) else (
                        "surname" if self.surname_ok(part) else kind)
                    if kind == "first" and self.wordlike_first(part):
                        kind = "word"
                relabeled.append((part, kind))
            items = self.promote_rare_first(self._initial_context(relabeled))
            if not self._fused_lead_ok(items) or not self.lead_extra_ok(items):
                return []
            for index in range(len(items) - 1):
                if items[index][1] == "initial":
                    joined = fold(items[index][0]) + fold(items[index + 1][0])
                    if self._word_counts.get(joined, 0) >= PHRASE_WORD_COUNT:
                        return []
            for index in range(1, len(items)):
                part, kind = items[index]
                if (kind == "surname" and len(fold(part)) <= 4
                        and items[index - 1][1] == "first"):
                    _, last = self._ranks(fold(part))
                    if last is None or last > INITIAL_SURNAME_TOP:
                        if not self.confident_first(items[index - 1][0]):
                            return []
                        items = items[:index]
                        break
            first_at = next((i for i, (_, k) in enumerate(items) if k == "first"), None)
            for part, kind in items[:first_at or 0]:
                if kind == "surname" and not self.rare_first(part):
                    _, last = self._ranks(fold(part))
                    long_enough = (len(fold(part)) >= LEADING_SURNAME_LEN and last is not None
                                   and last <= INITIAL_SURNAME_TOP)
                    if last is None or (last > LEADING_SURNAME_TOP and not long_enough):
                        return []
                    if last > LEADING_WEAK_SURNAME:
                        follower = fold(items[first_at][0])
                        rank = self.first_rank(follower)
                        share = self._gender_share(follower)
                        if not (rank is not None and rank <= 1000 and share is not None
                                and share >= GENDERED_SHARE):
                            return []
            cut = self._truncate_at(items)
            if cut is not None:
                items = items[:cut]
                if not any(k == "first" for _, k in items):
                    return []
            named = [(p, k) for p, k in items if k in name_kinds]
            if (named and any(k == "first" for _, k in named) and self._word_counts
                    and all(self._word_counts.get(fold(p), 0) >= PHRASE_WORD_COUNT
                            for p, _ in named)
                    and not any(k == "first" and self.strong_first(p) for p, k in named)
                    and not self.weak_but_real(named)):
                return []
            if business:
                head = next(((p, k) for p, k in items
                             if not (k == "word" and (self.is_phrase(p)
                                                      or fold(p) in _TITLES))), None)
                if head is None or head[1] != "first" or not self.business_name_ok(items):
                    return []
            seen_name = False
            for index, (part, kind) in enumerate(items):
                if kind in name_kinds:
                    seen_name = True
                elif kind in ("", "weak") and seen_name:
                    if len(fold(part)) >= 6 and not self.hard_junk(part):
                        return []
                    later = any(k in name_kinds for _, k in items[index + 1:])
                    if later:
                        items = items[:index]
                        break
            while items and items[-1][1] in ("", "weak"):
                part = items[-1][0]
                prev = items[-2] if len(items) >= 2 else ("", "")
                clear = len(fold(part)) >= 3 and self.hard_junk(part)
                if not clear and not (prev[1] == "first" and (
                        self.strong_first(prev[0]) or self.confident_first(prev[0]))):
                    return []
                items = items[:-1]
            if not items:
                return []

        kept = []
        in_phrase = plain_gap = False
        for part, kind in items:
            if kind in ("", "weak"):
                continue
            if kind == "word":
                if self._is_role(part):
                    continue
                if (not from_separators and kept and not in_phrase
                        and not self.is_phrase(part) and fold(part) not in _TITLES):
                    return []
                if kept and not in_phrase:
                    in_phrase = True
                    plain_gap = not self.is_phrase(part)
                    if not from_separators:
                        while kept and kept[-1][1] != "first":
                            kept.pop()
                    else:
                        while kept and kept[-1][1] in ("structural", "initial"):
                            kept.pop()
                continue
            if in_phrase:
                if kind == "first" and fold(part) in {fold(p) for p, _ in kept}:
                    continue
                if kind == "first" and (not from_separators or plain_gap):
                    return []
                if kind != "first":
                    continue
                in_phrase = False
            if kind != "initial" and fold(part) in {fold(p) for p, _ in kept}:
                continue
            kept.append((part, kind))
        if not kept:
            return []

        if len(kept) >= 2 and kept[0][1] == "first" and len(fold(kept[0][0])) <= 2:
            later = [p for p, k in kept[1:] if k == "first" and len(fold(p)) >= 3]
            if later:
                lead = fold(kept[0][0])
                lead_countries = self._countries(lead)
                other = set()
                for p in later:
                    other |= self._countries(fold(p))
                chinese = (lead in _EAST_ASIAN_SHORT_SURNAMES
                           and other & _CHINESE_NAME_COUNTRIES)
                if lead_countries and other and not (lead_countries & other) and not chinese:
                    kept.pop(0)

        if not from_separators:
            kept = self.prune_structural(kept)
            if not kept:
                return []

        has_first = any(k == "first" for _, k in kept)

        if not from_separators:
            cleaned = []
            for index, (part, kind) in enumerate(kept):
                if kind == "initial" and 0 < index < len(kept) - 1:
                    if fold(part) in _VOWELS and kept[index - 1][1] == "first":
                        longer = self.first_rank(fold(kept[index - 1][0]) + fold(part))
                        if longer is not None and longer <= SPLIT_FIRST_RANK:
                            return []
                    right_part, right_kind = kept[index + 1]
                    _, right_last = self._ranks(fold(right_part))
                    supported = kept[index - 1][1] == "first" and (
                        right_kind == "first" or (right_kind == "surname"
                                                  and right_last is not None
                                                  and right_last <= 1000))
                    if not supported:
                        break
                cleaned.append((part, kind))
            kept = cleaned
            if (len(kept) >= 2 and kept[-1][1] == "initial"
                    and kept[-2][1] in ("surname", "structural") and has_first):
                surname_part, surname_kind = kept[-2]
                _, surname_last = self._ranks(fold(surname_part))
                if (surname_kind == "structural" or surname_last is None
                        or surname_last > INITIAL_SURNAME_TOP):
                    kept = kept[:-2]
                else:
                    kept = kept[:-1]
                if not kept:
                    return []
        while kept and kept[-1][1] == "initial" and (
                has_first or fold(kept[-1][0]) in _DECORATION_LETTERS or len(kept) == 1):
            kept.pop()
        while kept and kept[0][1] == "initial" and (has_first or len(kept) == 1):
            kept.pop(0)
        if not kept:
            return []

        has_first = any(k == "first" for _, k in kept)
        if not has_first:
            named = [(p, k) for p, k in kept if k != "initial"]
            initials = [p for p, k in kept if k == "initial"]
            if from_separators:
                pair = (len(kept) == 2 and len(named) == 1 and len(initials) == 1
                        and not (fold(named[0][0]) in _NICK_WORDS
                                 and not self.reads_as_surname(named[0][0])))
                many = (len(named) >= 2 and not business
                        and all(k in ("surname", "structural") for _, k in named))
                if not (pair or many):
                    return []
            else:
                surnames = kept[1:]
                if not (kept[0][1] == "initial" and 1 <= len(surnames) <= 2
                        and all(k == "surname" for _, k in surnames)):
                    return []
                limit = INITIAL_SURNAME_TOP if len(surnames) == 1 else LEADING_SURNAME_TOP
                for surname, _ in surnames:
                    _, last = self._ranks(fold(surname))
                    if last is None or last > limit:
                        return []
                if self.clear_given_name(kept[1][0]):
                    return []

        if len(kept) == 1 and len(fold(kept[0][0])) < 3:
            return []

        if len(kept) == 1 and kept[0][1] == "first":
            if fold(kept[0][0]) in _NICK_WORDS:
                return []
            if had_words and self._nicknamey(kept[0][0]):
                return []
            if self.lone_surname(kept[0][0]):
                return []
            if not from_separators:
                rank = self.first_rank(kept[0][0])
                if (rank is None or rank > LONE_FIRST_RANK) and self.english_compound(kept[0][0]):
                    return []
        if self.nick_pair([p for p, k in kept if k != "initial"]):
            return []
        if not from_separators:
            firsts = [p for p, k in kept if k == "first"]
            if firsts and all(
                    (self.first_rank(p) is None or self.first_rank(p) > SPLIT_FIRST_RANK)
                    and not ((self._gender_share(fold(p)) or 0) >= GENDERED_SHARE)
                    for p in firsts):
                return []

        while len(kept) > MAX_TOKENS:
            middle = [i for i in range(1, len(kept) - 1) if kept[i][1] == "initial"]
            drop = middle[0] if middle else len(kept) - 2
            kept.pop(drop)
        return [p for p, _ in kept]

    def clean_guess(self, parts, fused=False):
        if fused and self.joined_word_guess(parts):
            return []
        kept = []
        fragment = False
        for part in parts or []:
            if not isinstance(part, str) or not part.strip():
                continue
            t = fold(part).strip(".'-")
            if not t or t in _TITLES:
                continue
            if len(t) == 1:
                kept.append((part, "initial"))
                continue
            if self.hard_junk(t) or t in _PHRASE_WORDS:
                fragment = fragment or self.is_fragment(t)
                continue
            if fold(part) in {fold(p) for p, k in kept if k != "initial"}:
                continue
            kept.append((part, "first" if self.first_ok(t, 2) else "guess"))
        if not kept:
            return []
        if fused and fragment and not any(k == "first" for _, k in kept):
            return []
        if len(kept) >= 2 and kept[0][1] == "first" and len(fold(kept[0][0])) <= 2:
            later = [p for p, k in kept[1:] if k == "first" and len(fold(p)) >= 3]
            if later:
                lead = fold(kept[0][0])
                other = set()
                for p in later:
                    other |= self._countries(fold(p))
                chinese = (lead in _EAST_ASIAN_SHORT_SURNAMES
                           and other & _CHINESE_NAME_COUNTRIES)
                lead_countries = self._countries(lead)
                if lead_countries and other and not (lead_countries & other) and not chinese:
                    kept.pop(0)
        named = [p for p, k in kept if k != "initial"]
        has_first = any(k == "first" and len(fold(p)) >= 3 for p, k in kept) and not (
            len(named) == 1 and self.reads_as_surname(named[0]))
        while kept and kept[-1][1] == "initial" and (
                has_first or fold(kept[-1][0]) in _DECORATION_LETTERS or len(kept) == 1):
            kept.pop()
        while kept and kept[0][1] == "initial" and (has_first or len(kept) == 1):
            kept.pop(0)
        if len(kept) == 1 and len(fold(kept[0][0])) < 3:
            return []
        if len(kept) == 1:
            only = fold(kept[0][0])
            if not self._lone_profile_name(only) or (
                    only in self.english_words and not self._is_first(only)
                    and not self.surname_ok(only)):
                return []
        return [p for p, _ in kept]


    def profile_tokens(self, name):
        if not isinstance(name, str):
            return None
        name = " ".join(name.split())
        if not name or len(name) > 60:
            return None
        if re.search(r"\d", name) or re.search(r"[@/\\_#|]|https?:|www\.", name, re.I):
            return None
        if len(scripts_of(name)) > 1:
            return None
        if not scripts_of(name):
            return None
        squashed = letters_only(name)
        if any(part in squashed for part in _SPAM_PARTS):
            return None
        tokens = [t.strip(".,") for t in re.split(r"[\s,]+", name) if t.strip(".,")]
        if not tokens or len(tokens) > 4:
            return None
        for t in tokens:
            if re.search(r"[^\w'.\-]", t, re.UNICODE):
                return None
            low = fold(t).strip(".'-")
            if low in WEB_WORDS or low in ROLE_WORDS or low in BUSINESS_WORDS:
                return None
        return tokens

    def profile_name(self, raw, local_part):
        tokens = self.profile_tokens(raw)
        if not tokens:
            return "", ""
        joined = " ".join(tokens)
        local_letters = letters_only(local_part or "")
        if not is_latin(joined):
            if len(tokens) == 1 and letters_only(joined) == local_letters:
                return "", ""
            return "", joined
        if len(tokens) == 1 and letters_only(joined) == local_letters:
            return "", ""
        if len(tokens) == 1:
            token = tokens[0]
            if (len(letters_only(token)) >= 3 and self.is_anchor(token)
                    and self._lone_profile_name(token)):
                return display_case(token), ""
            pieces = self.segment(token)
            if (len(pieces) >= 2 and all(k in ("first", "surname") for _, k in pieces)
                    and any(self.is_anchor(p) for p, _ in pieces)
                    and consistent_with_address([p for p, _ in pieces], local_letters)):
                kept = self.finalize([p for p, _ in pieces], False,
                                     [k for _, k in pieces])
                if len(kept) >= 2:
                    return " ".join(display_case(p) for p in kept), ""
            return "", ""
        kept = self.finalize(tokens, True)
        if not kept:
            return "", ""
        return " ".join(display_case(p) for p in kept), ""
