# -*- coding: utf-8 -*-
import math

from .name_words import (BUSINESS_WORDS, ROLE_WORDS, WEB_WORDS,
                         MAX_SEGMENT_INPUT, MAX_TOKEN_LEN, PLAIN_WORD_COUNT, _PHRASE_WORDS,
                         _NICK_WORDS, _NOT_NAME_WORDS, _EAST_ASIAN_SHORT_SURNAMES, _NICK_PREFIXES,
                         _KNOWN_PHRASES, _I_VERB_PREFIXES,
                         _CHINESE_NAME_COUNTRIES, fold, is_latin, letters_only)

PHRASE_WORD_COUNT = 1000000

GENDERED_SHARE = 0.85

SURNAME_DOMINANT_RATIO = 5

INITIAL_DUAL_SURNAME_RANK = 50

LONE_SURNAME_FIRST_RANK = 100

CONFIDENT_SHARE = 0.8
CONFIDENT_SURNAME_RANK = 1000

JOINED_KNOWN_RANK = 2000

PHRASE_NAME_RANK = 100
PHRASE_NAME_SHARE = 0.95

NICK_TAIL_WORD_COUNT = 10000000
NICK_TAIL_SURNAME_TOP = 50

WHOLE_FIRST_RANK = 500

CONCAT_SURNAME_RANK = 1000

CONCAT_FIRST_RANK = 300

CONCAT_PART_RANK = 50

CONCAT_SURNAME_PART = 10

_ONE_LETTER_WORDS = frozenset({"i", "a", "u"})

_SHORT_WORDS = frozenset({"my", "me", "be", "we", "is", "in", "on", "of", "at", "to",
                          "it", "an", "so", "go", "do", "no", "up", "us", "he", "or",
                          "as", "by", "if", "am", "hi", "oh", "ok", "mr", "dr", "ms"})

_SURNAMES_NOT_NAMES = frozenset({
    "singh", "kaur",
    "nguyen", "tran", "pham", "hoang", "huynh", "phan", "dang", "bui", "duong",
    "zhang", "wang", "chen", "liu", "yang", "huang", "zhao", "zhou", "sun",
    "zhu", "gao", "guo", "luo", "liang", "zheng", "xie", "tang", "feng", "deng",
    "cao", "peng", "zeng", "xiao", "tian", "dong", "pan", "yuan", "cai", "jiang",
    "cheng", "ding", "shen", "yao", "kim", "park", "choi", "jung", "kang", "cho",
    "yoon", "jang", "lim", "seo", "shin", "kwon", "hwang", "ahn", "yoo",
})


class EvidenceMixin:

    def dual_surname(self, token):
        _first, last = self._ranks(fold(token))
        return last is not None and last <= INITIAL_DUAL_SURNAME_RANK

    def reads_as_surname(self, token):
        t = fold(token)
        if t in _SURNAMES_NOT_NAMES:
            return True
        first, last = self._ranks(t)
        if last is None:
            return False
        if first is None or last * SURNAME_DOMINANT_RATIO <= first:
            return True
        share = self._gender_share(t)
        return share is not None and share < GENDERED_SHARE and last < first

    def lone_surname(self, token):
        t = fold(token)
        if t in _SURNAMES_NOT_NAMES:
            return True
        first, last = self._ranks(t)
        if last is None:
            return False
        if first is None:
            return True
        share = self._gender_share(t)
        if share is None or share < GENDERED_SHARE:
            return last * 3 <= first
        return last * SURNAME_DOMINANT_RATIO <= first and first > LONE_SURNAME_FIRST_RANK

    def not_a_name_string(self, letters):
        s = letters_only(letters)
        if s in _NOT_NAME_WORDS or s in _KNOWN_PHRASES or s.startswith(_I_VERB_PREFIXES):
            return True
        if any(s.startswith(prefix) and s[len(prefix):] in _NICK_WORDS
               for prefix in _NICK_PREFIXES):
            return True
        return any(len(s) >= 3 * k and s == s[:k] * (len(s) // k) for k in (1, 2, 3))

    def confident_first(self, part):
        t = fold(part)
        if len(t) < 5 or t in _NICK_WORDS or not self.first_ok(t, 5) or self.wordlike_first(t):
            return False
        share = self._gender_share(t)
        return share is not None and share >= GENDERED_SHARE

    def _lone_profile_name(self, token):
        t = fold(token)
        if t in _NICK_WORDS or t in _NOT_NAME_WORDS or self._nicknamey(t):
            return False
        if self.english_compound(t) or self.lone_surname(t):
            return False
        if self.strong_first(t):
            return True
        share = self._gender_share(t)
        return share is not None and share >= GENDERED_SHARE and t not in self.english_words

    def clear_given_name(self, token):
        t = fold(token)
        if self.reads_as_surname(t):
            return False
        rank = self.first_rank(t)
        share = self._gender_share(t)
        _, last = self._ranks(t)
        return (rank is not None and rank <= 1000 and share is not None
                and share >= GENDERED_SHARE and (last is None or rank <= last))

    def joined_known(self, letter, piece):
        first, last = self._ranks(fold(letter) + fold(piece))
        return ((first is not None and first <= JOINED_KNOWN_RANK)
                or (last is not None and last <= JOINED_KNOWN_RANK))

    def joined_word_guess(self, parts):
        whole = [p for p in parts or [] if isinstance(p, str) and p.strip()]
        return (len(whole) == 2 and len(fold(whole[0])) == 1 and len(fold(whole[1])) >= 2
                and self.joined_known(whole[0], whole[1]))

    def is_fragment(self, token):
        t = fold(token)
        if (t in WEB_WORDS or t in ROLE_WORDS or t in BUSINESS_WORDS or t in _PHRASE_WORDS
                or len(t) > MAX_TOKEN_LEN):
            return False
        return self.hard_junk(t)

    def weak_but_real(self, named):
        for part, kind in named:
            t = fold(part)
            if t in self.english_words:
                return False
            if kind == "first":
                rank, share = self.first_rank(t), self._gender_share(t)
                if not (rank is not None and rank <= 1000 and share is not None
                        and share >= GENDERED_SHARE):
                    return False
        return True

    def _asian_first(self, head):
        countries = self._countries(head)
        return bool(countries & _CHINESE_NAME_COUNTRIES) or bool(
            countries and countries <= {"CA", "DE"})

    def split_short_surname(self, letters, pieces):
        if len(pieces or []) != 1 or pieces[0][1] == "first":
            return pieces
        s = letters_only(letters)
        _, own = self._ranks(s)
        if pieces[0][1] == "surname" and own is not None and own <= 5000:
            return pieces
        for size in (3, 2):
            head, tail = s[:-size], s[-size:]
            known = (tail in _EAST_ASIAN_SHORT_SURNAMES if size == 2
                     else tail in _SURNAMES_NOT_NAMES or tail == "ngo")
            if len(head) >= 3 and known and self.first_ok(head, 3) and self._asian_first(head):
                return [(head, "first"), (tail, "surname")]
        return pieces

    def asian_tail_ambiguous(self, letters, pieces):
        s = letters_only(letters)
        for size in (5, 4, 3):
            head, tail = s[:-size], s[-size:]
            if len(head) < 4 or tail not in _SURNAMES_NOT_NAMES or tail in ("singh", "kaur"):
                continue
            pos, inside = 0, None
            for part, kind in pieces or []:
                if pos < len(head) < pos + len(part):
                    inside = (part, kind)
                pos += len(part)
            if inside is None:
                continue
            rank, share = self.first_rank(head), self._gender_share(head)
            if not (rank is not None and rank <= 6000 and share is not None
                    and share >= CONFIDENT_SHARE):
                continue
            piece_rank = self.first_rank(inside[0])
            if inside[1] == "first" and piece_rank is not None and piece_rank <= 2000:
                continue
            return True
        return False

    def split_initial(self, letters, pieces):
        if len(pieces or []) != 1 or pieces[0][1] not in ("surname", "structural", "junk", ""):
            return pieces
        s = letters_only(letters)
        if len(s) < 5 or not is_latin(s):
            return pieces
        _, own = self._ranks(s)
        _, rest = self._ranks(s[1:])
        if (rest is not None and rest <= 500 and (own is None or own > 1000)
                and self.surname_ok(s[1:])):
            return [(s[0], "initial"), (s[1:], "surname")]
        return pieces

    def _phrase_name(self, t):
        rank = self.first_rank(t)
        share = self._gender_share(t)
        return (rank is not None and rank <= PHRASE_NAME_RANK
                and share is not None and share >= PHRASE_NAME_SHARE)

    def nick_pair(self, named):
        if len(named) != 2 or fold(named[0]) not in _NICK_WORDS:
            return False
        tail = fold(named[1])
        _, tail_last = self._ranks(tail)
        common_word = self._word_counts.get(tail, 0) >= NICK_TAIL_WORD_COUNT
        return bool(tail in _NICK_WORDS or tail in _PHRASE_WORDS or tail_last is None
                    or tail_last > CONFIDENT_SURNAME_RANK
                    or (common_word and tail_last > NICK_TAIL_SURNAME_TOP))

    def _confident_pair(self, pieces):
        named = [(p, k) for p, k in pieces or [] if k in ("first", "surname", "structural")]
        if len(named) != 2 or not any(k == "first" for _, k in named):
            return False
        for part, kind in named:
            t = fold(part)
            if kind == "first":
                share = self._gender_share(t)
                if not (len(t) >= 4 and self.first_ok(t, 4) and share is not None
                        and share >= CONFIDENT_SHARE):
                    return False
            elif kind == "surname":
                _, last = self._ranks(t)
                if last is None or last > CONFIDENT_SURNAME_RANK or not self.surname_ok(t):
                    return False
            else:
                return False
        return True

    def _short_surnames(self, items):
        out = list(items)

        def namey(entry):
            part, kind = entry
            if kind == "initial":
                return True
            return kind in ("first", "structural", "surname") and len(fold(part)) >= 3

        for index, (part, kind) in enumerate(items):
            t = fold(part).strip(".'-")
            if kind == "initial" or len(t) != 2 or t not in _EAST_ASIAN_SHORT_SURNAMES:
                continue
            left = items[index - 1] if index > 0 else None
            right = items[index + 1] if index + 1 < len(items) else None
            if len(items) == 2:
                other = right if index == 0 else left
                o = fold(other[0]).strip(".'-")
                rank = self.first_rank(o)
                if len(o) == 2 and o not in _EAST_ASIAN_SHORT_SURNAMES and rank is not None \
                        and rank <= 1000:
                    out[index] = (part, "surname")
                    out[1 - index] = (other[0], "first")
                    continue
            if left is not None and namey(left):
                out[index] = (part, "surname")
                continue
            if right is not None and namey(right):
                if right[1] == "first":
                    mine = self._countries(t)
                    theirs = self._countries(fold(right[0]))
                    if (mine and theirs and not (mine & theirs)
                            and not (theirs & _CHINESE_NAME_COUNTRIES)):
                        continue
                out[index] = (part, "surname")
        return out

    def _initial_context(self, items, separators=False):
        names = [i for i, (_, k) in enumerate(items) if k in ("first", "surname", "structural")]
        if not names:
            return items
        index = names[0]
        part, kind = items[index]
        if kind != "first" or len(fold(part)) < 3:
            return items
        if any(items[i][1] != "surname" for i in names[1:]):
            return items
        if not (index > 0 and items[index - 1][1] == "initial"):
            return items
        if not (self.surname_ok(part) and (self.reads_as_surname(part)
                                           or self.surname_after_initial(part)
                                           or (separators and len(names) == 1
                                               and self.dual_surname(part)))):
            return items
        out = list(items)
        out[index] = (part, "surname")
        return out

    def english_reading(self, letters):
        s = letters_only(letters)
        if s in self._reading_memo:
            return self._reading_memo[s]
        n = len(s)
        result = None
        counts = self._word_counts
        if 0 < n <= MAX_SEGMENT_INPUT and counts:
            total = self._corpus_total()
            best = [None] * (n + 1)
            best[0] = (0.0, ())
            for i in range(n):
                if best[i] is None:
                    continue
                score, words = best[i]
                for j in range(i + 1, min(n, i + 2 * MAX_TOKEN_LEN) + 1):
                    piece = s[i:j]
                    count = counts.get(piece, 0)
                    if (count < PLAIN_WORD_COUNT
                            or (len(piece) == 1 and piece not in _ONE_LETTER_WORDS)
                            or (len(piece) == 2 and piece not in _SHORT_WORDS)):
                        count = 0
                    gain = (math.log10(count / total) if count
                            else math.log10(10.0 / total) - len(piece))
                    if best[j] is None or score + gain > best[j][0]:
                        best[j] = (score + gain, words + (piece,))
            words = best[n][1] if best[n] is not None else ()
            if words and all(counts.get(w, 0) >= PHRASE_WORD_COUNT
                             and (len(w) > 2 or w in _SHORT_WORDS or w in _ONE_LETTER_WORDS)
                             for w in words):
                cuts, pos = [], 0
                for w in words[:-1]:
                    pos += len(w)
                    cuts.append(pos)
                result = frozenset(cuts)
        return self._remember(self._reading_memo, s, result)

    def phrase_only(self, letters):
        s = letters_only(letters)
        n = len(s)
        if n < 6 or self.first_ok(s, 3):
            return False

        def word(piece):
            if piece in _PHRASE_WORDS:
                return True
            return (len(piece) >= 3 and piece in self.english_words
                    and not self._is_first(piece))

        reach = [None] * (n + 1)
        reach[0] = 0
        for i in range(n):
            if reach[i] is None:
                continue
            for j in range(i + 2, n + 1):
                if word(s[i:j]):
                    if reach[j] is None or reach[i] + 1 < reach[j]:
                        reach[j] = reach[i] + 1
        return reach[n] is not None and reach[n] >= 2

    def _compound_of_words(self, t):
        n = len(t)
        if n < 6:
            return False

        def word(piece):
            if piece in _PHRASE_WORDS:
                return len(piece) >= 3
            return len(piece) >= 4 and piece in self.english_words

        reach = [[None, None] for _ in range(n + 1)]
        reach[0][0] = 0
        for i in range(n):
            for spent in (0, 1):
                words = reach[i][spent]
                if words is None:
                    continue
                for j in range(i + 3, n + 1):
                    if word(t[i:j]):
                        cur = reach[j][spent]
                        if cur is None or words + 1 < cur:
                            reach[j][spent] = words + 1
                if not spent:
                    for j in (i + 1, i + 2):
                        if j <= n:
                            cur = reach[j][1]
                            if cur is None or words < cur:
                                reach[j][1] = words
        clean = reach[n][0]
        with_rest = reach[n][1]
        return ((clean is not None and clean >= 2)
                or (with_rest is not None and with_rest >= 1))

    def _corpus_total(self):
        total = getattr(self, "_total_count", None)
        if total is None:
            total = float(sum(v for v in self._word_counts.values()
                              if isinstance(v, (int, float))) or 1.0)
            self._total_count = total
        return total

    def english_compound(self, letters):
        cuts = self.english_reading(letters)
        if not cuts:
            return False
        s = letters_only(letters)
        bounds = [0] + sorted(cuts) + [len(s)]
        return all(b - a >= 3 for a, b in zip(bounds, bounds[1:]))

    def misaligned(self, letters, pieces):
        cuts = self.english_reading(letters)
        if cuts is None:
            return False
        s = letters_only(letters)
        bounds = [0] + sorted(cuts) + [len(s)]
        words = [s[a:b] for a, b in zip(bounds, bounds[1:])]
        if not all(w in self.english_words or w in _SHORT_WORDS or w in _ONE_LETTER_WORDS
                   for w in words):
            return False
        names = ("first", "surname", "structural")
        pos = 0
        for part, kind in pieces or []:
            if kind in names and len(part) >= 4 and not self.strong_first(part):
                inside = sorted(c for c in cuts if pos < c < pos + len(part))
                if inside and s[pos:inside[0]] in _NICK_PREFIXES:
                    return True
            pos += len(part)
        inner_function = any(w in _SHORT_WORDS or w in _ONE_LETTER_WORDS for w in words[1:-1])
        if inner_function and self._confident_pair(pieces):
            return False
        pos, prev, prev_kind = 0, "", ""
        for part, kind in pieces or []:
            if (len(prev) >= 2 and len(part) >= 2 and pos not in cuts
                    and (kind in names or prev_kind in names)):
                return True
            pos += len(part)
            prev, prev_kind = part, kind
        return False

    def whole_first(self, letters):
        s = letters_only(letters)
        if len(s) < 5 or not is_latin(s) or self.hard_junk(s) or s in _PHRASE_WORDS:
            return False
        if s in _NICK_WORDS or s in _NOT_NAME_WORDS or self.lone_surname(s):
            return False
        if s in self.english_words or self.is_plain_word(s) or self.phrase_only(s):
            return False
        first, last = self._ranks(s)
        if first is None or first > WHOLE_FIRST_RANK:
            return False
        if last is not None and first > 2 * last:
            return False
        if first > CONCAT_FIRST_RANK and self._joined_names(s):
            return False
        return not self.surname_leaning(s)

    def _strong_first_part(self, part):
        first, _ = self._ranks(part)
        return (len(part) >= 3 and first is not None and first <= CONCAT_PART_RANK
                and self.first_ok(part, 3))

    def _top_surname_part(self, part):
        _, last = self._ranks(part)
        return (len(part) >= 3 and last is not None and last <= CONCAT_SURNAME_PART
                and self.surname_ok(part))

    def _joined_names(self, piece):
        for k in range(3, len(piece) - 2):
            head, tail = piece[:k], piece[k:]
            if ((self._strong_first_part(head) and self._top_surname_part(tail))
                    or (self._top_surname_part(head) and self._strong_first_part(tail))):
                return True
        return False
