# -*- coding: utf-8 -*-
import os
import re

from .name_evidence import CONFIDENT_SHARE, PHRASE_WORD_COUNT
from .name_words import (MAX_TOKEN_LEN, PLAIN_WORD_COUNT, WEB_WORDS, _EAST_ASIAN_SHORT_SURNAMES, _PHRASE_INSIDE,
                         _PHRASE_WORDS, _TAIL_ROLE_WORDS, _TITLES, _VOWELS, _WORD_ONSETS,
                         fold, is_latin, letters_only)

MAX_STRUCTURAL = 10

MAX_NAME_TOKENS = 3

_WEB_GLUE = tuple(sorted(w for w in WEB_WORDS if len(w) >= 4))

_TRIGRAMS = None
_CLUSTERS = None
_CONSONANT_RUN = re.compile(r"[^aeiouy]+")


def _load(name):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), name)
    try:
        with open(path, encoding="utf-8") as f:
            return frozenset(f.read().split())
    except OSError:
        return frozenset()


def name_clusters():
    global _CLUSTERS
    if _CLUSTERS is None:
        _CLUSTERS = _load("name_clusters.txt")
    return _CLUSTERS


def name_trigrams():
    global _TRIGRAMS
    if _TRIGRAMS is None:
        _TRIGRAMS = _load("name_trigrams.txt")
    return _TRIGRAMS


class SplitMixin:

    def name_shaped(self, token):
        known = name_trigrams()
        t = fold(token)
        if not known or not is_latin(t) or len(t) < 3:
            return True
        padded = "^" + t + "$"
        return all(padded[i:i + 3] in known for i in range(len(padded) - 2))

    def cluster_shaped(self, token):
        known = name_clusters()
        t = fold(token)
        if not known or not is_latin(t):
            return True
        for m in _CONSONANT_RUN.finditer(t):
            group = m.group()
            if m.start() == 0 and m.end() == len(t):
                return False
            if m.start() == 0:
                if len(group) >= 2 and "^" + group not in known:
                    return False
            elif m.end() == len(t):
                if len(group) >= 2 and group + "$" not in known:
                    return False
            elif len(group) >= 3 and "-" + group + "-" not in known:
                return False
        return True

    def lead_extra_ok(self, items):
        if not items:
            return True
        part, kind = items[0]
        prefixed = kind == "initial" or (kind == "word" and (
            self.is_phrase(part) or fold(part).strip(".'-") in _TITLES))
        if not prefixed:
            return True
        index = 1
        while index < len(items) and items[index][1] == "word" and (
                self.is_phrase(items[index][0]) or fold(items[index][0]) in _TITLES):
            index += 1
        rest = items[index:]
        named = [(p, k) for p, k in rest if k in ("first", "surname", "structural")]
        if len(named) < 2 or not any(k == "first" for _, k in named):
            return True
        lead, lead_kind = named[0]
        if kind != "initial":
            if lead_kind == "first" and self.strong_first(lead) and (
                    len(fold(lead)) >= 5
                    or (len(fold(lead)) == 4 and (self.first_rank(lead) or 10 ** 9) <= 50)):
                return True
            return (lead_kind != "first" or self._solid_first(lead)) and all(
                self._solid_piece(p, k) for p, k in named[1:])
        if any(k == "initial" for _, k in rest):
            return False
        if lead_kind == "first" and not self.strong_first(lead):
            return False
        return all(self._solid_piece(p, k) for p, k in named[1:])

    CONFIRMED_SURNAME_RANK = 5000

    def confirmed_name(self, parts):
        for part in parts or []:
            t = fold(part)
            if len(t) == 1:
                continue
            if self.first_ok(t):
                continue
            if len(t) == 2 and t in _EAST_ASIAN_SHORT_SURNAMES:
                continue
            _, last = self._ranks(t)
            if (len(t) >= 3 and self.surname_ok(t) and last is not None
                    and last <= self.CONFIRMED_SURNAME_RANK):
                continue
            return False
        return True

    def web_glued(self, token):
        t = fold(token)
        return any(len(word) >= 4 and len(t) > len(word) and (t.startswith(word) or t.endswith(word))
                   for word in _WEB_GLUE)

    def rare_first(self, token):
        t = fold(token)
        rank = self.first_rank(t)
        share = self._gender_share(t)
        return (len(t) >= 4 and rank is not None and rank <= 10000
                and share is not None and share >= CONFIDENT_SHARE)

    def promote_rare_first(self, items):
        named = [(i, p, k) for i, (p, k) in enumerate(items)
                 if k in ("first", "surname", "structural", "initial")]
        if len(named) != 2 or any(k != "surname" for _, _, k in named):
            return items
        (i, head, _), (_, tail, _) = named
        _, head_last = self._ranks(fold(head))
        _, tail_last = self._ranks(fold(tail))
        if (self.rare_first(head) and (head_last is None or head_last > self.SOLID_RANK)
                and len(fold(tail)) >= 4 and tail_last is not None
                and tail_last <= self.SOLID_RANK):
            items = list(items)
            items[i] = (head, "first")
        return items

    def business_name_ok(self, items):
        names = []
        for part, kind in items:
            if self.is_business(part):
                if names:
                    break
                continue
            role = kind == "word" and (self._is_role(part) or fold(part).strip(".'-") in _TITLES)
            if kind in ("first", "surname", "structural"):
                names.append((part, kind))
            elif role or (not names and kind == "word" and self.is_phrase(part)):
                continue
            elif kind == "word" and names:
                _, last = self._ranks(fold(part))
                if last is None or last > self.SOLID_RANK:
                    return False
                names.append((part, "surname"))
            elif kind == "initial" and names:
                continue
            else:
                return False
        if not names:
            return False
        lead, lead_kind = names[0]
        if lead_kind != "first":
            return False
        if self.strong_first(lead) and len(fold(lead)) >= 4:
            return True
        if not (self._solid_first(lead) or self.confident_first(lead)):
            return False
        return all(self._solid_piece(p, k) for p, k in names[1:])

    def prune_structural(self, kept):
        def strong_neighbour(entry):
            return entry[1] == "first" and len(fold(entry[0])) >= 4

        pruned = []
        for index, (part, kind) in enumerate(kept):
            if kind == "structural":
                left = kept[index - 1] if index > 0 else ("", "")
                right = kept[index + 1] if index + 1 < len(kept) else ("", "")
                size = len(fold(part))
                joined = fold(left[0])[-2:] + fold(part) + fold(right[0])[:2]
                if (size < 5 or size > MAX_STRUCTURAL
                        or not (strong_neighbour(left) or strong_neighbour(right))
                        or any(word in joined for word in _PHRASE_INSIDE)):
                    if not any(k == "first" for _, k in pruned):
                        return []
                    continue
            pruned.append((part, kind))
        if len([entry for entry in pruned if entry[1] != "initial"]) > MAX_NAME_TOKENS:
            return []
        return pruned


    def drop_tail_role(self, items):
        dropped = False
        while (len(items) >= 2 and fold(items[-1][0]).strip(".'-") in _TAIL_ROLE_WORDS
               and any(k in ("first", "surname", "structural") for _, k in items[:-1])):
            items = items[:-1]
            dropped = True
        return items, dropped

    def tail_is_role(self, token):
        t = fold(token)
        if t in _TAIL_ROLE_WORDS:
            return True
        if self.first_ok(t) or self.surname_ok(t):
            return False
        return any(len(word) >= 3 and t.endswith(word) and len(t) > len(word)
                   for word in _TAIL_ROLE_WORDS)

    def odd_onset(self, token):
        t = fold(token)
        if len(t) < 3 or t[0] in _VOWELS or t[1] in _VOWELS:
            return False
        return t[:2] not in _WORD_ONSETS

    def tail_role_cut(self, letters):
        s = letters_only(letters)
        if not is_latin(s):
            return ""
        for word in sorted(_TAIL_ROLE_WORDS, key=len, reverse=True):
            if len(word) >= 3 and s.endswith(word) and len(s) - len(word) >= 5:
                return s[:-len(word)]
        return ""


    SOLID_RANK = 1000
    JOINED_RATIO = 20

    def _solid_first(self, piece):
        t = fold(piece)
        if not self.is_anchor(t):
            return False
        rank = self.first_rank(t)
        if len(t) == 3:
            return self.strong_first(t)
        return rank is not None and rank <= self.SOLID_RANK

    def _solid_piece(self, piece, kind):
        t = fold(piece)
        if len(t) < 3 or kind in ("initial", "word", "junk", "", "weak"):
            return False
        if self.strong_first(t):
            return True
        _, last = self._ranks(t)
        return len(t) >= 4 and self.surname_ok(t) and last is not None and last <= self.SOLID_RANK

    def _whole_surname(self, whole, lead):
        t = fold(whole)
        if not (4 <= len(t) <= MAX_STRUCTURAL) or self.odd_onset(t):
            return None
        if t in self.english_words:
            return None
        if self.surname_ok(t):
            return "surname"
        known = self.first_rank(t) is not None
        if not known and (self._compound_of_words(t) or self._reads_as_words(t)
                          or self._word_glued(t)):
            return None
        if not known and self._word_counts.get(t, 0) >= PLAIN_WORD_COUNT:
            return None
        if len(fold(lead)) >= 4 and (known or self.structural_ok(t)):
            return "structural"
        return None

    def _word_glued(self, token):
        t = fold(token)

        def phrase(piece):
            return len(piece) >= 3 and piece in _PHRASE_WORDS

        def word(piece):
            if len(piece) < 4:
                return False
            if piece in self.english_words:
                return True
            return (self._word_counts.get(piece, 0) >= PHRASE_WORD_COUNT
                    and not self.surname_ok(piece) and not self.first_ok(piece))

        return any(phrase(t[:k]) or word(t[-k:]) for k in range(3, len(t) - 1))

    def _reads_as_words(self, token):
        cuts = self.english_reading(token)
        if not cuts:
            return False
        bounds = [0] + sorted(cuts) + [len(token)]
        return all(b - a >= 4 for a, b in zip(bounds, bounds[1:]))

    def keeps_boundary(self, head, tail, tail_kind):
        if tail_kind != "surname" or not self.surname_ok(tail):
            return False
        h, t = fold(head), fold(tail)
        for k in range(1, min(3, len(t)) + 1):
            rank = self.first_rank(h + t[:k])
            if rank is None or rank > 300:
                continue
            rest = t[k:]
            if len(rest) <= 1 or self.surname_ok(rest) or self.first_ok(rest):
                return False
        return True

    def surname_after_initial(self, token):
        t = fold(token)
        first, last = self._ranks(t)
        return (not self.strong_first(t) and last is not None and last <= 500
                and (first is None or last < first) and self.surname_ok(t))

    def merge_oversplit(self, pieces):
        items = list(pieces or [])
        start = 0
        while start < len(items) and items[start][1] == "word" and (
                self.is_phrase(items[start][0]) or fold(items[start][0]) in _TITLES):
            start += 1
        end = len(items)
        while end > start and items[end - 1][1] in ("word", "junk", "") and (
                self._is_role(items[end - 1][0]) or self.is_phrase(items[end - 1][0])):
            end -= 1
        span = items[start:end]
        if len(span) < 3:
            return pieces

        def weak(run):
            return any(not self._solid_piece(p, k) for p, k in run)

        def middle_initial(run):
            if len(run) != 2 or run[0][1] != "initial" or not self._solid_piece(*run[1]):
                return False
            first, last = self._ranks(fold(run[0][0]) + fold(run[1][0]))
            own_first, own_last = self._ranks(fold(run[1][0]))
            own = min(r for r in (own_first, own_last, 10 ** 9) if r is not None)
            joined = min(r for r in (first, last, 10 ** 9) if r is not None)
            return joined > self.JOINED_RATIO * own

        lead, lead_kind = span[0]
        if self._solid_first(lead) or (len(fold(lead)) >= 5 and self.is_anchor(lead)):
            run = span[1:]
            whole = "".join(fold(p) for p, _ in run)
            longer = any(self.is_anchor(fold(lead) + whole[:k]) and (
                self.surname_ok(whole[k:]) or self.first_ok(whole[k:]))
                for k in range(1, min(3, len(whole) - 2) + 1))
            name_end = longer or self._longer_name(lead, whole) or (
                run[0][1] == "initial" and fold(run[0][0]) in _VOWELS
                and self.first_rank(fold(lead) + fold(run[0][0])) is not None)
            own = min(r for r in self._ranks(fold(run[0][0])) + (10 ** 9,) if r is not None)
            joined = min(r for r in self._ranks(whole) + (10 ** 9,) if r is not None)
            rest_len = sum(len(fold(p)) for p, _ in run[1:])
            scraps = all(k in ("initial", "junk", "", "word", "weak") for _, k in run[1:])
            if 0 < rest_len <= 3 and scraps and not name_end and joined > self.JOINED_RATIO * own:
                if rest_len == 1 and own <= 5000 and (
                        self._solid_piece(*run[0]) or self.surname_ok(run[0][0])):
                    return pieces
                if rest_len >= 2 and own <= 300 and len(fold(run[0][0])) >= 5:
                    return items[:start] + [(lead, lead_kind), run[0]] + items[end:]
            if len(run) == 2 and (self.first_rank(run[0][0]) or 10 ** 9) <= 100 \
                    and self.strong_first(run[0][0]) and len(fold(run[1][0])) >= 5 \
                    and self.surname_ok(run[1][0]) and (self._ranks(fold(run[1][0]))[1] or 10 ** 9) <= 5000:
                return pieces
            tail_piece, tail_kind = run[-1]
            if (tail_kind == "surname" and len(fold(tail_piece)) >= 6 and joined == 10 ** 9
                    and (self._ranks(fold(tail_piece))[1] or 10 ** 9) <= 200
                    and 0 < sum(len(fold(p)) for p, _ in run[:-1]) <= 2):
                return pieces
            if weak(run) and not middle_initial(run) and not name_end:
                kind = self._whole_surname(whole, lead)
                if kind:
                    return items[:start] + [(lead, lead_kind), (whole, kind)] + items[end:]
            return pieces
        letters = "".join(fold(p) for p, _ in span)
        for k in range(min(len(letters) - 4, MAX_TOKEN_LEN), 2, -1):
            head, rest = letters[:k], letters[k:]
            if self._solid_first(head) and self.strong_first(head) and self.surname_ok(rest) \
                    and self._whole_surname(rest, head) == "surname":
                return items[:start] + [(head, "first"), (rest, "surname")] + items[end:]
        last, last_kind = span[-1]
        if self._solid_piece(last, last_kind) and len(fold(last)) >= 4:
            run = span[:-1]
            whole = "".join(fold(p) for p, _ in run)
            if len(whole) >= 5 and self.rare_first(whole) and whole not in self.english_words:
                return items[:start] + [(whole, "structural"), (last, last_kind)] + items[end:]
        return pieces
