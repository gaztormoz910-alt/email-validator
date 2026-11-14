# -*- coding: utf-8 -*-
"""Границы кусков имени: где разбор режет лишнего и где не дорезает.

Примесь к NameQuality (core/parser/name_quality.py). Вынесено отдельно
13.11.2026: замер на настоящих базах (27 753 адреса) показал, что в режиме
«Точность» неверно около одного имени из пяти, и большая часть ошибок —
про границы кусков, а не про то, имя ли кусок:

* редкая фамилия, которой база не знает, дробилась на короткие известные
  «имена» и буквы (`elenacorvetti` давал «Elena Cor Etti», `emmabirdie` —
  «Emma Birdi»);
* слово-занятие в хвосте («dev», «art», «law») липло к имени фамилией
  (`annalopezdev` — «Anna Lopez Dev») или хоронило имя целиком;
* имя с частой фамилией-словом (`laurablack`) терялось.

Правила здесь общие — про форму строки и ранги базы, без единого адреса.
Примеры в комментариях выдуманы: адресов владельца в коде нет.
"""
import os
import re

from .name_evidence import CONFIDENT_SHARE, PHRASE_WORD_COUNT
from .name_words import (MAX_TOKEN_LEN, PLAIN_WORD_COUNT, WEB_WORDS, _EAST_ASIAN_SHORT_SURNAMES, _PHRASE_INSIDE,
                         _PHRASE_WORDS, _TAIL_ROLE_WORDS, _TITLES, _VOWELS, _WORD_ONSETS,
                         fold, is_latin, letters_only)

# Неподтверждённый кусок в слитной строке длиннее этого — уже не фамилия,
# которой не знает база, а хвост из нескольких слов. То же число, что
# MAX_STRUCTURAL_FUSED в name_quality.py; здесь — чтобы не тянуть оттуда.
MAX_STRUCTURAL = 10

# Больше трёх кусков имени в слитной строке — строку раздробило.
MAX_NAME_TOKENS = 3

# Слова сети, которые приклеивают к имени аккаунта: «anna|mailbox».
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
    """Группы согласных, с которых имена начинаются, которыми кончаются и
    которые стоят внутри (tools/build_name_trigrams.py). Файла нет — пусто,
    и признак молчит."""
    global _CLUSTERS
    if _CLUSTERS is None:
        _CLUSTERS = _load("name_clusters.txt")
    return _CLUSTERS


def name_trigrams():
    """Тройки букв, которые встречаются в именах (tools/build_name_trigrams.py).

    Читается один раз. Файла нет — набор пуст, и признак молчит: без него
    разбор работает, как до 13.11.2026, а не отвергает всё подряд.
    """
    global _TRIGRAMS
    if _TRIGRAMS is None:
        _TRIGRAMS = _load("name_trigrams.txt")
    return _TRIGRAMS


class SplitMixin:
    """Границы кусков. Полагается на поля и методы NameQuality."""

    def name_shaped(self, token):
        """Буквосочетание похоже на имя: все его тройки букв в именах встречаются.

        Фамилий, которых база не знает, много, и отвергать неизвестное
        нельзя; но «mqtzk» или «bgxq» фамилиями не бывают. Спрашивается
        только про куски, которых база не знает. Произносимый мусор признак
        не ловит — на то другие правила; как подобран порог — в
        tools/build_name_trigrams.py.
        """
        known = name_trigrams()
        t = fold(token)
        if not known or not is_latin(t) or len(t) < 3:
            return True
        padded = "^" + t + "$"
        return all(padded[i:i + 3] in known for i in range(len(padded) - 2))

    def cluster_shaped(self, token):
        """Группы согласных куска — такие, какие бывают в именах.

        Кусок, который кончается на «tc» или «ngc», начинается с «bc» или
        держит внутри «tsc», частым именем или фамилией не бывает. Признак
        грубее троек и спрашивается только про неизвестные базе куски между
        разделителями (см. сборщик). Цена известна: редкая настоящая
        фамилия с непривычной группой согласных внутри в имя не идёт. Без
        проверки групп внутри слова на полной базе 13.11.2026 возвращалось
        заметно больше названий фирм, чем терялось фамилий.
        """
        known = name_clusters()
        t = fold(token)
        if not known or not is_latin(t):
            return True
        for m in _CONSONANT_RUN.finditer(t):
            group = m.group()
            if m.start() == 0 and m.end() == len(t):
                return False                  # одни согласные — не имя
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
        """Строка начинается с буквы или слова фразы — дальше только бесспорное.

        Ведущая буква снималась как лишний инициал, и «имя» начиналось со
        второй буквы адреса («t|vane|lund» давало бы «Vane Lund»). Слово
        фразы впереди снималось, и в имя шли осколки названия («the|gina|
        lstore»). Буква или слово впереди законны перед частым именем
        («k|zoltan», «iam|mark|jones»), а если кусков после них два и
        больше — каждый обязан быть частым, и других букв быть не должно.
        Запись «буква + фамилии» («j|garcia|lopez») судится не здесь.
        """
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
            # Слово фразы или титул впереди: частому имени — доверие
            # («iam|mark|jones», «dr|anna|m|lopez»), остальным — только
            # бесспорные куски. Трёхбуквенному имени доверия нет,
            # четырёхбуквенному — только из первой полусотни (Anna — 1-е,
            # Mark — 5-е): имя с двухсотых мест после слова фразы на полной
            # базе 13.11.2026 чаще оказывалось началом названия, чем именем.
            # Порог грубый и в обе стороны ошибается на единицах адресов.
            if lead_kind == "first" and self.strong_first(lead) and (
                    len(fold(lead)) >= 5
                    or (len(fold(lead)) == 4 and (self.first_rank(lead) or 10 ** 9) <= 50)):
                return True
            return (lead_kind != "first" or self._solid_first(lead)) and all(
                self._solid_piece(p, k) for p, k in named[1:])
        # Буква впереди и два куска после: буква снимется, и имя начнётся со
        # второй буквы адреса. Законно только перед частым именем, без
        # других букв и с частыми кусками дальше.
        if any(k == "initial" for _, k in rest):
            return False
        if lead_kind == "first" and not self.strong_first(lead):
            return False
        return all(self._solid_piece(p, k) for p, k in named[1:])

    # Фамилия, которую можно назвать подтверждённой: не дальше этого места.
    CONFIRMED_SURNAME_RANK = 5000

    def confirmed_name(self, parts):
        """Каждый кусок угаданного имени база знает. Строгость «Точности».

        Решение владельца 14.11.2026. Имя, границы которого угадал разбор (а
        не поставил человек), в «Точности» остаётся, только если каждый его
        кусок — имя из индекса или первых мест базы либо фамилия от четырёх
        букв не дальше CONFIRMED_SURNAME_RANK; одна буква — инициал. Замер на
        отложенной выборке из 200 имён настоящих баз: неверных 19,1% -> 15,0%,
        ценой 13,5% имён, из которых примерно половина были верными
        (неизвестная базе редкая фамилия). Владелец видел этот обмен до
        решения.
        """
        for part in parts or []:
            t = fold(part)
            if len(t) == 1:
                continue
            if self.first_ok(t):
                continue
            # Короткие фамилии Китая, Вьетнама, Кореи («jing|li», «hung|ly»)
            # и частые трёхбуквенные (Doe, Cho — surname_ok сам требует места
            # не дальше SHORT_SURNAME_TOP) — подтверждены.
            if len(t) == 2 and t in _EAST_ASIAN_SHORT_SURNAMES:
                continue
            _, last = self._ranks(t)
            if (len(t) >= 3 and self.surname_ok(t) and last is not None
                    and last <= self.CONFIRMED_SURNAME_RANK):
                continue
            return False
        return True

    def web_glued(self, token):
        """К неизвестному куску приклеено слово сети: «annamailbox», «onlinemaria»."""
        t = fold(token)
        return any(len(word) >= 4 and len(t) > len(word) and (t.startswith(word) or t.endswith(word))
                   for word in _WEB_GLUE)

    def rare_first(self, token):
        """База знает слово именем с ясным полом, хотя индекс его не знает."""
        t = fold(token)
        rank = self.first_rank(t)
        share = self._gender_share(t)
        return (len(t) >= 4 and rank is not None and rank <= 10000
                and share is not None and share >= CONFIDENT_SHARE)

    def promote_rare_first(self, items):
        """Редкое имя и частая фамилия, а не две фамилии.

        Разбор метит оба куска фамилиями, имени не остаётся, и строка уходит
        в пустоту. Первое слово становится именем, только если база знает
        его именем с ясным полом, само оно фамилией редкое, а второе —
        частая фамилия: «gonzalez|lopez» остаётся двумя фамилиями.
        """
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
        """Рядом с родом деятельности имя обязано быть бесспорным.

        «annabrows», «maria.lopez.tech» — человек со своим делом: частое имя
        стоит первым, за ним, если есть, частая фамилия. А «golden|peak|
        academy», «blue|river|studio» — названия, в которых разбор находил
        осколки, похожие на имена (на полной базе 13.11.2026 таких было
        много). До слова деятельности допускаются только имя и частые куски,
        без словарных слов и без обломков.
        """
        names = []
        for part, kind in items:
            if self.is_business(part):
                if names:
                    break
                continue              # «management.anna»: слово впереди имени
            role = kind == "word" and (self._is_role(part) or fold(part).strip(".'-") in _TITLES)
            if kind in ("first", "surname", "structural"):
                names.append((part, kind))
            elif role or (not names and kind == "word" and self.is_phrase(part)):
                continue              # «dr|anna|…», «the|anna|…», «anna|office|…»
            elif kind == "word" and names:
                # Словарное слово после имени — только если база знает его
                # частой фамилией («anna.holland.studio»); иначе это
                # название: «nora|speed|and|engineering».
                _, last = self._ranks(fold(part))
                if last is None or last > self.SOLID_RANK:
                    return False
                names.append((part, "surname"))
            elif kind == "initial" and names:
                continue              # «mike|s|garage»: буква фамилии перед делом
            else:
                # Обломок или слово до имени либо посреди него:
                # «xq.llc.maria», «golden.peak.academy».
                return False
        if not names:
            return False
        lead, lead_kind = names[0]
        if lead_kind != "first":
            return False
        if self.strong_first(lead) and len(fold(lead)) >= 4:
            # Частое имя впереди — человек: «nina|marlowe|realty», даже если
            # фамилию база знает плохо. Трёхбуквенным доверия нет:
            # «sam|urai|realty» — это samurai, а не Sam.
            return True
        if not (self._solid_first(lead) or self.confident_first(lead)):
            return False
        return all(self._solid_piece(p, k) for p, k in names[1:])

    def prune_structural(self, kept):
        """Неподтверждённые куски слитной строки: что остаётся. [] — имени нет.

        Неподтверждённый кусок держится только рядом с подтверждённым именем
        от четырёх букв, сам не короче пяти и не длиннее десяти:
        «rogbin|anatol». «rogb|ina» — нет: короткий обломок рядом с
        трёхбуквенным именем ничего не доказывает.
        """
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
                        # «anna|h|ereget»: с хвостом соседа кусок даёт
                        # «hereget», то есть слово фразы, — это обломок
                        # фразы, а не фамилия.
                        or any(word in joined for word in _PHRASE_INSIDE)):
                    if not any(k == "first" for _, k in pruned):
                        # Отброшен кусок ПЕРЕД именем: имя начиналось бы
                        # с середины строки — «trav|anita» -> «Anita»,
                        # «bzlo|mason» -> «Mason». Это не имя.
                        return []
                    continue
            pruned.append((part, kind))
        # Четыре и больше кусков в слитной строке — строку раздробило на
        # короткие имена («tim|sai|chen|nam»). Это не имя, а гадание.
        if len([entry for entry in pruned if entry[1] != "initial"]) > MAX_NAME_TOKENS:
            return []
        return pruned

    # ── слово-занятие в хвосте ──────────────────────────────────────────

    def drop_tail_role(self, items):
        """Снять с конца слово-занятие, которое бывает и именем: Art, Dev, Law.

        «anna.lopez.art», «ravi|kumar|dev»: после имени такое слово — род
        занятий, а не третье имя. В общий перечень ролей его положить нельзя:
        Art и Dev — имена, и «dev.patel» обязан остаться. Поэтому судит
        место: только последний кусок и только если перед ним уже стоит имя
        или фамилия. Возвращает (куски, снято ли).
        """
        dropped = False
        while (len(items) >= 2 and fold(items[-1][0]).strip(".'-") in _TAIL_ROLE_WORDS
               and any(k in ("first", "surname", "structural") for _, k in items[:-1])):
            items = items[:-1]
            dropped = True
        return items, dropped

    def tail_is_role(self, token):
        """Последний кусок имени — слово-занятие или неизвестный кусок с ним на конце."""
        t = fold(token)
        if t in _TAIL_ROLE_WORDS:
            return True
        if self.first_ok(t) or self.surname_ok(t):
            return False
        return any(len(word) >= 3 and t.endswith(word) and len(t) > len(word)
                   for word in _TAIL_ROLE_WORDS)

    def odd_onset(self, token):
        """Слово начинается с пары согласных, с которой слова не начинаются.

        «gshukla», «jsmith», «kzoltan» — буква и слово, а не одно слово.
        «dorlov», «zelma» начинаются с согласной и гласной, как любое слово,
        и по одному звучанию их не разрежешь.
        """
        t = fold(token)
        if len(t) < 3 or t[0] in _VOWELS or t[1] in _VOWELS:
            return False
        return t[:2] not in _WORD_ONSETS

    def tail_role_cut(self, letters):
        """Слитная строка без слова-занятия в хвосте или "" — резать нечего.

        «annalopezart», «annasmithdev»: разбор видит в хвосте имя («Dev») или
        не видит ничего и берёт строку одним неизвестным куском. Здесь хвост
        только предлагается снять; принять ли вариант, решает вызывающий —
        «robertstewart» кончается на «art», но Stewart — фамилия.
        """
        s = letters_only(letters)
        if not is_latin(s):
            return ""
        for word in sorted(_TAIL_ROLE_WORDS, key=len, reverse=True):
            # Двухбуквенные приписки («jr», «md») в слитной строке не режутся:
            # на них кончается слишком много настоящих фамилий.
            if len(word) >= 3 and s.endswith(word) and len(s) - len(word) >= 5:
                return s[:-len(word)]
        return ""

    # ── раздробленный остаток ───────────────────────────────────────────

    # Фамилия или имя «на месте»: не дальше этого места в базе. Кусок слабее
    # в разборе слитной строки сам по себе ничего не доказывает.
    SOLID_RANK = 1000
    # Буква с фамилией вместе — одно слово, только если база знает его не
    # более чем в столько раз хуже самой фамилии: «m|callan» — Mcallan,
    # а «j|smith» — буква и Smith, хотя «Jsmith» в базе тоже есть (13245-е
    # место при первом у Smith).
    JOINED_RATIO = 20

    def _solid_first(self, piece):
        """Имя, на которое можно опереться в начале строки."""
        t = fold(piece)
        if not self.is_anchor(t):
            return False
        rank = self.first_rank(t)
        if len(t) == 3:
            return self.strong_first(t)
        return rank is not None and rank <= self.SOLID_RANK

    def _solid_piece(self, piece, kind):
        """Кусок, который разбор нашёл не случайно: частое имя или частая фамилия."""
        t = fold(piece)
        if len(t) < 3 or kind in ("initial", "word", "junk", "", "weak"):
            return False
        if self.strong_first(t):
            return True
        _, last = self._ranks(t)
        return len(t) >= 4 and self.surname_ok(t) and last is not None and last <= self.SOLID_RANK

    def _whole_surname(self, whole, lead):
        """Остаток строки целиком годится в фамилию: класс куска или None.

        Известная базе фамилия — годится. Неизвестная — только произносимая,
        не слово и не склейка слов, и только после имени от четырёх букв:
        «tomas|varelli», «elena|corvetti». «lovesdogs», «bikerepair» —
        склейки слов, «mrolan», «tkarlsson» начинаются так, как слова не
        начинаются.
        """
        t = fold(whole)
        if not (4 <= len(t) <= MAX_STRUCTURAL) or self.odd_onset(t):
            return None
        if t in self.english_words:
            return None
        if self.surname_ok(t):
            return "surname"
        # База знает слово именем («birdie»): проверка «склейка слов» по нему
        # не судит — она нашла бы «bird» и хвост из двух букв.
        known = self.first_rank(t) is not None
        if not known and (self._compound_of_words(t) or self._reads_as_words(t)
                          or self._word_glued(t)):
            return None
        # Слово сети, которого нет в словаре: «mike|b|iker» — это biker,
        # «nina|lunatic» — lunatic, а не фамилии.
        if not known and self._word_counts.get(t, 0) >= PLAIN_WORD_COUNT:
            return None
        if len(fold(lead)) >= 4 and (known or self.structural_ok(t)):
            return "structural"
        return None

    def _word_glued(self, token):
        """Неизвестный кусок кончается обычным словом или начинается словом фразы.

        На полной базе 13.11.2026 склейка остатка отдавала «фамилии» с
        приклеенным словом: «…stonegolf» (golf), «…marloelement» (element),
        «andmaria» (and). В хвосте слово — от четырёх букв из словаря или
        частое в корпусе; в начале — только слово фразы от трёх букв («and»,
        «the»): с обычных слов начинается слишком много настоящих фамилий
        (Landgraf, Woodrow). От куска при этом должно оставаться хотя бы две
        буквы.
        """
        t = fold(token)

        def phrase(piece):
            return len(piece) >= 3 and piece in _PHRASE_WORDS

        def word(piece):
            if len(piece) < 4:
                return False
            if piece in self.english_words:
                return True
            # Частое в корпусе, но имя или фамилия («diaz», «lima», «shin») —
            # не слово: иначе «…|diaz» и «lima|…» хоронили бы фамилии.
            return (self._word_counts.get(piece, 0) >= PHRASE_WORD_COUNT
                    and not self.surname_ok(piece) and not self.first_ok(piece))

        return any(phrase(t[:k]) or word(t[-k:]) for k in range(3, len(t) - 1))

    def _reads_as_words(self, token):
        """Строка читается английскими словами от четырёх букв каждое.

        Строже english_compound (там слова от трёх букв): трёхбуквенных слов
        корпус знает слишком много, и «lima|rok» хоронило бы фамилию Limarok.
        """
        cuts = self.english_reading(token)
        if not cuts:
            return False
        bounds = [0] + sorted(cuts) + [len(token)]
        return all(b - a >= 4 for a, b in zip(bounds, bounds[1:]))

    def keeps_boundary(self, head, tail, tail_kind):
        """Граница «имя | фамилия» верна, хотя имя с началом фамилии — тоже имя.

        Короткое имя, к которому начало фамилии дописывает другое частое имя
        (Bob + «o…» = Bobo), проверка оборванного имени читала как обрывок
        и хоронила строку целиком — хотя остаток после «Bobo» база не знает,
        а фамилию после «Bob» знает. Другое прочтение принимается, только
        если и его остаток — имя, фамилия или одна буква: «harsh|abhati» —
        Harsha Bhati.
        """
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
        """Слово сразу за буквой — фамилия, хотя индекс знает его и именем.

        «k|boyd», «t|archer»: Boyd и Archer — имена в индексе, но фамилией
        каждое намного чаще (280-е и 313-е места против 1254-го и 970-го).
        Запись «И. Фамилия» терялась целиком (замер 13.11.2026). Частое имя
        («k|zoltan», «s|priya») сюда не подпадает.
        """
        t = fold(token)
        first, last = self._ranks(t)
        return (not self.strong_first(t) and last is not None and last <= 500
                and (first is None or last < first) and self.surname_ok(t))

    def merge_oversplit(self, pieces):
        """Склеить остаток, который разбор раздробил на слабые куски.

        Разбор слитной строки платит за каждый известный базе кусок, а база
        знает почти любое короткое буквосочетание. Редкую фамилию, которой в
        ней нет, он поэтому дробит: «elena|cor|etti», «emma|birdi|e» — и
        дальше проверка либо отдаёт «Elena Cor Etti», либо хоронит имя (замер
        на настоящих базах 13.11.2026: самая частая причина и неверных, и
        потерянных имён).

        Правило: если строка начинается с надёжного имени, а всё после него
        раздроблено и среди осколков есть слабый, остаток берётся целиком —
        когда он целиком годится в фамилию. Настоящее «имя + имя + фамилия»
        из частых кусков («john|paul|smith») не трогается: слабых осколков
        там нет. Средний инициал перед частой фамилией («amy|k|walker»)
        остаётся инициалом, пока база не знает слово с буквой заметно лучше.
        """
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
            """«буква + частая фамилия» после имени — настоящий средний инициал."""
            if len(run) != 2 or run[0][1] != "initial" or not self._solid_piece(*run[1]):
                return False
            first, last = self._ranks(fold(run[0][0]) + fold(run[1][0]))
            own_first, own_last = self._ranks(fold(run[1][0]))
            own = min(r for r in (own_first, own_last, 10 ** 9) if r is not None)
            joined = min(r for r in (first, last, 10 ** 9) if r is not None)
            return joined > self.JOINED_RATIO * own

        lead, lead_kind = span[0]
        # Опора в начале: частое имя, а от пяти букв — любое подтверждённое.
        if self._solid_first(lead) or (len(fold(lead)) >= 5 and self.is_anchor(lead)):
            run = span[1:]
            whole = "".join(fold(p) for p, _ in run)
            # Имя могло оборваться раньше времени: «harsh|a|bhati» — это
            # Harsha Bhati. Если имя с началом остатка — тоже имя, а то, что
            # после него, база знает, склейка уступает этому прочтению.
            longer = any(self.is_anchor(fold(lead) + whole[:k]) and (
                self.surname_ok(whole[k:]) or self.first_ok(whole[k:]))
                for k in range(1, min(3, len(whole) - 2) + 1))
            name_end = longer or self._longer_name(lead, whole) or (
                run[0][1] == "initial" and fold(run[0][0]) in _VOWELS
                and self.first_rank(fold(lead) + fold(run[0][0])) is not None)
            # Обрывок после известного куска. Одна буква («hartley|t», «jean|c»)
            # к нему не клеится: её разбирает обычная проверка хвоста. Две-три
            # буквы снимаются только с очень частого куска от пяти букв
            # («norris|ka»); у остальных это конец редкой фамилии. Исключение
            # — слово, которое база знает целиком не хуже, чем кусок без
            # обрывка («birdi|e» — Birdie).
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
            # Очень частое второе имя и известная фамилия («mary|ellen|tasker»)
            # — не осколки, хотя фамилию база ставит далеко. Редкое второе имя
            # («anna|hille|brand») сюда не подпадает: это Hillebrand.
            if len(run) == 2 and (self.first_rank(run[0][0]) or 10 ** 9) <= 100 \
                    and self.strong_first(run[0][0]) and len(fold(run[1][0])) >= 5 \
                    and self.surname_ok(run[1][0]) and (self._ranks(fold(run[1][0]))[1] or 10 ** 9) <= 5000:
                return pieces
            # Обрывок в одну-две буквы ПЕРЕД очень частой длинной фамилией
            # («rahul|ya|agarwal», «paul|dr|muller») к ней не клеится, если
            # база не знает слово целиком. Правило узкое намеренно: в широком
            # виде оно хоронило настоящие фамилии вида «буква + фамилия»
            # («v|alnoir» — Valnoir).
            tail_piece, tail_kind = run[-1]
            if (tail_kind == "surname" and len(fold(tail_piece)) >= 6 and joined == 10 ** 9
                    and (self._ranks(fold(tail_piece))[1] or 10 ** 9) <= 200
                    and 0 < sum(len(fold(p)) for p, _ in run[:-1]) <= 2):
                return pieces
            if weak(run) and not middle_initial(run) and not name_end:
                kind = self._whole_surname(whole, lead)
                if kind:
                    return items[:start] + [(lead, lead_kind), (whole, kind)] + items[end:]
            return pieces         # имя в начале надёжное — с хвоста не клеим
        letters = "".join(fold(p) for p, _ in span)
        for k in range(min(len(letters) - 4, MAX_TOKEN_LEN), 2, -1):
            # Разбор начал с фамилии, а строка начинается с частого имени, и
            # всё после него — известная базе фамилия.
            head, rest = letters[:k], letters[k:]
            if self._solid_first(head) and self.strong_first(head) and self.surname_ok(rest) \
                    and self._whole_surname(rest, head) == "surname":
                return items[:start] + [(head, "first"), (rest, "surname")] + items[end:]
        last, last_kind = span[-1]
        if self._solid_piece(last, last_kind) and len(fold(last)) >= 4:
            run = span[:-1]
            whole = "".join(fold(p) for p, _ in run)
            if len(whole) >= 5 and self.rare_first(whole) and whole not in self.english_words:
                # «magno|lia|ferreira»: база знает Magnolia именем целиком.
                return items[:start] + [(whole, "structural"), (last, last_kind)] + items[end:]
            # Неизвестное базе слово впереди надёжного куска так не клеится:
            # на полной базе 13.11.2026 тем же путём шли и редкие имена, и
            # осколки названий, и отличить одно от другого было нечем.
        return pieces
