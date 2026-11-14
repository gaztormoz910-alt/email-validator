# -*- coding: utf-8 -*-
"""Годится ли строка, чтобы обратиться по ней к человеку в письме.

ЗАЧЕМ ОТДЕЛЬНЫЙ МОДУЛЬ. Разбор имени брал первое, что попадалось: ник из
профиля Gravatar (буквы с цифрами, прозвище одним словом), название фирмы,
спам, обломки английского сегментатора (имя с приклеенным хвостом
согласных), инициал на месте имени («K Anita» вместо Anita). Замерено
06.11.2026 на прогоне владельца (531 адрес с обогащением, режим
«Точность»): из 288 имён плохими оказались 63. Каждое такое имя уходит в
обращение письма — «Здравствуйте, K» хуже, чем пустая колонка.

Примеры в комментариях выдуманы: адресов владельца в коде нет.

Правило одно на все источники: кусок имени должен быть ПОДТВЕРЖДЁН. Имя —
индексом популярных имён (43 тыс.) или первой полсотней базы имён, фамилия —
базой фамилий, а то, что ни тем ни другим не подтверждается, в имя не
попадает или попадает только рядом с подтверждённым именем. Пустота честнее
догадки: владелец просил «нормальные осмысленные имена», а не «что попалось».

Знание о мире (индекс, база, словари) приходит снаружи, в конструктор: так
правила проверяются тестами на подставных словарях, без базы на 138 млн
записей, которая грузится восемь секунд.
"""
import re

from .name_words import (  # noqa: F401 — часть имён нужна тем, кто импортирует отсюда
    BUSINESS_WORDS, ROLE_WORDS, WEB_WORDS, _CHINESE_NAME_COUNTRIES,
    _CHINESE_SHORT_SURNAMES, _DECORATION_LETTERS, _KEYBOARD_JUNK, _MONTHS,
    _PHRASE_INSIDE, _PHRASE_WORDS, _RARE_TAIL_LETTERS, _SPAM_PARTS, _TITLES, _VOWELS,
    _NICK_WORDS, _PLACEHOLDER_WORDS, _NOT_NAME_WORDS, _KNOWN_PHRASES,
    _EAST_ASIAN_SHORT_SURNAMES,
    fold, scripts_of, is_latin, has_vowel, letters_only, max_consonant_run,
    trailing_consonants, consistent_with_address, display_case)
from .name_words import MAX_TOKEN_LEN, MAX_SEGMENT_INPUT, PLAIN_WORD_COUNT  # noqa: F401
from .name_split import SplitMixin
from .name_evidence import (EvidenceMixin, PHRASE_WORD_COUNT, CONCAT_SURNAME_RANK,
                            CONCAT_FIRST_RANK, GENDERED_SHARE)


# Неподтверждённый кусок в слитной строке длиннее этого — уже не фамилия,
# которую не знает база, а хвост из нескольких слов («youwujiujiaosh»).
MAX_STRUCTURAL_FUSED = 10

# Сколько кусков разрешено в имени: «Lan Thi Tran» бывает, дальше —
# почти наверняка разваленная строка.
MAX_TOKENS = 3


# Подряд столько согласных в одном куске — обломок, приклеенный к имени
# («kumarbcdf»), а не фамилия. Пять, а не четыре: немецкие Mutschall,
# Pietsch, Hirschfeld пишутся с «tsch» и «schf».
MAX_CONSONANT_RUN = 5

# Пороги базы фамилий. Ранг — место фамилии в стране, где она чаще всего.
# Словарное английское слово годится в фамилию, только если оно очень частая
# фамилия (Smith, White, Wright) или известно базе и как имя, и как фамилия
# (Warner, Doe, Sang): «junk» и «sloth» база тоже знает фамилиями где-то в
# мире (467 и 162 место), но именем — нет. Порог стоял на 100 и отсекал
# Black (145-я): `laurablack` терялось целиком (замер 13.11.2026). Выше 150
# поднимать нельзя — следом идёт «sloth».
ENGLISH_SURNAME_TOP = 150
ENGLISH_SURNAME_NAMELIKE = 1000
SHORT_SURNAME_TOP = 1000           # трёхбуквенные: Doe, Cho, Lee, Das
NON_LATIN_TOP = 5000               # кириллица и прочие алфавиты: фамилии
# Имя другим алфавитом — только частое и с перекосом по полу: «Привет»
# (2567-е «имя»), «Мама» (701-е, 74/26), «Магазин» база тоже знает именами
# (рецензия 08.11.2026, J19). Иван, Мария, Ольга — в первой сотне и 99%.
NON_LATIN_FIRST_TOP = 1000



# Фамилия впереди имени слабее этого места — только перед частым именем:
# «galatas|aray» (4697-я фамилия, 1212-е имя) — обломки слова, а не имя.
LEADING_WEAK_SURNAME = 1000

# «Инициал + фамилия» в слитной строке (`jsmith`, `pgupta`) — только с
# фамилией, которую база знает не дальше этого места.
INITIAL_SURNAME_TOP = 5000

# «Частое» имя: инициал перед ним снимается («k|zoltan» -> Zoltan), короткий
# обломок после него тоже («paul|zx» -> Paul). У редкого имени лишняя буква
# может оказаться его же частью: `beatrix` — это Beatrix, а не «Beatri».
STRONG_FIRST_RANK = 500

# Ранг, до которого слово базы считается именем для резки слитного куска
# между разделителями («markjones.jones»).
SPLIT_FIRST_RANK = 2000

# ── цена кусков при разборе слитной строки ─────────────────────────────
# Счёт = сумма по кускам (буквы × вес − плата за кусок). Плата за кусок
# делает дробление невыгодным: «vasilisa» одним именем дороже, чем
# «vasi»+«lisa», и строку не режет на трёхбуквенные имена, которых в
# индексе тысячи («nam», «gal», «man» — настоящие имена где-то в мире).
# Вес имени зависит от его ранга: частое имя выигрывает у редкого той же
# длины. Подобрано на синтетических адресах и проверено на отложенной
# выборке (другое зерно, имена с 41-го по 100-е место) —
# .unlazy/enrich-stop/name_bench.py.
PIECE_COST = 3.5
INITIAL_COST = 1.5
FIRST_WEIGHT = ((300, 1.4), (2000, 1.1))       # иначе FIRST_WEIGHT_LOW
FIRST_WEIGHT_LOW = 0.8
SURNAME_WEIGHT = ((500, 1.2), (5000, 0.9))     # иначе SURNAME_WEIGHT_LOW
SURNAME_WEIGHT_LOW = 0.6
# Длинная известная фамилия не должна проигрывать своим обломкам:
# «hammermeister» дороже, чем «hammer»+«meister».
LONG_SURNAME_LEN = 8
LONG_SURNAME_WEIGHT = 0.95
SHORT_FIRST_FACTOR = 0.85                      # трёхбуквенное имя
SHORT_SURNAME_FACTOR = 0.5                     # трёхбуквенная фамилия
TWO_LETTER_FIRST = 0.8                         # «bo», «li»: за букву
STRUCTURAL_WEIGHT = 0.35
PHRASE_WEIGHT = 0.9
ROLE_WEIGHT = 1.0
# Английское слово весит как фамилия: иначе имя, спрятанное внутри слова,
# перевешивало само слово — «g|lance|objects» вместо «glance|objects».
ENGLISH_WEIGHT = 1.0
# Обломок дешёвый: «angela|jj» должно быть выгоднее, чем «angel|ajj».
JUNK_WEIGHT = -0.3
JUNK_COST = 2.0

# Имя, которого нет в индексе популярных имён, но база знает его в первой
# полсотне имён страны: «mohammed», «muhammad», «ahmed» в индекс не попали,
# хотя в базе стоят на 2-м месте. Без этого «Точность» теряла самые частые
# имена мира. Порог строгий: на сотнях мест база знает и «jam», и «ras».
DATASET_FIRST_TOP = 50
# От пяти букв порог шире: обломков такой длины с хорошим рангом имени база
# почти не знает, а настоящих имён вне индекса — тысячи (Fransisca — 127-е
# место Индонезии). Строку ЦЕЛИКОМ судит WHOLE_FIRST_RANK: Damilola (201-е
# в Нигерии) и Funmilayo (205-е) сюда не проходят, и без того правила разбор
# отдавал «Dami Lola» (рецензия 07.11.2026).
DATASET_FIRST_TOP_LONG = 200

# Имя «усечено», если вместе со следующими одной-тремя буквами строки оно
# само оказывается именем базы не дальше этого места: «jeri|c» — это Jeric,
# «susan|to» — Susanto, «vibha|v» — Vibhav. Обращение «Susan» к человеку
# по имени Susanto — неверное, а это хуже пустой колонки.
TRUNCATION_FIRST_RANK = 300
# Фамилия «усечена» тем же способом: «arun|ranjan|e» — это Ranjane. База
# фамилий знает больше, поэтому порог шире, но проверяется только последний
# кусок имени перед хвостовой буквой.
TRUNCATION_SURNAME_RANK = 20000

# Частая английская фамилия, которая одновременно слово (Park, Smith,
# White), может стоять первой в слитной строке; редкая («bear» — 443-я)
# — нет: «bearlee» — это не Bear Lee.
LEADING_WORD_SURNAME_TOP = 100

# Имя из индекса, которое одновременно английское слово и как имя слабое
# (хуже 1000-го места), в слитной строке — слово: «able» (1660-е),
# «master» (1344-е). Mark, Will, Rose, Grace — в перечне имён-слов и сильные.
WORDLIKE_FIRST_RANK = 1000

# «Склонное к фамилии» имя: слабое как имя (хуже 500-го места) и при этом
# чаще встречается фамилией — Kowalska (1998 имя / 3 фамилия), Sharma
# (583 / 4). Kamal (32 / 19) и Kumar (12 / 1) — сильные имена, их это не
# касается: такие люди действительно носят их как имя.
LEANING_FIRST_RANK = 500
# И второе условие: фамилия из первой десятки, а имя — не в первой полсотне
# (Patel: 2-я фамилия базы, 6-я в Индии, а как имя — 89-е; иначе
# `patel4521` получал имя «Patel»).
LEANING_SURNAME_TOP = 10
LEANING_STRONG_FIRST = 50

# Трёхбуквенное имя внутри слитной строки — только частое (не хуже 600-го
# места): имена с дальних мест («nad» — 1027-е) резали ник на два
# трёхбуквенных обрывка. Ann, Joe, Max, Kim, Ali, Jun, Wei, Ava, Meg в эту
# границу укладываются (замерено).
SHORT_FIRST_MAX_RANK = 600

# Одно имя всей слитной строкой, слабее этого места, которое само
# складывается из частых английских слов, — слово, а не имя: «minecraft»
# (mine|craft; индекс зашумлён и знает его именем, 1436-е место базы,
# рецензия 08.11.2026). Sowmya (1609-е) английского прочтения не имеет и
# остаётся именем.
LONE_FIRST_RANK = 1000

# Имя-слово из словаря слабее этого места — прозвище, когда вокруг другие
# слова или титул: Nice (489-е), Rock (355-е), Wonder (395-е). Частые
# имена-слова (Sue — 51-е, Daisy — 156-е, Hope — 234-е) остаются именами.
NICK_FIRST_RANK = 300
NICK_GENDER_SHARE = 0.7

# Начало строки спорное, только если второе прочтение уступает лучшему не
# больше этого: «its|amy|hussain» против «it|samy|hussain» — 1,3 очка.
# «is|abel|le» против «isabelle» — девять с лишним: там спорить не о чем.
AMBIGUITY_MARGIN = 1.5


# Фамилия ВПЕРЕДИ имени в слитной строке («tanakahiroshi», «kowalskijan») —
# частая (не дальше этого места) или длинная (от LEADING_SURNAME_LEN букв и не
# дальше INITIAL_SURNAME_TOP): короткий обрывок вроде «haku» или «nama» база
# знает фамилией где-то в мире почти любой, а «mahapatra» или «lochmann» —
# нет, это настоящие фамилии.
LEADING_SURNAME_TOP = 500
# Шесть, а не пять букв: «mamac|ita» (2220-я «фамилия») давал «Mamac Ita»
# (рецензия 08.11.2026). Nagy, Kim, Silva впереди — частые, им длина не нужна.
LEADING_SURNAME_LEN = 6


# Сколько разборов помнить: одни и те же куски повторяются от адреса к
# адресу, а без памяти слитная строка в 20 букв стоила 50 мс (рецензия
# 07.11.2026). Переполнилась — забываем всё и копим заново.
_MEMO_LIMIT = 200000


class NameQuality(SplitMixin, EvidenceMixin):
    """Проверка кусков имени. Знание о мире приходит снаружи, правила — здесь.

    is_first(word)       — слово есть в индексе популярных имён;
    name_ranks(word)     — (лучший ранг как ИМЯ, лучший ранг как ФАМИЛИЯ) в
                           базе на 138 млн или (None, None);
    english_words        — английские словарные слова (имена в нём тоже есть,
                           поэтому индекс имён всегда решает раньше словаря);
    countries_for(word)  — страны, где имя популярно;
    english_surnames     — словарные слова, которые точно фамилии (Taylor,
                           Fisher): прежний перечень исключений разбора;
    word_counts          — частоты слов корпуса сегментатора (для «theorist»);
    leaning(word)        — имя склонно к фамилии в своей главной стране; без
                           него — по лучшим рангам (см. LEANING_FIRST_RANK).
    """

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
        # Память разборов. Словари в CPython меняются атомарно под GIL: два
        # потока в худшем случае посчитают один кусок дважды.
        self._options_memo = {}
        self._segment_memo = {}
        self._reading_memo = {}

    @staticmethod
    def _remember(memo, key, value):
        if len(memo) >= _MEMO_LIMIT:
            memo.clear()
        memo[key] = value
        return value

    # ── обращение к знаниям снаружи: сбой словаря не роняет адрес ─────────

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
        """Доля самого частого пола у слова как имени (0.5–1.0) или None."""
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

    # ── классы куска ────────────────────────────────────────────────────

    def is_business(self, token):
        return fold(token).strip(".'-") in BUSINESS_WORDS

    def _is_role(self, token):
        t = fold(token).strip(".'-")
        return t in BUSINESS_WORDS or t in ROLE_WORDS or t in WEB_WORDS

    def is_phrase(self, token):
        return fold(token).strip(".'-") in _PHRASE_WORDS

    def hard_junk(self, token):
        """Кусок, который не может стоять в имени ни при каком источнике."""
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
            return True           # «jj», «kk», «xxx»
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
        # Не латиница: индекс популярных имён латинский, решает база имён.
        first, _ = self._ranks(token)
        if first is None or first > NON_LATIN_FIRST_TOP:
            return False
        share = self._gender_share(token)
        return share is None or share >= GENDERED_SHARE

    def surname_leaning(self, token):
        """Имя, которое в своей главной стране чаще фамилия: Kowalska, Sharma.

        Индекс популярных имён собран из анкет, а в анкетах фамилию часто
        пишут в поле имени. Такое «имя» не должно перевешивать настоящее имя
        рядом и не делает строку именем само.
        """
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
        """Подтверждённое имя, по которому можно обратиться: «Kamal», «Naushad»."""
        t = fold(token)
        return len(t) >= 3 and self.first_ok(t, 3) and not self.surname_leaning(t)

    def _nicknamey(self, token):
        """Имя, по которому к человеку не обращаются: прозвище (King, Boss,
        Sky — _NICK_WORDS) или словарное слово, слабое как имя (см.
        NICK_FIRST_RANK)."""
        t = fold(token)
        if t in _NICK_WORDS:
            return True
        if t not in self.english_words:
            return False
        # Словарное слово без пола — слово, а не имя: «SweetHeart» давал
        # «Heart» (140-е «имя» базы, пол 56/44).
        share = self._gender_share(t)
        if share is not None and share < NICK_GENDER_SHARE:
            return True
        rank = self.first_rank(t)
        return rank is None or rank > NICK_FIRST_RANK

    def strong_first(self, token):
        """Частое имя (не дальше STRONG_FIRST_RANK): Lajos, Eric, Amy, Kiran."""
        if not self.is_anchor(token):
            return False
        rank = self.first_rank(token)
        return rank is not None and rank <= STRONG_FIRST_RANK

    def surname_ok(self, token):
        """Фамилия подтверждена базой фамилий.

        От четырёх букв любая известная базе фамилия; трёхбуквенная — только
        частая (Doe, Cho, Das). Словарное английское слово — по правилу
        ENGLISH_SURNAME_* выше: иначе «Rakesh Now», «Peter Ship» и «Sue Junk»
        проходят как имя с фамилией.
        """
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
            return False          # «neha|i|mhere»: это «im here», а не фамилия
        return True

    def wordlike_first(self, token):
        """Имя из индекса, которое на деле английское слово: «able», «master», «bean».

        Словарь на 9894 слова знает не всё, поэтому слово корпуса с
        частотой от PHRASE_WORD_COUNT тоже считается словом: «MrBean» давал
        «Bean» (рецензия 07.11.2026). Решает слабость имени: Rose, Grace,
        Mark — частые имена и остаются именами.
        """
        t = fold(token)
        if t in self.english_surnames:
            return False
        if t not in self.english_words:
            if self._word_counts.get(t, 0) < PHRASE_WORD_COUNT:
                return False
            # Слово корпуса, которое база знает фамилией, — фамилия, а не
            # слово: Medina (21-я фамилия) в адресе — человек, а не город.
            _, last = self._ranks(t)
            if last is not None and last <= WORDLIKE_FIRST_RANK:
                return False
        rank = self.first_rank(t)
        return rank is None or rank > WORDLIKE_FIRST_RANK

    def structural_ok(self, token, fused=True):
        """Кусок похож на фамилию, хотя база его не знает: «rogbin», «quorvel».

        Сам по себе такой кусок ничего не доказывает, поэтому он идёт в имя
        только рядом с подтверждённым именем или там, где границы поставил
        сам человек. Словарные слова, склейки из слов («freeform») и
        обломки с хвостом согласных («kumarbcdf», «ovtk») сюда не проходят.
        fused=False — кусок между разделителями: его границы поставил
        человек, и хвост из согласных у него законен — немецкие Kolbusch,
        Fritsch, Brandt (правило хвоста ловит обломки слитной строки).
        """
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
            return False          # «ujkr», «rogb»: хвост согласных — обломок
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
        """Строка целиком — одно английское слово, а не имя: «theorist», «writer».

        Словарь на 9894 слова знает не всё, поэтому спрашивается и корпус
        сегментатора (333 тыс. слов с частотами). Имя из индекса и частая
        фамилия словом не считаются: «smith» в корпусе тоже есть.
        """
        s = letters_only(letters)
        if len(s) < 4 or self._is_first(s):
            return False
        if s in self.english_words:
            return not self.surname_ok(s)
        if len(s) >= 5 and self.surname_ok(s[1:]):
            # «jsmith», «mjones» — частые строки корпуса (примеры в
            # документации), но это буква и частая фамилия, а не слово
            # (рецензия 08.11.2026, RN-2).
            _, rest = self._ranks(s[1:])
            if rest is not None and rest <= 500:
                return False
        count = self._word_counts.get(s)
        if count is None or count < PLAIN_WORD_COUNT:
            return False
        first, last = self._ranks(s)
        if first is not None and first <= 5000 and (self._gender_share(s) or 0) >= 0.9:
            return False          # слово сети, но база знает его частым именем с ясным полом
        return last is None or last > 3000

    def kind_of(self, token, from_separators):
        """'initial' | 'first' | 'surname' | 'structural' | 'word' | '' (мусор)."""
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
            # «guy.cruz»: между разделителями частое имя с ясным полом — имя.
            return "first" if from_separators and self._phrase_name(t) else "word"
        if self.first_ok(t, min_len=2 if from_separators else 3):
            if len(t) >= 3 and self.surname_leaning(t) and self.surname_ok(t):
                return "surname"      # «j.sharma» — это J Sharma, а не Sharma
            return "first"
        if self.is_plain_word(t):
            # Частое слово сети, которое база фамилией почти не знает, —
            # слово, а не фамилия: «cust.serv», «granite.analytics» давали
            # «Cust Serv» и «Granite Analytics» (замер 12.11.2026).
            return "word"
        if self.surname_ok(t):
            return "surname"
        if self.structural_ok(t, fused=not from_separators):
            return "structural"
        if t in self.english_words:
            return "word"
        return ""

    # ── слитная строка ──────────────────────────────────────────────────

    @staticmethod
    def _tier(rank, table, low):
        if rank is None:
            return low
        for limit, weight in table:
            if rank <= limit:
                return weight
        return low

    def _options(self, piece):
        """Чем может быть кусок слитной строки и сколько это стоит (см. PIECE_COST)."""
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
            # «mrjorgegarcia», «drmeenakumar»: титул снимается, как слово фразы.
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
                # Словарное слово, которое база признаёт фамилией (Doe,
                # Smith, Warner), словом не считается: иначе «janedoe»
                # терял бы фамилию.
                out.append(("word", ENGLISH_WEIGHT * n - PIECE_COST))
            if self.structural_ok(piece):
                out.append(("structural", STRUCTURAL_WEIGHT * n - PIECE_COST))
        out.append(("junk", JUNK_WEIGHT * n - JUNK_COST))
        return out

    def segment(self, letters):
        """Лучший разбор слитной строки: [(кусок, класс)]. См. segment_scored."""
        return self.segment_scored(letters)[1]

    def segment_scored(self, letters):
        """Лучший разбор слитной строки на имена, фамилии, инициалы и мусор.

        Английский сегментатор знает английские слова, а не имена, и резал
        слитное имя там, где кончается английское слово, а не имя. Здесь
        куски ищутся по индексу имён и базе фамилий, словарные слова
        распознаются как слова (и в имя не идут), а обломки без опоры стоят
        штрафа. Два инициала подряд не допускаются: «dlp» в `ravikumarsdlp` —
        обломок, а не три инициала. Возвращает (счёт, [(кусок, класс)]).
        """
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
            # Индекс и словарь латинские — резать кириллицу нечем. Целиком.
            return 0.0, [(s, self.kind_of(s, False))]
        # best[позиция][последний кусок — инициал?] = (счёт, куски)
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
        """Начало строки читается двумя способами, и имена выходят разные.

        `itsamyhussain` — «its|amy» (Amy) или «it|samy» (Samy); `mrannesimon`
        — «mr|anne» или «m|ranne». Разбор выбирает по очкам, но границу знает
        только сам человек. Сравниваются два прочтения: лучшее вообще и
        лучшее, которое начинается со слова фразы или титула. Если оба дают
        имя, имена разные и по очкам почти равны — это гадание, и честнее пусто.
        """
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
            # «m|ramos» — инициал и частая фамилия — против «mr|amos»: запись
            # «И. Фамилия» в адресе обычна, «титул + имя» — редкий ник
            # (рецензия 08.11.2026, RN-2).
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
                continue          # второе прочтение заметно хуже — оно не соперник
            forced = [(lead, "word")] + rest
            forced_name = self.finalize([p for p, _ in forced], False,
                                        [k for _, k in forced])
            if forced_name and fold(best_name[0]) != fold(forced_name[0]):
                return True
        return False

    def anchor_fallback(self, letters):
        """Лучший разбор имени не дал, но строка начинается с частого имени.

        Разбору бывает выгоднее прочесть строку одним неизвестным куском или
        фамилией с приставшей буквой, хотя впереди стоит частое имя, а за ним
        — фамилия, которую база знает плохо. Пробуются строки, которые
        НАЧИНАЮТСЯ с подтверждённого имени от четырёх букв, — от длинного к
        короткому, — и берётся первая, которую проходит обычная проверка.

        Не пробуется, если строка уже объяснена целиком — известной
        фамилией, словом, фамилиями подряд («gonzalez», «takahashi»,
        «arsenal»): имя в её начале — совпадение букв, и запасной разбор
        отдавал «Gonza», «Taka Hashi», «Arsen» (рецензия 07.11.2026). Свой
        разбор он тоже сверяет с английским прочтением (misaligned).
        """
        s = letters_only(letters)
        if not is_latin(s):
            # Чужой алфавит резать нечем (индекс и словарь латинские):
            # годится только «имя + фамилия целиком» — «иван|петров»;
            # «мага|зин» давал «Мага» (рецензия 08.11.2026, J19).
            for k in range(len(s) - 3, 2, -1):
                if self.is_anchor(s[:k]) and self.surname_ok(s[k:]):
                    return [s[:k], s[k:]]
            return []
        best = self.segment(s)
        if any(self.is_anchor(p) for p, k in best if k in ("first", "surname")):
            # Лучший разбор имя нашёл, а проверка его отвергла — значит, на
            # то была причина (имя с обломком). Обходить её запасным разбором
            # нельзя: он склеивал имя с обломком в новое «имя».
            return []
        if best and all(k in ("first", "surname", "word") for _, k in best):
            return []             # строка объяснена целиком — см. выше
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
                continue          # «arsen|al»: имя режет слово посередине
            name = self.finalize([p for p, _ in pieces], False, [kd for _, kd in pieces])
            if not name:
                continue
            if len(name) == 1 and (rank > STRONG_FIRST_RANK or head in self.english_words):
                continue          # «able|wood» -> «Able»: одно слабое имя — не имя
            return name
        return []

    def _longer_name(self, head, tail, surname=False):
        """Имя вместе с началом следующего куска — тоже частое имя: «jeri»+«c» = Jeric.

        Только частое (TRUNCATION_FIRST_RANK): база знает и «Ericz», и
        «Alexs» где-то на дальних местах, и без порога «Eric» и «Alex»
        считались бы оборванными. surname=True — то же для последнего куска
        как фамилии: «ranjan»+«e» = Ranjane.
        """
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
        """Где в слитной строке имя оборвано: индекс оборванного куска или None.

        Проверяется имя, за которым стоит НЕподтверждённый кусок (инициал,
        обломок, слово, неизвестная фамилия, короткое имя): «john|smith» не
        проверяется — фамилия Smith сама подтверждает границу. Инициал перед
        именем проверяется так же: «h|otman» — это Hotman, если база знает
        такое частое имя.
        """
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
                # Гласная сразу после имени, и дальше имени нет, — его же
                # конец, если база такое имя знает и оно не в двадцать раз
                # реже самого имени: «kiran|a» — Kirana (797-е место). База
                # знает и опечатки анкет («Jessicaa» — 5698-е при Jessica в
                # первой полусотне), а «hatice|a», «maria|o» не знает вовсе —
                # там имя и буква фамилии, и прежде имя терялось (перемер
                # инструментом рецензии, 12.11.2026). Если за гласной фамилия
                # («mark|e|jones»), это средний инициал — правило ниже.
                # Буква с хвостом после неё («mira|e|www») — по-прежнему
                # конец имени: там за ней не фамилия, а обломок.
                longer, longer_last = self._ranks(fold(part) + fold(nxt))
                own = self.first_rank(part)
                if (index + 2 < len(items)
                        or (longer is not None and (own is None or longer <= 20 * own))
                        or (longer_last is not None and longer_last <= INITIAL_SURNAME_TOP)):
                    return index
            if nkind == "initial":
                # Одна буква после куска — может быть его же концом. Фамилия:
                # «ranjan|e» — это Ranjane. Имя: «vibha|v», «alek|h» — это
                # Vibhav и Alekh; редкое имя проверяется относительно своего
                # же места, чтобы «john|e» не стал «Johne» (Johne в базе есть,
                # но в тысячи раз реже John). Многобуквенный обломок после
                # фамилии («kumar|bcdf») так не проверяется: база знает и
                # «Kumars», а обломок здесь явно отдельный.
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

    # ── итоговое решение по набору кусков ─────────────────────────────────

    def _fused_lead_ok(self, items):
        """Начало слитной строки: имя с первой буквы или после слова фразы.

        Человек пишет имя с начала адреса: `johnsmith`, `iammarkjones`,
        `mrjorgegarcia`. Если перед именем стоит английское слово
        («mycarstore», «hondachu», «controlpanelking») или обрубок
        («zvanatol»), строка — не имя, а имя в ней — совпадение.
        Инициал впереди годится только перед частым именем («k|zoltan») или
        фамилией («j|smith»): перед редким он может оказаться его же буквой
        («d|elwin» — это Delwin). Двухбуквенный кусок впереди — только как
        инициалы чужой культуры («du|rajesh»).
        """
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
                # Инициал узнаётся по звучанию: «k|zoltan», «s|priya» — так
                # слово не начинается, это буква имени отдельно. «a|maral»,
                # «e|steve» читаются одним словом (Amaral, Esteve — фамилии),
                # и разделять их — гадание. Согласная перед гласной —
                # одно слово, если база его знает: «h|otman» (Hotman),
                # «j|anita» (Janita), «d|amir» (Damir); «d|allen» база
                # не знает, и это инициал (рецензия 08.11.2026, RN-2).
                if vowel_letter == vowel_next:
                    return True
                return not vowel_letter and not self.joined_known(part, nxt[0])
            if nxt[1] == "surname":
                # «o|brien», «a|costa»: гласная перед согласной — слитное
                # прочтение (O'Brien, Acosta), если база такое слово знает;
                # «a|nguyen», «e|balogh» — инициал (см. joined_known).
                # «j|smith», «p|gupta» — инициал.
                return not (vowel_letter and not vowel_next
                            and self.joined_known(part, nxt[0]))
            return False
        # Двухбуквенный кусок впереди слитной строки («ka|vitha», «mo|nica»)
        # — часть имени, которое индекс не знает, а не инициалы: пусто.
        return False

    def finalize(self, parts, from_separators, kinds=None):
        """Чистит набор кусков и решает, годится ли он как имя. Возвращает список.

        from_separators — границы поставил человек (точка, подчёркивание,
        CamelCase, анкета профиля). Их не переразбиваем, но мусорные куски
        всё равно убираем: «rakesh.now» — это не «Rakesh Now».
        kinds — классы от разбора слитной строки; без них считаются здесь.
        """
        items = []
        titled = False
        for index, part in enumerate(parts or []):
            if not isinstance(part, str) or not part.strip():
                continue
            kind = kinds[index] if kinds else self.kind_of(part, from_separators)
            if fold(part).strip(".'-") in _TITLES:
                if from_separators:
                    titled = True
                    continue          # «rechtsanwalt-meier» — титул не имя
                kind = "word"         # в слитной строке титул — как слово фразы
            items.append((part, "" if kind == "junk" else kind))
        items, titled_tail = self.drop_tail_role(items)
        titled = titled or titled_tail
        if not items:
            return []
        # Заглушка программиста — пример или тест, а не человек: «foo.bar»
        # давал «Foo Bar» (рецензия 08.11.2026).
        if any(fold(p).strip(".'-") in _PLACEHOLDER_WORDS for p, _ in items):
            return []
        # Ласковые слова и лозунги других языков («zayka», «inshallah») и
        # известные фразы, герои, марки («Snow White», «King Kong») — не
        # имя, как бы их ни резал разбор (рецензия 08.11.2026).
        if any(fold(p).strip(".'-") in _NOT_NAME_WORDS for p, _ in items):
            return []
        squashed = [letters_only(fold(p)) for p, _ in items]
        for i in range(len(squashed)):
            for j in range(i + 2, len(squashed) + 1):
                if "".join(squashed[i:j]) in _KNOWN_PHRASES:
                    return []
        # Было ли вокруг имени что-то ещё — титул, слово, снятый кусок:
        # «SilverSurfer» — «surfer» словарь не знает и снимает молча.
        had_words = titled or len(items) > 1

        # «augnov», «jan.feb»: два месяца подряд — дата, а не имя.
        if sum(1 for p, _ in items if fold(p) in _MONTHS) >= 2:
            return []

        name_kinds = ("first", "surname", "structural")
        business = any(self.is_business(p) for p, _ in items)

        if from_separators:
            items = self._short_surnames(items)
            # «a.b.ce.d.fgh2», «m.n.o.vai»: россыпь букв с коротким куском
            # посередине — не имя. «natalia.s.k.o» — имя: оно впереди.
            loose = sum(1 for p, k in items if k in ("initial", "") or len(fold(p)) <= 2)
            if loose >= 3 and not (items[0][1] == "first" and len(fold(items[0][0])) >= 4):
                return []
            # Имя-слово из словаря («master», «bean») между разделителями —
            # слово, как и в слитной строке: «web.master», «MrBean».
            items = [(p, "word" if k == "first" and len(fold(p)) >= 3
                      and self.wordlike_first(p) else k) for p, k in items]
            # Английское слово ВПЕРЕДИ слабого имени или прозвища — прозвище
            # или название, а не человек: «IronMan», «BigBoss», «blue.sky»
            # отдавали «Man», «Boss», «Sky» (рецензия 07.11.2026). Перед
            # частым настоящим именем слово — род занятий или приставка:
            # «engineer.priya» — это Priya, «engineer.john» — John (словарь
            # знает и «john», поэтому судит не словарь, а _nicknamey). Слова
            # фраз, титулы и служебные слова впереди снимаются, как и раньше
            # («the.john», «sales.john»).
            lead_at = next((i for i, (p, k) in enumerate(items) if k not in ("", "weak") and not (
                k == "word" and (self.is_phrase(p) or self._is_role(p)
                                 or fold(p) in _TITLES))), None)
            if lead_at is not None and items[lead_at][1] == "word":
                after = next(((p, k) for p, k in items[lead_at + 1:]
                              if k in ("first", "surname", "structural")), None)
                if after is None or not (after[1] == "first" and self.strong_first(after[0])
                                         and not self._nicknamey(after[0])):
                    return []
            # Титул и одно слабое имя или прозвище — ник: «MrBean» (Bean —
            # 974-е имя), «mr.nice». «mr.john», «DrRaj» — частые имена —
            # остаются.
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
                    # Двухбуквенное «имя» внутри слитной строки — почти всегда
                    # кусок чужого слова («rachael|da|koala»): в индексе есть и
                    # «da», и «ab», и «ya». Остаётся оно только китайской
                    # фамилией рядом с китайским именем («liwei», «xujing»).
                    near = [items[j][0] for j in (index - 1, index + 1)
                            if 0 <= j < len(items) and items[j][1] == "first"
                            and len(fold(items[j][0])) >= 3]
                    chinese = (fold(part) in _CHINESE_SHORT_SURNAMES and any(
                        self._countries(fold(p)) & _CHINESE_NAME_COUNTRIES for p in near))
                    # Двухбуквенная фамилия Вьетнама, Китая, Кореи в конце
                    # строки сразу после имени: «hung|ly», «jing|li» (RN-7).
                    # Имя перед ней — китайское или из перечней Канады и
                    # Германии, где индекс держит вьетнамские имена (Hung,
                    # Linh, Minh — только CA и DE): «sarah|bi», «rahul|au» —
                    # обломки, а не фамилия (повтор прогона владельца).
                    prev_countries = (self._countries(fold(items[index - 1][0]))
                                      if index > 0 else set())
                    asian_name = (not prev_countries or bool(prev_countries & _CHINESE_NAME_COUNTRIES)
                                  or prev_countries <= {"CA", "DE"})
                    tail_surname = (fold(part) in _EAST_ASIAN_SHORT_SURNAMES
                                    and index == len(items) - 1 and index > 0
                                    and items[index - 1][1] == "first"
                                    and len(fold(items[index - 1][0])) >= 3 and asian_name)
                    # «linh|ho», «linh|do»: разбор пометил фамилию словом.
                    if tail_surname:
                        kind = "surname"
                    elif kind == "first":
                        kind = "first" if chinese else "weak"
                elif kind in ("first", "surname") and len(fold(part)) >= 3:
                    # Разбор метит кусок по очкам, а обращаться можно только
                    # к имени: Naushad, Kamal — имена, даже если база ставит
                    # их фамилией выше; Sharma и Kowalska — фамилии, даже если
                    # индекс знает их именем.
                    kind = "first" if self.is_anchor(part) else (
                        "surname" if self.surname_ok(part) else kind)
                    if kind == "first" and self.wordlike_first(part):
                        kind = "word"
                relabeled.append((part, kind))
            items = self.promote_rare_first(self._initial_context(relabeled))
            if not self._fused_lead_ok(items) or not self.lead_extra_ok(items):
                return []
            # Мнимый инициал: буква вместе со следующим куском — частое
            # слово, то есть она его начало, а не инициал: «g|randma|joan»
            # (grandma), «mike|b|iker» (biker) давали «Randma Joan», «Mike B
            # Iker» (рецензия 08.11.2026). У «m|patel», «d|ivanov» таких слов
            # нет, и запись «И. Фамилия» остаётся.
            for index in range(len(items) - 1):
                if items[index][1] == "initial":
                    joined = fold(items[index][0]) + fold(items[index + 1][0])
                    if self._word_counts.get(joined, 0) >= PHRASE_WORD_COUNT:
                        return []
            # Короткая слабая «фамилия» сразу за именем — обломок слова:
            # «babu|shka» (babushka, 6218-я), «lapo|chka» (12773-я). База
            # фамилий знает почти любой обломок (рецензия 08.11.2026, J13).
            for index in range(1, len(items)):
                part, kind = items[index]
                if (kind == "surname" and len(fold(part)) <= 4
                        and items[index - 1][1] == "first"):
                    _, last = self._ranks(fold(part))
                    if last is None or last > INITIAL_SURNAME_TOP:
                        if not self.confident_first(items[index - 1][0]):
                            return []
                        items = items[:index]     # «helena|kops» — Helena
                        break
            # Фамилия впереди имени («tanaka|hiroshi», «kowalski|jan») —
            # только частая: с редкими «haku|nama|tata» складывалось в
            # «Haku Nama Tata» (рецензия 07.11.2026). Слабая (дальше
            # LEADING_WEAK_SURNAME) — только перед частым именем.
            first_at = next((i for i, (_, k) in enumerate(items) if k == "first"), None)
            for part, kind in items[:first_at or 0]:
                if kind == "surname" and not self.rare_first(part):
                    _, last = self._ranks(fold(part))
                    long_enough = (len(fold(part)) >= LEADING_SURNAME_LEN and last is not None
                                   and last <= INITIAL_SURNAME_TOP)
                    if last is None or (last > LEADING_SURNAME_TOP and not long_enough):
                        return []
                    if last > LEADING_WEAK_SURNAME:
                        # Слабая фамилия впереди — только перед именем с ясным
                        # полом не дальше тысячного места: «galatas|aray» —
                        # обломки (Aray — 1212-е); перед Rodney (561-е имя,
                        # 99% мужчин) слабая фамилия остаётся.
                        follower = fold(items[first_at][0])
                        rank = self.first_rank(follower)
                        share = self._gender_share(follower)
                        if not (rank is not None and rank <= 1000 and share is not None
                                and share >= GENDERED_SHARE):
                            return []
            cut = self._truncate_at(items)
            if cut is not None:
                # Оборванный кусок и всё после него — вон; верным остаётся
                # только то, что до него, и только если там есть имя.
                items = items[:cut]
                if not any(k == "first" for _, k in items):
                    return []
            # Имя целиком из частых английских слов при слабом имени —
            # прозвище: «silver|fox» (Silver — 649-е имя). «john|smith» —
            # тоже слова корпуса, но John — частое имя (рецензия 07.11.2026).
            named = [(p, k) for p, k in items if k in name_kinds]
            if (named and any(k == "first" for _, k in named) and self._word_counts
                    and all(self._word_counts.get(fold(p), 0) >= PHRASE_WORD_COUNT
                            for p, _ in named)
                    and not any(k == "first" and self.strong_first(p) for p, k in named)
                    and not self.weak_but_real(named)):
                return []
            # Род деятельности в слитной строке: имя человека обязано стоять
            # первым («ninacarvalhotech»), иначе это название фирмы
            # («zeloterasports», «bluefoxclothingco»).
            if business:
                head = next(((p, k) for p, k in items
                             if not (k == "word" and (self.is_phrase(p)
                                                      or fold(p) in _TITLES))), None)
                if head is None or head[1] != "first" or not self.business_name_ok(items):
                    return []
            # Мусор посреди имени: «paul|xq|smith», «maria|bk|lopez». Всё,
            # что после него, — догадка поверх обломка; верным остаётся
            # только то, что до него, и только если там есть имя.
            seen_name = False
            for index, (part, kind) in enumerate(items):
                if kind in name_kinds:
                    seen_name = True
                elif kind in ("", "weak") and seen_name:
                    if len(fold(part)) >= 6 and not self.hard_junk(part):
                        return []     # «nora|qentrumbald»: длинный необъяснённый хвост — не имя
                    later = any(k in name_kinds for _, k in items[index + 1:])
                    if later:
                        items = items[:index]
                        break
            # Обломок в хвосте: длинный явный мусор («bcdf», «qwrt»)
            # снимается всегда, короткий («zx», «au») — только после частого
            # имени: у редкого он может быть его же буквами (`beatrix` —
            # Beatrix, а не «Beatri»).
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

        # Слова фраз. Ведущие («iam», «the», «real») просто снимаются. Слово
        # фразы ПОСЛЕ имени начинает фразу: всё, что за ним, — её часть
        # («sue|loves|frogs», «neha|im|here»), и неподтверждённый кусок прямо
        # перед ним тоже («rachael|dak|oala|girl»). Если после фразы снова
        # идёт другое имя — это двое людей или подпись («johnlovesmary»).
        kept = []
        in_phrase = plain_gap = False
        for part, kind in items:
            if kind in ("", "weak"):
                continue                      # обломок, веб-хвост — вон
            if kind == "word":
                if self._is_role(part):
                    # Род деятельности или служебное слово снимается, а имя
                    # рядом остаётся: «nina.carvalho.tech», «mike.sales».
                    continue
                if (not from_separators and kept and not in_phrase
                        and not self.is_phrase(part) and fold(part) not in _TITLES):
                    # Словарное слово сразу за именем в слитной строке:
                    # «ella|pencil», «nora|basket», «rosa|zinc».
                    # Имя здесь — обломок соседнего слова, а не имя.
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
                    continue                  # «nina|iam|nina» — Nina
                if kind == "first" and (not from_separators or plain_gap):
                    return []         # «ola.northwind.li»: слово посреди — не имя
                if kind != "first":
                    continue
                in_phrase = False
            if kind != "initial" and fold(part) in {fold(p) for p, _ in kept}:
                continue                      # «markjones.jones» -> Mark Jones
            kept.append((part, kind))
        if not kept:
            return []

        # Двухбуквенное имя впереди, а дальше настоящее имя ДРУГОЙ культуры —
        # это инициалы, а не имя: «du.rajesh» (Du — Китай и Бразилия, Rajesh —
        # Индия) — это Rajesh. У «bo.johansson» и «ed.harris» страны общие, и
        # оба куска остаются. Китайская фамилия перед китайским именем
        # («lu.chen») — тоже имя, хотя индекс знает «lu» латинским.
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
                # Другая культура — только если индекс знает обе стороны:
                # кусок, которого он не знает нигде, чужим не назовёшь.
                if lead_countries and other and not (lead_countries & other) and not chinese:
                    kept.pop(0)

        if not from_separators:
            # Неподтверждённые куски и раздробленная строка — name_split.py.
            kept = self.prune_structural(kept)
            if not kept:
                return []

        has_first = any(k == "first" for _, k in kept)

        # Инициалы. Посередине между именем и фамилией — законная часть имени
        # (Lena K Moss, Anil P Gupta). По краям рядом с ИМЕНЕМ — лишние:
        # «K Zoltan» -> Zoltan, «Paul X» -> Paul, «Peter D» -> Peter; по ним
        # письмо не начнёшь. Буква после ФАМИЛИИ в слитной строке — обломок
        # фамилии («rita|morah|y», «arun|ranjan|e»): уходит вместе с ней.
        # Рядом с одной фамилией инициал остаётся: «J Smith» — это запись имени.
        if not from_separators:
            cleaned = []
            for index, (part, kind) in enumerate(kept):
                if kind == "initial" and 0 < index < len(kept) - 1:
                    if fold(part) in _VOWELS and kept[index - 1][1] == "first":
                        # «minh|o|hwang»: с гласной выходит другое имя (Minho),
                        # и буква внутри имени — гадание: честнее пусто
                        # (рецензия 08.11.2026, RN-5).
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
                        # «mark|b|ezolt»: буква не между именем и частой
                        # фамилией — дальше догадка поверх обломка. Верно
                        # только то, что до неё.
                        break
                cleaned.append((part, kind))
            kept = cleaned
            if (len(kept) >= 2 and kept[-1][1] == "initial"
                    and kept[-2][1] in ("surname", "structural") and has_first):
                # Буква после фамилии. Частая фамилия остаётся без буквы
                # («ravi|murthy|g» -> Ravi Murthy); неизвестная уходит вместе с
                # ней — буква может быть её же концом («rita|morah|y»).
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

        # Пересчёт: обрезка выше могла выбросить единственное имя. Без него
        # строка «фамилия + буква + имя» отдавала одну фамилию — имя уходило
        # вместе с неподкреплённой буквой, а признак «имя есть» оставался.
        has_first = any(k == "first" for _, k in kept)
        if not has_first:
            named = [(p, k) for p, k in kept if k != "initial"]
            initials = [p for p, k in kept if k == "initial"]
            if from_separators:
                # Границы поставил человек. Годится «инициал + фамилия»
                # («j.smith», «p.walker», «rogbin.a») и два-три куска, похожих
                # на имя и фамилию («reza.bahramian», «wei.lin»).
                # Рядом с родом деятельности («city.center.spa») — нет.
                # «x-man»: буква и прозвище — не запись имени (рецензия
                # 08.11.2026). Прозвище, которое и частая фамилия, — фамилия:
                # «m.king» — это M King.
                pair = (len(kept) == 2 and len(named) == 1 and len(initials) == 1
                        and not (fold(named[0][0]) in _NICK_WORDS
                                 and not self.reads_as_surname(named[0][0])))
                many = (len(named) >= 2 and not business
                        and all(k in ("surname", "structural") for _, k in named))
                if not (pair or many):
                    return []
            else:
                # Своя догадка: только «инициал + подтверждённая фамилия», и
                # инициал впереди («jsmith» -> J Smith). Фамилия с буквой
                # после неё — обломок: ник из обрывка и фамилии давал
                # «Фамилия Буква» (прогон владельца, 07.11.2026). «Rogbin A» и
                # «Quorvel I» неотличимы, и подтвердить их нечем.
                # Две фамилии — только частые: «j|garcia|lopez».
                surnames = kept[1:]
                if not (kept[0][1] == "initial" and 1 <= len(surnames) <= 2
                        and all(k == "surname" for _, k in surnames)):
                    return []
                limit = INITIAL_SURNAME_TOP if len(surnames) == 1 else LEADING_SURNAME_TOP
                for surname, _ in surnames:
                    _, last = self._ranks(fold(surname))
                    if last is None or last > limit:
                        return []
                # Слово, которое ЯСНО имя, — не фамилия, а буква перед ним —
                # начало слова: «z|ayka» (zayka). См. clear_given_name.
                if self.clear_given_name(kept[1][0]):
                    return []

        # Одно короткое слово — не имя: «Ed», «Ab» без фамилии ничего не значат.
        if len(kept) == 1 and len(fold(kept[0][0])) < 3:
            return []

        if len(kept) == 1 and kept[0][1] == "first":
            # Одно имя-прозвище — ник: «king77», «princess», «angel2000»
            # (см. _NICK_WORDS). Словарное слабое имя — ник, если вокруг было
            # что-то ещё: «iamrich», «mrnice», «TheRock», «WonderWoman»
            # давали «Rich», «Nice», «Rock», «Wonder» (рецензия 08.11.2026).
            # «itsjohn», «mike.gamer» — настоящие имена — остаются.
            if fold(kept[0][0]) in _NICK_WORDS:
                return []
            if had_words and self._nicknamey(kept[0][0]):
                return []
            # Одна фамилия — не имя: см. lone_surname.
            if self.lone_surname(kept[0][0]):
                return []
            # Одно слабое имя всей слитной строкой, которое само читается
            # частыми английскими словами, — слово: см. LONE_FIRST_RANK.
            if not from_separators:
                rank = self.first_rank(kept[0][0])
                if (rank is None or rank > LONE_FIRST_RANK) and self.english_compound(kept[0][0]):
                    return []
        # Прозвище и слово или прозвище: «red.bull», «lone.wolf» (см. nick_pair).
        if self.nick_pair([p for p, k in kept if k != "initial"]):
            return []
        if not from_separators:
            # Все имена слитной строки очень слабые (дальше SPLIT_FIRST_RANK)
            # и без пола — совпадение букв, а не имя: «inshallah» разбор
            # резал на слабое «имя» (3875-е место, пол 74/26) и обломок
            # (рецензия 08.11.2026). Имена с тех же дальних мест, но с ясным
            # полом (97% женщин), остаются.
            firsts = [p for p, k in kept if k == "first"]
            if firsts and all(
                    (self.first_rank(p) is None or self.first_rank(p) > SPLIT_FIRST_RANK)
                    and not ((self._gender_share(fold(p)) or 0) >= GENDERED_SHARE)
                    for p in firsts):
                return []

        # Больше трёх кусков (между разделителями): первыми уходят срединные
        # инициалы, затем срединные куски — имя и фамилия по краям остаются.
        while len(kept) > MAX_TOKENS:
            middle = [i for i in range(1, len(kept) - 1) if kept[i][1] == "initial"]
            drop = middle[0] if middle else len(kept) - 2
            kept.pop(drop)
        return [p for p, _ in kept]

    def clean_guess(self, parts, fused=False):
        """Чистка догадки режима «Заполненность»: убрать ЗАВЕДОМЫЙ мусор.

        Режим «Заполненность» по решению владельца оставляет неподтверждённые,
        но правдоподобные догадки («Zelo Terasports»): это его компромисс
        «больше имён ценой точности». Но веб-слово, обломок без гласных,
        буква-украшение и инициал рядом с именем мусор в любом режиме:
        «Mirae Www», «Ravi Bcdf», «Paul X», «K Zoltan».

        fused=True — куски нарезал сегментатор, человек границ не ставил:
        у такой догадки есть две заведомо ложные формы — см. joined_word_guess
        и is_fragment (core/parser/name_evidence.py).
        """
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
        # Одно слово рядом с буквой, которое читается фамилией, — запись
        # «И. Фамилия», и буква остаётся: «j|garcia» давал «Garcia» на месте
        # имени (рецензия 08.11.2026, RN-2).
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
            # Одно слово — имя, только если оно подтверждено: не прозвище, не
            # фамилия, не слово и не обломок ника (решение владельца
            # 13.11.2026; планка та же, что у одного слова из профиля, —
            # _lone_profile_name). Прежде «Заполненность» отдавала одиночные
            # «Gonzalez», «King», «Belo» и «Sunset» от `sunset.generation`.
            only = fold(kept[0][0])
            if not self._lone_profile_name(only) or (
                    only in self.english_words and not self._is_first(only)
                    and not self.surname_ok(only)):
                return []
        return [p for p, _ in kept]

    # ── профиль ──────────────────────────────────────────────────────────

    def profile_tokens(self, name):
        """Куски имени из профиля или None, если это не имя человека вовсе."""
        if not isinstance(name, str):
            return None
        name = " ".join(name.split())
        if not name or len(name) > 60:
            return None
        if re.search(r"\d", name) or re.search(r"[@/\\_#|]|https?:|www\.", name, re.I):
            return None          # ник, адрес или ссылка, а не имя
        if len(scripts_of(name)) > 1:
            return None          # «JΛNE»: украшение смесью алфавитов
        if not scripts_of(name):
            return None          # одни знаки, ни одной буквы
        squashed = letters_only(name)
        if any(part in squashed for part in _SPAM_PARTS):
            return None
        tokens = [t.strip(".,") for t in re.split(r"[\s,]+", name) if t.strip(".,")]
        # Титул остаётся: его снимает finalize и по нему же судит, ник ли
        # это («Mr Nice», «Mr. Bean»). Прежде титул срезался ДО проверки, и
        # «Mr Nice» становился «Nice» (рецензия 08.11.2026, J16).
        if not tokens or len(tokens) > 4:
            return None
        for t in tokens:
            if re.search(r"[^\w'.\-]", t, re.UNICODE):
                return None
            low = fold(t).strip(".'-")
            if low in WEB_WORDS or low in ROLE_WORDS or low in BUSINESS_WORDS:
                return None      # «ACME TECH», «star enterprises»
        return tokens

    def profile_name(self, raw, local_part):
        """Имя из профиля Gravatar: (принятое, отложенное).

        Принятое — латиницей и проверенное: идёт в колонку сразу.
        Отложенное — другим алфавитом («王小明» у `david.wang…`): для
        рассылки на латинице адрес даёт более пригодное «David Wang», и
        профиль берётся, только если адрес не дал ничего.
        Отказ — ("", ""): ник («sunil07», «moviebuff»), логин, фирма, спам.
        """
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
            return "", ""         # это логин, а не имя
        if len(tokens) == 1:
            token = tokens[0]
            if (len(letters_only(token)) >= 3 and self.is_anchor(token)
                    and self._lone_profile_name(token)):
                return display_case(token), ""
            # Ник одним словом. Годится, только если без остатка и без
            # догадок складывается из имён и фамилий и опирается на адрес:
            # «annasilva» -> Anna Silva, «rajpatel» -> Raj Patel. Ник
            # «moviebuff», «realmikejones», «jgreen» — нет.
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
