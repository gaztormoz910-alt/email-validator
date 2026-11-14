# -*- coding: utf-8 -*-
"""Улики за и против имени, которые не сводятся к одному куску: английское
прочтение строки, склейки двух имён в записях базы, пол как признак имени,
имя целиком из базы. Примесь к NameQuality (core/parser/name_quality.py).

Вынесено отдельно после рецензии 07.11.2026: каждое из этих правил закрывает
найденный ею дефект («Ilo» из `iloveyou`, «Gonza» из `gonzalez`, «Garcia» на
месте имени у `m.garcia`, «Dami Lola»), и вместе они не помещались в бюджет
размера модуля правил. Знание о мире приходит через NameQuality: ранги
(_ranks), частоты корпуса (_word_counts), доля пола (_gender_share).

Примеры в комментариях выдуманы: адресов владельца в коде нет.
"""
import math

from .name_words import (BUSINESS_WORDS, ROLE_WORDS, WEB_WORDS,
                         MAX_SEGMENT_INPUT, MAX_TOKEN_LEN, PLAIN_WORD_COUNT, _PHRASE_WORDS,
                         _NICK_WORDS, _NOT_NAME_WORDS, _EAST_ASIAN_SHORT_SURNAMES, _NICK_PREFIXES,
                         _KNOWN_PHRASES, _I_VERB_PREFIXES,
                         _CHINESE_NAME_COUNTRIES, fold, is_latin, letters_only)

# Слово корпуса сегментатора с частотой от этой — обычное английское слово:
# «silver» (74 млн), «fox» (24 млн), «love» (201 млн). По таким словам
# строится английское прочтение строки (english_reading).
PHRASE_WORD_COUNT = 1000000

# Одно слово рядом с инициалом — запись «И. Фамилия» («m.garcia»,
# «tnguyen»), если база не говорит ясно, что оно имя (см. reads_as_surname).
# Имя человека почти всегда «мужское» или «женское»: Muhammad — 98%
# мужчин, Diksha — 96% женщин, Priya — 93%. Фамилия, которую вписали в поле
# имени, рода не имеет: Nguyen — 55/45, Zhang — 48/52, Garcia — 63/37
# (names_dataset, замерено 07.11.2026). Перекос по полу не меньше этого —
# признак имени, независимый от рангов, которые такие вписанные фамилии и
# портят.
GENDERED_SHARE = 0.85

# Фамилией рядом с инициалом считается и слово с перекосом по полу, если
# фамилией оно в столько раз сильнее, чем именем: Yilmaz — 17-я фамилия и
# 353-е «имя», Robinson — 11-я и 182-е, Santos — 2-я и 45-е. Перекос по полу
# у них есть — фамилию в поле имени вписывают мужчины (Yilmaz — 97%), — и
# одного пола мало (рецензия 08.11.2026, RN-1). Martin (2-е имя, 1-я
# фамилия), David (1/11), Muhammad (2/2) под это не подпадают: имя у них не
# слабее фамилии, и обращение по такому слову читается именем.
SURNAME_DOMINANT_RATIO = 5

# «Буква + слово, которое бывает и именем, и фамилией» между разделителями
# (m.martin, m.david) — запись «И. Фамилия»: «M Martin», а не «Martin»
# (решение владельца 14.11.2026; прежнее правило выше снимало букву). Слово
# считается такой фамилией, если фамилией оно не дальше этого места. Порог
# лежит в разрыве замеренных рангов (лучшее место по странам, 14.11.2026):
# Martin 1, Muhammad 2, Thomas 4, John 7, David 11, James 15, Paul 34 — и
# слова, которые читаются только именем: Mohan 93, Lajos 100, Anna 116,
# Priya 162, Zoltan 291, Deepika 2435, Diksha 3438. У них буква остаётся
# снятой («k.zoltan» — Zoltan, «m.deepika» — южноиндийское «инициал + имя»).
INITIAL_DUAL_SURNAME_RANK = 50

# Одно слово адреса — фамилия, а не имя, только если именем оно дальше этого
# места (lone_surname): Yilmaz (353-е) — фамилия, а Vera (65-е имя и 2-я
# фамилия), Santos (45-е), Kumar (12-е) в одиночку — имена.
LONE_SURNAME_FIRST_RANK = 100

# Уверенное имя для улик по строке целиком (_confident_pair, confident_first):
# перекос по полу не меньше этого. Чуть мягче GENDERED_SHARE: Deepa — 84,7%
# женщин, и «deep|an|air» резало Deepa Nair (рецензия 08.11.2026).
CONFIDENT_SHARE = 0.8
CONFIDENT_SURNAME_RANK = 1000

# Буква и следующий кусок вместе — слово, которое база знает не дальше этого
# места (joined_known): O'Brien — 7-я фамилия, Amaral — 78-я, Esteve —
# 478-я. «Anguyen», «Asmith», «Ebalogh» база не знает вовсе.
JOINED_KNOWN_RANK = 2000

# Слово фразы, которое между разделителями — частое имя с ясным полом:
# «guy.cruz» — это Guy Cruz (Guy — 17-е имя, 99% мужчин), а не «Cruz»
# (рецензия 08.11.2026, RN-4). В слитной строке («coolguy») это слово.
PHRASE_NAME_RANK = 100
PHRASE_NAME_SHARE = 0.95

# Прозвище и второе слово (_NICK_WORDS): слово корпуса с частотой от этой
# — слово, если фамилией оно не в первой полсотне. «red|bull» — Bull 10 млн и
# слабая фамилия; «angel|lopez» — Lopez 9 млн и 1-я фамилия; «rocky|smith» —
# Smith 63 млн, но 1-я фамилия.
NICK_TAIL_WORD_COUNT = 10000000
NICK_TAIL_SURNAME_TOP = 50

# Строка ЦЕЛИКОМ — имя базы не дальше этого места, хотя индекс его не знает:
# «damilola» (201-е в Нигерии), «funmilayo» (205-е). Куску слитной строки с
# таким рангом не верим (DATASET_FIRST_TOP_LONG) — внутри строки совпадений
# букв много, — а целой строке от пяти букв совпасть с именем почти не с чем.
WHOLE_FIRST_RANK = 500

# Кусок, который база знает слабо (фамилией дальше этого места или именем
# дальше CONCAT_FIRST_RANK), но который ровно делится на частое имя и частую
# фамилию (каждое не дальше CONCAT_PART_RANK), — склейка в записи базы, а не
# одно имя: «zhangwei» (1387-я фамилия) — это Zhang Wei,
# «ahmedali» — Ahmed Ali, «anilkumar» (310-е имя) — Anil Kumar. Без этого
# длинный кусок перевешивал разрез, и в «Точности» имя терялось целиком
# (рецензия 07.11.2026).
CONCAT_SURNAME_RANK = 1000

CONCAT_FIRST_RANK = 300

CONCAT_PART_RANK = 50

# Фамилия в склейке — из первой десятки (Kumar, Ali, Zhang): с полсотней
# «vasil|isa» внутри Vasilisa считалось склейкой — Isa где-то в мире
# входит в полсотню фамилий (повтор прогона владельца, 07.11.2026).
CONCAT_SURNAME_PART = 10

# Однобуквенные слова английского прочтения: «i», «a» и «u» переписки
# («iloveu» — i|love|u; без «u» у строки не было прочтения, и «Ilo»
# проходило, рецензия 08.11.2026).
_ONE_LETTER_WORDS = frozenset({"i", "a", "u"})

# Двухбуквенные служебные слова английского прочтения (english_reading).
_SHORT_WORDS = frozenset({"my", "me", "be", "we", "is", "in", "on", "of", "at", "to",
                          "it", "an", "so", "go", "do", "no", "up", "us", "he", "or",
                          "as", "by", "if", "am", "hi", "oh", "ok", "mr", "dr", "ms"})

# Фамилии, которые рядом с инициалом — фамилии всегда (reads_as_surname).
# Восточноазиатские анкеты массово вписывают фамилию в поле имени, и «ранг
# имени» у них в базе — это ранг фамилии (Nguyen — 3-е «имя», Chen — 1-е).
# Singh и Kaur — сикхские фамилии, а перекос по полу у них есть потому, что
# Singh носят мужчины, а Kaur — женщины. Слов, которые там же и частые имена
# (Wei, Han, Yu, Lin), здесь нет намеренно.
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
    """Улики к разбору имени. Полагается на поля и методы NameQuality."""

    def dual_surname(self, token):
        """Слово, которое бывает и именем, и частой фамилией: Martin, David.

        Только для записи «буква + слово» между разделителями (см.
        _initial_context и INITIAL_DUAL_SURNAME_RANK).
        """
        _first, last = self._ranks(fold(token))
        return last is not None and last <= INITIAL_DUAL_SURNAME_RANK

    def reads_as_surname(self, token):
        """Слово рядом с инициалом — фамилия, а не имя: Garcia, Yilmaz, Santos.

        Запись «инициал + слово» — это либо «И. Фамилия» (m.garcia,
        f.yilmaz), либо южноиндийское «инициал + имя» (m.deepika). Снять
        инициал как лишний значит поставить фамилию на место имени: «m.garcia»
        давал «Garcia» (рецензия 07.11.2026), «f.yilmaz» — «Yilmaz» (рецензия
        08.11.2026, RN-1).

        Фамилия — слово без перекоса по полу, которое фамилией стоит выше,
        чем именем (Garcia, Lee, Patel), и слово с перекосом, которое фамилией
        МНОГО сильнее (SURNAME_DOMINANT_RATIO: Yilmaz, Santos, Robinson,
        Kumar). Имя — слово с перекосом по полу, которое именем не слабее:
        Diksha, Priya, а также Martin, David, Muhammad, хотя они и частые
        фамилии — обращение по такому слову читается именем, а буква перед
        ним — нет. Фамилии из _SURNAMES_NOT_NAMES — фамилии всегда: у
        восточноазиатских ранг имени испорчен анкетами (Nguyen — 3-е «имя»
        базы), у Singh и Kaur перекос по полу — от обычая.
        """
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
        """Одно слово адреса без имени рядом — фамилия: «garcia», «nguyen», «yilmaz».

        Обратиться «Здравствуйте, Garcia» нельзя, и такое слово не имя
        (рецензия 08.11.2026, J21: прежде одиночная фамилия проходила).
        Строже, чем рядом с инициалом: одно слово в адресе чаще имя. Без
        перекоса по полу — фамилией втрое сильнее (Garcia, Patel; Lee, Han,
        Damilola — имена). С перекосом — см. LONE_SURNAME_FIRST_RANK.
        """
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
        """Слитная строка, в которой имени нет, как бы её ни резал разбор.

        Ласковое слово или лозунг другого языка («zayka», «inshallah»),
        известная фраза или герой («snowwhite»), лепет из повторов слога
        («lalala», «mamama») и фраза «я + глагол» («iloveyu», «ilovey»,
        «imissyou»): у неё нет английского прочтения, если хвост написан
        не по словарю, и разбор доставал «Ilo» (рецензия 08.11.2026).
        """
        s = letters_only(letters)
        if s in _NOT_NAME_WORDS or s in _KNOWN_PHRASES or s.startswith(_I_VERB_PREFIXES):
            return True
        # Приставка ника и прозвище целиком: «iamman», «imred», «theking».
        # Иначе разбор искал другое прочтение тех же букв и находил «I Amman»
        # и «Imre» (перемер пачек рецензента, 12.11.2026).
        if any(s.startswith(prefix) and s[len(prefix):] in _NICK_WORDS
               for prefix in _NICK_PREFIXES):
            return True
        return any(len(s) >= 3 * k and s == s[:k] * (len(s) // k) for k in (1, 2, 3))

    def confident_first(self, part):
        """Имя, которому не нужны соседи: от пяти букв, подтверждено, с перекосом по полу.

        Нужно там, где строку целиком читают словами: «heat|her|smith» внутри
        `heathersmith`, «fat|im|am» внутри `fatimam`. Heather и Fatima —
        имена, и фраза из коротких слов поверх них — совпадение букв
        (рецензия 08.11.2026, RN-4, RN-8).
        """
        t = fold(part)
        if len(t) < 5 or t in _NICK_WORDS or not self.first_ok(t, 5) or self.wordlike_first(t):
            return False
        share = self._gender_share(t)
        return share is not None and share >= GENDERED_SHARE

    def _lone_profile_name(self, token):
        """Одно слово профиля — имя, а не прозвище, слово или фамилия.

        «Minecraft», «Nice», «Wonder», «Ninja», «More» проходили в колонку
        как имя (рецензия 08.11.2026, J15): индекс знает их именами.
        """
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
        """Слово ЯСНО имя, а не фамилия: «ayka» (69-е имя), Diksha, Priya.

        Нужно слитной записи «буква + слово»: «z|ayka» (zayka) — не «Z
        Ayka», буква тут — начало слова. Фамилия и спорное слово так не
        судятся: буква перед словом, которое база знает и именем, и
        фамилией одинаково слабо (2517-е имя и 3036-я фамилия), — инициал
        и фамилия (рецензия 08.11.2026).
        """
        t = fold(token)
        if self.reads_as_surname(t):
            return False
        rank = self.first_rank(t)
        share = self._gender_share(t)
        _, last = self._ranks(t)
        # Фамилией чаще, чем именем, — уже не «ясно имя»: «t|archer».
        return (rank is not None and rank <= 1000 and share is not None
                and share >= GENDERED_SHARE and (last is None or rank <= last))

    def joined_known(self, letter, piece):
        """Буква и кусок вместе — слово, которое база знает: O'Brien, Amaral, Esteve.

        Гласная перед согласной читается одним словом, но только если такое
        слово есть: «a|nguyen», «a|smith», «e|balogh» база не знает, и это
        инициал с фамилией — прежде звучание одно хоронило их (рецензия
        08.11.2026, RN-2). См. JOINED_KNOWN_RANK.
        """
        first, last = self._ranks(fold(letter) + fold(piece))
        return ((first is not None and first <= JOINED_KNOWN_RANK)
                or (last is not None and last <= JOINED_KNOWN_RANK))

    def joined_word_guess(self, parts):
        """Догадка «буква + слово» по слитной строке, а вместе они — слово базы.

        Жалоба владельца 13.11.2026: в «Заполненности» строка — венгерская
        фамилия — давала имя без первой буквы; так же «d|souza» давал
        «D Souza». Границу здесь придумал сегментатор, а база знает строку
        целиком (см. joined_known): буква — первая буква этого слова, а не
        инициал, и «имя» после неё — совпадение букв. Строка, которую база
        слитно не знает («o|zoltan»), остаётся догадкой режима, как и была.
        Запись через разделитель («o.zoltan») сюда не приходит: там границу
        поставил человек.
        """
        whole = [p for p in parts or [] if isinstance(p, str) and p.strip()]
        return (len(whole) == 2 and len(fold(whole[0])) == 1 and len(fold(whole[1])) >= 2
                and self.joined_known(whole[0], whole[1]))

    def is_fragment(self, token):
        """Выброшенный из догадки кусок — обломок, то есть не слово вовсе.

        Без гласных, лепет клавиатуры, повтор буквы. Обломок рядом с
        НЕПОДТВЕРЖДЁННЫМ куском значит, что слитную строку разрезать не
        удалось: это ник, и его произносимое начало — не имя («belo|dx» давал
        «Belo»; жалоба владельца 13.11.2026). Подтверждённое имя перед
        обломком («priya|xx») остаётся: его границу держит индекс имён, а
        не разрез. Не обломок: веб-слово, роль и слово фразы («mirae|www» —
        приписка человека, граница настоящая) и слишком длинный кусок —
        склеенный хвост названия, догадку рядом с ним режим оставляет.
        """
        t = fold(token)
        if (t in WEB_WORDS or t in ROLE_WORDS or t in BUSINESS_WORDS or t in _PHRASE_WORDS
                or len(t) > MAX_TOKEN_LEN):
            return False
        return self.hard_junk(t)

    def weak_but_real(self, named):
        """Слабое по рангу имя, которое всё же имя: «violet48», «violet|mendoza».

        Правило «имя целиком из частых слов корпуса — прозвище» («silver|fox»)
        задевало и имена, которые корпус знает словами, а словарь — нет:
        Violet (583-е, 97% женщин) с фамилией Mendoza (рецензия 08.11.2026,
        RN-4). Имя — не словарное слово, не дальше тысячного места и с ясным
        полом; остальные куски — не словарные слова.
        """
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
        """Имя, которое индекс держит китайским или вьетнамским (последние у
        него числятся только за Канадой и Германией: Linh, Minh, Hung)."""
        countries = self._countries(head)
        return bool(countries & _CHINESE_NAME_COUNTRIES) or bool(
            countries and countries <= {"CA", "DE"})

    def split_short_surname(self, letters, pieces):
        """«linhho», «yanxu», «anhngo»: имя и короткая фамилия Восточной Азии.

        Разбору выгоднее взять такую строку одним неизвестным куском:
        двухбуквенная фамилия стоит дороже, чем даёт. До правки её резал
        английский сегментатор, и имя терялось (перемер инструментом
        рецензии, 12.11.2026).
        """
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
        """«jisookim»: разбор взял «jisook|im», а строка кончается фамилией Kim.

        Корейских имён индекс почти не знает (Jisoo — 2709-е место базы), и
        разбор находил внутри строки чужое слабое имя: «Jisook», «Sung Minah»
        (рецензия 08.11.2026, RN-5). Если строка кончается частой фамилией
        Восточной Азии, начало без неё похоже на имя (база знает его с ясным
        полом), а разбор эту границу не поставил и держит её внутри слабого
        куска, — это гадание: честнее пусто. Частое имя («christian» — не
        Chris Tian) так не судится.
        """
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
        """«rrodriguez», «rsanchez»: буква и частая фамилия, а не одна фамилия.

        База фамилий знает и такие склейки (Rrodriguez — 2107-я, Rsanchez —
        6137-я), и разбор брал строку одним куском, после чего имени не
        оставалось (рецензия 08.11.2026, RN-2). Если без первой буквы строка —
        частая фамилия (до 500-го места), а сама она — редкость (дальше
        1000-го), это инициал и фамилия.
        """
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
        """Слово фразы, которое — частое имя с ясным полом: «guy». См. PHRASE_NAME_RANK."""
        rank = self.first_rank(t)
        share = self._gender_share(t)
        return (rank is not None and rank <= PHRASE_NAME_RANK
                and share is not None and share >= PHRASE_NAME_SHARE)

    def nick_pair(self, named):
        """Прозвище и слово или второе прозвище: «red.bull», «lone.wolf», «snow|white».

        С настоящей фамилией имя остаётся: «angel.lopez», «prince.adewale»
        (рецензия 08.11.2026). Словарь знает и частые фамилии (Lopez, White),
        поэтому «слово» здесь — частое слово корпуса без сильного места
        фамилии (NICK_TAIL_*).
        """
        if len(named) != 2 or fold(named[0]) not in _NICK_WORDS:
            return False
        tail = fold(named[1])
        _, tail_last = self._ranks(tail)
        common_word = self._word_counts.get(tail, 0) >= NICK_TAIL_WORD_COUNT
        return bool(tail in _NICK_WORDS or tail in _PHRASE_WORDS or tail_last is None
                    or tail_last > CONFIDENT_SURNAME_RANK
                    or (common_word and tail_last > NICK_TAIL_SURNAME_TOP))

    def _confident_pair(self, pieces):
        """Разбор — подтверждённое имя с перекосом по полу и частая фамилия (или два имени)."""
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
        """Двухбуквенная восточноазиатская фамилия между разделителями — фамилия.

        «huong.do», «tam.vu», «minjun.oh», «t.vu», «na.liu», «vy.le»: без
        этого «do» и «oh» были словами, «vu» — обломком, и оставалось одно
        имя или пусто (рецензия 08.11.2026, RN-3, RN-9). Впереди имени другой
        культуры кусок не трогается: «du.rajesh» — это инициалы и Rajesh.
        """
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
                    out[index] = (part, "surname")          # «vy.le»: Vy Le
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
                        continue                            # «du.rajesh»
                out[index] = (part, "surname")
        return out

    def _initial_context(self, items, separators=False):
        """Единственное имя рядом с инициалом, которое читается фамилией, — фамилия.

        separators=True — границы поставил человек (`m.martin`). Только тогда
        действует правило «буква + имя-и-фамилия» (dual_surname): в слитной
        строке («jallen», «dallen») буква — чаще обломок, и Allen остаётся
        именем, как раньше.

        «m|garcia», «j.lee»: без этого инициал снимался как лишний рядом с
        «именем», и в колонку уходила фамилия. С фамилией запись остаётся
        «M Garcia», как и было до правки. «k|zoltan» не задевается: Zoltan —
        имя (reads_as_surname).
        """
        names = [i for i, (_, k) in enumerate(items) if k in ("first", "surname", "structural")]
        if not names:
            return items
        index = names[0]
        part, kind = items[index]
        if kind != "first" or len(fold(part)) < 3:
            return items
        # Дальше — только фамилии: «j|garcia|lopez» — это J Garcia Lopez, а
        # не «Garcia Lopez». Рядом с другим именем слово остаётся именем.
        if any(items[i][1] != "surname" for i in names[1:]):
            return items
        # Только инициал ВПЕРЕДИ: «m|garcia» — запись «И. Фамилия», а
        # «fatima|m», «attila|m» — имя и буква фамилии (рецензия 08.11.2026).
        if not (index > 0 and items[index - 1][1] == "initial"):
            return items
        if not (self.surname_ok(part) and (self.reads_as_surname(part)
                                           or self.surname_after_initial(part)
                                           # Только «буква + одно слово»: в
                                           # «m.martin.jones» Martin — имя.
                                           or (separators and len(names) == 1
                                               and self.dual_surname(part)))):
            return items
        out = list(items)
        out[index] = (part, "surname")
        return out

    def english_reading(self, letters):
        """Где строку режет её самое вероятное английское прочтение — или None.

        Прочтение — то, что выбрал бы сам сегментатор: произведение частот
        слов корпуса наибольшее, а незнакомое слово штрафуется по длине (та
        же формула, что у wordsegment). «iloveyou» — i|love|you, «angeleyes»
        — angel|eyes, «arsenal» — одно слово, а «francescabianchi» —
        francesca|bianchi: имена — тоже слова корпуса. Прочтению верим, только
        если каждое его слово частое (не ниже PHRASE_WORD_COUNT; одна
        буква — только «i» и «a», две — только служебные слова); иначе
        строка не английская, и судить по нему нельзя. Возвращает набор позиций разрезов (frozenset)
        или None.
        """
        s = letters_only(letters)
        if s in self._reading_memo:
            return self._reading_memo[s]
        n = len(s)
        result = None
        counts = self._word_counts
        if 0 < n <= MAX_SEGMENT_INPUT and counts:
            total = self._corpus_total()
            best = [None] * (n + 1)          # best[j] = (log-вероятность, слова)
            best[0] = (0.0, ())
            for i in range(n):
                if best[i] is None:
                    continue
                score, words = best[i]
                for j in range(i + 1, min(n, i + 2 * MAX_TOKEN_LEN) + 1):
                    piece = s[i:j]
                    count = counts.get(piece, 0)
                    # Редкое в корпусе — не слово, а незнакомая строка: сам ник
                    # «iloveyou» встречается там 36 тыс. раз и без этого
                    # перевешивал i|love|you (сегментатор решает это парами
                    # слов, а здесь хватает порога обычного слова). Короткие
                    # куски — только служебные слова: в корпусе веб-страниц
                    # «gi», «ur», «aja» тоже частые, и из них складывалось
                    # «прочтение» настоящего имени из коротких кусков.
                    if (count < PLAIN_WORD_COUNT
                            or (len(piece) == 1 and piece not in _ONE_LETTER_WORDS)
                            or (len(piece) == 2 and piece not in _SHORT_WORDS)):
                        count = 0
                    gain = (math.log10(count / total) if count
                            else math.log10(10.0 / total) - len(piece))
                    if best[j] is None or score + gain > best[j][0]:
                        best[j] = (score + gain, words + (piece,))
            words = best[n][1] if best[n] is not None else ()
            # Верим прочтению, только если КАЖДОЕ его слово частое (от
            # PHRASE_WORD_COUNT): цепочка обрывков веб-корпуса — не
            # английский текст, а случайность букв настоящего имени.
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
        """Строка целиком складывается из слов: «glanceobjects», «bethechange».

        Имена из индекса здесь словами не считаются: «markwill» и
        «rosegarden» — не фраза, в них есть имя. И строка, которая сама —
        имя, фразой не бывает: «ingrid» — не «in|grid», «andrea» — не
        «and|rea». Проверяется сама строка, а не разбор: внутри фразы почти
        всегда найдётся чьё-то имя («g|lance|objects»), и разбор его охотно
        достанет.
        """
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
        """Слово целиком складывается из английских слов: «freeform», «partofcar».

        Допускается один короткий (до двух букв) остаток: «da|koala|girl»,
        «oak|reps» — это склейка слов, а не фамилия, которую не знает база.
        Слова — от четырёх букв, слова фраз — от трёх: иначе «fe|lil|cia»
        хоронило бы фамилию Felilcia.
        """
        n = len(t)
        if n < 6:
            return False

        def word(piece):
            if piece in _PHRASE_WORDS:
                return len(piece) >= 3
            return len(piece) >= 4 and piece in self.english_words

        # reach[позиция][потрачен ли остаток] = наименьшее число слов
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
        """Строка — склейка частых английских слов от трёх букв: «minecraft»
        (mine|craft). «sowmya» (sow|my|a) — нет: короткие куски прочтения не
        делают имя словом (рецензия 08.11.2026)."""
        cuts = self.english_reading(letters)
        if not cuts:
            return False
        s = letters_only(letters)
        bounds = [0] + sorted(cuts) + [len(s)]
        return all(b - a >= 3 for a, b in zip(bounds, bounds[1:]))

    def misaligned(self, letters, pieces):
        """Разбор режет английское слово посередине: «ilo|veyou», «ange|leyes».

        Если строка целиком читается обычными английскими словами
        (english_reading), граница между двумя кусками разбора (от двух букв
        каждый) обязана совпасть с границей слов: «john|smith» совпадает,
        «ilo|veyou» и «ange|leyes» (angel eyes) — нет, и имя там — совпадение
        букв (рецензия 07.11.2026). Граница у инициала не проверяется: буква
        отдельно от слова и есть запись «И. Фамилия».

        Прочтение должно быть английским ТЕКСТОМ: каждое слово — из словаря
        или служебное. Частые обрывки веб-корпуса складывали «прочтение»
        настоящего имени — «bur|a|kde|mir» (burakdemir), «jin|gli» (jingli),
        «jun|hoh|wang» (junhohwang), — и правило хоронило 199 из 22 тыс.
        выдуманных слитных имён (рецензия 08.11.2026, RN-7). Служебное слово
        ВНУТРИ прочтения («deep|an|air», «rev|a|thin|air») при уверенном имени
        и частой фамилии — совпадение букв: это Deepa Nair и Revathi Nair.
        """
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
        # Кусок имени, который прочтение начинает служебным словом («the|be»
        # внутри «thebe»), — совпадение букв: «thebesteve» давал «Thebe Steve»
        # (рецензия 08.11.2026, J17). Проверяется раньше поправки ниже: там
        # «be» — тоже служебное слово внутри. Частое имя так не судится:
        # «to|bias» — это Tobias.
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
            # Сверяется граница, у которой хотя бы с одной стороны кусок
            # имени: «rachael|da|koala» и «rachael|dak|oala» — оба прочтения
            # фразы, и спорить о границе внутри неё незачем.
            if (len(prev) >= 2 and len(part) >= 2 and pos not in cuts
                    and (kind in names or prev_kind in names)):
                return True
            pos += len(part)
            prev, prev_kind = part, kind
        return False

    def whole_first(self, letters):
        """Строка целиком — имя базы, которого нет в индексе: «damilola».

        См. WHOLE_FIRST_RANK. Слово, фраза, фамилия по преимуществу (имя
        вдвое реже фамилии) и склонное к фамилии имя сюда не проходят.
        """
        s = letters_only(letters)
        if len(s) < 5 or not is_latin(s) or self.hard_junk(s) or s in _PHRASE_WORDS:
            return False
        if s in _NICK_WORDS or s in _NOT_NAME_WORDS or self.lone_surname(s):
            return False          # «mummy» (399-е «имя»), «nguyen» — не имя
        if s in self.english_words or self.is_plain_word(s) or self.phrase_only(s):
            return False
        first, last = self._ranks(s)
        if first is None or first > WHOLE_FIRST_RANK:
            return False
        if last is not None and first > 2 * last:
            return False
        if first > CONCAT_FIRST_RANK and self._joined_names(s):
            return False          # «anilkumar» — склейка Anil и Kumar, см. CONCAT_*
        # Пол здесь не спрашивается: имя целиком бывает и общим для обоих
        # полов (Damilola, Jordan, Andrea), и отказ по полу терял бы его.
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
        """Кусок ровно делится на частое имя и частую фамилию (в любом порядке).

        Только так: «anil|kumar», «zhang|wei», «ahmed|ali». Два имени подряд
        («vasil|isa» внутри Vasilisa, «anna|maria») — это одно сложное имя,
        и резать его нельзя: так терялось сложное имя с фамилией на повторе
        прогона владельца (07.11.2026). См. CONCAT_SURNAME_RANK.
        """
        for k in range(3, len(piece) - 2):
            head, tail = piece[:k], piece[k:]
            if ((self._strong_first_part(head) and self._top_surname_part(tail))
                    or (self._top_surname_part(head) and self._strong_first_part(tail))):
                return True
        return False
