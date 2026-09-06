import os
import re

from core.email_syntax import (harvest_pattern, validate_email_syntax,
                               _lower_domain_only)
from core.inputnorm import normalize_input, split_addresses
from core.provider import canonical_country, canonical_gender

from core.encoding import open_text

# Нумерация в начале строки: «12. », «3) », «100: », «5-й ».
#
# Лишняя косая черта закрывала класс символов раньше времени, и образец
# требовал после цифр буквального «:й». Он не снимал НИЧЕГО: строка
# «1. ivan@gmail.com» доезжала до разбора как есть, а нумерованный список
# прокси терялся построчно — «1. 1.2.3.4:8080» прокси не является. Списки,
# скопированные с форума или из документа, нумерованы почти всегда.
CLEAN_PREFIX_RE = re.compile(r'^\d+[-.)\]:й]*\s+')

# Regex для определения email в любой позиции
# Образец берётся из проверки синтаксиса, а не пишется здесь заново.
#
# Свой, более узкий образец резал адрес молча и в самом опасном виде — не
# терял его, а ПОДМЕНЯЛ другим, существующим: `o'brien@gmail.com` приезжал в
# базу как `brien@gmail.com`, `john.doe@` как `doe@`, а домен на кириллице
# `ivan@xn--80a1acny.xn--p1ai` обрубался до `ivan@xn--80a1acny.xn`. Владелец
# писал письмо чужому человеку и не имел ни одного признака, что это не тот,
# кого он собирал.
_EMAIL_RE = harvest_pattern(wide=True)

# Словарь гендеров для автоопределения колонок
_GENDER_VALUES = {
    'male', 'female', 'm', 'f',
    'мужской', 'женский', 'мужчина', 'женщина', 'муж', 'жен',
    'мужик', 'man', 'woman', 'boy', 'girl',
    'mostly_male', 'mostly_female', 'andy', 'unknown',
}

# Словарь стран (200+) для автоопределения колонок
_COUNTRY_VALUES = {
    # English
    'afghanistan', 'albania', 'algeria', 'andorra', 'angola', 'argentina', 'armenia',
    'australia', 'austria', 'azerbaijan', 'bahamas', 'bahrain', 'bangladesh', 'barbados',
    'belarus', 'belgium', 'belize', 'benin', 'bhutan', 'bolivia', 'bosnia', 'botswana',
    'brazil', 'brunei', 'bulgaria', 'burkina faso', 'burundi', 'cambodia', 'cameroon',
    'canada', 'chad', 'chile', 'china', 'colombia', 'comoros', 'congo', 'costa rica',
    'croatia', 'cuba', 'cyprus', 'czech republic', 'czechia', 'denmark', 'djibouti',
    'dominica', 'dominican republic', 'ecuador', 'egypt', 'el salvador', 'eritrea',
    'estonia', 'ethiopia', 'fiji', 'finland', 'france', 'gabon', 'gambia', 'georgia',
    'germany', 'ghana', 'greece', 'grenada', 'guatemala', 'guinea', 'guyana', 'haiti',
    'honduras', 'hungary', 'iceland', 'india', 'indonesia', 'iran', 'iraq', 'ireland',
    'israel', 'italy', 'jamaica', 'japan', 'jordan', 'kazakhstan', 'kenya', 'kiribati',
    'korea', 'south korea', 'north korea', 'kuwait', 'kyrgyzstan', 'laos', 'latvia',
    'lebanon', 'lesotho', 'liberia', 'libya', 'liechtenstein', 'lithuania', 'luxembourg',
    'madagascar', 'malawi', 'malaysia', 'maldives', 'mali', 'malta', 'mauritania',
    'mauritius', 'mexico', 'moldova', 'monaco', 'mongolia', 'montenegro', 'morocco',
    'mozambique', 'myanmar', 'namibia', 'nauru', 'nepal', 'netherlands', 'new zealand',
    'nicaragua', 'niger', 'nigeria', 'norway', 'oman', 'pakistan', 'palau', 'panama',
    'papua new guinea', 'paraguay', 'peru', 'philippines', 'poland', 'portugal', 'qatar',
    'romania', 'russia', 'russian federation', 'rwanda', 'samoa', 'saudi arabia',
    'senegal', 'serbia', 'seychelles', 'sierra leone', 'singapore', 'slovakia', 'slovenia',
    'somalia', 'south africa', 'spain', 'sri lanka', 'sudan', 'suriname', 'sweden',
    'switzerland', 'syria', 'taiwan', 'tajikistan', 'tanzania', 'thailand', 'togo',
    'tonga', 'trinidad', 'trinidad and tobago', 'tunisia', 'turkey', 'turkmenistan',
    'tuvalu', 'uganda', 'ukraine', 'united arab emirates', 'uae', 'united kingdom', 'uk',
    'united states', 'usa', 'us', 'uruguay', 'uzbekistan', 'vanuatu', 'venezuela',
    'vietnam', 'viet nam', 'yemen', 'zambia', 'zimbabwe', 'hong kong', 'macao', 'macau',
    'puerto rico', 'turkiye', 'türkiye',
    # Русский
    'россия', 'украина', 'беларусь', 'казахстан', 'узбекистан', 'таджикистан',
    'кыргызстан', 'туркменистан', 'азербайджан', 'армения', 'грузия', 'молдова',
    'латвия', 'литва', 'эстония', 'германия', 'франция', 'италия', 'испания',
    'великобритания', 'польша', 'нидерланды', 'бельгия', 'швеция', 'норвегия',
    'дания', 'финляндия', 'швейцария', 'австрия', 'португалия', 'греция', 'турция',
    'египет', 'израиль', 'иран', 'ирак', 'саудовская аравия', 'оаэ', 'индия',
    'китай', 'япония', 'южная корея', 'таиланд', 'вьетнам', 'индонезия',
    'малайзия', 'филиппины', 'австралия', 'канада', 'мексика', 'бразилия',
    'аргентина', 'чили', 'колумбия', 'перу', 'венесуэла', 'куба', 'сша', 'юар',
    'нигерия', 'кения', 'марокко', 'алжир', 'тунис', 'ливия', 'румыния',
    'болгария', 'хорватия', 'сербия', 'чехия', 'словакия', 'словения', 'венгрия',
    'ирландия', 'исландия', 'кипр', 'мальта', 'люксембург', 'монако', 'сингапур',
    'пакистан', 'бангладеш', 'непал',
    # ISO 2-letter codes
    'af', 'al', 'dz', 'ad', 'ao', 'ar', 'am', 'au', 'at', 'az', 'bs', 'bh', 'bd',
    'bb', 'by', 'be', 'bz', 'bj', 'bt', 'bo', 'ba', 'bw', 'br', 'bn', 'bg', 'bf',
    'bi', 'kh', 'cm', 'ca', 'td', 'cl', 'cn', 'co', 'km', 'cg', 'cr', 'hr', 'cu',
    'cy', 'cz', 'dk', 'dj', 'dm', 'do', 'ec', 'eg', 'sv', 'er', 'ee', 'et', 'fj',
    'fi', 'fr', 'ga', 'gm', 'ge', 'de', 'gh', 'gr', 'gd', 'gt', 'gn', 'gy', 'ht',
    'hn', 'hu', 'is', 'in', 'id', 'ir', 'iq', 'ie', 'il', 'it', 'jm', 'jp', 'jo',
    'kz', 'ke', 'ki', 'kr', 'kw', 'kg', 'la', 'lv', 'lb', 'ls', 'lr', 'ly', 'li',
    'lt', 'lu', 'mg', 'mw', 'my', 'mv', 'ml', 'mt', 'mr', 'mu', 'mx', 'md', 'mc',
    'mn', 'me', 'ma', 'mz', 'mm', 'na', 'nr', 'np', 'nl', 'nz', 'ni', 'ne', 'ng',
    'no', 'om', 'pk', 'pw', 'pa', 'pg', 'py', 'pe', 'ph', 'pl', 'pt', 'qa', 'ro',
    'ru', 'rw', 'ws', 'sa', 'sn', 'rs', 'sc', 'sl', 'sg', 'sk', 'si', 'so', 'za',
    'es', 'lk', 'sd', 'sr', 'se', 'ch', 'sy', 'tw', 'tj', 'tz', 'th', 'tg', 'to',
    'tt', 'tn', 'tr', 'tm', 'tv', 'ug', 'ua', 'ae', 'gb', 'us', 'uy', 'uz', 'vu',
    've', 'vn', 'ye', 'zm', 'zw',
}

# CSV-заголовки для автоопределения
_HEADER_EMAIL = {'email', 'e-mail', 'mail', 'email_address', 'emailaddress', 'email address', 'почта', 'емейл', 'емайл'}
_HEADER_NAME = {'name', 'first_name', 'firstname', 'last_name', 'lastname', 'full_name', 'fullname',
                'first name', 'last name', 'full name', 'имя', 'фамилия', 'фио', 'username', 'user_name'}
_HEADER_GENDER = {'gender', 'sex', 'пол', 'гендер'}
_HEADER_COUNTRY = {'country', 'location', 'region', 'страна', 'город', 'город/страна', 'geo', 'loc',
                   'country_code', 'country code', 'nationality'}


def clean_input_line_fast(line):
    """Снимает нумерацию вида "12. " в начале строки.

    Мусор на входе не роняет: сюда приходят строки из ЧУЖИХ файлов, а
    падение внутри обработки адреса проглатывается except-ом уровнем выше —
    адрес молча выпадет из выдачи, а счётчик его засчитает.
    """
    if not isinstance(line, str):
        return ""
    return CLEAN_PREFIX_RE.sub('', line.strip())


def _detect_delimiter(sample_lines):
    """Определяет разделитель по первым строкам файла."""
    candidates = [',', ';', ':', '|', '\t']
    best_delim = ':'
    best_score = 0

    # Сюда приходит выборка из ЧУЖОГО файла. Нестрока в списке — не повод
    # ронять чтение всей базы: падение уровнем выше проглатывается, и адреса
    # молча выпадут из выдачи.
    if not sample_lines or isinstance(sample_lines, (str, bytes)):
        return best_delim
    try:
        sample_lines = [line for line in sample_lines if isinstance(line, str)]
    except TypeError:
        return best_delim

    for delim in candidates:
        counts = [line.count(delim) for line in sample_lines if line.strip()]
        if not counts:
            continue
        # Стабильность: все строки дают одинаковое кол-во частей?
        parts_counts = [c + 1 for c in counts]
        if len(set(parts_counts)) == 1 and parts_counts[0] > 1:
            # Идеальная стабильность — все строки делятся одинаково
            score = parts_counts[0] * 100  # Высший приоритет
        elif counts:
            # Средняя частота * стабильность
            avg = sum(counts) / len(counts)
            stability = 1 - (max(counts) - min(counts)) / (max(counts) + 1)
            score = avg * stability
        else:
            score = 0

        if score > best_score:
            best_score = score
            best_delim = delim

    return best_delim


def _is_known_name(word):
    """Знает ли индекс такое имя. Индекс подгружается лениво и не обязателен.

    Импорт локальный намеренно: streamer читает файлы и не должен тянуть за
    собой парсер имён на каждом запуске. Если индекса нет, ответ «не знаю» —
    и классификация ведёт себя ровно так, как вела до его появления.
    """
    try:
        from core.parser.names_index import is_known_name
    except Exception:
        return False
    try:
        return is_known_name(word)
    except Exception:
        return False


def _classify_field(value):
    """Определяет тип поля: 'email', 'gender', 'country', 'name', 'junk'."""
    if not isinstance(value, str) or not value.strip():
        return 'empty'

    v = value.strip()
    v_lower = v.lower()

    # Email — однозначно по @
    if _EMAIL_RE.fullmatch(v):
        return 'email'

    # Имя ящика на кириллице образцом не ловится: он собран из ASCII-atext.
    # Адрес от этого адресом быть не перестаёт (RFC 6531), а объявить его
    # именем или мусором значило бы потерять его молча — без вердикта и без
    # строки в логе. Спрашивать грамматику стало безопасно только после
    # того, как она перестала признавать целую строку с запятыми одним
    # законным адресом (см. _UTF8_LOCAL_RE в core/email_syntax.py).
    if '@' in v and validate_email_syntax(v):
        return 'email'

    # Gender — точное совпадение со словарём
    if v_lower in _GENDER_VALUES:
        return 'gender'

    # Country — совпадение со словарём стран
    if v_lower in _COUNTRY_VALUES:
        return 'country'

    # Если это похоже на пароль (смешанные символы, цифры, спецсимволы) — junk
    has_special = bool(re.search(r'[!@#$%^&*()_+=\[\]{}<>?/\\|~`]', v))
    has_digit = bool(re.search(r'\d', v))
    has_alpha = bool(re.search(r'[a-zA-Zа-яА-ЯёЁ]', v))
    has_space = ' ' in v
    
    if has_special and has_digit:
        return 'junk'  # Скорее всего пароль (спецсимволы + цифры)
    
    if has_alpha and has_digit and not has_space and len(v) >= 4:
        # Буквы + цифры без пробелов — почти всегда пароль из связки
        # `email:password`, и такие базы здесь обычное дело.
        #
        # Но не всегда: в колонке имени встречается `Mohammed2`, `Anna3` —
        # человек с тем же именем, что и кто-то до него, получил номер при
        # выгрузке из CRM. Отличить одно от другого по форме нельзя, зато
        # можно СПРОСИТЬ: если отбросить хвост из цифр и остаток окажется
        # настоящим именем из индекса, это имя, а не пароль. Индекс на 43
        # тысячи отобранных имён, а не база на 138 млн: в базе такого размера
        # находится почти любое буквосочетание, и её ответ ничего не различал
        # бы. Про `password123` индекс скажет «нет», и пароль останется junk.
        stem = v.rstrip("0123456789")
        if len(stem) >= 3 and len(v) - len(stem) <= 4 and _is_known_name(stem):
            return 'name'
        return 'junk'

    # Если чисто числовое — junk (ID, телефон и т.д.)
    if v.isdigit():
        return 'junk'

    # Если содержит буквы и длина 1-60 — скорее всего имя
    if has_alpha and 1 < len(v) <= 60 and not has_special:
        return 'name'

    return 'junk'


def _detect_column_map(sample_lines, delimiter):
    """
    Определяет маппинг колонок по первым строкам.
    Возвращает dict: {column_index: field_type}
    field_type = 'email', 'name', 'gender', 'country', 'junk'
    """
    if not sample_lines or isinstance(sample_lines, (str, bytes)):
        return {0: 'email'}, False
    try:
        sample_lines = [line for line in sample_lines if isinstance(line, str)]
    except TypeError:
        return {0: 'email'}, False
    if not sample_lines:
        return {0: 'email'}, False
    if not isinstance(delimiter, str) or not delimiter:
        delimiter = ':'

    # Проверяем первую строку на наличие заголовков CSV
    first_line = sample_lines[0].strip()
    first_parts = [p.strip().lower() for p in first_line.split(delimiter)]

    header_map = {}
    is_header = False
    for i, part in enumerate(first_parts):
        if part in _HEADER_EMAIL:
            header_map[i] = 'email'
            is_header = True
        elif part in _HEADER_NAME:
            header_map[i] = 'name'
            is_header = True
        elif part in _HEADER_GENDER:
            header_map[i] = 'gender'
            is_header = True
        elif part in _HEADER_COUNTRY:
            header_map[i] = 'country'
            is_header = True

    if is_header and 'email' in header_map.values():
        return header_map, True  # True = первая строка это заголовок, пропустить

    # Нет заголовков — определяем по содержимому (голосование)
    # Берём до 10 строк для анализа
    analysis_lines = [line for line in sample_lines[:10] if line.strip()]
    if not analysis_lines:
        # Все строки пустые: колонок нет, но и падать не за что.
        return {0: 'email'}, False

    # Для каждой колонки считаем голоса
    votes = {}  # {col_index: {type: count}}
    for line in analysis_lines:
        if not line.strip():
            continue
        parts = line.split(delimiter)
        for i, part in enumerate(parts):
            if i not in votes:
                votes[i] = {}
            field_type = _classify_field(part.strip())
            votes[i][field_type] = votes[i].get(field_type, 0) + 1

    # Назначаем типы по большинству голосов
    col_map = {}
    assigned_types = set()

    # Сначала назначаем email (должен быть обязательно)
    for i in sorted(votes.keys()):
        if 'email' in votes[i]:
            email_votes = votes[i].get('email', 0)
            total_votes = sum(votes[i].values())
            if email_votes > total_votes * 0.5:  # Больше 50% строк содержат email
                col_map[i] = 'email'
                assigned_types.add('email')
                break

    # Если email не найден — берём первую колонку с хотя бы одним email
    if 'email' not in assigned_types:
        for i in sorted(votes.keys()):
            if votes[i].get('email', 0) > 0:
                col_map[i] = 'email'
                assigned_types.add('email')
                break

    # Если email вообще нигде не найден — первая колонка (legacy fallback)
    if 'email' not in assigned_types:
        col_map[0] = 'email'
        assigned_types.add('email')

    # Остальные колонки
    for i in sorted(votes.keys()):
        if i in col_map:
            continue
        best_type = max(votes[i], key=votes[i].get) if votes[i] else 'junk'
        if best_type == 'email':
            best_type = 'junk'  # Уже назначили email
        if best_type in assigned_types and best_type in ('gender', 'country'):
            best_type = 'junk'  # Дубликат типа
        if best_type not in ('empty', 'junk'):
            assigned_types.add(best_type)
        col_map[i] = best_type

    return col_map, False  # False = нет заголовка


# Знаки, которые бывают ОБЁРТКОЙ вокруг адреса: угловые скобки из выгрузок
# почтовиков, кавычки, запятые, пробелы. Всё, что не из этого набора, —
# часть самого адреса, а не мусор.
_ОБЁРТКА = set(" \t\r\n\"'<>[](){},;:|*!?«»“”‘’`")


def _взять_адрес_целиком(часть, match):
    """Адрес из строки — но НЕ кусок из его середины.

    Образец ищет подстроку, похожую на адрес, и раньше её брали как есть.
    На `a(b)c@example.com` он находил `c@example.com` — и дальше проверялся
    и в отчёт попадал ДРУГОЙ ящик, а владелец видел вердикт о том, чего не
    загружал. Это ровно тот подлог, против которого написан весь остальной
    код, просто спрятанный в разборе строки.

    Правило: срезать можно только ОБЁРТКУ. Если перед найденным адресом
    стоит что-то ещё — строка испорчена, и отдавать надо её целиком, чтобы
    проверка синтаксиса честно сказала «битый адрес», а не выносила вердикт
    о соседнем ящике.

    МУСОР НА ВХОДЕ — ЭТО «ОТДАЙ КАК ЕСТЬ», А НЕ ПАДЕНИЕ. Функция вызывается
    на каждую строку базы, и исключение отсюда проглотил бы except уровнем
    выше: адрес молча исчез бы из выдачи, а счётчик его засчитал. Поймано
    фаззингом (tests/test_robustness.py), а не рассуждением.
    """
    if not isinstance(часть, str):
        return ""
    try:
        начало, конец = match.start(), match.end()
        match.group(0)
    except Exception:
        return часть

    # «Имя <адрес>» — стандартная форма выгрузок почтовиков, и отображаемое
    # имя там может быть каким угодно. Угловые скобки говорят прямо, где
    # кончается имя и начинается адрес, поэтому гадать не нужно.
    if начало and часть[начало - 1] == "<" and часть.find(">", конец) != -1:
        return match.group(0)

    if начало and any(з not in _ОБЁРТКА for з in часть[:начало]):
        return часть
    return match.group(0)


def _разделитель_снаружи(строка, разделитель):
    """Встречается ли разделитель ВНЕ кавычек и квадратных скобок.

    Нужен ровно для одного решения: дробить строку на колонки или считать её
    целым адресом. Случая два, и они противоположны.

    `user@[IPv6:2001:db8::1]` при разделителе «:» дробить НЕЛЬЗЯ: двоеточия
    там внутри домена-литерала, и от дробления до проверки доезжало
    `user@[ipv6` — адрес терялся молча.

    `Ivan|ivan@gmail.com` при разделителе «|» дробить НАДО. Вертикальная
    черта по RFC 5322 §3.2.3 входит в atext, то есть в имени ящика законна,
    и вся строка целиком проходит проверку синтаксиса. Пока разницы между
    этими случаями не было, файл с «|» отдавал наружу строку вместо адреса,
    причём на латинице тоже — ЗАМЕРЕНО на всех 49 комбинациях владельца.
    """
    if not isinstance(строка, str) or not isinstance(разделитель, str):
        return False
    if not разделитель:
        return False
    if len(разделитель) != 1:
        return разделитель in строка
    в_кавычках = False
    в_скобках = False
    экран = False
    for знак in строка:
        if экран:
            экран = False
            continue
        if знак == "\\":
            экран = True
            continue
        if знак == '"' and not в_скобках:
            в_кавычках = not в_кавычках
            continue
        if not в_кавычках:
            if знак == "[":
                в_скобках = True
                continue
            if знак == "]":
                в_скобках = False
                continue
        if знак == разделитель and not в_кавычках and not в_скобках:
            return True
    return False


def _адрес_из_части(часть):
    """Адрес из одной ячейки строки. Пусто — адреса в ней нет.

    Мусор на входе — это пустой ответ, а не падение: функция вызывается на
    каждую ячейку каждой строки ЧУЖОГО файла, и исключение отсюда проглотил
    бы except уровнем выше. Адрес молча исчез бы из выдачи, а счётчик его
    засчитал. Поймано фаззингом (tests/test_robustness.py).
    """
    if not isinstance(часть, str) or not часть:
        return ""
    match = _EMAIL_RE.search(часть)
    if match:
        return _взять_адрес_целиком(часть, match)
    # Кириллическое имя ящика образцом не ловится — он собран из ASCII-atext.
    # Молча выбросить такой адрес нельзя: он законен по RFC 6531.
    if "@" in часть and validate_email_syntax(часть):
        return часть
    return ""


# Хвосты, которые в англоязычных базах пишут ЧЕРЕЗ ЗАПЯТУЮ от имени:
# `William John Lynch, Sr`. Запятая там разделяет не колонки, а части одного
# имени, и при склейке её надо вернуть на место — иначе в имени останется
# «William John Lynch», а «Sr» уедет в страну.
_ХВОСТЫ_ИМЕНИ = {"jr", "sr", "ii", "iii", "iv", "phd", "md", "esq", "dds",
                 "dvm", "ret", "мл", "ст"}


def _склеить_имя(куски):
    """Собирает имя обратно из кусков, разъехавшихся по колонкам.

    Мусор на входе — пустое имя, а не падение (см. `_адрес_из_части`).
    """
    if not isinstance(куски, (list, tuple)):
        return ""
    имя = ""
    for кусок in куски:
        if not isinstance(кусок, str):
            continue
        кусок = кусок.strip().strip(",").strip()
        if not кусок:
            continue
        if not имя:
            имя = кусок
        elif кусок.lower().rstrip(".") in _ХВОСТЫ_ИМЕНИ:
            имя += ", " + кусок
        else:
            имя += " " + кусок
    return имя


def _разрешить_спор(parts, типы, свои):
    """Chad, Georgia, India, Kenya и Andy — это и страны, и живые имена.

    Словарь стран отвечает на них «страна», и в двухколоночном файле
    `Chad,chad@gmail.com` имя человека превратилось бы в страну Чад — то
    есть данные владельца были бы не потеряны, а ПОДМЕНЕНЫ, что хуже.
    ЗАМЕРЕНО индексом имён: Chad, Georgia, India, Israel, Jordan, Kenya,
    Mali, China отвечают «это имя» — восемь ловушек только среди частых.

    Спор решают два признака: если в той же строке есть ДРУГАЯ страна, не
    являющаяся именем, — спорная ячейка это имя; если имени в строке нет
    вовсе — тоже имя. В остальных случаях страна остаётся страной.

    Разбираются только ячейки из `свои` — те, где решало содержимое. Явное
    указание карты по файлу не пересуживается.

    Мусор на входе — ничего не делаем, а не падаем (см. `_адрес_из_части`).
    """
    if not isinstance(parts, list) or not isinstance(типы, list):
        return
    if not isinstance(свои, list):
        return
    предел = min(len(parts), len(типы))
    свои = [i for i in свои
            if isinstance(i, int) and not isinstance(i, bool)
            and 0 <= i < предел and isinstance(parts[i], str)]
    for спорный in ('country', 'gender'):
        индексы = [i for i in свои if типы[i] == спорный]
        if not индексы:
            continue

        # 1. Хвост имени — не страна. `Sr` совпал с кодом Суринама, а `Jr`
        #    ни с чем не совпал, и различать их словарём ISO бессмысленно: в
        #    англоязычной базе это приставка к фамилии. ЗАМЕРЕНО на файле
        #    владельца: строка `...,William John Lynch, Sr,United States`
        #    приезжала страной «Sr», а настоящая страна из четвёртой колонки
        #    терялась — то есть подмена, а не просто потеря.
        for i in list(индексы):
            if parts[i].lower().rstrip(".") in _ХВОСТЫ_ИМЕНИ:
                типы[i] = 'name'
                индексы.remove(i)

        # 2. Двухбуквенный код — слабое свидетельство: `Jo`, `Al`, `Ed`, `Md`
        #    это чаще имя или его хвост, чем Иордания, Албания, Эстония и
        #    Молдова. Стране, записанной словом, он не соперник.
        if any(len(parts[i]) > 2 for i in индексы):
            for i in list(индексы):
                if len(parts[i]) <= 2:
                    типы[i] = 'name' if _is_known_name(parts[i]) else 'junk'
                    индексы.remove(i)

        # 3. Страна, которую мы умеем НАЗВАТЬ, сильнее той, которую только
        #    опознали как слово из списка. ЗАМЕРЕНО на файле владельца:
        #    `Jamaica,jamaica.ivey@flash.net,male,USA` — здесь Jamaica это
        #    имя человека (видно по самому адресу), а страна стоит
        #    последней. То же с `Togo` и `Cuba`.
        if спорный == 'country' and len(индексы) > 1:
            узнанные = {i for i in индексы
                        if canonical_country(parts[i]) != parts[i]}
            if узнанные and len(узнанные) < len(индексы):
                for i in list(индексы):
                    if i not in узнанные:
                        типы[i] = 'name'
                        индексы.remove(i)

        # 4. Chad, Georgia, India и Andy — и страна (или пол), и живое имя.
        бесспорные = {i for i in индексы if not _is_known_name(parts[i])}
        for i in индексы:
            if i in бесспорные:
                continue
            if бесспорные or 'name' not in типы:
                типы[i] = 'name'


def _типы_полей(parts, col_map, карта_подходит):
    """Тип каждой ячейки строки: карта по файлу плюс разбор по содержимому.

    Карта надёжнее одиночной догадки — она собрана голосованием по десятку
    строк. Но она ОДНА НА ВЕСЬ ФАЙЛ, а раскладка внутри файла меняется от
    строки к строке. ЗАМЕРЕНО на `Получатели.txt` владельца: 345 921 строка
    с почтой в первой колонке и 66 812 во второй; страна лежит в третьей
    колонке (386 332 строки) и в четвёртой, а в карте этих колонок нет
    вовсе. Из-за этого страна и пол выбрасывались целиком, и софт потом
    угадывал страну по имени — с точностью около половины.

    Поэтому карта решает там, где ей есть что сказать, а где молчит —
    решает содержимое ячейки.

    Мусор на входе — пустой разбор, а не падение (см. `_адрес_из_части`).
    """
    if not isinstance(parts, list):
        return []
    if not isinstance(col_map, dict):
        col_map = {}
    типы = []
    свои = []          # индексы, где решало содержимое, а не карта
    for i, part in enumerate(parts):
        if not isinstance(part, str) or not part:
            типы.append('empty')
            continue
        назначено = col_map.get(i) if карта_подходит else None
        if назначено in ('email', 'name', 'gender', 'country'):
            типы.append(назначено)
            continue
        по_содержимому = _classify_field(part)
        if назначено == 'junk':
            # Колонка признана мусором голосованием по всему файлу — обычно
            # это пароль из связки `почта:пароль`. Переспорить такой вердикт
            # может только словарь (пол, страна), но не догадка «похоже на
            # имя»: на `secretword` она отвечает «имя», и в колонку «Имя»
            # владельца поехали бы чужие пароли.
            типы.append(по_содержимому
                        if по_содержимому in ('gender', 'country') else 'junk')
            if по_содержимому in ('gender', 'country'):
                свои.append(i)
            continue
        типы.append(по_содержимому)
        свои.append(i)
    _разрешить_спор(parts, типы, свои)
    return типы


def _parse_line_smart(line, delimiter, col_map):
    """Парсит строку с помощью определённой карты колонок."""
    if not isinstance(line, str):
        return "", {"name": "", "gender": "", "country": ""}
    if not isinstance(delimiter, str) or not delimiter:
        delimiter = ':'
    if not isinstance(col_map, dict):
        col_map = {}

    # Строка, которая УЖЕ является законным адресом, не разбирается вовсе —
    # но только если разделитель файла в ней не встречается. Почему обе
    # половины этого условия нужны, написано у `_разделитель_снаружи`.
    целая = line.strip()
    if (целая and not _разделитель_снаружи(целая, delimiter)
            and validate_email_syntax(целая)):
        return целая, {"name": "", "gender": "", "country": ""}

    parts = [часть.strip() for часть in line.split(delimiter)]

    # Подходит ли карта ЭТОЙ строке. Признак один и проверяемый: почта лежит
    # там, где карта её обещала. Если не лежит — карта про эту строку не
    # знает ничего, и строка разбирается по содержимому целиком.
    индекс_почты = next((i for i, тип in sorted(col_map.items())
                         if тип == 'email'), None)
    карта_подходит = bool(
        индекс_почты is not None
        and 0 <= индекс_почты < len(parts)
        and _адрес_из_части(parts[индекс_почты]))

    типы = _типы_полей(parts, col_map, карта_подходит)

    email = ""
    gender = ""
    country = ""
    куски_имени = []
    for i, part in enumerate(parts):
        if not part:
            continue
        тип = типы[i]
        if тип == 'email':
            if not email:
                # Ячейка может быть испорчена (`a(b)c@example.com`) — тогда
                # `_адрес_из_части` вернёт её целиком либо пусто, и наружу
                # уедет то, что было в файле, а не соседний ящик.
                email = _адрес_из_части(part) or part
        elif тип == 'gender':
            if not gender:
                gender = part
        elif тип == 'country':
            if not country:
                country = part
        elif тип == 'name':
            куски_имени.append(part)
        # 'junk' и 'empty' — игнорируем

    # Почта не нашлась ни по карте, ни по содержимому — последняя попытка:
    # ищем адрес внутри любой ячейки.
    if not email or '@' not in email:
        for part in parts:
            найдено = _адрес_из_части(part)
            if найдено:
                email = найдено
                break

    # Ячейка с «собакой», из которой адрес не вынимается, — это ИСПОРЧЕННЫЙ
    # адрес, а не мусор. ЗАМЕРЕНО на файле владельца: таких строк 80, и все
    # испорчены в самом файле — `ISABELGUTIERREZ@BAMMODELS` (домен без зоны),
    # `docchristian.@hotmail.com` (точка перед собакой), `jumps@aol. com`
    # (пробел внутри), `www.wolfdavinchi@.com`.
    #
    # Отдавать её наружу обязательно. Прежний разбор так и делал: адрес
    # доезжал до проверки, получал честное «неправильный синтаксис», и
    # владелец видел его в отчёте. Если выбросить строку здесь, контакт
    # исчезнет молча — ни вердикта, ни строки в логе, ни разницы в счётчике.
    # Это ровно то, что запрещено: тихая потеря хуже видимого отказа.
    if not email or '@' not in email:
        for part in parts:
            if '@' in part:
                email = part
                break

    name = _склеить_имя(куски_имени)
    # Ячейка, из которой в итоге взята почта, не должна вторым лицом уехать
    # в имя. ЗАМЕРЕНО до правки на файле владельца: 66 824 строки приезжали
    # с собственным адресом в колонке «Имя».
    if name and email and name == email.strip():
        name = ""

    return email, {"name": name,
                   "gender": canonical_gender(gender),
                   "country": canonical_country(country)}


class StreamLoader:
    """Утилита для потокового чтения данных из различных источников с умным автоопределением формата"""
    def __init__(self, sources):
        self.sources = sources

    def _read_sample(self, source, max_lines=20):
        """Читает первые N строк для анализа формата."""
        lines = []
        if source["type"] == "text":
            for line in source["content"].split("\n"):
                if line.strip():
                    lines.append(line.strip())
                if len(lines) >= max_lines:
                    break
        elif source["type"] == "file":
            filepath = source["path"]
            if os.path.exists(filepath):
                with open_text(filepath) as f:
                    for line in f:
                        if line.strip():
                            lines.append(line.strip())
                        if len(lines) >= max_lines:
                            break
        return lines

    def stream_emails(self):
        """Генератор, который выдает пары (email, data) с умным парсингом."""
        for source in self.sources:
            # Шаг 1: Прочитать сэмпл для анализа формата
            sample = self._read_sample(source)
            if not sample:
                continue

            # Шаг 2: Определить разделитель
            delimiter = _detect_delimiter(sample)

            # Шаг 3: Определить маппинг колонок
            col_map, has_header = _detect_column_map(sample, delimiter)

            # Шаг 4: Стримить данные
            if source["type"] == "text":
                lines_iter = iter(source["content"].split("\n"))
            elif source["type"] == "file":
                filepath = source["path"]
                if not os.path.exists(filepath):
                    continue
                lines_iter = open_text(filepath)
            else:
                continue

            first_line = True
            try:
                for line in lines_iter:
                    line = line.strip()
                    if not line:
                        continue

                    # Пропускаем заголовок CSV
                    if first_line and has_header:
                        first_line = False
                        continue
                    first_line = False

                    # Приведение входа ДО разбора строки, а не после.
                    #
                    # Первая редакция ставила его после `_parse_line_smart`, и
                    # это было бесполезно: разбор уже успевал взять первое
                    # поле из «a@x.com, b@y.com» и уже успевал испортить
                    # `iv<невидимый>an@gmail.com`, отдав `an@gmail.com` —
                    # адрес обрезался ровно по невидимому знаку. Замерено
                    # обоими случаями.
                    line = normalize_input(line)
                    email, data = _parse_line_smart(line, delimiter, col_map)

                    # В одной строке бывает НЕ ОДИН адрес. Замерено до
                    # правки: «a@x.com, b@y.com» давало только первый —
                    # второй исчезал молча. Это хуже ложного Invalid: адрес
                    # не назван мёртвым, он просто пропадает, и инвариант
                    # «подано = выдано» этого не заметит, потому что считает
                    # ровно то, что загрузчик отдал.
                    несколько = split_addresses(line)
                    if len(несколько) > 1:
                        for один in несколько:
                            готовый = _lower_domain_only(
                                clean_input_line_fast(один).strip())
                            if готовый and "@" in готовый:
                                yield готовый, dict(data)
                        continue

                    # Базовая очистка email.
                    #
                    # К нижнему регистру приводится ТОЛЬКО домен. Имя ящика по
                    # RFC 5321 §2.4 регистрозависимо, и толковать его вправе
                    # только сервер назначения. Пока здесь стоял общий
                    # .lower(), исходная строка владельца переписывалась ещё
                    # на загрузке — до того, как её сохраняли в OriginalEmail,
                    # — и наружу, в выгрузку и в рассылку, уезжал НЕ ТОТ
                    # адрес, который он загрузил.
                    #
                    # Сравнение (дедуп, вычитание отписок, ключ кэша) считает
                    # свой ключ в нижнем регистре отдельно: там это сравнение,
                    # а не данные.
                    if email:
                        email = _lower_domain_only(
                            clean_input_line_fast(email).strip())

                    if email and '@' in email:
                        yield email, data
            finally:
                # Закрываем файл если открывали
                if source["type"] == "file" and hasattr(lines_iter, 'close'):
                    lines_iter.close()

    def stream_lines(self):
        """Генератор для прокси и дорков (без изменений)"""
        for source in self.sources:
            if source["type"] == "text":
                for line in source["content"].split("\n"):
                    line = line.strip()
                    if line:
                        yield clean_input_line_fast(line)
            elif source["type"] == "file":
                filepath = source["path"]
                if os.path.exists(filepath):
                    with open_text(filepath) as f:
                        for line in f:
                            line = line.strip()
                            if line:
                                yield clean_input_line_fast(line)

    # Размер куска при подсчёте строк. Мегабайт — компромисс между числом
    # системных вызовов и памятью: меньше даёт лишние вызовы, больше уже не
    # ускоряет, потому что упирается в скорость диска.
    _COUNT_CHUNK = 1 << 20

    def count_total_lines(self):
        """Точное число строк во всех источниках, без загрузки их в память.

        Читаем кусками и считаем переводы строк, а не итерируем построчно.
        Построчная итерация на каждой строке создаёт объект bytes, и на файле
        в 700 МБ это сотни миллионов ненужных объектов: тот же ответ получался
        в разы дольше. Здесь же вся работа — это str.count по куску, то есть
        один проход memchr на уровне Си.
        """
        total = 0
        for source in self.sources:
            if source["type"] == "text":
                total += len([line for line in source["content"].split("\n") if line.strip()])
            elif source["type"] == "file":
                filepath = source["path"]
                if not os.path.exists(filepath):
                    continue
                try:
                    with open(filepath, "rb") as handle:
                        tail = b""
                        while True:
                            chunk = handle.read(self._COUNT_CHUNK)
                            if not chunk:
                                break
                            total += chunk.count(b"\n")
                            tail = chunk[-1:]
                        # Последняя строка без перевода в конце файла тоже строка.
                        if tail and tail != b"\n":
                            total += 1
                except OSError:
                    continue
        return total

    # Сколько строк нюхать, чтобы оценить среднюю длину строки. Двести строк
    # хватает: разброс длин внутри одного файла невелик, а ошибка оценки в
    # несколько процентов знаменателю прогресс-бара безразлична.
    _ESTIMATE_SAMPLE = 200

    def estimate_total_lines(self):
        """Оценка числа строк ПО РАЗМЕРУ ФАЙЛА, без чтения его целиком.

        Зачем нужна отдельно от точного счёта. Прогон начинался с точного
        подсчёта всех строк — то есть с полного прохода по файлу ДО первого
        проверенного адреса. На базе в сотни мегабайт это минуты, в течение
        которых окно показывает 0/0 и выглядит зависшим, хотя работа даже не
        начиналась. Знаменателю прогресс-бара точность не нужна: настоящее
        число уникальных адресов всё равно известно только фидеру, и он его
        уточняет, когда закончит.

        Нюхаем файл В ТРЁХ МЕСТАХ — в начале, в середине и ближе к концу — и
        делим размер на среднюю длину строки. Пробы только из начала файла
        недостаточно, и это измерено: на реальном списке дорков в 712 МБ
        оценка по первым двумстам строкам ошиблась ВДВОЕ, потому что короткие
        запросы лежали в начале, а длинные в конце. Три точки убирают перекос
        почти полностью и стоят двух лишних seek — то есть ничего.
        """
        total = 0
        for source in self.sources:
            if source["type"] == "text":
                total += len([line for line in source["content"].split("\n") if line.strip()])
                continue
            if source["type"] != "file":
                continue
            filepath = source["path"]
            if not os.path.exists(filepath):
                continue
            try:
                size = os.path.getsize(filepath)
                if not size:
                    continue
                sampled = 0
                sampled_bytes = 0
                per_point = max(1, self._ESTIMATE_SAMPLE // 3)
                with open(filepath, "rb") as handle:
                    for fraction in (0.0, 0.5, 0.85):
                        offset = int(size * fraction)
                        if offset:
                            handle.seek(offset)
                            # Прыжок почти наверняка попал в середину строки —
                            # её огрызок в статистику брать нельзя.
                            handle.readline()
                        taken = 0
                        for raw in handle:
                            sampled += 1
                            sampled_bytes += len(raw)
                            taken += 1
                            if taken >= per_point:
                                break
                        if not taken:
                            break   # дошли до конца файла, дальше проб нет
                if not sampled or not sampled_bytes:
                    continue
                if sampled_bytes >= size:
                    # Файл целиком уместился в выборку — оценка стала точной.
                    total += sampled
                else:
                    total += max(sampled, int(size / (sampled_bytes / sampled)))
            except OSError:
                continue
        return total
