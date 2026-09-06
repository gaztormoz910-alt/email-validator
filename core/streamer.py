import os
import re

from core.email_syntax import (harvest_pattern, validate_email_syntax,
                               _lower_domain_only)
from core.inputnorm import normalize_input, split_addresses
from core.provider import best_address, canonical_country, canonical_gender

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
    'united states', 'united states of america', 'usa', 'us', 'great britain',
    'uruguay', 'uzbekistan', 'vanuatu', 'venezuela',
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

    # Та же защита с ПРАВОЙ стороны, но только для одного знака — «собаки».
    # `bunnellsabunnells@yahoo.com@hotmail.com` образец обрывает на первой
    # зоне и отдаёт `bunnellsabunnells@yahoo.com` — законный адрес, который
    # МОЖЕТ СУЩЕСТВОВАТЬ и принадлежать другому человеку. Владелец получил бы
    # настоящий вердикт про чужой ящик и ни одного признака подмены.
    #
    # Шире эту проверку делать нельзя, и это не осторожность, а замер:
    # `ivan@gmail.com (личная)` — обычная пометка в выгрузках, и запрет на
    # любой хвост похоронил бы такие адреса. Собака же после адреса значит
    # ровно одно: строка склеена из двух и целой правды в ней нет.
    if часть[конец:конец + 1] == "@":
        return часть
    return match.group(0)


# Сколько строк нюхать, чтобы решить: имена в колонке или пароли. Двадцати
# строк, которых хватает на разделитель и карту, здесь мало — главный признак
# это ПОВТОРЯЕМОСТЬ значений, а на двадцати строках не повторяется ничто.
_ПРОБА_КОЛОНКИ = 300
_МИН_ПРОБА_КОЛОНКИ = 100


def _похоже_на_колонку_паролей(значения):
    """Колонка из выгрузки `почта:пароль`, притворившаяся колонкой имён.

    Пароль из одних букв (`secretword`) по форме неотличим от фамилии:
    правило «буквы вместе с цифрами — это пароль» его не ловит. Голосование
    по файлу называет такую колонку именем, и чужие пароли едут в базу.

    ОДНОГО ПРИЗНАКА НЕ ХВАТАЕТ, и это замерено на 500 значениях в наборе:

        набор                  разных   с пробелом   имя по первому слову
        имена владельца         0.70       низкая           0.87
        полные имена            1.00       1.00             1.00
        вьетнамские фамилии     0.02       0.00             0.40
        пароли                  0.85       0.00             0.00-0.30

    Индекс имён в одиночку не разделяет: вьетнамские фамилии дают 0.40, а
    пароли 0.20-0.30 — полосы перекрываются. Поэтому признака три, и все
    три обязаны сойтись; каждый из настоящих наборов спасается хотя бы
    одним с большим запасом.

    ОШИБАТЬСЯ ЗДЕСЬ МОЖНО ТОЛЬКО В ОДНУ СТОРОНУ. Сработав зря, правило
    выбросит колонку имён на всём файле — молча и целиком. Поэтому пороги
    выбраны с запасом, проба не меньше ста значений, а само решение
    ОБЪЯВЛЯЕТСЯ В ЛОГ (см. `on_note` у StreamLoader).
    """
    if not isinstance(значения, (list, tuple)):
        return False
    зн = [v.strip() for v in значения if isinstance(v, str) and v.strip()]
    if len(зн) < _МИН_ПРОБА_КОЛОНКИ:
        return False
    разных = len(set(v.lower() for v in зн)) / len(зн)
    с_пробелом = sum(1 for v in зн if " " in v) / len(зн)
    имён = sum(1 for v in зн if _is_known_name(v.split()[0])) / len(зн)
    return разных > 0.5 and с_пробелом < 0.2 and имён < 0.5


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


def _починить_пробел_в_домене(часть):
    """`jumpsdropskicks@aol. com` -> `jumpsdropskicks@aol.com`.

    Чинится ТОЛЬКО правая половина адреса, и вот почему это не переписывание
    данных владельца. Метка DNS пробела содержать не может физически, значит
    у испорченной правой половины ровно одно прочтение — догадки нет.

    Левую половину не трогаем никогда. У `donald.m ross@yahoo.com` прочтений
    три — `donald.mross`, `donald.m.ross`, `ross`, — и любое может привести к
    ЧУЖОМУ СУЩЕСТВУЮЩЕМУ ящику. Это ровно та подмена, против которой написан
    весь остальной код: вердикт был бы настоящий, но про другого человека.

    ЗАМЕРЕНО на файле владельца: 429 строк с пробелом внутри адреса.
    Починка требует, чтобы результат прошёл проверку синтаксиса, — иначе
    возвращаем пусто и строка уезжает на проверку как есть.

    Гарантия «левую не трогаем» держится не проверкой, а самим построением:
    `ящик` переносится в ответ дословно. Отдельного запрета на пробел слева
    здесь СТОЯТЬ НЕ ДОЛЖНО — обратный контроль показал, что он ничего не
    ловит (адрес с пробелом слева и так не проходит синтаксис), зато мешает
    законному случаю: `"john smith"@x. com` — имя ящика в кавычках, где
    пробел разрешён по RFC 5321 §4.1.2, и правая половина у него чинится
    ровно так же, как у всех.
    """
    if not isinstance(часть, str) or часть.count("@") != 1:
        return ""
    ящик, _, домен = часть.partition("@")
    if " " not in домен:
        return ""
    склеен = ящик + "@" + домен.replace(" ", "")
    return склеен if validate_email_syntax(склеен) else ""


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
    return _починить_пробел_в_домене(часть)


# `Ivan Petrov <ivan@gmail.com>` — стандартная форма выгрузок почтовых
# клиентов. Адрес отсюда брался и раньше (угловые скобки прямо говорят, где
# кончается имя), а вот отображаемое имя выбрасывалось вместе с обёрткой.
_ПОДПИСЬ_RE = re.compile(r'^\s*"?(?P<имя>[^<>@"]{1,80}?)"?\s*<[^<>]+>\s*$')


def _имя_из_обёртки(часть):
    """Отображаемое имя из формы `Ivan Petrov <ivan@gmail.com>`."""
    if not isinstance(часть, str) or "<" not in часть:
        return ""
    найдено = _ПОДПИСЬ_RE.match(часть)
    if not найдено:
        return ""
    имя = найдено.group("имя").strip().strip(",").strip()
    # Подпись бывает и мусором, и повтором самого адреса. Пропускаем только
    # то, что разбор ячейки и так назвал бы именем.
    if not имя or "@" in имя or _classify_field(имя) != 'name':
        return ""
    return имя


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
        # Кавычка с краю — остаток формы `"Doe, John" <jd@x.com>`, которую
        # разделитель разрезал пополам. Снимаем её ТОЛЬКО при нечётном числе
        # кавычек: замер на файле владельца показал `Gregorio "Greg"` —
        # прозвище в кавычках внутри имени, и слепая обрезка краёв оставляла
        # от него `Gregorio "Greg`, то есть портила данные вместо починки.
        # Апостроф в `O'Brien` — часть фамилии, его не трогаем никогда.
        if кусок.count('"') % 2:
            кусок = кусок.strip('"').strip()
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

        # 3. Слово, которое видно В САМОМ АДРЕСЕ, — это имя человека, а не
        #    страна. ЗАМЕРЕНО на файле владельца:
        #    `Jamaica,jamaica.ivey@flash.net,male,USA` — Ямайка тут имя, и
        #    доказательство лежит в локальной части адреса.
        #
        #    Сравнение идёт ПО ЧАСТЯМ имени ящика, а не подстрокой. Замер
        #    показал, почему: `usa` случайно лежит внутри
        #    `tanjusaymontejesseal@yahoo.com`, и подстрочный поиск отнимал у
        #    таких строк страну. Части — это то, что человек отделил точкой,
        #    подчёркиванием или дефисом: `germany.tongish` -> germany.
        if len(индексы) > 1 or 'name' not in типы:
            куски_ящика = set()
            for j, тип in enumerate(типы):
                if тип == 'email' and j < len(parts):
                    ящик = parts[j].rsplit("@", 1)[0].lower()
                    куски_ящика = {к for к in re.split(r'[^a-zа-яё]+', ящик)
                                   if len(к) >= 3}
                    break
            if куски_ящика:
                for i in list(индексы):
                    if parts[i].lower() in куски_ящика:
                        типы[i] = 'name'
                        индексы.remove(i)

        # 4. Chad, Georgia, India и Andy — и страна (или пол), и живое имя.
        бесспорные = {i for i in индексы if not _is_known_name(parts[i])}
        for i in list(индексы):
            if i in бесспорные:
                continue
            if бесспорные or 'name' not in типы:
                типы[i] = 'name'
                индексы.remove(i)

        # 5. Двух стран (или двух полов) у человека не бывает. Если после
        #    всех правил кандидатов всё ещё больше одного, побеждает
        #    ПОСЛЕДНИЙ: во всех раскладках, замеренных на файле владельца,
        #    страна стоит последним полем — в трёхколоночных строках третьим
        #    (386 332 строки), в четырёхколоночных четвёртым. Проигравший
        #    уходит в имя, а не в мусор: это слово из файла, и терять его
        #    незачем. `Togo,cindy023@gmail.com,male,USA` -> имя Togo,
        #    страна США.
        #
        #    Это тай-брейк для НЕВОЗМОЖНОЙ строки, а не предположение о
        #    порядке полей: при одном кандидате правило не работает вовсе.
        for i in индексы[:-1]:
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
    ячейка_почты = -1
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
                ячейка_почты = i
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
        for i, part in enumerate(parts):
            найдено = _адрес_из_части(part)
            if найдено:
                email = найдено
                ячейка_почты = i
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
        for i, part in enumerate(parts):
            if '@' in part:
                email = part
                ячейка_почты = i
                break

    # Имя из формы `Ivan Petrov <ivan@gmail.com>`. Адрес из неё брался и
    # раньше, а имя пропадало вместе с обёрткой — так приходят выгрузки из
    # Outlook и Thunderbird целиком.
    if not куски_имени and 0 <= ячейка_почты < len(parts):
        подпись = _имя_из_обёртки(parts[ячейка_почты])
        if подпись:
            куски_имени.append(подпись)

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
    def __init__(self, sources, on_note=None):
        self.sources = sources
        # Куда сообщать о решениях, принятых по форме файла. Нужен ровно для
        # одного: отбраковка колонки объявляется вслух, а не делается молча.
        # Молчаливая потеря целой колонки — худшее, что этот код может
        # сделать с базой владельца.
        self.on_note = on_note

    def _сказать(self, текст):
        """Сообщает о решении по форме файла, если есть кому."""
        if not callable(self.on_note):
            return
        try:
            self.on_note(текст)
        except Exception:
            pass    # чужой обработчик не вправе уронить чтение базы

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
            # Шаг 1: Прочитать сэмпл для анализа формата.
            #
            # Проба глубокая, а разделитель и карта по-прежнему считаются по
            # первым двадцати строкам: они на этом настроены и проверены, а
            # менять им вход ради другой задачи значит менять их поведение.
            глубокая = self._read_sample(source, max_lines=_ПРОБА_КОЛОНКИ)
            sample = глубокая[:20]
            if not sample:
                continue

            # Шаг 2: Определить разделитель
            delimiter = _detect_delimiter(sample)

            # Шаг 3: Определить маппинг колонок
            col_map, has_header = _detect_column_map(sample, delimiter)

            # Шаг 3б: Колонка «имён», в которой имён нет, — это выгрузка
            # `почта:пароль`. Проверяется по всей глубокой пробе.
            for индекс in sorted(col_map):
                if col_map[индекс] != 'name':
                    continue
                значения = []
                for строка in глубокая:
                    ячейки = строка.split(delimiter)
                    if индекс < len(ячейки):
                        значения.append(ячейки[индекс])
                if _похоже_на_колонку_паролей(значения):
                    col_map[индекс] = 'junk'
                    self._сказать(
                        "Колонка %d похожа на пароли, а не на имена "
                        "(значения почти не повторяются и не найдены в "
                        "словаре имён) — в колонку «Имя» она не пойдёт."
                        % (индекс + 1))

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
            свёрнуто = 0        # отсеяно адресов
            строк_с_группой = 0  # в скольких строках была группа
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
                        готовые = []
                        for один in несколько:
                            готовый = _lower_domain_only(
                                clean_input_line_fast(один).strip())
                            if готовый and "@" in готовый:
                                готовые.append(готовый)
                        if готовые:
                            # Несколько адресов в ОДНОЙ строке — это один
                            # человек, а не несколько. Раньше отдавались все,
                            # и он получал столько писем, сколько у него
                            # ящиков: дедуп их не схлопывает, адреса-то
                            # разные. По решению владельца от 06.09.2026
                            # остаётся один, приоритетный (см.
                            # `address_priority` в core/provider.py).
                            if len(готовые) > 1:
                                свёрнуто += len(готовые) - 1
                                строк_с_группой += 1
                            yield best_address(готовые), data
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
                if свёрнуто:
                    self._сказать(
                        "Схлопнуто адресов одного человека: %d (в %d строках "
                        "стояло по нескольку). Оставлен один, приоритет у "
                        "крупного почтовика — Gmail и Яндекс отвечают с "
                        "любого IP, потом Outlook и iCloud, потом Yahoo и "
                        "AOL, потом корпоративные. Так человек не получит "
                        "несколько писем." % (свёрнуто, строк_с_группой))
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
