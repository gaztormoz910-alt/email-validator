import os
import re

from core.email_syntax import (harvest_pattern, validate_email_syntax,
                               _lower_domain_only)
from core.inputnorm import normalize_input, split_addresses
from core.provider import best_address, canonical_country, canonical_gender

from core.encoding import open_text

CLEAN_PREFIX_RE = re.compile(r'^\d+[-.)\]:й]*\s+')

_EMAIL_RE = harvest_pattern(wide=True)

_GENDER_VALUES = {
    'male', 'female', 'm', 'f',
    'мужской', 'женский', 'мужчина', 'женщина', 'муж', 'жен',
    'мужик', 'man', 'woman', 'boy', 'girl',
    'mostly_male', 'mostly_female', 'andy', 'unknown',
}

_COUNTRY_VALUES = {
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

_HEADER_EMAIL = {'email', 'e-mail', 'mail', 'email_address', 'emailaddress', 'email address', 'почта', 'емейл', 'емайл'}
_HEADER_NAME = {'name', 'first_name', 'firstname', 'last_name', 'lastname', 'full_name', 'fullname',
                'first name', 'last name', 'full name', 'имя', 'фамилия', 'фио', 'username', 'user_name'}
_HEADER_GENDER = {'gender', 'sex', 'пол', 'гендер'}
_HEADER_COUNTRY = {'country', 'location', 'region', 'страна', 'город', 'город/страна', 'geo', 'loc',
                   'country_code', 'country code', 'nationality'}


def clean_input_line_fast(line):
    if not isinstance(line, str):
        return ""
    return CLEAN_PREFIX_RE.sub('', line.strip())


def _detect_delimiter(sample_lines):
    candidates = [',', ';', ':', '|', '\t']
    best_delim = ':'
    best_score = 0

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
        parts_counts = [c + 1 for c in counts]
        if len(set(parts_counts)) == 1 and parts_counts[0] > 1:
            score = parts_counts[0] * 100
        elif counts:
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
    try:
        from core.parser.names_index import is_known_name
    except Exception:
        return False
    try:
        return is_known_name(word)
    except Exception:
        return False


def _classify_field(value):
    if not isinstance(value, str) or not value.strip():
        return 'empty'

    v = value.strip()
    v_lower = v.lower()

    if _EMAIL_RE.fullmatch(v):
        return 'email'

    if '@' in v and validate_email_syntax(v):
        return 'email'

    if v_lower in _GENDER_VALUES:
        return 'gender'

    if v_lower in _COUNTRY_VALUES:
        return 'country'

    has_special = bool(re.search(r'[!@#$%^&*()_+=\[\]{}<>?/\\|~`]', v))
    has_digit = bool(re.search(r'\d', v))
    has_alpha = bool(re.search(r'[a-zA-Zа-яА-ЯёЁ]', v))
    has_space = ' ' in v
    
    if has_special and has_digit:
        return 'junk'
    
    if has_alpha and has_digit and not has_space and len(v) >= 4:
        stem = v.rstrip("0123456789")
        if len(stem) >= 3 and len(v) - len(stem) <= 4 and _is_known_name(stem):
            return 'name'
        return 'junk'

    if v.isdigit():
        return 'junk'

    if re.match(r'^"?[^\W\d_][\w .-]{0,30}:\s*\S', v):
        return 'junk'

    if has_alpha and 1 < len(v) <= 60 and not has_special:
        return 'name'

    return 'junk'


def _detect_column_map(sample_lines, delimiter):
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
        return header_map, True

    analysis_lines = [line for line in sample_lines[:10] if line.strip()]
    if not analysis_lines:
        return {0: 'email'}, False

    votes = {}
    for line in analysis_lines:
        if not line.strip():
            continue
        parts = line.split(delimiter)
        for i, part in enumerate(parts):
            if i not in votes:
                votes[i] = {}
            field_type = _classify_field(part.strip())
            votes[i][field_type] = votes[i].get(field_type, 0) + 1

    col_map = {}
    assigned_types = set()

    for i in sorted(votes.keys()):
        if 'email' in votes[i]:
            email_votes = votes[i].get('email', 0)
            total_votes = sum(votes[i].values())
            if email_votes > total_votes * 0.5:
                col_map[i] = 'email'
                assigned_types.add('email')
                break

    if 'email' not in assigned_types:
        for i in sorted(votes.keys()):
            if votes[i].get('email', 0) > 0:
                col_map[i] = 'email'
                assigned_types.add('email')
                break

    if 'email' not in assigned_types:
        col_map[0] = 'email'
        assigned_types.add('email')

    for i in sorted(votes.keys()):
        if i in col_map:
            continue
        best_type = max(votes[i], key=votes[i].get) if votes[i] else 'junk'
        if best_type == 'email':
            best_type = 'junk'
        if best_type in assigned_types and best_type in ('gender', 'country'):
            best_type = 'junk'
        if best_type not in ('empty', 'junk'):
            assigned_types.add(best_type)
        col_map[i] = best_type

    return col_map, False


_ОБЁРТКА = set(" \t\r\n\"'<>[](){},;:|*!?«»“”‘’`")


def _взять_адрес_целиком(часть, match):
    if not isinstance(часть, str):
        return ""
    try:
        начало, конец = match.start(), match.end()
        match.group(0)
    except Exception:
        return часть

    if начало and часть[начало - 1] == "<" and часть.find(">", конец) != -1:
        return match.group(0)

    if начало and any(з not in _ОБЁРТКА for з in часть[:начало]):
        return часть

    if часть[конец:конец + 1] == "@":
        return часть
    return match.group(0)


_ПРОБА_КОЛОНКИ = 300
_МИН_ПРОБА_КОЛОНКИ = 100


def _похоже_на_колонку_паролей(значения):
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
    if not isinstance(часть, str) or часть.count("@") != 1:
        return ""
    ящик, _, домен = часть.partition("@")
    if " " not in домен:
        return ""
    склеен = ящик + "@" + домен.replace(" ", "")
    return склеен if validate_email_syntax(склеен) else ""


def _адрес_из_части(часть):
    if not isinstance(часть, str) or not часть:
        return ""
    match = _EMAIL_RE.search(часть)
    if match:
        return _взять_адрес_целиком(часть, match)
    if "@" in часть and validate_email_syntax(часть):
        return часть
    return _починить_пробел_в_домене(часть)


_ПОДПИСЬ_RE = re.compile(r'^\s*"?(?P<имя>[^<>@"]{1,80}?)"?\s*<[^<>]+>\s*$')


def _имя_из_обёртки(часть):
    if not isinstance(часть, str) or "<" not in часть:
        return ""
    найдено = _ПОДПИСЬ_RE.match(часть)
    if not найдено:
        return ""
    имя = найдено.group("имя").strip().strip(",").strip()
    if not имя or "@" in имя or _classify_field(имя) != 'name':
        return ""
    return имя


_ПОДПИСЬ_ЦЕЛИКОМ_RE = re.compile(
    r'^\s*(?P<кв>"?)(?P<имя>[^<>@"]{1,80}?)(?P=кв)\s*<(?P<адрес>[^<>\s]+)>\s*$')


def _подпись_с_запятой(строка):
    if not isinstance(строка, str) or "," not in строка or "<" not in строка:
        return None
    найдено = _ПОДПИСЬ_ЦЕЛИКОМ_RE.match(строка)
    if not найдено:
        return None
    адрес = найдено.group("адрес")
    if not validate_email_syntax(адрес):
        return None
    подпись = найдено.group("имя").strip()
    if подпись.count(",") != 1:
        return None
    до, _, после = (кусок.strip() for кусок in подпись.partition(","))
    if not до or not после:
        return None
    if после.lower().rstrip(".") in _ХВОСТЫ_ИМЕНИ:
        return (адрес, до + ", " + после) if _classify_field(до) == 'name' else None
    if _classify_field(до) != 'name' or _classify_field(после) != 'name':
        return None
    в_кавычках = bool(найдено.group("кв"))
    if в_кавычках or (_is_known_name(после.split()[0])
                      and not _is_known_name(до.split()[0])):
        return адрес, после + " " + до
    return адрес, до + " " + после


_ХВОСТЫ_ИМЕНИ = {"jr", "sr", "ii", "iii", "iv", "phd", "md", "esq", "dds",
                 "dvm", "ret", "мл", "ст"}


def _склеить_имя(куски):
    if not isinstance(куски, (list, tuple)):
        return ""
    имя = ""
    for кусок in куски:
        if not isinstance(кусок, str):
            continue
        кусок = кусок.strip().strip(",").strip()
        if not кусок:
            continue
        if кусок.count('"') % 2:
            кусок = кусок.strip('"').strip()
        elif len(кусок) >= 2 and кусок[0] == '"' == кусок[-1] and '"' not in кусок[1:-1]:
            кусок = кусок[1:-1].strip()
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

        for i in list(индексы):
            if parts[i].lower().rstrip(".") in _ХВОСТЫ_ИМЕНИ:
                типы[i] = 'name'
                индексы.remove(i)

        if any(len(parts[i]) > 2 for i in индексы):
            for i in list(индексы):
                if len(parts[i]) <= 2:
                    типы[i] = 'name' if _is_known_name(parts[i]) else 'junk'
                    индексы.remove(i)

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

        бесспорные = {i for i in индексы if not _is_known_name(parts[i])}
        for i in list(индексы):
            if i in бесспорные:
                continue
            if бесспорные or 'name' not in типы:
                типы[i] = 'name'
                индексы.remove(i)

        for i in индексы[:-1]:
            типы[i] = 'name'


def _типы_полей(parts, col_map, карта_подходит):
    if not isinstance(parts, list):
        return []
    if not isinstance(col_map, dict):
        col_map = {}
    типы = []
    свои = []
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
    if not isinstance(line, str):
        return "", {"name": "", "gender": "", "country": ""}
    if not isinstance(delimiter, str) or not delimiter:
        delimiter = ':'
    if not isinstance(col_map, dict):
        col_map = {}

    целая = line.strip()
    if (целая and not _разделитель_снаружи(целая, delimiter)
            and validate_email_syntax(целая)):
        return целая, {"name": "", "gender": "", "country": ""}

    с_запятой = _подпись_с_запятой(целая)
    if с_запятой:
        return с_запятой[0], {"name": с_запятой[1], "gender": "", "country": ""}

    parts = [часть.strip() for часть in line.split(delimiter)]

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

    if not email or '@' not in email:
        for i, part in enumerate(parts):
            найдено = _адрес_из_части(part)
            if найдено:
                email = найдено
                ячейка_почты = i
                break

    if not email or '@' not in email:
        for i, part in enumerate(parts):
            if '@' in part:
                email = part
                ячейка_почты = i
                break

    if not куски_имени and 0 <= ячейка_почты < len(parts):
        подпись = _имя_из_обёртки(parts[ячейка_почты])
        if подпись:
            куски_имени.append(подпись)

    name = _склеить_имя(куски_имени)
    if name and email and name == email.strip():
        name = ""

    return email, {"name": name,
                   "gender": canonical_gender(gender),
                   "country": canonical_country(country)}


class StreamLoader:
    def __init__(self, sources, on_note=None):
        self.sources = sources
        self.on_note = on_note

    def _сказать(self, текст):
        if not callable(self.on_note):
            return
        try:
            self.on_note(текст)
        except Exception:
            pass

    def _read_sample(self, source, max_lines=20):
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
        for source in self.sources:
            глубокая = self._read_sample(source, max_lines=_ПРОБА_КОЛОНКИ)
            sample = глубокая[:20]
            if not sample:
                continue

            delimiter = _detect_delimiter(sample)

            col_map, has_header = _detect_column_map(sample, delimiter)

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
            свёрнуто = 0
            строк_с_группой = 0
            try:
                for line in lines_iter:
                    line = line.strip()
                    if not line:
                        continue

                    if first_line and has_header:
                        first_line = False
                        continue
                    first_line = False

                    line = normalize_input(line)
                    email, data = _parse_line_smart(line, delimiter, col_map)

                    несколько = split_addresses(line)
                    if len(несколько) > 1:
                        готовые = []
                        for один in несколько:
                            готовый = _lower_domain_only(
                                clean_input_line_fast(один).strip())
                            if готовый and "@" in готовый:
                                готовые.append(готовый)
                        if готовые:
                            if len(готовые) > 1:
                                свёрнуто += len(готовые) - 1
                                строк_с_группой += 1
                            yield best_address(готовые), data
                        continue

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
                if source["type"] == "file" and hasattr(lines_iter, 'close'):
                    lines_iter.close()

    def stream_lines(self):
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

    _COUNT_CHUNK = 1 << 20

    def count_total_lines(self):
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
                        if tail and tail != b"\n":
                            total += 1
                except OSError:
                    continue
        return total

    _ESTIMATE_SAMPLE = 200

    def estimate_total_lines(self):
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
                            handle.readline()
                        taken = 0
                        for raw in handle:
                            sampled += 1
                            sampled_bytes += len(raw)
                            taken += 1
                            if taken >= per_point:
                                break
                        if not taken:
                            break
                if not sampled or not sampled_bytes:
                    continue
                if sampled_bytes >= size:
                    total += sampled
                else:
                    total += max(sampled, int(size / (sampled_bytes / sampled)))
            except OSError:
                continue
        return total
