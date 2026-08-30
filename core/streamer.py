import os
import re

from core.encoding import open_text

CLEAN_PREFIX_RE = re.compile(r'^\d+[-.)\\]:й]*\s+')

# Regex для определения email в любой позиции
_EMAIL_RE = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')

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


def _parse_line_smart(line, delimiter, col_map):
    """Парсит строку с помощью определённой карты колонок."""
    if not isinstance(line, str):
        return "", {"name": "", "gender": "", "country": ""}
    if not isinstance(delimiter, str) or not delimiter:
        delimiter = ':'
    if not isinstance(col_map, dict):
        col_map = {}
    parts = line.split(delimiter)

    email = ""
    name = ""
    gender = ""
    country = ""

    for i, part in enumerate(parts):
        part = part.strip()
        if not part:
            continue
        col_type = col_map.get(i, 'junk')

        if col_type == 'email':
            # Дополнительная проверка — убедимся что это действительно email
            match = _EMAIL_RE.search(part)
            if match:
                email = match.group(0)
            else:
                email = part  # На случай если regex не сработал
        elif col_type == 'name':
            name = part
        elif col_type == 'gender':
            gender = part
        elif col_type == 'country':
            country = part
        # 'junk' и 'empty' — игнорируем

    # Fallback: если email не нашелся по маппингу — ищем @-паттерн в любом поле
    if not email or '@' not in email:
        for part in parts:
            match = _EMAIL_RE.search(part.strip())
            if match:
                email = match.group(0)
                break

    return email, {"name": name, "gender": gender, "country": country}


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

                    email, data = _parse_line_smart(line, delimiter, col_map)

                    # Базовая очистка email
                    if email:
                        email = clean_input_line_fast(email).strip().lower()

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
