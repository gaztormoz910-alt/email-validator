# core/input_guard.py
"""Распознавание того, что именно владелец положил в поле ввода.

Зачем. Полей три — адреса, прокси, поисковые запросы — и перепутать их
проще простого: списки приходят одинаковыми txt-файлами, а имя файла ни о чём
не говорит. Раньше перепутанный список принимался молча, и ошибка всплывала
через минуту прогона в виде тысяч непонятных отказов.

Отдельная беда — раскладка. Строка `ивфт@пьфшд.сщь` появляется, когда адрес
набирают с включённой русской раскладкой, и на глаз она неотличима от
настоящего кириллического адреса.

Тут проходит важная граница, которую легко перейти по неосторожности:

    иван@почта.рф   — НАСТОЯЩИЙ адрес, кириллица в нём законна
    ивфт@пьфшд.сщь  — тот же ivan@gmail.com, набранный не в той раскладке

Резать всю кириллицу нельзя: домены .рф и .рус существуют, и валидатор обязан
их проверять. Поэтому раскладка распознаётся не по алфавиту, а по домену
верхнего уровня: у настоящего адреса он существует, у набранного не в той
раскладке — нет, зато после перевода раскладки строка становится нормальным
адресом. Оба случая закреплены тестами (tests/test_input_guard.py).
"""
import io
import os
import re

from core.encoding import open_text

# Сколько строк файла достаточно для опознания. Читать целиком нельзя: база на
# десять миллионов адресов встанет колом ровно на проверке, ради которой всё
# и затевалось. Тип списка виден по первым же строкам — если первые двести
# строк файла адреса, то это файл адресов.
SAMPLE_LINES = 200

KIND_EMAIL = "email"
KIND_PROXY = "proxy"
KIND_DORK = "dork"
KIND_UNKNOWN = "unknown"

KIND_TITLE = {
    KIND_EMAIL: "список адресов",
    KIND_PROXY: "список прокси",
    KIND_DORK: "поисковые запросы",
    KIND_UNKNOWN: "непонятно что",
}

# Куда какой список кладут. Используется в тексте отказа: назвать тип мало,
# надо сказать, в какое поле его нести.
KIND_FIELD = {
    KIND_EMAIL: "«Адреса для проверки»",
    KIND_PROXY: "«Прокси»",
    KIND_DORK: "«Поисковые запросы»",
}

# Разделители полей в базе адресов — те же, что распознаёт core/streamer.py.
# Список продублирован сознательно: streamer определяет разделитель
# статистикой по всему файлу, а тут нужно разобрать одну строку.
FIELD_SEPARATORS = ",;|\t"

# Операторы поисковых систем. Строка с любым из них — запрос, даже если в ней
# есть собака: дорк `site:linkedin.com "@gmail.com"` содержит и то и другое.
DORK_OPERATORS = (
    "site:", "intext:", "inurl:", "intitle:", "filetype:", "ext:",
    "allintext:", "allinurl:", "cache:", "related:", "link:", "before:",
    "after:", "define:", "imagesize:",
)

# Домены верхнего уровня не на латинице. Полного списка IANA тут нет и не
# нужно: важно отличить существующий кириллический домен от буквенной каши,
# получившейся из-за раскладки. Эти реально делегированы.
IDN_TLD = {
    "рф", "рус", "москва", "дети", "онлайн", "сайт", "ком", "орг", "укр",
    "бел", "бг", "срб", "мкд", "ею", "католик", "қаз", "мон", "рфс",
}

# ЙЦУКЕН -> QWERTY по физическим клавишам. Нужен только один направление:
# набранное русскими буквами переводится в латиницу.
_RU_TO_EN = {
    "й": "q", "ц": "w", "у": "e", "к": "r", "е": "t", "н": "y", "г": "u",
    "ш": "i", "щ": "o", "з": "p", "х": "[", "ъ": "]",
    "ф": "a", "ы": "s", "в": "d", "а": "f", "п": "g", "р": "h", "о": "j",
    "л": "k", "д": "l", "ж": ";", "э": "'",
    "я": "z", "ч": "x", "с": "c", "м": "v", "и": "b", "т": "n", "ь": "m",
    "б": ",", "ю": ".", "ё": "`",
}

_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HOST_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$")
_SCHEMES = ("socks5://", "socks4://", "socks://", "https://", "http://")


def fix_layout(text):
    """Переводит набранное русскими буквами в латиницу по клавишам."""
    out = []
    for char in str(text or ""):
        lower = char.lower()
        mapped = _RU_TO_EN.get(lower)
        if mapped is None:
            out.append(char)
        elif char.isupper() and mapped.isalpha():
            out.append(mapped.upper())
        else:
            out.append(mapped)
    return "".join(out)


def _is_host(value):
    """Похоже ли на хост: IP-адрес или доменное имя на латинице."""
    if not isinstance(value, str):
        return False
    return bool(_IP_RE.match(value) or _HOST_RE.match(value))


def _is_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= port <= 65535


def _tld_exists(domain):
    """Существует ли домен верхнего уровня у этой строки.

    Латинские не перечисляются: их почти две тысячи, список устаревает, и
    отвергнуть живой адрес из-за неполноты списка хуже, чем пропустить
    выдуманный — вердикт всё равно поставит SMTP. Не-ASCII проверяются по
    списку: именно там проходит граница с раскладкой.
    """
    if not isinstance(domain, str):
        return False
    if "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[1].strip().lower()
    if len(tld) < 2:
        return False
    if tld.isascii():
        # Зона в punycode состоит не из одних букв: .рф на проводе выглядит
        # как xn--p1ai. Проверка на isalpha() отвергала такой адрес, и база,
        # уже переведённая в punycode — а именно её отдаёт любой экспорт, —
        # объявлялась «не списком адресов» целиком.
        if tld.startswith("xn--"):
            return len(tld) > 4 and all(c.isalnum() or c == "-" for c in tld)
        return tld.isalpha()
    return _зона_idn_существует(tld)


def _зона_idn_существует(зона):
    """Существует ли эта не-латинская зона на самом деле.

    ЗАЧЕМ НЕ СПИСОК. Здесь проходит граница между настоящим адресом и строкой,
    набранной не в той раскладке: `иван@почта.рф` — адрес, `ивфт@пьфшд.сщь` —
    это `ivan@gmail.com` с включённой кириллицей. Отличает их ровно одно —
    существует ли зона.

    Рукописный перечень знал семнадцать зон из ста шестидесяти, которые
    делегированы на самом деле. Адрес в `.ελ`, `.中国`, `.ישראל` он адресом не
    считал — то есть файл таких контактов был бы отвергнут целиком, ещё до
    единой проверки. Приговора это не выносит, но работу не даёт начать.

    Список Mozilla знает их все. Рукописный перечень остаётся ПАРАШЮТОМ: нет
    файла списка — работаем по нему, а не перестаём работать.
    """
    # Мусор на входе — «такой зоны нет», а не падение: список или словарь в
    # роли ключа множества роняет поиск (`unhashable type`), а функция стоит
    # на пути КАЖДОЙ строки чужого файла. Поймано фаззингом набора.
    if not isinstance(зона, str) or not зона:
        return False
    try:
        from core.public_suffix import зоны_верхнего_уровня, правил_прочитано
        if правил_прочитано():
            return зона in зоны_верхнего_уровня()
    except Exception:
        pass
    return зона in IDN_TLD


def looks_like_email(value):
    """Разбирается ли строка как адрес. Не-ASCII здесь законен."""
    value = str(value or "").strip().strip("<>\"'")
    if value.count("@") != 1:
        return False
    local, _, domain = value.partition("@")
    if not local or not domain or " " in value:
        return False
    # Длины по БАЙТАМ в UTF-8, а не по символам: кириллическое имя из сорока
    # букв укладывается в лимит по символам и вылетает по байтам.
    if len(local.encode("utf-8")) > 64 or len(domain.encode("utf-8")) > 255:
        return False
    return _tld_exists(domain)


def looks_like_proxy(value):
    """Разбирается ли строка как прокси во всех форматах, что принимает движок.

    Форматы те же, что в core/proxy_transport.py: host:port,
    host:port:user:pass, user:pass@host:port, с любой схемой впереди.
    """
    value = str(value or "").strip()
    if not value or " " in value:
        return False

    had_scheme = False
    lowered = value.lower()
    for scheme in _SCHEMES:
        if lowered.startswith(scheme):
            value = value[len(scheme):]
            had_scheme = True
            break

    if "@" in value:
        creds, _, address = value.rpartition("@")
        if ":" not in creds:
            return False
        host, _, port = address.rpartition(":")
        return _is_host(host) and _is_port(port)

    parts = value.split(":")
    if len(parts) == 2:
        return _is_host(parts[0]) and _is_port(parts[1])
    if len(parts) == 4:
        return _is_host(parts[0]) and _is_port(parts[1])
    # Схема без порта — всё равно прокси, просто записанный небрежно.
    return had_scheme and _is_host(value)


def looks_like_dork(value):
    """Похожа ли строка на поисковый запрос."""
    value = str(value or "").strip()
    if not value:
        return False
    lowered = value.lower()
    if any(op in lowered for op in DORK_OPERATORS):
        return True
    # Запрос в кавычках — тоже запрос: `"@aol.com" контакты`.
    if '"' in value and " " in value:
        return True
    # Просто несколько слов без собаки и без двоеточия.
    if " " in value and "@" not in value and ":" not in value:
        return True
    return False


def detect_kind(line):
    """Что это за строка. Порядок проверок здесь и есть вся логика.

    Дорки идут первыми: запрос `site:linkedin.com "@gmail.com"` содержит и
    собаку, и двоеточие, и по любому другому порядку уехал бы в адреса или в
    прокси. Прокси идут раньше адресов из-за формата `user:pass@host:port` —
    в нём есть собака, но это не адрес.
    """
    line = str(line or "").strip()
    if not line or line.startswith("#"):
        return KIND_UNKNOWN

    if looks_like_dork(line):
        return KIND_DORK
    if looks_like_proxy(line):
        return KIND_PROXY
    if looks_like_email(line):
        return KIND_EMAIL

    # `Ivan Petrov <ivan@gmail.com>` — стандартная форма выгрузок почтовых
    # клиентов. Загрузчик её разбирает и берёт из неё ещё и имя, а страж
    # ввода про неё не знал. ЗАМЕРЕНО: выгрузка Outlook целиком отвергалась
    # окном со словами «ни одной строки, похожей на список адресов» — и при
    # вставке текстом, и при выборе файла. Расхождение между тем, что
    # принимает окно, и тем, что умеет движок, — это отказ владельцу в
    # данных, которые софт на самом деле разбирает.
    в_скобках = re.search(r"<([^<>]+)>", line)
    if в_скобках and looks_like_email(в_скобках.group(1).strip()):
        return KIND_EMAIL

    # База с дополнительными полями: ivan@gmail.com;Иван;Петров;США
    for separator in FIELD_SEPARATORS:
        if separator in line:
            for part in line.split(separator):
                if looks_like_email(part.strip()):
                    return KIND_EMAIL
    # Разделитель-двоеточие разбирается отдельно: у прокси он же служит
    # разделителем host:port, и до сюда доходят только строки, прокси не
    # являющиеся.
    if ":" in line:
        for part in line.split(":"):
            if looks_like_email(part.strip()):
                return KIND_EMAIL

    return KIND_UNKNOWN


def layout_suggestion(line):
    """Если строка набрана не в той раскладке — вернуть исправленную.

    Возвращает None, когда строка и так осмысленна. Настоящий кириллический
    адрес сюда не попадает: у него существующий домен верхнего уровня, и
    detect_kind опознаёт его как адрес ещё до этой проверки.
    """
    line = str(line or "").strip()
    if not line or detect_kind(line) != KIND_UNKNOWN:
        return None
    if not any(char.lower() in _RU_TO_EN for char in line):
        return None
    fixed = fix_layout(line)
    if fixed == line:
        return None
    return fixed if detect_kind(fixed) != KIND_UNKNOWN else None


def classify(lines, limit=SAMPLE_LINES):
    """Сводка по выборке строк: чего сколько и что это в целом.

    Возвращает словарь с числом строк каждого типа, доминирующим типом и
    примерами непонятных строк — их показывают владельцу, чтобы он видел, на
    чём именно споткнулась проверка, а не «в файле ошибка».
    """
    counts = {KIND_EMAIL: 0, KIND_PROXY: 0, KIND_DORK: 0, KIND_UNKNOWN: 0}
    samples = {KIND_EMAIL: [], KIND_PROXY: [], KIND_DORK: [], KIND_UNKNOWN: []}
    layout_fixes = []
    seen = 0

    # Строка — тоже итерируемое, но по СИМВОЛАМ: разбор одного адреса по
    # буквам дал бы «в файле 14 непонятных строк» вместо ответа. Отдельная
    # строка — это выборка из одной строки.
    if isinstance(lines, (str, bytes)):
        lines = [lines]
    elif lines is None or not hasattr(lines, "__iter__"):
        lines = []

    for raw in lines:
        line = str(raw or "").strip()
        if not line or line.startswith("#"):
            continue
        seen += 1
        if seen > limit:
            break
        kind = detect_kind(line)
        counts[kind] += 1
        if len(samples[kind]) < 3:
            samples[kind].append(line)
        if kind == KIND_UNKNOWN and len(layout_fixes) < 3:
            fixed = layout_suggestion(line)
            if fixed:
                layout_fixes.append((line, fixed))

    known = {k: v for k, v in counts.items() if k != KIND_UNKNOWN}
    dominant = max(known, key=lambda k: known[k]) if any(known.values()) else KIND_UNKNOWN
    return {
        "counts": counts,
        "samples": samples,
        "dominant": dominant,
        "checked": min(seen, limit),
        "layout": layout_fixes,
    }


# Какая доля строк должна быть «своей», чтобы список приняли. Не сто
# процентов: в живом файле всегда есть заголовок CSV, пустая строка с
# пробелом, случайная заметка. Требовать чистоты значит отвергать нормальные
# файлы, а это хуже, чем пропустить пару мусорных строк.
ACCEPT_SHARE = 0.6


def check(lines, expected, limit=SAMPLE_LINES):
    """Годится ли список для поля `expected`.

    Возвращает {"ok": bool, "reason": str, "summary": dict}. Причина написана
    так, чтобы её можно было показать владельцу без переписывания: она
    называет, что распознано, и куда это нести.
    """
    summary = classify(lines, limit=limit)
    counts = summary["counts"]
    checked = summary["checked"]

    # Неизвестное имя поля — это ошибка вызывающего кода, а не владельца.
    # Падение здесь запирало бы загрузку файла целиком, поэтому страж
    # молча пропускает: его дело — предупреждать, а не мешать работать.
    if not isinstance(expected, str) or expected not in KIND_TITLE:
        return {"ok": True, "reason": "", "summary": summary}

    if not checked:
        return {"ok": False, "reason": "Список пуст — проверять нечего.",
                "summary": summary}

    mine = counts.get(expected, 0)
    if mine / float(checked) >= ACCEPT_SHARE:
        return {"ok": True, "reason": "", "summary": summary}

    dominant = summary["dominant"]
    if dominant != KIND_UNKNOWN and dominant != expected:
        where = KIND_FIELD.get(dominant, "другое поле")
        example = (summary["samples"][dominant] or [""])[0]
        return {
            "ok": False,
            "reason": ("Это %s, а не %s. Пример строки: %s\n"
                       "Такой список кладут в поле %s."
                       % (KIND_TITLE[dominant], KIND_TITLE[expected],
                          example, where)),
            "summary": summary,
        }

    if summary["layout"]:
        typed, fixed = summary["layout"][0]
        return {
            "ok": False,
            "reason": ("Похоже, включена русская раскладка. Строка «%s» после "
                       "переключения читается как «%s» — исправьте раскладку и "
                       "вставьте заново." % (typed, fixed)),
            "summary": summary,
        }

    example = (summary["samples"][KIND_UNKNOWN] or [""])[0]
    return {
        "ok": False,
        "reason": ("Не удалось разобрать: ни одной строки, похожей на %s. "
                   "Пример непонятной строки: %s"
                   % (KIND_TITLE[expected], example)),
        "summary": summary,
    }


def check_text(text, expected):
    """Проверка вставленного текста."""
    return check(str(text or "").splitlines(), expected)


def check_file(path, expected, limit=SAMPLE_LINES):
    """Проверка файла по выборке первых строк.

    Файл не читается целиком сознательно: на базе в десять миллионов адресов
    полное чтение ради опознания типа стоило бы дороже самой проверки.
    """
    try:
        # Кодировка определяется по выборке байт. Читая cp1251 как UTF-8,
        # мы получали в каждой кириллической строке символы замены — и
        # страж честно объявлял базу «набранной не в той раскладке».
        with open_text(path) as handle:
            sample = []
            for line in handle:
                sample.append(line)
                # С запасом: пустые строки и комментарии не считаются, поэтому
                # значимых строк в выборке может оказаться меньше лимита.
                if len(sample) >= limit * 3:
                    break
    except (OSError, TypeError, ValueError) as error:
        # TypeError и ValueError сюда попадают из-за пути, которым файл не
        # открыть вовсе (None, число, строка с нулевым байтом). Для владельца
        # это тот же случай «файл не прочитан», и звучать должно так же.
        try:
            shown = os.path.basename(path)
        except Exception:
            shown = repr(path)
        return {"ok": False,
                "reason": "Не удалось прочитать %s: %s" % (shown, error),
                "summary": classify([])}

    result = check(sample, expected, limit=limit)
    if not result["ok"]:
        result["reason"] = "%s — %s" % (os.path.basename(path), result["reason"])
    return result
