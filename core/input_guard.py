import csv
import io
import os
import re

from core.encoding import open_text
from core.hostport import bare_ipv6_ambiguous, ipv6_literal, split_proxy_address

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

KIND_FIELD = {
    KIND_EMAIL: "«Адреса для проверки»",
    KIND_PROXY: "«Прокси»",
    KIND_DORK: "«Поисковые запросы»",
}

FIELD_SEPARATORS = ",;|\t"

DORK_OPERATORS = (
    "site:", "intext:", "inurl:", "intitle:", "filetype:", "ext:",
    "allintext:", "allinurl:", "cache:", "related:", "link:", "before:",
    "after:", "define:", "imagesize:",
)

_DORK_OPERATOR_RE = re.compile(
    r"(?:^|[\s\"'(+,;|-])(?:%s)" % "|".join(re.escape(op) for op in DORK_OPERATORS))

_SEARCH_OR_RE = re.compile(r"\s\|\s")

IDN_TLD = {
    "рф", "рус", "москва", "дети", "онлайн", "сайт", "ком", "орг", "укр",
    "бел", "бг", "срб", "мкд", "ею", "католик", "қаз", "мон", "рфс",
}

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
    if not isinstance(value, str):
        return False
    return bool(_IP_RE.match(value) or _HOST_RE.match(value)
                or ipv6_literal(value))


def _is_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return False
    return 1 <= port <= 65535


def _tld_exists(domain):
    if not isinstance(domain, str):
        return False
    if "." not in domain:
        return False
    tld = domain.rsplit(".", 1)[1].strip().lower()
    if len(tld) < 2:
        return False
    if tld.isascii():
        if tld.startswith("xn--"):
            return len(tld) > 4 and all(c.isalnum() or c == "-" for c in tld)
        return tld.isalpha()
    return _зона_idn_существует(tld)


def _зона_idn_существует(зона):
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
    value = str(value or "").strip().strip("<>\"'")
    if value.count("@") != 1:
        return False
    local, _, domain = value.partition("@")
    if not local or not domain or " " in value:
        return False
    if ":" in value:
        return False
    try:
        if len(local.encode("utf-8")) > 64 or len(domain.encode("utf-8")) > 255:
            return False
    except UnicodeError:
        return False
    return _tld_exists(domain)


def looks_like_proxy(value):
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
        split = split_proxy_address(address)
        return (bool(split) and len(split[1]) == 1
                and _is_host(split[0]) and _is_port(split[1][0]))

    split = split_proxy_address(value)
    if split and len(split[1]) in (1, 3):
        return _is_host(split[0]) and _is_port(split[1][0])
    return had_scheme and _is_host(value)


def _base_line_with_quotes(value):
    if not isinstance(value, str) or not value:
        return False
    в_скобках = re.search(r"<([^<>]+)>", value)
    if в_скобках and _is_plain_address(в_скобках.group(1).strip()):
        return True
    for separator in FIELD_SEPARATORS:
        if separator not in value:
            continue
        if separator == "|" and _SEARCH_OR_RE.search(value):
            continue
        поля = _csv_fields(value, separator)
        if поля and any(_is_plain_address(поле.strip()) for поле in поля):
            return True
    if ":" in value and value.lstrip().startswith('"'):
        поля = _csv_fields(value, ":")
        if (поля and len(поля) >= 2
                and re.fullmatch(r'\s*"[^"]*"(?:\s*:\s*"[^"]*")+\s*', value)
                and any(_is_plain_address(поле.strip()) for поле in поля)):
            return True
    return False


def _csv_fields(value, separator):
    if not isinstance(value, str) or separator not in tuple(FIELD_SEPARATORS + ":"):
        return None
    value = re.sub(r'"[ ]+(?=%s)' % re.escape(separator), '"', value)
    try:
        return next(csv.reader([value], delimiter=separator, skipinitialspace=True,
                               strict=True), None)
    except csv.Error:
        return None


def _is_plain_address(value):
    value = str(value or "").strip().strip("<>\"'")
    return "*" not in value and "%" not in value and looks_like_email(value)


def _address_not_pattern(value):
    value = str(value or "").strip().strip("<>\"'")
    return "*" not in value.partition("@")[0] and looks_like_email(value)


def looks_like_dork(value):
    value = str(value or "").strip()
    if not value:
        return False
    lowered = value.lower()
    if _DORK_OPERATOR_RE.search(lowered):
        return True
    if '"' in value and " " in value and not _base_line_with_quotes(value):
        return True
    if " " in value and "@" not in value and ":" not in value:
        return True
    return False


def detect_kind(line):
    line = str(line or "").strip()
    if not line or line.startswith("#"):
        return KIND_UNKNOWN

    if _DORK_OPERATOR_RE.search(line.lower()) and _base_line_with_quotes(line):
        return KIND_EMAIL

    if looks_like_dork(line):
        return KIND_DORK
    if '"' in line and _base_line_with_quotes(line):
        return KIND_EMAIL
    if looks_like_proxy(line):
        return KIND_PROXY
    if _address_not_pattern(line):
        return KIND_EMAIL

    в_скобках = re.search(r"<([^<>]+)>", line)
    if в_скобках and _address_not_pattern(в_скобках.group(1).strip()):
        return KIND_EMAIL

    for separator in FIELD_SEPARATORS:
        if separator in line:
            for part in line.split(separator):
                if any(_address_not_pattern(кусок.strip()) for кусок in part.split(":")):
                    return KIND_EMAIL
    if ":" in line:
        for part in line.split(":"):
            if _address_not_pattern(part.strip()):
                return KIND_EMAIL

    return KIND_UNKNOWN


def layout_suggestion(line):
    line = str(line or "").strip()
    if not line or detect_kind(line) != KIND_UNKNOWN:
        return None
    if not any(char.lower() in _RU_TO_EN for char in line):
        return None
    fixed = fix_layout(line)
    if fixed == line:
        return None
    return fixed if detect_kind(fixed) != KIND_UNKNOWN else None


def _dork_by_old_rules(line):
    if not isinstance(line, str):
        return False
    lowered = line.lower()
    return any(op in lowered for op in DORK_OPERATORS) or ('"' in line and " " in line)


_HEADER_WORDS = re.compile(
    r"(?:e-?mail|mail|address|name|first|last|surname|phone|country|gender|"
    r"city|company|почта|адрес|имя|фамилия|телефон|страна|пол|город)",
    re.IGNORECASE)


def _looks_like_header(line):
    if not isinstance(line, str) or not line.strip():
        return False
    if "@" in line or _DORK_OPERATOR_RE.search(line.lower()):
        return False
    separator = next((s for s in FIELD_SEPARATORS if s in line), None)
    поля = _csv_fields(line, separator) if separator else [line.strip().strip('"')]
    if not поля:
        return False
    поля = [поле.strip() for поле in поля]
    if any(not поле or len(поле.split()) > 4 for поле in поля):
        return False
    return any(_HEADER_WORDS.search(поле) for поле in поля)


def classify(lines, limit=SAMPLE_LINES, query_field=False):
    counts = {KIND_EMAIL: 0, KIND_PROXY: 0, KIND_DORK: 0, KIND_UNKNOWN: 0}
    samples = {KIND_EMAIL: [], KIND_PROXY: [], KIND_DORK: [], KIND_UNKNOWN: []}
    layout_fixes = []
    seen = 0

    if isinstance(lines, (str, bytes)):
        lines = [lines]
    elif lines is None or not hasattr(lines, "__iter__"):
        lines = []

    first = True
    for raw in lines:
        line = str(raw or "").strip()
        if not line or line.startswith("#"):
            continue
        if first and not query_field and _looks_like_header(line):
            first = False
            continue
        first = False
        seen += 1
        if seen > limit:
            break
        kind = detect_kind(line)
        if query_field and kind != KIND_DORK and _dork_by_old_rules(line):
            kind = KIND_DORK
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


ACCEPT_SHARE = 0.6


def check(lines, expected, limit=SAMPLE_LINES):
    summary = classify(lines, limit=limit, query_field=(expected == KIND_DORK))
    counts = summary["counts"]
    checked = summary["checked"]

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
    if expected == KIND_PROXY and bare_ipv6_ambiguous(example):
        return {
            "ok": False,
            "reason": ("Строка похожа на IPv6-прокси без квадратных скобок: %s\n"
                       "У IPv6 адрес и порт разделяет то же двоеточие, что и "
                       "группы адреса, — порт не отделить. Запишите адрес в "
                       "скобках: [2001:db8::10]:1080, "
                       "[2001:db8::10]:1080:логин:пароль или "
                       "логин:пароль@[2001:db8::10]:1080." % example),
            "summary": summary,
        }
    return {
        "ok": False,
        "reason": ("Не удалось разобрать: ни одной строки, похожей на %s. "
                   "Пример непонятной строки: %s"
                   % (KIND_TITLE[expected], example)),
        "summary": summary,
    }


def check_text(text, expected):
    return check(str(text or "").splitlines(), expected)


def check_file(path, expected, limit=SAMPLE_LINES):
    try:
        with open_text(path) as handle:
            sample = []
            for line in handle:
                sample.append(line)
                if len(sample) >= limit * 3:
                    break
    except (OSError, TypeError, ValueError) as error:
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
