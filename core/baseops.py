import os

from core.encoding import open_text

from core.cleaner import normalize_for_dedup

_EMAIL_HINT = "@"


def _key(email):
    return normalize_for_dedup(email) if isinstance(email, str) else ""


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return []
    if not hasattr(value, "__iter__"):
        return []
    try:
        return list(value)
    except Exception:
        return []


def read_emails(path, limit=None):
    emails = []
    if not isinstance(path, (str, bytes, os.PathLike)):
        return emails
    try:
        if not path or not os.path.exists(path):
            return emails
    except (TypeError, ValueError, OSError):
        return emails
    try:
        with open_text(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                for chunk in line.replace(";", ",").replace("\t", ",").split(","):
                    chunk = chunk.strip().strip('"').strip("'")
                    if _EMAIL_HINT in chunk:
                        emails.append(chunk)
                        break
                if limit and len(emails) >= limit:
                    break
    except Exception:
        return emails
    return emails


def dedupe(emails):
    seen = set()
    result = []
    for email in _as_list(emails):
        key = _key(email)
        if not key or key in seen:
            continue
        seen.add(key)
        result.append(email)
    return result


def merge(*lists):
    combined = []
    for chunk in lists:
        combined.extend(_as_list(chunk))
    return dedupe(combined)


def subtract(base, removals):
    drop = {_key(e) for e in _as_list(removals) if _key(e)}
    return [e for e in dedupe(base) if _key(e) not in drop]


def intersect(base, other):
    keep = {_key(e) for e in _as_list(other) if _key(e)}
    return [e for e in dedupe(base) if _key(e) in keep]


def chunks(items, size):
    items = _as_list(items)
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 0
    if size < 1 or not items:
        return [items] if items else []
    return [items[i:i + size] for i in range(0, len(items), size)]


def suppression_keys(path):
    return {_key(e) for e in read_emails(path) if _key(e)}


EXPORT_BOM_EXTENSIONS = frozenset({".csv"})


def export_encoding(path):
    try:
        ext = os.path.splitext(str(path))[1].lower()
    except Exception:
        return "utf-8"
    return "utf-8-sig" if ext in EXPORT_BOM_EXTENSIONS else "utf-8"


_FORMULA_STARTERS = ("=", "+", "-", "@", chr(9), chr(13))


def csv_cell(value):
    if not isinstance(value, str) or not value:
        return value
    return "'" + value if value.startswith(_FORMULA_STARTERS) else value


def csv_row(values):
    if values is None or isinstance(values, (str, bytes)) or not hasattr(values, "__iter__"):
        return []
    return [csv_cell(v) for v in values]


def write_chunks_stream(rows, path, size, writer):
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 0

    if not isinstance(path, (str, bytes, os.PathLike)) or not path:
        return [], 0
    if rows is None or not hasattr(rows, "__iter__") or isinstance(rows, (str, bytes)):
        return [], 0
    if not callable(writer):
        return [], 0

    base, ext = os.path.splitext(path)
    written = []
    total = 0
    buffer = []
    index = 0

    def flush(final=False):
        nonlocal buffer, index, total
        if not buffer and not (final and not written):
            return
        index += 1
        target = path if (size < 1) else f"{base}_{index:03d}{ext}"
        with open(target, "w", newline="", encoding=export_encoding(target)) as handle:
            writer(handle, buffer)
        written.append(target)
        total += len(buffer)
        buffer = []

    for row in rows:
        buffer.append(row)
        if size >= 1 and len(buffer) >= size:
            flush()
    if buffer or not written:
        flush(final=True)

    if size >= 1 and len(written) == 1 and written[0] != path:
        try:
            if os.path.exists(path):
                os.remove(path)
            os.rename(written[0], path)
            written = [path]
        except OSError:
            pass
    return written, total


def write_chunks(rows, path, size, writer):
    parts = chunks(rows, size)
    if not parts:
        return []

    base, ext = os.path.splitext(path)
    written = []
    single = len(parts) == 1
    for index, part in enumerate(parts, 1):
        target = path if single else f"{base}_{index:03d}{ext}"
        with open(target, "w", newline="", encoding=export_encoding(target)) as handle:
            writer(handle, part)
        written.append(target)
    return written


_SEGMENT_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "",
    "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def segment_filename(value):
    text = str(value or "").strip().lower()
    if not text:
        return "ne-opredeleno"
    out = []
    for char in text:
        if char in _SEGMENT_TRANSLIT:
            out.append(_SEGMENT_TRANSLIT[char])
        elif char.isalnum() and char.isascii():
            out.append(char)
        else:
            out.append("-")
    name = "".join(out).strip("-")
    while "--" in name:
        name = name.replace("--", "-")
    return name or "ne-opredeleno"


def split_by_segment(rows, key):
    if rows is None or isinstance(rows, (str, bytes)):
        return {}
    try:
        iterator = iter(rows)
    except TypeError:
        return {}

    buckets = {}
    for row in iterator:
        if not isinstance(row, dict):
            continue
        if key == "provider":
            email = str(row.get("email") or "")
            value = email.rpartition("@")[2].strip().lower() if "@" in email else ""
        else:
            data = row.get("data") if isinstance(row.get("data"), dict) else {}
            value = str(data.get(key) or "").strip()
        buckets.setdefault(value, []).append(row)
    return buckets
