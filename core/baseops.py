# core/baseops.py
"""Операции между базами: объединение, вычитание, пересечение.

Дедуп внутри одного прогона в проекте уже был, а операций МЕЖДУ файлами не
было вовсе — именно их не хватает, чтобы вычесть отписки или пересечь два
источника.

Ключевой момент — по чему сравнивать. Сравнение по сырой строке не работает:
`John.Doe@Gmail.com` и `johndoe@gmail.com` — один и тот же ящик, и человек,
попавший в отписки под одним написанием, обязан вычесться и под другим.
Поэтому сравниваем по каноническому виду (core/cleaner.normalize_for_dedup),
а наружу отдаём ОРИГИНАЛЬНЫЙ адрес: переписывать данные пользователя нельзя.
"""

import os

from core.cleaner import normalize_for_dedup

_EMAIL_HINT = "@"


def _key(email):
    return normalize_for_dedup(email) if isinstance(email, str) else ""


def _as_list(value):
    """Приводит вход к списку. Всё, что не перебирается, — пустой список.

    Операции с базами зовутся и из GUI, и из консоли, и из экспорта. Уронить
    выгрузку на неожиданном типе нельзя: адреса потеряются молча, а причина
    останется в проглоченном исключении.
    """
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
    """Читает адреса из файла. Берёт первое поле строки, разделители любые."""
    emails = []
    if not isinstance(path, (str, bytes, os.PathLike)):
        return emails
    try:
        if not path or not os.path.exists(path):
            return emails
    except (TypeError, ValueError, OSError):
        return emails
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
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
    """Схлопывает дубли по каноническому ключу, сохраняя порядок и оригиналы."""
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
    """Объединение нескольких списков с дедупом. Первое написание побеждает."""
    combined = []
    for chunk in lists:
        combined.extend(_as_list(chunk))
    return dedupe(combined)


def subtract(base, removals):
    """base минус removals. Основа для списка отписок."""
    drop = {_key(e) for e in _as_list(removals) if _key(e)}
    return [e for e in dedupe(base) if _key(e) not in drop]


def intersect(base, other):
    """Только те, кто есть в обоих списках."""
    keep = {_key(e) for e in _as_list(other) if _key(e)}
    return [e for e in dedupe(base) if _key(e) in keep]


def chunks(items, size):
    """Режет список на куски заданного размера — под лимиты ESP.

    Размер меньше единицы означает «не резать»: молча отдавать пустые куски
    хуже, чем один целый список.
    """
    items = _as_list(items)
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 0
    if size < 1 or not items:
        return [items] if items else []
    return [items[i:i + size] for i in range(0, len(items), size)]


def write_chunks(rows, path, size, writer):
    """Пишет строки кусками по size, нумеруя файлы. Возвращает список путей.

    writer(file_handle, rows_chunk) отвечает за формат — так одна и та же
    нарезка годится и для CSV, и для plain text.
    """
    parts = chunks(rows, size)
    if not parts:
        return []

    base, ext = os.path.splitext(path)
    written = []
    single = len(parts) == 1
    for index, part in enumerate(parts, 1):
        target = path if single else f"{base}_{index:03d}{ext}"
        with open(target, "w", newline="", encoding="utf-8") as handle:
            writer(handle, part)
        written.append(target)
    return written
