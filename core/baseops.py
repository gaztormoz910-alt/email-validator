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

from core.encoding import open_text

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
        # Кодировка определяется, а не предполагается. Здесь это дороже
        # всего остального: через read_emails идёт ВЫЧИТАНИЕ СПИСКА
        # ОТПИСОК. Прочитав cp1251 как UTF-8 с errors="ignore", мы
        # превращали «анна@mail.ru» в «@mail.ru», он не совпадал с
        # адресом в базе — и человек, прямо попросивший его не трогать,
        # получал письмо снова.
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


def suppression_keys(path):
    """Множество канонических ключей из файла отписок.

    Отдельная функция, потому что этим же ключом обязаны сравниваться все три
    операции — дедуп, вычитание отписок и пересечение баз. Человек отписался
    как `john.doe@gmail.com`, попал в базу как `johndoe@gmail.com`, и сверка
    по сырой строке отправит ему письмо снова. Цена такой ошибки выше, чем у
    обычного дубля: это жалоба от того, кто уже прямо просил его не трогать.
    """
    return {_key(e) for e in read_emails(path) if _key(e)}


# В какой кодировке писать выгрузку.
#
# Excel на русской Windows открывает CSV не в UTF-8, а в системной кодировке,
# и «Иван» превращается в «РІР°РЅ». Признаёт он ровно один признак — метку
# порядка байт в начале файла (кодек utf-8-sig её и ставит). Владелец
# открывает выгрузку именно в Excel, поэтому метка нужна.
#
# В .txt метку не ставим: такой файл обычно возвращается на вход валидатору
# или уходит в чужой рассыльщик, и лишние байты в начале первой строки там
# ни к чему.
EXPORT_BOM_EXTENSIONS = frozenset({".csv"})


def export_encoding(path):
    """Кодировка для записи выгрузки по расширению файла."""
    try:
        ext = os.path.splitext(str(path))[1].lower()
    except Exception:
        return "utf-8"
    return "utf-8-sig" if ext in EXPORT_BOM_EXTENSIONS else "utf-8"


def write_chunks_stream(rows, path, size, writer):
    """То же, что write_chunks, но вход — ГЕНЕРАТОР, а не список.

    Зачем понадобилось. write_chunks режет список срезами, то есть требует
    всю выборку в памяти целиком — а выгружают как раз большие базы, ради
    которых всё остальное сделано потоковым. Здесь строки приходят порциями и
    уходят на диск, поэтому пиковая память равна одному куску, а не всей
    выгрузке.

    Возвращает (список путей, сколько строк записано).
    """
    try:
        size = int(size)
    except (TypeError, ValueError):
        size = 0

    # Мусор на входе не должен ронять выгрузку: эта функция зовётся и из окна,
    # и из консоли, и падение здесь означало бы молча потерянные адреса.
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
        # Имя первого файла заранее не известно: пока не кончились строки,
        # неясно, будет он единственным или первым из многих. Поэтому пишем
        # под номером, а в конце единственный файл переименовываем обратно.
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

    # Один-единственный кусок не нужно нумеровать: человек просил файл, а не
    # файл_001. Переименование дешевле, чем два прохода по генератору.
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
        with open(target, "w", newline="", encoding=export_encoding(target)) as handle:
            writer(handle, part)
        written.append(target)
    return written


# Как называть сегмент в имени файла. Кириллица и пробелы в именах файлов
# работают, но ломаются при переносе между системами и в чужих рассыльщиках.
_SEGMENT_TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch", "ъ": "",
    "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def segment_filename(value):
    """Имя файла для сегмента: латиница, цифры, дефис.

    Пустое значение — это «не определено», и такой сегмент тоже нужен: адреса
    без страны никуда не деваются, и потерять их при раскладке нельзя.
    """
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
    """Раскладывает строки по значению одного поля.

    key — "country", "gender" или "provider". Возвращает
    {значение: [строки]}, где пустое значение живёт под своим ключом, а не
    выбрасывается: адрес без страны — это адрес, а не мусор.

    Генератор строк принимается лениво, но результат собирается в память:
    раскладка по сегментам нужна для выгрузки, а выгрузка и так материализует
    файлы. На десяти миллионах адресов это заметно, поэтому в интерфейсе она
    делается по уже отфильтрованной выборке.
    """
    # Мусор на входе — это пустая раскладка, а не падение. Функция вызывается
    # из выгрузки, где исключение уронило бы фоновый поток и оставило владельца
    # без файлов и без объяснения.
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
