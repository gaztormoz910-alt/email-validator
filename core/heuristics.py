# core/heuristics.py
"""Эвристики «стоит ли за адресом живой человек».

Два сигнала, которые не требуют сети и работают на любом домене:
  1. Энтропия локальной части — отличает 'ivan.petrov' от 'xk3n9fj2q'
  2. Припаркованный домен — MX ведёт на парковочный сервис, живых ящиков нет
"""

import math
import re

# Парковочные и «домен продаётся» сервисы. Если MX/A ведут сюда — почты там нет.
PARKING_HOSTS = (
    "sedoparking", "sedo.com", "bodis.com", "afternic", "parkingcrew",
    "dan.com", "undeveloped.com", "namecheap.com/parking", "parklogic",
    "above.com", "voodoo.com", "cashparking", "hugedomains", "domainmarket",
    "brandbucket", "efty.com", "parkpage", "parked.com",
)

# Клавиатурные ряды — их часто набирают, чтобы быстро создать мусорный ящик
_KEYBOARD_RUNS = ("qwerty", "asdf", "zxcv", "qazwsx", "12345", "йцукен", "987654")

_VOWELS = set("aeiouyаеёиоуыэюя")


def local_part_entropy(local: str) -> float:
    """Энтропия Шеннона на символ. Чем выше — тем «случайнее» строка."""
    if not local:
        return 0.0
    counts = {}
    for ch in local:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(local)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


# Приватные relay-сервисы выдают случайные локальные части, но за ними стоят
# РЕАЛЬНЫЕ люди: Apple Private Relay включён у миллионов по умолчанию.
# core/disposable.py специально не считает их одноразовыми — здесь та же логика.
PRIVACY_RELAY_DOMAINS = {
    "privaterelay.appleid.com", "icloud.com",
    "duck.com", "relay.firefox.com", "mozmail.com",
    "anonaddy.me", "anonaddy.com", "addy.io",
    "simplelogin.io", "simplelogin.com", "aleeas.com", "slmail.me",
    "passinbox.com", "passmail.net",
}


def looks_machine_generated(email: str) -> bool:
    """True, если локальная часть похожа на сгенерированную машиной.

    Ловит 'xk3n9fj2q@', 'a7f3k2m9x1@' и подобное — за такими адресами
    почти никогда нет живого человека.

    Намеренно КОНСЕРВАТИВНА: лучше пропустить бота, чем оболгать живого.
    """
    if not email or "@" not in email:
        return False

    local, _, domain = email.rpartition("@")
    local = local.lower()
    domain = domain.lower()

    # Приватный relay — случайная локальная часть тут норма, а не признак бота
    if domain in PRIVACY_RELAY_DOMAINS:
        return False

    # Короткие адреса не судим: 'ivan', 'jhn', 'ao' — нормальные человеческие
    if len(local) < 8:
        return False

    # Есть разделители (точка/подчёркивание/дефис) — типичный человеческий формат
    # 'john.doe', 'ivan_petrov', 'anna-maria'
    if re.search(r"[._-][a-zа-я]", local):
        return False

    letters = [c for c in local if c.isalpha()]
    if not letters:
        return False

    # Признак 1: почти нет гласных ('xkfjmqrst')
    vowel_ratio = sum(1 for c in letters if c in _VOWELS) / len(letters)

    # Признак 2: высокая энтропия символов
    entropy = local_part_entropy(local)

    # Признак 3: длинная мешанина букв и цифр вперемешку ('a7f3k2m9x1')
    alternations = len(re.findall(r"(?:[a-zа-я]\d|\d[a-zа-я])", local))

    # Признак 4: клавиатурный набор
    if any(run in local for run in _KEYBOARD_RUNS):
        return True

    # Судим только при СОВПАДЕНИИ нескольких признаков сразу
    suspicious = 0
    if vowel_ratio <= 0.20:
        suspicious += 1
    if entropy > 3.2:
        suspicious += 1
    if alternations >= 3:
        suspicious += 1

    return suspicious >= 2


def is_parked_domain(mx_record: str) -> bool:
    """True, если MX ведёт на парковочный сервис (домен продаётся/пустой)."""
    if not mx_record or mx_record == "N/A":
        return False
    mx = mx_record.lower()
    return any(host in mx for host in PARKING_HOSTS)


# Ролевые (не персональные) ящики. Раньше список лежал ВНУТРИ process_single,
# пересоздавался на каждом адресе и был продублирован в блоке повтора greylisting.
ROLE_EXACT = {
    "abuse", "admin", "billing", "compliance", "contact", "devnull", "dns",
    "ftp", "help", "hostmaster", "hr", "info", "jobs", "list", "maildaemon",
    "marketing", "media", "noc", "no-reply", "noreply", "null", "office",
    "postmaster", "privacy", "registrar", "root", "sales", "security", "spam",
    "staff", "subscribe", "support", "sysadmin", "tech", "unsubscribe",
    "webmaster", "www", "hello", "press", "legal", "feedback",
}

# Основы, от которых ролевые адреса образуются с суффиксами и разделителями:
# sales-team@, info.desk@, noreply2@, do-not-reply@, mailer-daemon@.
# Раньше сравнение шло только на точное равенство, и всё это проходило как личные.
ROLE_STEMS = (
    "noreply", "no-reply", "donotreply", "do-not-reply", "mailer-daemon",
    "maildaemon", "mailerdaemon", "postmaster", "abuse", "support", "sales",
    "info", "contact", "admin", "billing", "help", "hr", "jobs", "careers",
    "marketing", "newsletter", "news", "office", "team", "service", "enquiries",
    "inquiries", "feedback", "webmaster", "hostmaster", "security", "privacy",
    "legal", "press", "media", "orders", "shop", "store", "booking", "reception",
)

_ROLE_SPLIT = re.compile(r"[.\-_+]")


def is_role_based(email: str) -> bool:
    """True, если ящик ролевой (не принадлежит конкретному человеку).

    Ловит три формы:
      info@            — точное совпадение
      sales-team@      — ролевая основа + суффикс через разделитель
      noreply2@        — ролевая основа + цифры
    """
    if not email or "@" not in email:
        return False

    local = email.rsplit("@", 1)[0].strip().lower()
    if not local:
        return False

    if local in ROLE_EXACT:
        return True

    # Любая часть после разделителей совпала с ролевой: sales-team@, info.desk@
    parts = [p for p in _ROLE_SPLIT.split(local) if p]
    if any(p in ROLE_EXACT for p in parts):
        return True

    # Основа + цифры/суффикс без разделителя: noreply2@, support01@
    stripped = local.rstrip("0123456789")
    if stripped and stripped in ROLE_EXACT:
        return True

    # Многословные основы, которые не режутся разделителями: donotreply@
    compact = _ROLE_SPLIT.sub("", local).rstrip("0123456789")
    for stem in ROLE_STEMS:
        if compact == _ROLE_SPLIT.sub("", stem):
            return True

    return False
