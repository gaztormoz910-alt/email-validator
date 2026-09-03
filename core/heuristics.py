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
    # Крупные парковочные площадки
    "sedoparking", "sedo.com", "bodis.com", "afternic", "parkingcrew",
    "dan.com", "undeveloped.com", "namecheap.com/parking", "parklogic",
    "above.com", "voodoo.com", "cashparking", "hugedomains", "domainmarket",
    "brandbucket", "efty.com", "parkpage", "parked.com",
    # Биржи и брокеры доменов
    "namebright", "namesilo", "dynadot", "epik.com", "namejet", "snapnames",
    "buydomains", "domainholdings", "uniregistry", "domain-broker",
    "domainnamesales", "escrow.com", "flippa", "sav.com", "spaceship.com",
    "namecheap-parking", "parkingpanel", "domainparking", "parkedcontent",
    # Регистраторы, у которых парковка — отдельный хост
    "domaincontrol.com/park", "parking.godaddy", "wixdns-park",
    "registrar-servers.com/park", "parkingpage", "sedo-parking",
    "trafficz", "dsredirection", "fabulous.com", "rookmedia",
    "smartname", "oversee.net", "internettraffic", "domainsponsor",
    "skenzo", "teaminternet", "parkweb", "parkingspa", "domainapps",
    "247parking", "parkme", "domainprofi", "expiereddomains",
)

# Клавиатурные ряды — их часто набирают, чтобы быстро создать мусорный ящик
_KEYBOARD_RUNS = ("qwerty", "asdf", "zxcv", "qazwsx", "12345", "йцукен", "987654")

_VOWELS = set("aeiouyаеёиоуыэюя")


def local_part_entropy(local: str) -> float:
    """Энтропия Шеннона на символ. Чем выше — тем «случайнее» строка."""
    if not local or not isinstance(local, str):
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


# Минимальная длина префикса, который считаем осмысленным именем. Короче —
# совпадения случайны: в базе имён найдётся почти любое сочетание из трёх-четырёх
# букв, и защита начала бы выгораживать настоящих ботов.
_KNOWN_NAME_MIN = 5


def _starts_with_known_name(local: str) -> bool:
    """True, если локальная часть — это слитно написанное человеческое имя.

    Ловит 'wolfgangschmidt', 'robertanderson', 'mohammedlahlali'.

    Два ограничения, без которых защита стала бы дырой:
      * только строки БЕЗ цифр — у машинных адресов цифры почти всегда есть,
        и 'annaxk3n9fj' обязан по-прежнему считаться ботом;
      * префикс от пяти букв — иначе под защиту попадёт что угодно.

    Если индекса имён нет, признак не срабатывает и поведение прежнее.
    """
    if not isinstance(local, str) or not local:
        return False
    if any(c.isdigit() for c in local):
        return False
    try:
        from core.parser.names_index import is_known_name
    except Exception:
        return False
    letters = "".join(c for c in local if c.isalpha())
    if len(letters) < _KNOWN_NAME_MIN + 2:
        return False
    # Пробуем префиксы от длинного к короткому: 'wolfgang' найдётся раньше 'wolf'
    for size in range(min(len(letters), 12), _KNOWN_NAME_MIN - 1, -1):
        if is_known_name(letters[:size]):
            return True
    return False


def looks_machine_generated(email: str) -> bool:
    """True, если локальная часть похожа на сгенерированную машиной.

    Ловит 'xk3n9fj2q@', 'a7f3k2m9x1@' и подобное — за такими адресами
    почти никогда нет живого человека.

    Намеренно КОНСЕРВАТИВНА: лучше пропустить бота, чем оболгать живого.
    """
    if not isinstance(email, str) or "@" not in email:
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

    # Слитно написанные имя и фамилия — норма, а не машинная генерация.
    # 'wolfgangschmidt' даёт мало гласных и высокую энтропию, то есть проходит
    # сразу по двум признакам, и раньше метился ботом. Живой человек за таким
    # адресом есть, а цена ошибки здесь — удалённый контакт.
    if _starts_with_known_name(local):
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


def is_parked_domain(mx_record) -> bool:
    """True, если почта домена ведёт на парковочный сервис (домен продаётся).

    Принимает и одну запись, и список: домен может быть припаркован через
    ВТОРОЙ MX или вообще через A-запись без MX. Раньше смотрелся только
    первый MX, и такие домены проходили как обычные.
    """
    if not mx_record:
        return False
    if isinstance(mx_record, str):
        records = [mx_record]
    elif hasattr(mx_record, "__iter__") and not isinstance(mx_record, (bytes, dict)):
        records = list(mx_record)
    else:
        return False
    for record in records:
        if not isinstance(record, str) or not record or record == "N/A":
            continue
        low = record.lower()
        if any(host in low for host in PARKING_HOSTS):
            return True
    return False


# Год рождения в адресе.
#
# Нижняя граница — 1935: человек 1920 года рождения почту себе не заводил.
# Верхняя — минус 13 лет от сегодня: раньше почтовые ящики не регистрируют.
# Всё, что выше, почти наверняка год регистрации ящика, а не рождения.
_BIRTH_MIN = 1935


def _birth_year_bounds():
    import datetime
    current = datetime.date.today().year
    return _BIRTH_MIN, current - 13


# Четырёхзначный год: karl1985@, anna.2001.k@
_YEAR4_RE = re.compile(r'(?<!\d)(19[3-9]\d|20[0-2]\d)(?!\d)')
# Двузначный хвост после букв: sarah.jones91@, ivan_77@
_YEAR2_RE = re.compile(r'[a-zа-яё][._\-]?(\d{2})$')


def extract_birth_year(email: str):
    """Год рождения из локальной части адреса или None.

    `sarah.jones91@` -> 1991,  `karl1985@` -> 1985,  `user2024@` -> None
    (2024 — это год регистрации, а не рождения).

    Намеренно консервативна: сомнительное лучше не заполнять, чем выдать
    выдумку за факт. Адрес целиком из цифр не разбирается вовсе.
    """
    if not isinstance(email, str) or "@" not in email:
        return None
    local = email.rsplit("@", 1)[0].strip().lower()
    if not local or local.isdigit():
        return None

    low, high = _birth_year_bounds()

    # Четырёхзначные годы: берём самый правдоподобный (последний в строке)
    candidates = [int(m) for m in _YEAR4_RE.findall(local)]
    for year in reversed(candidates):
        if low <= year <= high:
            return year

    # Двузначный хвост: 91 -> 1991, 05 -> 2005
    tail = _YEAR2_RE.search(local)
    if tail:
        value = int(tail.group(1))
        year = 1900 + value if value >= 30 else 2000 + value
        if low <= year <= high:
            return year

    return None


# Ролевые (не персональные) ящики. Раньше список лежал ВНУТРИ process_single,
# пересоздавался на каждом адресе и был продублирован в блоке повтора greylisting.
ROLE_EXACT = {
    "abuse", "admin", "billing", "compliance", "contact", "devnull", "dns",
    "ftp", "help", "hostmaster", "hr", "info", "jobs", "list", "maildaemon",
    "marketing", "media", "noc", "no-reply", "noreply", "null", "office",
    "postmaster", "privacy", "registrar", "root", "sales", "security", "spam",
    "staff", "subscribe", "support", "sysadmin", "tech", "unsubscribe",
    "webmaster", "www", "hello", "press", "legal", "feedback",
    # Полные формы там, где раньше стояло только сокращение: ящик заводят и
    # так и так, а опознавался лишь один из двух (admin был, administrator —
    # нет). Список намеренно узкий: лишний «Role-based» отнимает у владельца
    # живой лид ровно так же, как ложный Invalid, поэтому имена, которые
    # бывают и личными ящиками (mail, it, dev, order, account, ceo, manager),
    # сюда НЕ внесены.
    "administrator", "administration", "webadmin", "sysadmin",
    "moderator", "operator", "sysop", "helpdesk",
    "enquiry", "enquiries", "inquiry", "inquiries",
    "customerservice", "customercare",
    "accounting", "invoice", "invoices",
    "career", "careers", "recruitment", "recruiting", "vacancy", "vacancies",
    "newsletter", "notification", "notifications", "notify",
    "alert", "alerts", "bounce", "bounces",
    "mailerdaemon", "mailer-daemon", "daemon",
    "autoreply", "auto-reply", "donotreply", "do-not-reply",
    # RFC 2142 §2-§5 — имена, которые обязан иметь оператор услуги.
    "usenet", "uucp", "news",
    "partners", "partnership", "affiliate", "affiliates", "advertising",
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
    # Отраслевые. Общие списки их не покрывают, а в B2B-базах они массовые:
    # за ними отдел, а не человек, и персонализация в письме промахнётся.
    "dispatch", "logistics", "procurement", "purchasing", "supply", "warehouse",
    "shipping", "delivery", "returns", "claims", "warranty", "service-desk",
    "servicedesk", "helpdesk", "frontdesk", "reservations", "bookings",
    "accounts", "accounting", "invoice", "invoices", "payments", "payroll",
    "finance", "treasury", "audit", "compliance", "tenders", "bids",
    "quality", "qa", "rnd", "engineering", "operations", "production",
    "recruitment", "recruiting", "talent", "training", "academy",
    "partners", "partnership", "affiliates", "resellers", "dealers",
    "wholesale", "retail", "export", "import", "customs",
    "clinic", "appointments", "patients", "admissions", "registrar",
    "donations", "membership", "volunteers", "events", "conference",
    "subscriptions", "renewals", "unsubscribe", "optout", "bounce",
    "notifications", "alerts", "system", "robot", "auto", "automail",
)

_ROLE_SPLIT = re.compile(r"[.\-_+]")


def is_role_based(email: str) -> bool:
    """True, если ящик ролевой (не принадлежит конкретному человеку).

    Ловит три формы:
      info@            — точное совпадение
      sales-team@      — ролевая основа + суффикс через разделитель
      noreply2@        — ролевая основа + цифры
    """
    if not isinstance(email, str) or "@" not in email:
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
