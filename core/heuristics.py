import math
import re

PARKING_HOSTS = (
    "sedoparking", "sedo.com", "bodis.com", "afternic", "parkingcrew",
    "dan.com", "undeveloped.com", "namecheap.com/parking", "parklogic",
    "above.com", "voodoo.com", "cashparking", "hugedomains", "domainmarket",
    "brandbucket", "efty.com", "parkpage", "parked.com",
    "namebright", "namesilo", "dynadot", "epik.com", "namejet", "snapnames",
    "buydomains", "domainholdings", "uniregistry", "domain-broker",
    "domainnamesales", "escrow.com", "flippa", "sav.com", "spaceship.com",
    "namecheap-parking", "parkingpanel", "domainparking", "parkedcontent",
    "domaincontrol.com/park", "parking.godaddy", "wixdns-park",
    "registrar-servers.com/park", "parkingpage", "sedo-parking",
    "trafficz", "dsredirection", "fabulous.com", "rookmedia",
    "smartname", "oversee.net", "internettraffic", "domainsponsor",
    "skenzo", "teaminternet", "parkweb", "parkingspa", "domainapps",
    "247parking", "parkme", "domainprofi", "expiereddomains",
)

_KEYBOARD_RUNS = ("qwerty", "asdf", "zxcv", "qazwsx", "12345", "йцукен", "987654")

_VOWELS = set("aeiouyаеёиоуыэюя")


def local_part_entropy(local: str) -> float:
    if not local or not isinstance(local, str):
        return 0.0
    counts = {}
    for ch in local:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(local)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


from core.disposable import NEVER_DISPOSABLE as PRIVACY_RELAY_DOMAINS


_KNOWN_NAME_MIN = 5


def _starts_with_known_name(local: str) -> bool:
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
    for size in range(min(len(letters), 12), _KNOWN_NAME_MIN - 1, -1):
        if is_known_name(letters[:size]):
            return True
    return False


def looks_machine_generated(email: str) -> bool:
    if not isinstance(email, str) or "@" not in email:
        return False

    local, _, domain = email.rpartition("@")
    local = local.lower()
    domain = domain.lower()

    метки = domain.split(".")
    if any(".".join(метки[i:]) in PRIVACY_RELAY_DOMAINS for i in range(len(метки) - 1)):
        return False

    if len(local) < 8:
        return False

    if re.search(r"[._-][a-zа-я]", local):
        return False

    letters = [c for c in local if c.isalpha()]
    if not letters:
        return False

    if _starts_with_known_name(local):
        return False

    vowel_ratio = sum(1 for c in letters if c in _VOWELS) / len(letters)

    entropy = local_part_entropy(local)

    alternations = len(re.findall(r"(?:[a-zа-я]\d|\d[a-zа-я])", local))

    if any(run in local for run in _KEYBOARD_RUNS):
        return True

    suspicious = 0
    if vowel_ratio <= 0.20:
        suspicious += 1
    if entropy > 3.2:
        suspicious += 1
    if alternations >= 3:
        suspicious += 1

    return suspicious >= 2


def _маркер_парковки_совпал(host: str, marker: str) -> bool:
    if not isinstance(host, str) or not isinstance(marker, str):
        return False
    if not marker:
        return False
    if "/" in marker:
        return False
    метки = host.split(".")
    части = marker.split(".")
    if len(части) > 1:
        ширина = len(части)
        return any(метки[i:i + ширина] == части
                   for i in range(len(метки) - ширина + 1))
    return marker in метки


def is_parked_domain(mx_record) -> bool:
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
        low = record.lower().strip().rstrip(".")
        if any(_маркер_парковки_совпал(low, host) for host in PARKING_HOSTS):
            return True
    return False


_BIRTH_MIN = 1935


def _birth_year_bounds():
    import datetime
    current = datetime.date.today().year
    return _BIRTH_MIN, current - 13


_YEAR4_RE = re.compile(r'(?<!\d)(19[3-9]\d|20[0-2]\d)(?!\d)')
_YEAR2_RE = re.compile(r'[a-zа-яё][._\-]?(\d{2})$')


def extract_birth_year(email: str):
    if not isinstance(email, str) or "@" not in email:
        return None
    local = email.rsplit("@", 1)[0].strip().lower()
    if not local or local.isdigit():
        return None

    low, high = _birth_year_bounds()

    candidates = [int(m) for m in _YEAR4_RE.findall(local)]
    for year in reversed(candidates):
        if low <= year <= high:
            return year

    tail = _YEAR2_RE.search(local)
    if tail:
        value = int(tail.group(1))
        year = 1900 + value if value >= 30 else 2000 + value
        if low <= year <= high:
            return year

    return None


ROLE_EXACT = {
    "abuse", "admin", "billing", "compliance", "contact", "devnull", "dns",
    "ftp", "help", "hostmaster", "hr", "info", "jobs", "list", "maildaemon",
    "marketing", "media", "noc", "no-reply", "noreply", "null", "office",
    "postmaster", "privacy", "registrar", "root", "sales", "security", "spam",
    "staff", "subscribe", "support", "sysadmin", "tech", "unsubscribe",
    "webmaster", "www", "hello", "press", "legal", "feedback",
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
    "usenet", "uucp", "news",
    "partners", "partnership", "affiliate", "affiliates", "advertising",
}

ROLE_STEMS = (
    "noreply", "no-reply", "donotreply", "do-not-reply", "mailer-daemon",
    "maildaemon", "mailerdaemon", "postmaster", "abuse", "support", "sales",
    "info", "contact", "admin", "billing", "help", "hr", "jobs", "careers",
    "marketing", "newsletter", "news", "office", "team", "service", "enquiries",
    "inquiries", "feedback", "webmaster", "hostmaster", "security", "privacy",
    "legal", "press", "media", "orders", "shop", "store", "booking", "reception",
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
    if not isinstance(email, str) or "@" not in email:
        return False

    local = email.rsplit("@", 1)[0].strip().lower()
    if not local:
        return False

    if local in ROLE_EXACT:
        return True

    parts = [p for p in _ROLE_SPLIT.split(local) if p]
    if any(p in ROLE_EXACT for p in parts):
        return True

    stripped = local.rstrip("0123456789")
    if stripped and stripped in ROLE_EXACT:
        return True

    compact = _ROLE_SPLIT.sub("", local).rstrip("0123456789")
    for stem in ROLE_STEMS:
        if compact == _ROLE_SPLIT.sub("", stem):
            return True

    return False


_TRAP_WORDS = frozenset({"spamtrap", "spamtraps", "honeypot", "honeypots",
                         "honeytrap", "trap", "traps"})


def trap_word_in_local(email) -> str:
    if not isinstance(email, str) or "@" not in email:
        return ""
    local = email.rsplit("@", 1)[0].strip().lower()
    if not local:
        return ""
    for part in _ROLE_SPLIT.split(local):
        if part in _TRAP_WORDS:
            return part
    склеено = _ROLE_SPLIT.sub("", local).rstrip("0123456789")
    return склеено if склеено in _TRAP_WORDS else ""
