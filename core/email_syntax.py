import ipaddress
import re

__all__ = [
    "to_ascii_domain",
    "has_non_ascii_local",
    "has_quoted_local",
    "MAX_LABEL_BYTES",
    "validate_email_syntax",
    "harvest_pattern",
    "MAX_EMAIL_BYTES",
    "MAX_LOCAL_BYTES",
    "MAX_DOMAIN_BYTES",
]

MAX_LOCAL_BYTES = 64
MAX_LABEL_BYTES = 63
MAX_DOMAIN_BYTES = 255
MAX_EMAIL_BYTES = 320

_TLD_PART = r'(?:xn--[a-zA-Z0-9\-]{2,}|[a-zA-Z]{2,})'

_ATEXT = r"a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-"

_LOCAL_PART = r'[' + _ATEXT + r']+(?:\.[' + _ATEXT + r']+)*'

_UTF8_ATEXT = _ATEXT + '\u0080-\U0010ffff'
_UTF8_LOCAL_RE = re.compile(
    r'^[' + _UTF8_ATEXT + r']+(?:\.[' + _UTF8_ATEXT + r']+)*$')

_QTEXT = r'[ !#-\[\]-~]'
_QUOTED_PAIR = '\\\\[ -~]'
_QUOTED_LOCAL_RE = re.compile(r'^"(?:' + _QTEXT + r'|' + _QUOTED_PAIR + r')*"$')


def has_quoted_form(local):
    return (isinstance(local, str) and len(local) >= 2
            and local.startswith('"') and local.endswith('"'))


_LABEL = r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?'
_DOMAIN_BODY = r'(?:' + _LABEL + r'\.)+' + _TLD_PART

_RFC5322_REGEX = re.compile(
    r'^' + _LOCAL_PART +
    r'@' + _DOMAIN_BODY + r'$'
)

_DOMAIN_REGEX = re.compile(r'^' + _DOMAIN_BODY + r'$')

_LOCAL_ONLY_REGEX = re.compile(r'^' + _LOCAL_PART + r'$')

_DOMAIN_LITERAL_RE = re.compile(r'^\[(IPv6:)?([0-9A-Fa-f:.]{2,45})\]$',
                                re.IGNORECASE)


def domain_literal_ip(domain):
    if not isinstance(domain, str):
        return None
    найдено = _DOMAIN_LITERAL_RE.match(domain.strip())
    if not найдено:
        return None
    метка, тело = найдено.group(1), найдено.group(2)
    try:
        адрес = ipaddress.ip_address(тело)
    except ValueError:
        return None
    if bool(метка) != (адрес.version == 6):
        return None
    return адрес

_BAD_SYNTAX_PATTERNS = re.compile(
    r'(^\.|'
    r'\.\.|'
    r'\.@|'
    r'@\.|'
    r'\s)'
)


def harvest_pattern(wide=True):
    url_structural = "=&?/#%"
    atext = _ATEXT if wide else "".join(
        ch for ch in _ATEXT if ch not in url_structural)
    local = r'[' + atext + r']+(?:\.[' + atext + r']+)*'
    if wide:
        quoted = r'"(?:' + _QTEXT + r'|' + _QUOTED_PAIR + r')*"'
        local = r'(?:' + quoted + r'|' + local + r')'
    return re.compile(local + r'@' + _LABEL + r'(?:\.' + _LABEL + r')*\.' + _TLD_PART)


def _byte_length(text):
    try:
        return len(text.encode("utf-8"))
    except (AttributeError, UnicodeError):
        return 0


def to_ascii_domain(domain: str):
    if not isinstance(domain, str) or not domain:
        return None
    try:
        if domain.isascii():
            return domain
        return domain.encode('idna').decode('ascii')
    except Exception:
        return None


def has_non_ascii_local(email: str) -> bool:
    if not isinstance(email, str) or "@" not in email:
        return False
    return not email.rsplit("@", 1)[0].isascii()


def has_quoted_local(email):
    if not isinstance(email, str) or "@" not in email:
        return False
    local = email.rpartition("@")[0].strip()
    return len(local) >= 2 and local.startswith('"') and local.endswith('"')


def _labels_fit(domain_ascii):
    if not isinstance(domain_ascii, str) or not domain_ascii:
        return False
    for label in domain_ascii.split("."):
        if not label or _byte_length(label) > MAX_LABEL_BYTES:
            return False
    return True


def validate_email_syntax(email: str) -> bool:
    if not email or not isinstance(email, str):
        return False
    if _byte_length(email) > MAX_EMAIL_BYTES:
        return False

    local, _, domain = email.rpartition('@')
    quoted = has_quoted_form(local)

    if not quoted:
        if email.count('@') != 1:
            return False
        if _BAD_SYNTAX_PATTERNS.search(email):
            return False
    elif not _QUOTED_LOCAL_RE.match(local):
        return False

    if not local or _byte_length(local) > MAX_LOCAL_BYTES:
        return False

    if domain_literal_ip(domain) is not None:
        if quoted:
            return True
        if not local.isascii():
            return bool(_UTF8_LOCAL_RE.match(local))
        return bool(_LOCAL_ONLY_REGEX.match(local))

    domain_ascii = to_ascii_domain(domain)
    if not domain_ascii:
        return False
    if _byte_length(domain_ascii) > MAX_DOMAIN_BYTES:
        return False
    if not _labels_fit(domain_ascii):
        return False

    if quoted:
        return bool(_DOMAIN_REGEX.match(domain_ascii))

    if not local.isascii():
        if not _UTF8_LOCAL_RE.match(local):
            return False
        return bool(_DOMAIN_REGEX.match(domain_ascii))

    return bool(_RFC5322_REGEX.match(f"{local}@{domain_ascii}"))


def _lower_domain_only(value: str) -> str:
    if not isinstance(value, str) or "@" not in value:
        return value.lower() if isinstance(value, str) else ""
    local, _, domain = value.rpartition("@")
    return local + "@" + domain.lower()
