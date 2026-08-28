# core/email_syntax.py
"""Синтаксис адреса: RFC 5322, IDN и длины.

Вынесено из network.py, потому что это ЕДИНСТВЕННОЕ место, где вердикт
ставится вообще без обращения к сети, — и потому же самое опасное. Ошибка
здесь тише всех остальных: адрес получает `invalid` не потому, что сервер
что-то ответил, а потому, что регулярка сочла его неправильным, и в логе
об этом не остаётся ничего, кроме слова «Bad Syntax».

Два правила, которые здесь важнее прочих:

* **Не-ASCII не означает «адрес неправильный».** `иван@почта.рф` и
  `müller@bücher.de` — законные адреса (RFC 6531). Домен переводится в
  punycode перед запросом DNS; не-ASCII в локальной части требует от сервера
  расширения SMTPUTF8, и если его нет — это `unknown`, а не `invalid`.

* **Длины считаются в БАЙТАХ, а не в символах.** Локальная часть до 64,
  домен до 255, всё вместе до 320 — так написано в RFC 5321 §4.5.3.1, и
  разница не теоретическая: кириллическое имя из сорока букв укладывается в
  лимит по символам и вылетает по байтам. Раньше здесь стоял `len(email)`,
  то есть счёт символов, и адрес на 300 кириллических букв (600 байт)
  проходил проверку, чтобы потом получить отказ от сервера.
"""
import re

__all__ = [
    "to_ascii_domain",
    "has_non_ascii_local",
    "validate_email_syntax",
    "MAX_EMAIL_BYTES",
    "MAX_LOCAL_BYTES",
    "MAX_DOMAIN_BYTES",
]

# RFC 5321 §4.5.3.1 — пределы в октетах.
MAX_LOCAL_BYTES = 64
MAX_DOMAIN_BYTES = 255
MAX_EMAIL_BYTES = 320

# TLD: либо обычные буквы, либо punycode-зона IDN (xn--p1ai для .рф, xn--80asehdb
# для .онлайн). Без второй половины любой интернационализированный домен после
# перевода в punycode не проходил регулярку и получал вердикт «Bad Syntax».
_TLD_PART = r'(?:xn--[a-zA-Z0-9\-]{2,}|[a-zA-Z]{2,})'

# RFC 5322 — строгая проверка синтаксиса email (п.1.3)
_RFC5322_REGEX = re.compile(
    r'^[a-zA-Z0-9]'                # Начинается с буквы или цифры
    r'[a-zA-Z0-9._%+\-]{0,63}'     # Локальная часть: до 64 символов
    r'@'
    r'[a-zA-Z0-9]'                 # Домен начинается с буквы/цифры
    r'[a-zA-Z0-9.\-]{0,251}'       # Тело домена
    r'\.' + _TLD_PART + r'$'       # TLD: буквы либо punycode-зона
)

# Домен отдельно — нужен, когда локальная часть не-ASCII и общей регуляркой
# адрес не проверить.
_DOMAIN_REGEX = re.compile(
    r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,251}\.' + _TLD_PART + r'$'
)

_BAD_SYNTAX_PATTERNS = re.compile(
    r'(\.\.|'           # Двойные точки
    r'\.@|'             # Точка перед @
    r'@\.|'             # Точка после @
    r'\s)'              # Пробелы
)


def _byte_length(text):
    """Длина в октетах. Именно её ограничивает RFC, а не число символов."""
    try:
        return len(text.encode("utf-8"))
    except (AttributeError, UnicodeError):
        return 0


def to_ascii_domain(domain: str):
    """Переводит домен в punycode. None — домен непереводим (значит, битый).

    почта.рф -> xn--80a1acny.xn--p1ai,  münchen.de -> xn--mnchen-3ya.de
    """
    if not isinstance(domain, str) or not domain:
        return None
    try:
        if domain.isascii():
            return domain
        return domain.encode('idna').decode('ascii')
    except Exception:
        return None


def has_non_ascii_local(email: str) -> bool:
    """True, если локальная часть содержит не-ASCII символы (нужен SMTPUTF8).

    Такой адрес законен по RFC 6531, но `RCPT TO` с ним отправить нельзя:
    smtplib кодирует команду в ASCII. Это повод для `unknown`, а не для `invalid`.
    """
    if not isinstance(email, str) or "@" not in email:
        return False
    return not email.rsplit("@", 1)[0].isascii()


def validate_email_syntax(email: str) -> bool:
    """Проверяет синтаксис email. True — адрес построен корректно.

    Интернационализированные адреса (IDN-домен, не-ASCII локальная часть)
    считаются КОРРЕКТНЫМИ. Раньше их резала ASCII-регулярка, и живой
    ivan@почта.рф получал вердикт `invalid` «Bad Syntax» — ложное захоронение
    лида на ровном месте. Проверяемость таких адресов решается отдельно.
    """
    if not email or not isinstance(email, str):
        return False
    if _byte_length(email) > MAX_EMAIL_BYTES:
        return False
    if email.count('@') != 1:
        return False
    if _BAD_SYNTAX_PATTERNS.search(email):
        return False

    local, _, domain = email.partition('@')
    if _byte_length(local) > MAX_LOCAL_BYTES:
        return False

    domain_ascii = to_ascii_domain(domain)
    if not domain_ascii:
        return False
    # Проверяем длину именно punycode-вида: по проводу уходит он, и лимит в
    # 255 октетов относится к нему. `münchen.de` короче своего xn---варианта.
    if _byte_length(domain_ascii) > MAX_DOMAIN_BYTES:
        return False

    # Не-ASCII локальная часть: общей регуляркой её не проверить, поэтому
    # смотрим только длину и домен. Отбраковывать адрес за это нельзя.
    if not local.isascii():
        return bool(local) and bool(_DOMAIN_REGEX.match(domain_ascii))

    return bool(_RFC5322_REGEX.match(f"{local}@{domain_ascii}"))
