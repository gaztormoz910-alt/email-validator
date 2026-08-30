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
    "has_quoted_local",
    "MAX_LABEL_BYTES",
    "validate_email_syntax",
    "harvest_pattern",
    "MAX_EMAIL_BYTES",
    "MAX_LOCAL_BYTES",
    "MAX_DOMAIN_BYTES",
]

# RFC 5321 §4.5.3.1 — пределы в октетах.
MAX_LOCAL_BYTES = 64
# RFC 1035 §2.3.4 — метка домена не длиннее 63 октетов. Это не наша строгость,
# а физический предел DNS: метку длиннее зарегистрировать нельзя, и запрос по
# ней не уйдёт. Без этой проверки адрес с меткой в 250 символов проходил
# синтаксис и тратил впустую запрос DNS и попытку SMTP.
MAX_LABEL_BYTES = 63
MAX_DOMAIN_BYTES = 255
MAX_EMAIL_BYTES = 320

# TLD: либо обычные буквы, либо punycode-зона IDN (xn--p1ai для .рф, xn--80asehdb
# для .онлайн). Без второй половины любой интернационализированный домен после
# перевода в punycode не проходил регулярку и получал вердикт «Bad Syntax».
_TLD_PART = r'(?:xn--[a-zA-Z0-9\-]{2,}|[a-zA-Z]{2,})'

# Разрешённые символы локальной части — ПОЛНЫЙ набор atext из RFC 5322 §3.2.3:
#
#   ALPHA / DIGIT / ! # $ % & ' * + - / = ? ^ _ ` { | } ~
#
# Раньше здесь стоял урезанный набор `._%+-`, и это молча убивало законные
# адреса ПРИГОВОРОМ БЕЗ ЗАПРОСА К СЕРВЕРУ — то есть неисправимо. Замерено на
# наборе живых форм: из 24 отвергались 14. Среди них o'brien@example.com —
# апостроф в ирландских и итальянских фамилиях встречается постоянно, и такие
# ящики существуют миллионами.
#
# Ошибка была тем опаснее, что выглядела строгостью: комментарий обещал
# «RFC 5322», а регулярка была строже самого RFC.
_ATEXT = r"a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-"

# Локальная часть — dot-atom (RFC 5322 §3.2.3): группы atext через точки.
# Точка не может стоять первой, последней или идти подряд, и это правило
# самого стандарта, а не наша дополнительная строгость.
_LOCAL_PART = r'[' + _ATEXT + r']+(?:\.[' + _ATEXT + r']+)*'

# Метка домена по RFC 1035 §2.3.1: начинается и заканчивается буквой или
# цифрой, дефисы допустимы только внутри. Это не наша дополнительная
# строгость, а правило DNS: метку вида `e-` зарегистрировать нельзя, поэтому
# отказ здесь — факт, а не догадка. Punycode (`xn--p1ai`) правилу подчиняется:
# дефисы у него внутри.
_LABEL = r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]*[a-zA-Z0-9])?'
_DOMAIN_BODY = r'(?:' + _LABEL + r'\.)+' + _TLD_PART

# RFC 5322 — проверка синтаксиса email (п.1.3)
_RFC5322_REGEX = re.compile(
    r'^' + _LOCAL_PART +
    r'@' + _DOMAIN_BODY + r'$'
)

# Домен отдельно — нужен, когда локальная часть не-ASCII и общей регуляркой
# адрес не проверить.
_DOMAIN_REGEX = re.compile(r'^' + _DOMAIN_BODY + r'$')

_BAD_SYNTAX_PATTERNS = re.compile(
    r'(\.\.|'           # Двойные точки
    r'\.@|'             # Точка перед @
    r'@\.|'             # Точка после @
    r'\s)'              # Пробелы
)


def harvest_pattern(wide=True):
    """Образец для ВЫЛАВЛИВАНИЯ адреса из сплошного текста.

    Отдельно от проверки синтаксиса, потому что задача другая: там ответ
    «да/нет» на готовую строку, здесь — где именно в тексте адрес кончается.
    Но набор символов обязан быть один и тот же, иначе сборщик приносит в
    базу обрезок: `o'brien@gmail.com` попадал как `obrien@gmail.com` — ящик
    существующий, но ЧУЖОЙ, и владелец терял человека, ни разу не увидев его
    настоящего адреса.

    wide=False — набор для текста, В КОТОРОМ ЕСТЬ ССЫЛКИ (страница из
    поисковика). Оттуда убраны только знаки, которыми устроен сам адрес
    ссылки: `= & ? / # %`. Из `?email=john@gmail.com` широкий набор вытащил
    бы `?email=john@gmail.com` целиком — законный по RFC, но не тот адрес.
    Остальное из atext остаётся: апостроф в `o'brien@gmail.com` — это часть
    фамилии, и выбрасывать его значит подставить чужой существующий ящик.
    """
    # Знаки, из которых состоит адрес ссылки. По RFC они в локальной части
    # законны, но внутри URL значат другое.
    url_structural = "=&?/#%"
    atext = _ATEXT if wide else "".join(
        ch for ch in _ATEXT if ch not in url_structural)
    # Точка внутри локальной части — РАЗДЕЛИТЕЛЬ, а не обычный знак: она не
    # входит в atext и не может стоять с краю. Без этого правила образец
    # цеплялся с последней точки, и `john.doe@gmail.com` попадал в базу как
    # `doe@gmail.com` — самый частый вид адреса, испорченный на каждой строке.
    local = r'[' + atext + r']+(?:\.[' + atext + r']+)*'
    return re.compile(local + r'@' + _LABEL + r'(?:\.' + _LABEL + r')*\.' + _TLD_PART)


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


def has_quoted_local(email):
    """Локальная часть в кавычках: `"john smith"@example.com`.

    По RFC 5321 §4.1.2 это законная форма, но проверить её мы не можем:
    кавычки надо сохранить в команде RCPT, а внутри них законны пробел и даже
    собственная `@`, из-за чего адрес не разбирается обычным способом.

    Отдельная функция нужна ровно затем, чтобы такой адрес получил «не
    проверено», а не «неправильный синтаксис». Разница принципиальна: второе
    — это приговор живому ящику без единого запроса к серверу.
    """
    if not isinstance(email, str) or "@" not in email:
        return False
    local = email.rpartition("@")[0].strip()
    return len(local) >= 2 and local.startswith('"') and local.endswith('"')


def _labels_fit(domain_ascii):
    """Каждая метка домена укладывается в предел DNS."""
    if not isinstance(domain_ascii, str) or not domain_ascii:
        return False
    for label in domain_ascii.split("."):
        if not label or _byte_length(label) > MAX_LABEL_BYTES:
            return False
    return True


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
    if not _labels_fit(domain_ascii):
        return False

    # Не-ASCII локальная часть: общей регуляркой её не проверить, поэтому
    # смотрим только длину и домен. Отбраковывать адрес за это нельзя.
    if not local.isascii():
        return bool(local) and bool(_DOMAIN_REGEX.match(domain_ascii))

    return bool(_RFC5322_REGEX.match(f"{local}@{domain_ascii}"))
