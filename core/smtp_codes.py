import re
from typing import Dict, Iterable, Optional, Sequence, Tuple

Verdict = Dict[str, str]
Enhanced = Optional[Tuple[int, int, int]]

__all__ = [
    "classify_smtp_response",
    "enhanced_status",
    "looks_transient",
    "looks_like_ip_reputation",
    "TRANSIENT_TEXT_MARKERS",
    "IP_REPUTATION_MARKERS",
    "RECIPIENT_NEGATIONS",
    "WEAK_REJECT_REASON",
]

WEAK_REJECT_REASON = "Получатель отвергнут"


_ENHANCED_RE = re.compile(r'(?:^|[\s\-])([245])\.(\d{1,3})\.(\d{1,3})(?![\d.])')


IP_REPUTATION_MARKERS = (
    "our ip blocked", "our ip blacklisted", "client host", "reputation",
    "spamhaus", "barracuda", "blacklist", "black list", "rbl", "dnsbl",
    "listed in", "listed by", "service unavailable", "5.7.1", "5.7.606",
    "poor reputation", "blocked using", "bad reputation", "spamcop",
    "sorbs", "uceprotect", "abuseat", "spamrats", "senderscore",
)

_HARD_REPUTATION_MARKERS = (
    "our ip blocked", "our ip blacklisted", "client host", "spamhaus",
    "barracuda", "blacklist", "black list", "rbl", "dnsbl", "listed in",
    "listed by", "blocked using", "poor reputation", "bad reputation",
    "spamcop", "sorbs", "uceprotect", "abuseat", "spamrats", "senderscore",
    "sending mta", "sending ip", "ip address sending",
)

_POLICY_MARKERS = IP_REPUTATION_MARKERS + (
    "spam", "policy", "blocked", "block list", "denied", "not allowed",
    "refused due to", "content rejected", "message rejected",
    "reject due", "abuse", "bulk", "unsolicited", "compliance",
    "security", "virus", "malware", "phishing", "attack",
)

_SENDER_MARKERS = (
    "sender", "relay", "relaying", "not permitted", "unable to relay",
    "sender verify", "spf", "dmarc", "dkim", "helo", "ehlo",
    "authentication", "not authorized", "access denied", "auth required",
    "must be authenticated", "from address", "return path", "return-path",
    "mail from", "originating", "no valid sender",
)

_EXPLICIT_SENDER_MARKERS = (
    "sender", "mail from", "relay", "relaying", "unable to relay",
    "return path", "return-path", "spf", "dmarc", "dkim",
)

_SENDER_SUBJECT_MARKERS = (
    "sender address rejected", "sender rejected", "sender verify failed",
    "sender verification failed", "unverified sender", "sender unknown",
    "unknown sender", "sender address is not", "sender domain",
    "mail from rejected", "rejected mail from", "bad sender",
    "invalid sender", "sender not allowed",
)

_RECIPIENT_SUBJECT_MARKERS = (
    "recipient address rejected", "recipient rejected", "recipient unknown",
    "unknown recipient", "no such recipient", "recipient not found",
    "recipient does not exist", "invalid recipient",
)

TRANSIENT_TEXT_MARKERS = (
    "temporarily", "temporary", "try again", "try later", "retry",
    "later", "deferred", "defer", "greylist", "grey list", "throttl",
    "too busy", "server busy", "overloaded", "over load", "rate limit",
    "resources temporarily", "not available at this time", "at this time",
    "come back", "in a few", "currently unavailable", "too many connections",
    "connection limit", "please wait",
)

_NO_MAILBOX_PROOF = (
    "does not exist", "doesn't exist", "no such user", "no such recipient",
    "no such mailbox", "no such address", "no such person", "user unknown",
    "unknown user", "recipient unknown", "unknown recipient",
    "user not found", "recipient not found", "mailbox not found",
    "no mailbox", "nonexistent", "non-existent", "no account",
    "account does not exist", "unknown in virtual mailbox table",
    "unknown in virtual alias table", "unknown in local recipient table",
    "unknown in relay recipient table", "user does not exist",
    "mailbox does not exist", "recipient does not exist",
    "address does not exist", "not a valid mailbox", "no valid recipients",
    "user doesn't have", "user does not have", "doesn't have an account",
    "does not have an account", "doesn't have a yahoo", "doesn't have a aol",
    "recipient not recognized", "addressee unknown", "no such local user",
    "user is unknown", "invalid recipient", "unknown address",
    "account has been disabled or discontinued",
)

_AMBIGUOUS_NO_MAILBOX = (
    "mailbox unavailable", "mailbox not available", "invalid mailbox",
    "invalid address", "bad destination", "address rejected",
    "recipient rejected", "undeliverable", "unrouteable", "unroutable",
    "recipient address rejected", "bad address", "user rejected",
)

RECIPIENT_NEGATIONS = (
    "no such", "not exist", "doesn't exist", "does not exist", "unknown",
    "not found", "no longer", "invalid", "rejected", "reject", "disabled",
    "unavailable", "not available", "cannot", "can not", "can't", "refused",
    "denied", "no mailbox", "nonexistent", "non-existent", "not accepted",
    "unrouteable", "unroutable", "undeliverable", "bad ", "illegal",
)

_DISABLED_MARKERS = (
    "disabled", "deactivated", "suspended", "frozen", "locked", "closed",
    "inactive account", "account is inactive", "is inactive",
    "no longer active", "account expired",
    "has been discontinued", "not accepting mail",
)

_RECIPIENT_RATE_MARKERS = (
    "receiving email at a rate", "receiving mail at a rate",
    "receiving email too quickly", "receiving mail too quickly",
    "receive limit", "message receive limit",
)

_NO_PTR_MARKERS = (
    "ptr record", "reverse dns", "forward-confirmed", "no ptr",
)

_MAILBOX_FULL_MARKERS = (
    "over quota", "overquota", "quota exceeded", "exceeded quota",
    "exceeded storage", "storage allocation", "mailbox full",
    "mailbox is full", "mail box is full", "mailbox has exceeded",
    "over the allowed quota", "quota violation", "recipient overquota",
    "user is over quota", "mailfolder is full", "inbox is full",
    "not enough space in mailbox", "mailbox size limit exceeded",
    "exceeded the storage", "user has exhausted",
    "out of storage space",
)

_SERVER_STORAGE_MARKERS = (
    "insufficient system storage", "system storage", "disk full",
    "no space left", "out of disk", "server storage",
)

_MESSAGE_SIZE_MARKERS = (
    "message size", "size exceeds", "too large", "message too big",
    "exceeds maximum", "exceeds size limit", "line limit", "message length",
)


def _contains(haystack: object, needles: object) -> bool:
    if not isinstance(haystack, str) or not haystack:
        return False
    if not needles or isinstance(needles, (str, bytes)):
        return False
    try:
        items = iter(needles)    # type: ignore[call-overload]
    except TypeError:
        return False
    return any(isinstance(item, str) and item in haystack for item in items)


def enhanced_status(message: object) -> Enhanced:
    if not isinstance(message, str):
        return None
    found = _ENHANCED_RE.search(message)
    if not found:
        return None
    status_class, subject, detail = found.groups()
    return int(status_class), int(subject), int(detail)


def looks_transient(reason: object) -> bool:
    if not isinstance(reason, str) or not reason:
        return False
    return _contains(reason.lower(), TRANSIENT_TEXT_MARKERS)


def looks_like_ip_reputation(reason: object) -> bool:
    if not isinstance(reason, str) or not reason:
        return False
    return _contains(reason.lower(), IP_REPUTATION_MARKERS)


def _decode(message: object) -> str:
    if isinstance(message, bytes):
        return message.decode("utf-8", "ignore").lower()
    return str(message).lower()


def classify_smtp_response(code: object, message: object) -> Verdict:
    try:
        numeric = int(code)          # type: ignore[call-overload]
    except (TypeError, ValueError):
        return {"status": "unknown", "reason": "Некорректный ответ сервера"}

    msg = _decode(message)
    enhanced = enhanced_status(msg)
    prefix = ""
    if enhanced:
        prefix = "%d.%d.%d " % enhanced

    def result(status: str, reason: object) -> Verdict:
        return _verdict(status, reason, prefix)

    if numeric == 250:
        return result("valid", "250 OK")
    if numeric == 251:
        return result("valid", "251 User Not Local, Will Forward")
    if numeric == 252:
        return result("unknown",
                      "252 Сервер не берётся подтвердить получателя "
                      "(RFC 5321 §3.5.3) — о существовании ящика не сказано")
    if 200 <= numeric < 300:
        return result("valid", f"{numeric} Accepted")

    if numeric in (452, 552, 522, 550):
        if _contains(msg, _SERVER_STORAGE_MARKERS):
            return result("unknown", f"{numeric} На сервере кончилось место (о ящике не сказано)")
        if _contains(msg, _MESSAGE_SIZE_MARKERS):
            return result("unknown", f"{numeric} Ограничение на размер письма (о ящике не сказано)")
        full_code = enhanced is not None and enhanced[1:] == (2, 2)
        no_mailbox = ((enhanced is not None and enhanced[1:] in ((1, 1), (1, 10)))
                      or (enhanced is None and _contains(msg, _NO_MAILBOX_PROOF)))
        if full_code or (_contains(msg, _MAILBOX_FULL_MARKERS) and not no_mailbox):
            return result("full", f"{numeric} Ящик переполнен — письмо не будет "
                                  "доставлено; переполняется обычно ящик, "
                                  "которым не пользуются")

    if 400 <= numeric < 500:
        return _classify_temporary(numeric, msg, enhanced, prefix)

    if 500 <= numeric < 600:
        return _classify_permanent(numeric, msg, enhanced, prefix)

    return result("unknown", f"{numeric} Unknown Response")


def _verdict(status: str, reason: object, prefix: object = "") -> Verdict:
    return {"status": status,
            "reason": (prefix if isinstance(prefix, str) else "") + str(reason)}


def _classify_temporary(code: int, msg: object, enhanced: Enhanced,
                        prefix: str = "") -> Verdict:
    msg = msg if isinstance(msg, str) else ""

    def result(status: str, reason: object) -> Verdict:
        return _verdict(status, reason, prefix)
    if (isinstance(enhanced, (tuple, list)) and tuple(enhanced[1:]) in ((7, 23), (7, 25))) \
            or _contains(msg, _NO_PTR_MARKERS):
        return result("unknown", f"{code} У нашего IP нет обратного DNS (PTR) — "
                                 "почтовик не принимает; нужен прокси или VPS с PTR-записью")

    if code == 421:
        return result("unknown", "421 Service Busy (Rate Limit)")

    greylisted = _contains(msg, ("grey", "greylist", "grey list", "try again",
                                 "try later", "deferred", "come back"))
    rate_limited = _contains(msg, ("rate", "too many", "throttl", "limit exceeded",
                                   "too fast", "too quickly", "connection limit"))

    if code == 450:
        if greylisted:
            return result("greylisted", "450 Greylisted (Retry Later)")
        if rate_limited:
            return result("unknown", "450 Rate Limited (Retry Later)")
        if _contains(msg, ("later", "busy", "temporarily", "temporary")):
            return result("greylisted", "450 Greylisted (Retry Later)")
        return result("unknown", "450 Temp Unavailable")

    if code == 451:
        if greylisted:
            return result("greylisted", "451 Greylisted (Retry Later)")
        return result("greylisted", "451 Server Error")

    if code == 452:
        if _contains(msg, ("too many", "recipients")):
            return result("unknown", "452 Too Many Recipients")
        return result("unknown", "452 Temp Error")

    if rate_limited:
        return result("unknown", f"{code} Rate Limited (Retry Later)")
    if greylisted:
        return result("greylisted", f"{code} Greylisted (Retry Later)")
    return result("unknown", f"{code} Temp Error")


def _classify_permanent(code: int, msg: object, enhanced: Enhanced,
                        prefix: str = "") -> Verdict:
    msg = msg if isinstance(msg, str) else ""

    def result(status: str, reason: object) -> Verdict:
        return _verdict(status, reason, prefix)
    subject = detail = None
    if isinstance(enhanced, (tuple, list)) and len(enhanced) >= 3:
        subject, detail = enhanced[1], enhanced[2]

    if isinstance(enhanced, (tuple, list)) and enhanced and enhanced[0] == 4:
        return result("risky", f"{code} Постоянный код с временным статусом (ящик не проверен)")

    if _contains(msg, TRANSIENT_TEXT_MARKERS):
        return result("risky", f"{code} Временный отказ с постоянным кодом (ящик не проверен)")

    if isinstance(code, int) and 500 <= code <= 504:
        return result("unknown",
                      f"{code} Сервер не понял команду (о ящике не сказано ничего)")

    if _contains(msg, _RECIPIENT_RATE_MARKERS):
        return result("unknown", f"{code} Ящик существует, но сейчас не принимает "
                                 "— лимит приёма у получателя (rate limit), "
                                 "перепроверить позже")

    proof = _contains(msg, _NO_MAILBOX_PROOF)
    reputation = _contains(msg, _HARD_REPUTATION_MARKERS)

    if (subject == 4 and detail == 1 and not reputation
            and "recipient address rejected: access denied" in msg):
        return result("invalid", f"{code} Microsoft 365: получателя нет в "
                                 "каталоге организации (DBEB)")

    if reputation and not proof:
        return result("unknown", f"{code} Отказ по политике/репутации IP (ящик может существовать)")

    sender_named = (subject == 1 and detail in (7, 8)) or (
        _contains(msg, _SENDER_SUBJECT_MARKERS)
        and not _contains(msg, _RECIPIENT_SUBJECT_MARKERS))
    if sender_named or (not proof and _contains(msg, _EXPLICIT_SENDER_MARKERS)):
        return result("unknown", f"{code} Отказ отправителю/релею (ящик может существовать)")

    policy = (subject == 7) or _contains(msg, _POLICY_MARKERS)
    if policy and (reputation or not proof):
        return result("unknown", f"{code} Отказ по политике/репутации IP (ящик может существовать)")

    if not proof and _contains(msg, _SENDER_MARKERS):
        return result("unknown", f"{code} Отказ отправителю/релею (ящик может существовать)")

    if subject == 1 and detail in (1, 10):
        return result("invalid", f"{code} {prefix_name(detail)}")

    if subject == 1 and detail == 3:
        return result("risky", f"{code} Сервер не принял ФОРМУ адреса "
                               "(о существовании ящика не сказано)")

    if subject == 1 and detail == 2:
        return result("risky", f"{code} Отвергнут домен получателя "
                               "(о самом ящике не сказано)")

    if proof:
        return result("invalid", f"{code} Получателя не существует")

    if code not in (521, 530, 535, 571):
        if subject == 2 and detail == 1:
            return result("disabled", f"{code} Ящик отключён — письма не принимаются")
        if _contains(msg, _DISABLED_MARKERS):
            return result("disabled", f"{code} Ящик отключён — письма не принимаются")

    not_about_mailbox = subject in (3, 4, 6)
    not_about_reason = (f"{code} Отказ про почтовую систему, маршрут или "
                        "содержимое письма, а не про ящик (не доказано)")

    if _contains(msg, _AMBIGUOUS_NO_MAILBOX):
        if not_about_mailbox:
            return result("risky", not_about_reason)
        return result("invalid", f"{code} {WEAK_REJECT_REASON}")

    if code == 551:
        return result("risky", "551 User Not Local (ящик может существовать на другом сервере)")

    if code == 553:
        return result("risky", "553 Адрес не принят (кому именно — не сказано)")

    if _contains(msg, ("recipient", "mailbox", "user", "address")):
        if _contains(msg, RECIPIENT_NEGATIONS):
            if not_about_mailbox:
                return result("risky", not_about_reason)
            return result("invalid", f"{code} {WEAK_REJECT_REASON}")
        return result("risky", f"{code} Упомянут получатель без явного отрицания (не доказано)")

    if code in (500, 501, 502, 503, 504, 521, 530, 535, 571):
        return result("unknown", f"{code} Ошибка сервера/авторизации (ящик может существовать)")

    if code == 554:
        return result("unknown", "554 Transaction Failed")

    return result("risky", f"{code} Отказ без объяснения (не доказано)")


def prefix_name(detail: object) -> str:
    names = {
        1: "Получателя не существует",
        3: "Некорректный адрес получателя",
        10: "Адрес не существует",
    }
    if isinstance(detail, int):
        return names.get(detail, "Получателя не существует")
    return "Получателя не существует"
