"""Расшифровка ответа почтового сервера в вердикт о ящике.

Здесь живёт единственное правило, из-за которого этот модуль вообще стоит
отдельно от всего остального: **`invalid` ставится ТОЛЬКО тогда, когда сервер
доказал, что получателя нет.** Всё прочее — `risky` или `unknown`.

Асимметрия цены ошибки огромна и несимметрична в обе стороны, поэтому обе
крайности одинаково опасны:

* Ложный `invalid` — навсегда потерянный живой контакт. Владелец базы удалит
  адрес и никогда не узнает, что он был рабочим.
* Ложный `valid` — отправленное письмо в несуществующий ящик, отскок и
  испорченная репутация отправителя.

Ложный `unknown` стоит одной перепроверки. Поэтому при любых сомнениях
вердикт — `unknown`/`risky`, и никогда не крайность.

Что здесь принципиально устроено иначе, чем в самописных валидаторах:

**Расширенный код (RFC 3463) читается как доказательство, а не как украшение.**
Строка `5.7.1` в ответе — это заявление сервера «отказ по политике/репутации»,
и оно означает, что про ящик не сказано НИЧЕГО. Строка `5.1.1` — «нет такого
почтового ящика», и это самое сильное доказательство из существующих. Раньше
этот код только подставлялся в текст причины.

**Подстрочный поиск идёт внутри ветки кода, а не выше неё,** и подстроки
подобраны так, чтобы не ловить чужие слова. Классическая ловушка: `"over" in
msg` ради `over quota` заодно ловит `server overloaded` — и перегруженный
сервер выдаёт живой ящик там, где ящика может не быть вовсе.
"""
import re
from typing import Dict, Iterable, Optional, Sequence, Tuple

# Вердикт — это всегда пара «статус, причина». Отдельное имя типа, чтобы
# сигнатуры читались, а не расшифровывались.
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
]


# Расширенный код состояния: "550 5.1.1 ..." -> (5, 1, 1).
# Требуем границу слева, иначе версия в баннере вида "8.14.7" читается как
# статус. Справа граница нужна, чтобы "5.1.10" не читалось как "5.1.1".
_ENHANCED_RE = re.compile(r'(?:^|[\s\-])([245])\.(\d{1,3})\.(\d{1,3})(?![\d.])')


# Формулировки, по которым видно: отказали не ящику, а нашему исходящему IP
# либо политике сервера. О существовании ящика они не говорят ничего.
IP_REPUTATION_MARKERS = (
    "our ip blocked", "our ip blacklisted", "client host", "reputation",
    "spamhaus", "barracuda", "blacklist", "black list", "rbl", "dnsbl",
    "listed in", "listed by", "service unavailable", "5.7.1", "5.7.606",
    "poor reputation", "blocked using", "bad reputation", "spamcop",
    "sorbs", "uceprotect", "abuseat", "spamrats", "senderscore",
)

# Формулировки, которые НЕ МОГУТ означать ничего, кроме нашего исходящего
# адреса. Только они имеют право отменить прямое доказательство отсутствия
# ящика: сервер, назвавший Spamhaus, до адреса ещё не дошёл.
#
# Голого расширенного кода "5.7.1" здесь нет намеренно. Yandex отвечает
# `550 5.7.1 No such user!` — код у него служебный, а смысл в тексте, и
# приговор по такому ответу законен. Список выше, где "5.7.1" есть, годится
# для диагностики прокси, но не для отмены доказательства.
_HARD_REPUTATION_MARKERS = (
    "our ip blocked", "our ip blacklisted", "client host", "spamhaus",
    "barracuda", "blacklist", "black list", "rbl", "dnsbl", "listed in",
    "listed by", "blocked using", "poor reputation", "bad reputation",
    "spamcop", "sorbs", "uceprotect", "abuseat", "spamrats", "senderscore",
    "sending mta", "sending ip", "ip address sending",
)

# Более широкий список «это про политику, а не про ящик». Используется как
# запрет на приговор, а не как самостоятельный вердикт.
_POLICY_MARKERS = IP_REPUTATION_MARKERS + (
    "spam", "policy", "blocked", "block list", "denied", "not allowed",
    "refused due to", "content rejected", "message rejected",
    "reject due", "abuse", "bulk", "unsolicited", "compliance",
    "security", "virus", "malware", "phishing", "attack",
)

# Отказ ОТПРАВИТЕЛЮ. Про получателя не говорит ничего: до него дело не дошло.
_SENDER_MARKERS = (
    "sender", "relay", "relaying", "not permitted", "unable to relay",
    "sender verify", "spf", "dmarc", "dkim", "helo", "ehlo",
    "authentication", "not authorized", "access denied", "auth required",
    "must be authenticated", "from address", "return path", "return-path",
    "mail from", "originating", "no valid sender",
)

# Подмножество, которое не может означать ничего, кроме отправителя: слово
# «sender» и команда MAIL FROM про получателя не говорят по определению.
# «access denied» сюда не входит намеренно — так отказывают и получателю.
_EXPLICIT_SENDER_MARKERS = (
    "sender", "mail from", "relay", "relaying", "unable to relay",
    "return path", "return-path", "spf", "dmarc", "dkim",
)

# Отказ ВРЕМЕННЫЙ, даже если код постоянный. Сервер, который в ответе 550
# пишет "try again later", противоречит сам себе, и верить в этом споре надо
# тексту: цена ошибки — похороненный живой адрес.
TRANSIENT_TEXT_MARKERS = (
    "temporarily", "temporary", "try again", "try later", "retry",
    "later", "deferred", "defer", "greylist", "grey list", "throttl",
    "too busy", "server busy", "overloaded", "over load", "rate limit",
    "resources temporarily", "not available at this time", "at this time",
    "come back", "in a few", "currently unavailable", "too many connections",
    "connection limit", "please wait",
)

# ЯЩИК ТОЧНО НЕ СУЩЕСТВУЕТ. Формулировки подобраны так, что ни одна из них не
# может означать «отказ по политике»: сервер прямо говорит о получателе и
# прямо его отрицает. Только эти строки имеют право пережить проверку на
# политику и вынести приговор.
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

# ЯЩИКА СКОРЕЕ ВСЕГО НЕТ, но формулировка используется и для политики.
# Приговор по ней выносится только после того, как политика исключена.
_AMBIGUOUS_NO_MAILBOX = (
    "mailbox unavailable", "mailbox not available", "invalid mailbox",
    "invalid address", "bad destination", "address rejected",
    "recipient rejected", "undeliverable", "unrouteable", "unroutable",
    "recipient address rejected", "bad address", "user rejected",
)

# Отрицания, при которых упоминание получателя действительно означает, что
# ящика нет. Без одного из них 550 про «mailbox» ничего не доказывает.
RECIPIENT_NEGATIONS = (
    "no such", "not exist", "doesn't exist", "does not exist", "unknown",
    "not found", "no longer", "invalid", "rejected", "reject", "disabled",
    "unavailable", "not available", "cannot", "can not", "can't", "refused",
    "denied", "no mailbox", "nonexistent", "non-existent", "not accepted",
    "unrouteable", "unroutable", "undeliverable", "bad ", "illegal",
)

# Ящик есть, но заморожен: человек существует, письмо не дойдёт.
_DISABLED_MARKERS = (
    "disabled", "deactivated", "suspended", "frozen", "locked", "closed",
    "inactive account", "no longer active", "account expired",
    "has been discontinued", "not accepting mail",
)

# Ящик ПЕРЕПОЛНЕН. Это доказательство не только существования, но и активного
# пользования — самый ценный положительный сигнал после чистого 250.
#
# Ни одна из строк здесь не является подстрокой чужого слова: "over quota"
# нельзя спутать с "overloaded", "quota" — со словом из отчёта о нагрузке.
# Голого "over" в списке нет намеренно: именно оно ловило "server overloaded".
_MAILBOX_FULL_MARKERS = (
    "over quota", "overquota", "quota exceeded", "exceeded quota",
    "exceeded storage", "storage allocation", "mailbox full",
    "mailbox is full", "mail box is full", "mailbox has exceeded",
    "over the allowed quota", "quota violation", "recipient overquota",
    "user is over quota", "mailfolder is full", "inbox is full",
    "not enough space in mailbox", "mailbox size limit exceeded",
    "exceeded the storage", "user has exhausted",
)

# Переполнен СЕРВЕР, а не ящик. Про получателя не говорит ничего.
_SERVER_STORAGE_MARKERS = (
    "insufficient system storage", "system storage", "disk full",
    "no space left", "out of disk", "server storage",
)

# Ограничение на РАЗМЕР ПИСЬМА. Ящик тут ни при чём, а код совпадает с
# «переполнен» (552), поэтому проверяется отдельно и раньше.
_MESSAGE_SIZE_MARKERS = (
    "message size", "size exceeds", "too large", "message too big",
    "exceeds maximum", "exceeds size limit", "line limit", "message length",
)


def _contains(haystack: object, needles: object) -> bool:
    """Есть ли хоть одна из подстрок в тексте. Мусор — это «нет», а не падение.

    Функция вызывается на каждый ответ сервера, и ответ приходит из СЕТИ.
    Уронить обработку адреса на кривом ответе нельзя: исключение проглотится
    уровнем выше, адрес выпадет из выдачи, а счётчик его засчитает.
    """
    if not isinstance(haystack, str) or not haystack:
        return False
    if not needles or isinstance(needles, (str, bytes)):
        return False
    try:
        items = iter(needles)    # type: ignore[call-overload]
    except TypeError:            # не список подстрок, а что-то неперебираемое
        return False
    return any(isinstance(item, str) and item in haystack for item in items)


def enhanced_status(message: object) -> Enhanced:
    """Расширенный код состояния (RFC 3463) как кортеж (class, subject, detail).

    Возвращает None, если сервер его не прислал. Именно этот код, а не
    трёхзначный, несёт смысл «почему»: у 550 их бывает добрый десяток, и
    `5.1.1` (нет ящика) с `5.7.1` (отказ по политике) — разные вселенные.
    """
    if not isinstance(message, str):
        return None
    found = _ENHANCED_RE.search(message)
    if not found:
        return None
    status_class, subject, detail = found.groups()
    return int(status_class), int(subject), int(detail)


def looks_transient(reason: object) -> bool:
    """True, если текст ответа говорит о временной проблеме, а не о ящике."""
    if not isinstance(reason, str) or not reason:
        return False
    return _contains(reason.lower(), TRANSIENT_TEXT_MARKERS)


def looks_like_ip_reputation(reason: object) -> bool:
    """True, если причина отказа — репутация исходящего IP, а не ящик."""
    if not isinstance(reason, str) or not reason:
        return False
    return _contains(reason.lower(), IP_REPUTATION_MARKERS)


def _decode(message: object) -> str:
    if isinstance(message, bytes):
        return message.decode("utf-8", "ignore").lower()
    return str(message).lower()


def classify_smtp_response(code: object, message: object) -> Verdict:
    """Вердикт о ящике по одному ответу сервера.

    Возвращает {"status": ..., "reason": ...}, где status — один из
    valid / invalid / risky / greylisted / unknown / catchall не выдаётся
    (это решение уровнем выше, по нескольким пробам).

    Порядок веток здесь — не стиль, а содержание. Каждая следующая проверка
    опирается на то, что предыдущая уже исключила свой случай, и переставить
    их местами значит поменять вердикты.
    """
    # После int() код — точно число. Отдельное имя нужно, чтобы это видел и
    # человек, и проверка типов: дальше по функции идут сравнения диапазонов,
    # и в них нельзя приходить с object.
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

    # ---------------------------------------------------------------- 2xx --
    # 250 — принято. 251 — «получателя тут нет, но письмо переправим»: адрес
    # доставляем, и это тоже успех, а не отказ.
    if numeric == 250:
        return result("valid", "250 OK")
    if numeric == 251:
        return result("valid", "251 User Not Local, Will Forward")
    # 252 — «не берусь проверить получателя, но письмо приму и попробую
    # доставить» (RFC 5321 §3.5.3). Это ПРЯМОЙ отказ отвечать о ящике, и
    # засчитывать его как доказательство существования нельзя: письмо уйдёт,
    # а получателя может не быть — отскок придёт потом, когда база уже
    # разослана. Для VRFY это отсекалось отдельно (core/network._ask_vrfy), а
    # тот же код на RCPT проваливался сюда и становился Valid.
    if numeric == 252:
        return result("unknown",
                      "252 Сервер не берётся подтвердить получателя "
                      "(RFC 5321 §3.5.3) — о существовании ящика не сказано")
    if 200 <= numeric < 300:
        return result("valid", f"{numeric} Accepted")

    # ------------------------------------------------- ящик ПЕРЕПОЛНЕН -----
    # Проверяется раньше всего прочего, потому что это самое сильное
    # положительное доказательство после 250: ящик не только есть, им
    # пользуются. Но сначала исключаем два чужих случая с теми же кодами:
    # кончилось место на СЕРВЕРЕ и слишком большое ПИСЬМО.
    # 550 сюда добавлен намеренно. Часть серверов отвечает на переполненный
    # ящик постоянным кодом, и тогда доказательство существования терялось:
    # адрес уезжал в risky «упомянут получатель без отрицания». Порядок при
    # этом сохранён: место на сервере и размер письма исключаются первыми.
    if numeric in (452, 552, 522, 550):
        if _contains(msg, _SERVER_STORAGE_MARKERS):
            return result("unknown", f"{numeric} На сервере кончилось место (о ящике не сказано)")
        if _contains(msg, _MESSAGE_SIZE_MARKERS):
            return result("unknown", f"{numeric} Ограничение на размер письма (о ящике не сказано)")
        if _contains(msg, _MAILBOX_FULL_MARKERS) or (enhanced and enhanced[1:] == (2, 2)):
            return result("valid", f"{numeric} Ящик существует и переполнен")

    # ------------------------------------------------------- 4xx временно --
    if 400 <= numeric < 500:
        return _classify_temporary(numeric, msg, enhanced, prefix)

    # ------------------------------------------------------- 5xx постоянно -
    if 500 <= numeric < 600:
        return _classify_permanent(numeric, msg, enhanced, prefix)

    return result("unknown", f"{numeric} Unknown Response")


def _verdict(status: str, reason: object, prefix: object = "") -> Verdict:
    """Собирает ответ. Отдельной функцией, чтобы ветки разбора принимали
    только данные: колбэк в параметрах означал бы, что фаззинг мусором
    неизбежно натыкается на «None не вызывается», и сито приходилось бы
    отключать вместо того, чтобы чинить код."""
    return {"status": status,
            "reason": (prefix if isinstance(prefix, str) else "") + str(reason)}


def _classify_temporary(code: int, msg: object, enhanced: Enhanced,
                        prefix: str = "") -> Verdict:
    """4xx: сервер просит прийти позже. Приговора здесь быть не может."""
    msg = msg if isinstance(msg, str) else ""

    def result(status: str, reason: object) -> Verdict:
        return _verdict(status, reason, prefix)
    if code == 421:
        return result("unknown", "421 Service Busy (Rate Limit)")

    greylisted = _contains(msg, ("grey", "greylist", "grey list", "try again",
                                 "try later", "deferred", "come back"))
    rate_limited = _contains(msg, ("rate", "too many", "throttl", "limit exceeded",
                                   "too fast", "connection limit"))

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
        # Переполненный ящик уже разобран выше. Здесь остаются лимиты сервера.
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
    """5xx: отказ окончательный. Вопрос только в том, кому именно отказали."""
    msg = msg if isinstance(msg, str) else ""

    def result(status: str, reason: object) -> Verdict:
        return _verdict(status, reason, prefix)
    subject = detail = None
    if isinstance(enhanced, (tuple, list)) and len(enhanced) >= 3:
        subject, detail = enhanced[1], enhanced[2]

    # Расширенный код класса 4 при трёхзначном 5xx — сервер противоречит сам
    # себе. Верим более конкретному: "приходите позже".
    if isinstance(enhanced, (tuple, list)) and enhanced and enhanced[0] == 4:
        return result("risky", f"{code} Постоянный код с временным статусом (ящик не проверен)")

    # Текст говорит «позже», код говорит «никогда». Так пишут перегруженные и
    # неверно настроенные серверы, и ящик за этим обычно живой.
    if _contains(msg, TRANSIENT_TEXT_MARKERS):
        return result("risky", f"{code} Временный отказ с постоянным кодом (ящик не проверен)")

    # 500-504 — «я НЕ ПОНЯЛ КОМАНДУ» (RFC 5321 §4.2.3). Такой ответ говорит о
    # нашем диалоге, а не о ящике, и приговором быть не может НИКОГДА.
    #
    # Ловушка была в расширенном коде: сервер, ответивший «501 5.1.3 Bad
    # recipient address syntax», попадал в ветку «5.1.x — ящика нет» и получал
    # invalid. Между тем 5.1.3 означает «адрес разобрать не удалось», а не
    # «такого ящика нет»: адрес, который наш собственный синтаксис пропустил,
    # чужой сервер мог не принять из-за своих правил или из-за того, как мы
    # оформили RCPT. Настоящее отсутствие ящика приходит кодом 550, а не 501.
    #
    # Цена ошибки здесь несимметрична: ложный invalid — это навсегда
    # потерянный живой контакт, ложный unknown — одна перепроверка.
    if isinstance(code, int) and 500 <= code <= 504:
        return result("unknown",
                      f"{code} Сервер не понял команду (о ящике не сказано ничего)")

    proof = _contains(msg, _NO_MAILBOX_PROOF)
    reputation = _contains(msg, _HARD_REPUTATION_MARKERS)

    # Отказ по политике или репутации нашего IP. Про ящик не сказано ничего.
    #
    # Единственное исключение — сервер, который ПРЯМО назвал получателя
    # несуществующим. Формулировки в _NO_MAILBOX_PROOF подобраны так, что
    # означать политику они не могут, поэтому «5.7.1 user unknown» читается
    # как приговор ящику. Но если рядом стоит признак репутации нашего адреса
    # (spamhaus, client host, blacklist), приговор снимается: такой ответ
    # чаще всего пришёл ещё до того, как сервер вообще посмотрел на адрес.
    # Однозначные признаки ОТПРАВИТЕЛЯ разбираются раньше политики. Статус в
    # обоих случаях unknown, но владельцу базы важно видеть, кому именно
    # отказали: «почини отправителя» и «смени прокси» — разные действия.
    if not proof and _contains(msg, _EXPLICIT_SENDER_MARKERS):
        return result("unknown", f"{code} Отказ отправителю/релею (ящик может существовать)")

    policy = (subject == 7) or _contains(msg, _POLICY_MARKERS)
    if policy and (reputation or not proof):
        return result("unknown", f"{code} Отказ по политике/репутации IP (ящик может существовать)")

    # Отвергнут ОТПРАВИТЕЛЬ, а не получатель.
    if not proof and _contains(msg, _SENDER_MARKERS):
        return result("unknown", f"{code} Отказ отправителю/релею (ящик может существовать)")

    # Расширенный код «нет такого ящика» — доказательство того же веса, что и
    # прямая формулировка. 5.1.1 — нет ящика, 5.1.3 — синтаксис адреса
    # получателя, 5.1.10 — адрес не существует (Office 365).
    # 5.1.1 — «нет такого ящика», 5.1.10 — «адрес не существует» (Office 365).
    # Это про ЯЩИК, и это доказательство.
    if subject == 1 and detail in (1, 10):
        return result("invalid", f"{code} {prefix_name(detail)}")

    # А 5.1.3 — «Bad destination mailbox address syntax» — про ФОРМУ адреса,
    # какой её увидел сервер, а не про существование ящика. Так отвечают на
    # не-ASCII имя без SMTPUTF8, на имя в кавычках и на слишком длинное имя,
    # то есть ровно на те адреса, которые мы специально учились не хоронить.
    # Тот же вывод сделан выше для кода 501; здесь он был упущен.
    if subject == 1 and detail == 3:
        return result("risky", f"{code} Сервер не принял ФОРМУ адреса "
                               "(о существовании ящика не сказано)")

    # 5.1.2 — «Bad destination system address»: сервер говорит про домен, а не
    # про ящик. Ниже это ловилось подстрокой «bad destination» и превращалось
    # в приговор получателю.
    if subject == 1 and detail == 2:
        return result("risky", f"{code} Отвергнут домен получателя "
                               "(о самом ящике не сказано)")

    if proof:
        return result("invalid", f"{code} Получателя не существует")

    # Ящик есть, но заморожен: адрес реальный, письмо не дойдёт.
    if subject == 2 and detail == 1:
        return result("risky", f"{code} Ящик отключён или заморожен")
    if _contains(msg, _DISABLED_MARKERS):
        return result("risky", f"{code} Ящик отключён или заморожен")

    # Формулировка про получателя, которая используется и для политики.
    # Политика уже исключена выше, поэтому здесь она означает ящик.
    if _contains(msg, _AMBIGUOUS_NO_MAILBOX):
        return result("invalid", f"{code} Получатель отвергнут")

    # 551 «User not local» — это НЕ «получателя нет». Сервер говорит «он не у
    # меня», и без пути пересылки вывод сделать нельзя. Раньше здесь стоял
    # приговор, и он хоронил адреса на доменах с раздельной маршрутизацией.
    if code == 551:
        return result("risky", "551 User Not Local (ящик может существовать на другом сервере)")

    # 553 чаще всего означает отвергнутого ОТПРАВИТЕЛЯ (postfix: "553 5.7.1
    # Sender address rejected: not owned by user"), а не кривой адрес
    # получателя. Отправитель уже исключён выше; остаётся синтаксис.
    if code == 553:
        return result("risky", "553 Адрес не принят (кому именно — не сказано)")

    # Упоминание получателя + отрицание рядом. Слово о получателе само по себе
    # не доказывает ничего — доказывает ОТРИЦАНИЕ рядом с ним.
    if _contains(msg, ("recipient", "mailbox", "user", "address")):
        if _contains(msg, RECIPIENT_NEGATIONS):
            return result("invalid", f"{code} Получатель отвергнут")
        return result("risky", f"{code} Упомянут получатель без явного отрицания (не доказано)")

    # Протокольные и авторизационные 5xx — это НЕ приговор ящику.
    # 500-504: сервер не понял нашу команду. 521: сервер вообще не принимает
    # почту. 530/535: требуется/провалена авторизация. 571: доставка не
    # разрешена (блок по IP). Ни один из них не про получателя.
    if code in (500, 501, 502, 503, 504, 521, 530, 535, 571):
        return result("unknown", f"{code} Ошибка сервера/авторизации (ящик может существовать)")

    if code == 554:
        return result("unknown", "554 Transaction Failed")

    # Голый отказ без объяснений. Через прокси это чаще всего отказ по IP или
    # отправителю, поэтому живой адрес не хороним.
    return result("risky", f"{code} Отказ без объяснения (не доказано)")


def prefix_name(detail: object) -> str:
    """Человеческое имя расширенного кода 5.1.x.

    Сам код уже стоит в начале причины, поэтому здесь его не повторяем.
    """
    names = {
        1: "Получателя не существует",
        3: "Некорректный адрес получателя",
        10: "Адрес не существует",
    }
    if isinstance(detail, int):
        return names.get(detail, "Получателя не существует")
    return "Получателя не существует"
