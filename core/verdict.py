__all__ = ["verdict_confidence", "CONFIDENCE_STEPS"]

CONFIDENCE_STEPS = {
    "fact_no_address": (99, "факт: адресовать некуда — сломанный синтаксис "
                            "или у домена нет почтовых серверов"),

    "server_confirmed_missing": (92, "сервер назвал получателя несуществующим, "
                                     "и ответ подтверждён вторым источником"),
    "server_says_missing": (75, "сервер назвал получателя несуществующим, но "
                                "второго мнения не было"),
    "server_accepted_with_control": (90, "сервер принял адрес и тут же отверг "
                                         "выдуманный — значит отвечает честно"),
    "server_accepted": (78, "сервер принял адрес; выдуманный в той же сессии "
                            "не проверялся"),
    "mailbox_full": (85, "ящик переполнен — письмо не будет доставлено; "
                         "переполняется обычно ящик, которым не пользуются"),
    "disabled": (85, "сервер назвал ящик отключённым — письма не принимаются"),
    "unconfirmed": (30, "сервер принял адрес, но исключить приём любых адресов "
                        "не удалось — выдуманный адрес не получил окончательного "
                        "ответа, либо почта домена уходит на парковку или в "
                        "пересылку"),

    "accept_all": (15, "домен принимает ЛЮБОЙ адрес: существование этого "
                       "ящика по SMTP не выясняется в принципе"),
    "tarpit": (10, "почтовик перестал отвечать честно — похоже, наш выходной "
                   "адрес под подозрением"),
    "policy_refusal": (20, "отказ по политике или репутации нашего IP: про "
                           "ящик не сказано ничего"),
    "server_untrustworthy": (25, "сервер отвергает и служебный адрес — его "
                                 "отказам верить нельзя"),

    "greylisted": (10, "сервер попросил прийти позже; вердикта ещё нет"),
    "our_side": (5, "проверка сорвалась на нашей стороне: таймаут, прокси или "
                    "лимит скорости"),
    "not_checked": (0, "адрес не проверялся по сети"),

    "policy_rule": (35, "нарушены нынешние правила провайдера, но сеть ответа "
                        "не дала — старый ящик мог быть заведён до правил"),
    "trap": (80, "ранний отказ без вопроса серверу: ловушка по имени ящика или "
                 "одноразовый сервис по почтовому серверу — писать нельзя"),
}

_REASON_MARKERS = (
    ("bad syntax", "fact_no_address"),
    ("idna", "fact_no_address"),
    ("no mx/a", "fact_no_address"),
    ("dead domain", "fact_no_address"),
    ("адресовать нечего", "fact_no_address"),
    ("противоречит первому", "server_says_missing"),
    ("служебный адрес", "server_untrustworthy"),
    ("postmaster@", "server_untrustworthy"),
    ("переполнен", "mailbox_full"),
    ("full inbox", "mailbox_full"),
    ("quota", "mailbox_full"),
    ("catch-all", "accept_all"),
    ("не проверяется намеренно", "not_checked"),
    ("принимает любые адреса", "tarpit"),
    ("под подозрением", "tarpit"),
    ("репутации", "policy_refusal"),
    ("отправителю/релею", "policy_refusal"),
    ("greylist", "greylisted"),
    ("серый список", "greylisted"),
    ("не может существовать", "fact_no_address"),
    ("по нынешним правилам", "policy_rule"),
    ("timeout", "our_side"),
    ("таймаут", "our_side"),
    ("proxy dead", "our_side"),
    ("прокси", "our_side"),
    ("dns не удалось", "our_side"),
    ("перепроверка не выполнена", "our_side"),
)


def _step(name):
    value, basis = CONFIDENCE_STEPS[name]
    return int(value), basis


def verdict_confidence(status, reason="", extras=None):
    try:
        extras = extras if isinstance(extras, dict) else {}
        low_status = str(status or "").strip().lower()
        low_reason = str(reason or "").lower()

        if low_status == "trap":
            return _step("trap")
        if low_status in ("full", "mailbox full"):
            return _step("mailbox_full")
        if low_status == "disabled":
            return _step("disabled")
        if low_status == "unconfirmed":
            return _step("unconfirmed")

        matched = None
        for marker, name in _REASON_MARKERS:
            if marker in low_reason:
                matched = name
                break

        if low_status in ("valid", "valid/deliverable"):
            if matched == "mailbox_full":
                return _step("mailbox_full")
            value, basis = _step("server_accepted_with_control"
                                 if extras.get("control_probe") else "server_accepted")
            if extras.get("valid_second_opinion") == "unavailable":
                basis += "; второго мнения с другого IP не было"
            return value, basis

        if low_status in ("invalid", "invalid/bounce"):
            if matched == "fact_no_address":
                return _step("fact_no_address")
            if extras.get("confirmed"):
                return _step("server_confirmed_missing")
            return _step("server_says_missing")

        if low_status in ("catchall", "accept_all"):
            if matched == "tarpit":
                return _step("tarpit")
            return _step("accept_all")

        if low_status == "greylisted":
            return _step("greylisted")

        if matched:
            return _step(matched)

        if low_status in ("risky", "unknown", "role-based"):
            return _step("our_side" if low_status == "unknown" else "policy_refusal")

        return _step("not_checked")
    except Exception:
        return 0, CONFIDENCE_STEPS["not_checked"][1]
