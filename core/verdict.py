# core/verdict.py
"""Уверенность в вердикте и его основание — отдельно от скора живости.

Зачем понадобился отдельный модуль. В программе уже был скор (0-100), но он
отвечает на другой вопрос: «насколько вероятно, что за адресом живой активный
человек». Уверенность — про доказательство: НАСКОЛЬКО ТВЁРДО мы знаем то, что
написали в колонке «Статус».

Эти две величины расходятся в обе стороны:

  * подтверждённый сервером ящик на свежем бесплатном домене без имени и
    аватара получает невысокий скор живости — но вердикт «существует» у него
    доказан ответом `250` и контрольной пробой;
  * адрес на домене с идеальным SPF, DMARC, десятилетним возрастом и живым
    сайтом получает высокий скор — а вердикт может стоять на одном
    неподтверждённом `550` или вовсе на «домен принимает что угодно».

Смешивать их — значит выдавать догадку за доказательство ровно там, где цена
ошибки максимальна. Поэтому здесь своя шкала и своя формулировка основания.

Шкала намеренно грубая, по ступеням, а не по формуле: точность в один балл
здесь выдумана, а ступень «доказано сервером / подтверждено вторым источником
/ не подтверждено / не проверялось» — нет.
"""

__all__ = ["verdict_confidence", "CONFIDENCE_STEPS"]

# Ступени уверенности. Ключ — что именно нам известно, значение — (число,
# основание). Число нужно для сортировки и фильтра, основание — чтобы
# владелец видел, ПОЧЕМУ здесь столько.
CONFIDENCE_STEPS = {
    # --- доказано без сети: адресовать физически некуда ---
    "fact_no_address": (99, "факт: адресовать некуда — сломанный синтаксис "
                            "или у домена нет почтовых серверов"),

    # --- сервер ответил про сам ящик ---
    "server_confirmed_missing": (92, "сервер назвал получателя несуществующим, "
                                     "и ответ подтверждён вторым источником"),
    "server_says_missing": (75, "сервер назвал получателя несуществующим, но "
                                "второго мнения не было"),
    "server_accepted_with_control": (90, "сервер принял адрес и тут же отверг "
                                         "выдуманный — значит отвечает честно"),
    "server_accepted": (78, "сервер принял адрес; выдуманный в той же сессии "
                            "не проверялся"),
    "mailbox_full": (85, "ящик переполнен — он существует и им пользуются"),

    # --- сервер ответил, но не про ящик ---
    "accept_all": (15, "домен принимает ЛЮБОЙ адрес: существование этого "
                       "ящика по SMTP не выясняется в принципе"),
    "tarpit": (10, "почтовик перестал отвечать честно — похоже, наш выходной "
                   "адрес под подозрением"),
    "policy_refusal": (20, "отказ по политике или репутации нашего IP: про "
                           "ящик не сказано ничего"),
    "server_untrustworthy": (25, "сервер отвергает и служебный адрес — его "
                                 "отказам верить нельзя"),

    # --- не дошли до ответа ---
    "greylisted": (10, "сервер попросил прийти позже; вердикта ещё нет"),
    "our_side": (5, "проверка сорвалась на нашей стороне: таймаут, прокси или "
                    "лимит скорости"),
    "not_checked": (0, "адрес не проверялся по сети"),

    # --- вердикт по локальному правилу, а не по ответу сервера ---
    "policy_rule": (35, "нарушены нынешние правила провайдера, но сеть ответа "
                        "не дала — старый ящик мог быть заведён до правил"),
    "trap": (80, "адрес принадлежит ловушке антиспам-вендора — писать нельзя"),
}

# Признаки в тексте причины. Порядок важен: первое совпадение решает, поэтому
# более узкие маркеры стоят выше более общих.
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
    """(уверенность 0-100, основание) для одного адреса.

    status  — сырой статус проверки (valid/invalid/risky/unknown/catchall/
              greylisted/trap) ИЛИ отображаемый (Valid, Invalid/Bounce...).
    reason  — текст причины, как он показан владельцу.
    extras  — необязательный словарь: control_probe (была ли контрольная
              проба), confirmed (подтверждён ли приговор вторым источником),
              postmaster_honored.

    Никогда не бросает: зовут из рабочих потоков, где исключение стоит адреса.
    """
    try:
        extras = extras if isinstance(extras, dict) else {}
        low_status = str(status or "").strip().lower()
        low_reason = str(reason or "").lower()

        # Ловушка вендора — отдельный случай: это не про существование ящика.
        if low_status == "trap":
            return _step("trap")

        # Сначала текст причины: он точнее статуса. «Invalid» бывает и фактом
        # (нет MX), и одиночным 550 — а это разная твёрдость.
        matched = None
        for marker, name in _REASON_MARKERS:
            if marker in low_reason:
                matched = name
                break

        if low_status in ("valid", "valid/deliverable"):
            # Принятый адрес: контрольная проба в той же сессии решает, можно
            # ли верить этому «принял».
            if matched == "mailbox_full":
                return _step("mailbox_full")
            if extras.get("control_probe"):
                return _step("server_accepted_with_control")
            return _step("server_accepted")

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
