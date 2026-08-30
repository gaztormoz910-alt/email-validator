# core/local_rules.py
"""Правила локальной части у конкретных почтовиков.

Зачем это нужно. Синтаксис RFC 5322 разрешает почти что угодно, но реальный
провайдер разрешает куда меньше. `ca@gmail.com` проходит RFC, а в Gmail такого
ящика быть не может: имя пользователя там от шести символов. Проверка стоит
ноль запросов и ноль времени, а отсеивает адреса, на которые нельзя писать.

ГЛАВНОЕ ПРАВИЛО ЭТОГО ФАЙЛА: не хоронить живого.

Поэтому вердиктов три, и они означают РАЗНОЕ:

  impossible — ящика с таким именем не может быть ни при каких условиях, и
               исключений тут не бывает по устройству самой регистрации.
               Таких случая два: пустое имя и имя длиннее предела провайдера
               (пределы длины только росли, поэтому старый аккаунт не может
               оказаться длиннее нынешнего максимума). Только это отбраковывается
               без единого сетевого запроса.
  unlikely   — имя нарушает нынешнее правило регистрации, но старые аккаунты
               могли быть заведены до его введения. Примеры: имя Gmail короче
               шести символов или с подчёркиванием внутри. Такой адрес
               ОБЯЗАТЕЛЬНО проверяется по сети:
               если сервер ответит 250, значит ящик из старых, и он живой.
               Правило лишь понижает доверие там, где сеть ответа не дала.
  ok         — правилам не противоречит.

Разница между impossible и unlikely — это разница между «доказано, что нельзя»
и «похоже, что вряд ли». Смешивать их значит выбрасывать живые контакты.
"""

import re

IMPOSSIBLE = "impossible"
UNLIKELY = "unlikely"
OK = "ok"


class Rule:
    """Правила имени пользователя у одного почтовика.

    allowed  — множество разрешённых символов (регулярка на ВСЮ строку);
    min_len  — нынешний минимум длины (нарушение = unlikely, см. выше);
    max_len  — максимум (нарушение = impossible: длиннее просто не принимали);
    starts   — регулярка на первый символ, если провайдер его ограничивает.
    """

    def __init__(self, name, allowed, min_len=None, max_len=None, starts=None,
                 note=""):
        self.name = name
        self.allowed = re.compile(allowed) if allowed else None
        self.min_len = min_len
        self.max_len = max_len
        self.starts = re.compile(starts) if starts else None
        self.note = note


# Домены -> правило. Значения взяты из правил регистрации самих провайдеров.
#
# Про плюс-тег. Он в проверку НЕ попадает: john+news@gmail.com доставляется в
# ящик john@gmail.com, и судить надо по базовому имени. Отрезается до проверки.
_RULES = {}


def _register(domains, rule):
    for domain in domains:
        _RULES[domain] = rule


_register(
    ("gmail.com", "googlemail.com"),
    Rule("Gmail", r"^[a-z0-9.]+$", min_len=6, max_len=30,
         note="имя Gmail — только латиница, цифры и точки, длина 6-30"))

_register(
    ("yahoo.com", "ymail.com", "rocketmail.com", "yahoo.co.uk", "yahoo.fr",
     "yahoo.de", "yahoo.es", "yahoo.it", "yahoo.ca", "yahoo.com.au",
     "yahoo.co.in", "yahoo.com.br", "yahoo.gr", "yahoo.ro", "yahoo.se",
     # Региональные домены были пропущены: правило есть, а к адресу на
     # yahoo.com.mx оно не применялось.
     "yahoo.com.ar", "yahoo.com.hk", "yahoo.com.mx", "yahoo.com.ph",
     "yahoo.com.sg", "yahoo.dk", "yahoo.hu", "yahoo.no"),
    Rule("Yahoo", r"^[a-z][a-z0-9_.]*$", min_len=4, max_len=32,
         starts=r"^[a-z]",
         note="имя Yahoo начинается с буквы, длина 4-32"))

# AOL — та же инфраструктура, что у Yahoo (оба принадлежат Verizon Media), и
# правила имени у них совпадают. Домены AOL здесь были пропущены целиком:
# критерий существовал, но к ним не применялся, и adres@aol.com проверялся на
# одно правило меньше остальных.
_register(
    ("aol.com", "aim.com", "verizon.net", "love.com", "games.com",
     "ygm.com", "wow.com", "aol.co.uk", "aol.de", "aol.fr"),
    Rule("AOL", r"^[a-z][a-z0-9_.]*$", min_len=3, max_len=32,
         starts=r"^[a-z]",
         note="имя AOL начинается с буквы, длина 3-32"))

_register(
    ("icloud.com", "me.com", "mac.com"),
    Rule("iCloud", r"^[a-z][a-z0-9_.\-]*$", min_len=3, max_len=20,
         starts=r"^[a-z]",
         note="имя iCloud начинается с буквы, длина 3-20"))

_register(
    ("yandex.ru", "ya.ru", "yandex.com", "yandex.by", "yandex.kz", "yandex.ua"),
    Rule("Yandex", r"^[a-z0-9][a-z0-9.\-]*$", min_len=1, max_len=30,
         note="имя Яндекса — латиница, цифры, точка и дефис, до 30 символов"))

_register(
    ("mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru"),
    Rule("Mail.ru", r"^[a-z0-9][a-z0-9._\-]*$", min_len=1, max_len=31,
         note="имя Mail.ru — латиница, цифры, точка, дефис и подчёркивание"))

_register(
    ("outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk",
     "hotmail.fr", "hotmail.de", "hotmail.es", "hotmail.it", "live.co.uk",
     "live.fr", "outlook.co.uk", "passport.com"),
    Rule("Outlook", r"^[a-z0-9][a-z0-9._\-]*$", min_len=1, max_len=64,
         note="имя Outlook — латиница, цифры, точка, дефис и подчёркивание"))

_register(
    ("protonmail.com", "protonmail.ch", "proton.me", "pm.me"),
    Rule("Proton", r"^[a-z0-9][a-z0-9._\-]*$", min_len=1, max_len=40,
         note="имя Proton — латиница, цифры, точка, дефис и подчёркивание"))

_register(
    ("gmx.com", "gmx.de", "gmx.net", "gmx.at", "gmx.ch"),
    Rule("GMX", r"^[a-z0-9][a-z0-9._\-]*$", min_len=3, max_len=60,
         note="имя GMX — латиница, цифры, точка, дефис и подчёркивание"))

_register(
    ("zoho.com", "zohomail.com", "zoho.eu", "zoho.in"),
    Rule("Zoho", r"^[a-z0-9][a-z0-9._\-]*$", min_len=1, max_len=30,
         note="имя Zoho — латиница, цифры, точка, дефис и подчёркивание"))

_register(
    ("qq.com", "foxmail.com"),
    Rule("QQ", r"^[a-z0-9][a-z0-9._\-]*$", min_len=3, max_len=30,
         note="имя QQ — латиница и цифры"))

_register(
    ("163.com", "126.com", "yeah.net"),
    Rule("NetEase", r"^[a-z][a-z0-9._\-]*$", min_len=6, max_len=18,
         starts=r"^[a-z]",
         note="имя NetEase начинается с буквы, длина 6-18"))

_register(
    ("naver.com",),
    Rule("Naver", r"^[a-z][a-z0-9_\-]*$", min_len=5, max_len=20,
         starts=r"^[a-z]",
         note="имя Naver начинается с буквы, длина 5-20"))


def has_rules(domain):
    """Известны ли правила для этого домена."""
    if not isinstance(domain, str):
        return False
    return domain.strip().lower().rstrip(".") in _RULES


def provider_of(domain):
    """Имя провайдера, чьи правила применяются, или пустая строка."""
    if not isinstance(domain, str):
        return ""
    rule = _RULES.get(domain.strip().lower().rstrip("."))
    return rule.name if rule else ""


def base_local(local):
    """Локальная часть без плюс-тега — то, что реально адресует ящик."""
    if not isinstance(local, str):
        return ""
    return local.split("+", 1)[0]


def check_local_part(email):
    """Возвращает (вердикт, причина).

    Вердикт — одна из констант OK / UNLIKELY / IMPOSSIBLE. Причина пустая,
    когда придраться не к чему. Домен без известных правил — всегда OK: молчать
    честнее, чем судить по общим соображениям.
    """
    if not isinstance(email, str) or email.count("@") != 1:
        return (OK, "")

    local, _, domain = email.rpartition("@")
    rule = _RULES.get(domain.strip().lower().rstrip("."))
    if rule is None:
        return (OK, "")

    name = base_local(local).strip().lower()
    if not name:
        return (IMPOSSIBLE, f"{rule.name}: пустое имя пользователя")

    # Символы, которых нынешние правила регистрации не допускают.
    #
    # ЭТО unlikely, А НЕ impossible — и вот почему. У Gmail в имени нет
    # подчёркивания, но аккаунты эпохи беты и перенесённые из Google Apps с
    # подчёркиванием встречаются до сих пор. Объявить такой адрес мёртвым без
    # спроса у сервера значит выбросить живой контакт. Поэтому адрес идёт в
    # сеть как обычно, и правило вступает в силу только если сеть промолчала.
    if rule.allowed and not rule.allowed.match(name):
        bad = sorted({ch for ch in name if not rule.allowed.match(ch)})
        shown = "".join(bad[:5])
        return (UNLIKELY,
                f"{rule.name}: недопустимые по нынешним правилам символы в имени "
                f"({shown}). {rule.note}")

    if rule.starts and not rule.starts.match(name):
        return (UNLIKELY, f"{rule.name}: имя начинается символом, который сейчас "
                          f"не разрешён. {rule.note}")

    # Слишком длинное имя тоже невозможно: форма регистрации его не примет,
    # и старых исключений здесь не бывает — предел длины только рос.
    if rule.max_len and len(name) > rule.max_len:
        return (IMPOSSIBLE,
                f"{rule.name}: имя длиннее {rule.max_len} символов. {rule.note}")

    # А вот слишком КОРОТКОЕ имя — не приговор. Минимальную длину провайдеры
    # вводили позже, и аккаунты, заведённые до этого, живы до сих пор. Поэтому
    # здесь unlikely: адрес всё равно проверяется по сети, и ответ сервера
    # важнее правила.
    if rule.min_len and len(name) < rule.min_len:
        return (UNLIKELY,
                f"{rule.name}: имя короче {rule.min_len} символов — по нынешним "
                f"правилам такой ящик не завести. {rule.note}")

    return (OK, "")


def rule_count():
    """Сколько доменов покрыто правилами — нужно тестам и отчётам."""
    return len(_RULES)
