import re

IMPOSSIBLE = "impossible"
UNLIKELY = "unlikely"
OK = "ok"


class Rule:

    def __init__(self, name, allowed, min_len=None, max_len=None, starts=None,
                 note="", dots_optional=False):
        self.name = name
        self.allowed = re.compile(allowed) if allowed else None
        self.min_len = min_len
        self.max_len = max_len
        self.starts = re.compile(starts) if starts else None
        self.note = note
        self.dots_optional = bool(dots_optional)


_RULES = {}


def _register(domains, rule):
    if isinstance(domains, str):
        domains = (domains,)
    elif domains is None or not hasattr(domains, "__iter__"):
        return
    if not isinstance(rule, Rule):
        return
    for domain in domains:
        if isinstance(domain, str) and domain:
            _RULES[domain.lower()] = rule


_register(
    ("gmail.com", "googlemail.com"),
    Rule("Gmail", r"^[a-z0-9.]+$", min_len=6, max_len=30, dots_optional=True,
         note="имя Gmail — только латиница, цифры и точки, длина 6-30 "
              "(точки не в счёт: они ничего не значат)"))

_register(
    ("yahoo.com", "ymail.com", "rocketmail.com", "yahoo.co.uk", "yahoo.fr",
     "yahoo.de", "yahoo.es", "yahoo.it", "yahoo.ca", "yahoo.com.au",
     "yahoo.co.in", "yahoo.com.br", "yahoo.gr", "yahoo.ro", "yahoo.se",
     "yahoo.com.ar", "yahoo.com.hk", "yahoo.com.mx", "yahoo.com.ph",
     "yahoo.com.sg", "yahoo.dk", "yahoo.hu", "yahoo.no",
     "yahoo.co.jp", "yahoo.in"),
    Rule("Yahoo", r"^[a-z][a-z0-9_.]*$", min_len=4, max_len=32,
         starts=r"^[a-z]",
         note="имя Yahoo начинается с буквы, длина 4-32"))

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
    if not isinstance(domain, str):
        return False
    return domain.strip().lower().rstrip(".") in _RULES


def provider_of(domain):
    if not isinstance(domain, str):
        return ""
    rule = _RULES.get(domain.strip().lower().rstrip("."))
    return rule.name if rule else ""


def base_local(local):
    if not isinstance(local, str):
        return ""
    return local.split("+", 1)[0]


def check_local_part(email):
    if not isinstance(email, str) or email.count("@") != 1:
        return (OK, "")

    local, _, domain = email.rpartition("@")
    rule = _RULES.get(domain.strip().lower().rstrip("."))
    if rule is None:
        return (OK, "")

    name = base_local(local).strip().lower()
    if not name:
        return (IMPOSSIBLE, f"{rule.name}: пустое имя пользователя")

    if rule.starts and not rule.starts.match(name):
        return (UNLIKELY, f"{rule.name}: имя начинается символом, который сейчас "
                          f"не разрешён. {rule.note}")

    if rule.allowed and not rule.allowed.match(name):
        bad = sorted({ch for ch in name
                      if not rule.allowed.match(ch) and not rule.allowed.match("a" + ch)})
        shown = "".join(bad[:5])
        return (UNLIKELY,
                f"{rule.name}: недопустимые по нынешним правилам символы в имени "
                f"({shown}). {rule.note}")

    measured = name.replace(".", "") if rule.dots_optional else name

    if rule.max_len and len(measured) > rule.max_len:
        return (UNLIKELY,
                f"{rule.name}: имя длиннее {rule.max_len} символов — по нынешним "
                f"правилам такой ящик не завести. {rule.note}")

    if rule.min_len and len(measured) < rule.min_len:
        return (UNLIKELY,
                f"{rule.name}: имя короче {rule.min_len} символов — по нынешним "
                f"правилам такой ящик не завести. {rule.note}")

    return (OK, "")


def rule_count():
    return len(_RULES)
