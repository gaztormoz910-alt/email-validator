import os
import re

from .parser_pipeline import GLOBAL_VERIFIED_DOMAINS
from core.email_syntax import to_ascii_domain, _lower_domain_only


_GMAIL_DOMAINS = {"gmail.com", "googlemail.com"}

_YANDEX_DOMAINS = {"yandex.ru", "yandex.com", "yandex.by", "yandex.kz",
                   "yandex.ua", "yandex.com.tr", "ya.ru", "narod.ru"}


_PLUS_TAG_DOMAINS = {
    "gmail.com", "googlemail.com", "google.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk",
    "yahoo.com", "ymail.com", "rocketmail.com",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "pm.me",
    "fastmail.com", "zoho.com", "yandex.ru", "ya.ru",
}


_JUNK_EDGES = "`'\"<>()[]{},;:|*!?«»“”‘’" \
              "\ufeff\u200b\u200c\u200d\xa0 \t\r\n"

_MAILTO_RE = re.compile(r'^\s*mailto:\s*', re.IGNORECASE)

from core.email_syntax import domain_literal_ip
from core.email_syntax import has_quoted_local
from core.email_syntax import has_quoted_form
from core.inputnorm import normalize_input


def strip_wrapping_junk(raw: str) -> str:
    if not isinstance(raw, str):
        return ""
    value = _MAILTO_RE.sub("", normalize_input(raw))
    quoted_before = has_quoted_local(value.strip().lower())
    if "<" in value and ">" in value:
        inner = value[value.rfind("<") + 1:value.rfind(">")]
        if "@" in inner:
            value = inner
    края = _JUNK_EDGES
    if domain_literal_ip(value.strip().rpartition("@")[2]) is not None:
        края = края.replace("[", "").replace("]", "")

    stripped = _lower_domain_only(value.strip(края))
    if quoted_before and not has_quoted_local(stripped):
        return _lower_domain_only(value.strip(края.replace('"', "")))
    return stripped


def normalize_for_dedup(email: str) -> str:
    if not isinstance(email, str) or "@" not in email:
        return (email or "").strip().lower() if isinstance(email, str) else ""

    email = normalize_input(email).strip().lower()
    local, domain = email.rsplit("@", 1)

    ascii_domain = to_ascii_domain(domain)
    if ascii_domain:
        domain = ascii_domain

    if domain in _PLUS_TAG_DOMAINS and "+" in local:
        local = local.split("+", 1)[0]

    if domain in _GMAIL_DOMAINS:
        local = local.replace(".", "")
        domain = "gmail.com"
    elif domain in _YANDEX_DOMAINS:
        domain = "yandex.ru"

    if not local:
        return email

    return f"{local}@{domain}"

class EmailCleaner:
    _KNOWN_TLDS = (
        "com", "org", "net", "ru", "ua", "by", "kz", "de", "fr", "it", "es",
        "pl", "nl", "be", "se", "no", "dk", "fi", "cz", "sk", "hu", "ro", "bg",
        "gr", "pt", "at", "ch", "uk", "ie", "us", "ca", "au", "nz", "jp", "cn",
        "kr", "in", "br", "mx", "ar", "cl", "co", "io", "me", "info", "biz",
        "edu", "gov", "mil", "int", "tv", "cc", "xyz", "online", "site", "shop",
        "app", "dev", "tech", "store", "pro", "name", "email", "cloud",
        "institute", "international", "industries", "ink", "insure",
        "company", "consulting", "construction", "community", "codes",
        "coffee", "cool", "coupons", "courses", "credit", "coop",
        "media", "menu", "memorial",
        "design", "delivery", "dental", "deals",
        "network", "organic", "shopping", "technology",
        "productions", "properties", "property",
        "cafe", "camera", "capital", "care", "careers", "cash", "casino",
        "chat", "church", "estate", "auction", "audio", "auto",
    )

    def __init__(self):
        self._проверка_домена = None
        self.popular_domains = set(GLOBAL_VERIFIED_DOMAINS)
        self._sorted_domains = sorted(self.popular_domains, key=lambda d: (-len(d), d))
        
        self._typo_map = {
            'gamil.com': 'gmail.com', 'gmial.com': 'gmail.com', 'gmal.com': 'gmail.com',
            'gmai.com': 'gmail.com', 'gmail.co': 'gmail.com', 'gmail.con': 'gmail.com',
            'gmail.ru': 'gmail.com', 'gnail.com': 'gmail.com', 'gmaill.com': 'gmail.com',
            'g.mail.com': 'gmail.com', 'gmaul.com': 'gmail.com', 'gmqil.com': 'gmail.com',
            'gmali.com': 'gmail.com', 'gemail.com': 'gmail.com', 'gmsil.com': 'gmail.com',
            'gmeil.com': 'gmail.com', 'gmaik.com': 'gmail.com', 'gmil.com': 'gmail.com',
            'yaho.com': 'yahoo.com', 'yahoo.co': 'yahoo.com',
            'yahoo.con': 'yahoo.com', 'yaboo.com': 'yahoo.com', 'yahooo.com': 'yahoo.com',
            'yshoo.com': 'yahoo.com', 'yaoo.com': 'yahoo.com', 'tahoo.com': 'yahoo.com',
            'outlok.com': 'outlook.com', 'outook.com': 'outlook.com', 'otlook.com': 'outlook.com',
            'outlool.com': 'outlook.com', 'outloock.com': 'outlook.com',
            'oultook.com': 'outlook.com', 'outlokk.com': 'outlook.com',
            'hotmal.com': 'hotmail.com', 'hotmai.com': 'hotmail.com', 'hotmail.co': 'hotmail.com',
            'hotmial.com': 'hotmail.com', 'hotmaill.com': 'hotmail.com',
            'hotmeil.com': 'hotmail.com', 'hotmsil.com': 'hotmail.com',
            'iclod.com': 'icloud.com', 'icoud.com': 'icloud.com', 'icloud.co': 'icloud.com',
            'icloude.com': 'icloud.com',
            'mail.r': 'mail.ru', 'mai.ru': 'mail.ru', 'maill.ru': 'mail.ru',
            'mail.rru': 'mail.ru', 'mall.ru': 'mail.ru',
            'yandex.r': 'yandex.ru', 'yanex.ru': 'yandex.ru', 'yandx.ru': 'yandex.ru',
            'yandez.ru': 'yandex.ru', 'yadex.ru': 'yandex.ru',
            'protonmal.com': 'protonmail.com', 'protonmai.com': 'protonmail.com',
            'protonmial.com': 'protonmail.com', 'protonmaill.com': 'protonmail.com',
            'protonmail.co': 'protonmail.com', 'protnmail.com': 'protonmail.com',
            'protonmil.com': 'protonmail.com',
            'aol.co': 'aol.com', 'aol.con': 'aol.com', 'aool.com': 'aol.com',
            'ao.com': 'aol.com',
            'zoho.co': 'zoho.com', 'zoho.con': 'zoho.com', 'zho.com': 'zoho.com',
            'gmx.co': 'gmx.com', 'gmx.con': 'gmx.com', 'gmc.com': 'gmx.com',
            'rambler.r': 'rambler.ru', 'ramblr.ru': 'rambler.ru', 'ramblerr.ru': 'rambler.ru',
            'qq.co': 'qq.com', 'qq.con': 'qq.com',
            '163.co': '163.com', '163.con': '163.com',
            'live.co': 'live.com', 'live.con': 'live.com', 'lve.com': 'live.com',
        }


    _APPENDIX_RE = re.compile(
        r"^(.+?\.(?:com|org|net|ru|edu|gov|io|me|info|biz))([-_].*)$")

    @staticmethod
    def _junk_tail(tail):
        return bool(tail) and "." not in tail

    @staticmethod
    def _на_одну_букву(a, b):
        if abs(len(a) - len(b)) > 1:
            return False
        if a == b:
            return False
        if len(a) == len(b):
            расхождений = sum(1 for х, у in zip(a, b) if х != у)
            return расхождений == 1
        короткая, длинная = (a, b) if len(a) < len(b) else (b, a)
        i = j = 0
        пропущено = False
        while i < len(короткая) and j < len(длинная):
            if короткая[i] == длинная[j]:
                i += 1
                j += 1
                continue
            if пропущено:
                return False
            пропущено = True
            j += 1
        return True

    def _похоже_на_опечатку_зоны(self, domain, цель):
        for pop in self._sorted_domains:
            if pop != цель and self._на_одну_букву(domain, pop):
                return True
        return False

    def _cut_tld_appendix(self, domain):
        m = self._APPENDIX_RE.match(domain)
        if m and self._junk_tail(m.group(2)):
            return m.group(1)
        return domain


    def _strip_tld_tail(self, domain: str) -> str:
        if "." not in domain:
            return domain
        зоны = self._зоны()
        last_label = domain.rsplit(".", 1)[-1]
        if last_label in зоны:
            return domain
        if last_label in self._английские_слова():
            return domain

        for длина in range(len(last_label) - 1, 1, -1):
            зона = last_label[:длина]
            if зона not in зоны:
                continue
            хвост = last_label[длина:]
            if len(хвост) < 2 or not (хвост.isascii() and хвост.isalpha()):
                continue
            if self._составная_зона(зона, хвост):
                return domain
            if len(зона) == 2:
                if len(хвост) < 3:
                    continue
                if self._в_одной_букве_от_зоны(last_label):
                    continue
            if зона[-1] == хвост[0]:
                continue
            почищенный = domain[:len(domain) - len(хвост)]
            if self._проверка_домена is not None:
                try:
                    отвечает = self._проверка_домена(почищенный)
                except Exception:
                    отвечает = None
                if отвечает is not True:
                    return domain
            return почищенный
        return domain

    _ЗОНЫ = None
    _ЗОНЫ_ПО_ДЛИНЕ = None

    @classmethod
    def _зоны(cls):
        if cls._ЗОНЫ is None:
            из_списка = set()
            try:
                from core.public_suffix import зоны_верхнего_уровня
                из_списка = set(зоны_верхнего_уровня())
            except Exception:
                из_списка = set()
            cls._ЗОНЫ = frozenset(из_списка | set(cls._KNOWN_TLDS))
            по_длине = {}
            for зона in cls._ЗОНЫ:
                по_длине.setdefault(len(зона), []).append(зона)
            cls._ЗОНЫ_ПО_ДЛИНЕ = {к: tuple(v) for к, v in по_длине.items()}
        return cls._ЗОНЫ

    @classmethod
    def _составная_зона(cls, зона, хвост):
        try:
            from core.public_suffix import публичный_суффикс
            return публичный_суффикс("%s.%s" % (зона, хвост))
        except Exception:
            return False

    @classmethod
    def _в_одной_букве_от_зоны(cls, метка):
        cls._зоны()
        for длина in (len(метка) - 1, len(метка), len(метка) + 1):
            if длина <= 2:
                continue
            for зона in cls._ЗОНЫ_ПО_ДЛИНЕ.get(длина, ()):
                if cls._на_одну_букву(метка, зона):
                    return True
        return False

    _СЛОВАРЬ = None

    @classmethod
    def _английские_слова(cls):
        if cls._СЛОВАРЬ is None:
            путь = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "english_words.txt")
            слова = set()
            try:
                with open(путь, encoding="utf-8", errors="replace") as файл:
                    слова = {строка.strip().lower() for строка in файл
                             if строка.strip()}
            except Exception:
                слова = set()
            cls._СЛОВАРЬ = слова
        return cls._СЛОВАРЬ

    def correct_and_normalize(self, email: str) -> str:
        email = strip_wrapping_junk(email)
        if not email or "@" not in email:
            return None

        local_part, domain = email.rsplit("@", 1)

        if " " in local_part and not has_quoted_form(local_part):
            local_part = local_part.replace(" ", "")
        if " " in domain:
            domain = domain.replace(" ", "")

        import re
        local_part = re.sub(r'\.{2,}', '.', local_part)
        local_part = local_part.strip('.')
        
        if not local_part:
            return None

        if domain_literal_ip(domain) is not None:
            return "%s@%s" % (local_part, domain)


        domain = self._cut_tld_appendix(domain)

        приклеено = self._почтовик_с_меткой(domain)
        if приклеено is not None:
            return f"{local_part}@{приклеено}"

        matches = [pop for pop in self._sorted_domains
                   if domain.startswith(pop) and len(domain) > len(pop)
                   and self._junk_tail(domain[len(pop):])
                   and not self._похоже_на_опечатку_зоны(domain, pop)]
        if matches:
            domain = matches[0]

        elif domain.count('.') > 3:
            inner = [(domain.index(pop), -len(pop), pop)
                     for pop in self._sorted_domains
                     if domain.startswith(pop + ".")]
            if inner:
                domain = min(inner)[2]

        else:
            domain = self._strip_tld_tail(domain)
        
        domain = domain.rstrip('.')
        
        
        if domain in self.popular_domains:
            return f"{local_part}@{domain}"
            
        
        if '.' in domain and len(domain) >= 4:
            return f"{local_part}@{domain}"
        
        return None

    def _почтовик_с_меткой(self, domain):
        if domain.count(".") < 2:
            return None
        почтовики = self._живые_почтовики()
        if domain in почтовики:
            return None
        основа, _, метка = domain.rpartition(".")
        if основа not in почтовики or not (метка.isascii() and метка.isalpha()):
            return None
        if self._проверка_домена is None:
            return domain

        def спросить(имя):
            try:
                return self._проверка_домена(имя)
            except Exception:
                return None

        if спросить(domain) is not False:
            return domain
        return основа if спросить(основа) is True else domain

    _ЖИВЫЕ_ПОЧТОВИКИ = None

    def _живые_почтовики(self):
        if EmailCleaner._ЖИВЫЕ_ПОЧТОВИКИ is None:
            try:
                from core.filters import BLACKLIST_SENTINELS
                names = set(BLACKLIST_SENTINELS)
            except Exception:
                names = set()
            EmailCleaner._ЖИВЫЕ_ПОЧТОВИКИ = frozenset(names | set(self.popular_domains))
        return EmailCleaner._ЖИВЫЕ_ПОЧТОВИКИ

    def установить_проверку_домена(self, проверка):
        self._проверка_домена = проверка if callable(проверка) else None

    def suggest_domain_fix(self, email: str):
        if not isinstance(email, str) or email.count("@") != 1:
            return None
        local_part, domain = email.rsplit("@", 1)
        domain = domain.strip().lower().rstrip(".")
        if not local_part or not domain:
            return None

        fixed = self._typo_map.get(domain)
        if fixed and fixed != domain:
            return "%s@%s" % (local_part, fixed)
        return None

    def clean_email(self, email: str) -> str:
        return self.correct_and_normalize(email)
