import re

__all__ = ["company_from_domain", "role_from_local_part", "enrich_org_role",
           "JOB_ROLES"]

JOB_ROLES = {
    "ceo": "Генеральный директор", "cto": "Технический директор",
    "cfo": "Финансовый директор", "coo": "Операционный директор",
    "cmo": "Директор по маркетингу", "ciso": "Директор по безопасности",
    "founder": "Основатель", "cofounder": "Сооснователь",
    "owner": "Владелец", "president": "Президент", "director": "Директор",
    "boss": "Руководитель", "chief": "Руководитель",
    "manager": "Менеджер", "head": "Руководитель направления",
    "sales": "Продажи", "sale": "Продажи", "marketing": "Маркетинг",
    "pr": "Связи с общественностью", "press": "Пресс-служба",
    "media": "Медиа", "partners": "Партнёрства",
    "partnership": "Партнёрства", "bd": "Развитие бизнеса",
    "business": "Развитие бизнеса", "reseller": "Партнёрская сеть",
    "support": "Поддержка", "help": "Поддержка", "helpdesk": "Поддержка",
    "service": "Сервис", "care": "Клиентский сервис",
    "customerservice": "Клиентский сервис", "contact": "Общий контакт",
    "info": "Общий контакт", "hello": "Общий контакт",
    "office": "Офис", "reception": "Приёмная",
    "billing": "Биллинг", "accounts": "Бухгалтерия",
    "accounting": "Бухгалтерия", "finance": "Финансы",
    "invoice": "Счета", "invoices": "Счета", "payments": "Платежи",
    "legal": "Юридический отдел", "compliance": "Комплаенс",
    "hr": "Кадры", "jobs": "Вакансии", "career": "Карьера",
    "careers": "Карьера", "recruiting": "Подбор персонала",
    "recruitment": "Подбор персонала", "hiring": "Подбор персонала",
    "admin": "Администратор", "administrator": "Администратор",
    "webmaster": "Веб-мастер", "hostmaster": "Хостмастер",
    "postmaster": "Почтовый администратор", "sysadmin": "Системный администратор",
    "root": "Системный администратор", "it": "ИТ-отдел",
    "dev": "Разработка", "developers": "Разработка", "engineering": "Инженерия",
    "security": "Безопасность", "abuse": "Служба злоупотреблений",
    "noc": "Сетевой центр", "devops": "DevOps", "qa": "Тестирование",
    "orders": "Заказы", "order": "Заказы", "shop": "Магазин",
    "booking": "Бронирование", "reservations": "Бронирование",
    "feedback": "Обратная связь", "newsletter": "Рассылка",
}

_SPLIT = re.compile(r"[.\-_+]")

_SECOND_LEVEL = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "id.au",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "ne.kr", "re.kr",
    "com.br", "net.br", "org.br", "gov.br", "edu.br",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn", "ac.cn",
    "com.mx", "com.ar", "com.tr", "com.sg", "com.hk", "com.tw",
    "com.ua", "co.il", "co.za", "co.in", "net.in", "org.in", "gov.in",
    "com.pl", "com.es", "com.pt", "com.my", "com.ph", "com.vn",
}

_NOISE = {"mail", "email", "www", "web", "smtp", "corp", "inc", "llc", "ltd",
          "gmbh", "group", "online", "site", "shop", "store", "app", "team"}


def _зона_второго_уровня(домен, parts):
    if not isinstance(домен, str) or not isinstance(parts, (list, tuple)):
        return False, 1
    parts = [ч for ч in parts if isinstance(ч, str)]
    if len(parts) < 2:
        return False, 1
    try:
        from core.public_suffix import правил_прочитано, публичный_суффикс
        if правил_прочитано():
            глубина = 0
            for сколько in range(1, len(parts)):
                if публичный_суффикс(".".join(parts[-сколько:])):
                    глубина = сколько
            if глубина:
                return len(parts) > глубина, глубина
    except Exception:
        pass
    if ".".join(parts[-2:]) in _SECOND_LEVEL:
        return len(parts) >= 3, 2
    return False, 1


def _registrable_name(domain):
    if not isinstance(domain, str):
        return ""
    низ = domain.strip().lower().strip(".")
    parts = [p for p in низ.split(".") if p]
    if len(parts) < 2:
        return ""
    левее, глубина = _зона_второго_уровня(низ, parts)
    if левее:
        name = parts[-(глубина + 1)]
    else:
        name = parts[-2]
    if name in _NOISE and len(parts) >= 3:
        candidate = parts[-3] if ".".join(parts[-2:]) not in _SECOND_LEVEL else ""
        name = candidate or name
    return "" if name in _NOISE else name


def company_from_domain(domain, domain_type=""):
    if domain_type and domain_type in ("Personal", "ISP", "Unknown"):
        return ""
    name = _registrable_name(domain)
    if not name or len(name) < 2:
        return ""
    words = [w for w in re.split(r"[-_]", name) if w]
    return " ".join(word.capitalize() for word in words)


def role_from_local_part(local):
    if not isinstance(local, str) or not local:
        return ""
    low = local.strip().lower()
    if low in JOB_ROLES:
        return JOB_ROLES[low]

    trimmed = low.rstrip("0123456789")
    if trimmed in JOB_ROLES:
        return JOB_ROLES[trimmed]

    parts = [p for p in _SPLIT.split(low) if p]
    for part in parts:
        stripped = part.rstrip("0123456789")
        if stripped in JOB_ROLES:
            return JOB_ROLES[stripped]

    compact = _SPLIT.sub("", low)
    for suffix in ("team", "department", "dept", "group", "office"):
        if compact.endswith(suffix):
            stem = compact[:-len(suffix)]
            if stem in JOB_ROLES:
                return JOB_ROLES[stem]
    return ""


def enrich_org_role(email, domain_type=""):
    if not isinstance(email, str) or "@" not in email:
        return {"company": "", "job_role": "",
                "company_source": "", "job_role_source": ""}

    local, _, domain = email.rpartition("@")
    company = company_from_domain(domain, domain_type)
    role = role_from_local_part(local)
    return {
        "company": company,
        "job_role": role,
        "company_source": "домен" if company else "",
        "job_role_source": "адрес" if role else "",
    }
