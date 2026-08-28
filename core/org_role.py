# core/org_role.py
"""Компания и должность — из того, что уже известно про адрес.

Аудит называл обогащение узким: единственным источником был Gravatar, а
компании и должности не было вовсе. Соблазн тут — пойти искать эти данные в
сети. Не стоит: платные сервисы держат их годами наработанными базами, а
бесплатных источников «email -> место работы» не существует. Попытка угадать
дала бы колонку, в которой каждая вторая запись выдумана, — ровно то, чего
владелец просил избегать.

Зато две вещи выводятся не догадкой, а ФАКТОМ, и обе уже лежат в самом адресе:

* **Компания — это домен.** `ppillai@tekveo.com` работает в Tekveo. Для
  корпоративного домена это не предположение, а определение: домен куплен
  организацией, и почта на нём принадлежит ей. Для бесплатного почтовика
  (gmail.com) компании нет — и колонка остаётся пустой, а не заполняется
  словом «Gmail».

* **Должность — это локальная часть.** `ceo@`, `sales@`, `hr@`, `support@` —
  это не имя человека, а функция, и она написана прямо в адресе. Ролевые
  адреса проект и так распознаёт (для отсева); здесь та же информация
  превращается из повода отсеять в повод сегментировать.

Каждое поле помечается источником, как имя, пол и страна: `домен` и `адрес` —
это факты, и отличать их от догадок надо и здесь.
"""
import re

__all__ = ["company_from_domain", "role_from_local_part", "enrich_org_role",
           "JOB_ROLES"]

# Домен -> должность. Составлено из ролевых адресов, которые встречаются в
# корпоративной почте. Слева то, что стоит до @, справа — человекочитаемое
# название функции.
JOB_ROLES = {
    # Руководство
    "ceo": "Генеральный директор", "cto": "Технический директор",
    "cfo": "Финансовый директор", "coo": "Операционный директор",
    "cmo": "Директор по маркетингу", "ciso": "Директор по безопасности",
    "founder": "Основатель", "cofounder": "Сооснователь",
    "owner": "Владелец", "president": "Президент", "director": "Директор",
    "boss": "Руководитель", "chief": "Руководитель",
    "manager": "Менеджер", "head": "Руководитель направления",
    # Продажи и маркетинг
    "sales": "Продажи", "sale": "Продажи", "marketing": "Маркетинг",
    "pr": "Связи с общественностью", "press": "Пресс-служба",
    "media": "Медиа", "partners": "Партнёрства",
    "partnership": "Партнёрства", "bd": "Развитие бизнеса",
    "business": "Развитие бизнеса", "reseller": "Партнёрская сеть",
    # Поддержка и сервис
    "support": "Поддержка", "help": "Поддержка", "helpdesk": "Поддержка",
    "service": "Сервис", "care": "Клиентский сервис",
    "customerservice": "Клиентский сервис", "contact": "Общий контакт",
    "info": "Общий контакт", "hello": "Общий контакт",
    "office": "Офис", "reception": "Приёмная",
    # Финансы и право
    "billing": "Биллинг", "accounts": "Бухгалтерия",
    "accounting": "Бухгалтерия", "finance": "Финансы",
    "invoice": "Счета", "invoices": "Счета", "payments": "Платежи",
    "legal": "Юридический отдел", "compliance": "Комплаенс",
    # Персонал
    "hr": "Кадры", "jobs": "Вакансии", "career": "Карьера",
    "careers": "Карьера", "recruiting": "Подбор персонала",
    "recruitment": "Подбор персонала", "hiring": "Подбор персонала",
    # Технические
    "admin": "Администратор", "administrator": "Администратор",
    "webmaster": "Веб-мастер", "hostmaster": "Хостмастер",
    "postmaster": "Почтовый администратор", "sysadmin": "Системный администратор",
    "root": "Системный администратор", "it": "ИТ-отдел",
    "dev": "Разработка", "developers": "Разработка", "engineering": "Инженерия",
    "security": "Безопасность", "abuse": "Служба злоупотреблений",
    "noc": "Сетевой центр", "devops": "DevOps", "qa": "Тестирование",
    # Прочее
    "orders": "Заказы", "order": "Заказы", "shop": "Магазин",
    "booking": "Бронирование", "reservations": "Бронирование",
    "feedback": "Обратная связь", "newsletter": "Рассылка",
}

_SPLIT = re.compile(r"[.\-_+]")

# Зоны второго уровня: у них имя организации лежит на уровень левее.
# `bbc.co.uk` — это BBC, а не CO.
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

# Слова в имени домена, которые не являются частью названия компании.
_NOISE = {"mail", "email", "www", "web", "smtp", "corp", "inc", "llc", "ltd",
          "gmbh", "group", "online", "site", "shop", "store", "app", "team"}


def _registrable_name(domain):
    """Имя организации из домена. Пусто, если выделить нечего."""
    if not isinstance(domain, str):
        return ""
    parts = [p for p in domain.strip().lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return ""
    if len(parts) >= 3 and ".".join(parts[-2:]) in _SECOND_LEVEL:
        name = parts[-3]
    else:
        name = parts[-2]
    # Поддомен почтовика: mail.company.com -> company
    if name in _NOISE and len(parts) >= 3:
        candidate = parts[-3] if ".".join(parts[-2:]) not in _SECOND_LEVEL else ""
        name = candidate or name
    return "" if name in _NOISE else name


def company_from_domain(domain, domain_type=""):
    """Название компании по домену. Пусто у бесплатных почтовиков.

    Для корпоративного домена это факт, а не догадка: домен куплен
    организацией. Для gmail.com компании нет, и писать туда «Gmail» значило бы
    выдать почтовика за место работы.
    """
    if domain_type and domain_type in ("Personal", "ISP", "Unknown"):
        return ""
    name = _registrable_name(domain)
    if not name or len(name) < 2:
        return ""
    # Дефисы и подчёркивания в названиях читаются как пробелы: tek-veo -> Tek Veo
    words = [w for w in re.split(r"[-_]", name) if w]
    return " ".join(word.capitalize() for word in words)


def role_from_local_part(local):
    """Должность по локальной части адреса. Пусто, если это имя человека.

    `sales@`, `hr@`, `ceo@` — функция, написанная в адресе прямым текстом.
    `john.smith@` — имя, и должности в нём нет.
    """
    if not isinstance(local, str) or not local:
        return ""
    low = local.strip().lower()
    if low in JOB_ROLES:
        return JOB_ROLES[low]

    # Цифровой хвост у роли встречается: support2@, sales01@
    trimmed = low.rstrip("0123456789")
    if trimmed in JOB_ROLES:
        return JOB_ROLES[trimmed]

    # Составные: sales.eu@, hr-moscow@, john.sales@
    parts = [p for p in _SPLIT.split(low) if p]
    for part in parts:
        stripped = part.rstrip("0123456789")
        if stripped in JOB_ROLES:
            return JOB_ROLES[stripped]

    # Слитно: salesteam@, hrdepartment@ — но только с точным началом, иначе
    # `information@` прочиталось бы как `info`, а `dev` нашёлся бы в `devine`.
    compact = _SPLIT.sub("", low)
    for suffix in ("team", "department", "dept", "group", "office"):
        if compact.endswith(suffix):
            stem = compact[:-len(suffix)]
            if stem in JOB_ROLES:
                return JOB_ROLES[stem]
    return ""


def enrich_org_role(email, domain_type=""):
    """Компания и должность одним вызовом. Оба поля — факты из самого адреса.

    Возвращает {'company', 'job_role', 'company_source', 'job_role_source'};
    пустые поля означают «выделить нечего», а не «не проверяли».
    """
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
