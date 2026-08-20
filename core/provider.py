# core/provider.py
"""Классификация почтового провайдера и типа домена (п.34, п.35, п.38 чек-листа).

Отвечает на два разных вопроса:
  provider_name — ЧЕЙ это почтовик (Gmail / Yahoo / Outlook / Mail.ru / ...)
  domain_type   — ЧТО это за домен (Personal / Corporate / ISP / Education / Government)

Нужно для сегментации базы: рассылка на Gmail и на корпоративные домены
ведёт себя по-разному (разные лимиты, разные пороги жалоб).
"""

# Провайдер -> его домены
_PROVIDER_DOMAINS = {
    "Gmail": {"gmail.com", "googlemail.com"},
    "Outlook": {"outlook.com", "hotmail.com", "live.com", "msn.com",
                "outlook.co.uk", "hotmail.co.uk", "live.co.uk", "passport.com"},
    "Yahoo": {"yahoo.com", "ymail.com", "rocketmail.com", "yahoo.co.uk",
              "yahoo.fr", "yahoo.de", "yahoo.co.jp", "yahoo.in", "yahoo.ca"},
    "Mail.ru": {"mail.ru", "bk.ru", "inbox.ru", "list.ru", "internet.ru"},
    "Yandex": {"yandex.ru", "ya.ru", "yandex.com", "yandex.by", "yandex.kz"},
    "iCloud": {"icloud.com", "me.com", "mac.com"},
    "Proton": {"protonmail.com", "protonmail.ch", "proton.me", "pm.me"},
    "AOL": {"aol.com", "aim.com", "love.com", "games.com"},
    "GMX": {"gmx.com", "gmx.de", "gmx.net", "gmx.at"},
    "Zoho": {"zoho.com", "zohomail.com"},
    "Tutanota": {"tutanota.com", "tuta.io", "tutanota.de"},
    "Fastmail": {"fastmail.com", "fastmail.fm"},
    "QQ": {"qq.com", "foxmail.com"},
    "NetEase": {"163.com", "126.com", "yeah.net"},
}

# Плоская карта домен -> провайдер (строится один раз при импорте)
_DOMAIN_TO_PROVIDER = {}
for _prov, _domains in _PROVIDER_DOMAINS.items():
    for _d in _domains:
        _DOMAIN_TO_PROVIDER[_d] = _prov

# Интернет-провайдеры (ISP). Такие ящики выдаются вместе с интернетом
# и часто умирают при смене оператора — это важный сигнал риска.
_ISP_DOMAINS = {
    "comcast.net", "verizon.net", "att.net", "sbcglobal.net", "bellsouth.net",
    "cox.net", "charter.net", "earthlink.net", "juno.com", "netzero.net",
    "optonline.net", "roadrunner.com", "rr.com", "windstream.net", "frontier.com",
    "centurylink.net", "embarqmail.com", "shaw.ca", "rogers.com", "sympatico.ca",
    "telus.net", "bigpond.com", "optusnet.com.au", "virginmedia.com", "sky.com",
    "btinternet.com", "talktalk.net", "orange.fr", "wanadoo.fr", "free.fr",
    "t-online.de", "web.de", "libero.it", "terra.com.br", "uol.com.br",
}

# MX-хосты крупных хостеров: по ним понимаем, на чьей инфраструктуре сидит домен
_MX_PROVIDER_HINTS = {
    "google": "Google Workspace",
    "googlemail": "Google Workspace",
    "outlook": "Microsoft 365",
    "microsoft": "Microsoft 365",
    "protection.outlook": "Microsoft 365",
    "yandex": "Yandex 360",
    "mail.ru": "Mail.ru Biz",
    "zoho": "Zoho Mail",
    "protonmail": "Proton",
    "yahoodns": "Yahoo",
    "secureserver": "GoDaddy",
    "mailgun": "Mailgun",
    "sendgrid": "SendGrid",
    "amazonaws": "Amazon SES",
    "qq.com": "QQ",
}

# Образовательные и государственные зоны
_EDU_SUFFIXES = (".edu", ".ac.uk", ".edu.au", ".edu.cn", ".ac.jp", ".edu.br",
                 ".ac.in", ".edu.in", ".ac.nz", ".edu.sg", ".ac.za", ".edu.mx")
_GOV_SUFFIXES = (".gov", ".gov.uk", ".mil", ".gov.au", ".gouv.fr", ".gov.in",
                 ".gov.br", ".gov.ru")


def classify_domain(email: str, mx_record: str = "") -> tuple:
    """Возвращает (provider_name, domain_type).

    provider_name: 'Gmail', 'Outlook', 'Google Workspace', 'Corporate' и т.п.
    domain_type:   'Personal' | 'ISP' | 'Education' | 'Government' | 'Corporate'
    """
    if not email or "@" not in email:
        return ("Unknown", "Unknown")

    domain = email.rsplit("@", 1)[1].lower().strip()

    # 1. Крупный бесплатный почтовик — определяем точно по домену
    provider = _DOMAIN_TO_PROVIDER.get(domain)
    if provider:
        return (provider, "Personal")

    # 2. Интернет-провайдер
    if domain in _ISP_DOMAINS:
        return ("ISP", "ISP")

    # 3. Образование и госструктуры — по зоне домена
    if domain.endswith(_EDU_SUFFIXES):
        return (_provider_from_mx(mx_record) or "Corporate", "Education")
    if domain.endswith(_GOV_SUFFIXES):
        return (_provider_from_mx(mx_record) or "Corporate", "Government")

    # 4. Свой домен — смотрим, на чьей почтовой инфраструктуре он сидит
    mx_provider = _provider_from_mx(mx_record)
    if mx_provider:
        return (mx_provider, "Corporate")

    return ("Corporate", "Corporate")


# Что можно проверить с текущего IP, а что требует особых условий.
# Основано на живых пробах SMTP, а не на догадках.
VERIFIABILITY = {
    # Отвечают честно любому IP
    "Gmail": "ok",
    "Yandex": "ok",
    "Proton": "ok",
    # Принимают ЛЮБОЙ адрес (catch-all на уровне протокола) — проверить нельзя ничем
    "Mail.ru": "never",
    # Нужен IP с обратным DNS (FCrDNS)
    "Yahoo": "needs_ptr",
    "AOL": "needs_ptr",
    # Нужен IP с чистой репутацией
    "Outlook": "needs_clean_ip",
    "iCloud": "needs_clean_ip",
    "GMX": "needs_clean_ip",
}

_VERDICT_LABEL = {
    "ok": "проверяется с любого IP",
    "never": "НЕ проверяется никогда (catch-all)",
    "needs_ptr": "нужен IP с PTR (FCrDNS)",
    "needs_clean_ip": "нужен IP с чистой репутацией",
    "unknown": "зависит от домена",
}


def scan_base_providers(email_sources, limit=None):
    """Считает разбивку базы по провайдерам БЕЗ единого сетевого запроса.

    Нужно, чтобы понять до запуска: какая доля базы вообще проверяема
    с текущего IP и стоит ли вкладываться в прокси с PTR.

    Возвращает dict: {'total', 'providers', 'verifiability'}
    """
    from core.streamer import StreamLoader
    from collections import Counter

    providers = Counter()
    verdicts = Counter()
    total = 0

    for email, _ in StreamLoader(email_sources).stream_emails():
        if not email or "@" not in email:
            continue
        total += 1
        prov, _dom_type = classify_domain(email)
        providers[prov] += 1
        verdicts[VERIFIABILITY.get(prov, "unknown")] += 1
        if limit and total >= limit:
            break

    return {"total": total, "providers": providers, "verifiability": verdicts}


def format_base_scan(scan) -> list:
    """Готовит человекочитаемый отчёт по результату scan_base_providers()."""
    total = scan["total"]
    if not total:
        return ["[INFO] Скан базы: адресов не найдено."]

    lines = [f"[INFO] === Состав базы: {total} адресов ==="]

    for prov, cnt in scan["providers"].most_common(12):
        pct = round(cnt * 100 / total, 1)
        note = _VERDICT_LABEL.get(VERIFIABILITY.get(prov, "unknown"), "")
        lines.append(f"[INFO]   {prov:<18} {cnt:>7}  ({pct:>5}%)  — {note}")

    v = scan["verifiability"]
    ok = v.get("ok", 0)
    never = v.get("never", 0)
    ptr = v.get("needs_ptr", 0)
    clean = v.get("needs_clean_ip", 0)
    unk = v.get("unknown", 0)

    def pct(n):
        return round(n * 100 / total, 1)

    lines.append("[INFO] --- Что это значит ---")
    lines.append(f"[INFO]   Проверю с текущего IP:        {ok + unk:>7} ({pct(ok + unk)}%)")
    lines.append(f"[INFO]   Нужен IP с чистой репутацией: {clean:>7} ({pct(clean)}%)")
    lines.append(f"[INFO]   Нужен IP с PTR (Yahoo/AOL):   {ptr:>7} ({pct(ptr)}%)")
    lines.append(f"[INFO]   Не проверяется никогда:       {never:>7} ({pct(never)}%)")

    gain = clean + ptr
    if gain == 0:
        lines.append("[INFO] Вывод: VPS с PTR ничего не добавит — таких адресов в базе нет.")
    elif pct(gain) < 10:
        lines.append(f"[INFO] Вывод: VPS с PTR добавит лишь {pct(gain)}% базы. Вероятно, не окупится.")
    else:
        lines.append(f"[INFO] Вывод: VPS с чистым IP и PTR откроет {gain} адресов ({pct(gain)}% базы).")

    return lines


def _provider_from_mx(mx_record: str):
    """Определяет хостера почты по MX-записи."""
    if not mx_record or mx_record == "N/A":
        return None
    mx = mx_record.lower()
    for hint, name in _MX_PROVIDER_HINTS.items():
        if hint in mx:
            return name
    return None
