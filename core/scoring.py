import json
import os
import threading

from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS
from core.provider import classify_domain, is_free_mail_domain
from core.paths import data_path


DEFAULT_WEIGHTS = {
    "smtp_valid": 55,
    "smtp_risky": 20,
    "smtp_unknown": 10,
    "gravatar": 10,
    "corporate_domain": 5,
    "dns_full": 10,
    "dns_good": 5,
    "dns_basic": 2,
    "domain_old_5y": 5,
    "domain_old_1y": 3,
    "name_extracted": 5,
    "disposable": -50,
    "domain_young_30d": -20,
    "domain_young_90d": -10,
    "role_based": -15,
    "server_outdated": -10,
    "in_dnsbl": -40,
    "no_ptr": -10,
    "no_starttls": -5,
    "no_website": -5,
    "machine_generated": -20,
    "parked_domain": -30,
}

WEIGHTS_PATH = data_path("scoring_weights.json")

_weights = dict(DEFAULT_WEIGHTS)
_weights_lock = threading.Lock()


def _sanitize(raw):
    if not isinstance(raw, dict):
        return {}
    clean = {}
    for key, value in raw.items():
        if key not in DEFAULT_WEIGHTS:
            continue
        try:
            number = int(round(float(value)))
        except (TypeError, ValueError):
            continue
        if -100 <= number <= 100:
            clean[key] = number
    return clean


def load_weights(path=None):
    target = path or WEIGHTS_PATH
    try:
        with open(target, "r", encoding="utf-8") as handle:
            raw = json.load(handle)
    except Exception:
        return 0
    clean = _sanitize(raw.get("weights") if isinstance(raw, dict) else None)
    if not clean:
        return 0
    with _weights_lock:
        _weights.update(clean)
    return len(clean)


def reset_weights():
    with _weights_lock:
        _weights.clear()
        _weights.update(DEFAULT_WEIGHTS)


def get_weights():
    with _weights_lock:
        return dict(_weights)


def W(key):
    if not isinstance(key, str):
        return 0
    with _weights_lock:
        return _weights.get(key, DEFAULT_WEIGHTS.get(key, 0))


def _is_free_provider(domain: str) -> bool:
    if not domain:
        return False
    if domain in GLOBAL_VERIFIED_DOMAINS:
        return True
    if is_free_mail_domain(domain):
        return True
    _provider, domain_type = classify_domain(f"x@{domain}")
    return domain_type in ("Personal", "ISP")


_STATUS_ALIASES = {
    "valid": "Valid",
    "250 ok": "Valid",
    "invalid": "Invalid/Bounce",
    "invalid/bounce": "Invalid/Bounce",
    "bounce": "Invalid/Bounce",
    "risky": "Risky",
    "unknown": "Unknown",
    "greylisted": "Unknown",
    "catchall": "Catch-All",
    "catch-all": "Catch-All",
    "role-based": "Role-based",
    "trap/disposable": "Trap/Disposable",
    "disposable": "Trap/Disposable",
    "full": "Mailbox Full",
    "mailbox full": "Mailbox Full",
    "disabled": "Disabled",
    "unconfirmed": "Unconfirmed",
}


_FULL_INBOX_MARKERS = (
    "full inbox", "mailbox full", "over quota", "overquota",
    "quota exceeded", "exceeded storage", "storage allocation",
    "переполнен", "полный ящик",
)


def _looks_like_full_inbox(reason):
    if not isinstance(reason, str) or not reason:
        return False
    low = reason.lower()
    return any(marker in low for marker in _FULL_INBOX_MARKERS)


def _canonical_status(status):
    if not isinstance(status, str):
        return ""
    low = status.strip().lower()
    if low in _STATUS_ALIASES:
        return _STATUS_ALIASES[low]
    return status.strip()


def calculate_engagement_score(
    email: str,
    smtp_status: str,
    smtp_reason: str = "",
    has_gravatar: bool = False,
    is_disposable: bool = False,
    dns_health_score: int = 0,
    domain_age_days: int = -1,
    name_extracted: str = "",
    is_role_based: bool = False,
    server_outdated: bool = False,
    has_ptr: bool = None,
    has_starttls: bool = None,
    in_dnsbl: bool = False,
    has_live_website: bool = True,
    original_smtp_status: str = None,
    machine_generated: bool = False,
    is_parked_domain: bool = False,
) -> dict:
    score = 0
    signals = []
    
    scoring_status = _canonical_status(
        original_smtp_status if original_smtp_status is not None else smtp_status)

    email = email if isinstance(email, str) else ""
    smtp_reason = smtp_reason if isinstance(smtp_reason, str) else ""
    domain = email.rsplit("@", 1)[1].lower() if "@" in email else ""
    is_free_provider = _is_free_provider(domain)

    if scoring_status == "Invalid/Bounce":
        return {
            "score": 0,
            "grade": "Dead",
            "signals": ["0: SMTP подтвердил, что ящик не существует"],
            "provider_type": "Free" if is_free_provider else "Corporate",
        }

    if scoring_status == "Disabled":
        return {
            "score": 0,
            "grade": "Dead",
            "signals": ["0: сервер назвал ящик отключённым"],
            "provider_type": "Free" if is_free_provider else "Corporate",
        }

    
    if scoring_status == "Mailbox Full" or (
            scoring_status == "Valid" and _looks_like_full_inbox(smtp_reason)):
        signals.append("0: Ящик переполнен — письмо не дойдёт; переполняется "
                       "обычно ящик, которым не пользуются")
    elif scoring_status == "Valid":
        score += W("smtp_valid")
        signals.append(f'+{W("smtp_valid")}: SMTP 250 OK (почта жива)')
    elif scoring_status == "Risky":
        score += W("smtp_risky")
        signals.append(f'+{W("smtp_risky")}: Risky (возможно жива)')
    elif scoring_status in ("Unknown", "Unconfirmed"):
        score += W("smtp_unknown")
        signals.append(f'+{W("smtp_unknown")}: {scoring_status} (неопределённо)')
    
    if has_gravatar:
        score += W("gravatar")
        signals.append(f'+{W("gravatar")}: Есть Gravatar (реальный человек)')
    
    if not is_free_provider and domain and scoring_status in ("Valid", "Risky"):
        if has_ptr or has_starttls or domain_age_days > 365:
            score += W("corporate_domain")
            signals.append(f'+{W("corporate_domain")}: Корпоративный домен')
    
    if dns_health_score >= 3:
        score += W("dns_full")
        signals.append(f'+{W("dns_full")}: Полный DNS (SPF+DMARC+DKIM)')
    elif dns_health_score >= 2:
        score += W("dns_good")
        signals.append(f'+{W("dns_good")}: Хороший DNS (2 из 3)')
    elif dns_health_score >= 1:
        score += W("dns_basic")
        signals.append(f'+{W("dns_basic")}: Базовый DNS (1 из 3)')
    
    if domain_age_days > 365 * 5:
        score += W("domain_old_5y")
        signals.append(f'+{W("domain_old_5y")}: Домен старше 5 лет')
    elif domain_age_days > 365:
        score += W("domain_old_1y")
        signals.append(f'+{W("domain_old_1y")}: Домен старше 1 года')
    
    if name_extracted:
        score += W("name_extracted")
        signals.append(f'+{W("name_extracted")}: Имя извлечено из email')
    
    
    if is_disposable:
        score += W("disposable")
        signals.append(f'{W("disposable")}: Одноразовый/временный домен')
    
    if 0 <= domain_age_days < 30:
        score += W("domain_young_30d")
        signals.append(f'{W("domain_young_30d")}: Молодой домен (< 30 дней)')
    elif 0 <= domain_age_days < 90:
        score += W("domain_young_90d")
        signals.append(f'{W("domain_young_90d")}: Молодой домен (< 90 дней)')
    
    if is_role_based:
        score += W("role_based")
        signals.append(f'{W("role_based")}: Role-based аккаунт (noreply, info и т.д.)')
    
    if server_outdated:
        score += W("server_outdated")
        signals.append(f'{W("server_outdated")}: Устаревший почтовый сервер')
        
    if in_dnsbl:
        score += W("in_dnsbl")
        signals.append(f'{W("in_dnsbl")}: IP сервера в чёрных списках (DNSBL)')
        
    if has_ptr is False and scoring_status in ('Valid', 'Risky'):
        score += W("no_ptr")
        signals.append(f'{W("no_ptr")}: Нет PTR-записи (подозрительный сервер)')

    if has_starttls is False and scoring_status in ('Valid', 'Risky'):
        score += W("no_starttls")
        signals.append(f'{W("no_starttls")}: Нет шифрования STARTTLS')
        
    if not has_live_website and not is_free_provider:
        score += W("no_website")
        signals.append(f'{W("no_website")}: Нет живого сайта (корпоративный домен)')

    if machine_generated:
        score += W("machine_generated")
        signals.append(f'{W("machine_generated")}: Адрес похож на сгенерированный машиной')

    if is_parked_domain:
        score += W("parked_domain")
        signals.append(f'{W("parked_domain")}: Домен припаркован (продаётся, почты нет)')
    
    score = max(0, min(100, score))
    
    if score >= 70:
        grade = "Hot"
    elif score >= 50:
        grade = "Warm"
    elif score >= 30:
        grade = "Neutral"
    elif score >= 10:
        grade = "Cold"
    else:
        grade = "Dead"
    
    return {
        "score": score,
        "grade": grade,
        "signals": signals,
        "provider_type": "Free" if is_free_provider else "Corporate",
    }
