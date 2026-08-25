# core/scoring.py
"""
Композитный Engagement Score (Скор Живости).
Объединяет все сигналы в один числовой скор от 0 до 100.
Чем выше скор — тем больше уверенность что за почтой стоит реальный живой человек.
"""

import json
import os
import threading

from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS
from core.provider import classify_domain, is_free_mail_domain


# Веса сигналов.
#
# Раньше числа стояли прямо в коде, и подогнать их под НАБЛЮДАЕМЫЕ отскоки было
# нельзя — только переписать функцию. Теперь это таблица: значения по умолчанию
# ровно те же, что были, но tools/calibrate_scoring.py умеет пересчитать их по
# реальному bounce-логу и положить результат рядом в JSON.
DEFAULT_WEIGHTS = {
    "smtp_valid": 55,
    "smtp_valid_full_inbox": 70,
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

WEIGHTS_PATH = os.path.join("data", "scoring_weights.json")

_weights = dict(DEFAULT_WEIGHTS)
_weights_lock = threading.Lock()


def _sanitize(raw):
    """Оставляет только известные ключи с числами в разумных рамках.

    Калибровка пишет файл сама, но файл лежит на диске и может быть испорчен
    руками. Вес в 10000 сломал бы шкалу молча, поэтому диапазон ограничен.
    """
    # Файл на диске может содержать что угодно — список, строку, null. Всё,
    # что не словарь, это «весов нет», а не повод уронить скоринг: он крутится
    # в сотне рабочих потоков, и исключение отсюда убило бы поток целиком.
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
    """Подхватывает откалиброванные веса с диска. Возвращает, сколько заменено."""
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
    """Возвращает веса по умолчанию — нужно тестам и кнопке «сбросить»."""
    with _weights_lock:
        _weights.clear()
        _weights.update(DEFAULT_WEIGHTS)


def get_weights():
    """Копия текущей таблицы весов."""
    with _weights_lock:
        return dict(_weights)


def W(key):
    """Вес сигнала. Неизвестный ключ весит ноль.

    Раньше здесь стоял DEFAULT_WEIGHTS[key], и опечатка в имени сигнала роняла
    KeyError прямо посреди скоринга — то есть убивала рабочий поток и вместе с
    ним все оставшиеся ему адреса. Ноль вместо исключения безопаснее, а от
    самой опечатки защищает отдельный тест: он сверяет каждое имя, с которым
    W() вызывается в этом файле, со списком DEFAULT_WEIGHTS.
    """
    # Ключом словаря может быть не всё: список или словарь вызовут TypeError
    # ещё до поиска. Имя сигнала — всегда строка, остальное просто «не сигнал».
    if not isinstance(key, str):
        return 0
    with _weights_lock:
        return _weights.get(key, DEFAULT_WEIGHTS.get(key, 0))


def _is_free_provider(domain: str) -> bool:
    """True, если домен принадлежит бесплатному почтовому провайдеру.

    Три источника, и все нужны. Сначала проверка шла только по
    GLOBAL_VERIFIED_DOMAINS (81 домен списка парсера) — в нём нет yandex.ru,
    mail.ru, protonmail.com. Потом добавилась classify_domain, знающая крупные
    почтовики и ISP. Но и этого мало: mail.com, zoho.com, seznam.cz, rambler.ru
    и ещё сотни бесплатных сервисов проходили как КОРПОРАТИВНЫЕ, получали +5,
    которого не получает gmail.com, и зря гоняли HTTP-HEAD на несуществующий сайт.
    """
    if not domain:
        return False
    if domain in GLOBAL_VERIFIED_DOMAINS:
        return True
    if is_free_mail_domain(domain):
        return True
    _provider, domain_type = classify_domain(f"x@{domain}")
    return domain_type in ("Personal", "ISP")


def calculate_engagement_score(
    email: str,
    smtp_status: str,
    smtp_reason: str = "",
    has_gravatar: bool = False,
    is_disposable: bool = False,
    dns_health_score: int = 0,
    domain_age_days: int = -1,  # -1 = неизвестно
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
    """
    Вычисляет композитный скор живости email.
    
    Возвращает dict:
    {
        'score': int (0-100),
        'grade': str ('Hot' / 'Warm' / 'Neutral' / 'Cold' / 'Dead'),
        'signals': list[str]  — какие сигналы сработали
    }
    """
    score = 0
    signals = []
    
    scoring_status = original_smtp_status if original_smtp_status is not None else smtp_status

    email = email if isinstance(email, str) else ""
    smtp_reason = smtp_reason if isinstance(smtp_reason, str) else ""
    domain = email.rsplit("@", 1)[1].lower() if "@" in email else ""
    is_free_provider = _is_free_provider(domain)

    # Сервер прямо ответил, что ящика нет (550) или домен мёртв.
    # Здоровье домена (SPF/DMARC, возраст) тут ничего не значит: живой gmail.com
    # не делает несуществующий ящик на нём хоть сколько-нибудь живым.
    if scoring_status == "Invalid/Bounce":
        return {
            "score": 0,
            "grade": "Dead",
            "signals": ["0: SMTP подтвердил, что ящик не существует"],
            "provider_type": "Free" if is_free_provider else "Corporate",
        }

    # === ПОЗИТИВНЫЕ СИГНАЛЫ ===
    
    # 1. SMTP статус
    # Вердикт SMTP — самое сильное доказательство, которое вообще можно получить,
    # поэтому он и весит больше всего. Остальные баллы — про ДОМЕН и СЕРВЕР
    # (SPF, PTR, возраст), а у бесплатных провайдеров их набрать неоткуда:
    # с прежним весом +30 подтверждённый живой Gmail упирался в потолок 50/100
    # и вечно показывался как "Neutral".
    if scoring_status == "Valid":
        if "Full Inbox" in smtp_reason or "Mailbox Full" in smtp_reason or "Over Quota" in smtp_reason:
            score += W("smtp_valid_full_inbox")
            signals.append(f'+{W("smtp_valid_full_inbox")}: Полный ящик (активно используется)')
        else:
            score += W("smtp_valid")
            signals.append(f'+{W("smtp_valid")}: SMTP 250 OK (почта жива)')
    elif scoring_status == "Risky":
        score += W("smtp_risky")
        signals.append(f'+{W("smtp_risky")}: Risky (возможно жива)')
    elif scoring_status == "Unknown":
        score += W("smtp_unknown")
        signals.append(f'+{W("smtp_unknown")}: Unknown (неопределённо)')
    # Invalid/Bounce = 0 баллов
    
    # 2. Gravatar (бонус, только в плюс)
    if has_gravatar:
        score += W("gravatar")
        signals.append(f'+{W("gravatar")}: Есть Gravatar (реальный человек)')
    
    # 3. Корпоративный домен
    if not is_free_provider and domain and scoring_status in ("Valid", "Risky"):
        if has_ptr or has_starttls or domain_age_days > 365:
            score += W("corporate_domain")
            signals.append(f'+{W("corporate_domain")}: Корпоративный домен')
    
    # 4. DNS здоровье (SPF + DMARC + DKIM)
    if dns_health_score >= 3:
        score += W("dns_full")
        signals.append(f'+{W("dns_full")}: Полный DNS (SPF+DMARC+DKIM)')
    elif dns_health_score >= 2:
        score += W("dns_good")
        signals.append(f'+{W("dns_good")}: Хороший DNS (2 из 3)')
    elif dns_health_score >= 1:
        score += W("dns_basic")
        signals.append(f'+{W("dns_basic")}: Базовый DNS (1 из 3)')
    
    # 5. Возраст домена
    if domain_age_days > 365 * 5:  # Старше 5 лет
        score += W("domain_old_5y")
        signals.append(f'+{W("domain_old_5y")}: Домен старше 5 лет')
    elif domain_age_days > 365:  # Старше 1 года
        score += W("domain_old_1y")
        signals.append(f'+{W("domain_old_1y")}: Домен старше 1 года')
    
    # 6. Имя извлечено
    if name_extracted:
        score += W("name_extracted")
        signals.append(f'+{W("name_extracted")}: Имя извлечено из email')
    
    # === НЕГАТИВНЫЕ СИГНАЛЫ ===
    
    # 7. Одноразовый домен
    if is_disposable:
        score += W("disposable")
        signals.append(f'{W("disposable")}: Одноразовый/временный домен')
    
    # 8. Молодой домен
    if 0 <= domain_age_days < 30:
        score += W("domain_young_30d")
        signals.append(f'{W("domain_young_30d")}: Молодой домен (< 30 дней)')
    elif 0 <= domain_age_days < 90:
        score += W("domain_young_90d")
        signals.append(f'{W("domain_young_90d")}: Молодой домен (< 90 дней)')
    
    # 9. Role-based аккаунт
    if is_role_based:
        score += W("role_based")
        signals.append(f'{W("role_based")}: Role-based аккаунт (noreply, info и т.д.)')
    
    # 10. Устаревший SMTP-сервер
    if server_outdated:
        score += W("server_outdated")
        signals.append(f'{W("server_outdated")}: Устаревший почтовый сервер')
        
    if in_dnsbl:
        score += W("in_dnsbl")
        signals.append(f'{W("in_dnsbl")}: IP сервера в чёрных списках (DNSBL)')
        
    # PTR и STARTTLS — гигиена почтового СЕРВЕРА, а не доказательство мёртвого ящика.
    # Штрафуем только при подтверждённом отсутствии (False), но не при None ("не проверено"),
    # и мягко: подтверждённый SMTP 250 OK не должен обнуляться из-за них.
    if has_ptr is False and scoring_status in ('Valid', 'Risky'):
        score += W("no_ptr")
        signals.append(f'{W("no_ptr")}: Нет PTR-записи (подозрительный сервер)')

    if has_starttls is False and scoring_status in ('Valid', 'Risky'):
        score += W("no_starttls")
        signals.append(f'{W("no_starttls")}: Нет шифрования STARTTLS')
        
    if not has_live_website and not is_free_provider:
        score += W("no_website")
        signals.append(f'{W("no_website")}: Нет живого сайта (корпоративный домен)')

    # Локальная часть похожа на машинную генерацию ('xk3n9fj2q@') — за такими
    # адресами почти никогда нет живого человека, даже если ящик существует.
    if machine_generated:
        score += W("machine_generated")
        signals.append(f'{W("machine_generated")}: Адрес похож на сгенерированный машиной')

    # Домен припаркован (MX ведёт на парковочный сервис) — живых ящиков там нет
    if is_parked_domain:
        score += W("parked_domain")
        signals.append(f'{W("parked_domain")}: Домен припаркован (продаётся, почты нет)')
    
    # Ограничиваем скор в диапазоне 0-100
    score = max(0, min(100, score))
    
    # Определяем грейд
    if score >= 70:
        grade = "Hot"          # 🔥 Горячий лид
    elif score >= 50:
        grade = "Warm"         # 🟢 Тёплый
    elif score >= 30:
        grade = "Neutral"      # 🟡 Нейтральный
    elif score >= 10:
        grade = "Cold"         # 🔵 Холодный
    else:
        grade = "Dead"         # ⚫ Мёртвый
    
    return {
        "score": score,
        "grade": grade,
        "signals": signals,
        "provider_type": "Free" if is_free_provider else "Corporate",
    }
