# core/scoring.py
"""
Композитный Engagement Score (Скор Живости).
Объединяет все сигналы в один числовой скор от 0 до 100.
Чем выше скор — тем больше уверенность что за почтой стоит реальный живой человек.
"""

from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS


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
    
    # === ПОЗИТИВНЫЕ СИГНАЛЫ ===
    
    # 1. SMTP статус
    if smtp_status == "Valid":
        if "Full Inbox" in smtp_reason or "Mailbox Full" in smtp_reason or "Over Quota" in smtp_reason:
            score += 40
            signals.append("+40: Полный ящик (активно используется)")
        else:
            score += 30
            signals.append("+30: SMTP 250 OK (почта жива)")
    elif smtp_status == "Risky":
        score += 10
        signals.append("+10: Risky (возможно жива)")
    elif smtp_status == "Unknown":
        score += 5
        signals.append("+5: Unknown (неопределённо)")
    # Invalid/Bounce = 0 баллов
    
    # 2. Gravatar (бонус, только в плюс)
    if has_gravatar:
        score += 20
        signals.append("+20: Есть Gravatar (реальный человек)")
    
    # 3. Корпоративный домен
    domain = email.rsplit("@", 1)[1].lower() if "@" in email else ""
    is_free_provider = domain in GLOBAL_VERIFIED_DOMAINS
    if not is_free_provider and domain and smtp_status in ("Valid", "Risky"):
        score += 10
        signals.append("+10: Корпоративный домен")
    
    # 4. DNS здоровье (SPF + DMARC + DKIM)
    if dns_health_score >= 3:
        score += 10
        signals.append("+10: Полный DNS (SPF+DMARC+DKIM)")
    elif dns_health_score >= 2:
        score += 5
        signals.append("+5: Хороший DNS (2 из 3)")
    elif dns_health_score >= 1:
        score += 2
        signals.append("+2: Базовый DNS (1 из 3)")
    
    # 5. Возраст домена
    if domain_age_days > 365 * 5:  # Старше 5 лет
        score += 5
        signals.append("+5: Домен старше 5 лет")
    elif domain_age_days > 365:  # Старше 1 года
        score += 3
        signals.append("+3: Домен старше 1 года")
    
    # 6. Имя извлечено
    if name_extracted:
        score += 5
        signals.append("+5: Имя извлечено из email")
    
    # === НЕГАТИВНЫЕ СИГНАЛЫ ===
    
    # 7. Одноразовый домен
    if is_disposable:
        score -= 50
        signals.append("-50: Одноразовый/временный домен")
    
    # 8. Молодой домен
    if 0 <= domain_age_days < 30:
        score -= 20
        signals.append("-20: Молодой домен (< 30 дней)")
    elif 0 <= domain_age_days < 90:
        score -= 10
        signals.append("-10: Молодой домен (< 90 дней)")
    
    # 9. Role-based аккаунт
    if is_role_based:
        score -= 15
        signals.append("-15: Role-based аккаунт (noreply, info и т.д.)")
    
    # 10. Устаревший SMTP-сервер
    if server_outdated:
        score -= 10
        signals.append("-10: Устаревший почтовый сервер")
    
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
