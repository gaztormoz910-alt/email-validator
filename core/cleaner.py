# core/cleaner.py

from .parser_pipeline import GLOBAL_VERIFIED_DOMAINS

class EmailCleaner:
    def __init__(self):
        # Самые популярные провайдеры для проверки на опечатки
        self.popular_domains = list(GLOBAL_VERIFIED_DOMAINS)

    def correct_and_normalize(self, email: str) -> str:
        """Исправляет опечатки в доменах и переводит в нижний регистр."""
        email = email.strip().lower()
        if "@" not in email:
            return email
            
        local_part, domain = email.rsplit("@", 1)
        
        # 0. Зачистка левой части (local_part)
        import re
        # Убираем повторяющиеся точки (karl....motiv -> karl.motiv)
        local_part = re.sub(r'\.{2,}', '.', local_part)
        # Убираем точки в самом начале и в самом конце левой части (.karl.motiv.@gmail.com -> karl.motiv@gmail.com)
        local_part = local_part.strip('.')
        
        # 1. Жесткая зачистка "хвостов" от копипаста в домене
        
        # Удаляем всякие странные приписки после доменов (типа -jobs, -site-..., .watch, .regarde)
        # Ищем стандартный домен (например .com, .org, .ru), а все что после него - отсекаем
        domain = re.sub(r'(\.(com|org|net|ru|edu|gov|co|io|me|info|biz))[-._].*$', r'\1', domain)
        
        # Хардкод-фикс для слипшихся мусорных доменов (типа gmail.comtelefoon, yahoo.comwatch)
        for pop in self.popular_domains:
            if domain.startswith(pop) and len(domain) > len(pop):
                domain = pop
                break
        
        # Убираем случайные точки в конце
        domain = domain.rstrip('.')
        
        # 2. Точное совпадение после жесткой очистки
        if domain in self.popular_domains:
            return f"{local_part}@{domain}"
            
        # 3. Быстрая проверка на опечатки через хэш-таблицу (O(1)) вместо difflib
        if not hasattr(self, '_typo_map'):
            self._typo_map = {
                'gamil.com': 'gmail.com', 'gmial.com': 'gmail.com', 'gmal.com': 'gmail.com',
                'gmai.com': 'gmail.com', 'gmail.co': 'gmail.com', 'gmail.con': 'gmail.com',
                'gmail.ru': 'gmail.com', 'yaho.com': 'yahoo.com', 'yahoo.co': 'yahoo.com',
                'yahoo.con': 'yahoo.com', 'yaboo.com': 'yahoo.com', 'outlok.com': 'outlook.com',
                'outook.com': 'outlook.com', 'otlook.com': 'outlook.com', 'hotmal.com': 'hotmail.com',
                'hotmai.com': 'hotmail.com', 'hotmail.co': 'hotmail.com', 'iclod.com': 'icloud.com',
                'icoud.com': 'icloud.com'
            }
            
        if domain in self._typo_map:
            return f"{local_part}@{self._typo_map[domain]}"
            
        # 4. Если домен не найден в белом списке и не поддается лечению - возвращаем None
        return None

    def process_batch(self, raw_emails_dict: dict) -> dict:
        """
        Берет словарь почт {email: data}, применяет авто-коррекцию и 
        удаляет дубликаты, возвращая очищенный словарь.
        """
        cleaned_emails = {}
        for raw, data in raw_emails_dict.items():
            corrected = self.correct_and_normalize(raw)
            if corrected and corrected not in cleaned_emails: # Добавляем только если домен прошел проверку
                cleaned_emails[corrected] = data
        return cleaned_emails
