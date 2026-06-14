# core/cleaner.py
import difflib

class EmailCleaner:
    def __init__(self):
        # Самые популярные провайдеры для проверки на опечатки
        self.popular_domains = [
            "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", 
            "icloud.com", "mail.ru", "yandex.ru", "bk.ru", "inbox.ru",
            "list.ru", "protonmail.com", "aol.com", "zoho.com"
        ]

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
            
        # 3. Проверка на опечатки через расстояние Левенштейна (difflib)
        # cutoff=0.8 означает высокую степень сходства (например gamil.com -> gmail.com)
        matches = difflib.get_close_matches(domain, self.popular_domains, n=1, cutoff=0.8)
        
        if matches:
            corrected_domain = matches[0]
            return f"{local_part}@{corrected_domain}"
            
        return f"{local_part}@{domain}"

    def process_batch(self, raw_emails: list) -> set:
        """
        Берет сырой список почт, применяет авто-коррекцию и 
        удаляет дубликаты, возвращая уникальное множество (set).
        """
        cleaned_emails = set()
        for raw in raw_emails:
            corrected = self.correct_and_normalize(raw)
            cleaned_emails.add(corrected)
        return cleaned_emails
