# core/cleaner.py

from .parser_pipeline import GLOBAL_VERIFIED_DOMAINS

class EmailCleaner:
    def __init__(self):
        # Самые популярные провайдеры для проверки на опечатки
        self.popular_domains = set(GLOBAL_VERIFIED_DOMAINS)
        
        # Хеш-таблица опечаток: неправильный домен → правильный
        self._typo_map = {
            'gamil.com': 'gmail.com', 'gmial.com': 'gmail.com', 'gmal.com': 'gmail.com',
            'gmai.com': 'gmail.com', 'gmail.co': 'gmail.com', 'gmail.con': 'gmail.com',
            'gmail.ru': 'gmail.com', 'gnail.com': 'gmail.com', 'gmaill.com': 'gmail.com',
            'g.mail.com': 'gmail.com', 'gmaul.com': 'gmail.com', 'gmqil.com': 'gmail.com',
            'yaho.com': 'yahoo.com', 'yahoo.co': 'yahoo.com',
            'yahoo.con': 'yahoo.com', 'yaboo.com': 'yahoo.com', 'yahooo.com': 'yahoo.com',
            'outlok.com': 'outlook.com', 'outook.com': 'outlook.com', 'otlook.com': 'outlook.com',
            'outlool.com': 'outlook.com', 'outloock.com': 'outlook.com',
            'hotmal.com': 'hotmail.com', 'hotmai.com': 'hotmail.com', 'hotmail.co': 'hotmail.com',
            'hotmial.com': 'hotmail.com', 'hotmaill.com': 'hotmail.com',
            'iclod.com': 'icloud.com', 'icoud.com': 'icloud.com', 'icloud.co': 'icloud.com',
            'mail.r': 'mail.ru', 'mai.ru': 'mail.ru', 'maill.ru': 'mail.ru',
            'yandex.r': 'yandex.ru', 'yanex.ru': 'yandex.ru', 'yandx.ru': 'yandex.ru',
        }

    def correct_and_normalize(self, email: str) -> str:
        """
        Гибридный Cleaner (п.1.1 ТЗ):
        - Известные домены → исправить опечатки, пропустить
        - Неизвестные домены → пропустить КАК ЕСТЬ (не убивать!)
        - DNS-проверка живости домена делается позже в network.py (get_mx_records)
        """
        email = email.strip().lower()
        if "@" not in email:
            return None
            
        local_part, domain = email.rsplit("@", 1)
        
        # 0. Зачистка левой части (local_part)
        import re
        # Убираем повторяющиеся точки (karl....motiv -> karl.motiv)
        local_part = re.sub(r'\.{2,}', '.', local_part)
        # Убираем точки в самом начале и в самом конце левой части (.karl.motiv.@gmail.com -> karl.motiv@gmail.com)
        local_part = local_part.strip('.')
        
        # Если локальная часть пустая после очистки — мусор
        if not local_part:
            return None
        
        # 1. Жесткая зачистка "хвостов" от копипаста в домене
        
        # Удаляем всякие странные приписки после доменов (типа -jobs, -site-..., .watch, .regarde)
        # Ищем стандартный домен (например .com, .org, .ru), а все что после него - отсекаем
        # НО: сохраняем составные TLD (.co.uk, .com.br, .co.in и т.д.)
        domain = re.sub(r'(\.(com|org|net|ru|edu|gov|io|me|info|biz))[-_].*$', r'\1', domain)
        
        # Хардкод-фикс для слипшихся мусорных доменов (типа gmail.comtelefoon, yahoo.comwatch)
        for pop in self.popular_domains:
            if domain.startswith(pop) and len(domain) > len(pop):
                domain = pop
                break
        
        # Убираем случайные точки в конце
        domain = domain.rstrip('.')
        
        # 2. Проверка на опечатки в известных доменах
        if domain in self._typo_map:
            domain = self._typo_map[domain]
        
        # 3. Точное совпадение с известным доменом — сразу пропускаем
        if domain in self.popular_domains:
            return f"{local_part}@{domain}"
            
        # 4. ГИБРИДНЫЙ ПОДХОД: Неизвестный домен — НЕ убиваем, а пропускаем как есть!
        #    DNS-проверка (MX/A-запись) будет выполнена позже в network.py.
        #    Если у домена нет ни MX, ни A-записи — network.py сам его отбракует.
        #    Таким образом корпоративные почты (ivan@sberbank.ru, john@tesla.com) не теряются.
        
        # Минимальная проверка: домен должен содержать хотя бы одну точку и не быть мусором
        if '.' in domain and len(domain) >= 4:
            return f"{local_part}@{domain}"
        
        # Совсем битый домен (без точки, слишком короткий) — мусор
        return None

    # Алиас для обратной совместимости (pipeline.py вызывает clean_email)
    def clean_email(self, email: str) -> str:
        return self.correct_and_normalize(email)

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
