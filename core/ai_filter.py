# core/ai_filter.py
import math
import re

class AIFilter:
    def __init__(self):
        self.role_prefixes = {
            "admin", "support", "staff", "info", "sales", 
            "postmaster", "webmaster", "contact", "billing", "help", "hr",
            "office", "marketing", "hello", "noreply", "no-reply"
        }
        self.bad_tlds = {".gov", ".mil", ".edu"}

    def is_role_based(self, local_part: str) -> bool:
        """Проверяет, является ли ящик ролевым (info@, admin@)."""
        return local_part.lower() in self.role_prefixes

    def is_bad_tld(self, domain: str) -> bool:
        """Проверяет опасные доменные зоны (gov, mil, edu)."""
        for tld in self.bad_tlds:
            if domain.lower().endswith(tld):
                return True
        return False

    def shannon_entropy(self, s: str) -> float:
        """Вычисляет энтропию Шеннона для строки."""
        if not s:
            return 0.0
        entropy = 0.0
        length = len(s)
        occurrences = {}
        for char in s:
            occurrences[char] = occurrences.get(char, 0) + 1
            
        for count in occurrences.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def is_bot_generated(self, local_part: str) -> bool:
        """
        Использует эвристики для определения спам-ботов и авторегов.
        Например: xj83jf9_q
        """
        if len(local_part) < 5:
            return False # Слишком коротко для точного анализа
            
        # 1. Считаем энтропию
        entropy = self.shannon_entropy(local_part)
        
        # 2. Считаем долю цифр
        digits = sum(c.isdigit() for c in local_part)
        digit_ratio = digits / len(local_part)
        
        # 3. Считаем согласные подряд
        consonants = "bcdfghjklmnpqrstvwxyz"
        max_consecutive_consonants = 0
        current_consecutive = 0
        for char in local_part.lower():
            if char in consonants:
                current_consecutive += 1
                max_consecutive_consonants = max(max_consecutive_consonants, current_consecutive)
            else:
                current_consecutive = 0

        # Логика: если энтропия очень высокая (символы случайны), 
        # много цифр, или много согласных подряд (нет гласных - непроизносимо)
        if entropy > 3.8 and digit_ratio > 0.4:
            return True
        if max_consecutive_consonants >= 6:
            return True
            
        return False

    def analyze(self, email: str, enable_ml: bool = False) -> dict:
        """
        Проводит полный анализ email и возвращает результат.
        """
        if "@" not in email:
            return {"is_safe": False, "reason": "Invalid Format"}
            
        local_part, domain = email.rsplit("@", 1)
        
        if self.is_bad_tld(domain):
            return {"is_safe": False, "reason": "Dangerous TLD (.gov/.mil/.edu)"}
            
        if self.is_role_based(local_part):
            return {"is_safe": False, "reason": "Role-Based Account"}
            
        if enable_ml and self.is_bot_generated(local_part):
            return {"is_safe": False, "reason": "AI: High Entropy Bot Pattern"}
            
        return {"is_safe": True, "reason": "OK"}
