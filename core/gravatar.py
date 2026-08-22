# core/gravatar.py
"""
Проверка наличия Gravatar-аватарки для email.
Бесплатный API без ключа. Если аватарка есть — это сильный сигнал реального пользователя.
Если нет — ничего не значит (нейтральный результат).
"""

import hashlib
import urllib.request
import urllib.error
import threading
from collections import OrderedDict


class GravatarChecker:
    """Потокобезопасный чекер Gravatar с кэшированием."""
    
    def __init__(self, timeout=3, proxy_provider=None):
        self.timeout = timeout
        # Даёт прокси на каждый запрос. Без него MD5 всей базы уезжает на
        # gravatar.com с реального IP, и он же блокирует за объём.
        self.proxy_provider = proxy_provider
        self._cache = OrderedDict()
        self._cache_lock = threading.Lock()
    
    def has_gravatar(self, email: str) -> bool:
        """
        Проверяет наличие Gravatar-аватарки для email.
        
        Возвращает:
          True  — аватарка существует (сильный сигнал реального человека)
          False — аватарки нет (нейтрально, НЕ значит что почта мёртвая)
        """
        email = email.strip().lower()
        
        if '@' in email:
            local, domain = email.split('@', 1)
            if '+' in local:
                local = local.split('+', 1)[0]
            email = f"{local}@{domain}"
        
        # Проверяем кэш
        with self._cache_lock:
            if email in self._cache:
                self._cache.move_to_end(email)  # LRU: помечаем как недавно использованный
                return self._cache[email]
        
        try:
            # MD5-хэш email (стандарт Gravatar API)
            email_hash = hashlib.md5(email.encode('utf-8')).hexdigest()
            
            # d=404 означает: если аватарки нет — вернуть HTTP 404 (а не дефолтную картинку)
            # s=1 — запрашиваем самый маленький размер (1x1 пиксель) чтобы минимизировать трафик
            url = f"https://gravatar.com/avatar/{email_hash}?d=404&s=1"
            
            proxies = self.proxy_provider() if self.proxy_provider else None
            if proxies:
                import requests
                resp = requests.head(url, timeout=self.timeout, proxies=proxies,
                                     headers={'User-Agent': 'Mozilla/5.0'},
                                     allow_redirects=False)
                result = resp.status_code == 200
            else:
                req = urllib.request.Request(url, method='HEAD')  # HEAD — только статус
                req.add_header('User-Agent', 'Mozilla/5.0')
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    result = response.status == 200

        except urllib.error.HTTPError:
            # 404 = аватарки нет (нейтрально)
            result = False
        except Exception:
            # Таймаут, нет интернета и т.д. — считаем нейтрально
            result = False
        
        # Сохраняем в кэш
        with self._cache_lock:
            if len(self._cache) >= 50000:
                self._cache.popitem(last=False)
            self._cache[email] = result
        
        return result
