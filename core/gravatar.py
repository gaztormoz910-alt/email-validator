import hashlib
import urllib.request
import urllib.error
import threading
from collections import OrderedDict


class GravatarChecker:
    
    def __init__(self, timeout=3, proxy_provider=None):
        self.timeout = timeout
        self.proxy_provider = proxy_provider
        self._cache = OrderedDict()
        self._cache_lock = threading.Lock()
    
    def has_gravatar(self, email: str) -> bool:
        if not isinstance(email, str):
            return False
        email = email.strip().lower()
        
        if '@' in email:
            local, domain = email.split('@', 1)
            if '+' in local:
                local = local.split('+', 1)[0]
            email = f"{local}@{domain}"
        
        with self._cache_lock:
            if email in self._cache:
                self._cache.move_to_end(email)
                return self._cache[email]
        
        try:
            email_hash = hashlib.md5(email.encode('utf-8')).hexdigest()
            
            url = f"https://gravatar.com/avatar/{email_hash}?d=404&s=1"
            
            proxies = self.proxy_provider() if self.proxy_provider else None
            if proxies:
                import requests
                resp = requests.head(url, timeout=self.timeout, proxies=proxies,
                                     headers={'User-Agent': 'Mozilla/5.0'},
                                     allow_redirects=False)
                result = resp.status_code == 200
            else:
                req = urllib.request.Request(url, method='HEAD')
                req.add_header('User-Agent', 'Mozilla/5.0')
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    result = response.status == 200

        except urllib.error.HTTPError:
            result = False
        except Exception:
            result = False
        
        with self._cache_lock:
            if len(self._cache) >= 50000:
                self._cache.popitem(last=False)
            self._cache[email] = result
        
        return result
