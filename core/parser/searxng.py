import requests
import random
import time
from typing import Iterator, Optional, Dict, List

class SearXNGEngine:
    def __init__(self, proxy_manager, on_log=None, use_tor=True):
        self.proxy_manager = proxy_manager
        self._safe_log = on_log
        self.use_tor = use_tor
        self.max_retries = 3
        self.instances: List[str] = []
        
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0", # Tor Browser default
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5"
        }

    def _log(self, msg: str) -> None:
        try:
            if self._safe_log:
                self._safe_log(msg)
            else:
                print(msg)
        except Exception:
            pass

    def _fetch_instances(self):
        if self.instances:
            return
        
        self._log("[SearXNG] Получение списка публичных зеркал...")
        try:
            proxy_url = None
            if self.use_tor:
                from core.tor_manager import TorManager
                proxy_url = TorManager().get_proxy_url()
            elif self.proxy_manager:
                proxy_url = self.proxy_manager.get_proxy()
                
            proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
            
            req_timeout = 45 if self.use_tor else 15
            res = requests.get("https://searx.space/data/instances.json", proxies=proxies, timeout=req_timeout)
            res.raise_for_status()
            data = res.json()
            
            valid_instances = []
            for url, info in data.get("instances", {}).items():
                # Skip .onion hidden services (can't reach them reliably from Windows)
                if ".onion" in url:
                    continue
                # Check uptime (uptimeDay >= 90%)
                uptime = info.get("uptime", {}).get("uptimeDay", 0)
                if uptime < 90:
                    continue
                # Check search speed (median < 3 seconds)
                timing = info.get("timing", {}).get("search", {}).get("all", {}).get("median")
                if timing and timing < 3.0:
                    valid_instances.append(url)
            
            if valid_instances:
                random.shuffle(valid_instances)
                self.instances = valid_instances
                self._log(f"[SearXNG] Успешно загружено {len(valid_instances)} быстрых зеркал.")
            else:
                raise ValueError("No valid instances found")
                
        except Exception as e:
            self._log(f"[SearXNG] Ошибка загрузки зеркал: {str(e)[:50]}. Использую надежные зеркала...")
            self.instances = [
                "https://priv.au",
                "https://search.mdosch.de",
                "https://etsi.me",
                "https://baresearch.org",
                "https://opnxng.com",
                "https://search.ononoki.org",
                "https://search.bus-hit.me",
                "https://search.einfachzocken.eu",
            ]

    def search_generator(self, query: str) -> Iterator[str]:
        if not query:
            return

        self._fetch_instances()
        
        page = 1
        pages_fetched = 0
        
        # Determine proxy
        proxy_url = None
        if self.use_tor:
            from core.tor_manager import TorManager
            self.tor_manager = TorManager()
            proxy_url = self.tor_manager.get_proxy_url()
        else:
            proxy_url = self.proxy_manager.get_proxy()
            
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        
        with requests.Session() as session:
            session.headers.update(self.headers)
            
            while True:
                retries = 0
                success = False
                
                # Pick a random instance for each page to distribute load
                instance = random.choice(self.instances)
                if instance.endswith('/'):
                    instance = instance[:-1]
                
                url = f"{instance}/search"
                params = {"q": query, "pageno": str(page), "language": "en-US", "format": "html"}
                
                while retries < self.max_retries:
                    try:
                        req_timeout = 45 if self.use_tor else 15
                        res = session.get(url, params=params, proxies=proxies, timeout=req_timeout)
                        
                        # SearXNG returns 429 on rate limit
                        if res.status_code == 429:
                            raise ValueError("Rate Limit 429")
                            
                        res.raise_for_status()
                        html = res.text
                        
                        if not html:
                            raise ValueError("Пустой ответ")
                            
                        # Searxng captchas
                        html_lower = html.lower()
                        if "captcha" in html_lower or "too many requests" in html_lower or "unusual traffic" in html_lower:
                            raise ValueError("Captcha or blocked")
                            
                        # If no results on this page, searxng usually has "we didn't find any results"
                        if "we didn't find any results" in html_lower or "suggestion" in html_lower:
                            if page == 1: # Maybe just a bad query, yield anyway to be safe
                                yield html
                            return # Stop pagination
                            
                        yield html
                        success = True
                        pages_fetched += 1
                        page += 1
                        break # Go to next page
                        
                    except Exception as e:
                        error_msg = str(e)
                        self._log(f"[SearXNG] Ошибка на {instance}: {error_msg[:50]}")
                        
                        # If Tor is blocked, renew IP
                        if self.use_tor and ("Captcha" in error_msg or "429" in error_msg):
                            self.tor_manager.renew_ip()
                            
                        # Pick a new instance on ANY error!
                        instance = random.choice(self.instances)
                        if instance.endswith('/'): instance = instance[:-1]
                        url = f"{instance}/search"
                            
                        retries += 1
                        time.sleep(random.uniform(1, 3))
                
                if not success:
                    self._log(f"[SearXNG] Не удалось загрузить страницу {page} после {self.max_retries} попыток.")
                    break
