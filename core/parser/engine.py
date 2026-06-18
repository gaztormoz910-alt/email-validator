import time
import random
import logging
import warnings

# Suppress deprecation warnings from the library
warnings.filterwarnings("ignore", category=UserWarning, module="duckduckgo_search")
warnings.filterwarnings("ignore", category=RuntimeWarning, module="duckduckgo_search")

try:
    from ddgs import DDGS
except ImportError:
    from duckduckgo_search import DDGS

try:
    from duckduckgo_search.exceptions import DuckDuckGoSearchException
except ImportError:
    try:
        from ddgs.exceptions import DuckDuckGoSearchException
    except ImportError:
        DuckDuckGoSearchException = Exception

class ProxyManager:
    def __init__(self, proxies, timeout=5.0):
        # Expects a list of proxy strings like 'ip:port' or 'user:pass@ip:port'
        self.proxies = [{"url": p, "dead": False, "fails": 0} for p in proxies]
        self.current_index = -1
        self.timeout = timeout

    def _normalize_url(self, url):
        if not url.startswith("socks5://") and not url.startswith("http"):
            return f"socks5://{url}"
        return url

    def get_proxy(self):
        # Round-robin selection of a live proxy
        live_proxies = [p for p in self.proxies if not p["dead"]]
        if not live_proxies:
            return None
        
        self.current_index = (self.current_index + 1) % len(live_proxies)
        proxy_info = live_proxies[self.current_index]
        return self._normalize_url(proxy_info["url"])

    def mark_fail(self, proxy_url):
        for p in self.proxies:
            if self._normalize_url(p["url"]) == proxy_url:
                p["fails"] += 1
                if p["fails"] >= 3:
                    p["dead"] = True
                break
                
    def mark_success(self, proxy_url):
        for p in self.proxies:
            if self._normalize_url(p["url"]) == proxy_url:
                p["fails"] = 0
                break
                
    def get_live_count(self):
        return sum(1 for p in self.proxies if not p["dead"])
        
    def get_total_count(self):
        return len(self.proxies)

    def check_all_proxies(self, max_workers=50, test_url="https://www.bing.com", progress_callback=None):
        """
        Проверяет все прокси асинхронно через режим HTTP (gstatic.com 204).
        """
        from core.async_proxy import run_async_checker

        raw_proxies = [p["url"] for p in self.proxies]
        
        live_list = run_async_checker(
            proxies=raw_proxies,
            workers=max_workers,
            timeout=self.timeout,
            mode="http",
            progress_callback=progress_callback
        )
        
        live_set = set(live_list)
        for p in self.proxies:
            if p["url"] in live_set:
                p["dead"] = False
                p["fails"] = 0
            else:
                p["dead"] = True

import requests
import re
import time
import random
import logging
from typing import Iterator, Optional, Dict, Any

class DuckDuckGoEngine:
    """
    Robust DuckDuckGo Scraper Engine.
    Implements infinite pagination, heavy error handling, and proxy rotation.
    """
    def __init__(self, proxy_manager: Any, max_retries: int = 15, max_results_per_dork: int = 250, on_log: Optional[Any] = None) -> None:
        self.proxy_manager = proxy_manager
        self.max_retries = max_retries
        self.max_results = max_results_per_dork
        self.on_log = on_log
        
        # Защита от дурака: убеждаемся, что on_log вызываем безопасно
        self._safe_log = on_log if callable(on_log) else (lambda x: logging.info(x))
        
        self.headers: Dict[str, str] = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Origin": "https://lite.duckduckgo.com",
            "Referer": "https://lite.duckduckgo.com/",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

    def _log(self, msg: str) -> None:
        try:
            self._safe_log(msg)
        except Exception:
            pass # Тотальная защита: падение логгера не должно ронять парсер

    def search_generator(self, query: str) -> Iterator[str]:
        """
        Генератор, который безопасно скачивает сырой HTML со всех доступных страниц поиска DuckDuckGo.
        Работает до тех пор, пока сервер сам не перестанет выдавать новые страницы.
        """
        if not query or not isinstance(query, str):
            self._log("[Система] Ошибка: Пустой или некорректный запрос.")
            return

        url: str = "https://lite.duckduckgo.com/lite/"
        data: Dict[str, str] = {"q": query, "kl": "wt-wt"}
        pages_fetched: int = 0
        
        # Создаем локальную сессию для оптимизации соединений
        with requests.Session() as session:
            session.headers.update(self.headers)
            
            while True: # Бесконечная пагинация (пока сервер отдает кнопку Next)
                retries: int = 0
                success: bool = False
                
                while retries < self.max_retries:
                    proxy_url: Optional[str] = self.proxy_manager.get_proxy()
                    
                    # Если прокси загружены, но живых не осталось - прерываем
                    if self.proxy_manager.get_total_count() > 0 and not proxy_url:
                        self._log("[Система] Все прокси мертвы. Остановка парсинга.")
                        return 
                        
                    proxies: Optional[Dict[str, str]] = {"http": proxy_url, "https": proxy_url} if proxy_url else None
                    timeout: float = float(getattr(self.proxy_manager, 'timeout', 15.0))
                    
                    try:
                        res = session.post(url, data=data, proxies=proxies, timeout=timeout)
                        res.raise_for_status() # Бросает исключение на 4xx и 5xx статусы
                        
                        html: str = res.text
                        if not html or not isinstance(html, str):
                            raise ValueError("Получен пустой ответ от сервера.")
                            
                        # Проверка на статус 202 (DuckDuckGo отдает его при капче)
                        if res.status_code == 202:
                            raise ValueError("DuckDuckGo выдал капчу (HTTP 202).")
                            
                        # Проверка на заглушки, блокировки и капчи от DuckDuckGo
                        html_lower = html.lower()
                        if "connected over tor" in html_lower or "tor exit node" in html_lower:
                            raise ValueError("DuckDuckGo заблокировал этот IP (Tor Exit Node).")
                        if "bots use duckduckgo too" in html_lower or "challenge-form" in html_lower:
                            raise ValueError("DuckDuckGo требует пройти капчу (Bot Detection).")
                        if "duckduckgo" not in html_lower and "results" not in html_lower:
                            raise ValueError("Заглушка или нетипичный ответ от сервера.")
                        
                        # Отдаем фулл HTML-код в главный цикл
                        yield html
                        
                        if proxy_url:
                            self.proxy_manager.mark_success(proxy_url)
                        
                        success = True
                        pages_fetched += 1
                        
                        # Парсинг параметров для следующей страницы
                        s_match = re.search(r'name="s"\s+value="(\d+)"', html)
                        vqd_match = re.search(r'name="vqd"\s+value="([^"]+)"', html)
                        v_match = re.search(r'name="v"\s+value="([^"]+)"', html)
                        
                        if s_match:
                            data = {
                                "q": query,
                                "s": str(s_match.group(1)),
                                "nextParams": "",
                                "v": str(v_match.group(1)) if v_match else "l",
                                "vqd": str(vqd_match.group(1)) if vqd_match else ""
                            }
                            break # Выходим из цикла попыток, идем на следующую страницу
                        else:
                            return # Кнопки "Next" нет, данные по Dork-у закончились
                            
                    except requests.exceptions.ProxyError:
                        self._log(f"[Прокси] {proxy_url} - Ошибка SOCKS/HTTP, пробую другой...")
                        if proxy_url: self.proxy_manager.mark_fail(proxy_url)
                    except requests.exceptions.Timeout:
                        self._log(f"[Прокси] {proxy_url} - Таймаут соединения, пробую другой...")
                        if proxy_url: self.proxy_manager.mark_fail(proxy_url)
                    except Exception as e:
                        error_msg = str(e)
                        short_proxy = proxy_url.split("//")[-1] if proxy_url else "direct"
                        self._log(f"[Прокси] {short_proxy} - Сбой: {error_msg[:80]}")
                        if proxy_url: self.proxy_manager.mark_fail(proxy_url)
                    finally:
                        retries += 1
                        time.sleep(random.uniform(0.5, 1.5))
                
                # Если после N попыток мы так и не скачали страницу - прерываем этот Dork
                if not success:
                    self._log(f"[Система] Не удалось загрузить страницу {pages_fetched + 1} после {self.max_retries} попыток.")
                    break

if __name__ == "__main__":
    class DummyProxyManager:
        def get_proxy(self): return None
        def mark_dead(self, url): print(f"Proxy died: {url}")
        def mark_success(self, url): print(f"Proxy success: {url}")
        def get_total_count(self): return 0
        
    engine = DuckDuckGoEngine(DummyProxyManager(), on_log=print)
    print("Searching...")
    count = 0
    for snippet in engine.search_generator("site:linkedin.com \"@gmail.com\" \"CEO\""):
        count += 1
        print(f"[{count}] {snippet[:120]}")
        if count >= 5:
            break
