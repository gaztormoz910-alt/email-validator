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
    def __init__(self, proxies):
        # Expects a list of proxy strings like 'ip:port' or 'user:pass@ip:port'
        self.proxies = [{"url": p, "dead": False, "fails": 0} for p in proxies]
        self.current_index = -1

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

    def mark_dead(self, proxy_url):
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

    def check_all_proxies(self, test_url="https://www.bing.com", progress_callback=None):
        """
        Pings all proxies against the REAL endpoint (bing.com) that the DDG library uses.
        Uses ThreadPoolExecutor to check concurrently.
        """
        import concurrent.futures
        import requests
        import threading

        total = len(self.proxies)
        checked_count = 0
        live_count = 0
        lock = threading.Lock()

        def check_proxy(p):
            nonlocal checked_count, live_count
            url = self._normalize_url(p["url"])
            try:
                resp = requests.get(test_url, proxies={"http": url, "https": url}, timeout=7)
                if resp.status_code == 200:
                    p["dead"] = False
                    p["fails"] = 0
                    with lock:
                        live_count += 1
                else:
                    p["dead"] = True
            except Exception:
                p["dead"] = True
                
            with lock:
                checked_count += 1
                if progress_callback:
                    progress_callback(checked_count, total, live_count)

        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            executor.map(check_proxy, self.proxies)

class DuckDuckGoEngine:
    def __init__(self, proxy_manager, max_retries=15, max_results_per_dork=250, on_log=None):
        self.proxy_manager = proxy_manager
        self.max_retries = max_retries
        self.max_results = max_results_per_dork
        self.on_log = on_log

    def _log(self, msg):
        if self.on_log:
            self.on_log(msg)

    def _single_search(self, query, proxy_url):
        """Execute a single search attempt on a given proxy. Returns list of combined text results."""
        ddgs = DDGS(proxy=proxy_url, timeout=25)
        results = ddgs.text(query, max_results=self.max_results)
        
        out = []
        for r in results:
            title = r.get("title", "")
            body = r.get("body", "")
            href = r.get("href", "")
            combined = f"{title} {body} {href}"
            if combined.strip():
                out.append(combined)
        return out

    def search_generator(self, query):
        """
        Executes search for a single query.
        """
        for snippet in self._search_with_retries(query):
            yield snippet

    def _search_with_retries(self, query):
        """Single query execution with proxy retry logic."""
        retries = 0
        while retries < self.max_retries:
            proxy_url = self.proxy_manager.get_proxy()
            if self.proxy_manager.get_total_count() > 0 and proxy_url is None:
                break

            try:
                results = self._single_search(query, proxy_url)
                self.proxy_manager.mark_success(proxy_url)
                return results
                    
            except Exception as e:
                error_msg = str(e)
                short_proxy = proxy_url.split("//")[-1] if proxy_url else "direct"
                
                if "ConnectError" in error_msg or "SOCKS" in error_msg:
                    self._log(f"[Прокси] {short_proxy} — Ошибка подключения, пробую другой...")
                elif "TimeoutError" in error_msg or "timed out" in error_msg:
                    self._log(f"[Прокси] {short_proxy} — Таймаут, пробую другой...")
                elif "RatelimitE" in error_msg or "202" in error_msg:
                    self._log(f"[Прокси] {short_proxy} — Рейт-лимит! Ждём и меняем прокси...")
                    time.sleep(random.uniform(3.0, 6.0))
                else:
                    self._log(f"[Прокси] {short_proxy} — {error_msg[:80]}")
                
                self.proxy_manager.mark_dead(proxy_url)
                retries += 1
                time.sleep(random.uniform(0.5, 2.0))
        
        return []  # All retries exhausted

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
