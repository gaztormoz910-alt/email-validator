import time
import random
import logging
import warnings

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


def _get_verified(session, url, *, proxies, timeout, headers, allow_redirects=True):
    try:
        return session.get(url, proxies=proxies, timeout=timeout, headers=headers,
                           allow_redirects=allow_redirects, verify=True)
    except requests.exceptions.SSLError:
        return session.get(url, proxies=proxies, timeout=timeout, headers=headers,
                           allow_redirects=allow_redirects, verify=False)


class ProxyManager:
    def __init__(self, proxies, timeout=5.0):
        self.proxies = [{"url": p, "dead": False, "fails": 0} for p in proxies]
        self.current_index = -1
        self.timeout = timeout

    def _normalize_url(self, url):
        if not url.startswith("socks5://") and not url.startswith("http"):
            return f"socks5://{url}"
        return url

    def get_proxy(self):
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
                if p["fails"] >= 10:
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

    def check_all_proxies(self, max_workers=50, test_url="https://www.bing.com", progress_callback=None,
                          should_stop=None):
        from core.async_proxy import run_async_checker

        raw_proxies = [p["url"] for p in self.proxies]
        
        live_list = run_async_checker(
            proxies=raw_proxies,
            workers=max_workers,
            timeout=self.timeout,
            mode="http",
            progress_callback=progress_callback,
            should_stop=should_stop,
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
import urllib3
from typing import Iterator, Optional, Dict, Any, List

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
]

class DuckDuckGoEngine:
    def __init__(self, proxy_manager: Any, max_retries: int = 50, max_results_per_dork: int = 500, on_log: Optional[Any] = None, is_stopped: Optional[Any] = None) -> None:
        self.proxy_manager = proxy_manager
        self.max_retries = max_retries
        self._is_stopped = is_stopped or (lambda: False)
        self.max_results = max_results_per_dork
        self.on_log = on_log
        
        self._safe_log = on_log if callable(on_log) else (lambda x: logging.info(x))
        
        self.headers: Dict[str, str] = {
            "User-Agent": random.choice(USER_AGENTS),
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
            pass

    def _extract_result_urls(self, html: str) -> List[str]:
        urls = []
        
        uddg_matches = re.findall(r'uddg=(https?[^&"]+)', html)
        for match in uddg_matches:
            try:
                from urllib.parse import unquote
                decoded = unquote(match)
                if decoded and 'duckduckgo.com' not in decoded.lower():
                    urls.append(decoded)
            except Exception:
                pass
        
        direct_matches = re.findall(r'<a[^>]+rel="nofollow"[^>]+href="(https?://[^"]+)"', html)
        for match in direct_matches:
            if 'duckduckgo.com' not in match.lower():
                urls.append(match)
        
        snippet_urls = re.findall(r'<span class="link-text">(https?://[^<]+)</span>', html)
        urls.extend(snippet_urls)
        
        seen = set()
        unique = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)
        return unique

    def _scrape_target_url(self, session: requests.Session, target_url: str, proxies: Optional[Dict]) -> Optional[str]:
        skip_domains = [
            'youtube.com', 'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
            'tiktok.com', 'reddit.com', 'wikipedia.org', 'amazon.com', 'ebay.com',
            'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'pinterest.com',
            'apple.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
        ]
        url_lower = target_url.lower()
        for skip in skip_domains:
            if skip in url_lower:
                return None
        
        skip_ext = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.mp4', '.mp3', '.png', '.jpg', '.gif']
        for ext in skip_ext:
            if url_lower.endswith(ext):
                return None
        
        try:
            scrape_headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            res = _get_verified(session, target_url, proxies=proxies, timeout=12,
                                headers=scrape_headers)
            
            content_type = res.headers.get('Content-Type', '')
            if 'text' not in content_type and 'html' not in content_type:
                return None
            
            if res.status_code == 200:
                return res.text[:80000]
            return None
        except Exception:
            return None

    def search_generator(self, query: str) -> Iterator[str]:
        if not query or not isinstance(query, str):
            self._log("[Система] Ошибка: Пустой или некорректный запрос.")
            return

        max_pages = self.max_results // 10
        if max_pages < 1: max_pages = 1

        url: str = "https://lite.duckduckgo.com/lite/"
        data: Dict[str, str] = {"q": query, "kl": "wt-wt"}
        pages_fetched: int = 0
        
        with requests.Session() as session:
            session.headers.update(self.headers)
            
            while True:
                retries: int = 0
                captcha_rotations: int = 0
                success: bool = False
                
                while retries < self.max_retries:
                    if self._is_stopped():
                        return
                    proxy_url: Optional[str] = self.proxy_manager.get_proxy()
                    
                    if self.proxy_manager.get_total_count() > 0 and not proxy_url:
                        self._log("[Система] Все прокси мертвы. Остановка парсинга.")
                        return 
                        
                    proxies: Optional[Dict[str, str]] = {"http": proxy_url, "https": proxy_url} if proxy_url else None
                    timeout: float = float(getattr(self.proxy_manager, 'timeout', 15.0))
                    
                    if retries % 5 == 0:
                        session.headers["User-Agent"] = random.choice(USER_AGENTS)
                    
                    try:
                        res = session.post(url, data=data, proxies=proxies, timeout=timeout)
                        
                        if res.status_code == 202:
                            captcha_rotations += 1
                            if captcha_rotations % 10 == 0:
                                self._log(f"[DDG] Капча: {captcha_rotations} ротаций, продолжаю...")
                            time.sleep(random.uniform(0.3, 1.0))
                            continue
                        
                        res.raise_for_status()
                        
                        html: str = res.text
                        if not html or not isinstance(html, str):
                            raise ValueError("Получен пустой ответ от сервера.")
                            
                        html_lower = html.lower()
                        if "connected over tor" in html_lower or "tor exit node" in html_lower:
                            captcha_rotations += 1
                            time.sleep(random.uniform(0.3, 1.0))
                            continue
                        if "bots use duckduckgo too" in html_lower or "challenge-form" in html_lower:
                            captcha_rotations += 1
                            time.sleep(random.uniform(0.3, 1.0))
                            continue
                        if "duckduckgo" not in html_lower and "results" not in html_lower:
                            raise ValueError("Заглушка или нетипичный ответ от сервера.")
                        
                        yield html
                        
                        if proxy_url:
                            self.proxy_manager.mark_success(proxy_url)
                        
                        target_urls = self._extract_result_urls(html)
                        if target_urls:
                            self._log(f"[DDG] Стр.{pages_fetched + 1}: {len(target_urls)} ссылок → скрапинг целевых сайтов...")
                            scraped_count = 0
                            for target in target_urls:
                                if self._is_stopped():
                                    return
                                page_content = self._scrape_target_url(session, target, proxies)
                                if page_content:
                                    scraped_count += 1
                                    yield page_content
                            if scraped_count > 0:
                                self._log(f"[DDG] Стр.{pages_fetched + 1}: успешно скрапнуто {scraped_count}/{len(target_urls)} сайтов")
                        
                        success = True
                        pages_fetched += 1
                        
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
                            break
                        else:
                            return
                            
                    except requests.exceptions.ProxyError:
                        if proxy_url: self.proxy_manager.mark_fail(proxy_url)
                    except requests.exceptions.Timeout:
                        if proxy_url: self.proxy_manager.mark_fail(proxy_url)
                    except Exception as e:
                        error_msg = str(e)
                        short_proxy = proxy_url.split("//")[-1] if proxy_url else "direct"
                        if retries % 50 == 0 and pages_fetched == 0 and getattr(self, '_debug_proxy', False):
                            self._log(f"[Прокси] {short_proxy} - Сбой: {error_msg[:80]}")
                        if proxy_url: self.proxy_manager.mark_fail(proxy_url)
                    finally:
                        retries += 1
                        time.sleep(random.uniform(0.3, 1.0))
                
                if not success:
                    self._log(f"[Система] Не удалось загрузить страницу {pages_fetched + 1} после {self.max_retries} попыток (+ {captcha_rotations} ротаций капчи).")
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

class AOLEngine:
    def __init__(self, proxy_manager: Any, max_retries: int = 15, max_results_per_dork: int = 500, on_log: Optional[Any] = None, is_stopped: Optional[Any] = None) -> None:
        self.proxy_manager = proxy_manager
        self.max_retries = max_retries
        self.max_results = max_results_per_dork
        self.on_log = on_log
        self._safe_log = on_log if callable(on_log) else (lambda x: logging.info(x))
        self._is_stopped = is_stopped or (lambda: False)
        
        self.headers: Dict[str, str] = {
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

    def _log(self, msg: str) -> None:
        try:
            self._safe_log(msg)
        except Exception:
            pass

    def _extract_result_urls(self, html: str) -> List[str]:
        urls = []
        import re
        direct_matches = re.findall(r'<a[^>]+href="(https?://[^"]+)"', html)
        for match in direct_matches:
            if 'yahoo.com' not in match.lower() and 'aol.com' not in match.lower():
                urls.append(match)
        
        seen = set()
        unique = []
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)
        return unique

    def _scrape_target_url(self, session: requests.Session, target_url: str, proxies: Optional[Dict]) -> Optional[str]:
        skip_domains = [
            'youtube.com', 'twitter.com', 'x.com', 'facebook.com', 'instagram.com',
            'tiktok.com', 'reddit.com', 'wikipedia.org', 'amazon.com', 'ebay.com',
            'google.com', 'bing.com', 'yahoo.com', 'duckduckgo.com', 'pinterest.com',
            'apple.com', 'microsoft.com', 'github.com', 'stackoverflow.com', 'aol.com',
            'linkedin.com', 'glassdoor.com', 'medium.com', 'yelp.com', 'tripadvisor.com',
            'quora.com', 'netflix.com'
        ]
        url_lower = target_url.lower()
        for skip in skip_domains:
            if skip in url_lower: return None
            
        skip_ext = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip', '.rar', '.mp4', '.mp3', '.png', '.jpg', '.gif']
        for ext in skip_ext:
            if url_lower.endswith(ext): return None
            
        try:
            scrape_headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            res = _get_verified(session, target_url, proxies=proxies, timeout=5.0,
                                headers=scrape_headers)
            content_type = res.headers.get('Content-Type', '')
            if 'text' not in content_type and 'html' not in content_type: return None
            if res.status_code == 200: return res.text[:80000]
            return None
        except Exception: return None

    def _build_url(self, query: str, offset: int) -> str:
        import urllib.parse
        return f"https://search.yahoo.com/yhs/search?hspart=aol&hsimp=yhs-aol_catchall&p={urllib.parse.quote_plus(query)}&b={offset}"

    def search_generator(self, query: str) -> Iterator[str]:
        if not query or not isinstance(query, str):
            self._log("[Система] Ошибка: Пустой или некорректный запрос.")
            return

        pages_fetched: int = 0
        b_offset: int = 1
        
        with requests.Session() as session:
            session.headers.update(self.headers)
            
            while True:
                if self._is_stopped():
                    return
                    
                retries: int = 0
                success: bool = False
                
                url = self._build_url(query, b_offset)
                
                while retries < self.max_retries:
                    if self._is_stopped():
                        return
                        
                    proxy_url: Optional[str] = self.proxy_manager.get_proxy()
                    
                    if not proxy_url:
                        return
                        
                    proxies: Optional[Dict[str, str]] = {"http": proxy_url, "https": proxy_url}
                    timeout: float = float(getattr(self.proxy_manager, 'timeout', 15.0))
                    
                    if retries % 5 == 0:
                        session.headers["User-Agent"] = random.choice(USER_AGENTS)
                    
                    try:
                        res = session.get(url, proxies=proxies, timeout=timeout)
                        
                        if res.status_code != 200:
                            retries += 1
                            time.sleep(0.5)
                            continue
                        
                        html: str = res.text
                        html_lower = html.lower()
                        
                        if "captcha" in html_lower or ("robot" in html_lower and "are you a" in html_lower) or "pardon our interruption" in html_lower or "verify you are a human" in html_lower:
                            self.proxy_manager.mark_fail(proxy_url)
                            retries += 1
                            time.sleep(1.0)
                            continue

                        
                        if "we did not find results for" in html_lower or "no results found" in html_lower or "no matching documents" in html_lower:
                            return
                        
                        if len(html) < 500:
                            retries += 1
                            time.sleep(0.5)
                            continue
                            
                        yield html
                        
                        self.proxy_manager.mark_success(proxy_url)
                            
                        target_urls = self._extract_result_urls(html)
                        if target_urls:
                            scraped_count = 0
                            for target in target_urls[:10]:
                                if self._is_stopped():
                                    return
                                page_content = self._scrape_target_url(session, target, proxies)
                                if page_content:
                                    scraped_count += 1
                                    yield page_content
                        
                        success = True
                        pages_fetched += 1
                        
                        next_b_match = re.search(r'<a[^>]+class=["\'][^"\']*next[^"\']*["\'][^>]*href=["\'][^"\']*b=(\d+)[^"\']*["\']', html, re.IGNORECASE)
                        
                        if next_b_match:
                            b_offset = int(next_b_match.group(1))
                            if b_offset > 1000:
                                return
                            break
                        else:
                            next_offset_str = f"b={b_offset + 10}"
                            if ('next' in html_lower and 'href' in html_lower) or next_offset_str in html or 'pagination' in html_lower:
                                b_offset += 10
                                if b_offset > 1000:
                                    return
                                break
                            else:
                                return
                    except requests.exceptions.Timeout:
                        self.proxy_manager.mark_fail(proxy_url)
                        time.sleep(0.3)
                    except requests.exceptions.ProxyError:
                        self.proxy_manager.mark_fail(proxy_url)
                        time.sleep(0.3)
                    except requests.exceptions.ConnectionError:
                        time.sleep(0.3)
                    except Exception as e:
                        error_msg = str(e)
                        if "10053" not in error_msg and "connection aborted" not in error_msg.lower():
                            if retries == self.max_retries - 1:
                                self._log(f"[Система] Сбой: {error_msg[:80]}")
                    finally:
                        retries += 1
                
                if not success:
                    break

class YahooEngine(AOLEngine):
    def _build_url(self, query: str, offset: int) -> str:
        import urllib.parse
        return f"https://search.yahoo.com/search?p={urllib.parse.quote_plus(query)}&b={offset}"
