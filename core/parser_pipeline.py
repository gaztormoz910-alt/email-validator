import threading
import queue
import time
import logging
from typing import Callable
from .parser.engine import ProxyManager, DuckDuckGoEngine, AOLEngine, YahooEngine
from .parser.extractor import EmailExtractor
from .parser.name_extractor import NameExtractor
from .parser.ml_predictor import MLPredictor

GLOBAL_VERIFIED_DOMAINS = {
    # USA / Global
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "mac.com", "me.com", "comcast.net", "sbcglobal.net", "att.net", "verizon.net", "cox.net", "charter.net",
    # Canada
    "yahoo.ca", "hotmail.ca", "bell.net", "sympatico.ca", "rogers.com", "shaw.ca", "telus.net", "videotron.ca", "cogeco.ca",
    # Australia
    "yahoo.com.au", "hotmail.com.au", "outlook.com.au", "live.com.au", "bigpond.com", "bigpond.net.au", "optusnet.com.au", "iinet.net.au", "tpg.com.au",
    # Netherlands
    "hotmail.nl", "live.nl", "ziggo.nl", "kpnmail.nl", "planet.nl", "hetnet.nl", "upcmail.nl", "chello.nl", "xs4all.nl",
    # UK
    "hotmail.co.uk", "yahoo.co.uk", "live.co.uk", "btinternet.com", "sky.com", "virginmedia.com", "talktalk.net", "blueyonder.co.uk", "ntlworld.com",
    # Germany
    "gmx.de", "gmx.net", "web.de", "t-online.de", "freenet.de", "googlemail.com", "hotmail.de", "yahoo.de", "outlook.de",
    # France
    "orange.fr", "free.fr", "sfr.fr", "laposte.net", "wanadoo.fr", "yahoo.fr", "hotmail.fr",
    # Italy
    "libero.it", "virgilio.it", "tim.it", "alice.it", "tiscali.it", "yahoo.it", "hotmail.it",
    # Spain
    "yahoo.es", "hotmail.es", "telefonica.net",
    # Poland
    "wp.pl", "onet.pl", "o2.pl", "interia.pl", "gazeta.pl"
}


class ParserPipeline(threading.Thread):
    def __init__(self, dork_sources, proxies, max_threads, timeout=5.0,
                 on_log=None, on_progress=None, on_stats_update=None, on_result_found=None, on_complete=None, engine_name="DuckDuckGo Lite", enable_osint=False):
        super().__init__()
        self.dork_sources = dork_sources
        self.proxies = proxies
        self.max_threads = max_threads
        self.timeout = timeout
        self.engine_name = engine_name
        
        self.on_log = on_log
        self.on_progress = on_progress
        self.on_stats_update = on_stats_update
        self.on_result_found = on_result_found
        self.on_complete = on_complete
        
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        
        self.proxy_manager = ProxyManager(self.proxies, timeout=self.timeout)
        self.enable_osint = enable_osint
        self.extractor = EmailExtractor()
        self.name_extractor = None
        self.ml_predictor = None
        self.dork_queue = queue.Queue(maxsize=1000)
        
        self.total_dorks = 0
        self.processed_dorks = 0
        self.processed_pages = 0
        self.processed_snippets = 0
        self.total_emails = 0
        
        self.stats_lock = threading.Lock()
        self.seen_lock = threading.Lock()
        self.global_seen_emails = set()
        
        self.feeder_thread = threading.Thread(target=self._feed_dorks, daemon=True)
        
    def _feed_dorks(self):
        from core.streamer import StreamLoader
        for i, d in enumerate(StreamLoader(self.dork_sources).stream_lines(), 1):
            if self._stop_event.is_set():
                break
            # block until space in queue
            self.dork_queue.put((i, d.strip(), d))
        
        # sentinel workers
        for _ in range(self.max_threads * 2):
            self.dork_queue.put(None)
    def _update_stats(self, dork_done=False, page=0, snippet=0, emails=0):
        with self.stats_lock:
            if dork_done:
                self.processed_dorks += 1
            self.processed_pages += page
            self.processed_snippets += snippet
            self.total_emails += emails
            
            # Snapshots for callbacks to avoid holding lock during I/O
            snap_tot = self.total_dorks
            snap_done = self.processed_dorks
            snap_pages = self.processed_pages
            snap_snip = self.processed_snippets
            snap_em = self.total_emails

        if self.on_stats_update:
            self.on_stats_update(
                snap_tot,
                snap_done,
                snap_pages,
                snap_snip,
                snap_em
            )
        if self.on_progress:
            pct = int((snap_done / max(1, snap_tot)) * 100)
            self.on_progress(snap_done, snap_tot, pct)

    def log(self, msg):
        if self.on_log:
            self.on_log(msg)

    def stop(self):
        self._stop_event.set()

    def pause(self):
        self._pause_event.set()

    def resume(self):
        self._pause_event.clear()

    def run(self):
        self.ml_predictor = MLPredictor()
        if self.name_extractor is None:
            self.name_extractor = NameExtractor(enable_osint=self.enable_osint)
        
        from core.streamer import StreamLoader
        self.log("[Система] Подсчёт количества дорков...")
        self.total_dorks = StreamLoader(self.dork_sources).count_total_lines()
        
        self.log(f"[Система] Инициализация парсера. Поисковик: {self.engine_name}. Загружено дорков: {self.total_dorks}")
        
        tor_engines = ["AOL (Tor)", "Yahoo (Tor)"]
        use_tor = self.engine_name in tor_engines
        
        if use_tor:
            from core.tor_manager import TorManager
            self.tor_manager = TorManager(log_callback=self.log)
            
            # 1 Tor instance per 50 threads, max 10 instances
            import math
            num_tor_instances = max(1, min(10, math.ceil(self.max_threads / 50)))
            
            if not self.tor_manager.start(num_instances=num_tor_instances):
                self.log("[Ошибка] Не удалось запустить Tor. Парсинг невозможен.")
                if self.on_complete:
                    self.on_complete(aborted=True)
                return
        else:
            # 1. Ping proxies
            if self.proxies:
                self.log(f"[Система] Проверка работоспособности SOCKS5 прокси ({len(self.proxies)} шт.)...")
                
                def _proxy_progress(checked, total, live):
                    if self.on_progress:
                        pct = int((checked / total) * 100) if total > 0 else 0
                        self.on_progress(checked, total, pct, label="Проверка прокси")
                    if checked % max(1, (total // 10)) == 0 or checked == total:
                        self.log(f"[Система] Проверка прокси: {checked}/{total} (Живых: {live})")
                        
                self.proxy_manager.check_all_proxies(max_workers=self.max_threads, progress_callback=_proxy_progress)
                
                live = self.proxy_manager.get_live_count()
                self.log(f"[Система] Рабочих прокси: {live} из {len(self.proxies)}")
                if live == 0:
                    self.log("[Ошибка] Нет ни одного рабочего прокси! Парсинг невозможен.")
                    if self.on_complete:
                        self.on_complete(aborted=True)
                    return
            else:
                self.log("[Предупреждение] Прокси не загружены. Парсинг пойдет через прямой IP!")

        # Initialize UI stats to 0
        self._update_stats()

        # 2. Worker thread logic
        def worker():
            if self.engine_name in ["AOL (Tor)", "Yahoo (Tor)"]:
                class TorProxyManagerWrapper:
                    def __init__(wrapper_self, tm, configured_timeout):
                        wrapper_self.tm = tm
                        # Cap timeout at 20s for Tor — waiting 300s per request kills performance
                        wrapper_self.timeout = min(float(configured_timeout), 20.0)
                        wrapper_self._last_renew = 0
                        wrapper_self._renew_lock = threading.Lock()
                    def get_total_count(wrapper_self):
                        return max(1, wrapper_self.tm.get_alive_count())
                    def get_proxy(wrapper_self):
                        url = wrapper_self.tm.get_proxy_url()
                        if url is None:
                            return None  # All Tor instances dead
                        return url
                    def mark_fail(wrapper_self, url):
                        # Rate-limit: don't hammer renew_ip from every thread
                        now = time.time()
                        if now - wrapper_self._last_renew < 5.0:
                            return  # Someone already renewed recently, skip
                        with wrapper_self._renew_lock:
                            if now - wrapper_self._last_renew < 5.0:
                                return
                            wrapper_self.tm.renew_ip(proxy_url=url)
                            wrapper_self._last_renew = time.time()
                    def mark_success(wrapper_self, url): pass
                if self.engine_name == "AOL (Tor)":
                    engine = AOLEngine(TorProxyManagerWrapper(self.tor_manager, self.timeout), on_log=self.log, is_stopped=lambda: self._stop_event.is_set())
                elif self.engine_name == "Yahoo (Tor)":
                    engine = YahooEngine(TorProxyManagerWrapper(self.tor_manager, self.timeout), on_log=self.log, is_stopped=lambda: self._stop_event.is_set())
            elif self.engine_name == "AOL (Proxies)":
                engine = AOLEngine(self.proxy_manager, on_log=self.log, is_stopped=lambda: self._stop_event.is_set())
            elif self.engine_name == "Yahoo (Proxies)":
                engine = YahooEngine(self.proxy_manager, on_log=self.log, is_stopped=lambda: self._stop_event.is_set())
            else:
                engine = DuckDuckGoEngine(self.proxy_manager, on_log=self.log)
                
            while not self._stop_event.is_set():
                while self._pause_event.is_set() and not self._stop_event.is_set():
                    time.sleep(0.5)
                    
                try:
                    dork_idx, sub_query, base_dork = self.dork_queue.get_nowait()
                except queue.Empty:
                    break # queue is empty, worker can exit
                self.log(f"[DORK {dork_idx}/{self.total_dorks}] Sub-query: {sub_query}")
                
                # Extract domain filter from dork (e.g. "@gmail.com" -> "gmail.com")
                import re as _re
                domain_filter = None
                domain_match = _re.search(r'["\']?@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?', sub_query)
                if domain_match:
                    domain_filter = domain_match.group(1).lower()
                
                pages_found = 0
                emails_from_dork = 0
                
                try:
                    # search_generator yields snippets directly
                    for snippet in engine.search_generator(sub_query):
                        if self._stop_event.is_set():
                            break
                        while self._pause_event.is_set():
                            time.sleep(0.5)
                            
                        # Increment snippet/page stats
                        pages_found += 0.1
                        if pages_found >= 1.0:
                            self._update_stats(page=1)
                            pages_found -= 1.0
                            
                        self._update_stats(snippet=1)
                        
                        emails = self.extractor.extract(snippet)
                        
                        # Filter emails by domain from dork query OR global verified list
                        if emails:
                            valid_emails = set()
                            for e in emails:
                                try:
                                    e_domain = e.split('@')[-1].lower()
                                    # Allow if it matches the specific dork domain, OR if it's in our global verified list
                                    if (domain_filter and e_domain == domain_filter) or e_domain in GLOBAL_VERIFIED_DOMAINS:
                                        valid_emails.add(e)
                                    # If no specific domain was requested in dork, keep all emails (original behavior)
                                    elif not domain_filter:
                                        valid_emails.add(e)
                                except Exception:
                                    pass
                            emails = valid_emails
                        
                        if emails:
                            new_unique_emails = []
                            with self.seen_lock:
                                for e in emails:
                                    if e not in self.global_seen_emails:
                                        self.global_seen_emails.add(e)
                                        new_unique_emails.append(e)
                                        
                            new_emails_count = len(new_unique_emails)
                            if new_emails_count > 0:
                                emails_from_dork += new_emails_count
                                self._update_stats(emails=new_emails_count)
                                
                                self.log(f"[DORK {dork_idx}/{self.total_dorks}] Страница: {max(1, int(pages_found*10))}, Найдено уникальных почт: {new_emails_count}")
                                
                                if self.on_result_found:
                                    for e in new_unique_emails:
                                        self.on_result_found(e, base_dork)
                                    
                except Exception as e:
                    self.log(f"[Ошибка DORK {dork_idx}] {str(e)}")
                    
                self._update_stats(dork_done=True)
                self.log(f"[РЕЗУЛЬТАТ] Sub-query '{sub_query}' завершен. Найдено почт: {emails_from_dork}")
                self.dork_queue.task_done()

        # 3. Spawn workers
        self.feeder_thread.start()
        threads = []
        safe_max_threads = min(self.max_threads, 500)
        
        # For Tor mode: limit threads to 5 per alive Tor instance (Tor SOCKS can't handle more)
        if use_tor:
            alive_count = self.tor_manager.get_alive_count()
            tor_max = max(5, alive_count * 5)
            safe_max_threads = min(safe_max_threads, tor_max)
            self.log(f"[Система] Tor: {alive_count} живых узлов × 5 = {tor_max} потоков")
            
        num_threads = min(safe_max_threads, self.total_dorks)
        if num_threads <= 0: num_threads = 1
        
        if num_threads < self.max_threads:
            if use_tor:
                self.log(f"[Система] Запуск {num_threads} потоков (адаптировано под Tor)...")
            else:
                self.log(f"[Система] Запуск {num_threads} потоков (ограничено количеством дорков)...")
        else:
            self.log(f"[Система] Запуск {num_threads} потоков...")
        for i in range(num_threads):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)
            
        # 4. Wait for completion
        for t in threads:
            t.join()
            
        if self._stop_event.is_set():
            self.log("[Система] Парсинг был принудительно остановлен.")
        else:
            self.log(f"[Система] Парсинг успешно завершен! Всего найдено: {self.total_emails}")
        
        if hasattr(self, 'tor_manager') and self.tor_manager:
            self.tor_manager.stop()
            
        self.log(f"[Система] Парсинг завершен. Всего почт: {self.total_emails}")
        if self.on_complete:
            self.on_complete(aborted=self._stop_event.is_set())
