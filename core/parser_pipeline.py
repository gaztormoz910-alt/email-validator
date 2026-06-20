import threading
import queue
import time
import logging
from typing import Callable
from .parser.engine import ProxyManager, DuckDuckGoEngine, AOLEngine
from .parser.extractor import EmailExtractor

class ParserPipeline(threading.Thread):
    def __init__(self, dorks, proxies, max_threads, timeout=5.0,
                 on_log=None, on_progress=None, on_stats_update=None, on_result_found=None, on_complete=None, engine_name="DuckDuckGo Lite"):
        super().__init__()
        self.dorks = dorks
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
        self.extractor = EmailExtractor()
        self.dork_queue = queue.Queue()
        
        self.total_dorks = len(self.dorks)
        self.processed_dorks = 0
        self.processed_pages = 0
        self.processed_snippets = 0
        self.total_emails = 0
        
        self.stats_lock = threading.Lock()
        self.seen_lock = threading.Lock()
        self.global_seen_emails = set()
        
        for i, d in enumerate(self.dorks, 1):
            # Передаем оригинальный dork без добавления мусорных символов
            self.dork_queue.put((i, d.strip(), d))
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
        self.log(f"[Система] Инициализация парсера. Поисковик: {self.engine_name}. Загружено дорков: {self.total_dorks}")
        
        tor_engines = ["AOL (Tor)"]
        use_tor = self.engine_name in tor_engines
        
        if use_tor:
            from core.tor_manager import TorManager
            self.tor_manager = TorManager(log_callback=self.log)
            if not self.tor_manager.start():
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
            if self.engine_name == "AOL (Tor)":
                class TorProxyManagerWrapper:
                    def __init__(self, tm):
                        self.tm = tm
                        self.timeout = 45.0
                    def get_total_count(self): return 1
                    def get_proxy(self): return self.tm.get_proxy_url()
                    def mark_fail(self, url): self.tm.renew_ip()
                    def mark_success(self, url): pass
                
                engine = AOLEngine(TorProxyManagerWrapper(self.tor_manager), on_log=self.log)
            else:
                engine = DuckDuckGoEngine(self.proxy_manager, on_log=self.log)
                
            while not self._stop_event.is_set():
                while self._pause_event.is_set() and not self._stop_event.is_set():
                    time.sleep(0.5)
                    
                try:
                    dork_idx, sub_query, base_dork = self.dork_queue.get_nowait()
                except queue.Empty:
                    break # queue is empty, worker can exit
                
                self.log(f"[DORK {dork_idx}/{len(self.dorks)}] Sub-query: {sub_query}")
                
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
                        
                        # Filter emails by domain from dork query
                        if emails and domain_filter:
                            emails = {e for e in emails if e.endswith('@' + domain_filter)}
                        
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
                                
                                self.log(f"[DORK {dork_idx}/{len(self.dorks)}] Страница: {max(1, int(pages_found*10))}, Найдено уникальных почт: {new_emails_count}")
                                
                                if self.on_result_found:
                                    for e in new_unique_emails:
                                        self.on_result_found(e, base_dork)
                                    
                except Exception as e:
                    self.log(f"[Ошибка DORK {dork_idx}] {str(e)}")
                    
                self._update_stats(dork_done=True)
                self.log(f"[РЕЗУЛЬТАТ] Sub-query '{sub_query}' завершен. Найдено почт: {emails_from_dork}")
                self.dork_queue.task_done()

        # 3. Spawn workers
        threads = []
        # Ограничиваем количество физических потоков до 500, чтобы не убить Windows (RuntimeError: can't start new thread)
        safe_max_threads = min(self.max_threads, 500)
        if use_tor:
            safe_max_threads = min(safe_max_threads, 50) # Tor daemon bottleneck 
            
        num_threads = min(safe_max_threads, self.total_dorks)
        if num_threads <= 0: num_threads = 1
        
        if num_threads < self.max_threads:
            self.log(f"[Система] Запуск {num_threads} потоков (ограничено {'системой безопасности' if safe_max_threads < self.max_threads else 'количеством текущих задач'})...")
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
