import threading
import queue
import time
from .parser.engine import ProxyManager, DuckDuckGoEngine
from .parser.extractor import EmailExtractor

class ParserPipeline(threading.Thread):
    def __init__(self, dorks, proxies, max_threads,
                 on_log=None, on_progress=None, on_stats_update=None, on_result_found=None, on_complete=None):
        super().__init__()
        self.dorks = dorks
        self.proxies = proxies
        self.max_threads = max_threads
        
        self.on_log = on_log
        self.on_progress = on_progress
        self.on_stats_update = on_stats_update
        self.on_result_found = on_result_found
        self.on_complete = on_complete
        
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        
        self.proxy_manager = ProxyManager(self.proxies)
        self.extractor = EmailExtractor()
        self.dork_queue = queue.Queue()
        
        deep_suffixes = [""] + list("abcdefghijklmnopqrstuvwxyz") + ["1", "2", "3", "info", "contact"]
        
        self.total_dorks = len(self.dorks) * len(deep_suffixes)
        self.processed_dorks = 0
        self.processed_pages = 0
        self.processed_snippets = 0
        self.total_emails = 0
        
        self.stats_lock = threading.Lock()
        
        for i, d in enumerate(self.dorks, 1):
            for s in deep_suffixes:
                sub_query = f"{d} {s}".strip()
                self.dork_queue.put((i, sub_query, d))
            


    def _update_stats(self, dork_done=False, page=0, snippet=0, emails=0):
        with self.stats_lock:
            if dork_done:
                self.processed_dorks += 1
            self.processed_pages += page
            self.processed_snippets += snippet
            self.total_emails += emails
            
            if self.on_stats_update:
                self.on_stats_update(
                    self.total_dorks,
                    self.processed_dorks,
                    self.processed_pages,
                    self.processed_snippets,
                    self.total_emails
                )
            if self.on_progress:
                pct = int((self.processed_dorks / max(1, self.total_dorks)) * 100)
                self.on_progress(self.processed_dorks, self.total_dorks, pct)

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
        self.log(f"[Система] Инициализация парсера. Загружено дорков: {self.total_dorks}, прокси: {len(self.proxies)}")
        
        # 1. Ping proxies
        if self.proxies:
            self.log("[Система] Проверка работоспособности SOCKS5 прокси...")
            
            def _proxy_progress(checked, total, live):
                if self.on_progress:
                    pct = int((checked / total) * 100) if total > 0 else 0
                    self.on_progress(checked, total, pct)
                if checked % max(1, (total // 10)) == 0 or checked == total:
                    self.log(f"[Система] Проверка прокси: {checked}/{total} (Живых: {live})")
                    
            self.proxy_manager.check_all_proxies(progress_callback=_proxy_progress)
            
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
            engine = DuckDuckGoEngine(self.proxy_manager, on_log=self.log)
            while not self._stop_event.is_set():
                while self._pause_event.is_set() and not self._stop_event.is_set():
                    time.sleep(0.5)
                    
                try:
                    dork_idx, sub_query, base_dork = self.dork_queue.get_nowait()
                except queue.Empty:
                    break # queue is empty, worker can exit
                
                self.log(f"[DORK {dork_idx}/{len(self.dorks)}] Sub-query: {sub_query}")
                
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
                        if emails:
                            new_emails_count = len(emails)
                            emails_from_dork += new_emails_count
                            self._update_stats(emails=new_emails_count)
                            
                            self.log(f"[DORK {dork_idx}/{len(self.dorks)}] Страница: {max(1, int(pages_found*10))}, Найдено почт: {new_emails_count}")
                            
                            if self.on_result_found:
                                for e in emails:
                                    self.on_result_found(e, base_dork)
                                    
                except Exception as e:
                    self.log(f"[Ошибка DORK {dork_idx}] {str(e)}")
                    
                self._update_stats(dork_done=True)
                self.log(f"[РЕЗУЛЬТАТ] Sub-query '{sub_query}' завершен. Найдено почт: {emails_from_dork}")
                self.dork_queue.task_done()

        # 3. Spawn workers
        threads = []
        num_threads = min(self.max_threads, self.total_dorks)
        if num_threads <= 0: num_threads = 1
        
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
            
        if self.on_complete:
            self.on_complete(aborted=self._stop_event.is_set())
