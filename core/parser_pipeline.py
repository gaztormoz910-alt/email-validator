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
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com", "icloud.com", "mac.com", "me.com", "comcast.net", "sbcglobal.net", "att.net", "verizon.net", "cox.net", "charter.net",
    "yahoo.ca", "hotmail.ca", "bell.net", "sympatico.ca", "rogers.com", "shaw.ca", "telus.net", "videotron.ca", "cogeco.ca",
    "yahoo.com.au", "hotmail.com.au", "outlook.com.au", "live.com.au", "bigpond.com", "bigpond.net.au", "optusnet.com.au", "iinet.net.au", "tpg.com.au",
    "hotmail.nl", "live.nl", "ziggo.nl", "kpnmail.nl", "planet.nl", "hetnet.nl", "upcmail.nl", "chello.nl", "xs4all.nl",
    "hotmail.co.uk", "yahoo.co.uk", "live.co.uk", "btinternet.com", "sky.com", "virginmedia.com", "talktalk.net", "blueyonder.co.uk", "ntlworld.com",
    "gmx.de", "gmx.net", "web.de", "t-online.de", "freenet.de", "googlemail.com", "hotmail.de", "yahoo.de", "outlook.de",
    "orange.fr", "free.fr", "sfr.fr", "laposte.net", "wanadoo.fr", "yahoo.fr", "hotmail.fr",
    "libero.it", "virgilio.it", "tim.it", "alice.it", "tiscali.it", "yahoo.it", "hotmail.it",
    "yahoo.es", "hotmail.es", "telefonica.net",
    "wp.pl", "onet.pl", "o2.pl", "interia.pl", "gazeta.pl"
}


SEARCH_ENGINES = (
    "DuckDuckGo Lite",
    "AOL (Tor)",
    "Yahoo (Tor)",
    "AOL (Proxies)",
    "Yahoo (Proxies)",
)

DEFAULT_ENGINE = SEARCH_ENGINES[0]


class ParserPipeline(threading.Thread):
    def __init__(self, dork_sources, proxies, max_threads, timeout=5.0,
                 on_log=None, on_progress=None, on_stats_update=None, on_result_found=None, on_complete=None, engine_name="DuckDuckGo Lite", enable_osint=False,
                 activity=None):
        super().__init__()
        if activity is None:
            from core.activity import ActivityMonitor
            activity = ActivityMonitor(kind="parser")
        self.activity = activity
        try:
            activity.set_net_budget(3.0 * float(timeout))
        except (TypeError, ValueError):
            pass
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
        from .runstate import RunState, run_id_for
        self._seen = RunState(run_id_for(dork_sources) + ":parsed", resume=False)
        self.global_seen_emails = self._seen
        
        self.feeder_thread = threading.Thread(target=self._feed_dorks, daemon=True)
        self.feeder_error = None
        self.failed_reason = ""
        self._completed = False

    def _put(self, item):
        while not self._stop_event.is_set():
            try:
                self.dork_queue.put(item, timeout=0.5)
                return True
            except queue.Full:
                continue
        return False

    def _feed_dorks(self):
        from core.streamer import StreamLoader
        lines = StreamLoader(self.dork_sources).stream_lines()
        try:
            for i, d in enumerate(lines, 1):
                if self._stop_event.is_set():
                    break
                if not self._put((i, d.strip(), d)):
                    break
        except Exception as exc:
            self.feeder_error = exc
            logging.getLogger(__name__).exception("чтение дорков оборвалось")
        finally:
            close = getattr(lines, "close", None)
            if close is not None:
                close()

        for _ in range(self.max_threads * 2):
            if not self._put(None):
                break

    def _stopped_before_search(self):
        if not self._stop_event.is_set():
            return False
        self.log("[Система] Сбор остановлен до начала поиска.")
        tor = getattr(self, "tor_manager", None)
        if tor is not None:
            tor.stop()
        self._complete(aborted=True)
        return True

    def _complete(self, aborted):
        if self._completed:
            return
        self._completed = True
        if self.on_complete:
            self.on_complete(aborted=aborted)
    def _update_stats(self, dork_done=False, page=0, snippet=0, emails=0):
        with self.stats_lock:
            if dork_done:
                self.processed_dorks += 1
            self.processed_pages += page
            self.processed_snippets += snippet
            self.total_emails += emails
            
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
        self._pause_event.clear()
        self.activity.set_paused(False)

    def pause(self):
        self._pause_event.set()
        self.activity.set_paused(True)

    def resume(self):
        self._pause_event.clear()
        self.activity.set_paused(False)

    def run(self):
        try:
            self._run()
        except Exception as exc:
            self.failed_reason = "%s: %s" % (type(exc).__name__, exc)
            self.log("[Ошибка] Сбор прерван ошибкой: %s" % self.failed_reason)
            self._complete(aborted=True)
            raise

    def _run(self):
        self.activity.stage("p_init")
        self.ml_predictor = MLPredictor()
        if self.name_extractor is None:
            self.name_extractor = NameExtractor(enable_osint=self.enable_osint)
        if self._stopped_before_search():
            return

        from core.streamer import StreamLoader
        self.total_dorks = StreamLoader(self.dork_sources).estimate_total_lines()
        if self.engine_name not in SEARCH_ENGINES:
            self.log("[Система] Движок «%s» больше не поддерживается — сбор "
                     "через открытые API удалён. Беру %s."
                     % (self.engine_name, DEFAULT_ENGINE))
            self.engine_name = DEFAULT_ENGINE

        self.log(f"[Система] Инициализация парсера. Поисковик: {self.engine_name}. "
                 f"Дорков примерно: {self.total_dorks}")

        def refine_total():
            try:
                exact = StreamLoader(self.dork_sources).count_total_lines()
            except Exception:
                return
            if exact and not self._stop_event.is_set():
                self.total_dorks = exact
                self.log(f"[Система] Точное число дорков: {exact}")

        threading.Thread(target=refine_total, daemon=True).start()
        
        tor_engines = ["AOL (Tor)", "Yahoo (Tor)"]
        use_tor = self.engine_name in tor_engines
        
        if use_tor:
            self.activity.stage("p_tor")
            from core.tor_manager import TorManager
            self.tor_manager = TorManager(log_callback=self.log)
            
            import math
            num_tor_instances = max(1, min(10, math.ceil(self.max_threads / 50)))
            
            if self._stopped_before_search():
                return
            if not self.tor_manager.start(num_instances=num_tor_instances,
                                          should_stop=self._stop_event.is_set):
                if self._stopped_before_search():
                    return
                self.log("[Ошибка] Не удалось запустить Tor. Парсинг невозможен.")
                self._complete(aborted=True)
                return
            if self._stopped_before_search():
                return
        else:
            if self.proxies:
                self.activity.stage("p_proxies")
                self.log(f"[Система] Проверка работоспособности SOCKS5 прокси ({len(self.proxies)} шт.)...")
                
                def _proxy_progress(checked, total, live):
                    if self.on_progress:
                        pct = int((checked / total) * 100) if total > 0 else 0
                        self.on_progress(checked, total, pct, label="Проверка прокси")
                    if checked % max(1, (total // 10)) == 0 or checked == total:
                        self.log(f"[Система] Проверка прокси: {checked}/{total} (Живых: {live})")
                        
                self.proxy_manager.check_all_proxies(
                    max_workers=self.max_threads, progress_callback=_proxy_progress,
                    should_stop=self._stop_event.is_set)
                if self._stopped_before_search():
                    return

                live = self.proxy_manager.get_live_count()
                self.log(f"[Система] Рабочих прокси: {live} из {len(self.proxies)}")
                if live == 0:
                    self.log("[Ошибка] Нет ни одного рабочего прокси! Парсинг невозможен.")
                    self._complete(aborted=True)
                    return
            else:
                self.log("[Предупреждение] Прокси не загружены. Парсинг пойдет через прямой IP!")

        if self._stopped_before_search():
            return
        self._update_stats()

        def worker():
            if self.engine_name in ["AOL (Tor)", "Yahoo (Tor)"]:
                class TorProxyManagerWrapper:
                    def __init__(wrapper_self, tm, configured_timeout):
                        wrapper_self.tm = tm
                        wrapper_self.timeout = min(float(configured_timeout), 20.0)
                        wrapper_self._last_renew = 0
                        wrapper_self._renew_lock = threading.Lock()
                    def get_total_count(wrapper_self):
                        return max(1, wrapper_self.tm.get_alive_count())
                    def get_proxy(wrapper_self):
                        url = wrapper_self.tm.get_proxy_url()
                        if url is None:
                            return None
                        return url
                    def mark_fail(wrapper_self, url):
                        now = time.time()
                        if now - wrapper_self._last_renew < 5.0:
                            return
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
                engine = DuckDuckGoEngine(self.proxy_manager, on_log=self.log,
                                          is_stopped=lambda: self._stop_event.is_set())
                
            while not self._stop_event.is_set():
                while self._pause_event.is_set() and not self._stop_event.is_set():
                    time.sleep(0.5)
                if self._stop_event.is_set():
                    break

                try:
                    item = self.dork_queue.get(timeout=0.5)
                except queue.Empty:
                    if self.feeder_thread.is_alive() or not self.dork_queue.empty():
                        continue
                    break
                if item is None:
                    break
                dork_idx, sub_query, base_dork = item
                self.activity.enter()
                try:
                    search_one(engine, dork_idx, sub_query, base_dork)
                finally:
                    self.activity.leave()

        def search_one(engine, dork_idx, sub_query, base_dork):
                self.log(f"[DORK {dork_idx}/{self.total_dorks}] Sub-query: {sub_query}")
                
                import re as _re
                domain_filter = None
                domain_match = _re.search(r'["\']?@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})["\']?', sub_query)
                if domain_match:
                    domain_filter = domain_match.group(1).lower()
                
                pages_found = 0
                emails_from_dork = 0
                
                try:
                    for snippet in engine.search_generator(sub_query):
                        if self._stop_event.is_set():
                            break
                        while self._pause_event.is_set() and not self._stop_event.is_set():
                            time.sleep(0.5)
                            
                        pages_found += 0.1
                        if pages_found >= 1.0:
                            self._update_stats(page=1)
                            pages_found -= 1.0
                            
                        self._update_stats(snippet=1)
                        
                        emails = self.extractor.extract(snippet)
                        
                        if emails:
                            valid_emails = set()
                            for e in emails:
                                try:
                                    e_domain = e.split('@')[-1].lower()
                                    if (domain_filter and e_domain == domain_filter) or e_domain in GLOBAL_VERIFIED_DOMAINS:
                                        valid_emails.add(e)
                                    elif not domain_filter:
                                        valid_emails.add(e)
                                except Exception:
                                    pass
                            emails = valid_emails
                        
                        if emails:
                            from .cleaner import normalize_for_dedup
                            new_unique_emails = []
                            with self.seen_lock:
                                for e in emails:
                                    if self._seen.add_if_new(normalize_for_dedup(e)):
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

        self.activity.stage("p_search")
        self.feeder_thread.start()
        threads = []
        safe_max_threads = min(self.max_threads, 500)
        
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
            
        for t in threads:
            t.join()
            
        if self.feeder_error is not None:
            self.failed_reason = "чтение файла дорков оборвалось: %s: %s" % (
                type(self.feeder_error).__name__, self.feeder_error)
            self.log("[Ошибка] Сбор прерван — %s. Обработано дорков: %s, остальные "
                     "не прочитаны." % (self.failed_reason, self.processed_dorks))
        elif self._stop_event.is_set():
            self.log("[Система] Парсинг был принудительно остановлен.")
        else:
            self.log(f"[Система] Парсинг успешно завершен! Всего найдено: {self.total_emails}")

        if hasattr(self, 'tor_manager') and self.tor_manager:
            self.tor_manager.stop()

        self.log(f"[Система] Парсинг завершен. Всего почт: {self.total_emails}")
        self._complete(aborted=self._stop_event.is_set() or self.feeder_error is not None)
