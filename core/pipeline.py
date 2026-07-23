# core/pipeline.py
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.cleaner import EmailCleaner
from core.filters import SpamFilter
from core.github_parser import BlacklistDownloader
from core.network import NetworkValidator
from core.ai_engine import EmailAI
from core.parser.name_extractor import NameExtractor
from core.parser.ml_predictor import MLPredictor

class ValidationPipeline:
    def __init__(self, callbacks):
        self.callbacks = callbacks 
        self.is_running = False
        self.is_paused = False
        
        self.cleaner = EmailCleaner()
        self.filter = None
        self.network = None
        self.ai = None
        self.name_extractor = None
        self.ml_predictor = None
        
    def setup(self, timeout=5, enable_ai=False, proxies=None, threads=100):
        # Гибридный режим: Whitelist + DNS-проверка неизвестных доменов
        self.callbacks['on_log']("[INFO] Подготовка валидатора (гибридный режим: Whitelist + DNS)...", "info")
        self.filter = None
        
        if proxies:
            from core.network import filter_live_proxies
            self.callbacks['on_log'](f"[INFO] Тестирование {len(proxies)} прокси-серверов (потоков: {threads}, таймаут: {timeout}с)...", "info")
            # Теперь таймаут строго подчиняется твоему ползунку (никаких ограничений!)
            live_proxies = filter_live_proxies(proxies, timeout=timeout, threads=threads, progress_callback=self.callbacks['on_progress'], log_callback=self.callbacks.get('on_log'))
            self.callbacks['on_log'](f"[INFO] Проверка завершена. Найдено рабочих прокси: {len(live_proxies)} из {len(proxies)}.", "info")
            if 'on_proxies_tested' in self.callbacks:
                self.callbacks['on_proxies_tested'](len(live_proxies), len(proxies))
            if not live_proxies:
                self.callbacks['on_log']("[DEAD] Внимание: Ни один из загруженных прокси не работает. Валидация скорее всего завершится с ошибками.", "dead")
            proxies = live_proxies
            
        self.network = NetworkValidator(timeout=timeout, proxies=proxies)
        
        if enable_ai:
            self.callbacks['on_log']("[INFO] Прогрев и обучение Нейросети (TensorFlow + NaiveBayes)...", "info")
            self.ai = EmailAI()
            self.ai.train_models()
            self.callbacks['on_log']("[INFO] ИИ успешно обучен и готов к бою!", "info")

    def run_pipeline(self, email_sources, threads=50, fix_typos=True, check_spam=True, deep_ping=True, enable_ai=False, enable_osint=False):
        self.is_running = True
        self.is_paused = False
        
        from core.streamer import StreamLoader
        total_emails = StreamLoader(email_sources).count_total_lines()
        self.callbacks['on_log'](f"[INFO] Запуск обработки {total_emails} сырых email...", "info")
        
        if 'on_unique_count' in self.callbacks:
            self.callbacks['on_unique_count'](total_emails) # Approximate since dedup is lazy
            
        self.callbacks['on_progress'](0, total_emails)
        processed_count = 0
        
        # Очередь для Greylisting retry (п.2.4)
        import queue as queue_module
        greylisted_queue = queue_module.Queue()
        greylisted_lock = threading.Lock()
        
        # Предзагрузка тяжелых модулей один раз (O(1) вместо O(N) в потоках)
        if not self.name_extractor:
            self.callbacks['on_log']("[INFO] Загрузка модуля извлечения имен...", "info")
            self.name_extractor = NameExtractor(enable_osint=enable_osint)
        if not self.ml_predictor:
            self.callbacks['on_log']("[INFO] Загрузка предиктора пола/страны...", "info")
            self.ml_predictor = MLPredictor(enable_ml=enable_ai)

        def process_single(item):
            if not self.is_running:
                return
            while self.is_paused:
                time.sleep(0.5)
                
            email, data = item
                
            # Шаг 1.2: Проверка на ролевые ящики (Role-based) — п.2.1
            # НЕ убиваем их! Помечаем как отдельную категорию "Role-based".
            # .gov/.edu/.mil — это легитимные домены, НЕ ловушки (п.1.2)
            if "@" in email:
                local_p, domain_p = email.split("@", 1)
                roles = {
                    "abuse", "admin", "billing", "compliance", "contact", "devnull",
                    "dns", "ftp", "help", "hostmaster", "hr", "info", "jobs",
                    "list", "maildaemon", "marketing", "media", "noc",
                    "no-reply", "noreply", "null", "office", "postmaster",
                    "privacy", "registrar", "root", "sales", "security",
                    "spam", "staff", "subscribe", "support", "sysadmin",
                    "tech", "unsubscribe", "webmaster", "www", "hello",
                    "press", "legal", "feedback"
                }
                if local_p in roles:
                    # Помечаем как Role-based, но НЕ отбрасываем — пусть пользователь решает
                    self.callbacks['on_result'](email, "Role-based", "Role-based Account", "N/A", data)
                    return

            # Шаг 1.5: Проверка через ИИ (Машинное обучение)
            if enable_ai and self.ai:
                if self.ai.predict(email):
                    self.callbacks['on_result'](email, "Trap/Disposable", "AI: Bot/Spam Pattern", "N/A", data)
                    return
                
            # Шаг 3: Глубокий SMTP Ping
            if deep_ping:
                res = self.network.check_email(email)
                raw_status = res["status"]

                # Greylisted — складываем в очередь для повторной проверки (п.2.4)
                if raw_status == "greylisted":
                    greylisted_queue.put((email, data))
                    return  # Не выводим результат сейчас — перепроверим позже

                if raw_status == "valid":
                    status_display = "Valid"
                elif raw_status == "catchall":
                    status_display = "Unknown"  # Catch-All — нельзя доверять, кладём в Unknown
                elif raw_status == "risky":
                    status_display = "Risky"
                elif raw_status == "unknown":
                    status_display = "Unknown"
                else:
                    status_display = "Invalid/Bounce"
                
                # Enrichment for valid emails
                if status_display == "Valid":
                    name = data.get("name")
                    gender = data.get("gender")
                    country = data.get("country")
                    
                    if not name or not gender or not country or gender == "":
                        if not name:
                            name = self.name_extractor.extract_name(email)
                            
                        # ML/AI Name Validation (NER)
                        if name and enable_ai:
                            is_human = self.ml_predictor.is_person(name)
                            if not is_human:
                                name = "" # ИИ понял, что это не человек (например ORG)
                        
                        pred_gender, pred_country_from_email = self.ml_predictor.predict(name, email=email)
                        
                        pred_country_from_name = ""
                        if name and enable_ai:
                            pred_country_from_name = self.ml_predictor.predict_country(name)
                        
                        if not gender or gender == "":
                            gender = pred_gender
                        if not country or country == "":
                            country = pred_country_from_name if pred_country_from_name else pred_country_from_email
                            
                    data["name"] = name
                    data["gender"] = gender
                    data["country"] = country

                self.callbacks['on_result'](email, status_display, res["reason"], res.get("mx_record", "N/A"), data)
            else:
                self.callbacks['on_result'](email, "Unverified", "Skipped Ping", "N/A", data)

        # Аппаратное ограничение количества потоков для предотвращения зависания сети и роутера
        safe_threads = min(int(threads), 300)
        
        import queue
        task_queue = queue.Queue(maxsize=safe_threads * 2)
        seen_emails = set()
        
        def feeder_thread():
            from core.streamer import StreamLoader
            for email, data in StreamLoader(email_sources).stream_emails():
                if not self.is_running:
                    break
                    
                if fix_typos:
                    email = self.cleaner.clean_email(email)
                    
                if not email:
                    continue
                    
                if email in seen_emails:
                    continue
                
                seen_emails.add(email)
                task_queue.put((email, data))
                
            for _ in range(safe_threads):
                task_queue.put(None)
                
        t_feeder = threading.Thread(target=feeder_thread, daemon=True)
        t_feeder.start()
        
        progress_lock = threading.Lock()
        
        def worker_loop():
            nonlocal processed_count
            while self.is_running:
                item = task_queue.get()
                if item is None:
                    break
                process_single(item)
                with progress_lock:
                    processed_count += 1
                    current = processed_count
                self.callbacks['on_progress'](current, total_emails)
                
        worker_threads = []
        for _ in range(safe_threads):
            wt = threading.Thread(target=worker_loop, daemon=True)
            wt.start()
            worker_threads.append(wt)
            
        for wt in worker_threads:
            wt.join()
        
        # === Greylisting Auto-Retry (п.2.4) ===
        greylisted_count = greylisted_queue.qsize()
        if greylisted_count > 0 and self.is_running and deep_ping:
            self.callbacks['on_log'](f"[INFO] Перепроверка {greylisted_count} Greylisted почт, ожидание 90 сек...", "info")
            
            # Ждём 90 секунд (серверы с greylisting ожидают повторной попытки через 1-5 мин)
            for i in range(90):
                if not self.is_running:
                    break
                time.sleep(1)
            
            if self.is_running:
                self.callbacks['on_log'](f"[INFO] Начинаю перепроверку {greylisted_count} Greylisted почт...", "info")
                retry_count = 0
                while not greylisted_queue.empty() and self.is_running:
                    try:
                        email, data = greylisted_queue.get_nowait()
                    except Exception:
                        break
                    
                    res = self.network.check_email(email)
                    raw_status = res["status"]
                    
                    if raw_status == "valid":
                        status_display = "Valid"
                    elif raw_status == "greylisted":
                        status_display = "Risky"  # Второй раз greylisted — помечаем как Risky
                    elif raw_status == "risky":
                        status_display = "Risky"
                    elif raw_status == "catchall":
                        status_display = "Unknown"
                    elif raw_status == "unknown":
                        status_display = "Unknown"
                    else:
                        status_display = "Invalid/Bounce"
                    
                    # Enrichment for valid emails (same as above)
                    if status_display == "Valid":
                        name = data.get("name")
                        gender = data.get("gender")
                        country = data.get("country")
                        if not name or not gender or not country or gender == "":
                            if not name:
                                name = self.name_extractor.extract_name(email)
                            if name and enable_ai:
                                is_human = self.ml_predictor.is_person(name)
                                if not is_human:
                                    name = ""
                            pred_gender, pred_country_from_email = self.ml_predictor.predict(name, email=email)
                            pred_country_from_name = ""
                            if name and enable_ai:
                                pred_country_from_name = self.ml_predictor.predict_country(name)
                            if not gender or gender == "":
                                gender = pred_gender
                            if not country or country == "":
                                country = pred_country_from_name if pred_country_from_name else pred_country_from_email
                        data["name"] = name
                        data["gender"] = gender
                        data["country"] = country
                    
                    self.callbacks['on_result'](email, status_display, res["reason"], res.get("mx_record", "N/A"), data)
                    retry_count += 1
                
                self.callbacks['on_log'](f"[INFO] Перепроверка Greylisted завершена: {retry_count} почт обработано.", "info")
                
        self.is_running = False
        self.callbacks['on_complete']()

    def start(self, email_sources, threads, timeout, fix_typos, check_spam, deep_ping, enable_ai, proxies=None, enable_osint=False):
        def worker():
            self.setup(timeout=timeout, enable_ai=enable_ai, proxies=proxies, threads=threads)
            self.run_pipeline(email_sources, threads, fix_typos, check_spam, deep_ping, enable_ai, enable_osint=enable_osint)
            
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        
    def stop(self):
        self.is_running = False
        
    def pause(self):
        self.is_paused = not self.is_paused
        return self.is_paused
