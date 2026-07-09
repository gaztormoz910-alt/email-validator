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
        # Очистка мусора: больше не загружаем блэклисты с GitHub, так как работает принцип Whitelist
        self.callbacks['on_log']("[INFO] Подготовка валидатора (работает в режиме Whitelist)...", "info")
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

    def run_pipeline(self, raw_emails_dict, threads=50, fix_typos=True, check_spam=True, deep_ping=True, enable_ai=False, enable_osint=False):
        self.is_running = True
        self.is_paused = False
        
        total_emails = len(raw_emails_dict)
        self.callbacks['on_log'](f"[INFO] Запуск обработки {total_emails} сырых email...", "info")
        
        if fix_typos:
            self.callbacks['on_log']("[INFO] Исправление опечаток и дедупликация (Cleaner)...", "info")
            unique_emails = self.cleaner.process_batch(raw_emails_dict)
            self.callbacks['on_log'](f"[INFO] После очистки: {len(unique_emails)} уникальных адресов.", "info")
        else:
            unique_emails = {e.strip().lower(): data for e, data in raw_emails_dict.items() if e.strip()}

        emails_to_process = list(unique_emails.items())
        total_unique = len(emails_to_process)
        if 'on_unique_count' in self.callbacks:
            self.callbacks['on_unique_count'](total_unique)
            
        self.callbacks['on_progress'](0, total_unique)
        processed_count = 0
        
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
                
            # Шаг 1.2: Проверка на опасные домены и ролевые ящики (Validol)
            if "@" in email:
                local_p, domain_p = email.split("@", 1)
                bad_tlds = {".gov", ".mil", ".edu"}
                roles = {"admin", "support", "staff", "info", "sales", "postmaster", "webmaster", "contact", "billing", "help", "hr", "office", "marketing", "hello", "noreply", "no-reply"}
                
                for tld in bad_tlds:
                    if domain_p.endswith(tld):
                        self.callbacks['on_result'](email, "Trap/Disposable", "Dangerous TLD", "N/A", data)
                        return
                if local_p in roles:
                    self.callbacks['on_result'](email, "Trap/Disposable", "Role-based Account", "N/A", data)
                    return

            # Шаг 1.5: Проверка через ИИ (Машинное обучение)
            if enable_ai and self.ai:
                if self.ai.predict(email):
                    self.callbacks['on_result'](email, "Trap/Disposable", "AI: Bot/Spam Pattern", "N/A", data)
                    return
                
            # Шаг 3: Глубокий SMTP Ping
            if deep_ping:
                res = self.network.check_email(email)
                status_display = "Valid" if res["status"] == "valid" else ("Risky" if res["status"] == "risky" else "Invalid/Bounce")
                if res["status"] == "unknown":
                    status_display = "Unknown"
                
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

        # Аппаратное ограничение количества потоков для предотвращения зависания ОС
        safe_threads = min(int(threads), 1000)
        
        with ThreadPoolExecutor(max_workers=safe_threads) as executor:
            futures = []
            for item in emails_to_process:
                if not self.is_running:
                    break
                futures.append(executor.submit(process_single, item))
                
            for future in as_completed(futures):
                if not self.is_running:
                    break
                future.result()
                processed_count += 1
                self.callbacks['on_progress'](processed_count, total_unique)
                
        self.is_running = False
        self.callbacks['on_complete']()

    def start(self, raw_emails_dict, threads, timeout, fix_typos, check_spam, deep_ping, enable_ai, proxies=None, enable_osint=False):
        def worker():
            self.setup(timeout=timeout, enable_ai=enable_ai, proxies=proxies, threads=threads)
            self.run_pipeline(raw_emails_dict, threads, fix_typos, check_spam, deep_ping, enable_ai, enable_osint=enable_osint)
            
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        
    def stop(self):
        self.is_running = False
        
    def pause(self):
        self.is_paused = not self.is_paused
        return self.is_paused
