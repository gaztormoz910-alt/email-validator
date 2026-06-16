# core/pipeline.py
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.cleaner import EmailCleaner
from core.filters import SpamFilter
from core.github_parser import BlacklistDownloader
from core.network import NetworkValidator
from core.ai_engine import EmailAI

class ValidationPipeline:
    def __init__(self, callbacks):
        self.callbacks = callbacks 
        self.is_running = False
        self.is_paused = False
        
        self.cleaner = EmailCleaner()
        self.filter = None
        self.network = None
        self.ai = None
        
    def setup(self, timeout=5, enable_ai=False, proxies=None, threads=100):
        self.callbacks['on_log']("[INFO] Загрузка баз с GitHub (Spam-Traps, Disposable)...", "info")
        downloader = BlacklistDownloader()
        downloader.download_all()
        
        self.callbacks['on_log']("[INFO] Загрузка списков в ОЗУ для O(1) поиска...", "info")
        self.filter = SpamFilter()
        
        if proxies:
            from core.network import filter_live_proxies
            self.callbacks['on_log'](f"[INFO] Тестирование {len(proxies)} прокси-серверов (потоков: {threads}, таймаут: {timeout}с)...", "info")
            # Теперь таймаут строго подчиняется твоему ползунку (никаких ограничений!)
            live_proxies = filter_live_proxies(proxies, timeout=timeout, threads=threads, progress_callback=self.callbacks['on_progress'])
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

    def run_pipeline(self, raw_emails, threads=50, fix_typos=True, check_spam=True, deep_ping=True, enable_ai=False):
        self.is_running = True
        self.is_paused = False
        
        total_emails = len(raw_emails)
        self.callbacks['on_log'](f"[INFO] Запуск обработки {total_emails} сырых email...", "info")
        
        if fix_typos:
            self.callbacks['on_log']("[INFO] Исправление опечаток и дедупликация (Cleaner)...", "info")
            unique_emails = self.cleaner.process_batch(raw_emails)
            self.callbacks['on_log'](f"[INFO] После очистки: {len(unique_emails)} уникальных адресов.", "info")
        else:
            unique_emails = set(e.strip().lower() for e in raw_emails if e.strip())

        emails_to_process = list(unique_emails)
        total_unique = len(emails_to_process)
        if 'on_unique_count' in self.callbacks:
            self.callbacks['on_unique_count'](total_unique)
            
        self.callbacks['on_progress'](0, total_unique)
        processed_count = 0

        def process_single(email):
            if not self.is_running:
                return
            while self.is_paused:
                time.sleep(0.5)
                
            # Шаг 1.2: Проверка на опасные домены и ролевые ящики (Validol)
            if "@" in email:
                local_p, domain_p = email.split("@", 1)
                bad_tlds = {".gov", ".mil", ".edu"}
                roles = {"admin", "support", "staff", "info", "sales", "postmaster", "webmaster", "contact", "billing", "help", "hr", "office", "marketing", "hello", "noreply", "no-reply"}
                
                for tld in bad_tlds:
                    if domain_p.endswith(tld):
                        self.callbacks['on_result'](email, "Trap/Disposable", "Dangerous TLD", "N/A")
                        return
                if local_p in roles:
                    self.callbacks['on_result'](email, "Trap/Disposable", "Role-based Account", "N/A")
                    return

            # Шаг 1.5: Проверка через ИИ (Машинное обучение)
            if enable_ai and self.ai:
                if self.ai.predict(email):
                    self.callbacks['on_result'](email, "Trap/Disposable", "AI: Bot/Spam Pattern", "N/A")
                    return
                
            # Шаг 2: Фильтр Спам-ловушек (Blacklist)
            if check_spam and self.filter.is_spam_or_disposable(email):
                self.callbacks['on_result'](email, "Trap/Disposable", "Blacklisted", "N/A")
                return
                
            # Шаг 3: Глубокий SMTP Ping
            if deep_ping:
                res = self.network.check_email(email)
                status_display = "Valid" if res["status"] == "valid" else ("Risky" if res["status"] == "risky" else "Invalid/Bounce")
                if res["status"] == "unknown":
                    status_display = "Unknown"
                
                self.callbacks['on_result'](email, status_display, res["reason"], res.get("mx_record", "N/A"))
            else:
                self.callbacks['on_result'](email, "Unverified", "Skipped Ping", "N/A")

        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = []
            for email in emails_to_process:
                if not self.is_running:
                    break
                futures.append(executor.submit(process_single, email))
                
            for future in as_completed(futures):
                if not self.is_running:
                    break
                future.result()
                processed_count += 1
                self.callbacks['on_progress'](processed_count, total_unique)
                
        self.is_running = False
        self.callbacks['on_complete']()

    def start(self, raw_emails, threads, timeout, fix_typos, check_spam, deep_ping, enable_ai, proxies=None):
        def worker():
            self.setup(timeout=timeout, enable_ai=enable_ai, proxies=proxies, threads=threads)
            self.run_pipeline(raw_emails, threads, fix_typos, check_spam, deep_ping, enable_ai)
            
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        
    def stop(self):
        self.is_running = False
        
    def pause(self):
        self.is_paused = not self.is_paused
        return self.is_paused
