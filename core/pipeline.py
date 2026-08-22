# core/pipeline.py
import threading
import time
import json
import datetime
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.cleaner import EmailCleaner, normalize_for_dedup
from core.filters import SpamFilter
from core.github_parser import BlacklistDownloader
from core.network import NetworkValidator, PROXY_MAX_CONSECUTIVE_FAILS
from core.ai_engine import EmailAI
from core.parser.name_extractor import NameExtractor
from core.parser.ml_predictor import MLPredictor
from core.disposable import is_disposable
from core.gravatar import GravatarChecker
from core.scoring import calculate_engagement_score
from core.provider import classify_domain
from core.heuristics import looks_machine_generated, is_parked_domain
from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS


def _utc_now():
    """Текущее время как aware-datetime в UTC."""
    return datetime.datetime.now(datetime.timezone.utc)


def _as_utc(dt):
    """Приводит datetime к aware-UTC. Naive-даты считаем уже записанными в UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


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
        self.gravatar_checker = GravatarChecker(timeout=3, proxy_provider=self._http_proxies)
        self._domain_age_cache = {}
        self._domain_age_lock = threading.Lock()
        self._http_alive_cache = {}
        self._http_alive_lock = threading.Lock()
        
    def _http_proxies(self):
        """Прокси для HTTP-проверок (Gravatar, RDAP, HEAD).

        Возвращает None, если прокси не заданы — тогда идём напрямую, как раньше.
        Если заданы, все HTTP-каналы идут через них: иначе реальный IP утекает
        и на gravatar.com, и в WHOIS, и на сайт самой проверяемой компании.
        """
        try:
            if self.network and self.network.has_proxies_configured():
                from core.network import build_proxy_dict
                proxy = self.network._pick_best_proxy()
                if proxy:
                    return build_proxy_dict(proxy)
        except Exception:
            pass
        return None

    def _get_domain_age_days(self, domain):
        """Получить возраст домена в днях через WHOIS/RDAP. Кэшируется."""
        with self._domain_age_lock:
            if domain in self._domain_age_cache:
                return self._domain_age_cache[domain]
        proxies = self._http_proxies()
        try:
            # Библиотека whois ходит по 43 порту напрямую и прокси не умеет.
            # Когда прокси заданы, пропускаем её и идём сразу в RDAP по HTTPS,
            # который проксируется. Иначе IP утекает регистратору домена.
            if proxies:
                raise RuntimeError("whois не проксируется — используем RDAP")
            import whois
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                # WHOIS часто возвращает datetime С таймзоной, а datetime.now() — без неё.
                # Раньше вычитание падало с TypeError, WHOIS-путь был мёртв и каждый
                # домен уходил в медленный RDAP-фоллбэк.
                age = (_utc_now() - _as_utc(creation)).days
                with self._domain_age_lock:
                    self._domain_age_cache[domain] = age
                return age
        except Exception:
            pass
        # Фоллбэк: RDAP через rdap.org
        try:
            url = f"https://rdap.org/domain/{domain}"
            if proxies:
                import requests
                data = requests.get(url, timeout=8, proxies=proxies,
                                    headers={"User-Agent": "Mozilla/5.0"}).json()
            else:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    dt = datetime.datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    age = (_utc_now() - _as_utc(dt)).days
                    with self._domain_age_lock:
                        self._domain_age_cache[domain] = age
                    return age
        except Exception:
            pass
        with self._domain_age_lock:
            self._domain_age_cache[domain] = -1
        return -1

    def _check_http_alive(self, domain):
        """Проверить, есть ли живой сайт на домене (HEAD запрос). Кэшируется."""
        with self._http_alive_lock:
            if domain in self._http_alive_cache:
                return self._http_alive_cache[domain]
        # Без прокси этот запрос оставляет реальный IP в логах самой проверяемой
        # компании — поэтому, если прокси заданы, идём через них.
        proxies = self._http_proxies()
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{domain}"
                if proxies:
                    import requests
                    alive = requests.head(url, timeout=6, proxies=proxies,
                                          headers={"User-Agent": "Mozilla/5.0"},
                                          allow_redirects=True).status_code < 400
                else:
                    req = urllib.request.Request(url, method="HEAD")
                    req.add_header("User-Agent", "Mozilla/5.0")
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        alive = resp.status < 400
                with self._http_alive_lock:
                    self._http_alive_cache[domain] = alive
                return alive
            except Exception:
                continue
        with self._http_alive_lock:
            self._http_alive_cache[domain] = False
        return False

    def setup(self, timeout=5, enable_ai=False, proxies=None, threads=100):
        # Гибридный режим: Whitelist + DNS-проверка неизвестных доменов
        self.callbacks['on_log']("[INFO] Подготовка валидатора (гибридный режим: Whitelist + DNS)...", "info")
        
        # Обновляем disposable/spam-списки ДО загрузки SpamFilter, чтобы он
        # сразу подхватил свежие данные. Списки переустанавливаются (замена, не
        # накопление), а качаются только если на сервере реально есть новое.
        try:
            self.callbacks['on_log']("[INFO] Проверка обновлений disposable-списков...", "info")
            BlacklistDownloader().download_all(log_callback=self.callbacks['on_log'])
        except Exception as e:
            self.callbacks['on_log'](f"[DEAD] Обновление списков не удалось ({type(e).__name__}), использую локальные.", "dead")

        # Подключаем SpamFilter из внешних файлов
        try:
            self.filter = SpamFilter()
            self.callbacks['on_log'](f"[INFO] SpamFilter загружен ({self.filter.get_count() if hasattr(self.filter, 'get_count') else '?'} доменов).", "info")
        except Exception:
            self.filter = None
        
        # Высокий таймаут вместе с повторами через прокси даёт огромное время на
        # один адрес: до 10 попыток * таймаут. Ползунок не трогаем (это осознанная
        # настройка), но предупреждаем, иначе прогон выглядит как зависание.
        if timeout > 30:
            self.callbacks['on_log'](
                f"[DEAD] Таймаут {timeout}с очень большой — прогон будет медленным. "
                "Обычно хватает 10-20с. (Зависнуть на одном адресе валидатор не даст: "
                "есть общий дедлайн, максимум 180с на адрес.)", "dead")

        ptr_proxies = []
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

            # Делим прокси на два пула по наличию обратного DNS. Yahoo/AOL/Verizon
            # пойдут только через PTR-прокси, всё остальное — через обычные, чтобы
            # не расходовать дефицитные PTR там, где они не нужны.
            if live_proxies:
                try:
                    from core.network import split_proxies_by_fcrdns
                    self.callbacks['on_log'](
                        f"[INFO] Проверка обратного DNS (PTR) у {len(live_proxies)} прокси...", "info")

                    def on_ptr_prog(done, total, found):
                        self.callbacks['on_log'](
                            f"[PROXY] PTR... {done}/{total} | С обратным DNS: {found}", "info")

                    ptr_proxies, plain_proxies = split_proxies_by_fcrdns(
                        live_proxies, timeout=timeout, progress_callback=on_ptr_prog)

                    if ptr_proxies:
                        pct = round(len(ptr_proxies) * 100 / len(live_proxies))
                        self.callbacks['on_log'](
                            f"[INFO] PTR есть у {len(ptr_proxies)} из {len(live_proxies)} прокси ({pct}%). "
                            f"Yahoo/AOL пойдут через них, остальные домены — через оставшиеся "
                            f"{len(plain_proxies)}.", "info")
                    else:
                        self.callbacks['on_log'](
                            "[DEAD] Обратного DNS (PTR) нет ни у одного прокси. Yahoo, AOL и Verizon "
                            "проверить НЕ получится — они отшивают такие IP до проверки адреса. "
                            "Остальные домены проверятся нормально.", "dead")
                except Exception as e:
                    self.callbacks['on_log'](
                        f"[DEAD] Проверка PTR не удалась ({type(e).__name__}), пулы не разделены.", "dead")

        self.network = NetworkValidator(timeout=timeout, proxies=proxies)
        if ptr_proxies:
            self.network.set_ptr_proxies(ptr_proxies)
        
        if enable_ai:
            self.callbacks['on_log']("[INFO] Прогрев и обучение Нейросети (TensorFlow + NaiveBayes)...", "info")
            self.ai = EmailAI()
            self.ai.train_models()
            self.callbacks['on_log']("[INFO] ИИ успешно обучен и готов к бою!", "info")

    def run_pipeline(self, email_sources, threads=50, fix_typos=True, check_spam=True, deep_ping=True, enable_ai=False, enable_osint=False):
        self.is_running = True
        self.is_paused = False
        
        from core.streamer import StreamLoader
        # Стартовая оценка по сырым строкам. Реальное число уникальных адресов
        # известно только фидеру (дедуп ленивый), поэтому ниже он уточнит total,
        # иначе прогресс-бар застревает и выглядит как зависание.
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

        # Предупреждаем один раз, когда прокси закончились посреди прогона
        proxies_dead_warned = threading.Event()

        def warn_if_proxies_dead():
            if (self.network and self.network.all_proxies_dead()
                    and not proxies_dead_warned.is_set()):
                proxies_dead_warned.set()
                self.callbacks['on_log'](
                    "[DEAD] Все прокси выбыли из ротации (каждый сдох "
                    f"{PROXY_MAX_CONSECUTIVE_FAILS} раза подряд). Прямое соединение НЕ используется, "
                    "чтобы не раскрыть твой реальный IP. Загрузи свежие прокси и запусти заново.",
                    "dead")

        def process_single(item):
            if not self.is_running:
                return
            while self.is_paused:
                time.sleep(0.5)

            email, data = item

            # Дата последней валидации (п.30 чек-листа). Ставим в начале, чтобы она
            # попала ВО ВСЕ результаты, включая ранние выходы ниже. Без неё нельзя
            # понять, когда адрес проверяли, и решить, пора ли перепроверять (п.21, п.43).
            data["validated_at"] = _utc_now().strftime("%Y-%m-%d %H:%M")

            # Классификация провайдера и типа домена (п.34, п.35, п.38)
            prov_name, dom_type = classify_domain(email)
            data["provider_name"] = prov_name
            data["domain_type"] = dom_type

            # Шаг 1.1: Проверка на одноразовый/временный домен (Disposable + SpamFilter)
            if is_disposable(email):
                data["engagement_score"] = 0
                data["engagement_grade"] = "Dead"
                data["provider_type"] = "Disposable"
                data["provider_name"] = "Disposable"
                data["domain_type"] = "Disposable"
                self.callbacks['on_result'](email, "Trap/Disposable", "Disposable Email Domain", "N/A", data)
                return

            # Шаг 1.1b: Дополнительная проверка через SpamFilter (внешние чёрные списки)
            if self.filter and hasattr(self.filter, 'is_spam_or_disposable'):
                if self.filter.is_spam_or_disposable(email):
                    data["engagement_score"] = 0
                    data["engagement_grade"] = "Dead"
                    data["provider_type"] = "Spam Trap"
                    data["provider_name"] = "Spam Trap"
                    data["domain_type"] = "Spam Trap"
                    self.callbacks['on_result'](email, "Trap/Disposable", "External Blacklist Match", "N/A", data)
                    return

            # Шаг 1.2: Проверка на ролевые ящики (Role-based) — п.2.1
            # НЕ убиваем их! Помечаем как отдельную категорию "Role-based".
            is_role = False
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
                if local_p.lower() in roles:
                    is_role = True

            # Шаг 1.5: Проверка через ИИ (Машинное обучение)
            if enable_ai and self.ai:
                if self.ai.predict(email):
                    data["engagement_score"] = 0
                    data["engagement_grade"] = "Dead"
                    data["provider_type"] = "Suspicious"
                    self.callbacks['on_result'](email, "Trap/Disposable", "AI: Bot/Spam Pattern", "N/A", data)
                    return
                
            # Шаг 3: Глубокий SMTP Ping
            if deep_ping:
                res = self.network.check_email(email)
                raw_status = res["status"]
                warn_if_proxies_dead()

                # Greylisted — складываем в очередь для повторной проверки (п.2.4)
                if raw_status == "greylisted":
                    greylisted_queue.put((email, data, is_role))
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
                
                # Сохраняем оригинальный SMTP-статус для скоринга (фикс бага Role-based)
                original_smtp_status = status_display
                
                # Если Role-based — перезаписываем отображаемый статус
                if is_role:
                    status_display = "Role-based"
                
                # Enrichment для ВСЕХ статусов (не только Valid)
                # Приоритет: данные из файла > ML-предсказание > пустое поле
                name = data.get("name", "")
                gender = data.get("gender", "")
                country = data.get("country", "")
                
                if not name or not gender or not country:
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

                # Gravatar-проверка (бонусный сигнал реального человека)
                has_avatar = False
                if status_display in ("Valid", "Risky", "Role-based"):
                    try:
                        has_avatar = self.gravatar_checker.has_gravatar(email)
                    except Exception:
                        pass
                
                # DNS Health Score (для Engagement Score)
                dns_score = 0
                try:
                    domain = email.split("@")[1].lower()
                    dns_info = self.network.check_dns_health(domain)
                    dns_score = dns_info.get("score", 0)
                except Exception:
                    pass
                
                # Новые сигналы: DNSBL, PTR, STARTTLS
                in_dnsbl = False
                has_ptr = None  # None = не проверено, чтобы скоринг не штрафовал вслепую
                has_starttls = res.get("has_starttls", None)
                mx_host = res.get("mx_record", "")
                if mx_host and mx_host != "N/A":
                    try:
                        in_dnsbl = self.network.check_dnsbl(mx_host)
                    except Exception:
                        pass
                    try:
                        has_ptr = self.network.check_ptr(mx_host)
                    except Exception:
                        pass
                
                # WHOIS: возраст домена
                domain_age = -1
                try:
                    domain = email.split("@")[1].lower()
                    domain_age = self._get_domain_age_days(domain)
                except Exception:
                    pass
                
                # HTTP-пинг: живой ли сайт (только для корпоративных доменов)
                has_live_site = True
                try:
                    domain = email.split("@")[1].lower()
                    if domain not in GLOBAL_VERIFIED_DOMAINS:
                        has_live_site = self._check_http_alive(domain)
                except Exception:
                    pass
                
                # Вычисление Engagement Score (с ВСЕМИ новыми сигналами)
                score_result = calculate_engagement_score(
                    email=email,
                    smtp_status=status_display,
                    smtp_reason=res.get("reason", ""),
                    has_gravatar=has_avatar,
                    is_disposable=False,  # Уже отсеяны выше
                    dns_health_score=dns_score,
                    domain_age_days=domain_age,
                    name_extracted=name,
                    is_role_based=is_role,
                    server_outdated=res.get("server_outdated", False),
                    has_ptr=has_ptr,
                    has_starttls=has_starttls,
                    in_dnsbl=in_dnsbl,
                    has_live_website=has_live_site,
                    original_smtp_status=original_smtp_status,
                    machine_generated=looks_machine_generated(email),
                    is_parked_domain=is_parked_domain(res.get("mx_record", "")),
                )
                
                data["engagement_score"] = score_result["score"]
                data["engagement_grade"] = score_result["grade"]
                data["provider_type"] = score_result["provider_type"]
                data["has_gravatar"] = has_avatar

                # Уточняем провайдера теперь, когда известна MX-запись:
                # по ней видно, сидит ли свой домен на Google Workspace / Microsoft 365.
                prov_name, dom_type = classify_domain(email, res.get("mx_record", ""))
                data["provider_name"] = prov_name
                data["domain_type"] = dom_type

                self.callbacks['on_result'](email, status_display, res["reason"], res.get("mx_record", "N/A"), data)
            else:
                self.callbacks['on_result'](email, "Unverified", "Skipped Ping", "N/A", data)

        # Аппаратное ограничение количества потоков для предотвращения зависания сети и роутера
        safe_threads = min(int(threads), 300)
        
        import queue
        task_queue = queue.Queue(maxsize=safe_threads * 2)
        seen_emails = set()
        duplicates_skipped = 0
        queued_count = 0

        def feeder_thread():
            nonlocal duplicates_skipped, queued_count
            from core.streamer import StreamLoader
            for email, data in StreamLoader(email_sources).stream_emails():
                if not self.is_running:
                    break

                if fix_typos:
                    email = self.cleaner.clean_email(email)

                if not email:
                    continue

                # Дедуп по КАНОНИЧЕСКОМУ виду: john.doe@gmail.com и johndoe@gmail.com —
                # один и тот же ящик, и слать туда дважды нельзя (жалобы на спам).
                # В обработку при этом уходит оригинальный адрес.
                dedup_key = normalize_for_dedup(email)
                if dedup_key in seen_emails:
                    duplicates_skipped += 1
                    continue

                seen_emails.add(dedup_key)
                queued_count += 1
                task_queue.put((email, data))
                
            for _ in range(safe_threads):
                task_queue.put(None)

            # Уточняем знаменатель прогресса: в очередь попали только уникальные
            # адреса, а стартовая оценка считалась по сырым строкам. Без этого
            # бар застревает (например на 5/17) и выглядит как зависание.
            nonlocal total_emails
            total_emails = queued_count
            if 'on_unique_count' in self.callbacks:
                self.callbacks['on_unique_count'](queued_count)

            if duplicates_skipped:
                self.callbacks['on_log'](
                    f"[INFO] Схлопнуто дублей: {duplicates_skipped} "
                    "(один ящик записан по-разному — двойная отправка предотвращена). "
                    f"К проверке: {queued_count}.", "info")

        t_feeder = threading.Thread(target=feeder_thread, daemon=True)
        t_feeder.start()
        
        progress_lock = threading.Lock()
        
        def worker_loop():
            nonlocal processed_count
            while self.is_running:
                item = task_queue.get()
                if item is None:
                    break
                try:
                    process_single(item)
                except Exception as e:
                    # Without this the whole worker thread would die and silently
                    # drop every remaining email it was going to handle.
                    email = item[0] if item else "?"
                    self.callbacks['on_log'](f"[DEAD] Ошибка обработки {email}: {type(e).__name__}: {e}", "dead")
                    try:
                        self.callbacks['on_result'](email, "Unknown", f"Processing error: {type(e).__name__}", "N/A", item[1])
                    except Exception:
                        pass
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
                        email, data, is_role = greylisted_queue.get_nowait()
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
                    
                    # Сохраняем оригинальный SMTP-статус для скоринга (фикс бага Role-based)
                    original_smtp_status = status_display
                    
                    if is_role:
                        status_display = "Role-based"
                    
                    # Enrichment для ВСЕХ статусов (не только Valid)
                    name = data.get("name", "")
                    gender = data.get("gender", "")
                    country = data.get("country", "")
                    if not name or not gender or not country:
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
                    
                    # Gravatar + Engagement Score
                    has_avatar = False
                    if status_display in ("Valid", "Risky", "Role-based"):
                        try:
                            has_avatar = self.gravatar_checker.has_gravatar(email)
                        except Exception:
                            pass
                    
                    dns_score = 0
                    try:
                        domain = email.split("@")[1].lower()
                        dns_info = self.network.check_dns_health(domain)
                        dns_score = dns_info.get("score", 0)
                    except Exception:
                        pass
                    
                    # Новые сигналы для retry
                    in_dnsbl = False
                    has_ptr = None  # None = не проверено, чтобы скоринг не штрафовал вслепую
                    has_starttls = res.get("has_starttls", None)
                    mx_host = res.get("mx_record", "")
                    if mx_host and mx_host != "N/A":
                        try:
                            in_dnsbl = self.network.check_dnsbl(mx_host)
                        except Exception:
                            pass
                        try:
                            has_ptr = self.network.check_ptr(mx_host)
                        except Exception:
                            pass
                    
                    domain_age = -1
                    try:
                        domain = email.split("@")[1].lower()
                        domain_age = self._get_domain_age_days(domain)
                    except Exception:
                        pass
                    
                    has_live_site = True
                    try:
                        domain = email.split("@")[1].lower()
                        if domain not in GLOBAL_VERIFIED_DOMAINS:
                            has_live_site = self._check_http_alive(domain)
                    except Exception:
                        pass
                    
                    score_result = calculate_engagement_score(
                        email=email,
                        smtp_status=status_display,
                        smtp_reason=res.get("reason", ""),
                        has_gravatar=has_avatar,
                        is_disposable=False,
                        dns_health_score=dns_score,
                        domain_age_days=domain_age,
                        name_extracted=name,
                        is_role_based=is_role,
                        server_outdated=res.get("server_outdated", False),
                        has_ptr=has_ptr,
                        has_starttls=has_starttls,
                        in_dnsbl=in_dnsbl,
                        has_live_website=has_live_site,
                        original_smtp_status=original_smtp_status,
                        machine_generated=looks_machine_generated(email),
                        is_parked_domain=is_parked_domain(res.get("mx_record", "")),
                    )
                    
                    data["engagement_score"] = score_result["score"]
                    data["engagement_grade"] = score_result["grade"]
                    data["provider_type"] = score_result["provider_type"]
                    data["has_gravatar"] = has_avatar

                    prov_name, dom_type = classify_domain(email, res.get("mx_record", ""))
                    data["provider_name"] = prov_name
                    data["domain_type"] = dom_type
                    data["validated_at"] = _utc_now().strftime("%Y-%m-%d %H:%M")
                    
                    self.callbacks['on_result'](email, status_display, res["reason"], res.get("mx_record", "N/A"), data)
                    retry_count += 1
                
                self.callbacks['on_log'](f"[INFO] Перепроверка Greylisted завершена: {retry_count} почт обработано.", "info")

        # Страховка: всё, что осталось в очереди — не перепроверено (нажали «Стоп»,
        # выключен deep_ping, или прогон прервался). Раньше такие адреса молча
        # исчезали: в выдачу они не попадали ни на первом проходе, ни на втором,
        # а прогресс-бар уже считал их обработанными. Отдаём их как Unknown.
        leftover = 0
        while True:
            try:
                email, data, is_role = greylisted_queue.get_nowait()
            except Exception:
                break
            leftover += 1
            data["validated_at"] = _utc_now().strftime("%Y-%m-%d %H:%M")
            try:
                self.callbacks['on_result'](
                    email, "Unknown", "Greylisted (перепроверка не выполнена)", "N/A", data)
            except Exception:
                pass
        if leftover:
            self.callbacks['on_log'](
                f"[INFO] {leftover} greylisted-адресов возвращены как Unknown "
                "(перепроверка не выполнена) — потеряться они не могут.", "info")

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
