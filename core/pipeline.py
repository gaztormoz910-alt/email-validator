# core/pipeline.py
import os
import threading
import time
import json
import datetime
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.cache import ResultCache
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
from core.provider import (classify_domain, country_from_domain,
                           country_from_location, extend_free_domains,
                           is_free_mail_domain)
from core.heuristics import (extract_birth_year, looks_machine_generated,
                             is_parked_domain, is_role_based)
from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS


# Причины Unknown, которые стоит перепроверить: они говорят о сбое НАШЕЙ стороны
# (прокси, сеть, лимит скорости), а не о ящике. Повтор другим прокси часто
# превращает их в однозначный вердикт.
_TRANSIENT_MARKERS = (
    "timeout", "proxy dead", "server disconnected", "smtp connect error",
    "rate limit", "service busy", "all proxies dead", "temp unavailable",
    "temp error", "our ip blocked", "our ip blacklisted", "transaction failed",
    "mail from rejected", "too many recipients",
    # DNS через прокси не ответил — домен не проверен, а не мёртв. Повтор другим
    # прокси обычно решает.
    "dns не удалось спросить",
)

# Эти Unknown повторять бессмысленно — ответ не изменится от смены прокси
_PERMANENT_UNKNOWN_MARKERS = (
    "catch-all", "catchall", "fcrdns", "обратного dns", "не проверяется",
)


def _is_transient_failure(raw_status: str, reason: str) -> bool:
    """True, если Unknown вызван временным сбоем и заслуживает повтора."""
    if raw_status != "unknown":
        return False
    low = (reason or "").lower()
    if any(m in low for m in _PERMANENT_UNKNOWN_MARKERS):
        return False
    return any(m in low for m in _TRANSIENT_MARKERS)


def _utc_now():
    """Текущее время как aware-datetime в UTC."""
    return datetime.datetime.now(datetime.timezone.utc)


def _as_utc(dt):
    """Приводит datetime к aware-UTC. Naive-даты считаем уже записанными в UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)


def _fmt_stamp(iso_stamp):
    """ISO-время из кэша в тот же формат, что и у свежих проверок."""
    try:
        return _as_utc(datetime.datetime.fromisoformat(iso_stamp)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""


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
        # Кэш доказанных вердиктов между прогонами (см. core/cache.py)
        self.cache = None
        self._cache_hits = 0
        self._cache_lock = threading.Lock()
        self._domain_age_cache = {}
        self._domain_age_lock = threading.Lock()
        self._http_alive_cache = {}
        self._http_alive_lock = threading.Lock()
        # Замки «один в полёте» на домен. Без них сто потоков, наткнувшись на
        # новый домен одновременно, делают сто одинаковых запросов WHOIS —
        # кэш спасает только тех, кто пришёл после первого ответа.
        self._inflight = {}
        self._inflight_guard = threading.Lock()

    def _domain_gate(self, key):
        """Замок на конкретный домен: остальные ждут результата, а не дублируют запрос."""
        with self._inflight_guard:
            gate = self._inflight.get(key)
            if gate is None:
                gate = threading.Lock()
                self._inflight[key] = gate
            return gate
        
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
        """Возраст домена в днях через WHOIS/RDAP. Кэшируется, запрос не дублируется."""
        with self._domain_age_lock:
            if domain in self._domain_age_cache:
                return self._domain_age_cache[domain]

        with self._domain_gate("age:" + domain):
            # Пока ждали замок, сосед мог всё посчитать — проверяем кэш снова
            with self._domain_age_lock:
                if domain in self._domain_age_cache:
                    return self._domain_age_cache[domain]
            return self._fetch_domain_age(domain)

    def _fetch_domain_age(self, domain):
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
        """Есть ли живой сайт на домене (HEAD). Кэшируется, запрос не дублируется."""
        with self._http_alive_lock:
            if domain in self._http_alive_cache:
                return self._http_alive_cache[domain]

        with self._domain_gate("http:" + domain):
            with self._http_alive_lock:
                if domain in self._http_alive_cache:
                    return self._http_alive_cache[domain]
            return self._fetch_http_alive(domain)

    def _fetch_http_alive(self, domain):
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

    def _enrich_and_score(self, email, data, res, status_display,
                          original_smtp_status, is_role, enable_ai):
        """Обогащение и скоринг одного адреса.

        Раньше этот код был скопирован дважды — в первый проход и в
        перепроверку — и копии успели разойтись. Теперь он один.
        """
        domain = email.rsplit("@", 1)[1].lower() if "@" in email else ""
        mx_host = res.get("mx_record", "")

        # --- Имя -----------------------------------------------------------
        name = data.get("name", "")
        name_source = "файл" if name else ""
        if not name:
            name = self.name_extractor.extract_name(email) or ""
            if name:
                name_source = "адрес"
            if name and enable_ai and not self.ml_predictor.is_person(name):
                name, name_source = "", ""   # NER распознал организацию, не человека

        # --- Страна --------------------------------------------------------
        # Порядок принципиален. Домен знает страну ТОЧНО (web.de — Германия),
        # а распределение имени по странам размазано: Ivan даёт Italy 0.235
        # при Mexico 0.135. Раньше имя стояло выше домена и превращало
        # bogdan.petrov@yandex.ru в итальянца.
        country = data.get("country", "")
        country_source = "файл" if country else ""
        if not country:
            country = country_from_domain(domain)
            if country:
                country_source = "домен"
        if not country:
            # Домен молчит (.com/.net). Профиль Gravatar, если он был получен
            # при разборе имени, знает город и страну точнее любой догадки.
            location = (self.name_extractor.last_profile().get("location") or "").strip()
            if location:
                country = country_from_location(location) or ""
                if country:
                    country_source = "Gravatar"
        if not country and name:
            # Последняя попытка — по имени, и только при явной уверенности
            country = self.ml_predictor.predict_country(name)
            if country:
                country_source = "имя"

        # --- Пол -----------------------------------------------------------
        gender = data.get("gender", "")
        gender_source = "файл" if gender else ""
        if not gender:
            # Страна повышает точность на неоднозначных именах:
            # Andrea в Италии — мужское, в Германии — женское.
            gender = self.ml_predictor.predict_gender(name, country)
            if gender:
                gender_source = "имя"

        birth_year = data.get("birth_year", "") or extract_birth_year(email) or ""

        data["name"] = name
        data["gender"] = gender
        data["country"] = country
        data["birth_year"] = birth_year
        # Откуда взято — чтобы в выгрузке отличать данные из файла от догадки
        data["name_source"] = name_source
        accounts = self.name_extractor.last_profile().get("accounts") or []
        if accounts:
            data["social_accounts"] = ", ".join(accounts[:5])
        data["gender_source"] = gender_source
        data["country_source"] = country_source

        # --- Сигналы живости ------------------------------------------------
        has_avatar = False
        if status_display in ("Valid", "Risky", "Role-based"):
            try:
                has_avatar = self.gravatar_checker.has_gravatar(email)
            except Exception:
                pass

        dns_score = 0
        try:
            dns_info = self.network.check_dns_health(domain, mx_record=mx_host)
            dns_score = dns_info.get("score", 0)
        except Exception:
            pass

        in_dnsbl = False
        has_ptr = None  # None = не проверено, чтобы скоринг не штрафовал вслепую
        has_starttls = res.get("has_starttls", None)
        if mx_host and mx_host != "N/A":
            try:
                in_dnsbl = self.network.check_dnsbl(mx_host)
            except Exception:
                pass
            try:
                has_ptr = self.network.check_ptr(mx_host)
            except Exception:
                pass

        # WHOIS и HTTP-HEAD стоят до 1.9 с и до 6.8 с на новый домен. Тратить
        # их на адрес, по которому вердикта нет, бессмысленно: эти сигналы
        # дают 3-5 баллов, а балл начисляется только Valid и Risky.
        domain_age = -1
        has_live_site = True
        if status_display in ("Valid", "Risky", "Role-based"):
            try:
                domain_age = self._get_domain_age_days(domain)
            except Exception:
                pass
            try:
                if domain not in GLOBAL_VERIFIED_DOMAINS and not is_free_mail_domain(domain):
                    has_live_site = self._check_http_alive(domain)
            except Exception:
                pass

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
            # Парковка могла быть и на втором MX, и на A-записи без MX
            is_parked_domain=is_parked_domain(res.get("mx_records") or mx_host),
        )

        data["engagement_score"] = score_result["score"]
        data["engagement_grade"] = score_result["grade"]
        data["provider_type"] = score_result["provider_type"]
        data["has_gravatar"] = has_avatar

        # Провайдера уточняем теперь, когда известна MX-запись: по ней видно,
        # сидит ли свой домен на Google Workspace или Microsoft 365.
        prov_name, dom_type = classify_domain(email, mx_host)
        data["provider_name"] = prov_name
        data["domain_type"] = dom_type

        # В кэш уходит SMTP-статус, а не отображаемый: ролевой ящик
        # показывается как Role-based, но доказан-то он как Valid.
        if self.cache:
            self.cache.put(email, original_smtp_status, res.get("reason", ""),
                           mx_host or "N/A", data)

    def _start_profile_refresher(self, timeout, workers, interval=600):
        """Фоновое обновление профиля прокси раз в interval секунд."""
        self._refresh_stop = threading.Event()

        def loop():
            while not self._refresh_stop.wait(interval):
                if not self.is_running or not self.network:
                    return
                try:
                    stats = self.network.refresh_proxy_profiles(
                        timeout=timeout, workers=workers)
                except Exception:
                    continue
                if not stats.get("checked"):
                    continue
                if stats["ip_changed"] or stats["ptr_lost"] or stats["ptr_gained"]:
                    self.callbacks['on_log'](
                        f"[PROXY] Профиль обновлён: сменили IP — {stats['ip_changed']}, "
                        f"потеряли PTR — {stats['ptr_lost']}, "
                        f"получили PTR — {stats['ptr_gained']}.", "info")

        self._refresh_thread = threading.Thread(target=loop, daemon=True)
        self._refresh_thread.start()

    def _stop_profile_refresher(self):
        stop = getattr(self, "_refresh_stop", None)
        if stop is not None:
            stop.set()

    def setup(self, timeout=5, enable_ai=False, proxies=None, threads=100, use_cache=True):
        # Гибридный режим: Whitelist + DNS-проверка неизвестных доменов
        self.callbacks['on_log']("[INFO] Подготовка валидатора (гибридный режим: Whitelist + DNS)...", "info")

        # Кэш вердиктов прошлых прогонов. Хранит только доказанное — Valid и
        # Invalid/Bounce; Unknown и Risky не кэшируются никогда, иначе сбой
        # нашей стороны закрепился бы за адресом навсегда.
        self.cache = None
        self._cache_hits = 0
        if use_cache:
            try:
                cache = ResultCache()
                if cache.enabled:
                    dropped = cache.purge_expired()
                    self.cache = cache
                    msg = f"[INFO] Кэш вердиктов: {cache.size()} адресов из прошлых прогонов."
                    if dropped:
                        msg += f" Просроченных удалено: {dropped}."
                    self.callbacks['on_log'](msg, "info")
                else:
                    self.callbacks['on_log'](
                        "[DEAD] Кэш вердиктов недоступен (не удалось открыть базу) — "
                        "проверяю всё заново.", "dead")
            except Exception as e:
                self.callbacks['on_log'](
                    f"[DEAD] Кэш вердиктов не включён ({type(e).__name__}).", "dead")
        
        # Обновляем disposable/spam-списки ДО загрузки SpamFilter, чтобы он
        # сразу подхватил свежие данные. Списки переустанавливаются (замена, не
        # накопление), а качаются только если на сервере реально есть новое.
        try:
            self.callbacks['on_log']("[INFO] Проверка обновлений disposable-списков...", "info")
            BlacklistDownloader().download_all(log_callback=self.callbacks['on_log'])
        except Exception as e:
            self.callbacks['on_log'](f"[DEAD] Обновление списков не удалось ({type(e).__name__}), использую локальные.", "dead")

        # Список бесплатных почтовиков. Он НЕ для отбраковки, а для скоринга:
        # без него сотни бесплатных сервисов считаются корпоративными и
        # получают +5, которого не получает gmail.com.
        try:
            free_path = os.path.join("data", "free_providers.txt")
            if os.path.exists(free_path):
                with open(free_path, "r", encoding="utf-8") as f:
                    added = extend_free_domains(line.strip() for line in f
                                                if line.strip() and not line.startswith("#"))
                if added:
                    self.callbacks['on_log'](
                        f"[INFO] Бесплатных почтовиков добавлено: {added}. "
                        "Скоринг больше не путает их с корпоративными.", "info")
        except Exception:
            pass

        # Подключаем SpamFilter из внешних файлов
        try:
            self.filter = SpamFilter(log_callback=self.callbacks.get('on_log'))
            self.callbacks['on_log'](f"[INFO] SpamFilter загружен ({self.filter.get_count() if hasattr(self.filter, 'get_count') else '?'} доменов).", "info")
            # Сливаем свежие списки во встроенную базу: она захардкожена и сама
            # не обновляется, зато умеет проверять ПОДДОМЕНЫ (foo.mailinator.com),
            # чего SpamFilter не делает — он сверяет только точное имя домена.
            try:
                from core.disposable import extend_disposable_domains, get_disposable_count
                added = extend_disposable_domains(self.filter.blacklist_domains)
                if added:
                    self.callbacks['on_log'](
                        f"[INFO] В базу одноразовых добавлено {added} доменов "
                        f"(всего {get_disposable_count()}), поддомены тоже ловятся.", "info")
            except Exception:
                pass
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

        proxy_profiles = {}
        if proxies:
            from core.network import filter_live_proxies, dedupe_proxies
            # Один прокси, записанный дважды, проверялся бы дважды и занимал
            # два места в ротации — сначала схлопываем повторы.
            before = len(proxies)
            proxies = dedupe_proxies(proxies)
            if before != len(proxies):
                self.callbacks['on_log'](
                    f"[INFO] Убрано повторов в списке прокси: {before - len(proxies)} "
                    f"(осталось {len(proxies)}).", "info")
            self.callbacks['on_log'](f"[INFO] Тестирование {len(proxies)} прокси-серверов (потоков: {threads}, таймаут: {timeout}с)...", "info")
            # Теперь таймаут строго подчиняется твоему ползунку (никаких ограничений!)
            live_proxies = filter_live_proxies(proxies, timeout=timeout, threads=threads, progress_callback=self.callbacks['on_progress'], log_callback=self.callbacks.get('on_log'))
            self.callbacks['on_log'](f"[INFO] Проверка завершена. Найдено рабочих прокси: {len(live_proxies)} из {len(proxies)}.", "info")
            if 'on_proxies_tested' in self.callbacks:
                self.callbacks['on_proxies_tested'](len(live_proxies), len(proxies))
            if not live_proxies:
                self.callbacks['on_log']("[DEAD] Внимание: Ни один из загруженных прокси не работает. Валидация скорее всего завершится с ошибками.", "dead")
            proxies = live_proxies

            # Профилируем прокси: реальный выходной IP, обратный DNS, чёрные списки.
            # Выходной IP спрашиваем у самого Gmail (он сообщает его в ответе на
            # EHLO) — стороннего сервиса не нужно. Проверять надо именно ЕГО:
            # адрес подключения к прокси совпадает с выходным не всегда.
            proxy_profiles = {}
            if live_proxies:
                try:
                    from core.network import profile_proxies
                    self.callbacks['on_log'](
                        f"[INFO] Профилирование {len(live_proxies)} прокси "
                        "(выходной IP, PTR, чёрные списки)...", "info")

                    def on_prof(done, total, ptr_n, bl_n):
                        self.callbacks['on_log'](
                            f"[PROXY] Профиль... {done}/{total} | с PTR: {ptr_n} | в списках: {bl_n}", "info")

                    # Потоки берём из ползунка: раньше здесь было жёсткое 30, и
                    # список в несколько тысяч прокси профилировался часами.
                    proxy_profiles = profile_proxies(
                        live_proxies, timeout=timeout, workers=threads,
                        progress_callback=on_prof)

                    vals = list(proxy_profiles.values())
                    ptr_n = sum(1 for v in vals if v["has_ptr"] is True)
                    bl_n = sum(1 for v in vals if v["in_dnsbl"])
                    known_ip = sum(1 for v in vals if v["exit_ip"])
                    dirty_n = sum(1 for v in vals if v.get("rdns_dirty"))
                    outlook_n = sum(1 for v in vals if v.get("outlook_ok") is True)
                    clean_n = len(live_proxies) - bl_n

                    lats = sorted(v["latency_ms"] for v in vals if v.get("latency_ms"))
                    if lats:
                        median = lats[len(lats) // 2]
                        self.callbacks['on_log'](
                            f"[INFO] Скорость прокси: медиана {median} мс, "
                            f"быстрейший {lats[0]} мс, медленнейший {lats[-1]} мс.", "info")

                    self.callbacks['on_log'](
                        f"[INFO] Профиль готов: выходной IP определён у {known_ip} из "
                        f"{len(live_proxies)}, с PTR — {ptr_n}, в чёрных списках — {bl_n}.", "info")

                    if outlook_n is not None:
                        self.callbacks['on_log'](
                            f"[INFO] Microsoft реально принял {outlook_n} прокси из "
                            f"{len(live_proxies)} (проверено пробой до MAIL FROM, "
                            "а не по спискам).", "info")
                    if dirty_n:
                        self.callbacks['on_log'](
                            f"[DEAD] У {dirty_n} прокси имя в PTR выдаёт прокси/VPN/динамику "
                            "(proxy, vpn, tor, pool...). Почтовики такие штрафуют даже "
                            "при валидном обратном DNS.", "dead")

                    if ptr_n:
                        self.callbacks['on_log'](
                            f"[INFO] Yahoo/AOL пойдут через {ptr_n} прокси с PTR.", "info")
                    else:
                        self.callbacks['on_log'](
                            "[DEAD] Обратного DNS (PTR) нет ни у одного прокси — Yahoo, AOL "
                            "и Verizon проверить не получится. Остальные домены проверятся.", "dead")

                    if clean_n:
                        self.callbacks['on_log'](
                            f"[INFO] Outlook/iCloud/GMX пойдут через {clean_n} прокси "
                            "с чистой репутацией.", "info")
                    else:
                        self.callbacks['on_log'](
                            "[DEAD] ВСЕ прокси числятся в чёрных списках — Outlook, iCloud "
                            "и GMX будут молчать. Нужны прокси с чистым IP.", "dead")
                except Exception as e:
                    self.callbacks['on_log'](
                        f"[DEAD] Профилирование прокси не удалось ({type(e).__name__}).", "dead")

        self.network = NetworkValidator(timeout=timeout, proxies=proxies)
        if proxy_profiles:
            self.network.set_proxy_profiles(proxy_profiles)
            # Профиль протухает: у ротирующегося прокси выходной IP меняется
            # по ходу прогона, и маршрутизация продолжает считать, что PTR
            # на месте. Обновляем в фоне, чтобы не держать воркеры.
            self._start_profile_refresher(timeout=timeout, workers=threads)
        
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
        # queue.Queue уже потокобезопасна — отдельный лок не нужен
        greylisted_queue = queue_module.Queue()

        # Статистика вердиктов по домену. Если у домена МНОГО адресов и ВСЕ до
        # единого ответили 250 OK — это почти наверняка catch-all, даже когда
        # тройная проба сказала обратное (она могла сорваться на прокси).
        # Тройная проба смотрит 3 выдуманных адреса, а здесь мы видим реальную
        # выборку из самой базы — сигнал сильнее.
        domain_stats = {}
        domain_stats_lock = threading.Lock()
        
        # Предзагрузка тяжелых модулей один раз (O(1) вместо O(N) в потоках)
        if not self.name_extractor:
            self.callbacks['on_log']("[INFO] Загрузка модуля извлечения имен...", "info")
            self.name_extractor = NameExtractor(enable_osint=enable_osint,
                                                proxy_provider=self._http_proxies)
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
                    # Не «ловушка»: это совпадение с внешним списком одноразовых
                    # доменов. Настоящих списков спам-ловушек в открытом доступе
                    # нет — опубликованная ловушка перестаёт работать.
                    data["provider_type"] = "Disposable (внешний список)"
                    data["provider_name"] = "Disposable"
                    data["domain_type"] = "Disposable"
                    self.callbacks['on_result'](email, "Trap/Disposable", "External Blacklist Match", "N/A", data)
                    return

            # Шаг 1.2: Проверка на ролевые ящики (Role-based) — п.2.1
            # НЕ убиваем их! Помечаем как отдельную категорию "Role-based".
            # Общая функция ловит не только точные совпадения (info@), но и
            # sales-team@, info.desk@, noreply2@, do-not-reply@, mailer-daemon@
            is_role = is_role_based(email)

            # Шаг 1.5: Проверка через ИИ (Машинное обучение)
            if enable_ai and self.ai:
                if self.ai.predict(email):
                    data["engagement_score"] = 0
                    data["engagement_grade"] = "Dead"
                    data["provider_type"] = "Suspicious"
                    self.callbacks['on_result'](email, "Trap/Disposable", "AI: Bot/Spam Pattern", "N/A", data)
                    return
                
            # Шаг 2: Кэш прошлых прогонов. Доказанный вердикт SMTP от перезапуска
            # не меняется, поэтому тратить на него прокси и время незачем.
            # В кэше лежат только Valid и Invalid/Bounce — см. core/cache.py.
            if deep_ping and self.cache:
                cached = self.cache.get(email)
                if cached:
                    # Данные из файла базы важнее кэша — их не перезаписываем.
                    # А вот вычисленное прошлым прогоном (скор, провайдер по
                    # MX-записи) точнее того, что проставлено выше вслепую.
                    # Пустая строка в data — это «в файле колонки не было»,
                    # а не «значение пустое»: такие поля кэш заполняет.
                    computed = ("engagement_score", "engagement_grade", "provider_type",
                                "provider_name", "domain_type", "has_gravatar")
                    for key, value in (cached.get("data") or {}).items():
                        if key in computed or not data.get(key):
                            data[key] = value
                    # Показываем ДАТУ ИСХОДНОЙ проверки, а не сегодняшнюю:
                    # иначе кэш выглядел бы как свежая проверка.
                    data["validated_at"] = _fmt_stamp(cached["checked_at"]) or data["validated_at"]
                    data["from_cache"] = True
                    status_display = "Role-based" if is_role else cached["status"]
                    with self._cache_lock:
                        self._cache_hits += 1
                    self.callbacks['on_result'](
                        email, status_display,
                        f"{cached['reason']} [из кэша, {cached['age_days']} дн. назад]",
                        cached["mx"], data)
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

                # Временный отказ (таймаут, сдохший прокси, лимит скорости, блок по
                # IP) — это НЕ вердикт о ящике, а сбой нашей стороны. Отправляем в ту
                # же очередь: через паузу лимиты отпускают, прокси восстанавливаются,
                # и повтор другим прокси часто даёт однозначный ответ вместо Unknown.
                if _is_transient_failure(raw_status, res.get("reason", "")):
                    greylisted_queue.put((email, data, is_role))
                    return

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
                
                # Копим статистику по домену для пост-анализа catch-all
                try:
                    dom_key = email.rsplit("@", 1)[1].lower()
                    with domain_stats_lock:
                        st = domain_stats.setdefault(dom_key, {"total": 0, "valid": 0})
                        st["total"] += 1
                        if raw_status == "valid":
                            st["valid"] += 1
                except Exception:
                    pass

                # Сохраняем оригинальный SMTP-статус для скоринга (фикс бага Role-based)
                original_smtp_status = status_display
                
                # Если Role-based — перезаписываем отображаемый статус
                if is_role:
                    status_display = "Role-based"
                
                self._enrich_and_score(email, data, res, status_display,
                                       original_smtp_status, is_role, enable_ai)

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
        
        # === Повторная проверка: greylisted + временные отказы (п.2.4) ===
        # Сюда попадают адреса, по которым НЕТ вердикта о ящике: сервер попросил
        # прийти позже (greylisting) либо сбой был на нашей стороне (таймаут,
        # прокси, лимит скорости). Пауза даёт лимитам отпустить, а повтор идёт
        # другим прокси — значительная часть превращается в однозначный ответ.
        greylisted_count = greylisted_queue.qsize()
        if greylisted_count > 0 and self.is_running and deep_ping:
            self.callbacks['on_log'](f"[INFO] Отложено на перепроверку: {greylisted_count} адресов (greylisting и временные сбои). Ожидание 90 сек...", "info")
            
            # Ждём 90 секунд (серверы с greylisting ожидают повторной попытки через 1-5 мин)
            for i in range(90):
                if not self.is_running:
                    break
                time.sleep(1)
            
            if self.is_running:
                self.callbacks['on_log'](f"[INFO] Начинаю перепроверку {greylisted_count} адресов...", "info")
                retry_count = 0
                retry_lock = threading.Lock()

                def retry_one(entry):
                    """Обрабатывает один отложенный адрес. Вызывается из пула потоков."""
                    nonlocal retry_count
                    email, data, is_role = entry
                    if not self.is_running:
                        return
                    
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
                    
                    self._enrich_and_score(email, data, res, status_display,
                                           original_smtp_status, is_role, enable_ai)

                    self.callbacks['on_result'](email, status_display, res["reason"], res.get("mx_record", "N/A"), data)
                    with retry_lock:
                        retry_count += 1

                # Забираем всё из очереди и обрабатываем ПАРАЛЛЕЛЬНО. Раньше повтор
                # шёл в один поток: на тысячах отложенных адресов это растягивалось
                # на часы, в течение которых их не было в выдаче.
                pending = []
                while True:
                    try:
                        pending.append(greylisted_queue.get_nowait())
                    except Exception:
                        break

                retry_workers = max(1, min(safe_threads, len(pending)))
                with ThreadPoolExecutor(max_workers=retry_workers) as retry_pool:
                    futures = [retry_pool.submit(retry_one, entry) for entry in pending]
                    for fut in as_completed(futures):
                        try:
                            fut.result()
                        except Exception as e:
                            self.callbacks['on_log'](
                                f"[DEAD] Ошибка перепроверки: {type(e).__name__}: {e}", "dead")

                self.callbacks['on_log'](
                    f"[INFO] Перепроверка завершена: {retry_count} из {len(pending)} адресов "
                    "получили окончательный вердикт.", "info")

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

        # Пост-анализ: домены, где ВСЕ адреса ответили 250 OK, почти наверняка
        # catch-all — они принимают что угодно, и их Valid ничего не доказывает.
        # Тройная проба смотрит 3 выдуманных адреса и могла сорваться; здесь же
        # выборка из реальной базы, поэтому сигнал надёжнее.
        try:
            suspicious = []
            with domain_stats_lock:
                for dom, st in domain_stats.items():
                    if st["total"] >= 5 and st["valid"] == st["total"]:
                        suspicious.append((dom, st["total"]))
            if suspicious:
                suspicious.sort(key=lambda x: -x[1])
                self.callbacks['on_log'](
                    "[DEAD] Подозрение на catch-all: у этих доменов ВСЕ проверенные "
                    "адреса ответили 250 OK. Их Valid не доказывает существование "
                    "ящика — сегментируйте отдельно:", "dead")
                for dom, cnt in suspicious[:15]:
                    self.callbacks['on_log'](f"[DEAD]    {dom} — {cnt} из {cnt} valid", "dead")
        except Exception:
            pass

        self._stop_profile_refresher()

        if self.cache:
            with self._cache_lock:
                hits = self._cache_hits
            if hits:
                self.callbacks['on_log'](
                    f"[INFO] Из кэша взято {hits} вердиктов — эти адреса заново "
                    "не проверялись. Дата в колонке «Проверено» у них исходная.", "info")
            self.cache.close()
            self.cache = None

        self.is_running = False
        self.callbacks['on_complete']()

    def start(self, email_sources, threads, timeout, fix_typos, check_spam, deep_ping, enable_ai, proxies=None, enable_osint=False, use_cache=True):
        def worker():
            self.setup(timeout=timeout, enable_ai=enable_ai, proxies=proxies, threads=threads,
                       use_cache=use_cache)
            self.run_pipeline(email_sources, threads, fix_typos, check_spam, deep_ping, enable_ai, enable_osint=enable_osint)
            
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        
    def stop(self):
        self.is_running = False
        
    def pause(self):
        self.is_paused = not self.is_paused
        return self.is_paused
