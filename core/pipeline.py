import os
import threading
import time
import json
import datetime
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.bounded import BoundedCache
from core.cache import ResultCache
from core.runstate import (RunState, run_id_for, DEFAULT_RETRY_DELAY,
                           GREYLIST_RETRY_DELAY)
from core.canary import CanaryWatch, canary_address
from core.verdict import verdict_confidence
from core.cleaner import EmailCleaner, normalize_for_dedup
from core.filters import SpamFilter
from core.github_parser import BlacklistDownloader
from core.network import NetworkValidator, PROXY_MAX_CONSECUTIVE_FAILS
from core.ai_engine import EmailAI
from core.parser.name_extractor import NameExtractor, split_name
from core.parser.ml_predictor import MLPredictor
from core.disposable import is_disposable
from core.gravatar import GravatarChecker
from core.org_role import enrich_org_role
from core.scoring import calculate_engagement_score
from core.provider import (classify_domain, country_from_domain,
                           country_from_location, extend_free_domains,
                           is_free_mail_domain)
from core.pipeline_setup import PipelineSetupMixin
from core.activity import PipelineActivityMixin
from core.pipeline_control import RunControlMixin
from core.enrichment import (EnrichmentMixin, AI_SUSPICION_PENALTY,
                             _enrich_signature, _utc_now, _as_utc, _fmt_stamp)
from core.verdict_revision import VerdictRevisionMixin
from core.settle import SettleContext, SettleMixin
from core.heuristics import (extract_birth_year, looks_machine_generated,
                             is_parked_domain, is_role_based)
from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS
from core.paths import data_path


_TRANSIENT_MARKERS = (
    "timeout", "proxy dead", "server disconnected", "smtp connect error",
    "rate limit", "service busy", "all proxies dead", "temp unavailable",
    "temp error", "our ip blocked", "our ip blacklisted", "transaction failed",
    "mail from rejected", "too many recipients", "лжёт выход",
    "dns не удалось спросить",
    "отказ по политике/репутации",
    "отказ отправителю/релею",
    "кончилось место",
)

MAX_RETRY_ROUNDS = 2

_PERMANENT_UNKNOWN_MARKERS = (
    "catch-all", "catchall", "fcrdns", "обратного dns", "не проверяется",
)


def _is_transient_failure(raw_status: str, reason: str) -> bool:
    if raw_status not in ("unknown", "risky"):
        return False
    low = (reason or "").lower()
    if any(m in low for m in _PERMANENT_UNKNOWN_MARKERS):
        return False
    return any(m in low for m in _TRANSIENT_MARKERS)


_CACHE_KEEPS = ("birth_year", "company", "job_role", "social_accounts",
                "company_source", "job_role_source")


class _DomainGate:

    __slots__ = ("_owner", "_key", "_lock")

    def __init__(self, owner, key):
        self._owner = owner
        self._key = key
        self._lock = None

    def __enter__(self):
        owner, key = self._owner, self._key
        with owner._inflight_guard:
            entry = owner._inflight.get(key)
            if entry is None:
                entry = [threading.Lock(), 0]
                owner._inflight[key] = entry
            entry[1] += 1
            self._lock = entry[0]
        self._lock.acquire()
        return self._lock

    def __exit__(self, exc_type, exc, tb):
        if self._lock is not None:
            self._lock.release()
            self._lock = None
        owner, key = self._owner, self._key
        with owner._inflight_guard:
            entry = owner._inflight.get(key)
            if entry is not None:
                entry[1] -= 1
                if entry[1] <= 0:
                    owner._inflight.pop(key, None)
        return False


class ValidationPipeline(RunControlMixin, PipelineSetupMixin, EnrichmentMixin,
                         VerdictRevisionMixin, SettleMixin, PipelineActivityMixin):
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self._init_activity()
        self.is_running = False
        self.is_paused = False
        self._stop_requested = False
        self._abort_event = threading.Event()
        self._aborting = False
        self._emitted = 0
        self._emitted_lock = threading.Lock()

        self.confirm_valid = True

        self.cleaner = EmailCleaner()
        self.filter = None
        self.network = None
        self.ai = None
        self.name_extractor = None
        self.ml_predictor = None
        self.gravatar_checker = GravatarChecker(timeout=3, proxy_provider=self._http_proxies)
        self.cache = None
        self._cache_hits = 0
        self._cache_lock = threading.Lock()
        self._domain_age_cache = BoundedCache()
        self._domain_age_lock = threading.Lock()
        self._http_alive_cache = BoundedCache()
        self._http_alive_lock = threading.Lock()
        self._inflight = {}
        self._inflight_guard = threading.Lock()

    def _domain_gate(self, key):
        return _DomainGate(self, key)
        

    def _phase(self, name, count=0):
        handler = self.callbacks.get('on_phase')
        if handler is None:
            return
        try:
            handler(str(name or ""), int(count or 0))
        except Exception:
            pass

    def _emit(self, email, status, reason, mx, data):
        if self._aborting:
            return False
        with self._emitted_lock:
            self._emitted += 1
        self.callbacks['on_result'](email, status, reason, mx, data)
        return True

    def run_pipeline(self, email_sources, threads=50, fix_typos=True,
                     check_spam=True, deep_ping=True, enable_ai=True,
                     enable_osint=True, resume=True):
        if self._stop_requested:
            self.is_running = False
            self._finish_activity()
            self.callbacks['on_complete']()
            return

        self.is_running = True
        with self._emitted_lock:
            self._emitted = 0
        
        from core.streamer import StreamLoader
        total_emails = StreamLoader(email_sources).estimate_total_lines()
        self.callbacks['on_log'](
            f"[INFO] Запуск обработки — во входе примерно {total_emails} строк. "
            "Точное число уникальных адресов появится по ходу.", "info")

        if 'on_unique_count' in self.callbacks:
            self.callbacks['on_unique_count'](total_emails)

        self.callbacks['on_progress'](0, total_emails)
        processed_count = 0
        feeder_finished = False

        def refine_total():
            nonlocal total_emails
            try:
                exact = StreamLoader(email_sources).count_total_lines()
            except Exception:
                return
            if feeder_finished or not exact or not self.is_running:
                return
            total_emails = exact
            try:
                if 'on_unique_count' in self.callbacks:
                    self.callbacks['on_unique_count'](exact)
                self.callbacks['on_progress'](processed_count, exact)
            except Exception:
                pass

        threading.Thread(target=refine_total, daemon=True).start()
        
        import queue as queue_module
        greylisted_queue = queue_module.Queue()

        def defer(email, data, is_role, delay=DEFAULT_RETRY_DELAY, proxy=None,
                  reason="", same_exit=False, attempts=0):
            greylisted_queue.put((email, data, is_role,
                                  time.monotonic() + max(0.0, float(delay)),
                                  proxy, reason or "", bool(same_exit),
                                  int(attempts)))

        domain_stats = BoundedCache(max_keys=100_000)
        domain_stats_lock = threading.Lock()

        self.canary = CanaryWatch()
        self._valid_exits = {}

        if not self.name_extractor or not self.ml_predictor:
            self._stage("models")
        if not self.name_extractor:
            self.callbacks['on_log']("[INFO] Загрузка модуля извлечения имен...", "info")
            self.name_extractor = NameExtractor(enable_osint=enable_osint,
                                                proxy_provider=self._http_proxies)
        if not self.ml_predictor:
            self.callbacks['on_log']("[INFO] Загрузка предиктора пола/страны...", "info")
            self.ml_predictor = MLPredictor(enable_ml=enable_ai)

        proxies_dead_warned = threading.Event()

        def warn_if_proxies_dead():
            if self.network is not None:
                try:
                    gone = self.network.take_recent_bans()
                except Exception:
                    gone = []
                for proxy in gone:
                    self.callbacks['on_log'](
                        f"[DEAD] Прокси выбыл из ротации: {proxy}. Сбои шли на "
                        "разных серверах — похоже, закрылся порт 25 или адрес "
                        "перестал отвечать.", "dead")
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
            if not self.is_running:
                return False

            email, data = item

            data["validated_at"] = _utc_now().strftime("%Y-%m-%d %H:%M")

            prov_name, dom_type = classify_domain(email)
            data["provider_name"] = prov_name
            data["domain_type"] = dom_type

            # Шаг 1.1: Проверка на одноразовый/временный домен (Disposable + SpamFilter)
            if is_disposable(email):
                data["engagement_score"] = 0
                data["engagement_grade"] = "Dead"
                data["provider_type"] = "Disposable"
                data["verdict_confidence"] = 95
                data["verdict_basis"] = ("домен из списка одноразовых: ящик "
                                         "живёт минуты и создан, чтобы его "
                                         "бросить")
                data["provider_name"] = "Disposable"
                data["domain_type"] = "Disposable"
                self._подсказать_опечатку(email, data, fix_typos)
                self._enrich_offline(email, data, "Trap/Disposable", enable_ai)
                self._emit(email, "Trap/Disposable", "Disposable Email Domain", "N/A", data)
                return

            if self.filter and hasattr(self.filter, 'is_spam_or_disposable'):
                if self.filter.is_spam_or_disposable(email):
                    data["engagement_score"] = 0
                    data["engagement_grade"] = "Dead"
                    data["provider_type"] = "Disposable (внешний список)"
                    data["provider_name"] = "Disposable"
                    data["domain_type"] = "Disposable"
                    self._подсказать_опечатку(email, data, fix_typos)
                    self._enrich_offline(email, data, "Trap/Disposable", enable_ai)
                    self._emit(email, "Trap/Disposable", "External Blacklist Match", "N/A", data)
                    return

            if self._trap_by_name(email, data, enable_ai, deep_ping):
                return

            is_role = is_role_based(email)

            if enable_ai and self.ai:
                if self.ai.predict(email):
                    data["ai_suspicious"] = True
                    data["provider_type"] = "Suspicious"
                
            # Шаг 2: Кэш прошлых прогонов. Доказанный вердикт SMTP от перезапуска
            # В кэше лежат только Valid и Invalid/Bounce — см. core/cache.py.
            if deep_ping and self.cache and not data.get("trap_word"):
                cached = self.cache.get(email)
                if cached:
                    cached_data = cached.get("data") or {}
                    cached_stamp = _fmt_stamp(cached["checked_at"]) or data["validated_at"]
                    data["from_cache"] = True
                    status_display = ("Role-based" if is_role and cached["status"] == "Valid"
                                      else cached["status"])
                    data["role_address"] = bool(is_role)

                    want = _enrich_signature(enable_osint, enable_ai)
                    if cached_data.get("enrich_sig") == want:
                        computed = ("engagement_score", "engagement_grade",
                                    "provider_type", "provider_name",
                                    "domain_type", "has_gravatar",
                                    "verdict_confidence", "verdict_basis")
                        for key, value in cached_data.items():
                            if key in computed or not data.get(key):
                                data[key] = value
                    else:
                        for key, value in cached_data.items():
                            if key in _CACHE_KEEPS and not data.get(key):
                                data[key] = value
                        cached_res = {
                            "status": cached["status"],
                            "reason": cached.get("reason", ""),
                            "mx_record": cached.get("mx", "N/A"),
                            "mx_records": [cached.get("mx")] if cached.get("mx") else [],
                            "has_starttls": None,
                        }
                        self._enrich_and_score(email, data, cached_res,
                                               status_display, cached["status"],
                                               is_role, enable_ai)
                        data["enrich_sig"] = want
                    if not data.get("verdict_basis"):
                        confidence, basis = verdict_confidence(
                            cached["status"], cached.get("reason", ""))
                        data["verdict_confidence"] = confidence
                        data["verdict_basis"] = basis

                    data["validated_at"] = cached_stamp
                    self._mark_typo_domain(email, data, cached["mx"])

                    with self._cache_lock:
                        self._cache_hits += 1
                    self._emit(
                        email, status_display,
                        f"{cached['reason']} [из кэша, {cached['age_days']} дн. назад]",
                        cached["mx"], data)
                    state.mark_done(normalize_for_dedup(email))
                    return

            if deep_ping and self._disposable_by_mx(email, data, enable_ai):
                state.mark_done(normalize_for_dedup(email))
                return

            # Шаг 3: Глубокий SMTP Ping
            if deep_ping:
                res = self.network.check_email(email)
                if res.get("aborted") or self._aborting:
                    return False
                raw_status = res["status"]
                warn_if_proxies_dead()

                if (raw_status == "invalid"
                        and "No MX" in res.get("reason", "")
                        and fix_typos):
                    suggestion = self.cleaner.suggest_domain_fix(email)
                    if suggestion and suggestion != email:
                        fixed_res = self.network.check_email(suggestion)
                        data["suggested_email"] = suggestion
                        data["suggested_status"] = fixed_res.get("status", "")
                        if fixed_res.get("status") in ("valid", "catchall"):
                            res["reason"] = (
                                "%s. Похоже на опечатку: на %s такой ящик "
                                "есть, но проверяли и хороним МЫ ЗАГРУЖЕННЫЙ "
                                "адрес — решение за вами"
                                % (res.get("reason", ""),
                                   suggestion.rsplit("@", 1)[1]))

                if raw_status == "greylisted" or (
                        raw_status == "unconfirmed" and not res.get("unconfirmed_final")):
                    defer(email, data, is_role, delay=GREYLIST_RETRY_DELAY,
                          proxy=res.get("proxy"), reason=res.get("reason", ""),
                          same_exit=True)
                    return False

                if _is_transient_failure(raw_status, res.get("reason", "")):
                    defer(email, data, is_role, proxy=res.get("proxy"),
                          reason=res.get("reason", ""))
                    return False

                if raw_status == "trap":
                    self._emit_trap(email, data, res.get("reason", ""),
                                    "AV Vendor", "trap", enable_ai,
                                    mx=res.get("mx_record", "N/A"))
                    state.mark_done(normalize_for_dedup(email))
                    return

                self._typo_hint_on_live_mx(email, data, res, fix_typos)

                self._settle(email, data, is_role, res, enable_ai, settle_ctx)
            else:
                self._emit(email, "Unverified", "Skipped Ping", "N/A", data)

        safe_threads = min(int(threads), 300)
        
        import queue
        task_queue = queue.Queue(maxsize=safe_threads * 2)

        state = RunState(run_id_for(email_sources), resume=resume)
        settle_ctx = SettleContext(domain_stats, domain_stats_lock, state)
        state.reset_seen()
        self.state = state
        if self._aborting:
            state.freeze()
        if resume and state.resumed_count:
            self.callbacks['on_log'](
                f"[INFO] Продолжаю прерванный прогон: {state.resumed_count} адресов "
                "уже проверены и заново проверяться не будут.", "info")
        elif not state.enabled:
            self.callbacks['on_log'](
                "[DEAD] Состояние прогона недоступно (не открылась база) — дедуп "
                "и возобновление отключены, проверка идёт как раньше.", "dead")

        duplicates_skipped = 0
        already_done = 0
        queued_count = 0

        def feeder_body():
            nonlocal duplicates_skipped, queued_count, already_done
            пропущено = 0

            def положить(item):
                while True:
                    try:
                        task_queue.put(item, timeout=0.5)
                        return True
                    except queue.Full:
                        if not self.is_running:
                            return False

            def отметить_пропуск():
                nonlocal пропущено
                пропущено += 1
                if пропущено % 500 == 0:
                    self.activity.skipped(пропущено)
            from core.streamer import StreamLoader
            загрузчик = StreamLoader(
                email_sources,
                on_note=lambda текст: self.callbacks['on_log'](текст, "warning"))
            for email, data in загрузчик.stream_emails():
                if not self.is_running:
                    break

                loaded_as = email
                if fix_typos:
                    email = self.cleaner.clean_email(email)

                if not email:
                    отметить_пропуск()
                    continue

                if isinstance(data, dict) and loaded_as != email:
                    data["original_email"] = loaded_as

                dedup_key = normalize_for_dedup(email)
                if not state.add_if_new(dedup_key):
                    duplicates_skipped += 1
                    отметить_пропуск()
                    continue

                if resume and state.is_done(dedup_key):
                    already_done += 1
                    отметить_пропуск()
                    continue

                if not положить((email, data)):
                    break
                queued_count += 1

            for _ in range(safe_threads):
                if not положить(None):
                    break

            nonlocal total_emails, feeder_finished
            feeder_finished = True
            total_emails = queued_count
            self.activity.skipped(пропущено)
            self.activity.retotal(queued_count)
            if 'on_unique_count' in self.callbacks:
                self.callbacks['on_unique_count'](queued_count)

            if already_done:
                self.callbacks['on_log'](
                    f"[INFO] Пропущено как уже проверенное: {already_done} адресов.", "info")

            if duplicates_skipped:
                self.callbacks['on_log'](
                    f"[INFO] Схлопнуто дублей: {duplicates_skipped} "
                    "(один ящик записан по-разному — двойная отправка предотвращена). "
                    f"К проверке: {queued_count}.", "info")

        feeder_error = []

        def feeder_thread():
            nonlocal total_emails, feeder_finished
            try:
                feeder_body()
            except Exception as exc:
                feeder_error.append(exc)
                self.callbacks['on_log'](
                    f"[DEAD] Чтение базы оборвалось: {type(exc).__name__}: {exc}. "
                    f"Проверяются только прочитанные до сбоя адреса ({queued_count}).",
                    "dead")
                feeder_finished = True
                total_emails = queued_count
                self.activity.retotal(queued_count)
                for _ in range(safe_threads):
                    while True:
                        try:
                            task_queue.put(None, timeout=0.5)
                            break
                        except queue.Full:
                            if not self.is_running:
                                break

        def после_проверки():
            if feeder_error and self.activity.stage_key == "check":
                return "failed"
            return None

        self._stage("check")
        t_feeder = threading.Thread(target=feeder_thread, daemon=True)
        t_feeder.start()
        
        progress_lock = threading.Lock()
        
        def worker_loop():
            nonlocal processed_count
            while self.is_running:
                item = task_queue.get()
                if item is None:
                    break
                deferred = False
                try:
                    with self.activity.working():
                        deferred = process_single(item) is False
                except Exception as e:
                    # Without this the whole worker thread would die and silently
                    email = item[0] if item else "?"
                    self.callbacks['on_log'](f"[DEAD] Ошибка обработки {email}: {type(e).__name__}: {e}", "dead")
                    try:
                        self._emit(email, "Unknown", f"Processing error: {type(e).__name__}", "N/A", item[1])
                    except Exception:
                        pass
                if not deferred:
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
        
        greylisted_count = greylisted_queue.qsize()
        self._phase("retry", greylisted_count)
        if greylisted_count > 0 and self.is_running and deep_ping:
            self._stage("retry", cut=после_проверки())

            if self.is_running:
                retry_count = 0
                retry_lock = threading.Lock()

                def retry_body(entry):
                    nonlocal retry_count, processed_count
                    (email, data, is_role, _due,
                     first_proxy, _reason, same_exit, attempts) = entry
                    while self.is_paused and self.is_running:
                        time.sleep(0.5)
                    if not self.is_running:
                        greylisted_queue.put(entry)
                        return

                    if same_exit:
                        res = self.network.check_email(
                            email, prefer_exit_of=first_proxy)
                    else:
                        res = self.network.check_email(
                            email, avoid_exit_of=first_proxy)
                    if res.get("aborted") or self._aborting:
                        return
                    raw_status = res["status"]

                    grey = raw_status == "greylisted" or (
                        raw_status == "unconfirmed" and not res.get("unconfirmed_final"))
                    if (attempts + 1 < MAX_RETRY_ROUNDS
                            and (grey or _is_transient_failure(
                                raw_status, res.get("reason", "")))):
                        defer(email, data, is_role,
                              delay=GREYLIST_RETRY_DELAY if grey else DEFAULT_RETRY_DELAY,
                              proxy=res.get("proxy") or first_proxy,
                              reason=res.get("reason", ""),
                              same_exit=grey, attempts=attempts + 1)
                        return

                    if raw_status == "trap":
                        self._emit_trap(email, data, res.get("reason", ""),
                                        "AV Vendor", "trap", enable_ai,
                                        mx=res.get("mx_record", "N/A"))
                        state.mark_done(normalize_for_dedup(email))
                    else:
                        self._typo_hint_on_live_mx(email, data, res, fix_typos)
                        self._settle(email, data, is_role, res, enable_ai, settle_ctx)
                    with retry_lock:
                        retry_count += 1
                    with progress_lock:
                        processed_count += 1
                        current = processed_count
                    self.callbacks['on_progress'](current, total_emails)

                def retry_one(entry):
                    nonlocal processed_count
                    try:
                        retry_body(entry)
                    except Exception as e:
                        email, data = entry[0], entry[1]
                        self.callbacks['on_log'](
                            f"[DEAD] Ошибка перепроверки {email}: {type(e).__name__}: {e}",
                            "dead")
                        try:
                            self._emit(email, "Unknown",
                                       f"Processing error: {type(e).__name__}", "N/A", data)
                        except Exception:
                            pass
                        with progress_lock:
                            processed_count += 1
                            current = processed_count
                        self.callbacks['on_progress'](current, total_emails)

                for retry_round in range(1, MAX_RETRY_ROUNDS + 1):
                    if not self.is_running:
                        break
                    pending = []
                    while True:
                        try:
                            pending.append(greylisted_queue.get_nowait())
                        except Exception:
                            break

                    if not pending:
                        break

                    pending.sort(key=lambda entry: entry[3])
                    total_pending = len(pending)
                    retry_workers = max(1, min(safe_threads, total_pending or 1))
                    waited = 0.0

                    with ThreadPoolExecutor(max_workers=retry_workers) as retry_pool:
                        futures = []
                        index = 0
                        announced = False
                        while index < total_pending and self.is_running:
                            if self.is_paused:
                                time.sleep(0.25)
                                continue
                            now = time.monotonic()
                            launched = 0
                            while index < total_pending and pending[index][3] <= now:
                                futures.append(retry_pool.submit(
                                    self.activity.counted(retry_one), pending[index]))
                                index += 1
                                launched += 1
                            if launched and not announced:
                                announced = True
                                self.callbacks['on_log'](
                                    f"[INFO] Перепроверка началась: {launched} из "
                                    f"{total_pending} адресов созрели сразу, ждать не пришлось.",
                                    "info")
                            if index >= total_pending:
                                break
                            remaining = pending[index][3] - time.monotonic()
                            if remaining > 0:
                                self.activity.wait(
                                    remaining, "ближайший отложенный адрес созреет "
                                    "для перепроверки")
                                if not announced and waited == 0.0:
                                    self.callbacks['on_log'](
                                        f"[INFO] Отложено на перепроверку: {total_pending}. "
                                        f"Ближайший созреет через {int(remaining)}с — ждём только его.",
                                        "info")
                                step = min(0.25, remaining)
                                time.sleep(step)
                                waited += step

                        self.activity.unwait()
                        for fut in as_completed(futures):
                            try:
                                fut.result()
                            except Exception as e:
                                self.callbacks['on_log'](
                                    f"[DEAD] Ошибка перепроверки: {type(e).__name__}: {e}", "dead")

                        for leftover_entry in pending[index:]:
                            greylisted_queue.put(leftover_entry)

                    self.callbacks['on_log'](
                        f"[INFO] Круг перепроверки {retry_round} из {MAX_RETRY_ROUNDS}: "
                        f"взято {total_pending}, вердикт получили {retry_count} "
                        "(счёт с начала перепроверки). Простой в ожидании: "
                        f"{waited:.1f}с.", "info")

        self._phase("", 0)
        self._stage("finish", cut=после_проверки())

        leftover = 0
        while True:
            try:
                (email, data, is_role, _due,
                 _proxy, first_reason, _same, _tries) = greylisted_queue.get_nowait()
            except Exception:
                break
            leftover += 1
            data["validated_at"] = _utc_now().strftime("%Y-%m-%d %H:%M")
            why = (first_reason or "Перепроверка не выполнена").strip()
            if "перепроверка не выполнена" not in why.lower():
                why = f"{why} (перепроверка не выполнена)"
            try:
                self._emit_unresolved(email, why, data, enable_ai)
            except Exception:
                pass
            with progress_lock:
                processed_count += 1
                current = processed_count
            self.callbacks['on_progress'](current, total_emails)
        if leftover:
            self.callbacks['on_log'](
                f"[INFO] {leftover} greylisted-адресов возвращены как Unknown "
                "(перепроверка не выполнена) — потеряться они не могут.", "info")

        try:
            trapped = self.network.tarpit_domains() if self.network else []
        except Exception:
            trapped = []

        try:
            proven = self.network.proven_catchall_domains() if self.network else []
        except Exception:
            proven = []
        proven, trapped = self._split_catchall_from_tarpit(proven, trapped)
        if proven:
            revised = self._revise(
                proven, "Unknown",
                "домен принимает любой адрес (catch-all) — существование "
                "ящика по SMTP не проверяется", spare=self._behind_gateway_spared())
            if revised:
                self.callbacks['on_log'](
                    f"[INFO] Пересмотрено строк по catch-all доменам: {revised}. "
                    "Их «Годен» ничего не доказывал.", "info")
            self._forget_cached(proven, "catch-all")
        try:
            self._final_canaries(trapped)
            лжецы = set(self.network.tarpit_pairs()) | self.canary.lying_pairs()
        except Exception:
            лжецы = None
        if trapped:
            уцелели = self._spared_valid(trapped, лжецы) if лжецы is not None else set()
            self._revise(trapped, "Unknown",
                         "домен перестал отвечать честно (тарпитинг) — «Годен» "
                         "по нему недоказуем", spare=уцелели)
            self._forget_cached(trapped, "тарпитинг")
            self._log_spared(уцелели, "тарпитинг")

        try:
            подставные = self.canary.compromised_domains() if getattr(
                self, "canary", None) else []
        except Exception:
            подставные = []
        if подставные:
            уцелели = self._spared_valid(подставные, лжецы) if лжецы is not None else set()
            self._revise(подставные, "Unknown",
                         "канарейка вернулась живой: сервер принял заведомо "
                         "несуществующий адрес — «Годен» недоказуем", spare=уцелели)
            self._forget_cached(подставные, "канарейка")
            self._log_spared(уцелели, "канарейка")
            свод = self.canary.summary()
            self.callbacks['on_log'](
                "[DEAD] Канареек выпущено: %d, поймано врущих выходов: %d. "
                "Домены: %s. Это НЕ проблема базы — нужен чистый прокси."
                % (свод["проб"], свод["поймано"], ", ".join(свод["домены"])),
                "dead")
            self.callbacks['on_log'](
                "[DEAD] ВНИМАНИЕ: %s перестал отвечать честно — принимает любые "
                "адреса, защищаясь от перебора с нашего IP. Все «Годен» по этим "
                "доменам в этом прогоне НЕДОКАЗУЕМЫ. Нужен чистый прокси, база "
                "тут ни при чём." % ", ".join(подставные), "dead")

        try:
            suspicious = []
            with domain_stats_lock:
                for dom, st in domain_stats.items():
                    if st["total"] >= 5 and st["valid"] == st["total"]:
                        suspicious.append((dom, st["total"]))
            suspicious = [(dom, cnt) for dom, cnt in suspicious
                          if not self._catchall_disproven(dom)]
            if suspicious:
                suspicious.sort(key=lambda x: -x[1])
                self.callbacks['on_log'](
                    "[DEAD] Подозрение на catch-all: у этих доменов ВСЕ проверенные "
                    "адреса ответили 250 OK. Их Valid не доказывает существование "
                    "ящика — сегментируйте отдельно:", "dead")
                for dom, cnt in suspicious[:15]:
                    self.callbacks['on_log'](f"[DEAD]    {dom} — {cnt} из {cnt} valid", "dead")
                self._revise([dom for dom, _ in suspicious], None,
                             "домен под подозрением на catch-all: все "
                             "проверенные адреса ответили 250")
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

        self._settle_resume_journal(state, resume, feeder_error)

        try:
            state.close()
        except Exception:
            pass

        with self._emitted_lock:
            emitted = self._emitted
        expected = total_emails if isinstance(total_emails, int) else 0
        if self._stop_requested:
            self.callbacks['on_log'](
                f"[INFO] Остановлено: показано {emitted}. Непроверенные адреса "
                "будут проверены при следующем запуске той же базы — уже "
                "проверенные повторно не проверяются.", "info")
        elif expected and emitted != expected:
            lost = expected - emitted
            if lost > 0:
                self.callbacks['on_log'](
                    f"[DEAD] ПОТЕРЯНО АДРЕСОВ: {lost}. Принято в работу "
                    f"{expected}, показано {emitted}. Это сбой внутри обработки, "
                    "а не свойство базы — сообщите о нём.", "dead")
            else:
                self.callbacks['on_log'](
                    f"[DEAD] Результатов больше, чем адресов: показано {emitted} "
                    f"при {expected} принятых. Возможен двойной показ.", "dead")
        elif expected:
            self.callbacks['on_log'](
                f"[INFO] Сверка: принято {expected}, показано {emitted} — сходится.",
                "info")

        self.is_running = False
        self._finish_activity(failed=bool(feeder_error), stage_done=True)
        self.callbacks['on_complete']()

    def start(self, email_sources, threads, timeout, fix_typos, check_spam,
              deep_ping, enable_ai=True, proxies=None, enable_osint=True,
              use_cache=True, resume=True,
              confirm_valid=True):
        self.confirm_valid = bool(confirm_valid)
        self._stop_requested = False
        self._aborting = False
        self._abort_event.clear()

        self.is_running = True
        self.is_paused = False
        self.__dict__["_worker"] = None
        self.activity.begin()

        def worker():
            try:
                self.setup(timeout=timeout, enable_ai=enable_ai, proxies=proxies, threads=threads,
                           use_cache=use_cache)
                self.run_pipeline(email_sources, threads, fix_typos, check_spam, deep_ping,
                                  enable_ai, enable_osint=enable_osint, resume=resume)
            except Exception as exc:
                self.callbacks['on_log'](
                    "[DEAD] Проверка прервана ошибкой: %s: %s"
                    % (type(exc).__name__, exc), "dead")
                self._finish_activity(failed=True)
            finally:
                self._finish_activity()
                if self.is_running:
                    self.is_running = False
                    self.callbacks['on_complete']()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        self.__dict__["_worker"] = t
        self._start_pulse()
        return t
        
