#!/usr/bin/env python3
import hashlib
import io
import json
import mimetypes
import os
import secrets
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from core.parser_pipeline import SEARCH_ENGINES
from core.winnoise import (install_webview_noise_filter, отметить_закрытие,
                           quiet_chromium, WebViewReaper)
from core.crashlog import (crash_log_path, log_crash,
                           recent_crashes)
from ui.result_store import normalize_filters
from core.baseops import csv_row, export_encoding

from core.paths import resource_path, seed_data

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = resource_path("ui", "web")

APP_NAME = "MailFact"

PAGE_SIZE = 100


from ui.webapp_sources import SourcesMixin, _тип_диалога
from ui.webapp_parser import ParserMixin
from ui.webapp_activity import ActivityBridgeMixin
from ui.webapp_reset import ResetMixin
from ui.webapp_base import BaseViewMixin

class ValidatorApi(BaseViewMixin, ResetMixin, SourcesMixin, ParserMixin,
                   ActivityBridgeMixin):

    def __init__(self):
        from ui.result_store import ResultStore, group_of
        from ui.log_buffer import LogBuffer
        from core.pipeline import ValidationPipeline

        self._group_of = group_of
        self.store = ResultStore(drop_repeats=True)
        from ui.base_store import BaseStore
        self.base = BaseStore()
        self.log = LogBuffer(capacity=4000)

        self._sources = {"emails": [], "proxies": [], "dorks": [], "pproxy": []}
        self.suppress_path = None

        self.window = None
        self._lock = threading.Lock()
        self._progress = (0, 0)
        self._proxy_progress = (0, 0)
        self._phase = ("", 0)
        self._line_counts = {"emails": 0, "proxies": 0, "dorks": 0, "pproxy": 0}
        self._count_jobs = {}
        self._count_lock = threading.Lock()
        self._scan_job = 0
        self._scan_lock = threading.Lock()
        self._state = "idle"
        self._proxy_summary = None
        self._pending = []
        self._log_seq = 0
        self._history = []
        self._history_cap = 1500
        self._file_stamps = {}
        self._export_busy = False

        self.parser = None
        self._starting = False
        self._discarding = False
        self._clear_store_after_export = False
        self._parser_state = "idle"
        self._parser_progress = (0, 0, 0, "Парсинг")
        self._parser_stats = {"dorksDone": 0, "dorksTotal": 0,
                              "pages": 0, "snippets": 0, "emails": 0}
        self._parser_pending = []
        self._parser_history = []
        self._parser_rows = []
        self._parser_seen = set()

        engine = self._quiet_after_stop
        self.pipeline = ValidationPipeline(callbacks={
            "on_log": engine(self._on_log),
            "on_progress": engine(self._on_progress),
            "on_phase": engine(self._on_phase),
            "on_revise": engine(self._on_revise),
            "on_proxy_progress": engine(self._on_proxy_progress),
            "on_result": engine(self._on_result),
            "on_complete": engine(self._on_complete),
            "on_unique_count": lambda count: None,
            "on_proxies_tested": engine(lambda live, total: self._on_log(
                f"[INFO] Прокси: рабочих {live} из {total}.", "info")),
            "on_proxy_profile": engine(self._on_proxy_profile),
        })

    @property
    def email_sources(self):
        return self._sources["emails"]

    @property
    def proxy_sources(self):
        return self._sources["proxies"]

    INLINE_LIMIT = 5 * 1024 * 1024

    _EXPECTED_KIND = {
        "emails": "email",
        "proxies": "proxy",
        "dorks": "dork",
        "pproxy": "proxy",
        "suppress": "email",
    }

    def _busy(self):
        if self._starting or getattr(self.pipeline, "is_running", False):
            if not self._discarding:
                return True
        parser = getattr(self, "parser", None)
        if parser is None:
            return False

        stopping = getattr(parser, "_stop_event", None)
        if stopping is not None and stopping.is_set():
            return False

        alive = getattr(parser, "is_alive", None)
        if callable(alive):
            return bool(alive())
        return bool(getattr(parser, "is_running", False))

    _BUSY_REFUSAL = ("Идёт проверка — менять исходные данные нельзя. "
                     "Остановите прогон или дождитесь конца.")

    _BAD_KIND = ("Не понял, куда это класть: поле не названо или названо "
                 "неизвестно как. Выберите поле и попробуйте ещё раз.")

    def _bucket(self, kind):
        if not isinstance(kind, str):
            return None
        return self._sources.get(kind)

    def _on_log(self, text, tag="info"):
        with self._lock:
            self._log_seq += 1
            line = {"text": str(text), "tag": tag, "n": self._log_seq, "t": time.time()}
            self._pending.append(line)
            self._history.append(line)
            if len(self._history) > self._history_cap:
                del self._history[:len(self._history) - self._history_cap]

    def resume_info(self, payload=None):
        from core.runstate import resumable_count

        try:
            done = resumable_count(list(self.email_sources))
        except Exception:
            done = 0
        return {"done": int(done)}

    def _on_revise(self, domains, new_status, note, spare=None):
        moved = 0
        for domain in domains or []:
            try:
                moved += self.store.revise_domain(domain, new_status, note, spare)
            except Exception:
                continue
        return moved

    last_seen_at = 0.0
    request_count = 0

    def _on_phase(self, name, count):
        self._phase = (str(name or ""), int(count or 0))

    def _on_progress(self, current, total):
        self._progress = (int(current or 0), int(total or 0))

    def _on_proxy_progress(self, checked, seen):
        self._proxy_progress = (int(checked or 0), int(seen or 0))

    def _on_result(self, email, status, reason, mx, data=None):
        data = data if isinstance(data, dict) else {}
        group = self.store.append(email, status, reason, mx, data)
        self._base_mark(email, data)
        label = {"valid": "VALID", "invalid": "DEAD"}.get(group)
        if label is None:
            label = str(status).upper()
        tag = {"valid": "valid", "invalid": "dead"}.get(group, "trap")
        self._on_log(f"[{label}] {email} -> {reason}", tag)

    def _on_complete(self):
        self._state = "done"
        причина = getattr(self.pipeline, "blocked_reason", "")
        if причина:
            self._on_log("[DEAD] Проверка не выполнялась: %s." % причина, "dead")
            return
        исход = getattr(getattr(self.pipeline, "activity", None), "state", "")
        if исход == "stopped":
            self._on_log("[INFO] Проверка остановлена.", "info")
        elif исход == "failed":
            self._on_log("[DEAD] Проверка прервана ошибкой — причина в журнале выше.", "dead")
        else:
            self._on_log("[INFO] Проверка завершена.", "info")

    def _on_proxy_profile(self, summary):
        self._proxy_summary = summary


    @staticmethod
    def _number(payload, key, default, low, high):
        try:
            value = float(payload.get(key, default))
        except (TypeError, ValueError):
            return default
        if value != value:
            return default
        return int(max(low, min(high, value)))

    def start(self, payload):
        refusal = self._claim_start(payload)
        if refusal is not None:
            return refusal
        self._discarding = False
        self._proxy_progress = (0, 0)

        from core.parser.ml_predictor import set_country_mode
        set_country_mode(payload.get("country") or "coverage")

        if not self.proxy_sources:
            self._on_log(
                "[DEAD] Прокси не заданы: проверка идёт с твоего домашнего IP. "
                "Сначала проверю, открыт ли у тебя исходящий порт 25.", "dead")

        self._progress = (0, 0)
        self._phase = ("", 0)
        self._state = "running"
        self._proxy_summary = None

        try:
            thread = self._launch_pipeline(payload)
        except Exception as exc:
            self._starting = False
            self._state = "done"
            return {"ok": False, "error": "Запуск не удался: %s" % exc}

        def release():
            if thread is not None:
                thread.join()
            self._starting = False

        threading.Thread(target=release, daemon=True).start()
        return {"ok": True}

    def _launch_pipeline(self, payload):
        from core.streamer import StreamLoader

        return self.pipeline.start(
            email_sources=list(self.email_sources),
            threads=self._number(payload, "threads", 100, 1, 500),
            timeout=self._number(payload, "timeout", 5, 1, 300),
            fix_typos=True, check_spam=True, deep_ping=True,
            proxies=(StreamLoader(list(self.proxy_sources)).stream_lines()
                     if self.proxy_sources else None),
            )

    def pause(self, payload=None):
        self.pipeline.pause()
        self._state = "paused" if self.pipeline.is_paused else "running"
        return {"state": self._state}

    def state(self, payload=None):
        counts = self.store.counts()
        current, total = self._progress
        proxy_checked, proxy_seen = self._proxy_progress
        running, proxies_running = self._run_flags()
        with self._lock:
            since = payload.get("logSince") if isinstance(payload, dict) else None
            if since is None:
                lines, self._pending = self._pending, []
            else:
                try:
                    since = int(since)
                except (TypeError, ValueError):
                    since = 0
                lines = [line for line in self._history if line.get("n", 0) > since]
                self._pending = []
            seq = self._log_seq
        return {
            "state": self._state,
            "running": running,
            "engineBusy": bool(self._starting) and not running,
            "counts": {
                "valid": counts["valid"], "invalid": counts["invalid"],
                "spam": counts["spam"], "unknown": counts["unknown"],
                "total": counts["total"], "names": counts["names"],
            },
            "progress": {"current": current, "total": total,
                         "pct": int(current * 100 / total) if total else 0},
            "proxyProgress": {"checked": proxy_checked, "seen": proxy_seen,
                              "running": proxies_running},
            "phase": {"name": self._phase[0], "count": self._phase[1]},
            "activity": self._validator_activity(),
            "log": lines,
            "logSeq": seq,
            "dropped": self.log.dropped,
            "proxy": self._proxy_summary,
            "exportBusy": self._export_busy,
            "base": self._base_state(),
        }

    def log_tail(self, payload=None):
        with self._lock:
            tail = list(self._history)
            self._pending = []
            return {"log": tail, "seq": self._log_seq}

    def _result_row(self, row):
        data = row.get("data") or {}
        return {
            "email": row["email"],
            "avatar": (_gravatar_hash(row["email"])
                       if data.get("has_gravatar") else ""),
            "status": row["status"],
            "group": self._group_of(row["status"]),
            "reason": row["reason"],
            "score": data.get("engagement_score", ""),
            "original": data.get("original_email", ""),
            "confidence": data.get("verdict_confidence", ""),
            "basis": data.get("verdict_basis", ""),
            "provider": data.get("provider_name", ""),
            "name": data.get("name", ""),
            "gender": data.get("gender", ""),
            "country": data.get("country", ""),
            "when": data.get("validated_at", ""),
            "more": {
                "domain_type": data.get("domain_type", ""),
                "provider_type": data.get("provider_type", ""),
                "grade": data.get("engagement_grade", ""),
                "company": data.get("company", ""),
                "job_role": data.get("job_role", ""),
                "birth_year": data.get("birth_year", ""),
                "first_name": data.get("first_name", ""),
                "last_name": data.get("last_name", ""),
                "social": data.get("social_accounts", ""),
                "name_source": data.get("name_source", ""),
                "gender_source": data.get("gender_source", ""),
                "country_source": data.get("country_source", ""),
                "company_source": data.get("company_source", ""),
                "job_role_source": data.get("job_role_source", ""),
                "ai_note": data.get("ai_note", ""),
                "checked_as": data.get("checked_as", ""),
                "from_cache": bool(data.get("from_cache")),
                "suggested_email": data.get("suggested_email", ""),
                "suggested_status": data.get("suggested_status", ""),
                "typo_of": data.get("typo_of", ""),
                "mx": row.get("mx", ""),
            },
            "age": _verdict_age(data.get("validated_at", "")),
        }

    @staticmethod
    def _filters(payload):
        payload = payload if isinstance(payload, dict) else {}
        return normalize_filters({
            "groups": payload.get("groups") or ("valid",),
            "minScore": payload.get("minScore"),
            "country": payload.get("country"),
            "gender": payload.get("gender"),
            "provider": payload.get("provider"),
            "search": payload.get("search"),
            "hideTypo": payload.get("hideTypo"),
        })

    def export(self, payload):
        if self._export_busy:
            return {"ok": False, "error": "Выгрузка уже идёт"}
        if self.window is None:
            return {"ok": False, "error": "Окно недоступно"}
        target = self.window.create_file_dialog(
            _тип_диалога("SAVE"), save_filename="valid_emails.csv")
        if not target:
            return {"ok": False, "cancelled": True}
        path = target if isinstance(target, str) else target[0]

        picked = self._filters(payload)
        chunk = self._number(payload, "chunk", 0, 0, 100_000_000)

        self._export_busy = True
        threading.Thread(target=self._export_worker,
                         args=(path, picked, chunk),
                         daemon=True).start()
        return {"ok": True}

    def _export_worker(self, path, picked, chunk):
        import csv
        from core import baseops
        from core.cleaner import normalize_for_dedup
        try:
            drop = set()
            if self.suppress_path:
                try:
                    drop = baseops.suppression_keys(self.suppress_path)
                except Exception as exc:
                    self._on_log(f"[DEAD] Отписки не применены: {exc}", "dead")

            def write_csv(handle, rows):
                writer = csv.writer(handle)
                writer.writerow(["Email", "OriginalEmail", "Status", "Reason",
                                 "MX", "Name",
                                 "FirstName", "LastName", "Gender", "Country",
                                 "BirthYear", "Company", "JobRole",
                                 "Score", "Grade",
                                 "Confidence", "ConfidenceBasis",
                                 "Provider", "DomainType",
                                 "NameSource", "GenderSource", "CountrySource",
                                 "CompanySource", "JobRoleSource",
                                 "SocialAccounts", "ValidatedAt",
                                 "DomainValidRatio", "DomainChecked",
                                 "FromCache",
                                 "RoleAddress",
                                 "SuggestedEmail",
                                 "TypoOf"])
                for row in rows:
                    data = row.get("data") or {}
                    writer.writerow(csv_row([
                        row["email"],
                        data.get("original_email", ""),
                        row["status"], row["reason"], row["mx"],
                        data.get("name", ""), data.get("first_name", ""),
                        data.get("last_name", ""), data.get("gender", ""),
                        data.get("country", ""),
                        data.get("birth_year", ""), data.get("company", ""),
                        data.get("job_role", ""),
                        data.get("engagement_score", ""),
                        data.get("engagement_grade", ""),
                        data.get("verdict_confidence", ""),
                        data.get("verdict_basis", ""),
                        data.get("provider_name", ""),
                        data.get("domain_type", ""),
                        data.get("name_source", ""), data.get("gender_source", ""),
                        data.get("country_source", ""),
                        data.get("company_source", ""),
                        data.get("job_role_source", ""),
                        data.get("social_accounts", ""),
                        data.get("validated_at", ""),
                        data.get("domain_valid_ratio", ""),
                        data.get("domain_checked", ""),
                        "да" if data.get("from_cache") else "",
                        "да" if data.get("role_address") else "",
                        data.get("suggested_email", ""),
                        data.get("typo_of", ""),
                    ]))

            skipped = {"n": 0}

            def rows():
                for row in self.store.iter_matching(filters=picked):
                    if drop and normalize_for_dedup(row["email"]) in drop:
                        skipped["n"] += 1
                        continue
                    yield row

            written, saved = baseops.write_chunks_stream(rows(), path, chunk, write_csv)
            note = f"[INFO] Сохранено строк: {saved}."
            if skipped["n"]:
                note += f" Вычтено по отпискам: {skipped['n']}."
            if len(written) > 1:
                note += f" Файлов: {len(written)}."
            if "pending" in picked.get("groups", ()):
                note += " Не проверенные в файл не входят: вердикта у них нет."
            self._on_log(note, "valid")
        except Exception as exc:
            self._on_log(f"[DEAD] Выгрузка не удалась: {type(exc).__name__}: {exc}", "dead")
        finally:
            self._export_done()


    PARSER_ENGINES = list(SEARCH_ENGINES)


    def client_error(self, payload=None):
        payload = payload if isinstance(payload, dict) else {}
        message = str(payload.get("message") or "")[:500]
        where = str(payload.get("where") or "")[:300]
        stack = str(payload.get("stack") or "")[:4000]

        if not (message.strip() or where.strip() or stack.strip()):
            return {"ok": False, "error": "пустое сообщение — записывать нечего"}

        body = message
        if stack:
            body += "\n" + stack
        log_crash("окно", body, context=where or None)

        куда = (self._parser_log if str(payload.get("mode") or "") == "parser"
                else self._on_log)
        куда("[DEAD] Сбой в окне: %s. Записано в %s"
             % (message, crash_log_path()), "dead")
        return {"ok": True, "path": crash_log_path()}


    def export_segments(self, payload):
        if self._export_busy:
            return {"ok": False, "error": "Выгрузка уже идёт"}

        key = str(payload.get("by") or "country").strip()
        if key not in ("country", "gender", "provider"):
            return {"ok": False, "error": "Неизвестный признак: %s" % key}

        if self.window is None:
            return {"ok": False, "error": "Окно недоступно"}
        chosen = self.window.create_file_dialog(_тип_диалога("FOLDER"))
        if not chosen:
            return {"ok": False, "cancelled": True}
        folder = chosen if isinstance(chosen, str) else chosen[0]

        picked = self._filters(payload)
        self._export_busy = True
        threading.Thread(target=self._segments_worker,
                         args=(folder, key, picked), daemon=True).start()
        return {"ok": True}

    def _segments_worker(self, folder, key, picked):
        import csv

        from core.baseops import segment_filename, split_by_segment
        try:
            rows = list(self.store.iter_matching(filters=picked))
            buckets = split_by_segment(rows, key)
            if not buckets:
                self._on_log("[DEAD] В выборке нечего раскладывать.", "dead")
                return

            written = 0
            for value, group in sorted(buckets.items(),
                                       key=lambda kv: -len(kv[1])):
                name = "%s-%s.csv" % (key, segment_filename(value))
                path = os.path.join(folder, name)
                with io.open(path, "w", encoding=export_encoding(path),
                             newline="") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(["Email", "Status", "Name", "Gender",
                                     "Country", "Score", "ValidatedAt"])
                    for row in group:
                        data = row.get("data") or {}
                        writer.writerow(csv_row([
                            row["email"], row["status"], data.get("name", ""),
                            data.get("gender", ""), data.get("country", ""),
                            data.get("engagement_score", ""),
                            data.get("validated_at", ""),
                        ]))
                written += 1
                self._on_log("[VALID] %s — %d адресов." % (name, len(group)), "valid")

            self._on_log("[INFO] Разложено файлов: %d. Папка: %s"
                         % (written, folder), "info")
        except Exception as exc:
            self._on_log("[DEAD] Раскладка не удалась: %s: %s"
                         % (type(exc).__name__, exc), "dead")
        finally:
            self._export_done()

    def copy_rows(self, payload):
        picked = self._filters(payload)
        limit = 200_000
        out = []
        for row in self.store.iter_matching(filters=picked):
            out.append(row["email"])
            if len(out) >= limit:
                break
        return {"text": "\n".join(out), "count": len(out), "capped": len(out) >= limit}


class _Handler(BaseHTTPRequestHandler):
    api: ValidatorApi = None
    token: str = ""

    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def handle_one_request(self):
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def _authorised(self):
        header = self.headers.get("X-Token")
        query = parse_qs(urlparse(self.path).query)
        given = header or (query.get("token") or [""])[0]
        return secrets.compare_digest(given or "", self.token)

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        raw = body if isinstance(body, bytes) else str(body).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    PUBLIC = {"/style.css", "/app.js"}

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/favicon.ico":
            with open(resource_path("assets", "MailFact.ico"), "rb") as handle:
                return self._send(200, handle.read(), "image/x-icon")
        if path not in self.PUBLIC and not self._authorised():
            self._send(403, json.dumps({"error": "forbidden"}))
            return

        name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        safe = os.path.normpath(os.path.join(WEB_DIR, name))
        inside = safe.startswith(WEB_DIR + os.sep)
        if not inside or not os.path.isfile(safe):
            self._send(404, json.dumps({"error": "not found"}))
            return

        with open(safe, "rb") as handle:
            body = handle.read()
        if name == "index.html":
            body = body.replace(b"__TOKEN__", self.token.encode())
        ctype = mimetypes.guess_type(safe)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        self._send(200, body, ctype)

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length") or 0)
            сырое = self.rfile.read(length) if length else b""
        except Exception:
            сырое = b""

        if not self._authorised():
            self._send(403, json.dumps({"error": "forbidden"}))
            return
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            self._send(404, json.dumps({"error": "not found"}))
            return

        try:
            self.api.last_seen_at = time.time()
            self.api.request_count += 1
        except Exception:
            pass

        method = path[len("/api/"):]
        handler = getattr(self.api, method, None)
        if handler is None or method.startswith("_") or not callable(handler):
            self._send(404, json.dumps({"error": "unknown method"}))
            return

        try:
            payload = json.loads(сырое or b"{}")
        except Exception:
            payload = {}

        try:
            result = handler(payload)
        except Exception as exc:
            log_crash("мост", "Обработчик метода не выполнился",
                      exc, context="метод %s" % method)
            self._send(500, json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
            return
        self._send(200, json.dumps(result, ensure_ascii=False, default=str))


def start_api_server(api):
    token = secrets.token_urlsafe(24)
    handler = type("Handler", (_Handler,), {"api": api, "token": token})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1], token


def _verdict_age(stamp):
    import datetime

    text = str(stamp or "").strip()
    if not text:
        return {}
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            when = datetime.datetime.strptime(text, fmt)
            break
        except ValueError:
            when = None
    if when is None:
        return {}

    days = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - when).days
    if days < 0:
        days = 0
    try:
        from core.settings import get
        limit = int(get("verdict_fresh_days", 30) or 30)
    except Exception:
        limit = 30
    return {"days": days, "stale": days > max(1, limit)}


def _gravatar_hash(email):
    try:
        return hashlib.md5(str(email).strip().lower().encode("utf-8")).hexdigest()
    except Exception:
        return ""


def _storage_path():
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "EmailValidatorPro", "webview")
    os.makedirs(path, exist_ok=True)
    return path


class WindowWatchdog:

    SLOW_RATE = 3.0

    def __init__(self, api, silence_seconds=20.0, check_every=5.0):
        self.api = api
        self.silence = float(silence_seconds)
        self.check_every = float(check_every)
        self._stop = threading.Event()
        self._reported = False
        self._slow_reported = False
        self._last_count = 0
        self._last_rate_at = 0.0

    def check_once(self, now=None):
        now = time.time() if now is None else now
        seen = getattr(self.api, "last_seen_at", 0.0) or 0.0
        if not seen:
            return False
        quiet = now - seen
        if quiet < self.silence:
            self._reported = False
            return False
        if self._reported:
            return False
        self._reported = True
        log_crash("окно",
                  "Окно перестало отвечать: за %.0f секунд ни одного запроса. "
                  "Питон при этом жив — значит замер сам интерфейс."
                  % quiet,
                  context="последний раз окно отвечало в %s"
                          % time.strftime("%H:%M:%S", time.localtime(seen)))
        return True

    def check_rate(self, now=None):
        """Не подавлено ли окно. Возвращает True, если подавление записано.

        Отдельно от проверки тишины, потому что случай ДРУГОЙ: подавленное
        окно не молчит, оно отвечает — просто вшестеро реже. Тишины не
        наступает никогда, и проверка по паузе такое пропускает полностью.

        Именно этот случай владелец показывал четыре раза подряд: интерфейс
        замирает, питон жив, ошибок нет, журнал пуст.
        """
        now = time.time() if now is None else now
        count = int(getattr(self.api, "request_count", 0) or 0)
        if not self._last_rate_at:
            self._last_rate_at, self._last_count = now, count
            return False

        elapsed = now - self._last_rate_at
        if elapsed < self.check_every:
            return False
        rate = (count - self._last_count) / elapsed
        self._last_rate_at, self._last_count = now, count

        if rate <= 0 or rate >= self.SLOW_RATE:
            self._slow_reported = False
            return False
        if self._slow_reported:
            return False
        self._slow_reported = True
        log_crash("окно",
                  "Окно отвечает намного реже обычного: %.1f запроса в "
                  "секунду вместо шести. Так выглядит страница, которую "
                  "браузер счёл невидимой: таймеры зажаты, отрисовка "
                  "остановлена. Программа при этом исправна." % rate,
                  context="темп ниже порога %.1f/с" % self.SLOW_RATE)
        return True

    def start(self):
        def loop():
            while not self._stop.wait(self.check_every):
                try:
                    self.check_once()
                    self.check_rate()
                except Exception:
                    pass

        threading.Thread(target=loop, daemon=True, name="сторож-окна").start()
        return self

    def stop(self):
        self._stop.set()


def _announce_past_crashes(api, within_hours=24):
    try:
        found = recent_crashes(within_hours=within_hours)
    except Exception:
        return 0
    if not found:
        return 0
    return len(found)


WEBVIEW_NO_THROTTLE = (
    "--disable-background-timer-throttling "
    "--disable-renderer-backgrounding "
    "--disable-backgrounding-occluded-windows"
)


def apply_no_throttle(environ=None):
    environ = os.environ if environ is None else environ
    key = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"
    current = environ.get(key, "")
    missing = [flag for flag in WEBVIEW_NO_THROTTLE.split()
               if flag not in current]
    if not missing:
        return current
    environ[key] = (current + " " + " ".join(missing)).strip()
    return environ[key]


def run(selftest_close=None):
    from core.timing import включено, отметить, записать

    apply_no_throttle()
    quiet_chromium()
    отметить("настройки движка")

    import webview

    api = ValidatorApi()
    отметить("ValidatorApi()")
    _server, port, token = start_api_server(api)
    отметить("мост поднят")

    seed_data()
    отметить("поставляемые списки на месте")

    window = webview.create_window(
        APP_NAME,
        f"http://127.0.0.1:{port}/?token={token}",
        width=1440, height=900, min_size=(900, 620),
        background_color="#0A0E14",
    )
    api.window = window
    отметить("окно создано")

    install_webview_noise_filter(
        on_hint=lambda текст: api._on_log("[WARN] " + текст, "trap"))
    window.events.closing += отметить_закрытие
    отметить("фильтр шума движка")

    for текст, тег in api.START_LINES:
        api._on_log(текст, тег)

    _announce_past_crashes(api)
    отметить("разбор прошлых аварий")
    WindowWatchdog(api).start()
    отметить("сторож окна")

    reaper = WebViewReaper()
    reaper.snapshot()
    отметить("снимок чужих процессов движка")

    if selftest_close:
        def _закрыть_потом():
            time.sleep(float(selftest_close))
            try:
                window.destroy()
            except Exception:
                pass

        threading.Thread(target=_закрыть_потом, daemon=True).start()

    from core.winicon import apply_when_shown
    apply_when_shown(resource_path("assets", "MailFact.ico"))
    отметить("иконка поставлена в очередь")

    if включено():
        def _замер_до_показа():
            from core.timing import дождаться_окна
            провал = дождаться_окна(window.events)
            try:
                записать(os.environ.get("MAILFACT_TIMING_FILE", "timing.log"), провал)
            except Exception:
                pass
            try:
                window.destroy()
            except Exception:
                pass

        threading.Thread(target=_замер_до_показа, daemon=True,
                         name="замер").start()

    отметить("перед webview.start")
    try:
        webview.start(storage_path=_storage_path(), private_mode=False)
    finally:
        reaper.reap()


if __name__ == "__main__":
    sys.path.insert(0, ROOT)
    run()
