# -*- coding: utf-8 -*-
import os
import threading
import time
from core.baseops import csv_row, export_encoding
from ui.webapp_sources import _тип_диалога

__all__ = ["ParserMixin"]


class ParserMixin:
    _PARSER_LAUNCH_LOCK = threading.Lock()

    def _parser_quiet(self):
        return bool(self.__dict__.get("_parser_discarding"))

    def _parser_log(self, message, tag="info"):
        if self._parser_quiet():
            return
        line = {"text": str(message), "tag": tag, "t": time.time()}
        with self._lock:
            self._parser_pending.append(line)
            self._parser_history.append(line)
            if len(self._parser_history) > self._history_cap:
                del self._parser_history[:len(self._parser_history) - self._history_cap]
    def _parser_progress_cb(self, current, total, pct, label="Парсинг"):
        if self._parser_quiet():
            return
        self._parser_progress = (int(current or 0), int(total or 0),
                                 int(pct or 0), str(label))
    def _parser_stats_cb(self, dorks_tot, dorks_done, pages, snippets, emails):
        if self._parser_quiet():
            return
        self._parser_stats = {"dorksTotal": int(dorks_tot or 0),
                              "dorksDone": int(dorks_done or 0),
                              "pages": int(pages or 0),
                              "snippets": int(snippets or 0),
                              "emails": int(emails or 0)}
    def _parser_result_cb(self, email, dork, *args, **kwargs):
        key = str(email).strip().lower()
        if not key or self._parser_quiet():
            return
        with self._lock:
            if key in self._parser_seen:
                return
            self._parser_seen.add(key)
            self._parser_rows.append((str(email), str(dork or "")))
    def _parser_complete_cb(self, aborted=False):
        if self._parser_quiet():
            self._finish_parser_activity(aborted)
            return
        self._parser_state = "done"
        failed = getattr(self.parser, "failed_reason", "") if self.parser is not None else ""
        self._parser_log("[Система] Сбор адресов прерван ошибкой." if failed
                         else "[Система] Сбор адресов завершён." if not aborted
                         else "[Система] Сбор адресов остановлен.", "info")
        self._finish_parser_activity(aborted)
    _PARSER_FREEING = ("Сбор ещё завершает остановленную работу — это займёт "
                       "несколько секунд. Нажмите «Начать сбор» чуть позже.")

    def _parser_draining(self):
        return bool(self._parser_quiet() and self.parser is not None
                    and self.parser.is_alive())

    def parser_start(self, payload):
        if self.parser is not None and self.parser.is_alive():
            return {"ok": False, "error": self._PARSER_FREEING if self._parser_quiet()
                    else "Сбор уже идёт"}
        if not self._sources["dorks"]:
            return {"ok": False, "error": "Сначала загрузите дорки"}

        engine = payload.get("engine") or self.PARSER_ENGINES[0]
        if engine not in self.PARSER_ENGINES:
            return {"ok": False, "error": "Неизвестный поисковик"}
        threads = self._number(payload, "threads", 20, 1, 500)
        timeout = self._number(payload, "timeout", 15, 1, 120)

        with self._PARSER_LAUNCH_LOCK:
            if self.__dict__.get("_parser_launching"):
                return {"ok": False, "error": "Сбор уже запускается"}
            self.__dict__["_parser_launching"] = True
            self.__dict__["_parser_cancel"] = False
        self.__dict__["_parser_discarding"] = False

        with self._lock:
            self._parser_rows = []
            self._parser_seen = set()
        self._parser_stats = {"dorksDone": 0, "dorksTotal": 0,
                              "pages": 0, "snippets": 0, "emails": 0}
        self._parser_progress = (0, 0, 0, "Парсинг")
        self._parser_state = "running"
        self.parser_activity.begin()
        callbacks = self._observed_parser_callbacks()

        dork_sources = list(self._sources["dorks"])
        proxy_sources = list(self._sources["pproxy"])

        def launch():
            try:
                proxies = []
                if proxy_sources:
                    from core.network import dedupe_proxies_stream
                    from core.streamer import StreamLoader
                    proxies = list(dedupe_proxies_stream(
                        StreamLoader(proxy_sources).stream_lines()))

                from core.parser_pipeline import ParserPipeline
                pipeline = ParserPipeline(
                    dork_sources=dork_sources,
                    proxies=proxies,
                    max_threads=threads,
                    timeout=timeout,
                    on_log=callbacks["on_log"],
                    on_progress=callbacks["on_progress"],
                    on_stats_update=callbacks["on_stats_update"],
                    on_result_found=callbacks["on_result_found"],
                    on_complete=self._parser_complete_cb,
                    engine_name=engine,
                    activity=self.parser_activity,
                )
                with self._PARSER_LAUNCH_LOCK:
                    cancelled = bool(self.__dict__.get("_parser_cancel"))
                    if not cancelled:
                        self.parser = pipeline
                        pipeline.start()
                        self.__dict__["_parser_launching"] = False
                if cancelled:
                    self._parser_state = "done"
                    self._parser_log("[Система] Сбор остановлен до начала работы.", "info")
                    self.parser_activity.finish("stopped")
                    self.__dict__["_parser_launching"] = False
                    return
                self._start_parser_pulse(pipeline)
            except Exception as exc:
                self._parser_state = "done"
                self._parser_log("[Ошибка] Сбор не запустился: %s" % exc, "dead")
                self.parser_activity.finish("failed")
                self.__dict__["_parser_launching"] = False

        threading.Thread(target=launch, daemon=True).start()
        return {"ok": True}
    def parser_pause(self, payload=None):
        pipeline = self.parser
        if pipeline is None or not pipeline.is_alive():
            return {"state": self._parser_state}
        if pipeline._pause_event.is_set():
            pipeline.resume()
            self._parser_state = "running"
            self._parser_log("[Система] Сбор возобновлён.", "info")
        else:
            pipeline.pause()
            self._parser_state = "paused"
            self._parser_log("[Система] Сбор приостановлен.", "info")
        return {"state": self._parser_state}
    def parser_stop(self, payload=None):
        with self._PARSER_LAUNCH_LOCK:
            launching = bool(self.__dict__.get("_parser_launching"))
            if launching:
                self.__dict__["_parser_cancel"] = True
        pipeline = self.parser
        if launching:
            self.parser_activity.request_stop()
            self._parser_log("[Система] Остановка сбора.", "info")
        elif pipeline is not None and pipeline.is_alive():
            pipeline.stop()
            self.parser_activity.request_stop()
            self._parser_log("[Система] Остановка сбора.", "info")
        self._reset_parser_view()
        if not self._validator_running():
            self._mute_engine()
            self._reset_validator_view()
        return {"ok": True, "state": self._parser_state}

    def parser_state(self, payload=None):
        with self._lock:
            lines, self._parser_pending = self._parser_pending, []
            found = len(self._parser_rows)
        current, total, pct, label = self._parser_progress
        alive = self.parser is not None and self.parser.is_alive()
        draining = self._parser_draining()
        stats = dict(self._parser_stats)
        stats["found"] = found
        return {"state": self._parser_state,
                "running": bool(alive) and not draining,
                "engineBusy": draining,
                "engines": list(self.PARSER_ENGINES),
                "stats": stats,
                "progress": {"current": current, "total": total,
                             "pct": pct, "label": label},
                "activity": self._parser_activity_payload(),
                "log": lines}
    def parser_log_tail(self, payload=None):
        with self._lock:
            self._parser_pending = []
            return {"log": list(self._parser_history)}
    def parser_page(self, payload=None):
        from ui.webapp import PAGE_SIZE
        payload = payload or {}
        number = max(1, int(payload.get("page") or 1))
        with self._lock:
            rows = list(self._parser_rows)
        total = len(rows)
        pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        number = min(number, pages)
        start = (number - 1) * PAGE_SIZE
        chunk = rows[start:start + PAGE_SIZE]
        return {"rows": [{"email": e, "dork": d} for e, d in chunk],
                "page": number, "pages": pages, "total": total}
    def parser_copy(self, payload=None):
        limit = 200_000
        with self._lock:
            rows = self._parser_rows[:limit]
        return {"text": chr(10).join(e for e, _ in rows), "count": len(rows),
                "capped": len(rows) >= limit}
    def parser_export(self, payload=None):
        if self.window is None:
            return {"ok": False, "error": "Окно недоступно"}
        with self._lock:
            rows = list(self._parser_rows)
        if not rows:
            return {"ok": False, "error": "Пока нечего сохранять"}

        path = self.window.create_file_dialog(
            _тип_диалога("SAVE"), save_filename="parsed_emails.txt",
            file_types=("Текст (*.txt)", "CSV (*.csv)"))
        if not path:
            return {"ok": False, "error": ""}
        path = path if isinstance(path, str) else path[0]

        def write():
            try:
                with open(path, "w", encoding=export_encoding(path),
                          newline="") as handle:
                    if path.lower().endswith(".csv"):
                        import csv
                        writer = csv.writer(handle)
                        writer.writerow(["email", "dork"])
                        writer.writerows(csv_row(r) for r in rows)
                    else:
                        for email, _dork in rows:
                            handle.write(email + chr(10))
                self._parser_log("[Система] Сохранено адресов: %d." % len(rows), "info")
            except OSError as exc:
                self._parser_log("[Ошибка] Не удалось сохранить: %s" % exc, "dead")

        threading.Thread(target=write, daemon=True).start()
        return {"ok": True, "path": os.path.basename(path), "count": len(rows)}
