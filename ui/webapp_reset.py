# -*- coding: utf-8 -*-
import threading

__all__ = ["ResetMixin"]


class ResetMixin:
    def _quiet_after_stop(self, handler):
        gate = self._view_gate()

        def wrapped(*args, **kwargs):
            with gate:
                if self._discarding:
                    return False
                return handler(*args, **kwargs)
        return wrapped

    def _view_gate(self):
        return self.__dict__.setdefault("_view_gate_lock", threading.RLock())

    def _mute_engine(self):
        with self._view_gate():
            self._discarding = True

    def _claim_start(self, payload):
        with self.__dict__.setdefault("_start_gate_lock", threading.Lock()):
            if self._busy() or self._starting:
                return {"ok": False, "error": self._start_refusal()}
            if not self.email_sources:
                return {"ok": False, "error": "Сначала выберите адреса"}
            if not self.proxy_sources and not payload.get("allowDirect"):
                return {"ok": False, "direct": True,
                        "error": "Прокси не заданы. Проверка пойдёт с твоего "
                                 "домашнего IP — подтверди, если это осознанно."}
            if not self._start_clears_the_table():
                return {"ok": False, "error": "Идёт выгрузка таблицы — дождитесь её конца."}
            self._starting = True
            return None

    def _start_refusal(self):
        if self._starting and self._discarding:
            return self._ENGINE_FREEING
        return "Проверка уже идёт"

    def _run_flags(self):
        running = bool(self.pipeline.is_running) and not self._discarding
        stage = getattr(getattr(self.pipeline, "activity", None), "stage_key", "")
        return running, running and stage == "proxies"

    _ENGINE_FREEING = ("Движок ещё завершает остановленную проверку — это займёт "
                       "несколько секунд. Нажмите «Начать проверку» чуть позже.")

    START_LINES = (("[INFO] Валидатор готов к работе.", "info"),
                   ("[INFO] Выберите базу адресов и список прокси.", "info"))

    def stop(self, payload=None):
        self._mute_engine()
        self.pipeline.stop(abort=True)
        self._reset_validator_view()
        if not self._parser_running():
            self._reset_parser_view()
        return {"ok": True, "state": self._state, "seq": self._log_seq,
                "engineBusy": bool(self._starting)}

    def _parser_running(self):
        parser = getattr(self, "parser", None)
        if self.__dict__.get("_parser_launching"):
            return True
        if parser is None or not callable(getattr(parser, "is_alive", None)):
            return False
        stopping = getattr(parser, "_stop_event", None)
        if stopping is not None and stopping.is_set():
            return False
        return bool(parser.is_alive())

    def _export_gate(self):
        return self.__dict__.setdefault("_export_gate_lock", threading.Lock())

    def _clear_results(self):
        self.store.clear()
        reset = getattr(self, "_base_reset", None)
        if callable(reset):
            reset()

    def _export_done(self):
        with self._export_gate():
            self._export_busy = False
            if self._clear_store_after_export:
                self._clear_store_after_export = False
                self._clear_results()

    def _reset_validator_view(self):
        with self._export_gate():
            if self._export_busy:
                self._clear_store_after_export = True
            else:
                self._clear_results()
        self._progress = (0, 0)
        self._proxy_progress = (0, 0)
        self._phase = ("", 0)
        self._state = "idle"
        self._proxy_summary = None
        with self._lock:
            self._history = []
            self._pending = []
        for text, tag in self.START_LINES:
            self._on_log(text, tag)
        for kind in ("emails", "proxies"):
            self._forget_sources(kind)
        self.suppress_path = None

    def _forget_sources(self, kind):
        bucket = self._sources.get(kind)
        if bucket is None:
            return
        bucket.clear()
        with self._count_lock:
            self._file_stamps[kind] = []
        self._recount(kind)
        self._rescan_base(kind)

    def _start_clears_the_table(self):
        with self._export_gate():
            if self._export_busy:
                return False
            self._clear_store_after_export = False
            self._clear_results()
            return True

    def _validator_running(self):
        pipeline = getattr(self, "pipeline", None)
        if pipeline is not None and getattr(pipeline, "is_running", False):
            return True
        return bool(getattr(self, "_starting", False)) and not getattr(self, "_discarding", False)

    def _reset_parser_view(self):
        self.__dict__["_parser_discarding"] = True
        with self._lock:
            self._parser_rows = []
            self._parser_seen = set()
            self._parser_history = []
            self._parser_pending = []
        self._parser_stats = {"dorksDone": 0, "dorksTotal": 0,
                              "pages": 0, "snippets": 0, "emails": 0}
        self._parser_progress = (0, 0, 0, "Парсинг")
        self._parser_state = "idle"
        for kind in ("dorks", "pproxy"):
            self._forget_sources(kind)
