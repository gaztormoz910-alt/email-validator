# -*- coding: utf-8 -*-
from core.activity import ActivityMonitor, Pulse, payload

__all__ = ["ActivityBridgeMixin"]


class ActivityBridgeMixin:
    def _validator_activity(self):
        pipeline = getattr(self, "pipeline", None)
        if getattr(self, "_discarding", False):
            return self._fresh_activity("validator", getattr(self, "_starting", False))
        try:
            snap = pipeline.activity.snapshot(
                paused=bool(getattr(pipeline, "is_paused", False)),
                alive=pipeline._worker_alive())
            return payload(snap)
        except Exception as exc:
            return {"level": "idle", "title": "Состояние недоступно",
                    "detail": "Не удалось снять состояние движка: %s" % exc,
                    "trail": []}

    @staticmethod
    def _fresh_activity(kind, engine_busy=False):
        snap = payload(ActivityMonitor(kind=kind).snapshot())
        if engine_busy:
            snap = dict(snap, detail="Движок завершает остановленную работу — через "
                                     "несколько секунд можно запускать снова.")
        return snap

    @property
    def parser_activity(self):
        mon = self.__dict__.get("_parser_activity")
        if mon is None:
            mon = ActivityMonitor(kind="parser", emit=self._parser_stage_line)
            self.__dict__["_parser_activity"] = mon
        return mon

    def _parser_stage_line(self, text, tag):
        self.parser_activity.beat()
        self._parser_log(text, tag)

    def _parser_activity_payload(self):
        pipeline = getattr(self, "parser", None)
        alive = None
        paused = False
        if self.__dict__.get("_parser_launching"):
            pipeline = None
        if self.__dict__.get("_parser_discarding"):
            return self._fresh_activity("parser", self._parser_draining())
        if pipeline is not None:
            try:
                alive = bool(pipeline.is_alive())
                paused = bool(pipeline._pause_event.is_set())
            except Exception:
                pass
        try:
            return payload(self.parser_activity.snapshot(paused=paused, alive=alive))
        except Exception as exc:
            return {"level": "idle", "title": "Состояние недоступно",
                    "detail": "Не удалось снять состояние сбора: %s" % exc,
                    "trail": []}

    def _observed_parser_callbacks(self):
        mon = self.parser_activity

        def on_log(message, *args):
            mon.beat()
            self._parser_log(message, *args)

        def on_progress(current, total, pct=0, label="Парсинг"):
            if label == "Проверка прокси":
                mon.aux(current, total)
            else:
                mon.beat()
            self._parser_progress_cb(current, total, pct, label)

        def on_stats(dorks_tot, dorks_done, pages, snippets, emails):
            mon.progress(dorks_done, dorks_tot)
            mon.set_found(emails)
            self._parser_stats_cb(dorks_tot, dorks_done, pages, snippets, emails)

        def on_result(email, dork, *args, **kwargs):
            mon.beat()
            self._parser_result_cb(email, dork, *args, **kwargs)

        return {"on_log": on_log, "on_progress": on_progress,
                "on_stats_update": on_stats, "on_result_found": on_result}

    def _start_parser_pulse(self, pipeline):
        pulse = Pulse(self.parser_activity,
                      emit=lambda text, tag: self._parser_log(text, tag),
                      paused=lambda: pipeline._pause_event.is_set(),
                      alive=pipeline.is_alive)
        pulse.start()
        self.__dict__["_parser_pulse"] = pulse
        return pulse

    def _finish_parser_activity(self, aborted):
        pipeline = getattr(self, "parser", None)
        stopped = False
        failed = ""
        try:
            stopped = pipeline is not None and pipeline._stop_event.is_set()
            failed = getattr(pipeline, "failed_reason", "") or ""
        except Exception:
            pass
        if failed:
            outcome, note = "failed", failed
        elif not aborted:
            outcome, note = "done", ""
        elif stopped:
            outcome, note = "stopped", ""
        else:
            outcome, note = "blocked", "сбор не смог начаться — причина в журнале выше"
        self.parser_activity.finish(outcome, note)
        pulse = self.__dict__.get("_parser_pulse")
        if pulse is not None:
            pulse.stop()
