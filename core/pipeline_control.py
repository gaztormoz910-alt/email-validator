# -*- coding: utf-8 -*-
__all__ = ["RunControlMixin"]


class RunControlMixin:
    def stop(self, abort=False):
        if abort:
            self._aborting = True
            self._abort_event.set()
            network = getattr(self, "network", None)
            event = getattr(network, "abort_event", None)
            if event is not None and event is not self._abort_event:
                event.set()
            close = getattr(network, "abort_connections", None)
            if callable(close):
                close()
            state = getattr(self, "state", None)
            freeze = getattr(state, "freeze", None)
            if callable(freeze):
                freeze()
        self._stop_requested = True
        self.is_running = False
        self.activity.request_stop()
        self.is_paused = False
        self.activity.set_paused(False)
        self._stop_profile_refresher()

    def _settle_resume_journal(self, state, resume, feeder_error):
        try:
            if (resume and not self._stop_requested and not feeder_error) or self._aborting:
                state.clear()
        except Exception:
            pass

    def pause(self):
        self.is_paused = not self.is_paused
        self.activity.set_paused(self.is_paused)
        return self.is_paused
