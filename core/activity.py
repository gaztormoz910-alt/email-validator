# -*- coding: utf-8 -*-
import threading
import time
from collections import deque
from contextlib import contextmanager

__all__ = ["ActivityMonitor", "describe", "payload", "pulse_line", "Pulse",
           "observe_callbacks", "PipelineActivityMixin", "fmt_duration",
           "fmt_number", "net_budget", "STAGES", "PAUSABLE", "INTERRUPTIBLE"]

STAGES = {
    "start":     ("Запуск", "Запуск", 60, False),
    "port25":    ("Проверка исходящего порта 25", "Порт 25", 120, True),
    "cache":     ("Кэш вердиктов прошлых прогонов", "Кэш", 120, False),
    "lists":     ("Обновление списков одноразовых доменов", "Списки", 300, True),
    "filters":   ("Загрузка фильтров спама", "Фильтры", 120, False),
    "proxies":   ("Проверка прокси", "Прокси", 120, True),
    "profiles":  ("Профили прокси: выходной IP, PTR, чёрные списки", "Профили", 300, True),
    "ai":        ("Прогрев модели ИИ", "ИИ", 900, False),
    "models":    ("Загрузка модулей имён, пола и страны", "Модули", 600, False),
    "check":     ("Проверка адресов", "Проверка", 60, True),
    "retry":     ("Перепроверка отложенных адресов", "Перепроверка", 60, True),
    "finish":    ("Подведение итогов", "Итоги", 180, False),
    "p_init":    ("Подготовка сбора", "Подготовка", 600, False),
    "p_tor":     ("Запуск Tor", "Tor", 600, True),
    "p_proxies": ("Проверка прокси", "Прокси", 120, True),
    "p_search":  ("Поиск по доркам", "Поиск", 90, True),
}

_SILENT = {"start"}

PAUSABLE = {"check", "retry", "p_search"}

INTERRUPTIBLE = PAUSABLE | {"proxies", "p_proxies", "profiles", "p_tor"}

NET_SLOW = 45.0
NET_STALL = 240.0


def net_budget(timeout, address_deadline):
    try:
        return 2.0 * float(address_deadline) + 6.0 * float(timeout)
    except (TypeError, ValueError):
        return None

PULSE_INTERVAL = 15.0

_FINAL = ("done", "stopped", "failed", "blocked")

LEVELS = ("idle", "done", "stopped", "ok", "wait", "paused", "stopping",
          "slow", "stall", "blocked", "failed", "dead")


def fmt_number(value):
    try:
        return format(int(value), ",").replace(",", " ")
    except (TypeError, ValueError):
        return str(value)


def fmt_duration(seconds):
    try:
        s = max(0, int(round(float(seconds))))
    except (TypeError, ValueError):
        return "—"
    if s < 60:
        return "%d с" % s
    m, s = divmod(s, 60)
    if m < 60:
        return "%d мин %02d с" % (m, s)
    h, m = divmod(m, 60)
    return "%d ч %02d мин" % (h, m)


def _ago(age):
    if age is None:
        return "событий ещё не было"
    if age < 2:
        return "последнее событие только что"
    return "последнее событие %s назад" % fmt_duration(age)


class ActivityMonitor:

    def __init__(self, kind="validator", emit=None, clock=None):
        self.kind = kind
        self.emit = emit
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        self.net_longest = None
        self._reset()

    def _reset(self):
        self.state = "idle"
        self.outcome_note = ""
        self.stage_key = ""
        self.stage_started = None
        self.run_started = None
        self.run_ended = None
        self.last_event = None
        self.inflight = 0
        self.wait_until = None
        self.wait_reason = ""
        self.stopping = False
        self.progress_current = 0
        self.progress_total = 0
        self.aux_current = 0
        self.aux_total = 0
        self.found = 0
        self.skipped_count = 0
        self.skip_in_total = True
        self._pinned_total = None
        self.paused = False
        self._pause_started = None
        self.trail = []
        self._samples = deque(maxlen=240)

    def begin(self):
        with self._lock:
            self._reset()
            now = self._clock()
            self.state = "running"
            self.run_started = now
            self.stage_key = "start"
            self.stage_started = now
            self.last_event = now

    def stage(self, key, cut=None):
        lines = []
        with self._lock:
            if self.state != "running":
                self.begin()
            now = self._clock()
            if self.stage_key == key:
                return
            if cut is None:
                cut = "stopped" if self.stopping and self.stage_key in INTERRUPTIBLE else ""
            lines.extend(self._close_stage(now, cut))
            self.stage_key = key
            self.stage_started = now
            self.last_event = now
            self.wait_until = None
            self.wait_reason = ""
            if key not in _SILENT:
                lines.append(("▶ %s" % STAGES.get(key, (key,))[0], "stage"))
        self._emit(lines)

    def finish(self, outcome="done", note="", interrupted=False, stage_done=False):
        lines = []
        with self._lock:
            if self.state in _FINAL:
                return
            if self.state == "idle":
                self.state = outcome
                self.outcome_note = note
                return
            now = self._clock()
            cut = ""
            if stage_done:
                cut = ""
            elif outcome == "failed":
                cut = "failed"
            elif outcome == "blocked":
                cut = "blocked"
            elif interrupted or (outcome == "stopped" and self.stage_key in INTERRUPTIBLE):
                cut = "stopped"
            lines.extend(self._close_stage(now, cut))
            self.state = outcome if outcome in _FINAL else "done"
            self.outcome_note = note
            self.stage_key = ""
            self.stage_started = None
            self.run_ended = now
            self.inflight = 0
            self.wait_until = None
            begun = self.run_started if self.run_started is not None else now
            total = fmt_duration(now - begun)
            text = {
                "done": "■ Готово. Весь прогон занял %s." % total,
                "stopped": "■ Остановлено по вашей команде через %s." % total,
                "failed": "■ Прервано ошибкой через %s — причина в журнале выше." % total,
                "blocked": "■ Работа не выполнялась: %s." % (note or "нечем проверять"),
            }[self.state]
            lines.append((text, "stage"))
        self._emit(lines)

    def _close_stage(self, now, cut=""):
        prev, started = self.stage_key, self.stage_started
        if not prev or started is None:
            return []
        took = max(0.0, now - started)
        self.trail.append((prev, took, bool(cut)))
        if prev in _SILENT:
            return []
        label = STAGES.get(prev, (prev,))[0]
        if cut == "failed":
            text = "✗ %s — оборвано ошибкой через %s" % (label, fmt_duration(took))
        elif cut == "blocked":
            text = "✗ %s — дальше не пройти, через %s" % (label, fmt_duration(took))
        elif cut:
            text = "✗ %s — остановлено через %s" % (label, fmt_duration(took))
        else:
            text = "✓ %s — %s" % (label, fmt_duration(took))
        return [(text, "stage")]

    def request_stop(self):
        with self._lock:
            if self.state == "running":
                self.stopping = True

    def _emit(self, lines):
        emit = self.emit
        if not emit:
            return
        for text, tag in lines:
            try:
                emit(text, tag)
            except Exception:
                pass

    def beat(self):
        with self._lock:
            self.last_event = self._clock()

    def progress(self, current, total):
        with self._lock:
            now = self._clock()
            self.last_event = now
            try:
                self.progress_current = int(current or 0)
                self.progress_total = int(total or 0)
            except (TypeError, ValueError):
                return
            if self._pinned_total is not None:
                self.progress_total = self._pinned_total
            if not self._samples or now - self._samples[-1][0] >= 1.0:
                self._samples.append((now, self.progress_current))

    def aux(self, current, total):
        with self._lock:
            self.last_event = self._clock()
            try:
                self.aux_current = int(current or 0)
                self.aux_total = int(total or 0)
            except (TypeError, ValueError):
                pass

    def set_found(self, count):
        with self._lock:
            try:
                self.found = int(count or 0)
            except (TypeError, ValueError):
                pass

    def skipped(self, count):
        with self._lock:
            self.last_event = self._clock()
            try:
                self.skipped_count = int(count or 0)
            except (TypeError, ValueError):
                pass

    def retotal(self, total):
        with self._lock:
            self.last_event = self._clock()
            try:
                self._pinned_total = int(total or 0)
            except (TypeError, ValueError):
                return
            self.progress_total = self._pinned_total
            self.skip_in_total = False

    def set_paused(self, paused):
        with self._lock:
            self._note_paused(bool(paused), self._clock())

    def _note_paused(self, paused, now):
        if paused == self.paused:
            return
        self.paused = paused
        if paused:
            self._pause_started = now
            if (self.wait_until is not None and self.last_event is not None
                    and self.inflight == 0):
                self.last_event = max(self.last_event, min(now, self.wait_until))
            return
        started, self._pause_started = self._pause_started, None
        if started is None or self.last_event is None or self.stage_key not in PAUSABLE:
            return
        held_from = max(started, self.last_event)
        self.last_event += max(0.0, now - held_from)

    def set_net_budget(self, seconds):
        with self._lock:
            try:
                self.net_longest = float(seconds) if seconds else None
            except (TypeError, ValueError):
                self.net_longest = None

    def enter(self):
        with self._lock:
            self.inflight += 1
            self.last_event = self._clock()

    def leave(self):
        with self._lock:
            self.inflight = max(0, self.inflight - 1)
            self.last_event = self._clock()

    @contextmanager
    def working(self):
        self.enter()
        try:
            yield
        finally:
            self.leave()

    def counted(self, fn):
        def wrapper(*args, **kwargs):
            with self.working():
                return fn(*args, **kwargs)
        return wrapper

    def wait(self, seconds, reason):
        with self._lock:
            self.wait_until = self._clock() + max(0.0, float(seconds))
            self.wait_reason = str(reason or "")

    def unwait(self):
        with self._lock:
            self.wait_until = None
            self.wait_reason = ""

    def snapshot(self, paused=None, alive=None):
        with self._lock:
            now = self._clock()
            if paused is not None:
                self._note_paused(bool(paused), now)
            rate = eta = None
            if self._samples:
                window = [p for p in self._samples if now - p[0] <= 60.0]
                if len(window) >= 2:
                    span = window[-1][0] - window[0][0]
                    done = window[-1][1] - window[0][1]
                    if span >= 15.0 and done > 0:
                        rate = done * 60.0 / span
                        left = self.progress_total - self.progress_current
                        if self.skip_in_total:
                            left -= self.skipped_count
                        if left > 0:
                            eta = left * 60.0 / rate
            last = self.last_event
            if (self.wait_until is not None and self.wait_until <= now
                    and (last is None or self.wait_until > last)):
                last = self.wait_until
            return {
                "kind": self.kind,
                "state": self.state,
                "note": self.outcome_note,
                "stage": self.stage_key,
                "stageElapsed": (now - self.stage_started) if self.stage_started is not None else None,
                "runElapsed": ((self.run_ended if self.run_ended is not None else now)
                               - self.run_started) if self.run_started is not None else None,
                "lastEventAge": (now - last) if last is not None else None,
                "inflight": self.inflight,
                "waitLeft": (self.wait_until - now) if self.wait_until is not None and self.wait_until > now else None,
                "waitReason": self.wait_reason,
                "stopping": self.stopping,
                "paused": self.paused,
                "alive": alive,
                "current": self.progress_current,
                "total": self.progress_total,
                "skipped": self.skipped_count,
                "skipInTotal": self.skip_in_total,
                "auxCurrent": self.aux_current,
                "auxTotal": self.aux_total,
                "found": self.found,
                "rate": rate,
                "eta": eta,
                "netLongest": self.net_longest,
                "trail": list(self.trail),
            }


def _progress_text(snap):
    stage = snap["stage"]
    cur, tot = snap["current"], snap["total"]
    if stage == "proxies":
        if snap["auxTotal"]:
            return "прокси проверено %s · прочитано %s" % (
                fmt_number(snap["auxCurrent"]), fmt_number(snap["auxTotal"]))
        return ""
    if stage == "p_proxies":
        if snap["auxTotal"]:
            return "прокси %s из %s" % (fmt_number(snap["auxCurrent"]),
                                        fmt_number(snap["auxTotal"]))
        return ""
    if stage == "p_search":
        parts = []
        if tot:
            parts.append("дорков %s из %s" % (fmt_number(cur), fmt_number(tot)))
        parts.append("адресов найдено %s" % fmt_number(snap["found"]))
        return " · ".join(parts)
    if stage in ("check", "retry"):
        skipped = snap.get("skipped") or 0
        if skipped and snap.get("skipInTotal", True):
            tot = max(cur, tot - skipped)
        parts = []
        if tot:
            pct = int(cur * 100 / tot) if tot else 0
            parts.append("проверено %s из %s (%d%%)" % (fmt_number(cur), fmt_number(tot), pct))
        if skipped:
            parts.append("пропущено %s: проверены раньше, повторы или не адреса"
                         % fmt_number(skipped))
        return " · ".join(parts)
    return ""


def _speed_text(snap):
    if snap["rate"] is None or snap["stage"] not in ("check", "retry", "p_search"):
        return ""
    unit = "дорков" if snap["kind"] == "parser" else "адресов"
    text = "~%s %s/мин" % (fmt_number(round(snap["rate"])), unit)
    if snap["eta"] is not None:
        text += " · осталось ≈ %s" % fmt_duration(snap["eta"])
    return text


def describe(snap):
    state = snap["state"]
    stage = snap["stage"]
    label = STAGES.get(stage, (stage or "",))[0]
    total = snap["runElapsed"]

    if state == "idle":
        button = "Начать сбор" if snap["kind"] == "parser" else "Начать проверку"
        return {"level": "idle", "title": "Не запущено",
                "detail": "Движок готов и ждёт команды. Нажмите «%s» — здесь "
                          "сразу будет видно, что он делает." % button}
    if state in _FINAL:
        took = fmt_duration(total) if total is not None else "—"
        if state == "done":
            return {"level": "done", "title": "Завершено",
                    "detail": "Работа закончена за %s. Движок свободен." % took}
        if state == "stopped":
            return {"level": "stopped", "title": "Остановлено",
                    "detail": "Остановлено по вашей команде через %s. Движок свободен." % took}
        if state == "blocked":
            return {"level": "blocked", "title": "Не выполнялось",
                    "detail": "Работа не начиналась: %s. Подробности — в журнале."
                              % (snap["note"] or "нечем проверять")}
        return {"level": "failed", "title": "Прервано ошибкой",
                "detail": "Работа прервалась через %s. Причина — в журнале выше "
                          "(%s). Движок свободен, можно запускать заново."
                          % (took, snap["note"] or "строка [DEAD] или [Ошибка]")}

    if snap["alive"] is False:
        return {"level": "dead", "title": "Движок остановился",
                "detail": "Поток работы завершился, не отчитавшись. Это сбой — "
                          "запустите заново; если повторится, пришлите журнал."}

    parts = [label] if label else []
    if snap["stageElapsed"] is not None and stage not in _SILENT:
        parts.append("%s на этапе" % fmt_duration(snap["stageElapsed"]))
    prog = _progress_text(snap)
    if prog:
        parts.append(prog)
    speed = _speed_text(snap)
    if speed:
        parts.append(speed)
    inflight = snap["inflight"]
    if inflight:
        parts.append("в работе %s" % fmt_number(inflight))

    if snap["stopping"]:
        return {"level": "stopping", "title": "Останавливаю",
                "detail": " · ".join(parts + [
                    "доделываются начатые проверки, после этого движок освободится"])}
    if snap["paused"] and stage in PAUSABLE:
        return {"level": "paused", "title": "На паузе",
                "detail": " · ".join(parts + [
                    "новых проверок нет, пока не нажмёте «Продолжить»"])}
    if snap["paused"] and stage == "finish":
        parts.append("пауза уже не действует: проверка закончена, подводятся итоги")
    elif snap["paused"]:
        nxt = "поиск по доркам" if snap["kind"] == "parser" else "проверка адресов"
        parts.append("пауза включится, когда начнётся %s: этот этап "
                     "приостановить нельзя, он доделывается" % nxt)

    age = snap["lastEventAge"]
    quiet = STAGES.get(stage, ("", "", 60, False))[2]
    network = STAGES.get(stage, ("", "", 60, False))[3]

    if snap["waitLeft"] is not None and not inflight:
        return {"level": "wait", "title": "Ждёт по плану",
                "detail": " · ".join(parts + ["ещё %s: %s" % (
                    fmt_duration(snap["waitLeft"]),
                    snap["waitReason"] or "так задумано")])}
    if snap["waitLeft"] is not None:
        parts.append("следующие созреют через %s" % fmt_duration(snap["waitLeft"]))

    silence = age if age is not None else (snap["stageElapsed"] or 0.0)
    if network and inflight:
        longest = snap.get("netLongest") or 0.0
        slow_at, stall_at = NET_SLOW, max(NET_STALL, longest + 60.0)
        limit = fmt_duration(longest) if longest else "3 мин"
        if snap["kind"] == "parser":
            why_slow = ("ответов нет %s — поисковик или прокси отвечают медленно, "
                        "запросы повторяются через другие прокси"
                        % fmt_duration(silence))
        else:
            why_slow = ("ответов нет %s — серверы отвечают медленно; одна проверка "
                        "может идти до %s" % (fmt_duration(silence), limit))
    elif network:
        slow_at, stall_at = float(quiet), float(quiet) * 3
        why_slow = ("ни одной проверки в работе и нет событий %s"
                    % fmt_duration(silence))
    else:
        slow_at, stall_at = float(quiet), float(quiet) * 3
        why_slow = ("этап идёт без промежуточных событий %s (обычно до %s)"
                    % (fmt_duration(silence), fmt_duration(quiet)))

    if silence >= stall_at:
        return {"level": "stall", "title": "Похоже на зависание",
                "detail": " · ".join(parts + [
                    "нет ни одного события %s. Если так продолжится — нажмите "
                    "«Стоп» и запустите заново" % fmt_duration(silence)])}
    if silence >= slow_at:
        return {"level": "slow", "title": "Работает медленно",
                "detail": " · ".join(parts + [why_slow])}
    if not network and silence >= 10:
        parts.append("этап идёт без промежуточных событий — это нормально (обычно до %s)"
                     % fmt_duration(quiet))
    else:
        parts.append(_ago(age))
    return {"level": "ok", "title": "Работает", "detail": " · ".join(parts)}


def payload(snap):
    out = dict(snap)
    out.update(describe(snap))
    out["stageLabel"] = STAGES.get(snap["stage"], (snap["stage"] or "",))[0]
    trail = [{"label": STAGES.get(k, (k, k))[1], "seconds": round(s, 1), "active": False,
              "cut": bool(c)}
             for k, s, c in snap["trail"] if k not in _SILENT]
    if snap["stage"] and snap["stage"] not in _SILENT and snap["state"] == "running":
        trail.append({"label": STAGES.get(snap["stage"], (snap["stage"], snap["stage"]))[1],
                      "seconds": round(snap["stageElapsed"] or 0.0, 1), "active": True})
    out["trail"] = trail
    return out


def pulse_line(snap):
    d = describe(snap)
    tag = {"slow": "pulse-slow", "stall": "pulse-stall", "dead": "pulse-stall"}.get(
        d["level"], "pulse")
    return "[ПУЛЬС] %s — %s" % (d["title"], d["detail"]), tag


class Pulse(threading.Thread):

    def __init__(self, monitor, emit, paused=None, alive=None,
                 interval=PULSE_INTERVAL, tick=1.0, clock=None):
        super().__init__(name="activity-pulse", daemon=True)
        self.monitor = monitor
        self.emit = emit
        self._paused = paused or (lambda: False)
        self._alive = alive or (lambda: True)
        self.interval = float(interval)
        self.tick = float(tick)
        self._clock = clock or time.monotonic
        self._halt = threading.Event()
        self.emitted = 0

    def stop(self):
        self._halt.set()

    def snapshot(self):
        try:
            alive = bool(self._alive())
        except Exception:
            alive = None
        try:
            paused = bool(self._paused())
        except Exception:
            paused = False
        return self.monitor.snapshot(paused=paused, alive=alive)

    def step(self, last_time, last_level):
        snap = self.snapshot()
        if snap["state"] != "running":
            return last_time, last_level, False
        level = describe(snap)["level"]
        now = self._clock()
        rank = {"slow": 1, "stall": 2, "dead": 2}
        changed = rank.get(level, 0) != rank.get(last_level, 0)
        due = last_time is None or now - last_time >= self.interval
        early = changed and last_level is not None and (
            last_time is None or now - last_time >= 5.0)
        if due or early:
            return now, level, True
        return last_time, last_level, False

    def run(self):
        last_time, last_level = self._clock(), "ok"
        while not self._halt.wait(self.tick):
            snap_state = self.monitor.state
            if snap_state != "running":
                break
            try:
                if not self._alive():
                    text, tag = pulse_line(self.snapshot())
                    self._send(text, tag)
                    break
            except Exception:
                pass
            last_time, last_level, write = self.step(last_time, last_level)
            if write:
                text, tag = pulse_line(self.snapshot())
                self._send(text, tag)

    def _send(self, text, tag):
        try:
            self.emit(text, tag)
            self.emitted += 1
        except Exception:
            pass


_VALIDATOR_OBSERVED = {
    "on_log": "beat",
    "on_result": "beat",
    "on_phase": "beat",
    "on_revise": "beat",
    "on_proxy_profile": "beat",
    "on_progress": "progress",
    "on_proxy_progress": "aux",
}


def _observed(fn, monitor, how):
    if getattr(fn, "__activity_observed__", None) is monitor:
        return fn

    def wrapper(*args, **kwargs):
        try:
            if how == "progress" and len(args) >= 2:
                monitor.progress(args[0], args[1])
            elif how == "aux" and len(args) >= 2:
                monitor.aux(args[0], args[1])
            else:
                monitor.beat()
        except Exception:
            pass
        return fn(*args, **kwargs)

    wrapper.__activity_observed__ = monitor
    wrapper.__wrapped__ = fn
    return wrapper


def observe_callbacks(callbacks, monitor, mapping=None):
    if not isinstance(callbacks, dict):
        return callbacks
    for key, how in (mapping or _VALIDATOR_OBSERVED).items():
        fn = callbacks.get(key)
        if callable(fn):
            callbacks[key] = _observed(fn, monitor, how)
    return callbacks


def raw(fn):
    return getattr(fn, "__wrapped__", fn) if getattr(fn, "__activity_observed__", None) else fn


class PipelineActivityMixin:

    @property
    def activity(self):
        mon = self.__dict__.get("_activity")
        if mon is None:
            mon = ActivityMonitor(kind="validator", emit=self._activity_emit)
            self.__dict__["_activity"] = mon
        return mon

    def _activity_emit(self, text, tag):
        log = (getattr(self, "callbacks", None) or {}).get("on_log")
        if callable(log):
            log(text, tag)

    def _init_activity(self):
        observe_callbacks(getattr(self, "callbacks", None), self.activity)

    def _stage(self, key, cut=None):
        self.activity.stage(key, cut=cut)

    def _worker_alive(self):
        t = self.__dict__.get("_worker")
        return t.is_alive() if t is not None else None

    def _finish_activity(self, failed=False, interrupted=False, stage_done=False):
        reason = getattr(self, "blocked_reason", "") or ""
        if failed:
            outcome, note = "failed", ""
        elif reason:
            outcome, note = "blocked", reason
        elif getattr(self, "_stop_requested", False):
            outcome, note = "stopped", ""
        else:
            outcome, note = "done", ""
        self.activity.finish(outcome, note, interrupted=interrupted, stage_done=stage_done)
        pulse = self.__dict__.get("_pulse")
        if pulse is not None:
            pulse.stop()

    def _start_pulse(self):
        log = (getattr(self, "callbacks", None) or {}).get("on_log")
        if not callable(log):
            return None
        sink = raw(log)
        pulse = Pulse(self.activity, emit=lambda text, tag: sink(text, tag),
                      paused=lambda: bool(getattr(self, "is_paused", False)),
                      alive=lambda: self._worker_alive() is not False)
        pulse.start()
        self.__dict__["_pulse"] = pulse
        return pulse
