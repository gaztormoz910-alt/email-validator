# -*- coding: utf-8 -*-
"""Журнал активности движка: чем он занят прямо сейчас и жив ли он.

ЗАЧЕМ. Владелец, 14.10.2026: «чтобы во время работы софта не создавалось
впечатление, будто он завис или даже не включён». До этого модуля окно знало
две вещи — «прогон идёт» и строки лога. Строки же идут неравномерно: перебор
прокси (на списке владельца — до 82 минут), скачивание списков одноразовых
доменов, прогрев модели ИИ — это минуты, за которые в журнале не появлялось
ни строчки. Снаружи такое неотличимо от зависания, а настоящее зависание —
от медленного почтового сервера.

Здесь движок сам рассказывает о себе четырьмя величинами:

  * ЭТАП — какая часть работы идёт и сколько она уже длится;
  * В РАБОТЕ — сколько адресов прямо сейчас проверяется (потоков, занятых
    сетью). Именно это отличает «ждём ответа почтовиков» от «ничего не
    делаем»: при зависшем движке занятых нет, а событий тоже нет;
  * ПОСЛЕДНЕЕ СОБЫТИЕ — когда движок в последний раз сообщил новое: строку
    лога, результат, сдвиг прогресса;
  * ПЛАНОВОЕ ОЖИДАНИЕ — паузы, которые движок держит намеренно
    (перепроверка ждёт срока серого списка).

describe() сводит их к одному уровню и одной фразе. Формулировки живут
ЗДЕСЬ, в одном месте: полоса состояния в окне, строка-пульс в журнале и
консоль CLI говорят одинаково и разойтись не могут.

Пульс сам событием НЕ считается. Иначе «последнее событие» никогда не было
бы старше интервала пульса, и зависание выглядело бы как работа.
"""
import threading
import time
from collections import deque
from contextlib import contextmanager

__all__ = ["ActivityMonitor", "describe", "payload", "pulse_line", "Pulse",
           "observe_callbacks", "PipelineActivityMixin", "fmt_duration",
           "fmt_number", "STAGES"]

# ─────────────────────────────── этапы ─────────────────────────────────
#
# ключ -> (подпись, короткая подпись для цепочки, сколько секунд этап имеет
# право молчать, сетевой ли он).
#
# «Право молчать» — не таймаут, а граница, после которой молчание уже
# необычно. Оно разное, потому что этапы по природе разные: прогрев модели
# идёт минутами БЕЗ единого промежуточного события, и называть это
# «медленно» через 30 секунд было бы враньём, которое владелец быстро
# научится не замечать. А проверка адресов при сотне потоков сообщает о себе
# много раз в секунду, и минута её молчания уже повод присмотреться.
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
    # Сбор адресов — свой конвейер, свои этапы.
    "p_init":    ("Подготовка сбора", "Подготовка", 600, False),
    "p_tor":     ("Запуск Tor", "Tor", 600, True),
    "p_proxies": ("Проверка прокси", "Прокси", 120, True),
    "p_search":  ("Поиск по доркам", "Поиск", 90, True),
}

# Этап, о котором в журнал не пишется: он длится доли секунды между нажатием
# «Начать» и первым настоящим этапом, и строка про него была бы шумом.
_SILENT = {"start"}

# Сетевой этап с занятыми потоками может молчать дольше: одна проверка адреса
# ограничена общим дедлайном 180 с (core/network.py), и пока он не истёк,
# долгое молчание — это медленный сервер, а не поломка. Зависание — всё, что
# дольше дедлайна с запасом.
NET_SLOW = 45.0
NET_STALL = 240.0

# Как часто движок пишет строку-пульс, если ничего не изменилось.
PULSE_INTERVAL = 15.0

_FINAL = ("done", "stopped", "failed", "blocked")

# Уровни для окна. Порядок — от спокойного к тревожному; окно красит по нему.
LEVELS = ("idle", "done", "stopped", "ok", "wait", "paused", "stopping",
          "slow", "stall", "blocked", "failed", "dead")


# ──────────────────────────── форматирование ────────────────────────────

def fmt_number(value):
    """1234567 -> «1 234 567». Пробел, а не запятая: так пишет окно."""
    try:
        return format(int(value), ",").replace(",", " ")
    except (TypeError, ValueError):
        return str(value)


def fmt_duration(seconds):
    """Длительность по-человечески: «8 с», «3 мин 05 с», «1 ч 02 мин»."""
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
    """Сколько назад было последнее событие — словами, без «0 с назад»."""
    if age is None:
        return "событий ещё не было"
    if age < 2:
        return "последнее событие только что"
    return "последнее событие %s назад" % fmt_duration(age)


# ─────────────────────────────── монитор ────────────────────────────────

class ActivityMonitor:
    """Что делает движок прямо сейчас. Потокобезопасен, дёшев на вызов.

    Часы подставляются: тесты гоняют время вручную, а не спят. Монотонные
    часы — для длительностей (их не сдвигает перевод времени), настенные —
    только для отметки начала прогона.
    """

    def __init__(self, kind="validator", emit=None, clock=None):
        self.kind = kind
        # Куда писать строки этапов. Это НАСТОЯЩИЕ события: смена этапа —
        # тоже жизнь движка, поэтому emit может и обновлять «последнее
        # событие» (в конвейере он идёт через наблюдаемый on_log).
        self.emit = emit
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
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
        self.trail = []              # [(ключ, длительность в секундах)]
        self._samples = deque(maxlen=240)

    # ── жизненный цикл ──
    def begin(self):
        """Начало прогона: всё прошлое забывается."""
        with self._lock:
            self._reset()
            now = self._clock()
            self.state = "running"
            self.run_started = now
            self.stage_key = "start"
            self.stage_started = now
            self.last_event = now

    def stage(self, key):
        """Новый этап. Пишет в журнал «✓ прошлый — за сколько» и «▶ новый».

        Строки уходят ВНЕ замка: emit может вернуться сюда же через beat, и
        под обычным замком это была бы взаимная блокировка.
        """
        lines = []
        with self._lock:
            if self.state != "running":
                # Прямой вызов этапов без begin(): так работает CLI и тесты,
                # которые зовут setup()/run_pipeline() напрямую.
                self.begin()
            now = self._clock()
            prev, started = self.stage_key, self.stage_started
            if prev == key:
                return
            if prev and started is not None:
                took = max(0.0, now - started)
                self.trail.append((prev, took))
                if prev not in _SILENT:
                    lines.append(("✓ %s — %s" % (STAGES.get(prev, (prev,))[0],
                                                 fmt_duration(took)), "stage"))
            self.stage_key = key
            self.stage_started = now
            self.last_event = now
            self.wait_until = None
            self.wait_reason = ""
            if key not in _SILENT:
                lines.append(("▶ %s" % STAGES.get(key, (key,))[0], "stage"))
        self._emit(lines)

    def finish(self, outcome="done", note=""):
        """Конец прогона. Последний этап закрывается, пишется итог."""
        lines = []
        with self._lock:
            if self.state in _FINAL:
                return
            if self.state == "idle":
                # Прогон не начинался: итог «завершено за 0 с» был бы ложью.
                self.state = outcome
                self.outcome_note = note
                return
            now = self._clock()
            prev, started = self.stage_key, self.stage_started
            if prev and started is not None:
                took = max(0.0, now - started)
                self.trail.append((prev, took))
                if prev not in _SILENT:
                    lines.append(("✓ %s — %s" % (STAGES.get(prev, (prev,))[0],
                                                 fmt_duration(took)), "stage"))
            self.state = outcome if outcome in _FINAL else "done"
            self.outcome_note = note
            self.stage_key = ""
            self.stage_started = None
            self.run_ended = now
            self.inflight = 0
            self.wait_until = None
            # `is not None`, а не `or`: отметка времени 0.0 — законная (часы
            # в тестах начинаются с нуля), и `or` молча превращал её в «сейчас».
            begun = self.run_started if self.run_started is not None else now
            total = fmt_duration(now - begun)
            text = {
                "done": "■ Готово. Весь прогон занял %s." % total,
                "stopped": "■ Остановлено по вашей команде через %s." % total,
                "failed": "■ Прервано ошибкой через %s — причина строкой выше." % total,
                "blocked": "■ Работа не выполнялась: %s." % (note or "нечем проверять"),
            }[self.state]
            lines.append((text, "stage"))
        self._emit(lines)

    def request_stop(self):
        """Нажали «Стоп»: до конца потока покажем «останавливаю», а не «работает»."""
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
                # Журнал — не условие работы: сбой вывода не роняет прогон.
                pass

    # ── события ──
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
            # Не чаще раза в секунду: при сотне потоков прогресс сдвигается
            # сотни раз в секунду, а для скорости нужны точки, а не поток.
            if not self._samples or now - self._samples[-1][0] >= 1.0:
                self._samples.append((now, self.progress_current))

    def aux(self, current, total):
        """Второй счётчик: прокси до проверки почт. Знаменатель — «прочитано»."""
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

    # ── в работе ──
    def enter(self):
        with self._lock:
            self.inflight += 1

    def leave(self):
        with self._lock:
            # Не ниже нуля: лишний leave (исключение до enter) не должен
            # превращаться в «в работе −1».
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
        """Та же функция, но пока она идёт — она «в работе». Для пулов потоков."""
        def wrapper(*args, **kwargs):
            with self.working():
                return fn(*args, **kwargs)
        return wrapper

    # ── плановое ожидание ──
    def wait(self, seconds, reason):
        with self._lock:
            self.wait_until = self._clock() + max(0.0, float(seconds))
            self.wait_reason = str(reason or "")

    def unwait(self):
        with self._lock:
            self.wait_until = None
            self.wait_reason = ""

    # ── снимок ──
    def snapshot(self, paused=False, alive=None):
        """Всё, что нужно describe(), одной копией под замком."""
        with self._lock:
            now = self._clock()
            rate = eta = None
            if self._samples:
                window = [p for p in self._samples if now - p[0] <= 60.0]
                if len(window) >= 2:
                    span = window[-1][0] - window[0][0]
                    done = window[-1][1] - window[0][1]
                    # Меньше 15 секунд наблюдения — не скорость, а случайность:
                    # первая пачка кэшированных адресов дала бы «8000 в минуту».
                    if span >= 15.0 and done > 0:
                        rate = done * 60.0 / span
                        left = self.progress_total - self.progress_current
                        if left > 0:
                            eta = left * 60.0 / rate
            return {
                "kind": self.kind,
                "state": self.state,
                "note": self.outcome_note,
                "stage": self.stage_key,
                "stageElapsed": (now - self.stage_started) if self.stage_started is not None else None,
                "runElapsed": ((self.run_ended if self.run_ended is not None else now)
                               - self.run_started) if self.run_started is not None else None,
                "lastEventAge": (now - self.last_event) if self.last_event is not None else None,
                "inflight": self.inflight,
                "waitLeft": (self.wait_until - now) if self.wait_until is not None and self.wait_until > now else None,
                "waitReason": self.wait_reason,
                "stopping": self.stopping,
                "paused": bool(paused),
                "alive": alive,
                "current": self.progress_current,
                "total": self.progress_total,
                "auxCurrent": self.aux_current,
                "auxTotal": self.aux_total,
                "found": self.found,
                "rate": rate,
                "eta": eta,
                "trail": list(self.trail),
            }


# ─────────────────────────────── описание ───────────────────────────────

def _progress_text(snap):
    """Где движок по счёту — словами, своими для каждого этапа."""
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
    if stage in ("check", "retry") and tot:
        pct = int(cur * 100 / tot) if tot else 0
        return "проверено %s из %s (%d%%)" % (fmt_number(cur), fmt_number(tot), pct)
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
    """Уровень, заголовок и подробность — единая формулировка для всех.

    Возвращает словарь {level, title, detail}. Уровень решается так:
      * прогон не идёт — idle или итог;
      * поток движка мёртв, а итога нет — dead (движок ушёл молча);
      * пауза, остановка, плановое ожидание — свои слова;
      * дальше — по молчанию: у сетевого этапа с занятыми потоками граница
        дедлайна проверки, у остальных — «право молчать» этапа.
    """
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
                "detail": "Работа прервалась через %s. Причина — в журнале строкой "
                          "[DEAD] выше. Движок свободен, можно запускать заново." % took}

    # Дальше — прогон идёт.
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
    if snap["paused"]:
        return {"level": "paused", "title": "На паузе",
                "detail": " · ".join(parts + [
                    "новых проверок нет, пока не нажмёте «Продолжить»"])}

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
        slow_at, stall_at = NET_SLOW, NET_STALL
        why_slow = ("ответов нет %s — серверы отвечают медленно; одна проверка "
                    "может идти до 3 мин" % fmt_duration(silence))
    elif network:
        # Сетевой этап, а занятых потоков нет: это не «сервер медлит», а
        # «никто ничего не ждёт» — так и говорим.
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
        # Тихий этап в пределах нормы: прямо говорим, что тишина ожидаема,
        # иначе владелец решит, что всё встало.
        parts.append("этап идёт без промежуточных событий — это нормально (обычно до %s)"
                     % fmt_duration(quiet))
    else:
        parts.append(_ago(age))
    return {"level": "ok", "title": "Работает", "detail": " · ".join(parts)}


def payload(snap):
    """Снимок + описание в виде, готовом для окна (JSON)."""
    out = dict(snap)
    out.update(describe(snap))
    out["stageLabel"] = STAGES.get(snap["stage"], (snap["stage"] or "",))[0]
    trail = [{"label": STAGES.get(k, (k, k))[1], "seconds": round(s, 1), "active": False}
             for k, s in snap["trail"] if k not in _SILENT]
    if snap["stage"] and snap["stage"] not in _SILENT and snap["state"] == "running":
        trail.append({"label": STAGES.get(snap["stage"], (snap["stage"], snap["stage"]))[1],
                      "seconds": round(snap["stageElapsed"] or 0.0, 1), "active": True})
    out["trail"] = trail
    return out


def pulse_line(snap):
    """Строка-пульс для журнала и её тег (по нему окно красит строку)."""
    d = describe(snap)
    tag = {"slow": "pulse-slow", "stall": "pulse-stall", "dead": "pulse-stall"}.get(
        d["level"], "pulse")
    return "[ПУЛЬС] %s — %s" % (d["title"], d["detail"]), tag


# ──────────────────────────────── пульс ─────────────────────────────────

class Pulse(threading.Thread):
    """Пишет строку-пульс в журнал, пока прогон идёт.

    Раз в PULSE_INTERVAL — всегда, чтобы в журнале было видно движение даже
    на тихих этапах. И сразу же — когда состояние ухудшилось (заработало
    медленно, похоже на зависание) или выправилось: тревога, которая ждёт
    15 секунд своей очереди, хуже, чем никакой.

    emit — СЫРОЙ вывод, не наблюдаемый монитором: пульс не должен обновлять
    «последнее событие» (см. описание модуля).
    """

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
        """Один шаг решения: писать ли сейчас. Отдельно от run() — для тестов.

        Возвращает (новое время последнего пульса, новый уровень, писать ли).
        """
        snap = self.snapshot()
        if snap["state"] != "running":
            return last_time, last_level, False
        level = describe(snap)["level"]
        now = self._clock()
        rank = {"slow": 1, "stall": 2, "dead": 2}
        changed = rank.get(level, 0) != rank.get(last_level, 0)
        due = last_time is None or now - last_time >= self.interval
        # Смена тревожности пишется сразу, но не чаще раза в 5 секунд: на
        # границе порога уровень может колебаться, и журнал не должен мигать.
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
                    # Поток движка умер — один раз скажем об этом и уйдём.
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


# ───────────────────────── наблюдение за событиями ──────────────────────

# Какие колбэки конвейера что значат для монитора.
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
        return fn                       # уже обёрнут этим же монитором

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
    """Оборачивает колбэки на месте: каждый вызов — событие для монитора.

    На месте, а не копией: окно и CLI передают свой словарь и иногда
    дописывают в него позже — копия разошлась бы с ним молча.
    """
    if not isinstance(callbacks, dict):
        return callbacks
    for key, how in (mapping or _VALIDATOR_OBSERVED).items():
        fn = callbacks.get(key)
        if callable(fn):
            callbacks[key] = _observed(fn, monitor, how)
    return callbacks


def raw(fn):
    """Исходная функция под наблюдаемой обёрткой (для пульса)."""
    return getattr(fn, "__wrapped__", fn) if getattr(fn, "__activity_observed__", None) else fn


# ─────────────────────────── примесь конвейера ──────────────────────────

class PipelineActivityMixin:
    """Подключение монитора к ValidationPipeline одной точкой.

    Монитор создаётся лениво: часть тестов собирает конвейер в обход
    __init__, и падать им из-за отсутствия журнала активности незачем.
    """

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

    def _stage(self, key):
        self.activity.stage(key)

    def _worker_alive(self):
        t = self.__dict__.get("_worker")
        return t.is_alive() if t is not None else None

    def _finish_activity(self, failed=False):
        """Итог прогона — по тому, ЧТО его закончило, одним местом.

        Порядок важен: блокировка (порт 25 закрыт, ни один прокси не ожил)
        тоже взводит _stop_requested, и без проверки blocked_reason первой
        она выглядела бы как «остановлено вами», хотя вы ничего не нажимали.
        """
        reason = getattr(self, "blocked_reason", "") or ""
        if failed:
            outcome, note = "failed", ""
        elif reason:
            outcome, note = "blocked", reason
        elif getattr(self, "_stop_requested", False):
            outcome, note = "stopped", ""
        else:
            outcome, note = "done", ""
        self.activity.finish(outcome, note)
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
