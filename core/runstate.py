# core/runstate.py
"""Состояние прогона на диске: дедуп, журнал сделанного и очередь повторов.

Три проблемы, из-за которых прогон на большой базе вёл себя плохо, решаются
одним хранилищем — тем же SQLite, что уже используется под кэш вердиктов.

1. ДЕДУП ДЕРЖАЛСЯ В ОЗУ. Множество увиденных ключей росло линейно по базе.
   На заявленных «файлах в десятки гигабайт» оно не влезает в память, и
   выигрыш от потокового чтения обнулялся: файл читался порциями, а рядом
   рос set на сотню миллионов строк.

2. ПРЕРВАННЫЙ ПРОГОН НАЧИНАЛСЯ ЗАНОВО. Нажатие «Стоп» на 80% базы означало
   выбросить всю работу: ни один адрес не помечался как уже сделанный.

3. ПОВТОРЫ ЖДАЛИ БЛОКИРУЮЩЕЙ ПАУЗОЙ. Отложенные адреса лежали в очереди без
   срока, а пайплайн спал ровно 90 секунд, ничего в это время не делая.
   Здесь у каждой записи есть СРОК, и готовность проверяется мгновенно —
   спать больше незачем.

Хранилище открывается в режиме WAL и рассчитано на сотни пишущих потоков.
Любая ошибка БД отключает состояние молча: это ускорение и удобство, а не
источник истины, и валидация обязана работать даже когда диск недоступен.
"""

import os
import sqlite3
import threading
import time

DEFAULT_STATE_PATH = os.path.join("data", "run_state.sqlite")

# Сколько ключей копится в памяти перед записью пачкой. Одиночный INSERT на
# каждый адрес упирается в диск и становится узким местом сам по себе.
FLUSH_EVERY = 512

# Сколько секунд ждать перед повтором отложенного адреса. Серверы с greylisting
# просят прийти через 1-5 минут; 90 секунд — прежнее значение пайплайна.
DEFAULT_RETRY_DELAY = 90

# Отдельная выдержка для серых списков.
#
# Greylisting — это не сбой, а правило: сервер намеренно отвечает «позже» и
# ждёт, что настоящий отправитель повторит попытку СПУСТЯ ВРЕМЯ. У postgrey,
# самой распространённой реализации, выдержка по умолчанию пять минут; повтор
# через полторы минуты почти наверняка получает тот же серый ответ, и адрес
# остаётся без вердикта вовсе.
#
# Семь минут — пять с запасом на разброс настроек. Временный сбой (таймаут,
# сдохший прокси, лимит скорости) повторяется по-прежнему быстро: это разные
# вещи, и мешать их значит либо тормозить одно, либо не дожидаться другого.
GREYLIST_RETRY_DELAY = 420


class RunState:
    """Дедуп, журнал обработанного и отложенная очередь одного прогона.

    run_id разделяет прогоны: продолжить можно только тот же самый прогон по
    тем же файлам, иначе «уже сделано» относилось бы к чужой базе.
    """

    def __init__(self, run_id, path=DEFAULT_STATE_PATH, resume=True,
                 flush_every=FLUSH_EVERY):
        self.run_id = str(run_id or "default")
        self.path = path
        self.flush_every = max(1, int(flush_every))
        self._lock = threading.Lock()
        self._conn = None
        self._pending_seen = []
        self._pending_done = []
        self.seen_count = 0
        self.resumed_count = 0

        try:
            directory = os.path.dirname(path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            self._conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS seen (
                       run_id TEXT NOT NULL,
                       key    TEXT NOT NULL,
                       PRIMARY KEY (run_id, key)
                   ) WITHOUT ROWID"""
            )
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS done (
                       run_id TEXT NOT NULL,
                       key    TEXT NOT NULL,
                       PRIMARY KEY (run_id, key)
                   ) WITHOUT ROWID"""
            )
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS retry (
                       run_id   TEXT NOT NULL,
                       key      TEXT NOT NULL,
                       due_at   REAL NOT NULL,
                       payload  TEXT,
                       attempts INTEGER NOT NULL DEFAULT 0,
                       PRIMARY KEY (run_id, key)
                   ) WITHOUT ROWID"""
            )
            self._conn.execute("CREATE INDEX IF NOT EXISTS retry_due ON retry(run_id, due_at)")
            self._conn.commit()

            if not resume:
                self.clear()
            else:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM done WHERE run_id = ?", (self.run_id,)
                ).fetchone()
                self.resumed_count = int(row[0]) if row else 0
        except Exception:
            self._close_quietly()

    # --- служебное ---------------------------------------------------------

    @property
    def enabled(self):
        return self._conn is not None

    def _close_quietly(self):
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        self._conn = None

    def _flush_locked(self):
        """Записывает накопленные пачки. Вызывается под уже взятым замком."""
        if self._conn is None:
            return
        try:
            if self._pending_seen:
                self._conn.executemany(
                    "INSERT OR IGNORE INTO seen (run_id, key) VALUES (?, ?)",
                    [(self.run_id, key) for key in self._pending_seen])
                self._pending_seen.clear()
            if self._pending_done:
                self._conn.executemany(
                    "INSERT OR IGNORE INTO done (run_id, key) VALUES (?, ?)",
                    [(self.run_id, key) for key in self._pending_done])
                self._pending_done.clear()
            self._conn.commit()
        except Exception:
            self._close_quietly()

    def flush(self):
        with self._lock:
            self._flush_locked()

    # --- дедуп -------------------------------------------------------------

    def add_if_new(self, key):
        """True, если ключ встретился впервые. Хранение на диске, не в ОЗУ.

        Порядок важен: сначала смотрим в ещё не записанную пачку, потом в
        таблицу. Без первой проверки два одинаковых адреса подряд оба
        считались бы новыми, пока пачка не долетела до диска.
        """
        if not key:
            return False
        if self._conn is None:
            return True   # без хранилища дедупа нет, но прогон продолжается
        with self._lock:
            if key in self._pending_seen:
                return False
            try:
                row = self._conn.execute(
                    "SELECT 1 FROM seen WHERE run_id = ? AND key = ?",
                    (self.run_id, key)).fetchone()
            except Exception:
                self._close_quietly()
                return True
            if row:
                return False
            self._pending_seen.append(key)
            self.seen_count += 1
            if len(self._pending_seen) >= self.flush_every:
                self._flush_locked()
            return True

    # --- журнал сделанного -------------------------------------------------

    def mark_done(self, key):
        """Отмечает адрес как получивший вердикт — чтобы не проверять снова."""
        if not key or self._conn is None:
            return
        with self._lock:
            self._pending_done.append(key)
            if len(self._pending_done) >= self.flush_every:
                self._flush_locked()

    def is_done(self, key):
        """Был ли адрес уже обработан в этом прогоне."""
        if not key or self._conn is None:
            return False
        with self._lock:
            if key in self._pending_done:
                return True
            try:
                row = self._conn.execute(
                    "SELECT 1 FROM done WHERE run_id = ? AND key = ?",
                    (self.run_id, key)).fetchone()
            except Exception:
                return False
        return bool(row)

    def done_count(self):
        if self._conn is None:
            return 0
        with self._lock:
            self._flush_locked()
            if self._conn is None:
                return 0
            try:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM done WHERE run_id = ?", (self.run_id,)).fetchone()
            except Exception:
                return 0
        return int(row[0]) if row else 0

    # --- отложенные повторы ------------------------------------------------

    def schedule_retry(self, key, payload="", delay=DEFAULT_RETRY_DELAY, attempts=0):
        """Кладёт адрес в очередь повтора СО СРОКОМ, а не в общий мешок."""
        if not key or self._conn is None:
            return False
        due = time.monotonic() + max(0.0, float(delay))
        with self._lock:
            try:
                self._conn.execute(
                    "INSERT OR REPLACE INTO retry (run_id, key, due_at, payload, attempts) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (self.run_id, key, due, payload or "", int(attempts)))
                self._conn.commit()
                return True
            except Exception:
                self._close_quietly()
                return False

    def due_retries(self, limit=256, now=None):
        """Забирает созревшие повторы и удаляет их из очереди.

        Возвращает [(key, payload, attempts)]. Несозревшие не отдаются — на
        этом и держится отказ от блокирующей паузы: воркер спрашивает, что
        готово, получает пусто и идёт заниматься основной очередью.
        """
        if self._conn is None:
            return []
        moment = time.monotonic() if now is None else now
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT key, payload, attempts FROM retry "
                    "WHERE run_id = ? AND due_at <= ? ORDER BY due_at LIMIT ?",
                    (self.run_id, moment, int(limit))).fetchall()
                if rows:
                    self._conn.executemany(
                        "DELETE FROM retry WHERE run_id = ? AND key = ?",
                        [(self.run_id, row[0]) for row in rows])
                    self._conn.commit()
            except Exception:
                self._close_quietly()
                return []
        return [(row[0], row[1] or "", int(row[2])) for row in rows]

    def pending_retries(self):
        """Сколько повторов ещё ждёт срока."""
        if self._conn is None:
            return 0
        with self._lock:
            try:
                row = self._conn.execute(
                    "SELECT COUNT(*) FROM retry WHERE run_id = ?", (self.run_id,)).fetchone()
            except Exception:
                return 0
        return int(row[0]) if row else 0

    def next_due_in(self):
        """Через сколько секунд созреет ближайший повтор. None — очередь пуста.

        Нужно, чтобы ждать ровно столько, сколько осталось, а не фиксированные
        90 секунд независимо от того, что в очереди.
        """
        if self._conn is None:
            return None
        with self._lock:
            try:
                row = self._conn.execute(
                    "SELECT MIN(due_at) FROM retry WHERE run_id = ?",
                    (self.run_id,)).fetchone()
            except Exception:
                return None
        if not row or row[0] is None:
            return None
        return max(0.0, float(row[0]) - time.monotonic())

    def drain_retries(self):
        """Забирает ВСЁ, что осталось в очереди, независимо от срока.

        Нужно в самом конце прогона: адрес, за который никто не отвечает,
        обязан вернуться пользователю как Unknown, а не исчезнуть.
        """
        if self._conn is None:
            return []
        with self._lock:
            try:
                rows = self._conn.execute(
                    "SELECT key, payload, attempts FROM retry WHERE run_id = ?",
                    (self.run_id,)).fetchall()
                self._conn.execute("DELETE FROM retry WHERE run_id = ?", (self.run_id,))
                self._conn.commit()
            except Exception:
                return []
        return [(row[0], row[1] or "", int(row[2])) for row in rows]

    # --- жизненный цикл ----------------------------------------------------

    def clear(self):
        """Стирает состояние ЭТОГО прогона. Чужие прогоны не трогает."""
        if self._conn is None:
            return
        with self._lock:
            self._pending_seen.clear()
            self._pending_done.clear()
            self.seen_count = 0
            self.resumed_count = 0
            try:
                for table in ("seen", "done", "retry"):
                    self._conn.execute(f"DELETE FROM {table} WHERE run_id = ?", (self.run_id,))
                self._conn.commit()
            except Exception:
                self._close_quietly()

    def close(self):
        with self._lock:
            self._flush_locked()
            self._close_quietly()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False


def run_id_for(sources):
    """Устойчивый идентификатор прогона по списку источников.

    Один и тот же набор файлов даёт один и тот же id, поэтому «продолжить»
    подхватывает именно свой журнал. Другой набор — другой id, и чужое
    «уже сделано» на него не распространяется.
    """
    import hashlib
    parts = []
    for source in sources or []:
        if isinstance(source, dict):
            path = source.get("path") or ""
        else:
            path = str(source)
        if not path:
            continue
        try:
            size = os.path.getsize(path)
        except Exception:
            size = -1
        parts.append(f"{os.path.abspath(path).lower()}:{size}")
    if not parts:
        return "empty"
    digest = hashlib.sha256("|".join(sorted(parts)).encode("utf-8")).hexdigest()
    return digest[:16]
