import os
import sqlite3
import threading
from core.paths import data_path

DEFAULT_STATE_PATH = data_path("run_state.sqlite")

FLUSH_EVERY = 512

DEFAULT_RETRY_DELAY = 90

GREYLIST_RETRY_DELAY = 420


class RunState:

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


    def add_if_new(self, key):
        if not key:
            return False
        if self._conn is None:
            return True
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


    def freeze(self):
        with self._lock:
            self._frozen = True
            self._pending_done.clear()
            if self._conn is None:
                return
            try:
                self._conn.execute("DELETE FROM done WHERE run_id = ?", (self.run_id,))
                self._conn.commit()
            except Exception:
                self._close_quietly()

    def mark_done(self, key):
        if not key or self._conn is None:
            return
        with self._lock:
            if getattr(self, "_frozen", False):
                return
            self._pending_done.append(key)
            if len(self._pending_done) >= self.flush_every:
                self._flush_locked()

    def is_done(self, key):
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


    def reset_seen(self):
        if self._conn is None:
            return
        with self._lock:
            self._pending_seen.clear()
            self.seen_count = 0
            try:
                self._conn.execute("DELETE FROM seen WHERE run_id = ?",
                                   (self.run_id,))
                self._conn.commit()
            except Exception:
                self._close_quietly()

    def clear(self):
        if self._conn is None:
            return
        with self._lock:
            self._pending_seen.clear()
            self._pending_done.clear()
            self.seen_count = 0
            self.resumed_count = 0
            try:
                for table in ("seen", "done"):
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


def resumable_count(sources, path=DEFAULT_STATE_PATH):
    try:
        state = RunState(run_id_for(sources), path=path, resume=True)
    except Exception:
        return 0
    try:
        return int(state.resumed_count or 0)
    except Exception:
        return 0
    finally:
        try:
            state.close()
        except Exception:
            pass


def run_id_for(sources):
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
            stat = os.stat(path)
            size, mtime = stat.st_size, stat.st_mtime_ns
        except Exception:
            size, mtime = -1, -1
        parts.append(f"{os.path.abspath(path).lower()}:{size}:{mtime}")
    if not parts:
        return "empty"
    digest = hashlib.sha256("|".join(sorted(parts)).encode("utf-8")).hexdigest()
    return digest[:16]
