# -*- coding: utf-8 -*-
import atexit
import os
import sqlite3
import tempfile
import threading
import time
import weakref

from core.paths import data_dir as data_dir_of_app

__all__ = ["BaseStore", "PENDING", "BATCH", "BREATHE_EVERY"]

PENDING = "pending"

BATCH = 2000

BREATHE_EVERY = 1000

FACETS_TTL = 5.0

_ORPHAN_AGE_HOURS = 24


def _escape_like(needle):
    needle = needle.replace("\\", "\\\\")
    return needle.replace("%", "\\%").replace("_", "\\_")


class BaseStore:

    def __init__(self, path=None):
        self._write_lock = threading.Lock()
        self._read_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._flush_lock = threading.Lock()
        self._writer = None
        self._reader = None
        self._path = None
        self._temporary = False
        self._epoch = 1
        self._loaded = 0
        self._done = 0
        self._loading = False
        self._generation = 0
        self._error = ""
        self._marks = []
        self._facets_cache = {}
        self._open(path)


    def _open(self, path):
        try:
            if path is None:
                directory = self._storage_dir()
                self._sweep_orphans(directory)
                handle, path = tempfile.mkstemp(prefix="base_", suffix=".sqlite",
                                                dir=directory)
                os.close(handle)
                self._temporary = True
            writer = sqlite3.connect(path, check_same_thread=False, timeout=30)
            writer.execute("PRAGMA journal_mode=WAL")
            writer.execute("PRAGMA synchronous=OFF")
            writer.execute(
                """CREATE TABLE IF NOT EXISTS base (
                       pos      INTEGER PRIMARY KEY,
                       email    TEXT,
                       key      TEXT,
                       name     TEXT,
                       gender   TEXT,
                       country  TEXT,
                       domain   TEXT,
                       run      INTEGER NOT NULL DEFAULT 0
                   )""")
            writer.execute("CREATE INDEX IF NOT EXISTS base_key ON base (key)")
            writer.execute("CREATE TABLE IF NOT EXISTS checked "
                           "(key TEXT PRIMARY KEY) WITHOUT ROWID")
            writer.execute("DELETE FROM base")
            writer.execute("DELETE FROM checked")
            writer.commit()
            reader = sqlite3.connect(path, check_same_thread=False, timeout=30)
            self._writer, self._reader, self._path = writer, reader, path
            if self._temporary:
                ссылка = weakref.ref(self)
                atexit.register(lambda: ссылка() is not None and ссылка().close())
        except Exception as беда:
            self._error = "%s: %s" % (type(беда).__name__, беда)
            self._writer = self._reader = None

    @staticmethod
    def _storage_dir():
        for candidate in (data_dir_of_app(), tempfile.gettempdir()):
            try:
                os.makedirs(candidate, exist_ok=True)
                if os.access(candidate, os.W_OK):
                    return candidate
            except Exception:
                continue
        return tempfile.gettempdir()

    @staticmethod
    def _sweep_orphans(directory):
        try:
            cutoff = time.time() - _ORPHAN_AGE_HOURS * 3600
            for name in os.listdir(directory):
                if not name.startswith("base_") or ".sqlite" not in name:
                    continue
                path = os.path.join(directory, name)
                try:
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                except OSError:
                    continue
        except Exception:
            pass

    def close(self):
        with self._state_lock:
            self._generation += 1
        with self._write_lock, self._read_lock:
            for conn in (self._writer, self._reader):
                try:
                    if conn is not None:
                        conn.close()
                except Exception:
                    pass
            self._writer = self._reader = None
            if self._temporary and self._path:
                for suffix in ("", "-wal", "-shm"):
                    try:
                        os.remove(self._path + suffix)
                    except OSError:
                        pass
                self._path = None


    def feeder(self, breathe=False):
        with self._state_lock:
            self._generation += 1
            generation = self._generation
            self._loading = self._writer is not None
            self._loaded = 0
            self._done = 0
            self._facets_cache = {}
        return _Feeder(self, generation, breathe)

    def reload(self, sources, on_done=None):
        snapshot = list(sources or [])
        приёмник = self.feeder(breathe=True)
        if self._writer is None:
            return None

        def work():
            from core.streamer import StreamLoader

            try:
                for email, data in StreamLoader(snapshot).stream_emails():
                    if not приёмник.add(email, data):
                        return
            except Exception as беда:
                приёмник.fail(беда)
                return
            loaded = приёмник.finish()
            if loaded is not None and callable(on_done):
                try:
                    on_done(loaded)
                except Exception:
                    pass

        thread = threading.Thread(target=work, daemon=True, name="база-в-таблицу")
        thread.start()
        return thread

    def _current(self, generation):
        with self._state_lock:
            return self._generation == generation

    def _clear_rows(self, generation):
        with self._write_lock:
            if not self._current(generation) or self._writer is None:
                return False
            self._writer.execute("DELETE FROM base")
            self._writer.commit()
            with self._state_lock:
                self._loaded = 0
                self._done = 0
                self._error = ""
        return True

    def _finish(self, generation):
        with self._state_lock:
            if self._generation != generation:
                return None
            self._loading = False
            self._facets_cache = {}
            return self._loaded

    def _write_batch(self, batch, generation):
        with self._write_lock:
            if not self._current(generation) or self._writer is None:
                return False
            epoch = self._epoch
            self._writer.executemany(
                "INSERT INTO base (pos, email, key, name, gender, country, domain) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)", batch)
            first, last = batch[0][0], batch[-1][0]
            cursor = self._writer.execute(
                "UPDATE base SET run = ? WHERE pos BETWEEN ? AND ? AND run < ? "
                "AND key IN (SELECT key FROM checked)", (epoch, first, last, epoch))
            done = max(0, cursor.rowcount or 0)
            self._writer.commit()
            with self._state_lock:
                self._loaded += len(batch)
                self._done += done
        return True

    def _fail(self, generation, беда):
        with self._state_lock:
            if self._generation == generation:
                self._loading = False
                self._error = "%s: %s" % (type(беда).__name__, беда)


    def mark(self, *emails):
        from core.cleaner import normalize_for_dedup

        keys = []
        for email in emails:
            if isinstance(email, str) and "@" in email:
                try:
                    keys.append(normalize_for_dedup(email))
                except Exception:
                    continue
        if not keys:
            return
        with self._state_lock:
            self._marks.extend(keys)
            много = len(self._marks) >= 500
        if много:
            self.flush()

    def flush(self):
        with self._flush_lock:
            self._flush_locked()

    def _flush_locked(self):
        with self._state_lock:
            if not self._marks:
                return
            keys, self._marks = self._marks, []
            epoch = self._epoch
        rows = [(k,) for k in dict.fromkeys(keys)]
        with self._write_lock:
            if self._writer is None or self._epoch != epoch:
                return
            try:
                self._writer.executemany(
                    "INSERT OR IGNORE INTO checked (key) VALUES (?)", rows)
                cursor = self._writer.executemany(
                    "UPDATE base SET run = ? WHERE key = ? AND run < ?",
                    [(epoch, key, epoch) for (key,) in rows])
                done = max(0, cursor.rowcount or 0)
                self._writer.commit()
            except Exception:
                return
            with self._state_lock:
                self._done += done

    def reset_checked(self):
        with self._flush_lock, self._write_lock:
            with self._state_lock:
                self._marks = []
                self._epoch += 1
                self._done = 0
                self._facets_cache = {}
            if self._writer is not None:
                try:
                    self._writer.execute("DELETE FROM checked")
                    self._writer.commit()
                except Exception:
                    pass


    def state(self):
        self.flush()
        with self._state_lock:
            return {"total": self._loaded, "pending": max(0, self._loaded - self._done),
                    "loading": self._loading, "error": self._error}

    @staticmethod
    def _wanted(filters):
        return (PENDING in tuple(filters.get("groups") or ())
                and not filters.get("min_score"))

    @staticmethod
    def _plain(filters):
        return not filters.get("search") and not any(
            filters.get(facet) for facet in ("country", "gender", "provider"))

    def _where(self, filters, skip=None):
        clauses = ["run < ?"]
        params = [self._epoch]
        for facet, column in (("country", "country"), ("gender", "gender"),
                              ("provider", "domain")):
            picked = filters.get(facet) or []
            if facet == skip or not picked:
                continue
            clauses.append("%s IN (%s)" % (column, ",".join("?" * len(picked))))
            params.extend(picked)
        if filters.get("search"):
            clauses.append("email LIKE ? ESCAPE '\\'")
            params.append("%" + _escape_like(filters["search"]) + "%")
        return " AND ".join(clauses), params

    def count(self, filters):
        if not self._wanted(filters) or self._reader is None:
            return 0
        self.flush()
        if self._plain(filters):
            return self.state()["pending"]
        where, params = self._where(filters)
        with self._read_lock:
            try:
                row = self._reader.execute(
                    "SELECT COUNT(*) FROM base WHERE " + where, params).fetchone()
                return int(row[0]) if row else 0
            except Exception:
                return 0

    def page(self, filters, offset, limit):
        if not self._wanted(filters) or self._reader is None or limit <= 0:
            return []
        self.flush()
        where, params = self._where(filters)
        with self._read_lock:
            try:
                cursor = self._reader.execute(
                    "SELECT email, name, gender, country FROM base "
                    "WHERE %s ORDER BY pos LIMIT ? OFFSET ?" % where,
                    params + [int(limit), max(0, int(offset))])
                rows = cursor.fetchall()
            except Exception:
                return []
        from core.provider import classify_domain
        return [{"email": email, "name": name or "", "gender": gender or "",
                 "country": country or "", "provider": classify_domain(email)[0]}
                for email, name, gender, country in rows]

    def facet_values(self, filters, limit=200):
        out = {"country": [], "gender": [], "provider": []}
        if not self._wanted(filters) or self._reader is None:
            return out
        self.flush()
        signature = repr(sorted((k, repr(v)) for k, v in filters.items()))
        with self._state_lock:
            hit = self._facets_cache.get(signature)
            fresh = (hit is not None and (time.monotonic() - hit[0] < FACETS_TTL
                                          or (not self._loading and hit[1] == self._done)))
            if fresh:
                return hit[2]
            done = self._done
        with self._read_lock:
            for facet, column in (("country", "country"), ("gender", "gender"),
                                  ("provider", "domain")):
                where, params = self._where(filters, skip=facet)
                try:
                    cursor = self._reader.execute(
                        "SELECT %s, COUNT(*) FROM base WHERE %s GROUP BY %s "
                        "ORDER BY COUNT(*) DESC, %s LIMIT ?" % (column, where, column, column),
                        params + [int(limit)])
                    out[facet] = [{"value": value or "", "count": int(count)}
                                  for value, count in cursor]
                except Exception:
                    out[facet] = []
        with self._state_lock:
            self._facets_cache[signature] = (time.monotonic(), done, out)
        return out


class _Feeder:

    def __init__(self, store, generation, breathe):
        from core.cleaner import normalize_for_dedup

        self._store = store
        self._generation = generation
        self._breathe = bool(breathe)
        self._key = normalize_for_dedup
        self._batch = []
        self._position = 0
        self._started = False
        self._alive = store._writer is not None

    def _start(self):
        self._started = True
        return self._store._clear_rows(self._generation)

    def add(self, email, data=None):
        if not self._alive:
            return False
        try:
            if not self._started and not self._start():
                self._alive = False
                return False
            if not isinstance(email, str) or "@" not in email:
                return True
            data = data if isinstance(data, dict) else {}
            self._batch.append((self._position, email, self._key(email),
                                str(data.get("name") or ""), str(data.get("gender") or ""),
                                str(data.get("country") or ""),
                                email.rpartition("@")[2].strip().lower()))
            self._position += 1
            if self._breathe and self._position % BREATHE_EVERY == 0:
                time.sleep(0.001)
            if len(self._batch) >= BATCH:
                batch, self._batch = self._batch, []
                if not self._store._write_batch(batch, self._generation):
                    self._alive = False
                    return False
            return True
        except Exception as беда:
            self.fail(беда)
            return False

    def finish(self):
        if not self._alive:
            return None
        self._alive = False
        try:
            if not self._started and not self._start():
                return None
            if self._batch and not self._store._write_batch(self._batch, self._generation):
                return None
            self._batch = []
        except Exception as беда:
            self.fail(беда)
            return None
        return self._store._finish(self._generation)

    def fail(self, беда):
        self._alive = False
        self._store._fail(self._generation, беда)
