import heapq
import itertools
import json
import os
import sqlite3
import tempfile
import threading
import time
from array import array
from core.paths import data_dir as data_dir_of_app


def group_of(status):
    if status == "Valid":
        return "valid"
    if isinstance(status, str) and "Invalid" in status:
        return "invalid"
    if status == "Role-based":
        return "spam"
    if status in ("Mailbox Full", "Disabled"):
        return "spam"
    if isinstance(status, str) and ("Trap" in status or "Disposable" in status):
        return "spam"
    if status in ("Unknown", "Risky"):
        return "unknown"

    return "unknown"


GROUPS = ("valid", "invalid", "spam", "unknown", "other")


def _score_of(payload):
    if not isinstance(payload, dict):
        return 0
    try:
        return int(payload.get("engagement_score", 0) or 0)
    except (TypeError, ValueError):
        return 0

def _provider_of(email):
    if not isinstance(email, str) or "@" not in email:
        return ""
    return email.rpartition("@")[2].strip().lower()


def _facet_of(payload, key):
    if not isinstance(payload, dict):
        return ""
    value = payload.get(key)
    if value is None:
        return ""
    text = str(value).strip()
    return text


FLUSH_EVERY = 500


ORDER_BY = "ORDER BY score DESC, pos ASC"


FACETS = ("country", "gender", "provider")


def normalize_filters(raw, groups=None, min_score=0):
    raw = raw if isinstance(raw, dict) else {}

    chosen = raw.get("groups") if raw.get("groups") is not None else groups
    chosen = tuple(chosen or ("valid",))

    try:
        score = int(raw.get("minScore", raw.get("min_score", min_score)) or 0)
    except (TypeError, ValueError):
        score = 0
    score = max(0, min(100, score))

    values = {}
    for facet in FACETS:
        picked = raw.get(facet) or raw.get(facet + "s") or []
        if isinstance(picked, str):
            picked = [picked]
        values[facet] = [str(v).strip() for v in picked if str(v).strip() != "" or v == ""]

    return {
        "groups": chosen,
        "min_score": score,
        "country": values["country"],
        "gender": values["gender"],
        "provider": [v.lower() for v in values["provider"]],
        "search": str(raw.get("search") or "").strip().lower(),
        "hide_typo": bool(raw.get("hideTypo") or raw.get("hide_typo")),
    }


def _filters_are_plain(filters):
    return (not filters["min_score"] and not filters["search"]
            and not filters.get("hide_typo")
            and not any(filters[facet] for facet in FACETS))


class ResultStore:

    def __init__(self, path=None, drop_repeats=False):
        self._lock = threading.RLock()
        self._index = {name: array("q") for name in GROUPS}
        self._counts = {name: 0 for name in GROUPS}
        self._names = 0
        self._total = 0

        self._conn = None
        self._path = None
        self._writes_ok = True
        self._pending = []
        self._memory_rows = {}
        self._drop_repeats = bool(drop_repeats)
        self._pending_keys = {}
        self._memory_keys = {}

        self._open(path)


    def _open(self, path):
        try:
            if path is None:
                directory = self._storage_dir()
                self._sweep_orphans(directory)
                handle, path = tempfile.mkstemp(prefix="results_", suffix=".sqlite",
                                                dir=directory)
                os.close(handle)
                self._temporary = True
            else:
                self._temporary = False
            self._conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=OFF")
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS rows (
                       pos      INTEGER PRIMARY KEY,
                       email    TEXT,
                       status   TEXT,
                       reason   TEXT,
                       mx       TEXT,
                       data     TEXT,
                       grp      TEXT,
                       score    INTEGER,
                       country  TEXT,
                       gender   TEXT,
                       provider TEXT,
                       email_lc TEXT,
                       typo     TEXT
                   )"""
            )
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS rows_grp_score ON rows (grp, score)")

            for column in ("country", "gender", "provider", "email_lc", "typo"):
                try:
                    self._conn.execute("ALTER TABLE rows ADD COLUMN %s TEXT" % column)
                except sqlite3.OperationalError:
                    pass

            for name, column in (("rows_grp_country", "grp, country"),
                                 ("rows_grp_gender", "grp, gender"),
                                 ("rows_grp_provider", "grp, provider"),
                                 ("rows_email_lc", "email_lc"),
                                 ("rows_facets", "grp, country, gender, score"),
                                 ("rows_grp_email", "grp, email_lc")):
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS %s ON rows (%s)" % (name, column))
            self._conn.commit()
            self._path = path
        except Exception:
            self._conn = None
            self._path = None

    _ORPHAN_AGE_HOURS = 24

    @classmethod
    def _sweep_orphans(cls, directory):
        try:
            cutoff = time.time() - cls._ORPHAN_AGE_HOURS * 3600
            for name in os.listdir(directory):
                if not name.startswith("results_") or ".sqlite" not in name:
                    continue
                path = os.path.join(directory, name)
                try:
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                except OSError:
                    continue
        except Exception:
            pass

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

    def close(self):
        with self._lock:
            self._flush_locked()
            if self._conn is not None:
                try:
                    self._conn.close()
                except Exception:
                    pass
                self._conn = None
            if getattr(self, "_temporary", False) and self._path:
                for suffix in ("", "-wal", "-shm"):
                    try:
                        os.remove(self._path + suffix)
                    except OSError:
                        pass
                self._path = None


    def _already_shown(self, key):
        if not self._drop_repeats or not key:
            return None
        for где in (self._pending_keys, self._memory_keys):
            if key in где:
                return где[key]
        if self._conn is None:
            return None
        try:
            cursor = self._conn.execute(
                "SELECT grp FROM rows WHERE email_lc = ? LIMIT 1", (key,))
            строка = cursor.fetchone()
            return строка[0] if строка else None
        except Exception:
            return None

    def append(self, email, status, reason, mx, data):
        payload = data if isinstance(data, dict) else {}
        group = group_of(status)
        key = str(email or "").strip().lower()
        with self._lock:
            прежняя = self._already_shown(key)
            if прежняя is not None:
                return прежняя
            position = self._total
            self._total += 1
            self._index[group].append(position)
            self._counts[group] += 1
            if payload.get("name"):
                self._names += 1

            if self._conn is None or not self._writes_ok:
                self._memory_rows[position] = {
                    "email": email, "status": status, "reason": reason,
                    "mx": mx, "data": payload}
                self._memory_keys[key] = group
                return group

            try:
                blob = json.dumps(payload, ensure_ascii=False, default=str)
            except Exception:
                blob = "{}"
            self._pending.append((
                position, email, status, reason, mx, blob,
                group, _score_of(payload),
                _facet_of(payload, "country"), _facet_of(payload, "gender"),
                _provider_of(email), key, _facet_of(payload, "typo_of")))
            self._pending_keys[key] = group
            if len(self._pending) >= FLUSH_EVERY:
                self._flush_locked()
        return group

    def _flush_locked(self):
        if not self._pending or self._conn is None:
            return
        try:
            self._conn.executemany(
                "INSERT OR REPLACE INTO rows "
                "(pos, email, status, reason, mx, data, grp, score, "
                " country, gender, provider, email_lc, typo) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", self._pending)
            self._conn.commit()
            self._pending.clear()
            self._pending_keys.clear()
        except Exception:
            for row in self._pending:
                position, email, status, reason, mx, blob = row[:6]
                self._memory_rows[position] = {
                    "email": email, "status": status, "reason": reason,
                    "mx": mx, "data": _loads(blob)}
                self._memory_keys[str(email or "").strip().lower()] = row[6]
            self._pending.clear()
            self._pending_keys.clear()
            self._writes_ok = False

    def clear(self):
        with self._lock:
            self._pending.clear()
            self._pending_keys.clear()
            self._memory_rows.clear()
            self._memory_keys.clear()
            for name in GROUPS:
                del self._index[name][:]
                self._counts[name] = 0
            self._names = 0
            self._total = 0
            if self._conn is not None:
                try:
                    self._conn.execute("DELETE FROM rows")
                    self._conn.commit()
                    self._writes_ok = True
                except Exception:
                    pass

    def revise_domain(self, domain, new_status, note, spare=None):
        domain = str(domain or "").strip().lower().lstrip("@")
        if not domain:
            return 0
        suffix = "@" + domain
        new_group = group_of(new_status) if new_status else None
        moved = 0
        with self._lock:
            self._flush_locked()
            targets = self._revisable_rows_locked(suffix)
            for position, old_group, reason, row, email_lc in targets:
                if spare and email_lc in spare:
                    continue
                fresh = ("%s | %s" % (reason or "", note)).strip(" |")
                if row is not None:
                    row["reason"] = fresh
                    if new_group is None:
                        moved += 1
                        continue
                    row["status"] = new_status
                    self._memory_keys[str(row.get("email") or "").strip().lower()] = new_group
                else:
                    try:
                        if new_group is None:
                            self._conn.execute(
                                "UPDATE rows SET reason = ? WHERE pos = ?",
                                (fresh, position))
                            moved += 1
                            continue
                        self._conn.execute(
                            "UPDATE rows SET status = ?, grp = ?, reason = ? WHERE pos = ?",
                            (new_status, new_group, fresh, position))
                    except Exception:
                        continue
                try:
                    old_positions = self._index.get(old_group)
                    if old_positions is not None:
                        index = old_positions.index(position)
                        del old_positions[index]
                        self._counts[old_group] -= 1
                except (ValueError, KeyError):
                    pass
                self._index[new_group].append(position)
                self._counts[new_group] += 1
                moved += 1
            if moved and self._conn is not None:
                try:
                    self._conn.commit()
                except Exception:
                    pass
        return moved

    _REVISABLE = ("Valid", "Role-based")

    def _revisable_rows_locked(self, suffix):
        targets = []
        seen = set()
        if self._conn is not None:
            try:
                rows = self._conn.execute(
                    "SELECT pos, grp, reason, email_lc FROM rows "
                    "WHERE status IN (%s) AND email_lc LIKE ?"
                    % ",".join("?" * len(self._REVISABLE)),
                    tuple(self._REVISABLE) + ("%" + suffix,)).fetchall()
            except Exception:
                rows = []
            for position, group, reason, email_lc in rows:
                seen.add(position)
                targets.append((position, group, reason, None, email_lc))
        for position, row in self._memory_rows.items():
            if position in seen or row.get("status") not in self._REVISABLE:
                continue
            email_lc = str(row.get("email") or "").strip().lower()
            if email_lc.endswith(suffix):
                targets.append((position, group_of(row.get("status")),
                                row.get("reason"), row, email_lc))
        return targets


    def __len__(self):
        with self._lock:
            return self._total

    def counts(self):
        with self._lock:
            snapshot = dict(self._counts)
            snapshot["names"] = self._names
            snapshot["total"] = self._total
            return snapshot

    def _selected(self, groups):
        lists = [self._index[name] for name in groups if name in self._index]
        if not lists:
            return iter(())
        if len(lists) == 1:
            return iter(lists[0])
        return heapq.merge(*lists)

    def _fetch(self, positions):
        if not positions:
            return []
        if self._conn is None:
            return [self._memory_rows[p] for p in positions if p in self._memory_rows]

        self._flush_locked()
        found = {}
        for start in range(0, len(positions), 500):
            batch = positions[start:start + 500]
            marks = ",".join("?" * len(batch))
            try:
                cursor = self._conn.execute(
                    f"SELECT pos, email, status, reason, mx, data "
                    f"FROM rows WHERE pos IN ({marks})", batch)
                for pos, email, status, reason, mx, blob in cursor:
                    found[pos] = {"email": email, "status": status,
                                  "reason": reason, "mx": mx,
                                  "data": _loads(blob)}
            except Exception:
                pass
        for position in positions:
            if position not in found and position in self._memory_rows:
                found[position] = self._memory_rows[position]
        return [found[p] for p in positions if p in found]

    def _sql_ready(self, groups):
        if self._conn is None or not self._writes_ok or self._memory_rows:
            return False
        return bool([name for name in groups if name in self._index])

    def _sql_groups(self, groups):
        return [name for name in groups if name in self._index]


    def _where(self, filters):
        names = self._sql_groups(filters["groups"])
        clauses = ["grp IN (%s)" % ",".join("?" * len(names))]
        params = list(names)

        if filters["min_score"] > 0:
            clauses.append("score >= ?")
            params.append(int(filters["min_score"]))

        for facet in FACETS:
            picked = filters[facet]
            if not picked:
                continue
            clauses.append("%s IN (%s)" % (facet, ",".join("?" * len(picked))))
            params.extend(picked)

        if filters["search"]:
            needle = filters["search"]
            needle = needle.replace('\\', '\\\\')
            needle = needle.replace("%", '\\%').replace("_", '\\_')
            clauses.append("email_lc LIKE ? ESCAPE '\\'")
            params.append("%" + needle + "%")

        if filters.get("hide_typo"):
            # COALESCE: у строк из файла прежней версии колонки не было, и
            clauses.append("COALESCE(typo, '') = ''")

        return " AND ".join(clauses), params

    def _matches(self, row, filters):
        payload = row.get("data") if isinstance(row.get("data"), dict) else {}

        if filters["min_score"] > 0:
            try:
                score = int(payload.get("engagement_score", 0) or 0)
            except (TypeError, ValueError):
                return False
            if score < filters["min_score"]:
                return False

        for facet in ("country", "gender"):
            picked = filters[facet]
            if picked and _facet_of(payload, facet) not in picked:
                return False

        if filters["provider"]:
            if _provider_of(row.get("email")) not in filters["provider"]:
                return False

        if filters["search"]:
            if filters["search"] not in str(row.get("email") or "").lower():
                return False

        if filters.get("hide_typo") and _facet_of(payload, "typo_of"):
            return False

        return True

    def page(self, groups=None, page=1, size=100, min_score=0, filters=None):
        picked = normalize_filters(filters, groups, min_score)
        page = max(1, int(page or 1))
        size = max(1, int(size or 1))
        start = (page - 1) * size

        with self._lock:
            if _filters_are_plain(picked) and self._sql_ready(picked["groups"]):
                self._flush_locked()
                try:
                    where, params = self._where(picked)
                    cursor = self._conn.execute(
                        "SELECT pos FROM rows WHERE %s %s LIMIT ? OFFSET ?"
                        % (where, ORDER_BY), params + [size, start])
                    return self._fetch([row[0] for row in cursor])
                except Exception:
                    pass
            if _filters_are_plain(picked):
                chosen = list(itertools.islice(self._selected(picked["groups"]),
                                               start, start + size))
                return self._fetch(chosen)

            if self._sql_ready(picked["groups"]):
                self._flush_locked()
                try:
                    where, params = self._where(picked)
                    cursor = self._conn.execute(
                        "SELECT pos FROM rows WHERE %s %s LIMIT ? OFFSET ?"
                        % (where, ORDER_BY), params + [size, start])
                    return self._fetch([row[0] for row in cursor])
                except Exception:
                    pass

            chosen = []
            for position in self._selected(picked["groups"]):
                rows = self._fetch([position])
                if rows and self._matches(rows[0], picked):
                    chosen.append((-_score_of(rows[0].get("data")), position))
            chosen.sort()
            return self._fetch([pos for _score, pos in chosen[start:start + size]])

    def matching_count(self, groups=None, min_score=0, filters=None):
        picked = normalize_filters(filters, groups, min_score)
        with self._lock:
            if _filters_are_plain(picked):
                return sum(self._counts[name] for name in picked["groups"]
                           if name in self._counts)

            if self._sql_ready(picked["groups"]):
                self._flush_locked()
                try:
                    where, params = self._where(picked)
                    cursor = self._conn.execute(
                        "SELECT COUNT(*) FROM rows WHERE %s" % where, params)
                    row = cursor.fetchone()
                    if row is not None:
                        return int(row[0])
                except Exception:
                    pass

            total = 0
            for position in self._selected(picked["groups"]):
                rows = self._fetch([position])
                if rows and self._matches(rows[0], picked):
                    total += 1
            return total

    def facet_values(self, groups=None, filters=None, limit=200):
        picked = normalize_filters(filters, groups, 0)
        out = {facet: [] for facet in FACETS}

        with self._lock:
            if self._sql_ready(picked["groups"]):
                self._flush_locked()
                try:
                    for facet in FACETS:
                        narrowed = dict(picked)
                        narrowed[facet] = []
                        where, params = self._where(narrowed)
                        cursor = self._conn.execute(
                            "SELECT %s, COUNT(*) FROM rows WHERE %s "
                            "GROUP BY %s ORDER BY COUNT(*) DESC, %s LIMIT ?"
                            % (facet, where, facet, facet), params + [int(limit)])
                        out[facet] = [{"value": value or "", "count": int(count)}
                                      for value, count in cursor]
                    return out
                except Exception:
                    pass

            tally = {facet: {} for facet in FACETS}
            for position in self._selected(picked["groups"]):
                rows = self._fetch([position])
                if not rows:
                    continue
                row = rows[0]
                payload = row.get("data") if isinstance(row.get("data"), dict) else {}
                for facet in FACETS:
                    narrowed = dict(picked)
                    narrowed[facet] = []
                    if not self._matches(row, narrowed):
                        continue
                    value = (_provider_of(row.get("email")) if facet == "provider"
                             else _facet_of(payload, facet))
                    tally[facet][value] = tally[facet].get(value, 0) + 1
            for facet in FACETS:
                ordered = sorted(tally[facet].items(), key=lambda kv: (-kv[1], kv[0]))
                out[facet] = [{"value": value, "count": count}
                              for value, count in ordered[:limit]]
            return out

    STREAM_BATCH = 1000

    def iter_matching(self, groups=None, min_score=0, filters=None):
        picked = normalize_filters(filters, groups, min_score)
        with self._lock:
            positions = list(self._selected(picked["groups"]))
        for start in range(0, len(positions), self.STREAM_BATCH):
            batch = positions[start:start + self.STREAM_BATCH]
            with self._lock:
                rows = self._fetch(batch)
            for row in rows:
                if _filters_are_plain(picked) or self._matches(row, picked):
                    yield row

    def all_rows(self):
        with self._lock:
            positions = list(range(self._total))
            return self._fetch(positions)


def _loads(blob):
    try:
        value = json.loads(blob) if blob else {}
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}
