import json
import os
import sqlite3
import threading
import datetime
from core.paths import data_path


DEFAULT_CACHE_PATH = data_path("validation_cache.sqlite")

CACHEABLE_STATUSES = ("Valid", "Invalid/Bounce")


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class ResultCache:

    def __init__(self, path=DEFAULT_CACHE_PATH, ttl_valid_days=7, ttl_invalid_days=90):
        self.path = path
        self.ttl_valid_days = max(1, int(ttl_valid_days))
        self.ttl_invalid_days = max(1, int(ttl_invalid_days))
        self._lock = threading.Lock()
        self._conn = None
        self.hits = 0
        self.writes = 0

        try:
            directory = os.path.dirname(path)
            if directory and not os.path.exists(directory):
                os.makedirs(directory, exist_ok=True)
            self._conn = sqlite3.connect(path, check_same_thread=False, timeout=10)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS results (
                       email      TEXT PRIMARY KEY,
                       status     TEXT NOT NULL,
                       reason     TEXT,
                       mx         TEXT,
                       payload    TEXT,
                       checked_at TEXT NOT NULL
                   )"""
            )
            self._forget_verdicts_without_proof()
            self._conn.commit()
        except Exception:
            self._close_quietly()

    _NO_PROOF_REASON = ("Имя не может существовать%", "%длиннее%")

    def _forget_verdicts_without_proof(self):
        if self._conn is None:
            return 0
        удалено = 0
        try:
            cursor = self._conn.execute(
                "DELETE FROM results WHERE status = ? AND reason LIKE ? AND reason LIKE ?",
                ("Invalid/Bounce",) + self._NO_PROOF_REASON)
            удалено += int(cursor.rowcount or 0)
        except Exception:
            pass
        try:
            cursor = self._conn.execute(
                "DELETE FROM results WHERE status = 'Valid' AND ("
                "reason LIKE '%переполнен%' OR lower(reason) LIKE '%quota%' "
                "OR lower(reason) LIKE '%mailbox full%' "
                "OR lower(reason) LIKE '%out of storage%')")
            удалено += int(cursor.rowcount or 0)
        except Exception:
            pass
        return удалено


    @property
    def enabled(self):
        return self._conn is not None

    @staticmethod
    def _key(email):
        return email.strip().lower() if isinstance(email, str) else ""

    def _close_quietly(self):
        try:
            if self._conn is not None:
                self._conn.close()
        except Exception:
            pass
        self._conn = None

    def _ttl_days(self, status):
        return self.ttl_invalid_days if status == "Invalid/Bounce" else self.ttl_valid_days


    def size(self):
        if not self.enabled:
            return 0
        try:
            with self._lock:
                row = self._conn.execute("SELECT COUNT(*) FROM results").fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0

    def get(self, email):
        key = self._key(email)
        if not key or not self.enabled:
            return None
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT status, reason, mx, payload, checked_at FROM results WHERE email = ?",
                    (key,),
                ).fetchone()
        except Exception:
            return None
        if not row:
            return None

        status, reason, mx, payload, checked_at = row
        if status not in CACHEABLE_STATUSES:
            return None

        try:
            stamp = datetime.datetime.fromisoformat(checked_at)
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=datetime.timezone.utc)
            age_days = (_utc_now() - stamp).days
        except Exception:
            return None

        if age_days < 0 or age_days > self._ttl_days(status):
            return None

        try:
            data = json.loads(payload) if payload else {}
        except Exception:
            data = {}
        if not isinstance(data, dict):
            data = {}

        with self._lock:
            self.hits += 1
        return {
            "status": status,
            "reason": reason or "",
            "mx": mx or "N/A",
            "data": data,
            "checked_at": checked_at,
            "age_days": age_days,
        }

    def put(self, email, status, reason, mx, data=None):
        key = self._key(email)
        if not key or not self.enabled:
            return False
        if status not in CACHEABLE_STATUSES:
            return False

        try:
            payload = json.dumps(data if isinstance(data, dict) else {}, ensure_ascii=False)
        except Exception:
            payload = "{}"

        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO results "
                    "(email, status, reason, mx, payload, checked_at) VALUES (?, ?, ?, ?, ?, ?)",
                    (key, status, str(reason or "")[:500], str(mx or "N/A"),
                     payload, _utc_now().isoformat()),
                )
                self._conn.commit()
                self.writes += 1
            return True
        except Exception:
            return False

    BOUNCE_REASON = "Отскок при рассылке: письмо ушло и вернулось"

    def record_bounce(self, email, detail=""):
        """Кладёт адрес как Invalid по факту ОТСКОКА. True, если записано.

        Это доказательство сильнее любого SMTP-ответа, и вот почему. Проба
        `RCPT TO` спрашивает сервер о намерении; отскок означает, что письмо
        было реально принято, доставлено до почтового ящика и отвергнуто там.
        Между этими двумя событиями стоит вся внутренняя маршрутизация
        получателя, о которой снаружи не знает никто.

        Поэтому запись идёт поверх всего: даже если в кэше лежит свежий
        `Valid`, отскок его перекрывает. Обратное — оставить `Valid` при
        известном отскоке — означало бы отправить второе письмо туда же.

        ТОЛЬКО ЖЁСТКИЙ ОТСКОК. Мягкий (ящик переполнен, сервер занят, серый
        список) доказывает ОБРАТНОЕ — что ящик существует, — и звать эту
        функцию для него нельзя. Разделение делает вызывающий: у разных
        рассыльщиков форматы отчётов разные, и разбирать их здесь значило бы
        привязаться к одному.
        """
        key = self._key(email)
        if not key or not self.enabled:
            return False
        причина = self.BOUNCE_REASON
        if detail:
            причина = "%s (%s)" % (причина, str(detail)[:200])
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO results "
                    "(email, status, reason, mx, payload, checked_at) "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (key, "Invalid/Bounce", причина, "N/A", "{}",
                     _utc_now().isoformat()))
                self._conn.commit()
                self.writes += 1
            return True
        except Exception:
            return False

    def import_bounces(self, emails, detail=""):
        записано = 0
        for адрес in emails or []:
            if self.record_bounce(адрес, detail):
                записано += 1
        return записано

    def bounced_domains(self, min_count=3):
        try:
            min_count = max(1, int(min_count))
        except Exception:
            min_count = 3
        if not self.enabled:
            return []
        try:
            with self._lock:
                cur = self._conn.execute(
                    "SELECT substr(email, instr(email, \'@\') + 1) AS dom, "
                    "COUNT(*) FROM results WHERE status = ? AND reason LIKE ? "
                    "GROUP BY dom HAVING COUNT(*) >= ?",
                    ("Invalid/Bounce", self.BOUNCE_REASON + "%", min_count))
                return sorted(строка[0] for строка in cur.fetchall() if строка[0])
        except Exception:
            return []

    def forget_domain(self, domain):
        key = str(domain or "").strip().lower()
        if not key or not self.enabled:
            return 0
        экранированный = (key.replace("\\", "\\\\")
                             .replace("%", "\\%")
                             .replace("_", "\\_"))
        try:
            with self._lock:
                cur = self._conn.execute(
                    "DELETE FROM results WHERE email LIKE ? ESCAPE '\\'",
                    ("%@" + экранированный,))
                self._conn.commit()
                return int(cur.rowcount or 0)
        except Exception:
            return 0

    def purge_expired(self):
        if not self.enabled:
            return 0
        now = _utc_now()
        valid_edge = (now - datetime.timedelta(days=self.ttl_valid_days)).isoformat()
        invalid_edge = (now - datetime.timedelta(days=self.ttl_invalid_days)).isoformat()
        try:
            with self._lock:
                cur = self._conn.execute(
                    "DELETE FROM results WHERE (status = 'Valid' AND checked_at < ?) "
                    "OR (status = 'Invalid/Bounce' AND checked_at < ?) "
                    "OR status NOT IN ('Valid', 'Invalid/Bounce')",
                    (valid_edge, invalid_edge),
                )
                self._conn.commit()
                return cur.rowcount or 0
        except Exception:
            return 0

    def close(self):
        with self._lock:
            self._close_quietly()
