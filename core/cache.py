# core/cache.py
"""Кэш доказанных вердиктов между прогонами.

Зачем. Без него перезапуск проверяет базу заново от первого адреса. А вердикт
SMTP от перезапуска не меняется: если сервер сказал «250 OK» или «550 такого
ящика нет», он скажет то же самое и завтра. Повторный прогон 100k базы — это
часы работы прокси и лишний трафик к чужим почтовикам ради ответа, который
уже был получен.

Что кэшируется. ТОЛЬКО доказанные вердикты SMTP: Valid и Invalid/Bounce.

Что НЕ кэшируется никогда:
  * Unknown  — это сбой НАШЕЙ стороны (прокси, таймаут, блок по IP).
               Закэшировать его — значит законсервировать собственную неудачу
               и больше никогда не дать адресу шанса.
  * Risky    — вердикта о ящике не было, чаще всего это отказ по репутации IP.
               С другого прокси ответ вполне может стать однозначным.
  * Catch-all и greylisted — по той же причине: ответ ещё не получен.

Срок годности. Valid живёт 30 дней: ящик могут забросить или удалить.
Invalid живёт дольше, 90 дней: подтверждённый отскок — состояние устойчивое,
и повторно жечь на нём прокси незачем. Просроченная запись просто не отдаётся,
адрес проверяется заново и запись перезаписывается.
"""

import json
import os
import sqlite3
import threading
import datetime


DEFAULT_CACHE_PATH = os.path.join("data", "validation_cache.sqlite")

# Только эти два статуса — доказательства. Остальные говорят о нашей стороне.
CACHEABLE_STATUSES = ("Valid", "Invalid/Bounce")


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


class ResultCache:
    """Потокобезопасное хранилище вердиктов. Любая ошибка БД тихо отключает кэш.

    Кэш — ускорение, а не источник истины: если SQLite недоступен (нет прав,
    диск занят), валидация обязана продолжить работу, просто без ускорения.
    """

    def __init__(self, path=DEFAULT_CACHE_PATH, ttl_valid_days=30, ttl_invalid_days=90):
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
            # WAL: писать из 100+ потоков и одновременно читать, не блокируя друг друга.
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
            self._conn.commit()
        except Exception:
            self._close_quietly()

    # --- служебное ---------------------------------------------------------

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

    # --- интерфейс ---------------------------------------------------------

    def size(self):
        """Сколько вердиктов лежит в кэше."""
        if not self.enabled:
            return 0
        try:
            with self._lock:
                row = self._conn.execute("SELECT COUNT(*) FROM results").fetchone()
            return int(row[0]) if row else 0
        except Exception:
            return 0

    def get(self, email):
        """Вердикт из кэша или None.

        Возвращает {'status', 'reason', 'mx', 'data', 'checked_at'}, где status —
        это SMTP-статус (Valid / Invalid/Bounce), а не то, что показано в таблице:
        ролевой адрес мог отображаться как Role-based, и это решается заново.
        """
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
            return None  # Протухло — пусть проверяется заново

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
        """Кладёт вердикт. Всё, кроме Valid и Invalid/Bounce, молча игнорируется."""
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

    def purge_expired(self):
        """Убирает протухшие записи. Возвращает, сколько удалено."""
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
