# core/longterm.py
"""Память, которая переживает перезапуск программы.

Три вещи выяснялись заново при каждом запуске, хотя добываются дорого и
меняются медленно:

  * **catch-all домена.** Выясняется тройной пробой выдуманными адресами —
    три RCPT в отдельной сессии на КАЖДЫЙ домен базы. На десяти тысячах
    доменов это тридцать тысяч лишних подключений при каждом старте, и каждое
    из них — повод почтовику нас заметить. А ответ на вопрос «принимает ли
    домен что угодно» меняется раз в годы.

  * **профиль прокси.** Выходной IP, обратный DNS, семь чёрных списков и три
    пробы почтовиков — на большом пуле это минуты до первой почты, каждый раз
    с нуля.

  * **нагрузка на выходной IP.** Потолок в 800 обращений задумывался как
    СУТОЧНЫЙ (общепринятый ориентир — 500-1000 писем на IP в сутки), но
    счётчик жил в памяти прогона. Два запуска за день — 1600 обращений с
    одного адреса, и программа об этом не знала.

Главное правило: **память не имеет права ни врать, ни мешать.** Протухшая
запись не применяется. Недоступная база молча выключает память, а не роняет
проверку: это ускорение, а не источник истины. Мусор на входе не роняет
ничего — зовут отсюда из рабочих потоков, где исключение проглатывается и
адрес молча выпадает из выдачи.

Почему SQLite, а не JSON: пишут сюда из нескольких потоков и по ходу работы.
Почему один файл на три таблицы: это три стороны одного вопроса — «что мы уже
узнали и незачем узнавать снова».
"""
import json
import os
import sqlite3
import threading
import time

__all__ = ["LongTermMemory", "DEFAULT_PATH",
           "CATCHALL_TTL_HOURS", "PROFILE_TTL_HOURS"]

DEFAULT_PATH = os.path.join("data", "longterm.sqlite")

# Сколько живёт ответ про catch-all. Домен, принимающий что угодно, таким и
# остаётся годами — но месяц выбран сознательно: настройку могли поменять, а
# цена ошибки здесь высокая (несуществующие ящики уехали бы в Valid).
CATCHALL_TTL_HOURS = 30 * 24

# Профиль прокси стареет быстро: у дешёвых прокси выходной IP меняется, PTR
# появляется и пропадает. Сутки — компромисс между «не спрашивать заново
# каждые десять минут» и «не верить позавчерашнему».
PROFILE_TTL_HOURS = 24

# Сколько дней хранить счёт нагрузки. Позапрошлая неделя не нужна никому.
IP_LOAD_KEEP_DAYS = 7


def _now():
    """Время одной точкой входа — чтобы проверки могли отмотать часы."""
    return time.time()


def _today(stamp=None):
    """Номер суток. Считаем целыми днями: вопрос ровно «сколько за сегодня»."""
    return int((stamp if stamp is not None else _now()) // 86400)


class LongTermMemory:
    """Долгая память валидатора. Потокобезопасна; при сбое просто выключается."""

    def __init__(self, path=None):
        # DEFAULT_PATH читается в момент ВЫЗОВА, а не при объявлении: тесты
        # подменяют его на свой временный файл, и значение по умолчанию,
        # связанное в сигнатуре, эту подмену бы не заметило — набор писал бы в
        # настоящую базу владельца.
        path = path or DEFAULT_PATH
        self._lock = threading.Lock()
        self._conn = None
        self._path = None
        try:
            folder = os.path.dirname(path)
            if folder:
                os.makedirs(folder, exist_ok=True)
            # check_same_thread=False: пишут рабочие потоки проверки.
            self._conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS catchall (
                       domain TEXT PRIMARY KEY,
                       is_catchall INTEGER NOT NULL,
                       seen_at REAL NOT NULL)""")
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS proxy_profile (
                       proxy TEXT PRIMARY KEY,
                       payload TEXT NOT NULL,
                       seen_at REAL NOT NULL)""")
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS ip_load (
                       exit_ip TEXT NOT NULL,
                       day INTEGER NOT NULL,
                       used INTEGER NOT NULL,
                       PRIMARY KEY (exit_ip, day))""")
            self._conn.commit()
            self._path = path
        except Exception:
            self._close_quietly()

    # ------------------------------------------------------------------
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
        self._path = None

    def close(self):
        with self._lock:
            self._close_quietly()

    def _query(self, sql, params=(), fetch=None, commit=False):
        """Один запрос под замком. Любая беда гасит память, а не программу."""
        if self._conn is None:
            return None
        with self._lock:
            if self._conn is None:
                return None
            try:
                cursor = self._conn.execute(sql, params)
                answer = None
                if fetch == "one":
                    answer = cursor.fetchone()
                elif fetch == "all":
                    answer = cursor.fetchall()
                if commit:
                    self._conn.commit()
                return answer if answer is not None else True
            except Exception:
                return None

    # ─────────────────────────────────────────────────────── catch-all
    def catchall_get(self, domain):
        """True/False, если про домен уже знаем, иначе None.

        None означает именно «не выясняли», а не «не catch-all». Схлопнуть
        одно в другое — значит пропустить тройную пробу на незнакомом домене
        и отправить его несуществующие ящики в Valid.
        """
        if not isinstance(domain, str) or not domain.strip():
            return None
        row = self._query(
            "SELECT is_catchall, seen_at FROM catchall WHERE domain = ?",
            (domain.strip().lower(),), fetch="one")
        if not row or row is True:
            return None
        if _now() - float(row[1]) > CATCHALL_TTL_HOURS * 3600:
            return None
        return bool(row[0])

    def catchall_put(self, domain, is_catchall):
        """Запоминает выясненный ответ. False — не записали."""
        if not isinstance(domain, str) or not domain.strip():
            return False
        done = self._query(
            "INSERT OR REPLACE INTO catchall (domain, is_catchall, seen_at) "
            "VALUES (?, ?, ?)",
            (domain.strip().lower(), 1 if is_catchall else 0, _now()),
            commit=True)
        return done is not None

    def catchall_count(self):
        row = self._query("SELECT COUNT(*) FROM catchall", fetch="one")
        return int(row[0]) if row and row is not True else 0

    # ─────────────────────────────────────────────────── профиль прокси
    def profiles_load(self, proxies):
        """{прокси: профиль} для тех из списка, что помним и не протухли.

        Спрашиваются ИМЕННО перечисленные: пул между запусками меняется, и
        тащить профили выброшенных прокси незачем.
        """
        if not proxies or isinstance(proxies, (str, bytes)):
            return {}
        try:
            wanted = {p for p in proxies if isinstance(p, str)}
        except TypeError:
            return {}
        if not wanted:
            return {}

        rows = self._query("SELECT proxy, payload, seen_at FROM proxy_profile",
                           fetch="all")
        if not rows or rows is True:
            return {}
        deadline = PROFILE_TTL_HOURS * 3600
        now = _now()
        found = {}
        for proxy, payload, seen_at in rows:
            if proxy not in wanted:
                continue
            if now - float(seen_at) > deadline:
                continue
            try:
                info = json.loads(payload)
            except Exception:
                continue
            if isinstance(info, dict):
                found[proxy] = info
        return found

    def profiles_save(self, profiles):
        """Сохраняет профили пачкой. Возвращает, сколько записано."""
        if not isinstance(profiles, dict) or not profiles or self._conn is None:
            return 0
        stamp = _now()
        rows = []
        for proxy, info in profiles.items():
            if not isinstance(proxy, str) or not isinstance(info, dict):
                continue
            try:
                rows.append((proxy, json.dumps(info, ensure_ascii=False), stamp))
            except Exception:
                continue
        if not rows:
            return 0
        with self._lock:
            if self._conn is None:
                return 0
            try:
                self._conn.executemany(
                    "INSERT OR REPLACE INTO proxy_profile (proxy, payload, seen_at) "
                    "VALUES (?, ?, ?)", rows)
                self._conn.commit()
                return len(rows)
            except Exception:
                return 0

    # ────────────────────────────────────────── суточная нагрузка на IP
    def ip_load_today(self, exit_ip):
        """Сколько обращений ушло через этот адрес СЕГОДНЯ."""
        if not isinstance(exit_ip, str) or not exit_ip:
            return 0
        row = self._query(
            "SELECT used FROM ip_load WHERE exit_ip = ? AND day = ?",
            (exit_ip, _today()), fetch="one")
        if not row or row is True:
            return 0
        try:
            return int(row[0])
        except (TypeError, ValueError):
            return 0

    def ip_load_add(self, exit_ip, count=1):
        """Отмечает обращения и возвращает счёт за сегодня. 0 — не записали."""
        if not isinstance(exit_ip, str) or not exit_ip:
            return 0
        # Число, а не «что-нибудь похожее»: строка «много» здесь означает
        # ошибку вызывающего, и превращать её в единицу нельзя.
        if isinstance(count, bool) or not isinstance(count, int):
            return 0
        if count < 0 or self._conn is None:
            return 0

        day = _today()
        with self._lock:
            if self._conn is None:
                return 0
            try:
                self._conn.execute(
                    "INSERT INTO ip_load (exit_ip, day, used) VALUES (?, ?, ?) "
                    "ON CONFLICT(exit_ip, day) DO UPDATE SET used = used + ?",
                    (exit_ip, day, count, count))
                self._conn.commit()
                row = self._conn.execute(
                    "SELECT used FROM ip_load WHERE exit_ip = ? AND day = ?",
                    (exit_ip, day)).fetchone()
                return int(row[0]) if row else 0
            except Exception:
                return 0

    def ip_load_purge(self, keep_days=IP_LOAD_KEEP_DAYS):
        """Выбрасывает счёт старше keep_days суток. Возвращает, сколько удалено."""
        try:
            keep_days = max(0, int(keep_days))
        except (TypeError, ValueError):
            keep_days = IP_LOAD_KEEP_DAYS
        if self._conn is None:
            return 0
        oldest = _today() - keep_days
        with self._lock:
            if self._conn is None:
                return 0
            try:
                cursor = self._conn.execute(
                    "DELETE FROM ip_load WHERE day < ?", (oldest,))
                self._conn.commit()
                return int(cursor.rowcount or 0)
            except Exception:
                return 0

    def loaded_ips(self, at_least=1):
        """{IP: сколько} по сегодняшнему дню — для отчёта о нагрузке."""
        rows = self._query(
            "SELECT exit_ip, used FROM ip_load WHERE day = ?",
            (_today(),), fetch="all")
        if not rows or rows is True:
            return {}
        return {ip: int(used) for ip, used in rows if int(used) >= at_least}

    def forget_everything(self):
        """Полная очистка — для кнопки «проверить всё заново» и для тестов."""
        for table in ("catchall", "proxy_profile", "ip_load"):
            self._query("DELETE FROM %s" % table, commit=True)
        return True
