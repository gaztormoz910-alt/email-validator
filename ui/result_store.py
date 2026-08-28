# ui/result_store.py
"""Хранилище результатов валидации для интерфейса.

Зачем оно появилось. Раньше таблица жила прямо в списке `results_data`, и на
КАЖДОМ тике опроса очередей (каждые 50 мс) интерфейс звал `_get_filtered_results()`,
который перебирал ВЕСЬ список целиком, чтобы показать сотню строк одной
страницы. На базе в сто тысяч адресов это сто тысяч итераций двадцать раз в
секунду в главном потоке Tk — то есть окно переставало отзываться ровно тогда,
когда результатов становилось много. Причём чем дольше работал прогон, тем
хуже: стоимость тика росла линейно вместе с базой.

Что здесь сделано. Строки складываются один раз, а рядом ведутся индексы по
группам статусов. Тогда:

  * счётчики берутся готовыми, без перебора;
  * страница собирается ленивым слиянием нужных индексов и обрывается, как
    только набрана — то есть стоит примерно столько же на первой странице
    стотысячной базы, сколько на первой странице сотни.

ВТОРАЯ ПРОБЛЕМА, решённая позже: **память**. Индексы сделали показ дешёвым, но
сами СТРОКИ по-прежнему лежали в ОЗУ все до единой. Строка результата — это
словарь с вложенным словарём обогащения, около килобайта на адрес; на десяти
миллионах адресов это десяток гигабайт, то есть прогон падал по памяти именно
на тех объёмах, ради которых затевалось потоковое чтение входа.

Теперь содержимое строк лежит в SQLite (том же, что уже используется под кэш
вердиктов и состояние прогона), а в памяти остаются только позиции — по восемь
байт на строку в `array('q')` вместо словаря. Десять миллионов результатов
стоят восемьдесят мегабайт вместо десяти гигабайт, а стоимость показа страницы
не изменилась: позиции по-прежнему берутся из индекса, и SQLite достаёт ровно
сто строк по первичному ключу.

Если БД открыть не удалось — хранилище молча работает как раньше, целиком в
памяти. Это интерфейс, а не источник истины: показать результаты важнее, чем
сэкономить память.

Само хранилище про Tk ничего не знает — поэтому его можно измерить тестом
без окна.
"""

import heapq
import itertools
import json
import os
import sqlite3
import tempfile
import threading
import time
from array import array


# Отображаемый статус -> группа, которой он управляется в фильтрах.
# Группы, а не сами статусы: галочка «Spam/Trap» включает сразу несколько
# разных вердиктов, и раньше это условие было размазано по трём местам.
def group_of(status):
    """Группа фильтра для отображаемого статуса."""
    if status == "Valid":
        return "valid"
    if isinstance(status, str) and "Invalid" in status:
        return "invalid"
    if status in ("Role-based", "Risky"):
        return "spam"
    if isinstance(status, str) and ("Trap" in status or "Disposable" in status):
        return "spam"
    if status == "Unknown":
        return "unknown"
    return "other"


GROUPS = ("valid", "invalid", "spam", "unknown", "other")


def _score_of(payload):
    """Скор строки числом. Мусор и пустота — это ноль, а не падение.

    Значение приходит из обогащения и может быть чем угодно, вплоть до None
    или строки: уронить запись результата на этом нельзя, иначе адрес молча
    выпадет из выдачи, а счётчик его засчитает.
    """
    if not isinstance(payload, dict):
        return 0
    try:
        return int(payload.get("engagement_score", 0) or 0)
    except (TypeError, ValueError):
        return 0

# Сколько строк копится перед записью пачкой. Одиночный INSERT на каждый
# результат упирается в диск и становится узким местом сам по себе, а пачкой
# в пятьсот строк запись стоит примерно столько же, сколько одна.
FLUSH_EVERY = 500


class ResultStore:
    """Потокобезопасное хранилище строк результата с индексами по группам.

    Содержимое строк — на диске, позиции — в памяти. Публичный интерфейс тот
    же, что был у чисто-оперативной версии, поэтому окно про подмену не знает.
    """

    def __init__(self, path=None):
        self._lock = threading.RLock()
        # Позиции по группам. array('q') вместо list: восемь байт на элемент
        # против двадцати восьми у списка питоновских int.
        self._index = {name: array("q") for name in GROUPS}
        self._counts = {name: 0 for name in GROUPS}
        self._names = 0
        self._total = 0

        self._conn = None
        self._path = None
        # Разделено намеренно: сломаться может ЗАПИСЬ (кончилось место,
        # файл заблокирован антивирусом), и это не повод терять то, что уже
        # записано. Раньше первая же неудачная запись обнуляла соединение —
        # и вместе с ним из таблицы исчезали все ранее показанные строки.
        self._writes_ok = True
        self._pending = []
        # Запасной путь: строки в ОЗУ, если БД недоступна.
        self._memory_rows = {}

        self._open(path)

    # --- устройство -----------------------------------------------------

    def _open(self, path):
        """Открывает файл под строки. Провал не является ошибкой."""
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
            self._conn.execute("PRAGMA synchronous=OFF")   # это кэш показа, не архив
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS rows (
                       pos    INTEGER PRIMARY KEY,
                       email  TEXT,
                       status TEXT,
                       reason TEXT,
                       mx     TEXT,
                       data   TEXT,
                       grp    TEXT,
                       score  INTEGER
                   )"""
            )
            # Группа и скор вынесены из JSON в свои колонки не для красоты.
            # Фильтр «показать только со скором выше N» стоял на разборе JSON
            # в Python, по одному запросу к базе на строку: замерено 2.47 с на
            # трёхстах тысячах строк — и это в ГЛАВНОМ потоке, дважды в
            # секунду, пока таблица открыта. То есть стоило подвинуть ползунок
            # скора, и окно умирало тем вернее, чем дольше шёл прогон.
            # С этим индексом тот же ответ даёт один COUNT.
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS rows_grp_score ON rows (grp, score)")
            self._conn.commit()
            self._path = path
        except Exception:
            self._conn = None
            self._path = None

    # Через сколько часов брошенный файл считается мусором. Сутки — с запасом
    # на самый долгий прогон: пока окно работает, файл открыт и его никто не
    # трогает, а лишний час ожидания дешевле удалённых чужих данных.
    _ORPHAN_AGE_HOURS = 24

    @classmethod
    def _sweep_orphans(cls, directory):
        """Убирает файлы прошлых прогонов, которые никто не закрыл.

        close() удаляет свой файл сам, но до close() дело доходит не всегда:
        окно закрыли крестиком, процесс убили, машина ушла в перезагрузку. Без
        уборки такие файлы копятся в data/ и на больших базах занимают сотни
        мегабайт каждый.
        """
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
                    continue      # занят другим прогоном — не наше дело
        except Exception:
            pass

    @staticmethod
    def _storage_dir():
        for candidate in ("data", tempfile.gettempdir()):
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

    # --- запись ---------------------------------------------------------

    def append(self, email, status, reason, mx, data):
        """Добавляет строку и обновляет индексы. Возвращает её группу."""
        payload = data if isinstance(data, dict) else {}
        group = group_of(status)
        with self._lock:
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
                return group

            try:
                blob = json.dumps(payload, ensure_ascii=False, default=str)
            except Exception:
                blob = "{}"
            self._pending.append((position, email, status, reason, mx, blob,
                                  group, _score_of(payload)))
            if len(self._pending) >= FLUSH_EVERY:
                self._flush_locked()
        return group

    def _flush_locked(self):
        """Пишет накопленное. Вызывается только под захваченным локом."""
        if not self._pending or self._conn is None:
            return
        try:
            self._conn.executemany(
                "INSERT OR REPLACE INTO rows "
                "(pos, email, status, reason, mx, data, grp, score) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", self._pending)
            self._conn.commit()
            self._pending.clear()
        except Exception:
            # Запись сломалась на середине прогона. Соединение НЕ закрываем:
            # то, что уже легло на диск, читается по-прежнему, и терять его
            # незачем. Дальше новые строки копятся в памяти — она дороже, но
            # потерять показанные результаты хуже.
            for row in self._pending:
                position, email, status, reason, mx, blob, _grp, _score = row
                self._memory_rows[position] = {
                    "email": email, "status": status, "reason": reason,
                    "mx": mx, "data": _loads(blob)}
            self._pending.clear()
            self._writes_ok = False

    def clear(self):
        with self._lock:
            self._pending.clear()
            self._memory_rows.clear()
            for name in GROUPS:
                # array не умеет clear() в старых версиях — режем срезом.
                del self._index[name][:]
                self._counts[name] = 0
            self._names = 0
            self._total = 0
            if self._conn is not None:
                try:
                    self._conn.execute("DELETE FROM rows")
                    self._conn.commit()
                    self._writes_ok = True   # чистый лист — даём записи второй шанс
                except Exception:
                    pass

    # --- чтение ---------------------------------------------------------

    def __len__(self):
        with self._lock:
            return self._total

    def counts(self):
        """Готовые счётчики по группам — без перебора строк."""
        with self._lock:
            snapshot = dict(self._counts)
            snapshot["names"] = self._names
            snapshot["total"] = self._total
            return snapshot

    def _selected(self, groups):
        """Ленивое слияние индексов выбранных групп в порядке добавления."""
        lists = [self._index[name] for name in groups if name in self._index]
        if not lists:
            return iter(())
        if len(lists) == 1:
            return iter(lists[0])
        return heapq.merge(*lists)

    def _fetch(self, positions):
        """Строки по позициям, в том же порядке, что и позиции."""
        if not positions:
            return []
        if self._conn is None:
            return [self._memory_rows[p] for p in positions if p in self._memory_rows]

        self._flush_locked()
        # После неудачной записи соединение остаётся годным для чтения, но
        # часть строк живёт уже в памяти — ниже берётся и то, и другое.
        found = {}
        # Разбиваем на порции: у SQLite потолок на число параметров запроса,
        # и страница в тысячу строк в него уже может не поместиться.
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

    def _passes_score(self, position, min_score):
        """Проходит ли одна строка порог по скору. Запасной путь, без БД.

        Медленный по устройству: одна строка — один запрос. Пока скор лежал
        только внутри JSON, другого способа не было, и именно этим фильтр по
        скору вешал окно. Теперь по нему есть колонка с индексом, а этот метод
        остаётся для случая, когда база не открылась и строки лежат в ОЗУ.
        """
        if min_score <= 0:
            return True
        rows = self._fetch([position])
        if not rows:
            return False
        try:
            return int(rows[0]["data"].get("engagement_score", 0) or 0) >= min_score
        except (TypeError, ValueError):
            return False

    def _sql_ready(self, groups):
        """Годится ли быстрый путь через SQL для этого набора групп.

        Не годится, когда база не открылась или запись сломалась на середине:
        тогда часть строк живёт в ОЗУ, и SQL знает не про всю выборку. Считать
        по половине хуже, чем считать медленно.
        """
        if self._conn is None or not self._writes_ok or self._memory_rows:
            return False
        return bool([name for name in groups if name in self._index])

    def _sql_groups(self, groups):
        return [name for name in groups if name in self._index]

    def page(self, groups, page=1, size=100, min_score=0):
        """Строки одной страницы.

        Перебор обрывается, как только страница набрана: именно это и делает
        стоимость показа независимой от размера базы.
        """
        page = max(1, int(page or 1))
        size = max(1, int(size or 1))
        start = (page - 1) * size
        with self._lock:
            if min_score > 0 and self._sql_ready(groups):
                self._flush_locked()
                names = self._sql_groups(groups)
                marks = ",".join("?" * len(names))
                try:
                    cursor = self._conn.execute(
                        f"SELECT pos FROM rows WHERE grp IN ({marks}) AND score >= ? "
                        f"ORDER BY pos LIMIT ? OFFSET ?",
                        names + [int(min_score), size, start])
                    chosen = [row[0] for row in cursor]
                    return self._fetch(chosen)
                except Exception:
                    pass          # молча падаем на медленный, но верный путь
            if min_score > 0:
                # Запасной путь без БД: позиции отбираются по одной, потому что
                # скор лежит внутри строки. Перебор обрывается по набору
                # страницы, поэтому стоит он размера страницы, а не базы.
                chosen = []
                for position in self._selected(groups):
                    if not self._passes_score(position, min_score):
                        continue
                    chosen.append(position)
                    if len(chosen) >= start + size:
                        break
                chosen = chosen[start:start + size]
            else:
                chosen = list(itertools.islice(self._selected(groups),
                                               start, start + size))
            return self._fetch(chosen)

    def matching_count(self, groups, min_score=0):
        """Сколько строк проходит фильтр.

        Без порога по скору ответ берётся из счётчиков и не стоит ничего.
        С порогом перебор неизбежен — зато он нужен только для номера
        последней страницы, а не на каждом тике.
        """
        with self._lock:
            if min_score <= 0:
                return sum(self._counts[name] for name in groups if name in self._counts)
            if self._sql_ready(groups):
                self._flush_locked()
                names = self._sql_groups(groups)
                marks = ",".join("?" * len(names))
                try:
                    cursor = self._conn.execute(
                        f"SELECT COUNT(*) FROM rows "
                        f"WHERE grp IN ({marks}) AND score >= ?",
                        names + [int(min_score)])
                    row = cursor.fetchone()
                    if row is not None:
                        return int(row[0])
                except Exception:
                    pass          # молча падаем на медленный, но верный путь
            total = 0
            for position in self._selected(groups):
                if self._passes_score(position, min_score):
                    total += 1
            return total

    # Сколько строк доставать за один запрос при потоковом чтении. Порция
    # нужна, чтобы экспорт гигантской базы не собирал её целиком в память.
    STREAM_BATCH = 1000

    def iter_matching(self, groups, min_score=0):
        """Все подходящие строки — для экспорта, где нужна вся выборка.

        Генератор, а не список: на большой базе выборка в память не влезет, и
        экспорт обязан идти порциями. Позиции снимаются одним снимком под
        локом, чтобы приходящие во время выгрузки результаты не сдвигали
        нумерацию на середине.
        """
        with self._lock:
            positions = list(self._selected(groups))
        for start in range(0, len(positions), self.STREAM_BATCH):
            batch = positions[start:start + self.STREAM_BATCH]
            with self._lock:
                rows = self._fetch(batch)
            for row in rows:
                if min_score > 0:
                    try:
                        score = int(row["data"].get("engagement_score", 0) or 0)
                    except (TypeError, ValueError):
                        continue
                    if score < min_score:
                        continue
                yield row

    def all_rows(self):
        """Вся база строк списком. Только для маленьких выборок и тестов."""
        with self._lock:
            positions = list(range(self._total))
            return self._fetch(positions)


def _loads(blob):
    try:
        value = json.loads(blob) if blob else {}
    except Exception:
        return {}
    return value if isinstance(value, dict) else {}
