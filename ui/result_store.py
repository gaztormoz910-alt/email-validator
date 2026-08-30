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
    """Группа фильтра для отображаемого статуса.

    Группы отвечают на вопрос «что с этим адресом ДЕЛАТЬ», а не «как он
    называется»:

      valid    — доказано, что ящик есть: слать можно
      invalid  — доказано, что ящика нет: слать нельзя никогда
      spam     — ящик, может, и есть, но письмо туда портит репутацию:
                 одноразовые домены, ловушки, ролевые ящики (info@, admin@)
      unknown  — вердикта НЕТ. Ни доказательства, ни опровержения

    Risky живёт в `unknown`, и это не мелочь. Раньше он попадал в `spam`, и
    карточка «Спам / Ловушки» показывала 58 при шести настоящих ловушках:
    остальные пятьдесят два были адреса, которые просто не успели ответить.
    Владелец смотрел на это число, решая, кому слать, — а оно означало совсем
    не то, что написано на карточке.

    Risky и Unknown отличаются лишь тем, НАСКОЛЬКО не доказано, и для решения
    о рассылке это одно и то же: доказательства нет.
    """
    if status == "Valid":
        return "valid"
    if isinstance(status, str) and "Invalid" in status:
        return "invalid"
    if status == "Role-based":
        return "spam"
    if isinstance(status, str) and ("Trap" in status or "Disposable" in status):
        return "spam"
    if status in ("Unknown", "Risky"):
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

def _provider_of(email):
    """Домен адреса в нижнем регистре — он же почтовик для фильтра.

    Берётся домен, а не красивое имя из обогащения: имя есть не у каждой
    строки, а домен есть всегда, и владелец просил фильтр именно доменами —
    «@gmail.com, @yahoo.com, @aol.com».
    """
    if not isinstance(email, str) or "@" not in email:
        return ""
    return email.rpartition("@")[2].strip().lower()


def _facet_of(payload, key):
    """Значение грани строкой. Пустое и мусорное — пустая строка.

    Пустая строка, а не NULL: по ней можно и отфильтровать («без страны»), и
    сгруппировать, не разводя два разных вида «ничего».
    """
    if not isinstance(payload, dict):
        return ""
    value = payload.get(key)
    if value is None:
        return ""
    text = str(value).strip()
    return text


# Сколько строк копится перед записью пачкой. Одиночный INSERT на каждый
# результат упирается в диск и становится узким местом сам по себе, а пачкой
# в пятьсот строк запись стоит примерно столько же, сколько одна.
FLUSH_EVERY = 500


# Порядок строк в таблице. Сначала качество по убыванию — сотня сверху, ноль
# внизу, — потом порядок поступления, чтобы одинаковые оценки не прыгали
# между перерисовками. Сортировка живёт в запросе, а не в странице: иначе она
# упорядочивала бы только видимую сотню строк.
ORDER_BY = "ORDER BY score DESC, pos ASC"


# Грани, по которым владелец отбирает строки помимо вердикта. Ключ здесь —
# имя колонки в таблице; оно же приезжает с страницы.
FACETS = ("country", "gender", "provider")


def normalize_filters(raw, groups=None, min_score=0):
    """Приводит запрос страницы к одному виду.

    Отдельная функция, потому что фильтр приходит из трёх мест (страница
    таблицы, счётчик совпадений, выгрузка) и разъезжается, если каждое
    разбирает его по-своему.
    """
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
        # Пустые значения не выкидываем: «без страны» — законный выбор.
        values[facet] = [str(v).strip() for v in picked if str(v).strip() != "" or v == ""]

    return {
        "groups": chosen,
        "min_score": score,
        "country": values["country"],
        "gender": values["gender"],
        "provider": [v.lower() for v in values["provider"]],
        "search": str(raw.get("search") or "").strip().lower(),
    }


def _filters_are_plain(filters):
    """Ничего, кроме групп, не выбрано — можно идти самым дешёвым путём."""
    return (not filters["min_score"] and not filters["search"]
            and not any(filters[facet] for facet in FACETS))


class ResultStore:
    """Потокобезопасное хранилище строк результата с индексами по группам.

    Содержимое строк — на диске, позиции — в памяти. Публичный интерфейс тот
    же, что был у чисто-оперативной версии, поэтому окно про подмену не знает.
    """

    def __init__(self, path=None, drop_repeats=False):
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
        # Ключи ещё не записанной пачки и ключи строк, живущих только в ОЗУ.
        # Отбрасывать ли повторный результат по уже показанному ящику.
        #
        # По умолчанию НЕТ, и это важно. Хранилище общего назначения не должно
        # молча глотать строки: тот, кто положил в него шесть записей, вправе
        # получить шесть. Тихое схлопывание превращает потерю данных в
        # «особенность», которую замечаешь через месяц.
        #
        # Окно включает его сознательно: там строка — это предложение
        # отправить письмо, и один ящик двумя строками означает двойную
        # отправку. Дедуп входа делает конвейер, это лишь пояс поверх
        # подтяжек — на случай, если результат придёт дважды по любой другой
        # причине.
        self._drop_repeats = bool(drop_repeats)
        # Нужны для проверки «этот ящик уже показан»: в БД такой поиск идёт по
        # индексу, а вот про несохранённую пачку она ещё не знает.
        self._pending_keys = set()
        self._memory_keys = set()

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
                       email_lc TEXT
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

            # Файл мог остаться от прежней версии — тогда колонок фасетов в
            # нём нет. Добавляем молча: упасть здесь значит потерять показ
            # результатов целиком ради колонки фильтра.
            for column in ("country", "gender", "provider", "email_lc"):
                try:
                    self._conn.execute("ALTER TABLE rows ADD COLUMN %s TEXT" % column)
                except sqlite3.OperationalError:
                    pass          # уже есть

            # Индексы парой (группа, грань), а не по одной грани. Группа есть
            # в КАЖДОМ запросе — и в отборе, и в сборе значений для списков
            # фильтра, — поэтому вести ей должна она. Замерено на двухстах
            # тысячах строк: по одиночным индексам сбор значений занимал
            # 3.5 с, потому что GROUP BY приходилось делать сортировкой уже
            # после отбора по группе. С парными — десятые доли.
            for name, column in (("rows_grp_country", "grp, country"),
                                 ("rows_grp_gender", "grp, gender"),
                                 ("rows_grp_provider", "grp, provider"),
                                 ("rows_email_lc", "email_lc")):
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS %s ON rows (%s)" % (name, column))
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

    def _already_shown(self, key):
        """Показан ли уже этот ящик. Вызывается под захваченным локом.

        Пояс поверх подтяжек. Дедуп входа делает конвейер, но если результат
        по одному адресу придёт дважды по любой другой причине, владелец
        увидит один ящик двумя строками — то есть предложение отправить
        письмо дважды. Жалоба на спам стоит дороже одного лишнего поиска по
        индексу.
        """
        if not self._drop_repeats or not key:
            return False
        if key in self._pending_keys or key in self._memory_keys:
            return True
        if self._conn is None:
            return False
        try:
            cursor = self._conn.execute(
                "SELECT 1 FROM rows WHERE email_lc = ? LIMIT 1", (key,))
            return cursor.fetchone() is not None
        except Exception:
            return False

    def append(self, email, status, reason, mx, data):
        """Добавляет строку и обновляет индексы. Возвращает её группу.

        Повторный результат по уже показанному ящику отбрасывается: возвращаем
        его прежнюю группу, но второй строки не создаём.
        """
        payload = data if isinstance(data, dict) else {}
        group = group_of(status)
        key = str(email or "").strip().lower()
        with self._lock:
            if self._already_shown(key):
                return group
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
                self._memory_keys.add(key)
                return group

            try:
                blob = json.dumps(payload, ensure_ascii=False, default=str)
            except Exception:
                blob = "{}"
            self._pending.append((
                position, email, status, reason, mx, blob,
                group, _score_of(payload),
                _facet_of(payload, "country"), _facet_of(payload, "gender"),
                _provider_of(email), key))
            self._pending_keys.add(key)
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
                "(pos, email, status, reason, mx, data, grp, score, "
                " country, gender, provider, email_lc) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", self._pending)
            self._conn.commit()
            self._pending.clear()
            # Записанное теперь найдётся в базе по индексу — держать ключи в
            # памяти больше незачем.
            self._pending_keys.clear()
        except Exception:
            # Запись сломалась на середине прогона. Соединение НЕ закрываем:
            # то, что уже легло на диск, читается по-прежнему, и терять его
            # незачем. Дальше новые строки копятся в памяти — она дороже, но
            # потерять показанные результаты хуже.
            for row in self._pending:
                position, email, status, reason, mx, blob = row[:6]
                self._memory_rows[position] = {
                    "email": email, "status": status, "reason": reason,
                    "mx": mx, "data": _loads(blob)}
                self._memory_keys.add(str(email or "").strip().lower())
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

    # --- отбор -----------------------------------------------------------

    def _where(self, filters):
        """Условие и параметры для SQL по разобранному фильтру."""
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
            # Поиск идёт по отдельной колонке, уже приведённой к нижнему
            # регистру, а не по LOWER(email): вызов функции в условии выключил
            # бы индекс. Проценты и подчёркивания в запросе экранируются —
            # иначе поиск «a_b» нашёл бы «axb».
            needle = filters["search"]
            needle = needle.replace('\\', '\\\\')
            needle = needle.replace("%", '\\%').replace("_", '\\_')
            # В SQLite обратный слэш ничего не экранирует сам по себе, поэтому
            # символ экранирования объявляется явно и записывается ОДИН раз:
            # ESCAPE '\\' задал бы escape-символом два слэша, и защита
            # процентов перестала бы работать.
            clauses.append("email_lc LIKE ? ESCAPE '\\'")
            params.append("%" + needle + "%")

        return " AND ".join(clauses), params

    def _matches(self, row, filters):
        """То же условие для запасного пути, когда база недоступна."""
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

        return True

    def page(self, groups=None, page=1, size=100, min_score=0, filters=None):
        """Строки одной страницы.

        Перебор обрывается, как только страница набрана: именно это и делает
        стоимость показа независимой от размера базы.
        """
        picked = normalize_filters(filters, groups, min_score)
        page = max(1, int(page or 1))
        size = max(1, int(size or 1))
        start = (page - 1) * size

        with self._lock:
            if _filters_are_plain(picked) and self._sql_ready(picked["groups"]):
                # Даже без фильтров идём через SQL: сортировка по качеству
                # обязана действовать на ВСЮ выборку, а не на ту сотню строк,
                # что попала на экран. Отсортировать страницу после выборки —
                # значит показать «лучшие из случайных ста», а владелец решает
                # по этому списку, кому слать.
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
                    pass          # молча падаем на медленный, но верный путь

            # Запасной путь без БД: строки достаются по одной, потому что
            # грани лежат внутри строки. Здесь перебор оборвать нельзя —
            # сортировка по качеству требует видеть всю выборку, иначе на
            # первой странице окажутся лучшие из первых ста, а не лучшие
            # вообще. Путь запасной и включается, только когда база не
            # открылась.
            chosen = []
            for position in self._selected(picked["groups"]):
                rows = self._fetch([position])
                if rows and self._matches(rows[0], picked):
                    chosen.append((-_score_of(rows[0].get("data")), position))
            chosen.sort()
            return self._fetch([pos for _score, pos in chosen[start:start + size]])

    def matching_count(self, groups=None, min_score=0, filters=None):
        """Сколько строк проходит фильтр.

        Без фильтров ответ берётся из счётчиков и не стоит ничего. С ними —
        одним запросом по индексу, а не перебором в питоне.
        """
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
                    pass          # молча падаем на медленный, но верный путь

            total = 0
            for position in self._selected(picked["groups"]):
                rows = self._fetch([position])
                if rows and self._matches(rows[0], picked):
                    total += 1
            return total

    def facet_values(self, groups=None, filters=None, limit=200):
        """Какие страны, полы и почтовики реально встретились в выборке.

        Списки берутся из базы, а не из справочника: показать пункт
        «Германия», когда немцев в базе нет, — значит предложить владельцу
        фильтр, который заведомо ничего не найдёт.

        Каждая грань считается БЕЗ учёта себя самой. Иначе, выбрав Германию,
        владелец увидел бы в списке стран одну Германию и не смог бы
        передумать, не сбросив фильтр.
        """
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
                    pass          # молча падаем на медленный, но верный путь

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

    # Сколько строк доставать за один запрос при потоковом чтении. Порция
    # нужна, чтобы экспорт гигантской базы не собирал её целиком в память.
    STREAM_BATCH = 1000

    def iter_matching(self, groups=None, min_score=0, filters=None):
        """Все подходящие строки — для экспорта, где нужна вся выборка.

        Генератор, а не список: на большой базе выборка в память не влезет, и
        экспорт обязан идти порциями. Позиции снимаются одним снимком под
        локом, чтобы приходящие во время выгрузки результаты не сдвигали
        нумерацию на середине.
        """
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
