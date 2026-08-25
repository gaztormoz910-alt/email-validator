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

Фильтр по скору перебор всё же требует, но и он обрывается по набору страницы,
а не проходит базу до конца.

Само хранилище про Tk ничего не знает — поэтому его можно измерить тестом
без окна.
"""

import heapq
import itertools
import threading


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


class ResultStore:
    """Потокобезопасное хранилище строк результата с индексами по группам."""

    def __init__(self):
        self._lock = threading.RLock()
        self._rows = []
        self._index = {name: [] for name in GROUPS}
        self._counts = {name: 0 for name in GROUPS}
        self._names = 0

    # --- запись ---------------------------------------------------------

    def append(self, email, status, reason, mx, data):
        """Добавляет строку и обновляет индексы. Возвращает её группу."""
        row = {"email": email, "status": status, "reason": reason,
               "mx": mx, "data": data if isinstance(data, dict) else {}}
        group = group_of(status)
        with self._lock:
            position = len(self._rows)
            self._rows.append(row)
            self._index[group].append(position)
            self._counts[group] += 1
            if row["data"].get("name"):
                self._names += 1
        return group

    def clear(self):
        with self._lock:
            self._rows.clear()
            for name in GROUPS:
                self._index[name].clear()
                self._counts[name] = 0
            self._names = 0

    # --- чтение ---------------------------------------------------------

    def __len__(self):
        with self._lock:
            return len(self._rows)

    def counts(self):
        """Готовые счётчики по группам — без перебора строк."""
        with self._lock:
            snapshot = dict(self._counts)
            snapshot["names"] = self._names
            snapshot["total"] = len(self._rows)
            return snapshot

    def _selected(self, groups):
        """Ленивое слияние индексов выбранных групп в порядке добавления."""
        lists = [self._index[name] for name in groups if name in self._index]
        if not lists:
            return iter(())
        if len(lists) == 1:
            return iter(lists[0])
        return heapq.merge(*lists)

    def _passes_score(self, position, min_score):
        if min_score <= 0:
            return True
        try:
            return int(self._rows[position]["data"].get("engagement_score", 0) or 0) >= min_score
        except (TypeError, ValueError):
            return False

    def page(self, groups, page=1, size=100, min_score=0):
        """Строки одной страницы.

        Перебор обрывается, как только страница набрана: именно это и делает
        стоимость показа независимой от размера базы.
        """
        page = max(1, int(page or 1))
        size = max(1, int(size or 1))
        start = (page - 1) * size
        with self._lock:
            stream = self._selected(groups)
            if min_score > 0:
                stream = (p for p in stream if self._passes_score(p, min_score))
            chosen = list(itertools.islice(stream, start, start + size))
            return [self._rows[p] for p in chosen]

    def matching_count(self, groups, min_score=0):
        """Сколько строк проходит фильтр.

        Без порога по скору ответ берётся из счётчиков и не стоит ничего.
        С порогом перебор неизбежен — зато он нужен только для номера
        последней страницы, а не на каждом тике.
        """
        with self._lock:
            if min_score <= 0:
                return sum(self._counts[name] for name in groups if name in self._counts)
            return sum(1 for p in self._selected(groups)
                       if self._passes_score(p, min_score))

    def iter_matching(self, groups, min_score=0):
        """Все подходящие строки — для экспорта, где нужна вся выборка."""
        with self._lock:
            positions = list(self._selected(groups))
        for position in positions:
            with self._lock:
                if not self._passes_score(position, min_score):
                    continue
                yield self._rows[position]

    def all_rows(self):
        with self._lock:
            return list(self._rows)
