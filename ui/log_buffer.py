# ui/log_buffer.py
"""Ограниченный буфер строк терминала.

Зачем. Раньше КАЖДЫЙ проверенный адрес порождал строку в терминале, и каждая
строка отдельно вставлялась в текстовое поле Tk: `insert`, пересчёт числа
строк, `see("end")`, переключение состояния виджета — и так сто тысяч раз.
Само поле при этом обрезалось до тысячи строк, то есть 99% работы делалось
ради текста, который тут же выбрасывался.

Здесь строки копятся в очереди с ЖЁСТКИМ потолком: при переполнении самые
старые выбрасываются сразу, ещё до Tk. Интерфейс забирает накопленное пачкой
и вставляет одним вызовом на тик.

Отдельно считается, сколько строк было отброшено, — молча терять лог нельзя,
иначе по терминалу нельзя судить о прогоне.
"""

import threading
from collections import deque


DEFAULT_CAPACITY = 2000


class LogBuffer:
    """Очередь строк лога с потолком и счётчиком потерь."""

    def __init__(self, capacity=DEFAULT_CAPACITY):
        self.capacity = max(1, int(capacity))
        self._lines = deque(maxlen=self.capacity)
        self._lock = threading.Lock()
        self._dropped = 0
        self._total = 0

    def put(self, text, tag="info"):
        with self._lock:
            # deque с maxlen вытесняет молча — считаем потери сами, иначе
            # пропажу строк невозможно заметить.
            if len(self._lines) == self.capacity:
                self._dropped += 1
            self._lines.append((text, tag))
            self._total += 1

    def drain(self, limit=None):
        """Забирает накопленное. limit ограничивает объём одного тика."""
        with self._lock:
            if limit is None or limit >= len(self._lines):
                chunk = list(self._lines)
                self._lines.clear()
                return chunk
            chunk = [self._lines.popleft() for _ in range(max(0, int(limit)))]
            return chunk

    @property
    def dropped(self):
        with self._lock:
            return self._dropped

    @property
    def total(self):
        with self._lock:
            return self._total

    def __len__(self):
        with self._lock:
            return len(self._lines)


class Throttle:
    """Пропускает событие не чаще, чем раз в interval секунд.

    Нужен там, где источник событий быстрее глаза: счётчики, прогресс и
    перерисовка таблицы. Раньше таблица перерисовывалась на каждом тике
    опроса очередей — двадцать раз в секунду, независимо от того, изменилось
    ли что-нибудь на видимой странице.
    """

    def __init__(self, interval, clock=None):
        self.interval = float(interval)
        self._clock = clock or __import__("time").monotonic
        self._last = None
        self._lock = threading.Lock()

    def ready(self):
        """True, если с прошлого пропуска прошло достаточно времени."""
        now = self._clock()
        with self._lock:
            if self._last is None or (now - self._last) >= self.interval:
                self._last = now
                return True
            return False

