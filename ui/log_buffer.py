import threading
from collections import deque


DEFAULT_CAPACITY = 2000


class LogBuffer:

    def __init__(self, capacity=DEFAULT_CAPACITY):
        self.capacity = max(1, int(capacity))
        self._lines = deque(maxlen=self.capacity)
        self._lock = threading.Lock()
        self._dropped = 0
        self._total = 0

    def put(self, text, tag="info"):
        with self._lock:
            if len(self._lines) == self.capacity:
                self._dropped += 1
            self._lines.append((text, tag))
            self._total += 1

    def drain(self, limit=None):
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

    def __init__(self, interval, clock=None):
        self.interval = float(interval)
        self._clock = clock or __import__("time").monotonic
        self._last = None
        self._lock = threading.Lock()

    def ready(self):
        now = self._clock()
        with self._lock:
            if self._last is None or (now - self._last) >= self.interval:
                self._last = now
                return True
            return False

