import threading
from collections import OrderedDict

DEFAULT_MAX_KEYS = 200_000

_MISSING = object()


class BoundedCache:

    __slots__ = ("_data", "_lock", "max_keys", "evictions")

    def __init__(self, max_keys=DEFAULT_MAX_KEYS):
        try:
            max_keys = int(max_keys)
        except (TypeError, ValueError):
            max_keys = DEFAULT_MAX_KEYS
        self.max_keys = max(1, max_keys)
        self._data = OrderedDict()
        self._lock = threading.Lock()
        self.evictions = 0

    def __contains__(self, key):
        with self._lock:
            return key in self._data

    def __len__(self):
        with self._lock:
            return len(self._data)

    def get(self, key, default=None):
        with self._lock:
            value = self._data.get(key, _MISSING)
            if value is _MISSING:
                return default
            self._data.move_to_end(key)
            return value

    def __getitem__(self, key):
        value = self.get(key, _MISSING)
        if value is _MISSING:
            raise KeyError(key)
        return value

    def __setitem__(self, key, value):
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
            self._data[key] = value
            while len(self._data) > self.max_keys:
                self._data.popitem(last=False)
                self.evictions += 1

    def setdefault(self, key, default=None):
        with self._lock:
            if key in self._data:
                self._data.move_to_end(key)
                return self._data[key]
            self._data[key] = default
            while len(self._data) > self.max_keys:
                self._data.popitem(last=False)
                self.evictions += 1
            return default

    def pop(self, key, default=None):
        with self._lock:
            return self._data.pop(key, default)

    def clear(self):
        with self._lock:
            self._data.clear()
            self.evictions = 0

    def keys(self):
        with self._lock:
            return list(self._data.keys())

    def items(self):
        with self._lock:
            return list(self._data.items())

    def values(self):
        with self._lock:
            return list(self._data.values())
