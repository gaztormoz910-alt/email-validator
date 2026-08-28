"""Словарь с потолком: кэш по домену, который не может съесть всю память.

Зачем понадобился. Проверка кэширует по ДОМЕНУ почти всё, что стоит дорого:
MX-записи, catch-all, здоровье DNS, PTR, DNSBL, возраст домена, живой сайт,
страну почтовика. На базе бесплатных почтовиков доменов десяток, и обычный
словарь там идеален. Но база, собранная дорками, — это корпоративные адреса,
и разных доменов в ней столько же, сколько строк.

Замерено: три структуры пайплайна (замки «один в полёте» плюс два кэша)
стоили 468 байт на домен, то есть 2.3 ГБ на пяти миллионах доменов. И это
без шести кэшей сетевого клиента. Прогон падал по памяти ровно на тех
объёмах, ради которых всё остальное делалось потоковым.

Что здесь сделано. При переполнении выбрасывается САМАЯ СТАРАЯ запись —
`OrderedDict.popitem(last=False)`, то есть настоящий LRU-порядок. Обращение
к записи двигает её в конец, поэтому домены, которые встречаются постоянно
(gmail.com в базе из гмейлов), из кэша не вылетают никогда, а одиночные
корпоративные домены вытесняются, как только перестают быть нужны.

Потеря записи ничем не грозит: это КЭШ, а не источник истины. Промах стоит
одного повторного запроса, переполнение памяти стоит всего прогона.
"""

import threading
from collections import OrderedDict

# Потолок по умолчанию. Двести тысяч доменов — это около сотни мегабайт на
# кэш в худшем случае и заведомо больше, чем число РАЗНЫХ доменов в любой
# нормальной базе: даже в собранной дорками базе на миллион адресов доменов
# обычно десятки тысяч.
DEFAULT_MAX_KEYS = 200_000

_MISSING = object()


class BoundedCache:
    """Потокобезопасный LRU-словарь с жёстким потолком по числу ключей.

    Интерфейс намеренно узкий — ровно то, чем пользуются вызывающие: проверка
    наличия, чтение, запись, длина. Всё под общим замком: кэши читают и пишут
    сотня рабочих потоков, а `OrderedDict.move_to_end` атомарным не является.
    """

    __slots__ = ("_data", "_lock", "max_keys", "evictions")

    def __init__(self, max_keys=DEFAULT_MAX_KEYS):
        try:
            max_keys = int(max_keys)
        except (TypeError, ValueError):
            max_keys = DEFAULT_MAX_KEYS
        # Ноль или отрицательное значение означало бы «кэш, который ничего не
        # хранит»: молча превратить его в такой — значит превратить каждый
        # промах в сетевой запрос и не сказать об этом никому.
        self.max_keys = max(1, max_keys)
        self._data = OrderedDict()
        self._lock = threading.Lock()
        # Сколько записей вытеснено. Нужно, чтобы можно было ИЗМЕРИТЬ, стоит
        # ли поднимать потолок, а не гадать.
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
