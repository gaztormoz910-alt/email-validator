import os
import threading

_INDEX_PATH = os.path.join(os.path.dirname(__file__), "names_by_country.txt")

_index = None
_lock = threading.Lock()


def _load():
    global _index
    if _index is not None:
        return _index
    with _lock:
        if _index is not None:
            return _index
        data = {}
        try:
            with open(_INDEX_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    name, _, countries = line.partition("\t")
                    name = name.strip().lower()
                    if not name:
                        continue
                    data[name] = tuple(c for c in countries.split(",") if c)
        except Exception:
            data = {}
        _index = data
        return _index


def is_known_name(word: str) -> bool:
    if not isinstance(word, str) or not word:
        return False
    return word.strip().lower() in _load()


def countries_for(word: str) -> tuple:
    if not isinstance(word, str) or not word:
        return ()
    return _load().get(word.strip().lower(), ())


def sole_country(word: str):
    countries = countries_for(word)
    return countries[0] if len(countries) == 1 else None


def size() -> int:
    return len(_load())
