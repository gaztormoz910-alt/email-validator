import io
import json
import os
import threading
from core.paths import data_path

SETTINGS_PATH = data_path("settings.json")

DEFAULTS = {
    "cache_path": "",

    "spamhaus_resolvers": [],

    "proxy_enough": 0,

    "verdict_fresh_days": 30,
}

_lock = threading.Lock()
_cache = None


def _read():
    try:
        with io.open(SETTINGS_PATH, encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def load(refresh=False):
    global _cache
    with _lock:
        if _cache is None or refresh:
            merged = dict(DEFAULTS)
            merged.update({k: v for k, v in _read().items() if k in DEFAULTS})
            _cache = merged
        return dict(_cache)


def get(name, default=None):
    if not isinstance(name, str):
        return default
    return load().get(name, DEFAULTS.get(name, default))


def save(values):
    global _cache
    if not isinstance(values, dict):
        return False
    keep = {k: v for k, v in values.items() if k in DEFAULTS}
    with _lock:
        merged = dict(DEFAULTS)
        merged.update(_read())
        merged.update(keep)
        try:
            directory = os.path.dirname(SETTINGS_PATH)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with io.open(SETTINGS_PATH, "w", encoding="utf-8") as handle:
                json.dump(merged, handle, ensure_ascii=False, indent=2)
        except OSError:
            return False
        _cache = merged
        return True


def cache_path():
    from core.cache import DEFAULT_CACHE_PATH

    chosen = str(get("cache_path") or "").strip()
    return chosen or DEFAULT_CACHE_PATH


def spamhaus_resolvers():
    value = get("spamhaus_resolvers") or []
    if isinstance(value, str):
        value = [value]
    return [str(v).strip() for v in value if str(v).strip()]
