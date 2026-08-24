# core/parser/names_index.py
"""Локальный индекс популярных имён по странам.

Файл собирается скриптом tools/build_name_index.py из базы names_dataset и
даёт две вещи, которых у неё самой нет в удобном виде:

  * быстрый ответ «это вообще имя?» без обращения к базе на 138 млн записей;
  * узкий страновой сигнал: имя, входящее в топ ровно ОДНОЙ страны, эту
    страну и означает. Глобальное распределение для этого не годится — там
    Ivan получается итальянцем, потому что доли размазаны по десятку стран.

Индекс лежит рядом с модулем, а НЕ в data/: SpamFilter грузит оттуда все .txt
подряд, и 43 тысячи имён уехали бы в чёрный список доменов.
"""

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
    """True, если имя есть в индексе. Быстрый путь перед тяжёлым поиском."""
    if not isinstance(word, str) or not word:
        return False
    return word.strip().lower() in _load()


def countries_for(word: str) -> tuple:
    """Страны, в топе которых встречается имя. Пустой кортеж — не знаем."""
    if not isinstance(word, str) or not word:
        return ()
    return _load().get(word.strip().lower(), ())


def sole_country(word: str):
    """Код страны, если имя популярно РОВНО в одной стране, иначе None.

    Намеренно строго. Ivan входит в топ доброго десятка стран и ответа не
    даёт — и это правильно, лучше пусто, чем «Италия».
    """
    countries = countries_for(word)
    return countries[0] if len(countries) == 1 else None


def size() -> int:
    return len(_load())
