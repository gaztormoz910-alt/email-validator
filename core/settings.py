# core/settings.py
"""Настройки, которые живут дольше одного прогона.

Зачем отдельный модуль. Есть три вещи, которые нельзя задать ползунком в
окне, потому что они относятся не к прогону, а к рабочему месту:

  * куда класть кэш вердиктов — чтобы две машины не проверяли одно и то же;
  * какой резолвер спрашивать про Spamhaus — публичные он не обслуживает;
  * адрес своего SOCKS5, если владелец поднял его на VPS.

Файл настроек необязателен: без него всё работает как раньше. Это важно —
настройка, без которой программа не запускается, называется не настройкой, а
обязательным шагом.
"""
import io
import json
import os
import threading

# Рядом с данными, а не в домашней папке: программу носят на флешке вместе с
# базами, и настройки логично держать там же.
SETTINGS_PATH = os.path.join("data", "settings.json")

DEFAULTS = {
    # Пустая строка = «где всегда». Положите сюда путь внутри синхронизируемой
    # папки (OneDrive, Dropbox, сетевой диск) — и вердикты, добытые на одной
    # машине, не придётся добывать заново на другой.
    "cache_path": "",

    # Свой резолвер для Spamhaus ZEN. Крупнейший чёрный список отклоняет
    # запросы с публичных резолверов (8.8.8.8, 1.1.1.1) и отвечает NXDOMAIN
    # даже на обязательную тестовую запись. Без своего резолвера зона просто
    # молчит, и половина репутационных сигналов теряется.
    #
    # Сюда идёт адрес рекурсивного резолвера: на том же VPS, где поднят
    # прокси, либо любой непубличный, который согласится обслуживать зону.
    "spamhaus_resolvers": [],

    # Сколько живых прокси достаточно, чтобы перестать перебирать остальные.
    #
    # Ноль — проверять весь список, и это по умолчанию: чем шире ротация, тем
    # реже каждый выходной адрес попадается почтовику на глаза. Но у
    # бесплатных списков цена перебора несоразмерна результату: двадцать шесть
    # тысяч адресов при трёхстах потоках и таймауте в пятнадцать секунд — это
    # больше двадцати минут ДО ПЕРВОЙ ПРОВЕРЕННОЙ ПОЧТЫ, а живыми окажутся
    # полсотни. Поставив сюда, скажем, 200, владелец говорит «мне хватит».
    #
    # Само собой это не включается: сколько прокси держать в ротации — его
    # решение, а не моё.
    "proxy_enough": 0,

    # Сколько дней вердикт считается свежим. По истечении срока адрес в
    # таблице помечается как требующий перепроверки: ящик могли удалить.
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
    """Настройки словарём. Отсутствие файла — не ошибка, а обычный случай."""
    global _cache
    with _lock:
        if _cache is None or refresh:
            merged = dict(DEFAULTS)
            merged.update({k: v for k, v in _read().items() if k in DEFAULTS})
            _cache = merged
        return dict(_cache)


def get(name, default=None):
    # Имя настройки может прийти откуда угодно, вплоть до разобранного
    # запроса страницы. Список или словарь в роли ключа роняет поиск по
    # словарю, а падение в чтении настроек останавливает запуск.
    if not isinstance(name, str):
        return default
    return load().get(name, DEFAULTS.get(name, default))


def save(values):
    """Пишет настройки. Возвращает True, если получилось.

    Неудача записи не должна ронять программу: настройки — удобство, а не
    условие работы.
    """
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
    """Куда класть кэш вердиктов. Пусто в настройках — путь по умолчанию."""
    from core.cache import DEFAULT_CACHE_PATH

    chosen = str(get("cache_path") or "").strip()
    return chosen or DEFAULT_CACHE_PATH


def spamhaus_resolvers():
    """Адреса резолверов для Spamhaus. Пустой список = зона не опрашивается."""
    value = get("spamhaus_resolvers") or []
    if isinstance(value, str):
        value = [value]
    return [str(v).strip() for v in value if str(v).strip()]
