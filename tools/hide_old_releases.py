# -*- coding: utf-8 -*-
"""Прячет прежние релизы в черновики: на странице релизов остаётся одна версия.

ЗАЧЕМ. Решение владельца 30.09.2026: посторонние видят только последнюю
версию программы. Прежние не удаляются, а становятся черновиками — их видит
только владелец, и любой возвращается кнопкой «Publish release» на странице
черновика. Удаление было бы необратимым; черновик — нет. Заодно из открытого
доступа уходят установщики старых версий, собранные до чистки истории.

КОГДА. Шагом release.yml, ПОСЛЕ публикации нового релиза:

    python3 tools/hide_old_releases.py --keep v1.3.7 --apply

Без --apply только печатает план и ничего не меняет — так его можно
проверить на машине разработчика без токена (без токена GitHub показывает
только опубликованные релизы, этого для плана достаточно). Токен берётся из
GITHUB_TOKEN, репозиторий — из GITHUB_REPOSITORY.

ГЛАВНАЯ ЗАЩИТА. Худший исход — спрятать всё, включая новый релиз: страница
осталась бы пустой, и скачать программу было бы неоткуда. Поэтому ничего не
трогается, пока новый релиз не виден среди ОПУБЛИКОВАННЫХ (GitHub показывает
только что созданный релиз не мгновенно — несколько попыток с паузой), а
после скрытия проверяется, что опубликован ровно он один и он же «Latest».
"""
import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

API = "https://api.github.com"
РЕПОЗИТОРИЙ = "gaztormoz910-alt/email-validator"
ПОПЫТОК_НАЙТИ_НОВЫЙ = 6
ПАУЗА_С = 10


class Отказ(Exception):
    """План невыполним — не трогать ничего."""


def запрос(метод, путь, токен=None, тело=None):
    заголовки = {"Accept": "application/vnd.github+json",
                 "User-Agent": "mailfact-hide-old-releases",
                 "X-GitHub-Api-Version": "2022-11-28"}
    if токен:
        заголовки["Authorization"] = "Bearer " + токен
    данные = None
    if тело is not None:
        данные = json.dumps(тело).encode("utf-8")
        заголовки["Content-Type"] = "application/json"
    r = urllib.request.Request(API + путь, data=данные, headers=заголовки, method=метод)
    with urllib.request.urlopen(r, timeout=60) as ответ:
        сырое = ответ.read()
    return json.loads(сырое) if сырое else None


def все_релизы(репо, токен=None, получить=None):
    получить = получить or запрос
    релизы, страница = [], 1
    while True:
        часть = получить("GET", "/repos/%s/releases?per_page=100&page=%d" % (репо, страница), токен)
        релизы.extend(часть or [])
        if not часть or len(часть) < 100:
            return релизы
        страница += 1


def версия(тег):
    """(1, 3, 7) из «v1.3.7»; None, если тег не похож на номер версии."""
    м = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", тег or "")
    return tuple(int(ч) for ч in м.groups()) if м else None


def план(релизы, оставить):
    """Какие релизы спрятать. Бросает Отказ, если оставляемый не опубликован.

    Прячется всё опубликованное, кроме оставляемого, — и предварительные
    выпуски тоже: на странице должна быть одна версия. Черновики не трогаются.
    """
    своя = версия(оставить)
    if своя is None:
        raise Отказ("«%s» не похож на номер версии — ничего не трогаю" % оставить)
    # Повторный запуск сборки СТАРОГО тега не должен прятать новую версию:
    # оставляемый обязан быть старшим среди всех релизов, черновики тоже
    # считаются (спрятанная новая версия — всё равно новая).
    новее = [р.get("tag_name") for р in релизы if (версия(р.get("tag_name")) or ()) > своя]
    if новее:
        raise Отказ("есть релизы новее %s: %s — прятать новое ради старого не буду"
                    % (оставить, ", ".join(новее)))
    опубликованные = [р for р in релизы if not р.get("draft")]
    if not any(р.get("tag_name") == оставить for р in опубликованные):
        raise Отказ("релиз %s не найден среди опубликованных — ничего не трогаю" % оставить)
    return [р for р in опубликованные if р.get("tag_name") != оставить]


def выполнить(репо, оставить, применить, токен=None, получить=None, спать=time.sleep):
    # Функция запроса ищется при вызове, а не при определении: иначе подмена
    # модуля в тестах не доходила бы сюда, и тест ушёл бы в настоящий API.
    получить = получить or запрос
    for попытка in range(ПОПЫТОК_НАЙТИ_НОВЫЙ):
        try:
            спрятать = план(все_релизы(репо, токен, получить), оставить)
            break
        except Отказ:
            if попытка == ПОПЫТОК_НАЙТИ_НОВЫЙ - 1:
                raise
            спать(ПАУЗА_С)
    print("оставить опубликованным: %s" % оставить)
    print("спрятать в черновики (%d): %s" % (len(спрятать), ", ".join(р["tag_name"] for р in спрятать) or "—"))
    if not применить:
        print("режим плана: ничего не изменено (для изменений нужен --apply)")
        return 0
    if not токен:
        raise Отказ("для --apply нужен GITHUB_TOKEN")
    for р in спрятать:
        получить("PATCH", "/repos/%s/releases/%d" % (репо, р["id"]), токен, {"draft": True})
        print("  спрятан %s" % р["tag_name"])
    # Проверка итога тем же API: опубликован ровно оставляемый, и он «Latest».
    осталось = sorted(р["tag_name"] for р in все_релизы(репо, токен, получить) if not р.get("draft"))
    последний = (получить("GET", "/repos/%s/releases/latest" % репо, токен) or {}).get("tag_name")
    print("опубликовано после: %s; Latest: %s" % (осталось, последний))
    if осталось != [оставить] or последний != оставить:
        raise Отказ("после скрытия опубликовано %s, Latest %s — ожидался один %s"
                    % (осталось, последний, оставить))
    print("HIDE_OLD_RELEASES_OK")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--keep", required=True, help="тег релиза, который остаётся опубликованным")
    p.add_argument("--apply", action="store_true", help="на самом деле спрятать (иначе только план)")
    args = p.parse_args(argv)
    репо = os.environ.get("GITHUB_REPOSITORY") or РЕПОЗИТОРИЙ
    токен = os.environ.get("GITHUB_TOKEN") or None
    try:
        return выполнить(репо, args.keep, args.apply, токен)
    except (Отказ, urllib.error.URLError) as беда:
        print("ОТКАЗ: %s" % беда)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
