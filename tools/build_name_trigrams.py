# -*- coding: utf-8 -*-
"""Собирает core/parser/name_trigrams.txt — «на что похожи имена».

ЗАЧЕМ. Разбору имени из адреса нужен ответ на вопрос «похоже ли это
буквосочетание на имя или фамилию», когда база куска не знает: фамилий,
которых в ней нет, много (Pucelli, Limanec), и отвергать всё неизвестное
нельзя; но и «hallbgi», «gnitc», «honmmaop» фамилиями не бывают. Перечень
«плохих» сочетаний руками не составить, поэтому признак берётся из самих
имён: тройки букв подряд (с метками начала «^» и конца «$»), которые
встречаются в известных именах и фамилиях. Кусок, в котором есть тройка,
не встретившаяся ни в одном имени, на имя не похож.

Источники: индекс популярных имён проекта (core/parser/names_by_country.txt)
и имена и фамилии базы names_dataset, у которых есть место в рейтинге хотя
бы одной страны. Данных владельца здесь нет.

    python tools/build_name_trigrams.py            # пересобрать файл
    python tools/build_name_trigrams.py --check    # сверить файл с пересборкой
"""
import collections
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "core", "parser", "name_trigrams.txt")
CLUSTERS = os.path.join(ROOT, "core", "parser", "name_clusters.txt")
INDEX = os.path.join(ROOT, "core", "parser", "names_by_country.txt")

# Тройка считается «встречается в именах», если её несут не меньше стольких
# разных слов: единичные — опечатки и ники, пролезшие в рейтинги.
#
# Порог и охват подобраны 13.11.2026 на словах из имён, которые разбор
# выдал на 27 753 настоящих адресах (9601 разное слово). Узкий набор
# (места до 3000, порог 10) отвергал 7,4% слов, и среди них настоящие
# имена других культур: Sapna, Jiaxuan, Seojun, Boatwright. Широкий (все
# места рейтингов, порог 5) отвергает 1,4% — почти сплошь обломки
# («tannn», «iitkgp», «lbfse», «woood»); настоящих среди них единицы
# (Kalbfleisch). Признак спрашивается только про куски, которых база не
# знает, так что известные имена и фамилии он не задевает вовсе.
MIN_WORDS = 5
WORD = re.compile(r"^[a-z]{3,20}$")


def trigrams(word):
    padded = "^" + word + "$"
    return [padded[i:i + 3] for i in range(len(padded) - 2)]


# Группы согласных — второй, более грубый признак: с какой группы имя
# начинается («^str»), какой кончается («rdt$») и какие группы от трёх букв
# стоят внутри («-ndr-»). Берутся только частые имена (места до
# CLUSTER_RANK): в дальних местах рейтингов сидят ники и опечатки. Признак
# строже троек и задевает настоящие редкие фамилии (Kalbfleisch), поэтому
# спрашивается только про куски между разделителями: там отвергнутый кусок
# просто не идёт в имя, а не ломает разбор соседних.
CLUSTER_RANK = 3000
CLUSTER_MIN = 3
_CONSONANTS = re.compile(r"[^aeiouy]+")


def clusters(word):
    found = []
    for m in _CONSONANTS.finditer(word):
        group = m.group()
        if m.start() == 0 and m.end() == len(word):
            continue
        if m.start() == 0:
            if len(group) >= 2:
                found.append("^" + group)
        elif m.end() == len(word):
            if len(group) >= 2:
                found.append(group + "$")
        elif len(group) >= 3:
            found.append("-" + group + "-")
    return found


def ranked_words(limit=None):
    found = set()
    with open(INDEX, encoding="utf-8") as f:
        for line in f:
            name = line.split("\t")[0].strip().lower()
            if WORD.match(name):
                found.add(name)
    from names_dataset import NameDataset
    nd = NameDataset()
    for table in (nd.first_names, nd.last_names):
        for name, info in table.items():
            ranks = [r for r in ((info or {}).get("rank") or {}).values() if r]
            if ranks and (limit is None or min(ranks) <= limit):
                low = name.lower()
                if WORD.match(low):
                    found.add(low)
    return found


def build():
    counts = collections.Counter()
    for word in ranked_words():
        counts.update(set(trigrams(word)))
    return sorted(t for t, n in counts.items() if n >= MIN_WORDS)


def build_clusters():
    counts = collections.Counter()
    for word in ranked_words(CLUSTER_RANK):
        counts.update(set(clusters(word)))
    return sorted(c for c, n in counts.items() if n >= CLUSTER_MIN)


def main():
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    made = ((OUT, build(), "троек"), (CLUSTERS, build_clusters(), "групп согласных"))
    for path, fresh, what in made:
        text = "\n".join(fresh) + "\n"
        if "--check" in sys.argv:
            current = open(path, encoding="utf-8").read() if os.path.exists(path) else ""
            if current != text:
                sys.exit("NAME-TRIGRAMS STALE: %s не совпадает с пересборкой"
                         % os.path.basename(path))
            continue
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print("записано %s: %d -> %s" % (what, len(fresh), os.path.relpath(path, ROOT)))
    if "--check" in sys.argv:
        print("NAME-TRIGRAMS-OK (%s)" % ", ".join("%d %s" % (len(f), w) for _, f, w in made))


if __name__ == "__main__":
    main()
