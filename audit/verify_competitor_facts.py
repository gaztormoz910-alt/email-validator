#!/usr/bin/env python
"""Оракул для гейтов сравнения: перекачивает страницы конкурента и ищет в них факты.

Зачем именно так. Сравнение легко написать по памяти и по общим словам — и
проверить такое нечем. Здесь каждый факт привязан к дословному куску текста
страницы. Скрипт качает страницу заново и ищет этот кусок. Выдуманный факт
или устаревшее утверждение отсюда не пройдут.

Чего оракул НЕ доказывает: что факт истолкован верно. Он доказывает лишь, что
такой текст на странице действительно есть.

Требует сети. Если сеть недоступна, гейт обязан краснеть, а не «проходить по
умолчанию»: недоступность источника — это не подтверждение факта.

Успех печатает FACTS OK: <N>/<N> и выходит с нулём.
"""

import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

HEADERS = {"User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 (KHTML, like Gecko) "
                          "Chrome/120.0 Safari/537.36")}


def page_text(url):
    """Видимый текст страницы одной строкой."""
    import requests
    resp = requests.get(url, timeout=25, headers=HEADERS)
    resp.raise_for_status()
    # У обеих страниц charset в заголовке не проставлен, а содержимое в UTF-8.
    # Без явной установки requests декодирует их как latin-1, и весь русский
    # текст превращается в мусор — искать в нём было бы нечего.
    resp.encoding = "utf-8"
    html = re.sub(r"(?is)<(script|style)[^>]*>.*?</\1>", " ", resp.text)
    return re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", html))


def normalize(value):
    """Схлопывает пробелы и разные виды дефисов и кавычек."""
    value = re.sub(r"[‐-―−]", "-", value)
    value = re.sub(r"[«»“”‘’]", '"', value)
    return re.sub(r"\s+", " ", value).strip().lower()


def main():
    data = json.load(open(os.path.join(ROOT, "audit", "competitor_facts.json"),
                          encoding="utf-8"))
    failures = []
    checked = 0

    for source in data["sources"]:
        url = source["url"]
        try:
            text = normalize(page_text(url))
        except Exception as exc:
            failures.append(f"{url}: страница не прочитана ({type(exc).__name__}) — "
                            "факты с неё не подтверждены")
            failures.extend(f"{url} :: {f['claim']}" for f in source["facts"])
            checked += len(source["facts"])
            continue

        # Негативный контроль: если бы поиск «находил» что угодно, все проверки
        # ниже были бы бессмысленны. Заведомо отсутствующая строка обязана
        # не находиться.
        if normalize("заведомо отсутствующая строка zzqq7788") in text:
            failures.append(f"{url}: поиск находит заведомо отсутствующий текст — "
                            "оракул сломан, его зелёный цвет ничего не значит")

        for fact in source["facts"]:
            checked += 1
            if normalize(fact["anchor"]) not in text:
                failures.append(f"{url} :: {fact['claim']}\n"
                                f"      не найдено на странице: {fact['anchor']!r}")

    if failures:
        print(f"FACTS MISMATCH ({len(failures)} из {checked})")
        for line in failures:
            print("  - " + line)
        return 1
    print(f"FACTS OK: {checked}/{checked}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
