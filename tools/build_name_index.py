# tools/build_name_index.py
"""Собирает локальный индекс имён по странам из базы names_dataset.

Зачем это нужно отдельным файлом, а не запросом на лету:

  1. Скорость. `NameDataset.search()` работает по базе на 138 миллионов
     записей, и на каждый адрес это заметно. Локальный набор из ~43 тысяч
     популярных имён отвечает мгновенно и снимает основную часть нагрузки.

  2. Регион вместо глобального шума. Глобальное распределение имени по
     странам размазано — именно из-за него Ivan получался итальянцем. А вот
     факт «имя входит в топ-1000 ровно одной страны» — сигнал узкий и честный.

  3. Замена мёртвого файла. В core/parser/names.txt лежало 4945 имён,
     на которые в коде не было ни одной ссылки.

Запуск (нужен установленный names_dataset):

    python tools/build_name_index.py
"""

import os
import sys

# Без этого скрипт падает в консоли cp1252 на первом же русском символе
# и работает только там, где вручную выставлен PYTHONIOENCODING.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# Страны, ради которых всё затевается: рынки EU, US и СНГ плюс крупные азиатские.
COUNTRIES = [
    "US", "GB", "DE", "FR", "IT", "ES", "NL", "BE", "PL", "CZ", "SK", "HU",
    "RO", "BG", "GR", "PT", "SE", "NO", "DK", "FI", "AT", "CH", "IE", "RU",
    "UA", "BY", "KZ", "TR", "IL", "IN", "CN", "JP", "KR", "BR", "MX", "AR",
    "CA", "AU", "NZ", "ZA",
]

TOP_PER_COUNTRY = 1000
OUTPUT = os.path.join("core", "parser", "names_by_country.txt")


def build():
    try:
        from names_dataset import NameDataset
    except ImportError:
        print("Нужен пакет names-dataset: pip install names-dataset")
        return 1

    print("Загружаю базу имён (это долго, порядка 10 секунд)...")
    nd = NameDataset()

    by_name = {}
    for code in COUNTRIES:
        try:
            top = nd.get_top_names(n=TOP_PER_COUNTRY, country_alpha2=code)
        except Exception as exc:
            print(f"  {code}: пропущено ({type(exc).__name__})")
            continue
        collected = set()
        for gender_map in top.values():
            for values in gender_map.values():
                collected.update(v.strip().lower() for v in values if v and v.strip())
        for name in collected:
            by_name.setdefault(name, set()).add(code)
        print(f"  {code}: {len(collected)}")

    if not by_name:
        print("Ничего не собралось — файл не трогаю.")
        return 1

    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    tmp = OUTPUT + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("# имя<TAB>страны, где имя входит в топ-%d\n" % TOP_PER_COUNTRY)
        f.write("# Собрано tools/build_name_index.py из names_dataset\n")
        for name in sorted(by_name):
            f.write(f"{name}\t{','.join(sorted(by_name[name]))}\n")
    os.replace(tmp, OUTPUT)

    print(f"\nГотово: {len(by_name)} имён -> {OUTPUT}")
    return 0


if __name__ == "__main__":
    sys.exit(build())
