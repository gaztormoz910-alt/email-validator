import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

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
