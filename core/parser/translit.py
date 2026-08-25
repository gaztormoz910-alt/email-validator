# core/parser/translit.py
"""Варианты латинского написания славянских имён.

Зачем. `dmitriy`, `dmitry`, `dmitri`, `dmitrii` — одно имя, но в базе имён они
лежат по-разному: часть написаний известна, часть нет. Из-за этого адрес
`dmitriy.k@yandex.ru` мог не пройти проверку «это вообще имя?», а по стране
дать пусто. Единого стандарта транслитерации нет — их несколько (ГОСТ,
загранпаспортный, бытовой), и люди пишут как привыкли.

Решение простое: не «привести к канону» (канона не существует), а
перебрать правдоподобные написания и взять первое, которое база знает.
"""

import re

# Взаимозаменяемые куски. Каждая пара порождает варианты в обе стороны.
# Порядок важен: длинные сочетания стоят раньше коротких, иначе `shch`
# распадётся на `sh` + `ch` и потеряется.
_SWAPS = (
    ("shch", "sch"), ("shch", "sh"), ("sch", "sh"),
    ("zh", "j"), ("kh", "h"), ("ts", "c"), ("ch", "tch"),
    ("yu", "ju"), ("yu", "iu"), ("ya", "ja"), ("ya", "ia"),
    ("yo", "e"), ("ye", "e"), ("jo", "yo"),
    ("ks", "x"), ("ov", "off"), ("ev", "eff"),
    ("ii", "iy"), ("iy", "y"), ("iy", "i"), ("yi", "y"),
    ("ay", "ai"), ("ey", "ei"), ("oy", "oi"), ("uy", "ui"),
)

# Окончания, которые часто просто отбрасывают или меняют
_TAIL_SWAPS = (("iy", "y"), ("iy", "i"), ("ij", "y"), ("yj", "y"),
               ("y", "i"), ("i", "y"))

_LATIN_RE = re.compile(r"^[a-z]+$")

MAX_VARIANTS = 24


def looks_translit(word: str) -> bool:
    """True, если слово похоже на латиницу без диакритики — только её и трогаем."""
    if not isinstance(word, str) or not word:
        return False
    return bool(_LATIN_RE.match(word.lower()))


def variants(word: str, limit: int = MAX_VARIANTS) -> list:
    """Правдоподобные написания имени, начиная с исходного.

    Не пытается угадать «правильное» — отдаёт список, по которому вызывающий
    код спрашивает базу имён, пока не найдётся известное написание.
    """
    if not isinstance(word, str):
        return []
    base = word.strip().lower()
    if not looks_translit(base) or len(base) < 3:
        return [base] if base else []

    seen = [base]
    known = {base}

    def add(candidate):
        if candidate and candidate not in known and len(candidate) >= 3:
            known.add(candidate)
            seen.append(candidate)

    # Замены внутри слова, в обе стороны
    for left, right in _SWAPS:
        for src, dst in ((left, right), (right, left)):
            if src in base:
                add(base.replace(src, dst))
        if len(seen) >= limit:
            return seen[:limit]

    # Замены окончаний — самый частый источник расхождений
    for src, dst in _TAIL_SWAPS:
        if base.endswith(src):
            add(base[: -len(src)] + dst)

    # Комбинация: замена внутри слова плюс замена окончания
    for candidate in list(seen):
        for src, dst in _TAIL_SWAPS:
            if candidate.endswith(src):
                add(candidate[: -len(src)] + dst)
        if len(seen) >= limit:
            break

    return seen[:limit]
