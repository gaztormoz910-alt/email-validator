import re

_SWAPS = (
    ("shch", "sch"), ("shch", "sh"), ("sch", "sh"),
    ("zh", "j"), ("kh", "h"), ("ts", "c"), ("ch", "tch"),
    ("yu", "ju"), ("yu", "iu"), ("ya", "ja"), ("ya", "ia"),
    ("yo", "e"), ("ye", "e"), ("jo", "yo"),
    ("ks", "x"), ("ov", "off"), ("ev", "eff"),
    ("ii", "iy"), ("iy", "y"), ("iy", "i"), ("yi", "y"),
    ("ay", "ai"), ("ey", "ei"), ("oy", "oi"), ("uy", "ui"),
)

_TAIL_SWAPS = (("iy", "y"), ("iy", "i"), ("ij", "y"), ("yj", "y"),
               ("y", "i"), ("i", "y"))

_LATIN_RE = re.compile(r"^[a-z]+$")

MAX_VARIANTS = 24


def looks_translit(word: str) -> bool:
    if not isinstance(word, str) or not word:
        return False
    return bool(_LATIN_RE.match(word.lower()))


def variants(word: str, limit: int = MAX_VARIANTS) -> list:
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

    for left, right in _SWAPS:
        for src, dst in ((left, right), (right, left)):
            if src in base:
                add(base.replace(src, dst))
        if len(seen) >= limit:
            return seen[:limit]

    for src, dst in _TAIL_SWAPS:
        if base.endswith(src):
            add(base[: -len(src)] + dst)

    for candidate in list(seen):
        for src, dst in _TAIL_SWAPS:
            if candidate.endswith(src):
                add(candidate[: -len(src)] + dst)
        if len(seen) >= limit:
            break

    return seen[:limit]
