# -*- coding: utf-8 -*-
import html as _html
import re
import unicodedata
import urllib.parse

__all__ = ["strip_invisible", "fold_fullwidth", "to_nfc", "decode_wrappers",
           "strip_escape_residue", "strip_comments", "normalize_input",
           "split_addresses", "INVISIBLE"]

INVISIBLE = (
    "\u200b\u200c\u200d\u2060\ufeff"
    "\u200e\u200f"
    "\u202a\u202b\u202c\u202d\u202e"
    "\u2066\u2067\u2068\u2069"
    "\u00ad"
)
_НЕВИДИМЫЕ = {ord(з): None for з in INVISIBLE}

_СДВИГ = 0xFF01 - 0x21


def strip_invisible(text):
    if not isinstance(text, str):
        return text
    return text.translate(_НЕВИДИМЫЕ)


def fold_fullwidth(text):
    if not isinstance(text, str):
        return text
    вышло = []
    for знак in text:
        код = ord(знак)
        if 0xFF01 <= код <= 0xFF5E:
            вышло.append(chr(код - _СДВИГ))
        elif код == 0x3000:
            вышло.append(" ")
        else:
            вышло.append(знак)
    return "".join(вышло)


def to_nfc(text):
    if not isinstance(text, str):
        return text
    try:
        return unicodedata.normalize("NFC", text)
    except Exception:
        return text


_ПРОЦЕНТ = re.compile(r"%[0-9A-Fa-f]{2}")
_СУЩНОСТЬ = re.compile(r"&(#\d{2,5}|#x[0-9A-Fa-f]{2,4}|[a-zA-Z]{2,8});")


def decode_wrappers(text):
    if not isinstance(text, str) or "@" in text:
        return text

    for раскрыть, образец in ((urllib.parse.unquote, _ПРОЦЕНТ),
                              (_html.unescape, _СУЩНОСТЬ)):
        if not образец.search(text):
            continue
        try:
            вышло = раскрыть(text)
        except Exception:
            continue
        if вышло.count("@") == 1:
            return вышло
    return text


_ОСТАТКИ_ЭКРАНИРОВАНИЯ = (
    "u003c", "u003e", "u003d", "u0022", "u0027", "u0026",
    "u200b", "u200c", "u200d", "u200e", "u200f", "u202a", "u202c",
    "ufeff", "u00a0",
)


def strip_escape_residue(text):
    if not isinstance(text, str) or "@" not in text:
        return text
    вышло = text.lstrip()
    if вышло != text.strip():
        вышло = text
    снято = 0
    while снято < 4:
        низ = вышло.lower()
        для_снятия = next((о for о in _ОСТАТКИ_ЭКРАНИРОВАНИЯ if низ.startswith(о)), None)
        if для_снятия is None:
            break
        остаток = вышло[len(для_снятия):]
        from core.email_syntax import validate_email_syntax
        try:
            ответ = validate_email_syntax(остаток)
            ok = bool(ответ[0] if isinstance(ответ, tuple) else ответ)
        except Exception:
            ok = False
        if not ok:
            break
        вышло = остаток
        снято += 1
    return вышло if снято else text


def _снять_комментарий_с_краёв(часть):
    вышло = часть
    if вышло.startswith("(") and ")" in вышло:
        конец = вышло.index(")")
        if "(" not in вышло[1:конец]:
            вышло = вышло[конец + 1:]
    if вышло.endswith(")") and "(" in вышло:
        начало = вышло.rindex("(")
        if ")" not in вышло[начало + 1:-1]:
            вышло = вышло[:начало]
    if "(" in вышло or ")" in вышло:
        return часть
    return вышло


def strip_comments(text):
    if not isinstance(text, str) or "(" not in text or ")" not in text:
        return text
    if '"' in text:
        return text

    имя, собака, домен = text.rpartition("@")
    if not собака:
        return text

    новое_имя = _снять_комментарий_с_краёв(имя)
    новый_домен = _снять_комментарий_с_краёв(домен)
    if новое_имя == имя and новый_домен == домен:
        return text

    итог = новое_имя + "@" + новый_домен
    if not новое_имя or not новый_домен or итог.count("@") != 1:
        return text
    return итог


def normalize_input(text):
    if not isinstance(text, str):
        return text
    вышло = strip_invisible(text)
    вышло = fold_fullwidth(вышло)
    вышло = to_nfc(вышло)
    вышло = decode_wrappers(вышло)
    вышло = strip_escape_residue(вышло)
    return strip_comments(вышло)


_АДРЕС = re.compile(
    r"[^\s,;<>()\[\]{}\"]+@[^\s,;<>()\[\]{}\"]+\.[^\s,;<>()\[\]{}\"]+")


def split_addresses(line):
    if not isinstance(line, str) or "@" not in line:
        return [line] if isinstance(line, str) and line.strip() else []
    найдено = _АДРЕС.findall(line)
    if len(найдено) <= 1:
        return [line]
    return найдено
