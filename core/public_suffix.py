# -*- coding: utf-8 -*-
import os
import threading

__all__ = ["зоны_верхнего_уровня", "публичный_суффикс", "версия_списка",
           "правил_прочитано"]

ФАЙЛ = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "public_suffix_list.dat")

_замок = threading.Lock()
_разобрано = None


def _разобрать():
    правила = set()
    подстановки = set()
    исключения = set()
    зоны = set()
    версия = ""

    def положить(куда, имя):
        куда.add(имя)
        зоны.add(имя.rsplit(".", 1)[-1])
        if not имя.isascii():
            try:
                пуни = имя.encode("idna").decode("ascii")
            except Exception:
                return
            куда.add(пуни)
            зоны.add(пуни.rsplit(".", 1)[-1])

    try:
        with open(ФАЙЛ, encoding="utf-8") as файл:
            for строка in файл:
                текст = строка.strip()
                if not текст:
                    continue
                if текст.startswith("//"):
                    if "VERSION:" in текст and not версия:
                        версия = текст.split("VERSION:", 1)[1].strip()
                    continue
                имя = текст.lower()
                if имя.startswith("!"):
                    положить(исключения, имя[1:])
                elif имя.startswith("*."):
                    положить(подстановки, имя[2:])
                else:
                    положить(правила, имя)
    except Exception:
        return frozenset(), frozenset(), frozenset(), frozenset(), ""
    return (frozenset(правила), frozenset(подстановки), frozenset(исключения),
            frozenset(зоны), версия)


def _данные():
    global _разобрано
    if _разобрано is None:
        with _замок:
            if _разобрано is None:
                _разобрано = _разобрать()
    return _разобрано


def зоны_верхнего_уровня():
    return _данные()[3]


def публичный_суффикс(имя):
    if not isinstance(имя, str):
        return False
    очищенное = имя.strip().lower().rstrip(".")
    if not очищенное:
        return False
    правила, подстановки, исключения, _зоны, _версия = _данные()
    if очищенное in исключения:
        return False
    if очищенное in правила:
        return True
    if "." in очищенное:
        родитель = очищенное.split(".", 1)[1]
        if родитель in подстановки:
            return True
    return False


def версия_списка():
    return _данные()[4]


def правил_прочитано():
    правила, подстановки, исключения, _зоны, _версия = _данные()
    return len(правила) + len(подстановки) + len(исключения)
