# -*- coding: utf-8 -*-
import os
import sys


class ТихийПоток:

    encoding = "utf-8"
    errors = "replace"

    def write(self, текст):
        return len(текст) if isinstance(текст, str) else 0

    def writelines(self, строки):
        for с in строки:
            self.write(с)

    def flush(self):
        pass

    def isatty(self):
        return False

    def fileno(self):
        raise OSError("у этого потока нет дескриптора")

    def close(self):
        pass

    @property
    def closed(self):
        return False


ПОТОЛОК = 1024 * 1024
ОСТАВЛЯТЬ = 256 * 1024


def _подрезать(путь):
    try:
        if os.path.getsize(путь) <= ПОТОЛОК:
            return
        with open(путь, "rb") as файл:
            файл.seek(-ОСТАВЛЯТЬ, os.SEEK_END)
            хвост = файл.read()
        ПЕРЕВОД = bytes([10])
        граница = хвост.find(ПЕРЕВОД)
        if 0 <= граница < len(хвост) - 1:
            хвост = хвост[граница + 1:]
        with open(путь, "wb") as файл:
            файл.write(хвост)
    except OSError:
        pass


def _файл_журнала(куда):
    try:
        os.makedirs(куда, exist_ok=True)
        путь = os.path.join(куда, "stdout.log")
        _подрезать(путь)
        return open(путь, "a",
                    encoding="utf-8", errors="replace", buffering=1)
    except OSError:
        return None


def _не_ронять_на_кодировке(поток):
    try:
        "Ёё".encode(поток.encoding or "ascii")
        кодировка = None
    except (LookupError, UnicodeError, AttributeError, TypeError):
        кодировка = "utf-8"
    try:
        if кодировка:
            поток.reconfigure(encoding=кодировка, errors="replace")
        else:
            поток.reconfigure(errors="replace")
    except Exception:
        pass


def readable_output():
    for имя in ("stdout", "stderr"):
        поток = getattr(sys, имя, None)
        if поток is not None:
            _не_ронять_на_кодировке(поток)


def ensure_streams(куда=None):
    сделано = {}
    файл = None
    for имя in ("stdout", "stderr"):
        поток = getattr(sys, имя, None)
        годен = поток is not None and hasattr(поток, "write")
        if годен:
            _не_ронять_на_кодировке(поток)
            сделано[имя] = "был"
            continue
        if файл is None and куда:
            файл = _файл_журнала(куда)
        замена = файл or ТихийПоток()
        setattr(sys, имя, замена)
        сделано[имя] = "файл" if файл else "тихий"
    return сделано
