# -*- coding: utf-8 -*-
import io
import os
import time

_отметки = None
_начало = None


def включить(момент_старта=None):
    global _отметки, _начало
    _начало = момент_старта if момент_старта is not None else time.perf_counter()
    _отметки = []


def включено():
    return _отметки is not None


def отметить(имя):
    if _отметки is None:
        return
    _отметки.append((имя, time.perf_counter() - _начало))


def дождаться_окна(события, показ=180, страница=60):
    for событие, имя, предел in (("shown", "окно показалось", показ),
                                 ("loaded", "страница загрузилась", страница)):
        try:
            if not getattr(события, событие).wait(предел):
                return "%s — нет за %d с" % (имя, предел)
        except Exception as ошибка:
            return "ожидание «%s» упало: %s" % (имя, ошибка)
        отметить(имя)
    return ""


def записать(путь, провал=""):
    if not _отметки:
        return 0.0
    каталог = os.path.dirname(os.path.abspath(путь))
    if каталог:
        os.makedirs(каталог, exist_ok=True)
    строки = ["MailFact: отметки запуска", ""]
    строки.append("%-34s %9s %9s" % ("шаг", "от старта", "сам шаг"))
    прошлое = 0.0
    самый = ("", 0.0)
    for имя, когда in _отметки:
        шаг = когда - прошлое
        if шаг > самый[1]:
            самый = (имя, шаг)
        строки.append("%-34s %8.2f с %8.2f с" % (имя, когда, шаг))
        прошлое = когда
    строки.append("")
    строки.append("ВСЕГО: %.2f с" % прошлое)
    строки.append("САМЫЙ ДОЛГИЙ ШАГ: %s — %.2f с" % (самый[0], самый[1]))
    строки.append("TIMING_FAILED: %s" % провал if провал else "TIMING_OK")
    with io.open(путь, "w", encoding="utf-8", newline="") as файл:
        файл.write(chr(10).join(строки) + chr(10))
    return прошлое
