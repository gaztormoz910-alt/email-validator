# -*- coding: utf-8 -*-
import inspect
import io
import sys


def модули_конвейера():
    from core.pipeline import ValidationPipeline

    найдено = []
    for класс in ValidationPipeline.__mro__:
        if класс is object:
            continue
        модуль = sys.modules.get(класс.__module__)
        if модуль is not None and модуль not in найдено:
            найдено.append(модуль)
    return найдено


def исходник_конвейера():
    куски = []
    for модуль in модули_конвейера():
        try:
            куски.append(inspect.getsource(модуль))
        except (OSError, TypeError):
            continue
    return "\n".join(куски)


def исходник_окна():
    from ui.webapp import ValidatorApi

    куски = []
    видели = set()
    for класс in ValidatorApi.__mro__:
        if класс is object:
            continue
        модуль = sys.modules.get(класс.__module__)
        if модуль is None or модуль.__name__ in видели:
            continue
        видели.add(модуль.__name__)
        try:
            куски.append(inspect.getsource(модуль))
        except (OSError, TypeError):
            continue
    return "\n".join(куски)

def исходник_сети():
    from core.network import NetworkValidator

    куски = []
    видели = set()
    for класс in NetworkValidator.__mro__:
        if класс is object:
            continue
        модуль = sys.modules.get(класс.__module__)
        if модуль is None or модуль.__name__ in видели:
            continue
        видели.add(модуль.__name__)
        try:
            куски.append(inspect.getsource(модуль))
        except (OSError, TypeError):
            continue
    return chr(10).join(куски)


_СЕМЬИ = {
    "core/pipeline.py": исходник_конвейера,
    "core/network.py": исходник_сети,
    "ui/webapp.py": исходник_окна,
}


def исходник_файла(путь, корень=None):
    ключ = путь.replace("\\", "/").lstrip("./")
    for имя, собрать in _СЕМЬИ.items():
        if ключ.endswith(имя):
            return собрать()
    import os
    корень = корень or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    полный = путь if os.path.isabs(путь) else os.path.join(корень, *ключ.split("/"))
    return io.open(полный, encoding="utf-8").read()


def файлы_окна():
    from ui.webapp import ValidatorApi

    найдено = []
    видели = set()
    for класс in ValidatorApi.__mro__:
        if класс is object:
            continue
        модуль = sys.modules.get(класс.__module__)
        if модуль is None or модуль.__name__ in видели:
            continue
        видели.add(модуль.__name__)
        путь = getattr(модуль, "__file__", None)
        if not путь:
            continue
        try:
            найдено.append((путь, io.open(путь, encoding="utf-8").read()))
        except OSError:
            continue
    return найдено
