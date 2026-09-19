# -*- coding: utf-8 -*-
"""Исходник конвейера целиком — для проверок, которые читают КОД, а не зовут его.

ЗАЧЕМ ЭТОТ ФАЙЛ. Часть проверок устроена так: взять исходный текст конвейера и
убедиться, что в нём есть нужная строка — например, что число берётся из
настроек, а не зашито константой. Пока весь конвейер лежал в одном файле,
хватало `inspect.getsource(core.pipeline)`.

После разделения на примеси (`core/pipeline_setup.py`, `core/enrichment.py`,
`core/verdict_revision.py`) половина кода уехала из того файла, и такие
проверки стали зелёными не потому, что код верен, а потому, что искали не там.
Это худший вид поломки проверки: она продолжает докладывать успех.

Поэтому исходник собирается по ВСЕМ модулям конвейера сразу. Список берётся
из настоящих баз класса, а не переписывается руками: разделят файл ещё раз —
новая примесь попадёт сюда сама, и проверки не придётся догонять.
"""
import inspect
import io
import sys


def модули_конвейера():
    """Модули, из которых собран ValidationPipeline: сам файл и все примеси."""
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
    """Склеенный текст всех модулей конвейера.

    Склейка, а не поиск по каждому отдельно, нужна ровно для того, чтобы
    вызывающему не пришлось знать, в каком именно файле лежит проверяемая
    строка. Проверяется наличие кода в конвейере, а не его расположение.
    """
    куски = []
    for модуль in модули_конвейера():
        try:
            куски.append(inspect.getsource(модуль))
        except (OSError, TypeError):
            # Модуль без доступного исходника пропускаем молча: это не
            # поломка проверки, а особенность окружения (например, .pyc без
            # исходного файла). Остальные модули всё равно будут прочитаны.
            continue
    return "\n".join(куски)


def исходник_окна():
    """То же самое для окна: ui/webapp.py вместе с его примесями."""
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
    """То же для проверяющей сети: core/network.py вместе с примесями."""
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


# Разрезанные модули: путь -> собиратель полного текста семьи.
_СЕМЬИ = {
    "core/pipeline.py": исходник_конвейера,
    "core/network.py": исходник_сети,
    "ui/webapp.py": исходник_окна,
}


def исходник_файла(путь, корень=None):
    """Текст файла; для разрезанных модулей — вместе с их примесями.

    Проверки, читающие КОД, обязаны искать его там, где он лежит сейчас.
    После разделения на примеси половина кода уехала из исходного файла, и
    чтение одного файла превратило бы такую проверку в зелёную по ошибке —
    она искала бы не там и ничего не находила бы уже никогда.
    """
    ключ = путь.replace("\\", "/").lstrip("./")
    for имя, собрать in _СЕМЬИ.items():
        if ключ.endswith(имя):
            return собрать()
    import os
    корень = корень or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    полный = путь if os.path.isabs(путь) else os.path.join(корень, *ключ.split("/"))
    return io.open(полный, encoding="utf-8").read()


def файлы_окна():
    """Пары (путь, текст) по всем модулям окна: сам webapp и его примеси.

    Нужна проверкам, которые разбирают КОД деревом, а не ищут подстроку: им
    важен путь (для сообщения об ошибке) и текст каждого файла отдельно.
    """
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
