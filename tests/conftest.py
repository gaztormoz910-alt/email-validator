# -*- coding: utf-8 -*-
"""Общая подготовка набора тестов.

Задача одна: изолировать ДОЛГОВРЕМЕННУЮ ПАМЯТЬ валидатора (core/longterm.py).

Две причины, и обе важные.

Первая: память заводится внутри NetworkValidator сама, без параметров, и по
умолчанию это data/longterm.sqlite — та самая база, где лежат catch-all
домены владельца, профили его прокси и суточный счёт нагрузки на IP. Прогон
тестов не имеет права её трогать.

Вторая: память ОБЩАЯ для процесса, и в этом весь её смысл — суточная нагрузка
на выходной IP переживает перезапуск. Но в наборе тестов это превращается в
связь между проверками: одна записала нагрузку на 1.1.1.1, а соседняя, взяв
тот же адрес, находит чужой счёт и падает. Поэтому файл здесь свой на КАЖДЫЙ
тест: изоляция важнее экономии, а файл создаётся лениво — только если тест
действительно поднимает валидатор.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture(autouse=True)
def _isolate_longterm_memory(tmp_path_factory, request):
    from core import longterm

    original = longterm.DEFAULT_PATH
    # Имя от узла теста: в отчёте сразу видно, чья это база, если она
    # понадобится при разборе падения.
    safe = "".join(ch if ch.isalnum() else "_" for ch in request.node.nodeid)[-60:]
    folder = tmp_path_factory.mktemp("longterm", numbered=True)
    longterm.DEFAULT_PATH = str(folder / ("%s.sqlite" % safe))
    yield
    longterm.DEFAULT_PATH = original
