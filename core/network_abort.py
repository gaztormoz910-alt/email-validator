# -*- coding: utf-8 -*-
"""«Стоп» в сетевом слое: оборвать паузу и ожидание очереди к серверу.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. core/network.py стоит у потолка размера модуля
(tools/verify_module_sizes.py), а у темы «бросить начатую проверку» свой
смысл: событие остановки, ответ брошенной попытки и два ожидания, которые
его слышат. Сетевой диалог с сервером здесь не меняется.

Без этого «Стоп» из окна действовал только между адресами: начатая
проверка спала до 8 секунд перед запросом, потом без таймаута ждала места
в очереди к серверу (5 на сервер и выходной адрес) и к прокси (8), и всё
это — по каждой из десяти попыток (жалоба владельца 06.11.2026: «в работе
227 → 130», «Останавливаю» минутами).
"""
import time

__all__ = ["AbortableMixin"]


class AbortableMixin:
    # Ответ брошенной «Стопом» попытки. Не вердикт и не сбой прокси: штраф
    # прокси за него не ставится, а выше по цепочке он не выдаётся вовсе.
    ABORTED = {"status": "unknown", "reason": "Проверка остановлена", "aborted": True}

    def aborted(self):
        event = getattr(self, "abort_event", None)
        return bool(event is not None and event.is_set())

    def _pause(self, seconds):
        """Пауза, которую обрывает «Стоп». True — пауза прервана."""
        event = getattr(self, "abort_event", None)
        if event is None:
            if seconds > 0:
                time.sleep(seconds)
            return False
        if seconds <= 0:
            return event.is_set()
        return event.wait(seconds)

    def _take(self, lock):
        """Захват семафора, который обрывает «Стоп». True — захвачен.

        Голый acquire() без таймаута держал поток в очереди к серверу
        сколько угодно, и «Стоп» его не видел.
        """
        while True:
            if lock.acquire(timeout=0.25):
                if self.aborted():
                    lock.release()
                    return False
                return True
            if self.aborted():
                return False
