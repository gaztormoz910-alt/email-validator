# -*- coding: utf-8 -*-
"""«Стоп» в сетевом слое: оборвать паузу, ожидание очереди и открытую сессию.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. core/network.py стоит у потолка размера модуля
(tools/verify_module_sizes.py), а у темы «бросить начатую проверку» свой
смысл: событие остановки, ответ брошенной попытки, ожидания, которые его
слышат, и открытые SMTP-сессии, которые «Стоп» закрывает. Сетевой диалог с
сервером здесь не меняется.

Без этого «Стоп» из окна действовал только между адресами: начатая
проверка спала до 8 секунд перед запросом, потом без таймаута ждала места
в очереди к серверу (5 на сервер и выходной адрес) и к прокси (8), и всё
это — по каждой из десяти попыток (жалоба владельца 06.11.2026: «в работе
227 → 130», «Останавливаю» минутами).

Открытая сессия — третье такое место (этап 3 плана 14.11.2026). Поток,
ждущий ответа почтового сервера, сидел в recv до таймаута сессии, а потом
ещё раз — в QUIT. «Стоп» теперь закрывает сокеты всех открытых сессий, и
recv просыпается сразу.
"""
import socket
import threading
import time
import weakref

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

    # ── открытые SMTP-сессии ────────────────────────────────────────────

    def _live_sessions(self):
        """(замок, слабое множество открытых сессий). Создаётся лениво.

        Слабое: сессия, про которую забыли, не держится в памяти списком —
        у сотни потоков за прогон их тысячи. Лениво: часть тестов собирает
        валидатор через __new__.
        """
        live = getattr(self, "_smtp_live", None)
        if live is None:
            live = self._smtp_live = (threading.Lock(), weakref.WeakSet())
        return live

    def _track(self, server):
        """Запомнить сессию, чтобы «Стоп» мог её закрыть. Возвращает её же.

        Сокет появляется внутри connect(): сначала TCP (через прокси — с его
        рукопожатием), потом чтение баннера. Если «Стоп» пришёл, пока шло
        TCP-соединение, закрывать было ещё нечего, и чтение баннера ждало бы
        полный таймаут. Поэтому сокет, полученный уже после «Стопа»,
        закрывается тут же, а connect() падает сразу.
        """
        lock, sessions = self._live_sessions()
        with lock:
            sessions.add(server)
        make_socket = server._get_socket

        def guarded(host, port, timeout):
            sock = make_socket(host, port, timeout)
            if self.aborted():
                _shut(sock)
                raise OSError("Проверка остановлена")
            return sock

        server._get_socket = guarded
        return server

    def abort_connections(self):
        """Закрыть сокеты всех открытых сессий. Возвращает, сколько закрыто.

        shutdown, а не только close: на Windows close из другого потока не
        всегда будит recv, а shutdown будит на любой системе.
        """
        lock, sessions = self._live_sessions()
        with lock:
            servers = list(sessions)
        closed = 0
        for server in servers:
            sock = getattr(server, "sock", None)
            if sock is not None:
                _shut(sock)
                closed += 1
        return closed

    def _finish(self, server):
        """Закрыть сессию: QUIT, а после «Стопа» — сразу, без ожидания ответа."""
        lock, sessions = self._live_sessions()
        with lock:
            sessions.discard(server)
        try:
            if self.aborted():
                server.close()
            else:
                server.quit()
        except Exception:
            pass


def _shut(sock):
    for step in (lambda: sock.shutdown(socket.SHUT_RDWR), sock.close):
        try:
            step()
        except OSError:
            pass
