# -*- coding: utf-8 -*-
import socket
import threading
import time
import weakref

__all__ = ["AbortableMixin"]


class AbortableMixin:
    ABORTED = {"status": "unknown", "reason": "Проверка остановлена", "aborted": True}

    def aborted(self):
        event = getattr(self, "abort_event", None)
        return bool(event is not None and event.is_set())

    def _pause(self, seconds):
        event = getattr(self, "abort_event", None)
        if event is None:
            if seconds > 0:
                time.sleep(seconds)
            return False
        if seconds <= 0:
            return event.is_set()
        return event.wait(seconds)

    def _take(self, lock):
        while True:
            if lock.acquire(timeout=0.25):
                if self.aborted():
                    lock.release()
                    return False
                return True
            if self.aborted():
                return False


    def _live_sessions(self):
        live = getattr(self, "_smtp_live", None)
        if live is None:
            live = self._smtp_live = (threading.Lock(), weakref.WeakSet())
        return live

    def _track(self, server):
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
