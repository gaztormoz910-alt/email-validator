# -*- coding: utf-8 -*-
import socket
import threading
import time

import pytest

from core.pipeline_control import RunControlMixin

TIMEOUT = 4.0
FAST = 1.5


class _FakeSmtp:

    def __init__(self, answers):
        self.answers = answers
        self.seen = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.stop = threading.Event()
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        self.sock.settimeout(0.2)
        while not self.stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except OSError:
                continue
            threading.Thread(target=self._talk, args=(conn,), daemon=True).start()

    def _talk(self, conn):
        left = self.answers
        try:
            if left <= 0:
                self.stop.wait(TIMEOUT * 3)
                return
            conn.sendall(b"220 fake.test ESMTP\r\n")
            left -= 1
            buf = b""
            while not self.stop.is_set():
                chunk = conn.recv(1024)
                if not chunk:
                    return
                buf += chunk
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    self.seen.append(line.split(b" ")[0].upper())
                    if left <= 0:
                        continue
                    left -= 1
                    conn.sendall(b"221 bye\r\n" if line.upper().startswith(b"QUIT")
                                 else b"250 ok\r\n")
        except OSError:
            pass
        finally:
            conn.close()

    def close(self):
        self.stop.set()
        self.sock.close()


class _Run(RunControlMixin):

    def __init__(self, network):
        self._abort_event = network.abort_event
        self.network = network

        class _Activity:
            def request_stop(self):
                pass

            def set_paused(self, value):
                pass

        self.activity = _Activity()

    def _stop_profile_refresher(self):
        pass


@pytest.fixture
def validator():
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=TIMEOUT)
    v._mx_delay = lambda mx: 0
    return v


def _redirect(v, port):
    make = v._make_smtp_connection

    def to_fake(proxy=None):
        server = make(proxy)
        connect = server.connect
        server.connect = lambda host="", port_=0, source_address=None: connect("127.0.0.1", port)
        return server

    v._make_smtp_connection = to_fake


def _probe_in_thread(v):
    out = {}

    def run():
        start = time.monotonic()
        out["result"] = v._probe_recipients(["anna@corp.test"], "mx.corp.test")
        out["took"] = time.monotonic() - start

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread, out


def test_stop_wakes_a_session_waiting_for_the_server(validator):
    fake = _FakeSmtp(answers=2)
    try:
        _redirect(validator, fake.port)
        thread, out = _probe_in_thread(validator)
        time.sleep(0.5)
        stopped = time.monotonic()
        _Run(validator).stop(abort=True)
        thread.join(TIMEOUT * 3)
        assert not thread.is_alive()
        assert time.monotonic() - stopped < FAST, "поток досиживал таймаут сессии"
    finally:
        fake.close()


def test_stop_before_the_banner_does_not_wait_for_it(validator):
    fake = _FakeSmtp(answers=0)
    try:
        server = validator._make_smtp_connection(None)
        validator.abort_event.set()
        start = time.monotonic()
        with pytest.raises(Exception):
            server.connect("127.0.0.1", fake.port)
        assert time.monotonic() - start < FAST, "чтение баннера ждало таймаут"
    finally:
        fake.close()


def test_stop_does_not_penalize_the_proxy(validator):
    validator.abort_event.set()
    validator._update_proxy_score("192.0.2.1:1080", False, mx_record="mx.corp.test")
    assert not validator._proxy_consecutive_fails.get("192.0.2.1:1080")


def test_control_failure_without_stop_still_penalizes(validator):
    validator._update_proxy_score("192.0.2.1:1080", False, mx_record="mx.corp.test")
    assert validator._proxy_consecutive_fails.get("192.0.2.1:1080") == 1


def test_control_session_without_stop_ends_with_quit(validator):
    fake = _FakeSmtp(answers=10)
    try:
        _redirect(validator, fake.port)
        result = validator._probe_recipients(["anna@corp.test"], "mx.corp.test")
        assert result and result[0]["status"] == "valid"
        deadline = time.monotonic() + 2
        while b"QUIT" not in fake.seen and time.monotonic() < deadline:
            time.sleep(0.05)
        assert b"QUIT" in fake.seen, "без «Стопа» сессия закрывается вежливо"
    finally:
        fake.close()
