import os
import smtplib
import socket
import ssl
import threading

import pytest

from core import mx_certificate as mc

TLS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tls")


def _context_trusting_test_ca():
    context = mc.verifying_context()
    context.load_verify_locations(os.path.join(TLS, "ca.pem"))
    return context


class _FakeMx:

    def __init__(self, cert, starttls=True):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.starttls = starttls
        self.connections = 0
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.load_cert_chain(os.path.join(TLS, cert + ".pem"),
                                 os.path.join(TLS, cert + ".key"))
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _session(self, conn):
        conn.settimeout(5)
        reader = conn.makefile("rb")
        try:
            conn.sendall(b"220 mx.corp.test ESMTP\r\n")
            while True:
                line = reader.readline()
                if not line:
                    return
                verb = line.strip().upper()
                if verb.startswith(b"EHLO"):
                    conn.sendall(b"250-mx.corp.test\r\n" +
                                 (b"250-STARTTLS\r\n" if self.starttls else b"") +
                                 b"250 8BITMIME\r\n")
                elif verb == b"STARTTLS":
                    conn.sendall(b"220 go ahead\r\n")
                    try:
                        conn = self.tls.wrap_socket(conn, server_side=True)
                    except (ssl.SSLError, OSError):
                        return
                    reader = conn.makefile("rb")
                elif verb == b"QUIT":
                    conn.sendall(b"221 bye\r\n")
                    return
                else:
                    conn.sendall(b"250 ok\r\n")
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def close(self):
        self.listener.close()


class _Network:

    def __init__(self, stopped=False):
        self.stopped = stopped
        self.finished = 0

    def aborted(self):
        return self.stopped

    def _make_smtp_connection(self, proxy=None):
        return smtplib.SMTP(timeout=5)

    def _helo_for(self, proxy):
        return "probe.test"

    def _finish(self, server):
        self.finished += 1
        try:
            server.quit()
        except Exception:
            server.close()


@pytest.fixture(autouse=True)
def _fresh_memory():
    mc.forget()
    yield
    mc.forget()


@pytest.fixture
def mx(request):
    server = _FakeMx(*request.param)
    yield server
    server.close()


@pytest.mark.parametrize("names, expected", [
    (["mx.google.com", "*.aspmx.l.google.com"], "Google Workspace"),
    (["*.mail.protection.outlook.com", "mail.protection.outlook.com"], "Microsoft 365"),
    (["*.pphosted.com"], "Proofpoint"),
    (["mail.corp.test"], None),
    (["mail.googleplex-fans.test"], None),
    (["mx.notmimecast.test"], None),
    (["mx.google.com", "*.pphosted.com"], None),
    ([], None),
    (None, None),
])
def test_provider_from_names(names, expected):
    assert mc.provider_from_names(names) == expected


def test_names_fall_back_to_common_name():
    cert = {"subject": ((("commonName", "mx.google.com"),),)}
    assert mc.names_from_peercert(cert) == ["mx.google.com"]
    assert mc.names_from_peercert(None) == []


@pytest.mark.parametrize("mx", [("google",)], indirect=True)
def test_certificate_from_trusted_chain_names_provider(mx):
    net = _Network()
    got = mc.provider_by_certificate(net, "127.0.0.1", context=_context_trusting_test_ca(),
                                     port=mx.port)
    assert got == "Google Workspace"
    assert net.finished == 1


@pytest.mark.parametrize("mx", [("forged",)], indirect=True)
def test_forged_self_signed_certificate_is_not_believed(mx):
    got = mc.provider_by_certificate(_Network(), "127.0.0.1",
                                     context=_context_trusting_test_ca(), port=mx.port)
    assert got is None


@pytest.mark.parametrize("mx", [("google",)], indirect=True)
def test_certificate_from_unknown_authority_is_not_believed(mx):
    got = mc.provider_by_certificate(_Network(), "127.0.0.1", port=mx.port)
    assert got is None


@pytest.mark.parametrize("mx", [("corp",)], indirect=True)
def test_company_own_certificate_gives_no_provider(mx):
    got = mc.provider_by_certificate(_Network(), "127.0.0.1",
                                     context=_context_trusting_test_ca(), port=mx.port)
    assert got is None


@pytest.mark.parametrize("mx", [("google", False)], indirect=True)
def test_server_without_starttls_gives_no_provider(mx):
    got = mc.provider_by_certificate(_Network(), "127.0.0.1",
                                     context=_context_trusting_test_ca(), port=mx.port)
    assert got is None


@pytest.mark.parametrize("mx", [("google",)], indirect=True)
def test_single_connection_per_mx_host(mx):
    net = _Network()
    context = _context_trusting_test_ca()
    for _ in range(5):
        assert mc.provider_by_certificate(net, "127.0.0.1", context=context,
                                          port=mx.port) == "Google Workspace"
    assert mx.connections == 1


def test_unreachable_host_is_tried_a_bounded_number_of_times():
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    calls = []

    class _Counting(_Network):
        def _make_smtp_connection(self, proxy=None):
            calls.append(proxy)
            return smtplib.SMTP(timeout=2)

    net = _Counting()
    for _ in range(5):
        assert mc.provider_by_certificate(net, "127.0.0.1", port=port) is None
    assert len(calls) == mc._ATTEMPTS_PER_HOST


def test_stop_means_no_connection():
    calls = []

    class _Stopped(_Network):
        def _make_smtp_connection(self, proxy=None):
            calls.append(proxy)
            raise AssertionError("после «Стопа» соединений быть не должно")

    assert mc.provider_by_certificate(_Stopped(stopped=True), "mx.corp.test") is None
    assert calls == []


def _enrich(monkeypatch, email, res):
    from core.pipeline import ValidationPipeline

    class _Silent:

        def last_profile(self):
            return {}

        def __getattr__(self, name):
            return lambda *a, **kw: None

    pipeline = ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None, "on_result": lambda *a: None,
        "on_progress": lambda *a: None, "on_complete": lambda: None})
    pipeline.cache = None
    pipeline.name_extractor = _Silent()
    pipeline.ml_predictor = _Silent()
    for name, value in (("check_dns_health", {"score": 0}), ("check_dnsbl", False),
                        ("check_ptr", None)):
        if hasattr(pipeline.network, name):
            monkeypatch.setattr(pipeline.network, name, lambda *a, _v=value, **kw: _v)
    calls = []

    def fake(network, mx_host, proxy=None, **kw):
        calls.append((mx_host, proxy))
        return "Microsoft 365"

    monkeypatch.setattr(mc, "provider_by_certificate", fake)
    data = {"name": "Mira Lind", "country": "Норвегия", "gender": "female"}
    base = {"status": "invalid", "reason": "нет такого ящика", "mx_records": [res.get("mx_record")]}
    base.update(res)
    pipeline._enrich_and_score(email, data, base, "Invalid", "Invalid", False, False)
    return data, calls


def test_enrichment_uses_certificate_for_hidden_corporate_mx(monkeypatch):
    data, calls = _enrich(monkeypatch, "ml@corp.test",
                          {"mx_record": "mail.corp.test", "has_starttls": True,
                           "proxy": "socks5://198.51.100.7:1080"})
    assert calls == [("mail.corp.test", "socks5://198.51.100.7:1080")]
    assert data["provider_name"] == "Microsoft 365"
    assert data["provider_basis"] == "сертификат MX"


@pytest.mark.parametrize("email, res", [
    ("ml@corp.test", {"mx_record": "corp-test.mail.protection.outlook.com", "has_starttls": True}),
    ("ml@corp.test", {"mx_record": "mail.corp.test", "has_starttls": False}),
    ("ml@corp.test", {"mx_record": "mail.corp.test", "has_starttls": None}),
    ("ml@gmail.com", {"mx_record": "gmail-smtp-in.l.google.com", "has_starttls": True}),
])
def test_control_enrichment_does_not_ask_certificate(monkeypatch, email, res):
    data, calls = _enrich(monkeypatch, email, res)
    assert calls == []
    assert "provider_basis" not in data
