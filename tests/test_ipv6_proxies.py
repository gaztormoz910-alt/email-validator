# -*- coding: utf-8 -*-
import os
import socket
import struct
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import hostport, input_guard
from core.proxy_transport import (_parse_proxy, build_proxy_dict,
                                  exit_ip_from_banner, proxy_socket)

V6 = "2001:db8::10"


@pytest.mark.parametrize("line, expected", [
    ("[2001:db8::10]:1080", (V6, 1080, None, None)),
    ("socks5://[2001:db8::10]:1080", (V6, 1080, None, None)),
    ("http://[2001:db8::10]:3128", (V6, 3128, None, None)),
    ("[2001:db8::10]:1080:user:pass", (V6, 1080, "user", "pass")),
    ("user:pass@[2001:db8::10]:1080", (V6, 1080, "user", "pass")),
    ("socks4://user:pass@[2001:db8::10]:1080", (V6, 1080, "user", "pass")),
    ("[2001:0db8:0000:0000:0000:0000:0000:0010]:1080", (V6, 1080, None, None)),
    ("2001:db8:0:0:0:0:0:10:1080", (V6, 1080, None, None)),
])
def test_ipv6_proxy_lines_are_parsed(line, expected):
    assert _parse_proxy(line) == expected


@pytest.mark.parametrize("line", [
    "2001:db8::10:1080",
    "2001::1:1080",
    "socks5://2001:db8::10:1080",
    "user:pass@2001:db8::10:1080",
    "[2001:db8::zz]:1080",
    "[2001:db8::10]",
    "[2001:db8::10]1080",
    "[fe80::1%eth0]:1080",
    "[2001:db8::10:1080",
])
def test_ambiguous_or_broken_ipv6_lines_are_refused(line):
    assert _parse_proxy(line) is None


@pytest.mark.parametrize("line, expected", [
    ("203.0.113.10:1080", ("203.0.113.10", 1080, None, None)),
    ("203.0.113.10:1080:user:pass", ("203.0.113.10", 1080, "user", "pass")),
    ("user:pass@203.0.113.10:1080", ("203.0.113.10", 1080, "user", "pass")),
    ("socks5://proxy.example.test:1080", ("proxy.example.test", 1080, None, None)),
    ("203.0.113.10:1080:user", None),
    ("203.0.113.10:порт", None),
])
def test_ipv4_and_host_lines_behave_as_before(line, expected):
    assert _parse_proxy(line) == expected


@pytest.mark.parametrize("line", [
    "[2001:db8::10]:1080", "socks5://[2001:db8::10]:1080",
    "[2001:db8::10]:1080:user:pass", "user:pass@[2001:db8::10]:1080",
    "2001:db8:0:0:0:0:0:10:1080",
])
def test_window_recognises_ipv6_proxy_lines(line):
    assert input_guard.looks_like_proxy(line) is True
    assert input_guard.detect_kind(line) == input_guard.KIND_PROXY


def test_window_accepts_an_ipv6_proxy_list():
    text = "\n".join("[2001:db8::%x]:1080" % i for i in range(1, 8))
    assert input_guard.check_text(text, "proxy")["ok"] is True


def test_window_accepts_a_mixed_list():
    text = "203.0.113.5:1080\n[2001:db8::5]:1080\nuser:pass@[2001:db8::6]:1080\n"
    assert input_guard.check_text(text, "proxy")["ok"] is True


def test_window_explains_brackets_for_bare_ipv6():
    text = "\n".join("2001:db8::%x:1080" % i for i in range(1, 6))
    verdict = input_guard.check_text(text, "proxy")
    assert verdict["ok"] is False
    assert "квадратных скобок" in verdict["reason"]
    assert "[2001:db8::10]:1080" in verdict["reason"]


def test_ipv6_proxy_line_is_not_an_address_or_query():
    for line in ("user:pass@[2001:db8::10]:1080", "[2001:db8::10]:1080"):
        assert input_guard.detect_kind(line) == input_guard.KIND_PROXY


def test_http_proxy_url_puts_ipv6_in_brackets():
    assert build_proxy_dict("user:pass@[2001:db8::10]:1080") == {
        "http": "socks5h://user:pass@[2001:db8::10]:1080",
        "https": "socks5h://user:pass@[2001:db8::10]:1080"}
    assert build_proxy_dict("203.0.113.10:1080")["http"] == "socks5h://203.0.113.10:1080"


def test_proxy_socket_family_follows_the_proxy_address():
    for host, family in ((V6, socket.AF_INET6), ("203.0.113.10", socket.AF_INET),
                         ("proxy.example.test", socket.AF_INET)):
        sock = proxy_socket(host)
        try:
            assert sock.family == family, host
        finally:
            sock.close()


@pytest.mark.parametrize("banner, expected", [
    ("mx.google.com at your service, [203.0.113.77]", "203.0.113.77"),
    ("mx.google.com at your service, [2001:db8:1:2::77]", "2001:db8:1:2::77"),
    ("at your service, [2001:0db8:0001:0002:0000:0000:0000:0077]", "2001:db8:1:2::77"),
    ("hello [IPv6:2001:db8::5]", "2001:db8::5"),
    ("[abc] then [203.0.113.8]", "203.0.113.8"),
    ("[999.1.1.1]", None),
    ("mx.google.com at your service", None),
])
def test_exit_ip_is_read_from_the_banner(banner, expected):
    assert exit_ip_from_banner(banner) == expected


def test_ipv6_exit_is_counted_by_its_slash64():
    a = hostport.sender_key("2001:db8:1:2::77")
    b = hostport.sender_key("2001:db8:1:2:ffff::1")
    c = hostport.sender_key("2001:db8:1:3::77")
    assert a == b == "2001:db8:1:2::/64"
    assert c != a
    assert hostport.sender_key("203.0.113.9") == "203.0.113.9"
    assert hostport.sender_key("") == "" and hostport.sender_key(None) == ""


class _Answer:
    def __init__(self, text):
        self._text = text

    def to_text(self):
        return self._text

    def __str__(self):
        return self._text


class _FakeResolver:

    def __init__(self, table):
        self.table = table
        self.asked = []

    def resolve(self, name, rdtype):
        import dns.resolver

        key = (str(name).rstrip("."), rdtype)
        self.asked.append(key)
        answer = self.table.get(key)
        if answer is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(answer, Exception):
            raise answer
        return [_Answer(a) for a in answer]


@pytest.fixture
def validator():
    from core.network import NetworkValidator

    return NetworkValidator(timeout=2, proxy_dns=False)


def test_ipv6_exit_is_never_called_clean_without_a_checked_zone(validator):
    spy = _FakeResolver({})
    validator.resolver = spy
    assert validator.check_dnsbl_ip("2001:db8:1:2::77") is None
    assert spy.asked == []


def test_ipv6_exit_is_asked_in_nibble_form_when_a_zone_supports_it(validator, monkeypatch):
    import core.dns_checks as dc

    monkeypatch.setattr(dc, "DNSBL_ZONES_IPV6", ("v6.bl.test",))
    nibbles = "7.7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2"
    listed = _FakeResolver({(nibbles + ".v6.bl.test", "A"): ["127.0.0.2"]})
    validator.resolver = listed
    assert validator.check_dnsbl_ip("2001:db8:1:2::77") is True
    assert listed.asked == [(nibbles + ".v6.bl.test", "A")]
    validator.resolver = _FakeResolver({})
    assert validator.check_dnsbl_ip("2001:db8:1:2::77") is False


def test_ipv4_blacklist_check_is_unchanged(validator):
    import core.dns_checks as dc

    zone = dc.DNSBL_ZONES[0]
    spy = _FakeResolver({("9.113.0.203." + zone, "A"): ["127.0.0.2"]})
    validator.resolver = spy
    validator._spamhaus_ok = False
    assert validator.check_dnsbl_ip("203.0.113.9") is True
    assert ("9.113.0.203." + zone, "A") in spy.asked


def test_fcrdns_for_ipv6_checks_aaaa_in_any_notation(validator):
    ptr = "7.7.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.1.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa"
    spy = _FakeResolver({
        (ptr, "PTR"): ["mail.example.test."],
        ("mail.example.test", "AAAA"): ["2001:0db8:0001:0002:0000:0000:0000:0077"],
    })
    validator.resolver = spy
    assert validator.check_fcrdns("2001:db8:1:2::77") is True
    assert ("mail.example.test", "AAAA") in spy.asked
    assert ("mail.example.test", "A") not in spy.asked


def test_fcrdns_for_ipv4_still_checks_a(validator):
    spy = _FakeResolver({
        ("9.113.0.203.in-addr.arpa", "PTR"): ["mail.example.test."],
        ("mail.example.test", "A"): ["203.0.113.9"],
    })
    validator.resolver = spy
    assert validator.check_fcrdns("203.0.113.9") is True
    assert ("mail.example.test", "A") in spy.asked


def test_profile_keys_an_ipv6_exit_by_slash64_and_checks_the_exact_address(monkeypatch):
    import core.proxy_probe as pp
    import core.proxy_profile as prof
    from core.network import NetworkValidator

    exits = {"[2001:db8::a]:1080": "2001:db8:1:2::77",
             "[2001:db8::b]:1080": "2001:db8:1:2:ffff::1",
             "203.0.113.5:1080": "203.0.113.5"}
    monkeypatch.setattr(pp, "probe_proxy_target",
                        lambda proxy, host, timeout=10, want_exit_ip=False:
                        (True, 12, exits[proxy] if want_exit_ip else None, "ok"))
    checked = []
    monkeypatch.setattr(NetworkValidator, "check_fcrdns",
                        lambda self, ip: checked.append(("ptr", ip)) or True)
    monkeypatch.setattr(NetworkValidator, "get_ptr_hostname", lambda self, ip: "mail.example.test")
    monkeypatch.setattr(NetworkValidator, "check_dnsbl_ip",
                        lambda self, ip: checked.append(("bl", ip)) or False)
    monkeypatch.setattr(prof, "lookup_ip_meta", lambda ip, **kw: {"ip_type": "datacenter"})

    profiles = pp.profile_proxies(list(exits), timeout=2, workers=1, probe_outlook=False)
    a, b, v4 = (profiles[p] for p in exits)
    assert a["exit_ip"] == b["exit_ip"] == "2001:db8:1:2::/64"
    assert (a["exit_addr"], b["exit_addr"]) == ("2001:db8:1:2::77", "2001:db8:1:2:ffff::1")
    assert v4["exit_ip"] == v4["exit_addr"] == "203.0.113.5"
    assert ("ptr", "2001:db8:1:2::77") in checked and ("bl", "2001:db8:1:2::77") in checked


def test_no_ipv6_route_is_named_as_the_reason():
    from core.pipeline_setup import _count_ipv6_proxies, _warn_ipv6_unreachable

    seen = [0]
    stream = ["203.0.113.5:1080", "[2001:db8::5]:1080", "user:pass@[2001:db8::6]:1080",
              "2001:db8::7:1080"]
    assert list(_count_ipv6_proxies(iter(stream), seen)) == stream
    assert seen[0] == 2

    lines = []
    assert _warn_ipv6_unreachable(lambda t, tag: lines.append((t, tag)), seen[0],
                                  route=lambda: False) is True
    assert len(lines) == 1 and lines[0][1] == "dead"
    assert "нет выхода в интернет по IPv6" in lines[0][0] and "2" in lines[0][0]

    quiet = []
    assert _warn_ipv6_unreachable(lambda t, tag: quiet.append(t), 2, route=lambda: True) is False
    assert _warn_ipv6_unreachable(lambda t, tag: quiet.append(t), 0, route=lambda: False) is False
    assert quiet == []


def test_route_check_answers_without_sending_anything():
    assert hostport.has_ipv6_route() in (True, False)


def _ipv6_loopback_available():
    if not socket.has_ipv6:
        return False
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        probe.bind(("::1", 0))
        probe.close()
        return True
    except OSError:
        return False


needs_v6_loopback = pytest.mark.skipif(not _ipv6_loopback_available(),
                                       reason="на машине нет петли IPv6 ([::1])")


def _listen6():
    srv = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    srv.bind(("::1", 0))
    srv.listen(4)
    srv.settimeout(10)
    return srv


def _pump(src, dst):
    try:
        while True:
            data = src.recv(65536)
            if not data:
                break
            dst.sendall(data)
    except OSError:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _socks5_to(backend_port):
    srv = _listen6()
    asked = []

    def serve():
        while True:
            try:
                conn, _ = srv.accept()
            except OSError:
                return
            try:
                conn.settimeout(10)
                conn.recv(262)
                conn.sendall(b"\x05\x00")
                head = conn.recv(4)
                atyp = head[3]
                if atyp == 1:
                    dest = socket.inet_ntop(socket.AF_INET, conn.recv(4))
                elif atyp == 4:
                    dest = socket.inet_ntop(socket.AF_INET6, conn.recv(16))
                else:
                    dest = conn.recv(conn.recv(1)[0]).decode()
                port = struct.unpack(">H", conn.recv(2))[0]
                asked.append((dest, port))
                out = socket.create_connection(("::1", backend_port), timeout=10)
                conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
                threading.Thread(target=_pump, args=(conn, out), daemon=True).start()
                threading.Thread(target=_pump, args=(out, conn), daemon=True).start()
            except OSError:
                conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], asked


def _fake_smtp(exit_ip):
    srv = _listen6()

    def serve():
        conn, _ = srv.accept()
        f = conn.makefile("rwb")
        f.write(b"220 mx.example.test ESMTP\r\n")
        f.flush()
        for raw in f:
            cmd = raw.strip().upper()
            if cmd.startswith(b"EHLO"):
                f.write(b"250-mx.example.test at your service, [" + exit_ip.encode()
                        + b"]\r\n250 SIZE 1000\r\n")
            elif cmd.startswith(b"QUIT"):
                f.write(b"221 bye\r\n")
                f.flush()
                break
            else:
                f.write(b"250 ok\r\n")
            f.flush()
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1]


@needs_v6_loopback
def test_probe_through_an_ipv6_proxy_reads_the_ipv6_exit():
    from core.proxy_probe import probe_proxy_target

    smtp_port = _fake_smtp("2001:db8:1:2::77")
    socks_port, asked = _socks5_to(smtp_port)
    ok, latency, exit_ip, reason = probe_proxy_target(
        "socks5://[::1]:%d" % socks_port, "mx.example.test", timeout=10,
        want_exit_ip=True)
    assert (ok, exit_ip, reason) == (True, "2001:db8:1:2::77", "ok"), (ok, exit_ip, reason)
    assert asked == [("mx.example.test", 25)]


@needs_v6_loopback
def test_whois_through_an_ipv6_proxy():
    from core.whois_client import _whois_ask

    srv = _listen6()

    def serve():
        conn, _ = srv.accept()
        conn.recv(256)
        conn.sendall(b"Domain Name: EXAMPLE.TEST\r\nCreation Date: 2001-01-01\r\n")
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    socks_port, asked = _socks5_to(srv.getsockname()[1])
    text = _whois_ask("whois.example.test", "example.test",
                      proxy="[::1]:%d" % socks_port, timeout=10)
    assert "Creation Date: 2001-01-01" in text
    assert asked == [("whois.example.test", 43)]


@needs_v6_loopback
def test_dns_over_tcp_through_an_ipv6_proxy(monkeypatch):
    import dns.message
    import dns.rrset

    import core.dns_resolver as dr

    srv = _listen6()

    def serve():
        conn, _ = srv.accept()
        size = struct.unpack(">H", conn.recv(2))[0]
        query = dns.message.from_wire(conn.recv(size))
        reply = dns.message.make_response(query)
        reply.answer.append(dns.rrset.from_text(
            query.question[0].name, 60, "IN", "A", "192.0.2.10"))
        wire = reply.to_wire()
        conn.sendall(struct.pack(">H", len(wire)) + wire)
        conn.close()

    threading.Thread(target=serve, daemon=True).start()
    socks_port, asked = _socks5_to(srv.getsockname()[1])
    monkeypatch.setattr(dr, "_is_local_address", lambda host: False)
    resolver = dr.ProxiedResolver(["192.0.2.53"], timeout=10)
    query = dns.message.make_query("mx.example.test", "A")
    response = resolver._ask_tcp("192.0.2.53", query, "[::1]:%d" % socks_port)
    assert response is not None
    assert "192.0.2.10" in response.to_text()
    assert asked == [("192.0.2.53", 53)]
