import ssl
import threading

_ATTEMPTS_PER_HOST = 2

_lock = threading.Lock()
_known = {}
_attempts = {}


def _labels(name):
    if not isinstance(name, str):
        return []
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return [label for label in name.split(".") if label]


def _has_run(labels, hint_labels):
    n = len(hint_labels)
    return n > 0 and any(labels[i:i + n] == hint_labels for i in range(len(labels) - n + 1))


def provider_from_names(names):
    from core.provider import _MX_PROVIDER_HINTS

    if not isinstance(names, (list, tuple, set, frozenset)):
        return None
    found = set()
    for name in names:
        labels = _labels(name)
        if not labels:
            continue
        for hint, provider in _MX_PROVIDER_HINTS.items():
            if _has_run(labels, _labels(hint)):
                found.add(provider)
    return found.pop() if len(found) == 1 else None


def names_from_peercert(cert):
    if not isinstance(cert, dict):
        return []
    names = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
    if names:
        return names
    for rdn in cert.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                names.append(value)
    return names


def verifying_context():
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def fetch_names(network, mx_host, proxy=None, context=None, port=25):
    if getattr(network, "aborted", lambda: False)():
        return False, []
    server = None
    try:
        server = network._make_smtp_connection(proxy)
        code, _banner = server.connect(mx_host, port)
        if code != 220:
            return False, []
        server.ehlo(network._helo_for(proxy))
        if not server.has_extn("starttls"):
            return True, []
        server._host = mx_host
        try:
            server.starttls(context=context or verifying_context())
        except ssl.SSLCertVerificationError:
            return True, []
        return True, names_from_peercert(server.sock.getpeercert())
    except Exception:
        return False, []
    finally:
        if server is not None:
            finish = getattr(network, "_finish", None)
            try:
                if finish:
                    finish(server)
                else:
                    server.close()
            except Exception:
                pass


def provider_by_certificate(network, mx_host, proxy=None, context=None, port=25):
    if not isinstance(mx_host, str) or not mx_host or mx_host == "N/A":
        return None
    key = mx_host.lower().rstrip(".")
    with _lock:
        if key in _known:
            return _known[key]
        if _attempts.get(key, 0) >= _ATTEMPTS_PER_HOST:
            return None
    final, names = fetch_names(network, key, proxy=proxy, context=context, port=port)
    provider = provider_from_names(names) if final else None
    with _lock:
        if final:
            _known[key] = provider
        else:
            _attempts[key] = _attempts.get(key, 0) + 1
    return provider


def forget():
    with _lock:
        _known.clear()
        _attempts.clear()
