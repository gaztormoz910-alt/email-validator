# -*- coding: utf-8 -*-
import socket
from concurrent.futures import ThreadPoolExecutor

__all__ = ["probe_port25", "PORT25_HOSTS", "CONTROL_HOSTS"]

PORT25_HOSTS = ("gmail-smtp-in.l.google.com", "alt1.gmail-smtp-in.l.google.com",
                "mx.yandex.ru", "mxs.mail.ru")
CONTROL_HOSTS = (("www.google.com", 443), ("yandex.ru", 443))


def _стук(хост, порт, таймаут):
    try:
        адрес = socket.getaddrinfo(хост, порт, type=socket.SOCK_STREAM)[0][4]
    except Exception:
        return False, False
    try:
        with socket.create_connection(адрес[:2], timeout=таймаут):
            return True, True
    except Exception:
        return True, False


def probe_port25(hosts=PORT25_HOSTS, control=CONTROL_HOSTS, timeout=6, knock=None):
    knock = knock or _стук
    цели = [(h, 25) for h in hosts] + list(control)
    with ThreadPoolExecutor(max_workers=max(1, len(цели))) as pool:
        ответы = list(pool.map(lambda hp: knock(hp[0], hp[1], timeout), цели))
    почта = ответы[:len(hosts)]
    контроль = ответы[len(hosts):]
    открыто = sum(1 for _r, ok in почта if ok)
    разрешено = sum(1 for r, _ok in почта if r)
    контроль_ок = any(ok for _r, ok in контроль)
    if открыто:
        verdict = "open"
    elif разрешено and контроль_ок:
        verdict = "closed"
    else:
        verdict = "unknown"
    return {"verdict": verdict, "open": открыто, "tried": len(hosts),
            "resolved": разрешено, "control_ok": контроль_ок}
