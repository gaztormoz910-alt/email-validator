# -*- coding: utf-8 -*-
"""Открыт ли с этого компьютера исходящий порт 25 — до того, как начать прогон.

ЗАЧЕМ. Почтовые серверы принимают проверку только на 25-м порту, а многие
провайдеры его закрывают. Прямой прогон (без прокси) при закрытом порте не
проверяет НИ ОДНОГО ящика, но выглядит как работа: каждый адрес ждёт таймаута
на каждом MX, потом дважды уходит на перепроверку, и через несколько часов
вся база оказывается «Неясно». Замерено 27.09.2026 на машине владельца:
порт 25 закрыт у 0 из 4 почтовиков при открытых 443/587/465, одна прямая
проверка postmaster@gmail.com — 28.3 с и «Timeout» (аудит, D4).

КАК РЕШАЕТСЯ. Пробуем соединиться на 25 с несколькими крупными почтовиками
параллельно. «Закрыт» — только когда НИ ОДИН не ответил, хотя хоть одно имя
разрешилось и КОНТРОЛЬ (обычный HTTPS тех же служб) проходит: иначе это не
закрытый порт, а отсутствие сети, и вывод о порте делать нельзя.
"""
import socket
from concurrent.futures import ThreadPoolExecutor

__all__ = ["probe_port25", "PORT25_HOSTS", "CONTROL_HOSTS"]

PORT25_HOSTS = ("gmail-smtp-in.l.google.com", "alt1.gmail-smtp-in.l.google.com",
                "mx.yandex.ru", "mxs.mail.ru")
CONTROL_HOSTS = (("www.google.com", 443), ("yandex.ru", 443))


def _стук(хост, порт, таймаут):
    """(разрешилось ли имя, соединились ли)."""
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
    """Итог проверки: {"verdict": "open"|"closed"|"unknown", ...}.

    knock(host, port, timeout) -> (resolved, connected) — подменяется в тестах.
    """
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
