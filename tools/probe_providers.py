#!/usr/bin/env python
"""Живая проба почтовиков: врёт ли сервер на заведомо несуществующий ящик.

Зачем это нужно владельцу базы. Поведение почтовых сервисов меняется без
объявлений, а от него напрямую зависит, какой вердикт можно ставить:

* Сервер, который отвечает `550 ... no such user`, проверяется честно —
  его `Invalid` можно верить.
* Сервер, который отвечает `250 OK` на ЛЮБОЙ выдуманный адрес, catch-all.
  Его нельзя пропускать мимо детектора catch-all: иначе все его мёртвые
  ящики уедут в Valid и превратятся в отскоки.
* Сервер, который отшивает по репутации IP или требует обратный DNS,
  не проверяется С ЭТОГО адреса. Это `Unknown`, а не «ящика нет».

Проба спрашивает у каждого почтовика случайный адрес, которого заведомо не
существует, и печатает, что он ответил. Запускать раз в несколько месяцев и
после смены прокси: результат прямо говорит, каким вердиктам сегодня можно
верить, а каким нет.

    python tools/probe_providers.py
    python tools/probe_providers.py --proxies proxies.txt
    python tools/probe_providers.py --domains mail.ru,web.de,seznam.cz

Выход: 0, если ни одно допущение кода не разошлось с ответом сервера.
"""
import argparse
import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass


# Что код ожидает от каждого почтовика. Расхождение здесь — не мелочь:
# именно из него получаются ложные Valid и ложные Invalid.
#
# "honest"    — отвечает 550 на несуществующий ящик, приговор законен
# "catchall"  — отвечает 250 на что угодно, приговор невозможен
# "ip-gated"  — отшивает по репутации IP или требует PTR, ответ зависит от
#               того, откуда спрашивать; проверять «не сходится» нельзя
EXPECTED = {
    "gmail.com": "honest",
    "googlemail.com": "honest",
    "yandex.ru": "honest",
    "proton.me": "honest",
    "protonmail.com": "honest",
    "zoho.com": "honest",
    "mail.ru": "catchall",
    "bk.ru": "catchall",
    "inbox.ru": "catchall",
    "list.ru": "catchall",
    "icloud.com": "ip-gated",
    "outlook.com": "ip-gated",
    "hotmail.com": "ip-gated",
    "live.com": "ip-gated",
    "gmx.com": "ip-gated",
    "yahoo.com": "ip-gated",
    "aol.com": "ip-gated",
}

VERDICT_MEANING = {
    "invalid": "сервер прямо сказал, что ящика нет — ему можно верить",
    "valid": "принял ВЫДУМАННЫЙ адрес — это catch-all, приговор невозможен",
    "catchall": "принял выдуманный адрес — catch-all",
    "risky": "ответ неоднозначный",
    "unknown": "не проверяется с этого адреса (репутация IP, PTR, отказ)",
    "greylisted": "попросил прийти позже",
}


def load_proxies(path):
    if not path:
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        return [line.strip() for line in handle if line.strip()]


def probe(validator, domain):
    """Спрашивает почтовик о заведомо несуществующем ящике."""
    fake = f"{uuid.uuid4().hex[:20]}@{domain}"
    try:
        mx_records = validator.get_mx_records(domain)
    except Exception as exc:
        return "ошибка", f"MX: {type(exc).__name__}: {exc}"
    if not mx_records:
        return "нет MX", "домен не принимает почту"
    try:
        result = validator.stealth_smtp_ping(fake, mx_records[:1])
    except Exception as exc:
        return "ошибка", f"{type(exc).__name__}: {exc}"
    return result.get("status", "?"), (result.get("reason") or "").strip()


def disagreement(domain, status):
    """Расходится ли ответ сервера с тем, что заложено в коде.

    Про "ip-gated" ничего утверждать нельзя: их ответ зависит от того, с
    какого адреса спрашивать, и «не пустили» — нормальный исход, а не
    расхождение.
    """
    expected = EXPECTED.get(domain)
    if expected is None or expected == "ip-gated":
        return ""
    if expected == "honest" and status == "invalid":
        return ""
    if expected == "catchall" and status in ("valid", "catchall"):
        return ""
    if status in ("unknown", "greylisted", "ошибка", "нет MX"):
        # Не дошли до ответа о ящике — утверждать нечего.
        return ""
    if expected == "honest" and status in ("valid", "catchall"):
        return ("код считает домен честным, а он принял ВЫДУМАННЫЙ адрес — "
                "его мёртвые ящики уйдут в Valid")
    if expected == "catchall" and status == "invalid":
        return ("код считает домен catch-all, а он честно отверг выдуманный "
                "адрес — проверку по нему можно ужесточить")
    return ""


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--proxies", help="файл со SOCKS5-прокси")
    parser.add_argument("--timeout", type=int, default=12)
    parser.add_argument("--domains", help="свой список доменов через запятую")
    args = parser.parse_args()

    from core.network import NetworkValidator

    domains = ([d.strip().lower() for d in args.domains.split(",") if d.strip()]
               if args.domains else list(EXPECTED))
    validator = NetworkValidator(timeout=args.timeout,
                                 proxies=load_proxies(args.proxies))

    print("Спрашиваю каждый почтовик о заведомо несуществующем ящике.")
    print("Прямое соединение" if not args.proxies else f"Через прокси: {args.proxies}")
    print()
    print(f"{'домен':18s} {'вердикт':12s} {'ожидалось':10s} ответ сервера")
    print("-" * 100)

    problems = []
    for domain in domains:
        status, reason = probe(validator, domain)
        expected = EXPECTED.get(domain, "-")
        print(f"{domain:18s} {status:12s} {expected:10s} {reason[:58]}")
        note = disagreement(domain, status)
        if note:
            problems.append((domain, status, note))

    print()
    print("Как читать вердикт:")
    for name, meaning in VERDICT_MEANING.items():
        print(f"  {name:12s} — {meaning}")

    print()
    if problems:
        print("РАСХОЖДЕНИЯ С ТЕМ, ЧТО ЗАЛОЖЕНО В КОДЕ:")
        for domain, status, note in problems:
            print(f"  {domain}: получено «{status}» — {note}")
        print("PROVIDER-PROBE-MISMATCH")
        return 1
    print("Ни одно допущение кода не разошлось с ответом сервера.")
    print("PROVIDER-PROBE-OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
