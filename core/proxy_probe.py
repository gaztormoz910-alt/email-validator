# core/proxy_probe.py
"""Профилирование прокси: живой ли, годен ли для ПОЧТЫ, кто он на выходе.

Разделение, ради которого модуль существует: «прокси живой» и «прокси годен
для валидации» — разные вещи, и путать их дорого. Живым для веба прокси
бывает почти всегда, а валидация требует открытого исходящего порта 25, и
проверять это надо соединением на 25-й порт с чтением баннера `220`, а не
HTTP-запросом.

Дальше идёт второе разделение, по провайдерам получателя:

* просто рабочий прокси открывает Gmail, Yandex, Proton и большинство
  корпоративных доменов;
* чистая репутация IP нужна для Outlook, Hotmail, Live, iCloud и GMX;
* PTR-запись (FCrDNS) нужна для Yahoo, AOL и Verizon — без неё они отвечают
  `550 5.7.25` ещё на MAIL FROM, и до проверки адреса дело не доходит.

Поэтому профиль каждого прокси — это не «жив/мёртв», а набор: выходной IP,
его ASN и страна, обратный DNS, присутствие в чёрных списках и результат
ПРЯМОЙ пробы Yahoo и iCloud. Прямая проба важнее вывода по PTR и спискам:
она отвечает на тот самый вопрос, который задаёт валидация.
"""
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor

import socks

import random
import threading

from core.proxy_transport import (PROXY_TYPES as _PROXY_TYPES, SocksSMTP,
                                  build_proxy_dict, _parse_proxy,
                                  _proxy_scheme, _EXIT_IP_RE,
                                  EXIT_IP_PROBE_HOST, PROXY_PROBE_TARGETS,
                                  PROBE_GMAIL, PROBE_OUTLOOK, PROBE_YAHOO,
                                  PROBE_ICLOUD)
from core.mail_constants import LEGIT_HELO_NAMES, MAIL_FROM_POOL

__all__ = ["probe_proxy_target", "get_proxy_exit_ip", "dedupe_proxies",
           "dedupe_proxies_stream", "is_dirty_rdns", "profile_proxies",
           "filter_live_proxies", "DIRTY_RDNS_KEYWORDS"]


DIRTY_RDNS_KEYWORDS = ("proxy", "vpn", "tor", "torexit", "exit", "anon",
                       "spam", "abuse", "dynamic", "dyn", "dhcp", "pool",
                       "dial", "dialup", "pppoe", "cable", "dsl")

_DIRTY_RDNS_RE = re.compile(
    r'(?:^|[.\-])(' + "|".join(DIRTY_RDNS_KEYWORDS) + r')(?:[.\-0-9]|$)')

# Почтовые шлюзы безопасности. Стоят ПЕРЕД корпоративным доменом и принимают

def probe_proxy_target(proxy, host, timeout=10, want_exit_ip=False):
    """Полная проба прокси до конкретного почтовика.

    Идём до MAIL FROM, а не до баннера: именно там Microsoft отвечает
    "550 5.7.1 Service unavailable, Client host [IP]", а Yahoo — 5.7.25.
    До этого этапа оба выглядят рабочими.

    Возвращает (ok, latency_ms, exit_ip, reason).
    """
    server = None
    started = time.monotonic()
    try:
        parsed = _parse_proxy(proxy)
        if not parsed:
            return (False, None, None, "неверный формат прокси")
        ip, port, user, password = parsed
        server = SocksSMTP(ip, port, proxy_user=user, proxy_pass=password,
                           timeout=timeout,
                           proxy_type=_PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5))
        server.connect(host, 25)
        latency = int((time.monotonic() - started) * 1000)

        _code, msg = server.ehlo(random.choice(LEGIT_HELO_NAMES))
        text = msg.decode('utf-8', 'ignore') if isinstance(msg, bytes) else str(msg)
        exit_ip = None
        if want_exit_ip:
            m = _EXIT_IP_RE.search(text)
            exit_ip = m.group(1) if m else None

        mail_code, mail_msg = server.mail(random.choice(MAIL_FROM_POOL))
        if mail_code >= 400:
            reason = mail_msg.decode('utf-8', 'ignore') if isinstance(mail_msg, bytes) else str(mail_msg)
            return (False, latency, exit_ip, f"{mail_code} {reason[:60]}")
        return (True, latency, exit_ip, "ok")
    except Exception as e:
        return (False, None, None, type(e).__name__)
    finally:
        if server:
            try:
                server.quit()
            except Exception:
                pass


def get_proxy_exit_ip(proxy, timeout=10):
    """Возвращает реальный выходной IP прокси или None.

    Спрашиваем у самого почтового сервера — стороннего сервиса не нужно,
    лимитов нет, и ответ гарантированно совпадает с тем, что увидит Yahoo.
    """
    _ok, _lat, exit_ip, _reason = probe_proxy_target(
        proxy, EXIT_IP_PROBE_HOST, timeout=timeout, want_exit_ip=True)
    return exit_ip


def dedupe_proxies(proxies):
    """Убирает повторы, сохраняя порядок.

    Один прокси, записанный дважды (или с разным регистром схемы), проверялся
    бы дважды и занимал два места в ротации.
    """
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return []
    seen = set()
    result = []
    for p in proxies:
        if not isinstance(p, str):
            continue
        norm = p.strip()
        if not norm:
            continue
        parsed = _parse_proxy(norm)
        # Ключ по разобранным частям: socks5://1.2.3.4:1080 и 1.2.3.4:1080 — одно
        key = (_proxy_scheme(norm), parsed) if parsed else norm.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(norm)
    return result


def dedupe_proxies_stream(proxies, max_keys=2_000_000):
    """Ленивый дедуп прокси: отдаёт уникальные по мере чтения.

    Зачем отдельно от dedupe_proxies. Та строит список из ВСЕГО входа, и на
    файле в миллионы строк это сотни мегабайт ОЗУ ещё до первого соединения.
    Здесь вход читается по строке, а наружу сразу уходит следующий уникальный
    прокси — потребитель (чекер) начинает работать, не дожидаясь конца файла.

    В памяти остаётся только множество ключей, и хранятся там ХЕШИ, а не сами
    строки: набор из миллиона кортежей весит сотни мегабайт, набор из миллиона
    64-битных чисел — единицы. Плата за это — теоретическая коллизия хешей, при
    которой один прокси из пары был бы принят за повтор. На двух миллионах
    записей вероятность такого события порядка одной десятимиллионной, а цена
    ошибки — один непроверенный прокси из миллиона, и это несопоставимо
    дешевле, чем исчерпать память на середине прогона.

    У множества есть и жёсткий потолок: после max_keys новые ключи не
    запоминаются, и дальше возможны повторы. Тот же размен, доведённый до
    конца: повтор дешевле, чем остановка.
    """
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return
    seen = set()
    capped = False
    for raw in proxies:
        if not isinstance(raw, str):
            continue
        norm = raw.strip()
        if not norm:
            continue
        parsed = _parse_proxy(norm)
        key = hash((_proxy_scheme(norm), parsed) if parsed else norm.lower())
        if not capped:
            if key in seen:
                continue
            seen.add(key)
            if len(seen) >= max_keys:
                capped = True
        yield norm


def is_dirty_rdns(hostname):
    """True, если имя из PTR выдаёт прокси/VPN/динамический IP.

    Почтовики штрафуют такие имена даже при валидном FCrDNS: по хосту видно,
    что письмо идёт не с нормального почтового сервера.

    Совпадение по границам ярлыка: pool-71-105.fios.verizon.net — динамика,
    а exitcom.net и hosting-provider.net — обычные хосты, и метить их грязными
    значит выбрасывать годные датацентровые прокси.
    """
    if not isinstance(hostname, str) or not hostname:
        return False
    return bool(_DIRTY_RDNS_RE.search(hostname.lower()))


def profile_proxies(proxies, timeout=10, workers=30, progress_callback=None,
                    probe_outlook=True):
    """Профилирует прокси и говорит, для каких провайдеров он пригоден.

    За один проход выясняем всё, что определяет пригодность:
      * реальный выходной IP (спрашиваем у Gmail — он сообщает его на EHLO)
      * задержку соединения (медленный прокси растягивает прогон)
      * PTR по выходному IP: три состояния, "не проверили" != "нет"
      * имя из PTR: proxy/vpn/tor в нём почтовики штрафуют
      * чёрные списки по выходному IP
      * реальную достижимость Microsoft — у него своя база репутации,
        и DNSBL её предсказывает лишь частично

    Возвращает {proxy: {exit_ip, latency_ms, has_ptr, rdns, rdns_dirty,
                        in_dnsbl, outlook_ok, outlook_reason}}.
    """
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return {}
    proxies = list(proxies)

    # Импорт локальный намеренно: core.network импортирует этот модуль, и
    # импорт на уровне файла замкнул бы круг. Валидатор нужен здесь ровно для
    # одного — спросить обратный DNS выходного адреса.
    from core.network import NetworkValidator

    # proxy_dns=False осознанно: здесь резолвятся обратные записи САМИХ прокси,
    # данных пользователя в этих запросах нет. Гнать их через проверяемый прокси
    # значило бы ставить качество профиля в зависимость от того, что мы измеряем.
    validator = NetworkValidator(timeout=timeout, proxy_dns=False)
    result = {}
    done = 0
    lock = threading.Lock()

    def profile_one(proxy):
        empty = {"exit_ip": None, "latency_ms": None, "has_ptr": None,
                 "rdns": None, "rdns_dirty": False, "in_dnsbl": False,
                 "outlook_ok": None, "outlook_reason": None,
                 "asn": None, "asn_country": "", "asn_org": "",
                 "ip_type": "unknown", "yahoo_ok": None, "icloud_ok": None}

        ok, latency, exit_ip, reason = probe_proxy_target(
            proxy, EXIT_IP_PROBE_HOST, timeout=timeout, want_exit_ip=True)
        if not exit_ip:
            empty["latency_ms"] = latency
            empty["outlook_reason"] = reason if not ok else None
            return proxy, empty

        # check_fcrdns различает "PTR нет" (False) и "проверить не удалось" (None).
        # Во время профилирования летят сотни параллельных DNS-запросов, и часть
        # ожидаемо отваливается по таймауту. Схлопывать None в False нельзя:
        # хороший прокси с PTR вылетел бы из пула Yahoo из-за случайного сбоя DNS.
        has_ptr = validator.check_fcrdns(exit_ip)
        if has_ptr is None:
            with validator._fcrdns_lock:
                validator._fcrdns_cache.pop(exit_ip, None)   # не кэшируем неудачу
            time.sleep(0.3)
            has_ptr = validator.check_fcrdns(exit_ip)        # вторая попытка

        rdns = validator.get_ptr_hostname(exit_ip)
        in_dnsbl = validator.check_dnsbl_ip(exit_ip)

        # ASN, страна и тип адреса. Датацентровый IP фильтры режут заметно
        # чаще резидентного, а страна нужна, чтобы подбирать прокси под гео
        # домена получателя. Раньше про выходной IP было известно только то,
        # числится ли он в чёрных списках.
        from core.proxy_profile import lookup_ip_meta
        meta = lookup_ip_meta(exit_ip, timeout=timeout,
                              proxies=build_proxy_dict(proxy))

        outlook_ok = None
        outlook_reason = None
        yahoo_ok = None
        icloud_ok = None
        if probe_outlook:
            o_ok, _lat, _ip, o_reason = probe_proxy_target(
                proxy, PROXY_PROBE_TARGETS[PROBE_OUTLOOK][1], timeout=timeout)
            outlook_ok, outlook_reason = o_ok, o_reason

            # Yahoo и iCloud спрашиваем напрямую. Каждая проба — один SMTP-диалог
            # до MAIL FROM; на старте это окупается тем, что маршрутизация потом
            # не гоняет письма туда, где их точно не примут.
            y_ok, _yl, _yi, _yr = probe_proxy_target(
                proxy, PROXY_PROBE_TARGETS[PROBE_YAHOO][1], timeout=timeout)
            yahoo_ok = y_ok
            i_ok, _il, _ii, _ir = probe_proxy_target(
                proxy, PROXY_PROBE_TARGETS[PROBE_ICLOUD][1], timeout=timeout)
            icloud_ok = i_ok

        return proxy, {"exit_ip": exit_ip, "latency_ms": latency,
                       "has_ptr": has_ptr, "rdns": rdns,
                       "rdns_dirty": is_dirty_rdns(rdns), "in_dnsbl": in_dnsbl,
                       "outlook_ok": outlook_ok, "outlook_reason": outlook_reason,
                       "asn": meta.get("asn"),
                       "asn_country": meta.get("asn_country", ""),
                       "asn_org": meta.get("asn_org", ""),
                       "ip_type": meta.get("ip_type", "unknown"),
                       "yahoo_ok": yahoo_ok, "icloud_ok": icloud_ok}

    # Число потоков приходит из ползунка. Раньше здесь стояло жёсткое 30, и на
    # списке в несколько тысяч прокси профилирование занимало часы: на каждый
    # прокси идут два полных SMTP-диалога плюс DNS. Потолок в 300 — та же
    # аппаратная защита, что и у валидации.
    try:
        workers = int(workers)
    except (TypeError, ValueError):
        workers = 30
    workers = max(1, min(workers, 300))

    with ThreadPoolExecutor(max_workers=min(workers, max(1, len(proxies)))) as pool:
        for proxy, info in pool.map(profile_one, proxies):
            result[proxy] = info
            with lock:
                done += 1
                if progress_callback and (done % 50 == 0 or done == len(proxies)):
                    ptr_n = sum(1 for v in result.values() if v["has_ptr"] is True)
                    bl_n = sum(1 for v in result.values() if v["in_dnsbl"])
                    progress_callback(done, len(proxies), ptr_n, bl_n)

    return result


def filter_live_proxies(proxies, timeout, threads=100, progress_callback=None, log_callback=None):
    """Проверяет прокси и возвращает (живые, сколько всего увидели).

    Вход может быть генератором: список в миллионы строк материализовать
    нельзя. Поэтому общее число возвращается ВТОРЫМ значением — заранее его
    никто не знает, оно становится известно только по мере чтения.
    """
    if not proxies or isinstance(proxies, (str, bytes)) or not hasattr(proxies, "__iter__"):
        return [], 0
    from core.async_proxy import run_async_checker

    def on_prog(c, t, l):
        if progress_callback:
            progress_callback(c, t)
        if log_callback:
            if c % 100 == 0 or c == t:
                # Не «c/t»: дробь читается как доля от известного целого, а
                # тут второе число — лишь «сколько прочитано на сейчас».
                # Источник ещё читается, и итог станет известен только в конце.
                log_callback(
                    f"[PROXY] Проверено: {c} | Прочитано: {t} | Рабочих: {l}",
                    "info")

    seen = {"total": 0}

    def counted(source):
        for item in source:
            seen["total"] += 1
            yield item

    live_proxies = run_async_checker(
        proxies=counted(proxies),
        workers=threads,
        timeout=timeout,
        mode="smtp",
        progress_callback=on_prog
    )

    return live_proxies, seen["total"]
