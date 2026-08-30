# core/proxy_profile.py
"""Что на самом деле представляет собой пул прокси.

Три вещи, которых профилировщик раньше не знал, хотя данные для двух из них
уже собирал:

1. СКОЛЬКО В ПУЛЕ РАЗНЫХ ВЫХОДНЫХ IP. Сто прокси могут выходить через один
   адрес — тогда «ротация из ста» это ротация из одного, и почтовик видит
   ровно тот же IP каждый раз. Выходной IP профилировщик уже спрашивал у
   Gmail, но по нему ничего не схлопывал.

2. ЧТО ЭТО ЗА IP. Датацентровый, резидентный или мобильный — от этого прямо
   зависит, пропустит ли письмо фильтр. Определяется по ASN и организации
   владельца через RDAP: bootstrap-сервис отдаёт и то, и страну.

3. ЖИВ ЛИ ПРОКСИ, У КОТОРОГО ЗАКРЫТ 25 ПОРТ. Раньше оба случая давали одно
   «мёртв», и пользователь с полностью рабочим списком видел «ни один прокси
   не работает». Это разные диагнозы и разные действия: в первом случае нужен
   другой список, во втором — другой тариф у того же провайдера.
"""

import ipaddress
import json
import threading
import urllib.request

# Кто выдал адрес — по названию организации из RDAP. Списки намеренно короткие
# и общие: задача не назвать провайдера точно, а отличить датацентр от жилого
# сектора, потому что фильтры смотрят именно на это.
_DATACENTER_HINTS = (
    "amazon", "aws", "google", "microsoft", "azure", "digitalocean", "linode",
    "vultr", "hetzner", "ovh", "scaleway", "contabo", "leaseweb", "choopa",
    "oracle", "alibaba", "tencent", "cloudflare", "fastly", "akamai",
    "datacamp", "m247", "psychz", "quadranet", "colocrossing", "hostinger",
    "godaddy", "namecheap", "ionos", "1&1", "rackspace", "equinix",
    "server", "hosting", "host", "cloud", "datacenter", "data center",
    "colo", "vps", "dedicated", "netcup", "aruba", "serverius",
)

_MOBILE_HINTS = (
    "mobile", "cellular", "wireless", "gsm", "lte", "t-mobile", "vodafone",
    "orange", "telefonica", "mts", "megafon", "beeline", "tele2", "airtel",
    "jio", "verizon wireless", "at&t mobility", "sprint", "o2",
)

_RESIDENTIAL_HINTS = (
    "broadband", "cable", "dsl", "fiber", "fibre", "residential", "telecom",
    "communications", "internet service", "isp", "comcast", "charter",
    "spectrum", "cox", "centurylink", "frontier", "bt ", "sky broadband",
    "deutsche telekom", "rostelecom", "ttk", "dom.ru", "er-telecom",
)

RDAP_IP_ENDPOINT = "https://rdap.org/ip/{ip}"

_asn_cache = {}
_asn_lock = threading.Lock()


def classify_org(org_name):
    """Тип адреса по названию организации-владельца.

    Порядок проверок важен: мобильные операторы часто содержат в названии и
    слово telecom, поэтому мобильные признаки смотрятся раньше резидентных,
    а датацентровые — раньше обоих, потому что «Hosting Telecom Ltd» это
    датацентр, а не домашний интернет.
    """
    if not isinstance(org_name, str) or not org_name.strip():
        return "unknown"
    low = org_name.lower()
    if any(hint in low for hint in _DATACENTER_HINTS):
        return "datacenter"
    if any(hint in low for hint in _MOBILE_HINTS):
        return "mobile"
    if any(hint in low for hint in _RESIDENTIAL_HINTS):
        return "residential"
    return "unknown"


def _is_public_ip(ip):
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_loopback or addr.is_reserved
                or addr.is_link_local or addr.is_multicast)


def lookup_ip_meta(ip, timeout=8, proxies=None, fetcher=None):
    """ASN, страна, организация и тип адреса. Пустые поля — если не узнали.

    Запрос идёт через тот же прокси, что и всё остальное: адрес принадлежит
    прокси, но запрос о нём с реального IP всё равно связывает одно с другим.

    fetcher нужен тестам: подменяет сеть, не подменяя разбор ответа.
    """
    empty = {"asn": None, "asn_country": "", "asn_org": "", "ip_type": "unknown"}
    if not ip or not _is_public_ip(ip):
        return dict(empty)

    with _asn_lock:
        if ip in _asn_cache:
            return dict(_asn_cache[ip])

    try:
        if fetcher is not None:
            data = fetcher(ip)
        elif proxies:
            import requests
            response = requests.get(RDAP_IP_ENDPOINT.format(ip=ip), timeout=timeout,
                                    proxies=proxies,
                                    headers={"User-Agent": "Mozilla/5.0"})
            if response.status_code != 200:
                return dict(empty)
            data = response.json()
        else:
            request = urllib.request.Request(RDAP_IP_ENDPOINT.format(ip=ip),
                                             headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(request, timeout=timeout) as response:
                data = json.loads(response.read().decode("utf-8", "ignore"))
    except Exception:
        return dict(empty)

    if not isinstance(data, dict):
        return dict(empty)

    org = ""
    for entity in data.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        for item in entity.get("vcardArray") or []:
            if not isinstance(item, list):
                continue
            for field in item:
                if (isinstance(field, list) and len(field) >= 4
                        and field[0] == "fn" and isinstance(field[3], str)):
                    org = field[3]
                    break
            if org:
                break
        if org:
            break
    if not org:
        org = data.get("name") or ""

    asn = None
    for key in ("handle", "startAddress"):
        value = data.get(key)
        if isinstance(value, str) and value.upper().startswith("AS"):
            digits = "".join(ch for ch in value if ch.isdigit())
            if digits:
                asn = int(digits)
                break
    if asn is None:
        for entry in data.get("arin_originas0_originautnums") or []:
            try:
                asn = int(entry)
                break
            except (TypeError, ValueError):
                continue

    meta = {
        "asn": asn,
        "asn_country": (data.get("country") or "").upper(),
        "asn_org": org,
        "ip_type": classify_org(org),
    }
    with _asn_lock:
        _asn_cache[ip] = dict(meta)
    return meta


def group_by_exit_ip(profiles):
    """{выходной IP: [прокси]} — только для тех, у кого IP известен.

    Это и есть настоящий размер ротации: почтовик видит ключи этого словаря,
    а не число строк в файле прокси.
    """
    groups = {}
    if not isinstance(profiles, dict):
        return groups
    for proxy, info in profiles.items():
        if not isinstance(info, dict):
            continue
        exit_ip = info.get("exit_ip")
        if not exit_ip:
            continue
        groups.setdefault(exit_ip, []).append(proxy)
    return groups


def rotation_report(profiles):
    """Честная сводка по пулу.

    Возвращает:
        total          — сколько прокси в пуле
        known_ip       — у скольких выходной IP определён
        unique_ips     — сколько РАЗНЫХ адресов видят почтовики
        duplicates     — сколько прокси лишние (дубли по выходному IP)
        largest_group  — размер самой крупной группы с общим IP
        by_type        — разбивка по типу адреса
    """
    profiles = profiles if isinstance(profiles, dict) else {}
    groups = group_by_exit_ip(profiles)
    known = sum(len(items) for items in groups.values())
    unique = len(groups)

    by_type = {}
    for exit_ip, items in groups.items():
        info = profiles.get(items[0]) or {}
        kind = info.get("ip_type") or "unknown"
        by_type[kind] = by_type.get(kind, 0) + 1

    return {
        "total": len(profiles),
        "known_ip": known,
        "unique_ips": unique,
        "duplicates": max(0, known - unique),
        "largest_group": max((len(v) for v in groups.values()), default=0),
        "by_type": by_type,
    }


def pick_one_per_exit_ip(profiles, prefer=None):
    """Оставляет по одному прокси на каждый выходной IP.

    Остальные из группы не выбрасываются вызывающим кодом насовсем — они
    остаются запасом на случай, если выбранный умрёт. Но в ротации место
    занимает один: гонять письма через десять входов в один и тот же выход
    бессмысленно, а нагрузку на репутацию этого IP умножает вдесятеро.

    prefer(proxy, info) -> сортируемый ключ; меньше значит лучше. По умолчанию
    предпочитается меньшая задержка.
    """
    def default_prefer(_proxy, info):
        latency = info.get("latency_ms")
        return latency if isinstance(latency, (int, float)) else 10 ** 9

    chooser = prefer or default_prefer
    chosen, spare = [], {}
    if not isinstance(profiles, dict):
        return chosen, spare
    for exit_ip, items in group_by_exit_ip(profiles).items():
        ranked = sorted(items, key=lambda p: chooser(p, profiles.get(p) or {}))
        chosen.append(ranked[0])
        if len(ranked) > 1:
            spare[exit_ip] = ranked[1:]

    # Прокси без известного выходного IP не схлопываем: мы про них ничего не
    # знаем, и выбросить их означало бы сузить пул на догадке.
    for proxy, info in profiles.items():
        if isinstance(info, dict) and not info.get("exit_ip"):
            chosen.append(proxy)

    return chosen, spare


# Что каждому провайдеру нужно от выходного IP. Ключ — как показываем,
# значение — функция «годится ли этот профиль».
#
# Зачем таблица. Раньше пригодность разъяснялась строчками лога, которые
# уезжали вверх и терялись. Пользователь тратит деньги на прокси и должен
# видеть глазами, какие письма он сейчас проверить МОЖЕТ, а какие нет.
def _fit_yahoo(info):
    """Yahoo/AOL пускают только IP с обратным DNS (FCrDNS)."""
    if not isinstance(info, dict):
        return False
    if info.get("yahoo_ok") is not None:
        return bool(info["yahoo_ok"])       # спросили напрямую — это факт
    if info.get("has_ptr") is True:
        return True
    if info.get("has_ptr") is None:
        return None                          # PTR не проверили — вывода нет
    return False


def _fit_clean_ip(info, direct_key):
    """Outlook/iCloud/GMX смотрят на репутацию адреса."""
    if not isinstance(info, dict):
        return False
    direct = info.get(direct_key)
    if direct is not None:
        return bool(direct)
    if info.get("in_dnsbl") or info.get("rdns_dirty"):
        return False
    if info.get("exit_ip"):
        return None                          # напрямую не спрашивали
    return None


PROVIDER_FITNESS = {
    "Gmail / Yandex": lambda info: bool(info.get("exit_ip")),
    "Yahoo / AOL": _fit_yahoo,
    "Outlook / Hotmail": lambda info: _fit_clean_ip(info, "outlook_ok"),
    "iCloud / GMX": lambda info: _fit_clean_ip(info, "icloud_ok"),
}


def provider_fitness(profiles):
    """{провайдер: {"ok": n, "no": n, "unknown": n}} по всему пулу."""
    profiles = profiles if isinstance(profiles, dict) else {}
    report = {}
    for label, test in PROVIDER_FITNESS.items():
        counts = {"ok": 0, "no": 0, "unknown": 0}
        for info in profiles.values():
            if not isinstance(info, dict):
                continue
            try:
                verdict = test(info)
            except Exception:
                verdict = None
            if verdict is True:
                counts["ok"] += 1
            elif verdict is False:
                counts["no"] += 1
            else:
                counts["unknown"] += 1
        report[label] = counts
    return report


def pool_summary(profiles):
    """Единая сводка по пулу для интерфейса.

    Собрана здесь, а не в окне, по двум причинам: её можно проверить тестом
    без Tk, и одни и те же числа тогда попадают и в панель, и в лог, и в CLI —
    расходиться им негде.
    """
    profiles = profiles if isinstance(profiles, dict) else {}
    summary = rotation_report(profiles)

    values = [info for info in profiles.values() if isinstance(info, dict)]
    latencies = sorted(v["latency_ms"] for v in values
                       if isinstance(v.get("latency_ms"), (int, float)))

    summary.update({
        "with_ptr": sum(1 for v in values if v.get("has_ptr") is True),
        "ptr_unknown": sum(1 for v in values if v.get("has_ptr") is None),
        "in_dnsbl": sum(1 for v in values if v.get("in_dnsbl")),
        "rdns_dirty": sum(1 for v in values if v.get("rdns_dirty")),
        "latency_median": latencies[len(latencies) // 2] if latencies else None,
        "latency_min": latencies[0] if latencies else None,
        "latency_max": latencies[-1] if latencies else None,
        "countries": _country_breakdown(values),
        "fitness": provider_fitness(profiles),
    })
    return summary


def _country_breakdown(values):
    """{страна: сколько РАЗНЫХ выходных адресов}. Считаем адреса, не строки."""
    seen_ip = set()
    counts = {}
    if values is None or not hasattr(values, "__iter__"):
        return counts
    for info in values:
        if not isinstance(info, dict):
            continue
        exit_ip = info.get("exit_ip")
        if not exit_ip or exit_ip in seen_ip:
            continue
        seen_ip.add(exit_ip)
        country = (info.get("asn_country") or "").upper() or "??"
        counts[country] = counts.get(country, 0) + 1
    return counts


# Провайдеры, у которых требования к нашему адресу жёстче прочих. Порядок —
# по доле в типичной базе: gmail проверяется всегда и почти всем, yahoo и
# outlook закрывают заметный кусок, icloud поменьше.
# Имена берутся ИЗ PROVIDER_FITNESS, а не переписываются рядом: свой список
# разошёлся с настоящим на первом же прогоне («Gmail» против «Gmail / Yandex»)
# и молча отчитался, что доступных провайдеров нет вовсе.
_READINESS_ORDER = tuple(PROVIDER_FITNESS)

# Кто обязателен: без него проверять нечего вообще. Остальные лишь сужают
# охват.
_READINESS_REQUIRED = "Gmail / Yandex"

# Что именно чинить, если провайдер закрыт. Владельцу нужен не диагноз, а
# следующий шаг: «нет PTR» само по себе не подсказывает, что делать.
_READINESS_FIX = {
    "Gmail / Yandex": "прокси не открывает порт 25 — нужен другой поставщик или свой VPS",
    "Outlook / Hotmail": "выходной IP в чёрных списках или с плохой репутацией — нужен чистый адрес",
    "Yahoo / AOL": "у выходного IP нет обратной записи (PTR) — её выдаёт хостер VPS",
    "iCloud / GMX": "выходной IP с плохой репутацией — нужен чистый адрес",
}


def readiness_report(profiles):
    """Что владелец сможет проверить этими прокси, а что нет.

    Зачем отдельно от pool_summary. Сводка отвечает на вопрос «какие у меня
    прокси», а этот отчёт — на вопрос «стоит ли вообще запускать». Разница
    практическая: прогон без годных прокси возвращает сплошное «не доказано»,
    и понимает это владелец только через полчаса, глядя в лог. Лучше сказать
    заранее и назвать причину.

    Возвращает {"ready": bool, "usable": n, "total": n,
                "providers": [{name, ok, reason}], "verdict": текст}.
    """
    profiles = profiles if isinstance(profiles, dict) else {}
    values = [info for info in profiles.values() if isinstance(info, dict)]
    total = len(values)

    fitness = provider_fitness(profiles)
    providers = []
    for name in _READINESS_ORDER:
        counts = fitness.get(name) or {}
        ok = int(counts.get("ok", 0))
        providers.append({
            "name": name,
            "ok": ok,
            "reason": "" if ok else _READINESS_FIX.get(name, ""),
        })

    # Годным считаем прокси, который хотя бы куда-то пускает: без этого он не
    # проверит ни одного адреса, сколько бы ни было у него хороших признаков.
    usable = sum(1 for v in values
                 if v.get("exit_ip") and v.get("outlook_ok") is not None
                 or v.get("exit_ip"))
    gmail_ok = next((p["ok"] for p in providers
                     if p["name"] == _READINESS_REQUIRED), 0)

    if not total:
        verdict = ("Прокси не загружены. Проверка пойдёт с вашего домашнего "
                   "адреса: Yahoo, AOL и Outlook на такой не отвечают, и их "
                   "адреса уйдут в «не доказано».")
        ready = False
    elif not gmail_ok:
        verdict = ("Ни один прокси не открывает порт 25 — проверить нельзя "
                   "ничего. Порты 587 и 465 для валидации не годятся: они для "
                   "отправки через релей.")
        ready = False
    else:
        closed = [p["name"] for p in providers if not p["ok"]]
        if closed:
            verdict = ("Проверять можно, но %s останутся недоказанными: %s."
                       % (", ".join(closed),
                          "; ".join(p["reason"] for p in providers
                                    if not p["ok"] and p["reason"])))
        else:
            verdict = "Все проверенные провайдеры доступны."
        ready = True

    return {"ready": ready, "usable": usable, "total": total,
            "providers": providers, "verdict": verdict}
