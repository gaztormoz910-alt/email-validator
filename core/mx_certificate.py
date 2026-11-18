# core/mx_certificate.py
"""Чей почтовый сервер, по его TLS-сертификату (решение владельца 14.11.2026, п.12).

Зачем. Хостер почты определяется по имени MX (`_MX_PROVIDER_HINTS` в
core/provider.py): `aspmx.l.google.com` — Google Workspace. Но MX бывает
спрятан под именем самой компании — `mail.corp.example` — и тогда колонка
«Провайдер» говорила «Corporate», хотя письма принимает Microsoft 365 или
шлюз Proofpoint. Сертификат, который сервер показывает на STARTTLS, называет
настоящего хозяина: `*.mail.protection.outlook.com`, `mx.google.com`.

Что это НЕ делает — и почему. Вердикт «есть ящик / нет ящика» отсюда не
меняется никак: его по-прежнему решают RCPT и контрольная проба catch-all у
любого домена (core/network.py). Здесь только метка провайдера. Поэтому:
  * отдельное короткое соединение (EHLO, STARTTLS, сертификат, QUIT) — сессия
    проверки ящика не трогается, у неё нет ни одной новой команды;
  * любая неудача — None, то есть ровно прежнее «Corporate»;
  * один раз на MX-хост за процесс: у базы на тысячу адресов одной компании
    соединение одно, а не тысяча.

Подставной сертификат. Самоподписанный сертификат с именем `mx.google.com`
выпустит кто угодно. Поэтому имена берутся ТОЛЬКО из сертификата, цепочка
которого сходится к удостоверяющему центру из системного хранилища, и только
после завершённого рукопожатия — то есть сервер доказал, что владеет ключом.
Совпадения имени сертификата с именем MX не требуется: у спрятанного MX оно
и не совпадает, ради этого всё и делается. Купить у удостоверяющего центра
сертификат на чужое имя `google.com` нельзя — это и есть вся защита.
"""

import ssl
import threading

# Сколько раз пробовать хост, если ответа по существу не было (обрыв, тайм-аут
# через прокси). Окончательный ответ — сертификат, отказ проверки цепочки, нет
# STARTTLS — запоминается сразу и навсегда до конца процесса.
_ATTEMPTS_PER_HOST = 2

_lock = threading.Lock()
_known = {}          # mx_host -> провайдер или None (ответ окончательный)
_attempts = {}       # mx_host -> сколько неудачных попыток было


def _labels(name):
    if not isinstance(name, str):
        return []
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return [label for label in name.split(".") if label]


def _has_run(labels, hint_labels):
    """Встречается ли подсказка целыми метками подряд: `google` в mx.google.com.

    Подстрокой нельзя: `mail.googleplex-fans.example` — не Google, а при поиске
    подстрокой сертификат любой компании со словом google в имени дал бы чужого
    провайдера.
    """
    n = len(hint_labels)
    return n > 0 and any(labels[i:i + n] == hint_labels for i in range(len(labels) - n + 1))


def provider_from_names(names):
    """Провайдер по именам из сертификата; None — не узнан или имена спорят."""
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
    # Два разных провайдера в одном сертификате — смысл неизвестен; угадывать
    # между ними значило бы выбрать наугад.
    return found.pop() if len(found) == 1 else None


def names_from_peercert(cert):
    """DNS-имена из `getpeercert()`: subjectAltName, а без него — CN."""
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
    """Контекст, который проверяет цепочку, но не имя: см. шапку модуля."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def fetch_names(network, mx_host, proxy=None, context=None, port=25):
    """Имена из проверенного сертификата MX.

    Возвращает (окончательно, имена): (True, [...]) — сертификат получен;
    (True, []) — STARTTLS нет или цепочка не сошлась, спрашивать снова незачем;
    (False, []) — связи не было, можно попробовать позже.
    """
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
        try:
            server.starttls(context=context or verifying_context())
        except ssl.SSLCertVerificationError:
            # Самоподписанный, просроченный, от неизвестного центра — имён в
            # таком сертификате не верим, и ответ окончательный.
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
    """Провайдер MX по сертификату, с памятью на процесс. None — не узнан."""
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
    """Сбросить память (для тестов и нового прогона с другими прокси)."""
    with _lock:
        _known.clear()
        _attempts.clear()
