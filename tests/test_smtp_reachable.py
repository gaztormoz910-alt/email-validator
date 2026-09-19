# -*- coding: utf-8 -*-
"""SMTP-проверка: доказать, что она есть, и дать до неё дойти.

Владелец сказал, что SMTP-проверки у него нет. Проверено живым прогоном с
его машины БЕЗ ЕДИНОГО ПРОКСИ:

    порт 25 открыт, Gmail и Яндекс отвечают баннером 220
    nosuchbox-…@yandex.ru  -> Invalid/Bounce  «5.7.1 550 Получателя не существует»
    nosuchbox-…@gmail.com  -> Invalid/Bounce  «5.1.1 550 Получателя не существует»
    postmaster@yandex.ru   -> 250 OK, скор 50
    nosuchbox-…@mail.ru    -> Catch-All (недоказуемо) — распознан верно
    весь конвейер на шести адресах: шесть вердиктов за шестьдесят секунд

Проверка есть и работает. Причина, по которой её не видно, оказалась другой:
ОКНО НЕ ДАВАЛО ЗАПУСТИТЬСЯ БЕЗ ПРОКСИ. Список у владельца — двадцать шесть
тысяч бесплатных, живых из них полсотни; перебор при таймауте пятнадцать
секунд съедал двадцать с лишним минут, и до почт дело не доходило.

Здесь закрепляется и то, и другое: что код проверки на месте, и что дойти до
него теперь можно. Сеть в этих тестах НЕ трогается — живой прогон был
разовым доказательством, а набор должен идти на любой машине.
"""
# Исходник конвейера собирается по ВСЕМ его модулям: после
# разделения на примеси половина кода лежит не в core/pipeline.py,
# и чтение одного файла молча проверяло бы не то. См. tests/исходники.py.
from исходники import исходник_конвейера
import inspect
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


# ═══════════════════════════════ G1: код SMTP-проверки на месте

def test_exists_the_whole_smtp_dialogue():
    """Каждый шаг диалога с сервером — отдельным методом, а не заглушкой."""
    from core.network import NetworkValidator

    for name in ("check_email", "stealth_smtp_ping", "_do_single_ping",
                 "is_catch_all_domain", "postmaster_is_honored",
                 "_parse_smtp_response"):
        assert callable(getattr(NetworkValidator, name, None)), name


def test_exists_real_socket_on_port_25():
    """Проверка ходит на 25-й порт настоящим соединением.

    Не «предполагается»: в коде стоит именно connect на 25, и именно этот
    порт слушают почтовые серверы. 587 и 465 — для отправки через релей, к
    проверке существования ящика они отношения не имеют.
    """
    source = inspect.getsource(
        __import__("core.network", fromlist=["x"]))
    assert "server.connect(mx_record, 25)" in source


def test_exists_rcpt_to_is_the_probe():
    """Существование ящика доказывается командой RCPT TO, а не догадкой."""
    source = inspect.getsource(__import__("core.network", fromlist=["x"]))
    assert "server.rcpt(email)" in source
    assert "server.mail(from_addr)" in source


def test_exists_verdicts_come_from_the_server_answer():
    """Вердикт разбирается из ответа сервера — на живом корпусе ответов."""
    from core.smtp_codes import classify_smtp_response

    assert classify_smtp_response(250, "2.1.5 OK")["status"] == "valid"
    assert classify_smtp_response(
        550, "5.1.1 no such user")["status"] == "invalid"
    assert classify_smtp_response(
        550, "5.7.1 blocked by policy")["status"] == "unknown"


def test_exists_pipeline_actually_calls_it():
    """Конвейер зовёт сетевую проверку, а не обходит её стороной.

    Проверка именно этого: между «код есть» и «код работает на каждом адресе»
    была бы ровно та разница, о которой спрашивал владелец.
    """
    source = исходник_конвейера()
    assert "res = self.network.check_email(email)" in source


# ═══════════════════════════════ G2: до проверки можно дойти без прокси

def test_direct_run_is_allowed_without_proxies():
    """Окно требовало прокси и дальше не пускало.

    Движок ходить напрямую умеет и предупреждает об этом; запрет был только
    в окне — и стоил владельцу всей проверки.
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    sources = api.sources()
    assert sources["ready"] is True
    assert sources["direct"] is True


def test_direct_run_hint_names_who_will_not_answer():
    """Подсказка называет цену прямого прогона поимённо."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    hint = api.sources()["hint"]
    for name in ("Gmail", "Яндекс", "Yahoo", "AOL", "Outlook", "iCloud"):
        assert name in hint, hint


def test_direct_run_is_not_direct_when_proxies_are_loaded():
    """Обратная сторона: с прокси прогон прямым не считается."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})
    sources = api.sources()
    assert sources["direct"] is False
    assert sources["hint"] == "Всё готово — можно запускать"


def test_direct_run_still_needs_addresses():
    """Без базы запускать по-прежнему нечего."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    answer = api.start({})
    assert answer["ok"] is False
    assert "адреса" in answer["error"]


# ═══════════════════════════════ G3: молча напрямую не ходим

def test_consent_is_required_before_running_direct():
    """Прямой прогон раскрывает домашний IP — согласие должно быть осознанным."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    answer = api.start({})
    assert answer["ok"] is False
    assert answer.get("direct") is True
    assert "домашнего IP" in answer["error"]


def test_consent_given_lets_the_run_start():
    """Подтвердил — запускаем. Запрет как раз и стоил проверки почт."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    started = api.start({"allowDirect": True})
    try:
        assert started["ok"] is True
    finally:
        api.stop()


def test_consent_is_asked_by_the_window_too():
    """Спрашивает именно окно, а не только движок."""
    js = io.open(os.path.join(ROOT, "ui", "web", "app.js"), encoding="utf-8").read()
    assert "res.direct" in js
    assert "window.confirm" in js
    assert "allowDirect" in js


def test_consent_warning_reaches_the_log():
    """В логе прогона это тоже сказано — лог остаётся, всплывашка нет."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.start({"allowDirect": True})
    try:
        text = " ".join(line["text"] for line in api.log_tail()["log"])
        assert "домашнего IP" in text
    finally:
        api.stop()


# ═══════════════════════════════ G4: перебор прокси можно оборвать

def test_enough_stops_the_sweep_when_the_quota_is_reached():
    """Двадцать шесть тысяч бесплатных прокси — двадцать минут до первой почты.

    Останов ленивый: подача перестаёт отдавать новые адреса, начатые проверки
    доходят до конца. Резать их на полуслове значило бы оборвать соединения
    на чужих серверах.
    """
    from core import proxy_probe

    calls = {"fed": 0}

    def fake_checker(proxies, workers, timeout, mode, progress_callback):
        live = []
        for item in proxies:
            calls["fed"] += 1
            live.append(item)
            progress_callback(len(live), len(live), len(live))
        return live

    # Подменяем там, откуда его импортирует filter_live_proxies: импорт
    # лежит внутри функции, поэтому в самом proxy_probe имени нет.
    from core import async_proxy

    original = async_proxy.run_async_checker
    async_proxy.run_async_checker = lambda **kw: fake_checker(
        kw["proxies"], kw["workers"], kw["timeout"], kw["mode"],
        kw["progress_callback"])
    try:
        source = ("10.0.0.%d:8080" % i for i in range(1, 500))
        live, seen = proxy_probe.filter_live_proxies(
            source, timeout=1, threads=4, enough=25)
    finally:
        async_proxy.run_async_checker = original

    assert len(live) >= 25
    assert calls["fed"] < 100, "перебор не остановился: подано %d" % calls["fed"]


def test_enough_zero_checks_everything():
    """Ноль означает «проверить весь список» — так и должно быть."""
    from core import proxy_probe

    def fake_checker(proxies, workers, timeout, mode, progress_callback):
        live = []
        for item in proxies:
            live.append(item)
            progress_callback(len(live), len(live), len(live))
        return live

    # Подменяем там, откуда его импортирует filter_live_proxies: импорт
    # лежит внутри функции, поэтому в самом proxy_probe имени нет.
    from core import async_proxy

    original = async_proxy.run_async_checker
    async_proxy.run_async_checker = lambda **kw: fake_checker(
        kw["proxies"], kw["workers"], kw["timeout"], kw["mode"],
        kw["progress_callback"])
    try:
        source = ("10.0.0.%d:8080" % i for i in range(1, 60))
        live, seen = proxy_probe.filter_live_proxies(
            source, timeout=1, threads=4, enough=0)
    finally:
        async_proxy.run_async_checker = original

    assert seen == 59, seen


# ═══════════════════════════════ G5: сама собой остановка не включается

def test_opt_in_default_is_check_everything():
    """Больше прокси — реже каждый IP попадается почтовику на глаза.

    Решать этот размен владельцу, а не мне: по умолчанию перебираем всё.
    """
    from core.settings import DEFAULTS

    assert DEFAULTS["proxy_enough"] == 0


def test_opt_in_pipeline_reads_the_setting():
    """Конвейер берёт число из настроек, а не из константы в коде."""
    source = исходник_конвейера()
    assert 'setting("proxy_enough", 0)' in source
    assert "enough=max(0, enough)" in source


# ═══════════════════════════════ G6: итог перебора сказан вслух

def test_says_how_the_proxy_sweep_ended():
    """«Найдено 54 из 26390» не отвечает на вопрос «проверятся ли мои почты»."""
    source = исходник_конвейера()
    assert "живых %d из %d" in source


def test_says_what_zero_live_proxies_means():
    """Ноль живых — это ноль вердиктов, и так и надо сказать."""
    source = исходник_конвейера()
    assert "Вердиктов не будет" in source
    assert "make_vps_proxy" in source


def test_says_when_there_are_too_few():
    """Мало прокси — отдельная беда: почтовик считает нагрузку по IP."""
    source = исходник_конвейера()
    assert "Живых прокси всего" in source


# ═══════════════════════════════ G7: пересылку нельзя объявить одноразовой

RELAYS = ["duck.com", "relay.firefox.com", "privaterelay.appleid.com"]


@pytest.mark.parametrize("domain", RELAYS)
def test_relay_survives_an_external_blacklist(domain):
    """Пересылка — не временный ящик: письмо доходит до живого человека.

    Найдено полным прогоном: встроенный список исключал эти домены
    СОЗНАТЕЛЬНО — над строкой стоял комментарий об этом, — а автообновляемый
    data/disposable_more.txt возвращал duck.com обратно. Решение молча
    отменялось скачанным файлом, и адрес получал вердикт Trap/Disposable со
    скором ноль. Это ложный приговор живому контакту.
    """
    from core.disposable import extend_disposable_domains, is_disposable

    extend_disposable_domains([domain])
    assert is_disposable("user@" + domain) is False


def test_relay_guard_does_not_break_real_disposables():
    """Обратная сторона: настоящие одноразовые из списка по-прежнему ловятся."""
    from core.disposable import extend_disposable_domains, is_disposable

    extend_disposable_domains(["some-temp-domain-for-the-test.example"])
    assert is_disposable("user@some-temp-domain-for-the-test.example") is True
    assert is_disposable("user@mailinator.com") is True
    assert is_disposable("user@sub.mailinator.com") is True


def test_relay_guard_lists_exactly_what_the_comment_promised():
    """Защищены ровно те домены, которые встроенный список назвал не-одноразовыми."""
    from core.disposable import NEVER_DISPOSABLE

    assert set(NEVER_DISPOSABLE) == set(RELAYS)


def test_relay_is_actually_in_the_shipped_blacklist():
    """Проверка ловит настоящую беду, а не выдуманную.

    Если duck.com когда-нибудь уберут из скачиваемого списка, защита останется
    нужной — но именно эта проверка перестанет что-либо доказывать, и об этом
    лучше узнать здесь.
    """
    path = os.path.join(ROOT, "data", "disposable_more.txt")
    if not os.path.exists(path):
        pytest.skip("файл внешнего списка отсутствует")
    listed = {line.strip().lower()
              for line in io.open(path, encoding="utf-8", errors="replace")}
    assert "duck.com" in listed, "в списке больше нет duck.com — проверка холостая"
