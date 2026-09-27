# -*- coding: utf-8 -*-
"""Живой прогон тестовых файлов владельца 27.09.2026: найденное не вернётся.

Прогон test.txt через список прокси владельца (21 живой из 1394) дал
дефекты, которых не ловил ни один тест, — хотя по отдельности каждая
половина была покрыта:

1. «Итог: None=5». Пять доказанно живых Gmail вышли со статусом «None».
   `_revise(домены, None, оговорка)` отдавал поверхности `str(None)`, а обе
   поверхности понимают «статус не трогать» как None, а не как строку.
   Хранилище окна тестировалось вызовом с настоящим None — и было зелёным;
   путь через `_revise` не проверял никто.
2. Те же пять получили приписку «домен под подозрением на catch-all», хотя
   Gmail catch-all не бывает, а у остальных доменов «Годен» с 27.09 даётся
   только при отвергнутом выдуманном адресе.
3. Подсказка «имелся в виду gmail.com» для user@gamil.com (домен-опечатка из
   списка одноразовых) в выгрузку не попадала — только в карточку окна.
4. Журнал о прокси противоречил сам себе: «Outlook/iCloud/GMX пойдут через
   16 прокси», а двумя строками ниже — «Outlook / Hotmail — 0 годных».

Рядом с каждым правилом — контроль, на котором оно срабатывать не должно.
"""
from unittest import mock

import cli
from core.network import NetworkValidator
from core.pipeline import ValidationPipeline
import tests.test_audit6_fixes as стенд

# Стенд с поддельным почтовым сервером — тот же, что у исправлений аудита.
# Присваиванием, а не импортом имён: фикстуру pytest находит по имени в
# модуле, а pyflakes считает импорт, перекрытый параметром теста,
# «переопределением неиспользованного» — и tests/test_cleanup.py падает.
поднять = стенд.поднять
Принимает, валидатор, прогон = стенд.Принимает, стенд.валидатор, стенд.прогон


def _пайплайн(**ещё):
    строки = []
    callbacks = {
        "on_log": lambda текст, вид="info": строки.append(текст),
        "on_result": lambda *a, **k: None,
        "on_progress": lambda *a, **k: None,
        "on_complete": lambda *a, **k: None,
    }
    callbacks.update(ещё)
    return ValidationPipeline(callbacks), строки


# ══════════════════════════ 1. «статус не трогать» — это None, а не «None»

def test_revise_hands_none_over_as_none():
    """Обработчик получает None, если статус трогать не надо, и строку — если надо."""
    полученные = []
    pipe, _ = _пайплайн(on_revise=lambda домены, статус, оговорка: полученные.append(статус) or 1)
    pipe._revise(["corp.example"], None, "оговорка")
    pipe._revise(["corp.example"], "Unknown", "разоблачён")
    assert полученные == [None, "Unknown"], полученные


def test_note_only_revision_keeps_live_address_valid_in_window(tmp_path):
    """Путь целиком: конвейер -> хранилище окна. Живой адрес остаётся «Годен».

    Прогон 27.09: окно получало строку «None», принимало её за статус и
    переносило живой адрес в «Неясно» со статусом «None».
    """
    from ui.result_store import ResultStore

    store = ResultStore(path=str(tmp_path / "rows.sqlite"))
    try:
        store.append("a@corp.example", "Valid", "2.1.5 250 OK", "mx", {})
        pipe, _ = _пайплайн(on_revise=lambda домены, статус, оговорка: sum(
            store.revise_domain(д, статус, оговорка) for д in домены))
        pipe._revise(["corp.example"], None, "под подозрением")
        assert store.counts()["valid"] == 1, store.counts()
        строка = store.page(groups=["valid"])[0]
        assert строка["status"] == "Valid", строка
        assert "под подозрением" in строка["reason"]
    finally:
        store.close()


def test_note_only_revision_control_real_status_still_moves(tmp_path):
    """Контроль: настоящий новый статус по-прежнему переносит строку."""
    from ui.result_store import ResultStore

    store = ResultStore(path=str(tmp_path / "rows.sqlite"))
    try:
        store.append("a@catchall.example", "Valid", "2.1.5 250 OK", "mx", {})
        pipe, _ = _пайплайн(on_revise=lambda домены, статус, оговорка: sum(
            store.revise_domain(д, статус, оговорка) for д in домены))
        pipe._revise(["catchall.example"], "Unknown", "принимает любой адрес")
        assert store.counts()["valid"] == 0
        assert store.page(groups=["unknown"])[0]["status"] == "Unknown"
    finally:
        store.close()


# ══════════════════════ 2. подозрение не спорит с доказанным «не catch-all»

def test_honest_domain_where_everyone_is_alive_stays_valid(monkeypatch, поднять):
    """Пять живых на честном домене: все «Годен», без приписки подозрения.

    Сервер отвергает выдуманный адрес — catch-all опровергнут фактом, и
    «все пятеро ответили 250» ничего к этому не добавляет. До исправления
    строки выходили со статусом «None» (дефект 1) и с подозрением (дефект 2).
    """
    имена = ["anna.ivanova", "boris.orlov", "vera.lebedeva", "gleb.sokolov", "dina.markova"]
    порт = поднять(Принимает(*имена))
    итог = прогон(monkeypatch, валидатор(monkeypatch, порт),
                  ["%s@all-alive-corp.ru" % и for и in имена])
    assert len(итог) == 5, итог
    for адрес, (статус, причина, _) in итог.items():
        assert статус == "Valid", (адрес, статус, причина)
        assert "подозрени" not in причина, (адрес, причина)


def test_suspicion_still_annotates_when_catchall_not_disproven(monkeypatch, поднять):
    """Контроль: без опровержения подозрение по-прежнему приписывается.

    И только приписывается: статус остаётся «Годен». Эвристика не выключена,
    она лишь перестала спорить с фактом.
    """
    monkeypatch.setattr(ValidationPipeline, "_catchall_disproven",
                        lambda self, домен: False, raising=False)
    имена = ["anna.ivanova", "boris.orlov", "vera.lebedeva", "gleb.sokolov", "dina.markova"]
    порт = поднять(Принимает(*имена))
    итог = прогон(monkeypatch, валидатор(monkeypatch, порт),
                  ["%s@all-alive-corp.ru" % и for и in имена])
    assert len(итог) == 5, итог
    for адрес, (статус, причина, _) in итог.items():
        assert статус == "Valid", (адрес, статус, причина)
        assert "под подозрением на catch-all" in причина, (адрес, причина)


def test_catchall_disproven_only_by_fact():
    pipe, _ = _пайплайн()
    pipe.network = NetworkValidator(timeout=5)
    # Гигант: catch-all не бывает по устройству.
    assert pipe._catchall_disproven("gmail.com") is True
    # Выдуманный адрес отвергнут в этом прогоне.
    with pipe.network.catchall_lock:
        pipe.network.catchall_cache["honest.example"] = False
        pipe.network.catchall_cache["catchall.example"] = True
    assert pipe._catchall_disproven("honest.example") is True
    # Разоблачённый и неизвестный — не опровергнуты.
    assert pipe._catchall_disproven("catchall.example") is False
    assert pipe._catchall_disproven("never-asked.example") is False
    pipe.network = None
    assert pipe._catchall_disproven("gmail.com") is False


# ═══════════════════════════════ 3. подсказка об опечатке доходит до выгрузки

def test_cli_export_carries_typo_suggestion():
    строка = cli._row({"email": "user@gamil.com", "status": "Trap/Disposable",
                       "reason": "Disposable Email Domain", "mx": "N/A",
                       "data": {"suggested_email": "user@gmail.com"}})
    assert строка["suggested_email"] == "user@gmail.com"
    assert "suggested_email" in cli.EXPORT_FIELDS
    # Каждое поле строки объявлено в заголовке — иначе DictWriter упадёт.
    assert set(строка) <= set(cli.EXPORT_FIELDS), set(строка) - set(cli.EXPORT_FIELDS)


def test_cli_export_typo_suggestion_control_empty_without_hint():
    строка = cli._row({"email": "anna@corp.example", "status": "Valid",
                       "reason": "250", "mx": "mx", "data": {}})
    assert строка["suggested_email"] == ""


# ═══════════════════════════════════ 4. журнал о прокси не спорит сам с собой

ПРОКСИ = ["socks5://203.0.113.7:1080", "socks5://198.51.100.9:1080",
          "socks5://192.0.2.44:1080"]


def _журнал_профиля(профили):
    pipe, строки = _пайплайн()
    pipe.network = NetworkValidator(timeout=5, proxies=list(ПРОКСИ))
    pipe.network.recall_proxy_profiles = lambda live: {}
    with mock.patch("core.network.profile_proxies", return_value=профили):
        pipe._profile_live_proxies(ПРОКСИ, 5, 10)
    return строки


def _противоречия(строки):
    """Провайдер, про которого сказано и «пойдут через», и «0 годных»."""
    плохо = []
    for провайдер in ("Yahoo", "Outlook"):
        ноль = any(провайдер in s and "0 годных" in s for s in строки)
        пойдут = [s for s in строки if провайдер in s and "пойдут через" in s]
        if ноль and пойдут:
            плохо.append(пойдут[0])
    return плохо


def test_proxy_log_does_not_contradict_readiness():
    """Как в прогоне владельца: PTR один и «грязный», Microsoft не пустил никого."""
    профили = {
        ПРОКСИ[0]: {"exit_ip": "203.0.113.7", "has_ptr": True, "rdns_dirty": True,
                    "yahoo_ok": False, "in_dnsbl": False, "outlook_ok": False,
                    "latency_ms": 900},
        ПРОКСИ[1]: {"exit_ip": "198.51.100.9", "has_ptr": False, "rdns_dirty": False,
                    "in_dnsbl": False, "outlook_ok": False, "latency_ms": 1200},
        ПРОКСИ[2]: {"exit_ip": None, "has_ptr": None, "in_dnsbl": True,
                    "outlook_ok": None, "latency_ms": 4000},
    }
    строки = _журнал_профиля(профили)
    assert any("0 годных" in s for s in строки), строки
    assert _противоречия(строки) == [], _противоречия(строки)
    # И сказано, почему Yahoo не годится, — а не просто промолчано.
    assert any("PTR есть у 1" in s and "Yahoo" in s for s in строки), строки


def test_proxy_log_control_good_pool_is_announced():
    """Контроль: годные прокси по-прежнему называются годными."""
    профили = {
        ПРОКСИ[0]: {"exit_ip": "203.0.113.7", "has_ptr": True, "rdns_dirty": False,
                    "in_dnsbl": False, "outlook_ok": True, "latency_ms": 300},
        ПРОКСИ[1]: {"exit_ip": "198.51.100.9", "has_ptr": False, "rdns_dirty": False,
                    "in_dnsbl": False, "outlook_ok": True, "latency_ms": 300},
        ПРОКСИ[2]: {"exit_ip": "192.0.2.44", "has_ptr": False, "rdns_dirty": False,
                    "in_dnsbl": False, "outlook_ok": True, "latency_ms": 300},
    }
    строки = _журнал_профиля(профили)
    assert any("Yahoo/AOL пойдут через 1" in s for s in строки), строки
    assert any("Outlook" in s and "пойдут через 3" in s for s in строки), строки
    assert _противоречия(строки) == []



# ═════════════ 5. отвергнутая версия списка не качается при каждом запуске

def _список(*имена, живых=()):
    """Тело списка одноразовых: 200 выдуманных доменов плюс названные."""
    return "\n".join(list(живых) + list(имена)
                     + ["d%03d.disposable-sample.example" % i for i in range(200)])


class _Сервер:
    """Подмена urlopen: отвечает телом с ETag или 304, если метка знакома."""

    def __init__(self, тело, метка):
        self.тело, self.метка, self.запросы = тело, метка, []

    def __call__(self, запрос, timeout=15):
        import urllib.error
        знакомые = запрос.get_header("If-none-match") or ""
        self.запросы.append(знакомые)
        if self.метка in знакомые:
            raise urllib.error.HTTPError(запрос.full_url, 304, "Not Modified", {}, None)
        сервер = self

        class Ответ:
            headers = {"ETag": сервер.метка}

            def read(self):
                return сервер.тело.encode("utf-8")

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        return Ответ()


def _загрузчик(tmp_path, monkeypatch, сервер):
    import urllib.request
    from core.github_parser import BlacklistDownloader
    monkeypatch.setattr(urllib.request, "urlopen", сервер)
    d = BlacklistDownloader(data_dir=str(tmp_path))
    d.sources = {"disposable.txt": "https://lists.example/disposable.txt"}
    (tmp_path / "disposable.txt").write_text("mailinator.com\n", encoding="utf-8")
    return d


def test_rejected_list_version_is_not_downloaded_again(tmp_path, monkeypatch):
    """Отвергнутая версия: второй запуск спрашивает её ETag и получает 304.

    Прогон 27.09: три списка скачивались и отвергались при каждом старте —
    72 с до первой проверки.
    """
    from core.filters import BLACKLIST_SENTINELS
    живые = sorted(BLACKLIST_SENTINELS)[:40]          # 40 из 240 — больше 5%
    сервер = _Сервер(_список(живых=живые), '"v1"')
    d = _загрузчик(tmp_path, monkeypatch, сервер)
    первый = d.download_all()
    второй = d.download_all()
    assert any("обновление не взято" in s for s in первый), первый
    assert сервер.запросы[0] == "", "в первый раз метки быть не могло"
    assert '"v1"' in сервер.запросы[1], "отвергнутую версию спросили заново: %r" % сервер.запросы
    assert any("уже отклонена" in s for s in второй), второй
    assert (tmp_path / "disposable.txt").read_text(encoding="utf-8") == "mailinator.com\n"


def test_list_with_a_few_disputed_names_is_taken(tmp_path, monkeypatch):
    """Два спорных имени на двести — обновление берётся, как и у фильтра.

    Прогон 27.09: все три списка «не взяты» из-за двух-трёх имён вроде
    duck.com, и с 12.09 новые одноразовые домены до программы не доходили.
    Фильтр сам выбрасывает спорные имена при загрузке — проверено ниже.
    """
    from core.filters import SpamFilter
    сервер = _Сервер(_список("fresh-temp-box.example", живых=["duck.com", "addy.io"]), '"v2"')
    d = _загрузчик(tmp_path, monkeypatch, сервер)
    отчёт = d.download_all()
    assert not any("не взято" in s for s in отчёт), отчёт
    текст = (tmp_path / "disposable.txt").read_text(encoding="utf-8")
    assert "fresh-temp-box.example" in текст
    ф = SpamFilter(data_dir=str(tmp_path))
    assert ф.is_spam_or_disposable("x@fresh-temp-box.example")
    assert not ф.is_spam_or_disposable("x@duck.com"), "живой почтовик попал в одноразовые"
    # Взятая версия стирает память об отвергнутой.
    import json
    with open(tmp_path / ".blacklist_etags.json", encoding="utf-8") as f:
        метки = json.load(f)
    assert метки.get("disposable.txt") == '"v2"'
    assert not any(k.endswith("#rejected") for k in метки), метки


def test_list_stuffed_with_live_providers_is_still_refused(tmp_path, monkeypatch):
    """Контроль: файл, набитый живыми почтовиками, по-прежнему не берётся."""
    from core.filters import BLACKLIST_SENTINELS
    живые = sorted(BLACKLIST_SENTINELS)[:40]
    сервер = _Сервер(_список(живых=живые), '"v3"')
    d = _загрузчик(tmp_path, monkeypatch, сервер)
    отчёт = d.download_all()
    assert any("обновление не взято" in s for s in отчёт), отчёт
    assert (tmp_path / "disposable.txt").read_text(encoding="utf-8") == "mailinator.com\n"


# ═══════════════════ 6. поиск резолвера Spamhaus не держит старт прогона

def test_setup_does_not_wait_for_spamhaus_resolver_search(monkeypatch):
    """Прогон 27.09: поиск резолвера — 186 с простоя до первой проверки.

    Поиск теперь идёт в фоне: setup() возвращается, не дожидаясь его, а
    строка о результате приходит, когда поиск закончен.
    """
    import threading
    import time
    import core.network as net
    from core.github_parser import BlacklistDownloader

    отпустить = threading.Event()

    def долгий_поиск(self, candidates=None):
        отпустить.wait(10)
        return "9.9.9.9"

    monkeypatch.setattr(BlacklistDownloader, "download_all", lambda self, **k: None)
    monkeypatch.setattr(net, "filter_live_proxies",
                        lambda proxies, **k: (["socks5://203.0.113.7:1080"], 1))
    monkeypatch.setattr(ValidationPipeline, "_profile_live_proxies",
                        lambda self, *a, **k: {})
    monkeypatch.setattr(NetworkValidator, "autodetect_spamhaus_resolver", долгий_поиск)
    pipe, строки = _пайплайн()
    начало = time.time()
    try:
        pipe.setup(timeout=2, proxies=["socks5://203.0.113.7:1080"], threads=1,
                   use_cache=False)
        прошло = time.time() - начало
    finally:
        отпустить.set()
    assert прошло < 8, "setup() ждал поиска резолвера: %.1f с" % прошло
    конец = time.time() + 10
    while time.time() < конец and not any("Spamhaus ZEN" in s for s in строки):
        time.sleep(0.05)
    assert any("Spamhaus ZEN подключён сам" in s for s in строки), строки[-5:]
