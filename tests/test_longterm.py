# -*- coding: utf-8 -*-
"""Что валидатор обязан помнить между запусками.

Три вещи выяснялись заново при каждом старте, хотя за сутки не меняются:
catch-all домена (три RCPT в отдельной сессии на КАЖДЫЙ домен базы), профиль
прокси (выходной IP, PTR, семь чёрных списков и три пробы почтовиков на
каждый прокси) и нагрузка на выходной IP (потолок в 800 обращений обнулялся
вместе с программой — два прогона в день давали 1600 с одного адреса).

Главное правило, которое здесь проверяется чаще всего: **память не имеет
права ни врать, ни мешать**. Протухшая запись не применяется, недоступная
база не роняет прогон, свежий факт вытесняет запомненный.
"""
# Исходник конвейера собирается по ВСЕМ его модулям: после
# разделения на примеси половина кода лежит не в core/pipeline.py,
# и чтение одного файла молча проверяло бы не то. См. tests/исходники.py.
from исходники import исходник_конвейера
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def memory(tmp_path):
    """Своя база на каждый тест: настоящую data/longterm.sqlite не трогаем."""
    from core.longterm import LongTermMemory

    made = LongTermMemory(str(tmp_path / "longterm.sqlite"))
    yield made
    made.close()


# ═══════════════════════════════ G1: catch-all помнится

def test_catchall_is_remembered_between_runs(memory, tmp_path):
    """Второй запуск не переспрашивает то, что выяснил первый."""
    from core.longterm import LongTermMemory

    memory.catchall_put("catchall.example", True)
    memory.catchall_put("strict.example", False)

    # Новый объект памяти = новый запуск программы.
    again = LongTermMemory(str(tmp_path / "longterm.sqlite"))
    try:
        assert again.catchall_get("catchall.example") is True
        assert again.catchall_get("strict.example") is False
    finally:
        again.close()


def test_catchall_unknown_is_not_false(memory):
    """«Не выясняли» обязано отличаться от «не catch-all».

    Схлопнув одно в другое, мы бы пропускали тройную пробу на доменах, о
    которых ничего не знаем, — и их несуществующие ящики уехали бы в Valid.
    """
    assert memory.catchall_get("never-asked.example") is None
    memory.catchall_put("asked.example", False)
    assert memory.catchall_get("asked.example") is False


def test_catchall_validator_asks_memory_first():
    """Валидатор смотрит в память ДО того, как открыть сессию."""
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    v.memory.catchall_put("remembered.example", True)
    v.catchall_cache.pop("remembered.example", None)

    def explode(*args, **kwargs):
        raise AssertionError("полезли в сеть за ответом, который уже помним")

    v._probe_recipients = explode
    assert v.is_catch_all_domain("remembered.example", "mx.remembered.example") is True


def test_catchall_verdict_reaches_memory():
    """Выясненный ответ уходит в долгую память, а не только в кэш прогона."""
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    domain = "fresh-%d.example" % int(time.time() * 1000)
    v._probe_recipients = lambda *a, **k: [{"status": "valid"}] * 3
    assert v.is_catch_all_domain(domain, "mx." + domain) is True
    assert v.memory.catchall_get(domain) is True


# ═══════════════════════════════ G2: профиль прокси помнится

def test_profile_survives_a_restart(memory, tmp_path):
    from core.longterm import LongTermMemory

    memory.profiles_save({"1.2.3.4:8080": {"exit_ip": "5.6.7.8", "has_ptr": True}})

    again = LongTermMemory(str(tmp_path / "longterm.sqlite"))
    try:
        loaded = again.profiles_load(["1.2.3.4:8080"])
        assert loaded["1.2.3.4:8080"]["exit_ip"] == "5.6.7.8"
        assert loaded["1.2.3.4:8080"]["has_ptr"] is True
    finally:
        again.close()


def test_profile_returns_only_the_proxies_asked_for(memory):
    """Пул между запусками меняется: тащить профили выброшенных незачем."""
    memory.profiles_save({"a:1": {"exit_ip": "1.1.1.1"},
                          "b:2": {"exit_ip": "2.2.2.2"}})
    loaded = memory.profiles_load(["a:1"])
    assert list(loaded) == ["a:1"]


def test_profile_validator_recalls_them():
    """У валидатора есть чем вспомнить — и он это делает через память."""
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    proxy = "9.9.9.9:1080"
    v.memory.profiles_save({proxy: {"exit_ip": "7.7.7.7"}})
    assert v.recall_proxy_profiles([proxy])[proxy]["exit_ip"] == "7.7.7.7"


def test_profile_is_saved_when_set():
    """Снятый профиль запоминается сам, без отдельного вызова."""
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    proxy = "8.8.8.8:3128"
    v.set_proxy_profiles({proxy: {"exit_ip": "6.6.6.6", "has_ptr": False}})
    assert v.memory.profiles_load([proxy])[proxy]["exit_ip"] == "6.6.6.6"


def test_profile_pipeline_skips_what_it_remembers():
    """Конвейер профилирует только тех, кого не помнит."""
    import inspect

    from core import pipeline

    source = исходник_конвейера()
    assert "recall_proxy_profiles(live_proxies)" in source
    assert "fresh_needed = [p for p in live_proxies if p not in remembered]" in source


# ═══════════════════════════════ G3: нагрузка на IP считается за сутки

def test_ipload_survives_a_restart(memory, tmp_path):
    """Потолок обнулялся вместе с программой — это и была вся беда."""
    from core.longterm import LongTermMemory

    memory.ip_load_add("1.2.3.4", 800)

    again = LongTermMemory(str(tmp_path / "longterm.sqlite"))
    try:
        assert again.ip_load_today("1.2.3.4") == 800
    finally:
        again.close()


def test_ipload_adds_up_across_calls(memory):
    memory.ip_load_add("1.2.3.4", 300)
    memory.ip_load_add("1.2.3.4", 250)
    assert memory.ip_load_today("1.2.3.4") == 550


def test_ipload_is_per_address(memory):
    memory.ip_load_add("1.1.1.1", 100)
    assert memory.ip_load_today("2.2.2.2") == 0


def test_ipload_validator_sees_yesterdays_run():
    """Новый прогон ЗНАЕТ, что адресом сегодня уже пользовались."""
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    proxy = "5.5.5.5:8080"
    v.set_proxy_profiles({proxy: {"exit_ip": "4.4.4.4"}})
    v.memory.ip_load_add("4.4.4.4", 700)

    fresh = NetworkValidator(timeout=2)
    fresh.set_proxy_profiles({proxy: {"exit_ip": "4.4.4.4"}})
    assert fresh.ip_load(proxy) >= 700, "суточный счёт потерялся при перезапуске"


def test_ipload_purge_drops_old_days(memory):
    """Счёт за прошлый месяц не нужен никому."""
    memory.ip_load_add("1.2.3.4", 10)
    assert memory.ip_load_purge(keep_days=7) == 0     # сегодняшний день остаётся
    assert memory.ip_load_today("1.2.3.4") == 10


# ═══════════════════════════════ G4: память не врёт и не мешает

def test_safety_stale_catchall_is_not_used(memory, monkeypatch):
    """Запись старше срока не применяется: домен мог перестать быть catch-all."""
    from core import longterm

    memory.catchall_put("old.example", True)
    # Отматываем часы вперёд на срок с запасом.
    later = time.time() + (longterm.CATCHALL_TTL_HOURS + 1) * 3600
    monkeypatch.setattr(longterm, "_now", lambda: later)
    assert memory.catchall_get("old.example") is None


def test_safety_stale_profile_is_not_used(memory, monkeypatch):
    """У прокси меняется выходной IP — вчерашний профиль может быть чужим."""
    from core import longterm

    memory.profiles_save({"a:1": {"exit_ip": "1.1.1.1"}})
    later = time.time() + (longterm.PROFILE_TTL_HOURS + 1) * 3600
    monkeypatch.setattr(longterm, "_now", lambda: later)
    assert memory.profiles_load(["a:1"]) == {}


def test_safety_broken_database_does_not_break_the_run(tmp_path):
    """Недоступная база молча отключает память, а не роняет проверку.

    Память — ускорение, а не источник истины: без неё проверка обязана
    работать как раньше, просто медленнее.
    """
    from core.longterm import LongTermMemory

    # Путь, по которому базу не создать: файл вместо каталога.
    blocker = tmp_path / "blocker"
    blocker.write_text("не каталог", encoding="utf-8")
    broken = LongTermMemory(str(blocker / "sub" / "longterm.sqlite"))

    assert broken.enabled is False
    assert broken.catchall_get("any.example") is None
    assert broken.catchall_put("any.example", True) is False
    assert broken.profiles_load(["a:1"]) == {}
    assert broken.profiles_save({"a:1": {"exit_ip": "1.1.1.1"}}) == 0
    assert broken.ip_load_today("1.2.3.4") == 0
    assert broken.ip_load_add("1.2.3.4", 5) == 0
    broken.close()


def test_safety_validator_works_without_memory():
    """Валидатор с отключённой памятью проверяет как прежде."""
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    v.memory = None
    v._probe_recipients = lambda *a, **k: [{"status": "valid"}] * 3
    assert v.is_catch_all_domain("nomemory.example", "mx.nomemory.example") is True
    assert v.recall_proxy_profiles(["a:1"]) == {}
    assert v.ip_load("a:1") == 0


def test_safety_fresh_probe_beats_the_remembered_one():
    """Свежая проба вытесняет запомненное, а не наоборот."""
    from core.network import NetworkValidator

    v = NetworkValidator(timeout=2)
    proxy = "3.3.3.3:8080"
    v.memory.profiles_save({proxy: {"exit_ip": "старый"}})
    v.set_proxy_profiles({proxy: {"exit_ip": "новый"}})
    assert v._proxy_profiles[proxy]["exit_ip"] == "новый"
    assert v.memory.profiles_load([proxy])[proxy]["exit_ip"] == "новый"


def test_safety_garbage_does_not_crash_memory(memory):
    """Мусор на входе не роняет память — её зовут из рабочих потоков."""
    for junk in (None, 0, [], {}, object(), b"bytes"):
        assert memory.catchall_get(junk) is None
        assert memory.catchall_put(junk, True) is False
    assert memory.profiles_save("не словарь") == 0
    assert memory.profiles_load([]) == {}
    assert memory.ip_load_add(None, 5) == 0
    assert memory.ip_load_add("1.2.3.4", "много") == 0
