# -*- coding: utf-8 -*-
"""Что показали два живых прогона 15.11.2026 через бесплатные прокси.

300 адресов с прежними ответами серверов. Прогон 1: 14 живых прокси (11 в
чёрных списках, обратный DNS у двух). Прогон 2: 76 живых (33 в чёрных
списках, обратного DNS ни у одного). Оба раза вскрылось одно и то же:
грязный выход отравляет вывод.

1. С грязного IP yandex.com и protonmail.com приняли выдуманный адрес и легли
   в ДОЛГУЮ память как «принимает любой адрес» — на месяц, хотя прежде оба
   честно отвечали «нет такого ящика». Теперь долгую память пишет только
   надёжный выход: прямое соединение или прокси с PTR вне грязных.
2. Первая попытка лечения — внести yandex.com в список гигантов — во втором
   прогоне дала ЛОЖНЫЙ «Годен»: у гигантов контроль идёт на каждом 25-м
   адресе, а Яндекс с грязного IP отвечает «да» на всё. Откачено; тест ниже
   держит это решение.
3. 82 адреса gmail получили причину «домен принимает любой адрес
   (catch-all)», хотя у гиганта это тарпитинг нашего выхода.

Сеть не нужна: проверяется решение, а не диалог с сервером.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network import NetworkValidator  # noqa: E402
from core.verdict_revision import VerdictRevisionMixin  # noqa: E402

CLEAN = "socks5://198.51.100.10:1080"     # адреса из диапазона для документации
DIRTY = "socks5://198.51.100.20:1080"
NO_PTR = "socks5://198.51.100.30:1080"


class _Память:
    def __init__(self):
        self.записи = []

    def catchall_put(self, domain, is_catchall):
        self.записи.append((domain, is_catchall))

    def catchall_get(self, domain):
        return None


def validator(profiles=None):
    nv = NetworkValidator(timeout=2, proxy_dns=False)
    if profiles is not None:
        nv.set_proxy_profiles(profiles)
    nv.memory = _Память()
    return nv


PROFILES = {
    CLEAN: {"exit_ip": "198.51.100.10", "has_ptr": True, "in_dnsbl": False},
    DIRTY: {"exit_ip": "198.51.100.20", "has_ptr": True, "in_dnsbl": True},
    NO_PTR: {"exit_ip": "198.51.100.30", "has_ptr": False, "in_dnsbl": False},
}


def test_dirty_exit_does_not_write_catch_all_for_a_month():
    nv = validator(PROFILES)
    nv._remember_catchall("corp-example.test", True, proxy=DIRTY)
    nv._remember_catchall("corp-example.test", True, proxy=NO_PTR)
    assert nv.memory.записи == []


def test_clean_exit_and_direct_connection_still_remember():
    """Контроль: настоящий catch-all по-прежнему запоминается — иначе тройная
    проба переспрашивала бы одно и то же каждый запуск."""
    nv = validator(PROFILES)
    nv._remember_catchall("corp-example.test", True, proxy=CLEAN)
    nv._remember_catchall("shop-example.test", True, proxy=None)
    assert nv.memory.записи == [("corp-example.test", True), ("shop-example.test", True)]


def test_unprofiled_proxy_is_not_trusted_for_long_memory():
    nv = validator()           # профилей нет вовсе
    nv._remember_catchall("corp-example.test", True, proxy=CLEAN)
    assert nv.memory.записи == []


def test_dirty_exit_still_marks_the_domain_in_this_run():
    """Защита от ложного «Годен» в текущем прогоне не ослабла: грязный выход
    принял выдуманный адрес — домен в этом прогоне catch-all."""
    nv = validator(PROFILES)
    answer = nv._mark_catchall("corp-example.test", "проба", proxy=DIRTY)
    assert answer["status"] == "catchall"
    assert nv.catchall_cache["corp-example.test"] is True
    assert nv.memory.записи == []


def test_yandex_com_stays_out_of_the_giants_list():
    """Внесение yandex.com в гиганты дало ложный «Годен» (прогон 2): у гиганта
    «да» берётся без контроля на каждом адресе. Держим откат."""
    nv = validator()
    for домен in ("yandex.com", "yandex.by", "yandex.kz", "yandex.com.tr",
                  "protonmail.com", "mail.ru", "bk.ru", "inbox.ru", "list.ru"):
        assert not nv._is_never_catchall(домен), домен


class _Конвейер(VerdictRevisionMixin):
    def __init__(self):
        self.network = NetworkValidator(timeout=2, proxy_dns=False)


def test_giant_that_accepted_a_fake_is_reported_as_tarpit_not_catch_all():
    proven, trapped = _Конвейер()._split_catchall_from_tarpit(
        ["corp-example.test", "gmail.com", "hotmail.com"], [])
    assert proven == ["corp-example.test"]
    assert trapped == ["gmail.com", "hotmail.com"]


def test_split_keeps_existing_tarpit_and_plain_catch_all():
    """Контроль: без гигантов ничего не перекладывается и не теряется."""
    proven, trapped = _Конвейер()._split_catchall_from_tarpit(
        ["corp-example.test", "shop-example.test"], ["outlook.com"])
    assert proven == ["corp-example.test", "shop-example.test"]
    assert trapped == ["outlook.com"]
    assert _Конвейер()._split_catchall_from_tarpit([], []) == ([], [])


def test_pipeline_uses_the_split_before_revising():
    """Пересмотр в конце прогона идёт через деление, а не напрямую."""
    import io
    src = io.open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "core", "pipeline.py"), encoding="utf-8").read()
    i = src.index("proven_catchall_domains()")
    assert "_split_catchall_from_tarpit(proven, trapped)" in src[i:i + 600]


def test_session_control_passes_its_exit_to_the_memory():
    """Контроль в сессии сообщает, с какого выхода пришёл приём выдуманного."""
    import io
    src = io.open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "core", "network.py"), encoding="utf-8").read()
    i = src.index("self._control_in_session(server, domain, result,")
    assert "proxy=proxy" in src[i:i + 200]
