# -*- coding: utf-8 -*-
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network import NetworkValidator
from core.verdict_revision import VerdictRevisionMixin

CLEAN = "socks5://198.51.100.10:1080"
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
    nv = validator(PROFILES)
    nv._remember_catchall("corp-example.test", True, proxy=CLEAN)
    nv._remember_catchall("shop-example.test", True, proxy=None)
    assert nv.memory.записи == [("corp-example.test", True), ("shop-example.test", True)]


def test_unprofiled_proxy_is_not_trusted_for_long_memory():
    nv = validator()
    nv._remember_catchall("corp-example.test", True, proxy=CLEAN)
    assert nv.memory.записи == []


def test_dirty_exit_still_marks_the_domain_in_this_run():
    nv = validator(PROFILES)
    answer = nv._mark_catchall("corp-example.test", "проба", proxy=DIRTY)
    assert answer["status"] == "catchall"
    assert nv.catchall_cache["corp-example.test"] is True
    assert nv.memory.записи == []


def test_yandex_com_stays_out_of_the_giants_list():
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
    proven, trapped = _Конвейер()._split_catchall_from_tarpit(
        ["corp-example.test", "shop-example.test"], ["outlook.com"])
    assert proven == ["corp-example.test", "shop-example.test"]
    assert trapped == ["outlook.com"]
    assert _Конвейер()._split_catchall_from_tarpit([], []) == ([], [])


def test_pipeline_uses_the_split_before_revising():
    import io
    src = io.open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "core", "pipeline.py"), encoding="utf-8").read()
    i = src.index("proven_catchall_domains()")
    assert "_split_catchall_from_tarpit(proven, trapped)" in src[i:i + 600]


def test_session_control_passes_its_exit_to_the_memory():
    import io
    src = io.open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "core", "network.py"), encoding="utf-8").read()
    i = src.index("self._control_in_session(server, domain, result,")
    assert "proxy=proxy" in src[i:i + 200]
