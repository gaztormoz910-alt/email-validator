# -*- coding: utf-8 -*-
import pytest

from core import disposable
from core.disposable import NEVER_DISPOSABLE, disposable_mx_owner, is_disposable


@pytest.mark.parametrize("domain", ["sneakemail.com", "getburner.email"])
def test_relays_are_not_disposable_even_if_a_list_says_so(domain):
    disposable.extend_disposable_domains([domain])
    assert domain in NEVER_DISPOSABLE
    assert is_disposable("anna@" + domain) is False


def test_control_burner_mx_does_not_bury_the_relay():
    assert disposable_mx_owner(["mail.burnermail.io"]) == ""


def test_control_real_disposable_still_disposable():
    assert is_disposable("anna@mailinator.com") is True


def test_control_free_listed_domain_with_disposable_mx_is_caught(monkeypatch):
    from core.disposable import is_protected_domain

    assert not is_protected_domain("freebox-e4.example")
    assert disposable_mx_owner(["mx.mailinator.com"]) == "mailinator.com"


def _settler():
    from core.cleaner import EmailCleaner
    from core.settle import SettleMixin

    class Settler(SettleMixin):
        def __init__(self):
            self.cleaner = EmailCleaner()

        def _подсказать_опечатку(self, email, data, fix_typos):
            pass

    return Settler()


@pytest.mark.parametrize("status", ["valid", "catchall", "unknown"])
def test_typo_domain_with_live_mx_is_marked_for_any_status(status):
    s = _settler()
    data = {}
    res = {"status": status, "mx_record": "mx.gmai.com", "reason": "250 OK"}
    s._typo_hint_on_live_mx("anna@gmai.com", data, res, True)
    assert data.get("typo_of") == "gmail.com"
    assert res["status"] == status, "статус по SMTP не меняется"


def test_control_typo_domain_without_mx_is_not_marked():
    s = _settler()
    data = {}
    s._typo_hint_on_live_mx("anna@gmai.com", data, {"status": "valid", "mx_record": "N/A"}, True)
    assert "typo_of" not in data


def test_control_normal_domain_is_not_marked():
    s = _settler()
    data = {}
    s._typo_hint_on_live_mx("anna@corp.test", data, {"status": "valid", "mx_record": "mx.corp.test"}, True)
    assert "typo_of" not in data


def _store(on_disk, tmp_path):
    from ui.result_store import ResultStore

    return ResultStore(path=None if on_disk else str(tmp_path))


@pytest.mark.parametrize("on_disk", [True, False])
def test_typo_filter_hides_marked_rows_by_choice(on_disk, tmp_path):
    from ui.result_store import normalize_filters

    store = _store(on_disk, tmp_path)
    try:
        store.append("anna@gmai.com", "Valid", "250 OK", "mx.gmai.com", {"typo_of": "gmail.com"})
        store.append("boris@corp.test", "Valid", "250 OK", "mx.corp.test", {})
        shown = {r["email"] for r in store.page(filters={"groups": ["valid"], "hideTypo": True})}
        assert shown == {"boris@corp.test"}
        picked = normalize_filters({"groups": ["valid"], "hideTypo": True})
        assert store.matching_count(filters=picked) == 1
    finally:
        store.close()


def test_control_without_the_choice_marked_rows_stay():
    store = _store(True, None)
    try:
        store.append("anna@gmai.com", "Valid", "250 OK", "mx.gmai.com", {"typo_of": "gmail.com"})
        shown = {r["email"] for r in store.page(filters={"groups": ["valid"]})}
        assert shown == {"anna@gmai.com"}
    finally:
        store.close()
