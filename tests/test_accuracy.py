# -*- coding: utf-8 -*-
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cache import ResultCache
from core.cleaner import EmailCleaner, strip_wrapping_junk
from core.email_syntax import _lower_domain_only
from core.heuristics import is_role_based
from core.network import NetworkValidator
from core.smtp_codes import classify_smtp_response
from core.streamer import StreamLoader

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _validator(profiles):
    nv = NetworkValidator(proxies=list(profiles))
    nv.set_proxy_profiles(profiles)
    nv._mx_delay = lambda mx: 0.0
    nv.country_for_domain = lambda domain, mx_host="": ""
    nv.check_dns_health = lambda d, mx_record="": {
        "score": 0, "has_spf": False, "has_dmarc": False, "has_dkim": False}
    return nv


def _tmp_cache():
    return ResultCache(path=os.path.join(tempfile.mkdtemp(), "acc.sqlite"))


B1_ЗАКОННЫЕ = [
    "user@sky.company.co.uk",
    "b@aol.company.com",
    "a@web.de.hosting.net",
    "d@list.ru-company.com",
]

B1_СКЛЕЙКИ = {
    "user@gmail.comtelefoon": "user@gmail.com",
    "y@mail.ruxxx": "y@mail.ru",
    "z@corp.com-jobs": "z@corp.com",
    "w@yandex.rublahblah": "w@yandex.ru",
    "q@gmail.com.br.spam.xyz": "q@gmail.com",
}


def test_b1_legit_domains_are_never_rewritten():
    cleaner = EmailCleaner()
    подменено = []
    for адрес in B1_ЗАКОННЫЕ:
        вышло = cleaner.correct_and_normalize(адрес)
        if вышло != адрес:
            подменено.append("%s -> %s" % (адрес, вышло))
    assert not подменено, "домен подменён, вердикт будет про чужой ящик: %s" % подменено


def test_b1_control_real_glue_is_still_repaired():
    cleaner = EmailCleaner()
    для_отчёта = []
    for адрес, ждём in B1_СКЛЕЙКИ.items():
        вышло = cleaner.correct_and_normalize(адрес)
        if вышло != ждём:
            для_отчёта.append("%s -> %s (ждали %s)" % (адрес, вышло, ждём))
    assert not для_отчёта, "склейка перестала чиниться: %s" % для_отчёта


def test_b1_rule_is_about_the_dot_not_a_list_of_exceptions():
    cleaner = EmailCleaner()
    assert cleaner._junk_tail("telefoon") is True
    assert cleaner._junk_tail("-jobs") is True
    assert cleaner._junk_tail("pany.co.uk") is False
    assert cleaner._junk_tail(".hosting.net") is False
    assert cleaner._junk_tail("") is False
    assert cleaner.correct_and_normalize("k@bbc.company.co.uk") == "k@bbc.company.co.uk"


def test_b2_cache_can_forget_a_domain():
    cache = _tmp_cache()
    try:
        cache.put("a@catchall.test", "Valid", "250 OK", "mx.catchall.test", {})
        cache.put("b@catchall.test", "Valid", "250 OK", "mx.catchall.test", {})
        assert cache.get("a@catchall.test") is not None
        убрано = cache.forget_domain("catchall.test")
        assert убрано == 2, "убрано %s" % убрано
        assert cache.get("a@catchall.test") is None
        assert cache.get("b@catchall.test") is None
    finally:
        cache.close()


def test_b2_control_other_domains_survive():
    cache = _tmp_cache()
    try:
        cache.put("a@catchall.test", "Valid", "250 OK", "mx1", {})
        cache.put("a@honest.test", "Valid", "250 OK", "mx2", {})
        cache.forget_domain("catchall.test")
        assert cache.get("a@honest.test") is not None, "стёрт посторонний домен"
    finally:
        cache.close()


def test_b2_control_partial_domain_name_does_not_match():
    cache = _tmp_cache()
    try:
        cache.put("a@notcatchall.test", "Valid", "250 OK", "mx", {})
        cache.forget_domain("catchall.test")
        assert cache.get("a@notcatchall.test") is not None
    finally:
        cache.close()


def test_b2_control_like_wildcards_in_the_domain_are_escaped():
    cache = _tmp_cache()
    try:
        cache.put("a@myxcorp.test", "Valid", "250 OK", "mx", {})
        cache.put("a@my_corp.test", "Valid", "250 OK", "mx", {})
        убрано = cache.forget_domain("my_corp.test")
        assert убрано == 1, "убрано %s — задет чужой домен" % убрано
        assert cache.get("a@myxcorp.test") is not None
        assert cache.get("a@my_corp.test") is None
    finally:
        cache.close()


def test_b4_the_giant_list_lives_in_one_place():
    источник = io.open(os.path.join(ROOT, "core", "network.py"),
                       encoding="utf-8").read()
    assert "skip_catchall = self._is_never_catchall(domain)" in источник, (
        "ветка проверки снова набирает список гигантов сама")
    nv = _validator({})
    for домен in ("mail.ru", "bk.ru", "inbox.ru", "list.ru"):
        assert nv._is_never_catchall(домен) is False, домен


def test_b2_pipeline_forgets_after_unmasking():
    источник = io.open(os.path.join(ROOT, "core", "pipeline.py"),
                       encoding="utf-8").read()
    assert "_forget_cached" in источник
    assert источник.count("self._forget_cached(") >= 2, (
        "забывание подключено не ко всем разоблачениям")


def _catchall_harness():
    nv = _validator({"socks5://1.2.3.4:1080": {"exit_ip": "1.2.3.4"}})
    nv.get_mx_records = lambda d: ["mx.example.test"]
    попытки = []

    def ping(email, mx, proxy=None, control_probe=False, **kw):
        попытки.append(email)
        if control_probe:
            return {"status": "catchall",
                    "reason": "Catch-All: сервер принял и выдуманный адрес"}
        return {"status": "valid", "reason": "250 OK"}

    nv._do_single_ping = ping
    nv.is_catch_all_domain = lambda d, mx: False
    return nv, попытки


def test_b3_catchall_stops_the_retry_loop():
    nv, попытки = _catchall_harness()
    итог = nv.stealth_smtp_ping("someone@example.test", ["mx.example.test"],
                                control_probe=True)
    assert итог["status"] == "catchall", итог
    assert len(попытки) == 1, "повторов после разоблачения: %d" % len(попытки)


def test_b3_control_valid_still_returns_at_once():
    nv, попытки = _catchall_harness()
    итог = nv.stealth_smtp_ping("someone@example.test", ["mx.example.test"],
                                control_probe=False)
    assert итог["status"] == "valid", итог
    assert len(попытки) == 1


def test_b3_control_unknown_still_retries():
    nv = _validator({"socks5://1.2.3.4:1080": {"exit_ip": "1.2.3.4"},
                     "socks5://5.6.7.8:1080": {"exit_ip": "5.6.7.8"}})
    nv.get_mx_records = lambda d: ["mx.example.test"]
    попытки = []

    def ping(email, mx, proxy=None, control_probe=False, **kw):
        попытки.append(email)
        return {"status": "unknown", "reason": "Timeout"}

    nv._do_single_ping = ping
    nv.is_catch_all_domain = lambda d, mx: False
    nv.stealth_smtp_ping("someone@example.test", ["mx.example.test"])
    assert len(попытки) > 1, "повторов не было вовсе: %d" % len(попытки)


class _Память(object):

    def __init__(self):
        self.записи = []

    def catchall_put(self, domain, is_catchall):
        self.записи.append((domain, is_catchall))

    def catchall_get(self, domain):
        return None


def test_b4_tarpit_is_not_remembered_as_catchall():
    nv = _validator({"socks5://9.9.9.9:1080": {"exit_ip": "9.9.9.9"}})
    nv.memory = _Память()
    for домен in ("gmail.com", "yandex.ru", "icloud.com",
                  "yahoo.com", "outlook.com", "aol.com"):
        nv._remember_catchall(домен, True)
    assert nv.memory.записи == [], (
        "тарпитинг записан как catch-all: %s" % nv.memory.записи)


def test_b4_control_ordinary_domain_is_still_remembered():
    nv = _validator({"socks5://9.9.9.9:1080": {"exit_ip": "9.9.9.9"}})
    nv.memory = _Память()
    nv._remember_catchall("corp-example.test", True)
    assert nv.memory.записи == [("corp-example.test", True)]


def test_b4_control_negative_answer_is_remembered_for_giants_too():
    nv = _validator({"socks5://9.9.9.9:1080": {"exit_ip": "9.9.9.9"}})
    nv.memory = _Память()
    nv._remember_catchall("gmail.com", False)
    assert nv.memory.записи == [("gmail.com", False)]


def test_b4_call_site_is_guarded_too():
    from исходники import исходник_сети
    источник = исходник_сети()
    assert "if not self._is_never_catchall(domain):" in источник
    nv = _validator({})
    assert nv._is_never_catchall("gmail.com") is True
    assert nv._is_never_catchall("yahoo.com") is True
    assert nv._is_never_catchall("corp-example.test") is False


def test_b5_guard_fires_when_profiling_found_no_ptr():
    nv = _validator({"socks5://1.2.3.4:1080": {"exit_ip": "1.2.3.4",
                                               "has_ptr": False}})
    nv.get_mx_records = lambda d: ["mx.yahoo.test"]
    попытки = []
    nv._do_single_ping = lambda *a, **k: (попытки.append(1) or
                                          {"status": "valid", "reason": "250"})
    итог = nv.stealth_smtp_ping("someone@yahoo.com", ["mx.yahoo.test"])
    assert итог["status"] == "unknown", итог
    assert "PTR" in итог["reason"], итог["reason"]
    assert попытки == [], "потрачено холостых попыток: %d" % len(попытки)


def test_b5_control_diagnosis_names_the_real_cause():
    nv = _validator({"socks5://1.2.3.4:1080": {"exit_ip": "1.2.3.4",
                                               "has_ptr": False}})
    nv.get_mx_records = lambda d: ["mx.yahoo.test"]
    nv._do_single_ping = lambda *a, **k: {"status": "valid", "reason": "250"}
    причина = nv.stealth_smtp_ping("s@yahoo.com", ["mx.yahoo.test"])["reason"]
    assert "мертв" not in причина.lower(), причина
    assert "прокси" in причина.lower()


def test_b5_control_unprofiled_pool_is_not_blocked():
    nv = NetworkValidator(proxies=["socks5://1.2.3.4:1080"])
    nv._mx_delay = lambda mx: 0.0
    nv.country_for_domain = lambda domain, mx_host="": ""
    nv.check_dns_health = lambda d, mx_record="": {"score": 0}
    nv.get_mx_records = lambda d: ["mx.yahoo.test"]
    nv._do_single_ping = lambda *a, **k: {"status": "valid", "reason": "250 OK"}
    итог = nv.stealth_smtp_ping("someone@yahoo.com", ["mx.yahoo.test"])
    assert итог["status"] == "valid", итог


def test_b6_code_252_is_not_a_verdict():
    итог = classify_smtp_response(252, b"2.0.0 cannot VRFY user")
    assert итог["status"] == "unknown", итог
    assert "252" in итог["reason"]


def test_b6_control_250_and_251_remain_valid():
    assert classify_smtp_response(250, b"OK")["status"] == "valid"
    assert classify_smtp_response(251, b"will forward")["status"] == "valid"


def test_b6_control_mailbox_full_is_recognised():
    итог = classify_smtp_response(452, b"4.2.2 mailbox full, over quota")
    assert итог["status"] == "full", итог


def test_b7_mailbox_case_survives_loading():
    загружено = [e for e, _ in StreamLoader(
        [{"type": "text", "content": "Jeronimo.Alcott@Corp-Example.com\n"}]
    ).stream_emails()]
    assert загружено == ["Jeronimo.Alcott@corp-example.com"], загружено


def test_b7_mailbox_case_survives_cleaning():
    assert strip_wrapping_junk("  John.Smith@Corp.COM ") == "John.Smith@corp.com"
    assert strip_wrapping_junk("Ivan P <IvanP@Example.RU>") == "IvanP@example.ru"


def test_b7_control_domain_is_still_lowercased():
    assert _lower_domain_only("A@B.COM") == "A@b.com"
    assert strip_wrapping_junk("x@GMAIL.COM").endswith("@gmail.com")


def test_b7_control_dedup_key_is_still_case_insensitive():
    from core.cleaner import normalize_for_dedup
    assert normalize_for_dedup("John.Smith@Corp.COM") == \
        normalize_for_dedup("john.smith@corp.com")


def test_b7_control_no_at_sign_is_survivable():
    assert _lower_domain_only("MUSOR") == "musor"
    assert _lower_domain_only(None) == ""


def test_b8_full_forms_are_recognised():
    непойманные = [имя for имя in
                   ("administrator", "administration", "webadmin", "helpdesk",
                    "moderator", "operator", "newsletter", "careers",
                    "recruitment", "notifications", "autoreply", "donotreply",
                    "mailerdaemon", "invoices", "enquiries")
                   if not is_role_based("%s@corp-example.test" % имя)]
    assert not непойманные, "не опознаны как ролевые: %s" % непойманные


def test_b8_control_short_forms_still_work():
    for имя in ("admin", "info", "support", "postmaster", "abuse", "noreply"):
        assert is_role_based("%s@corp-example.test" % имя), имя


def test_b8_control_personal_mailboxes_are_not_swept_up():
    личные = [имя for имя in
              ("ivan", "j.smith", "maria2005", "alex.petrov", "mail", "it",
               "dev", "order", "account", "ceo", "manager", "anna")
              if is_role_based("%s@corp-example.test" % имя)]
    assert not личные, "личный ящик помечен ролевым: %s" % личные


def test_docs_describe_the_fixed_behaviour():
    док = io.open(os.path.join(ROOT, "docs", "КРИТЕРИИ.md"),
                  encoding="utf-8").read()
    отсутствует = [кусок for кусок in
                   ("252", "точк", "регистр", "тарпит")
                   if кусок.lower() not in док.lower()]
    assert not отсутствует, "в критериях не описано: %s" % отсутствует
