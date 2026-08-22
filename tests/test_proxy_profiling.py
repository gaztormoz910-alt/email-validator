"""Тесты профилирования прокси: выходной IP, PTR, чёрные списки.

Смысл: «живой» прокси и «пригодный для валидации» — разные вещи. Outlook,
iCloud и GMX режут по репутации IP, Yahoo и AOL требуют обратный DNS.
Знать это надо ДО прогона, а не выяснять по молчанию серверов.
"""
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.network import (NetworkValidator, profile_proxies, get_proxy_exit_ip,
                          NEEDS_CLEAN_IP_DOMAINS, _EXIT_IP_RE)


class TestExitIpParsing(unittest.TestCase):
    """Выходной IP берём из ответа Gmail на EHLO — он сообщает его сам."""

    def test_parses_gmail_ehlo_form(self):
        text = "mx.google.com at your service, [31.192.250.3]\nSIZE 157286400"
        self.assertEqual(_EXIT_IP_RE.search(text).group(1), "31.192.250.3")

    def test_no_ip_returns_no_match(self):
        self.assertIsNone(_EXIT_IP_RE.search("mx.google.com at your service"))

    def test_bad_proxy_gives_none(self):
        self.assertIsNone(get_proxy_exit_ip("мусор", timeout=2))
        self.assertIsNone(get_proxy_exit_ip(None, timeout=2))


class TestDnsblByIp(unittest.TestCase):
    """Санити-контракт чёрных списков: 127.0.0.2 числится, 127.0.0.1 нет."""

    def setUp(self):
        self.v = NetworkValidator(timeout=2)

    def test_empty_ip_is_not_listed(self):
        self.assertFalse(self.v.check_dnsbl_ip(""))
        self.assertFalse(self.v.check_dnsbl_ip(None))

    def test_result_is_cached(self):
        self.v._dnsbl_cache["9.9.9.9"] = True
        self.assertTrue(self.v.check_dnsbl_ip("9.9.9.9"))


class TestProfileAwareSelection(unittest.TestCase):
    """Прокси подбирается под требования конкретного провайдера."""

    POOL = ["ptr-clean:1080", "ptr-dirty:1080", "plain-clean:1080", "plain-dirty:1080"]
    PROFILES = {
        "ptr-clean:1080":   {"exit_ip": "1.1.1.1", "has_ptr": True,  "in_dnsbl": False},
        "ptr-dirty:1080":   {"exit_ip": "2.2.2.2", "has_ptr": True,  "in_dnsbl": True},
        "plain-clean:1080": {"exit_ip": "3.3.3.3", "has_ptr": False, "in_dnsbl": False},
        "plain-dirty:1080": {"exit_ip": "4.4.4.4", "has_ptr": False, "in_dnsbl": True},
    }

    def setUp(self):
        self.v = NetworkValidator(timeout=2, proxies=list(self.POOL))
        self.v.set_proxy_profiles(self.PROFILES)

    def sample(self, **kw):
        return {self.v._pick_best_proxy(**kw) for _ in range(60)}

    def test_yahoo_gets_only_ptr_proxies(self):
        self.assertTrue(self.sample(need_ptr=True) <= {"ptr-clean:1080", "ptr-dirty:1080"})

    def test_outlook_gets_only_clean_proxies(self):
        self.assertEqual(self.sample(need_clean=True), {"plain-clean:1080"})

    def test_ordinary_domains_conserve_ptr_proxies(self):
        picked = self.sample()
        self.assertTrue(picked <= {"plain-clean:1080", "plain-dirty:1080"})

    def test_both_requirements_pick_the_ideal_proxy(self):
        self.assertEqual(self.sample(need_ptr=True, need_clean=True), {"ptr-clean:1080"})

    def test_falls_back_to_dirty_when_no_clean_left(self):
        # Лучше попытка через грязный прокси, чем отказ от проверки
        v = NetworkValidator(timeout=2, proxies=["plain-dirty:1080"])
        v.set_proxy_profiles({"plain-dirty:1080": {"exit_ip": "4.4.4.4",
                                                   "has_ptr": False, "in_dnsbl": True}})
        self.assertEqual(v._pick_best_proxy(need_clean=True), "plain-dirty:1080")

    def test_helpers_report_pool_state(self):
        self.assertTrue(self.v.has_ptr_proxies())
        self.assertTrue(self.v.has_clean_proxies())


class TestCleanIpDomains(unittest.TestCase):
    def test_reputation_sensitive_providers_listed(self):
        for d in ["outlook.com", "hotmail.com", "live.com", "icloud.com", "gmx.com"]:
            with self.subTest(domain=d):
                self.assertIn(d, NEEDS_CLEAN_IP_DOMAINS)

    def test_gmail_and_yandex_not_reputation_sensitive(self):
        # Они отвечают честно с любого живого IP — чистый прокси на них тратить незачем
        for d in ["gmail.com", "yandex.ru", "proton.me"]:
            with self.subTest(domain=d):
                self.assertNotIn(d, NEEDS_CLEAN_IP_DOMAINS)


class TestProfileProxiesDegenerate(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(profile_proxies([]), {})
        self.assertEqual(profile_proxies(None), {})


class TestPtrTriState(unittest.TestCase):
    """PTR имеет ТРИ состояния, и путать их нельзя.

    True  — PTR подтверждён, Yahoo пустит.
    False — PTR точно нет, Yahoo отошьёт на MAIL FROM: брать такой прокси
            для Yahoo бессмысленно, это гарантированный холостой ход.
    None  — проверить не удалось. Во время профилирования летят сотни
            параллельных DNS-запросов, часть отваливается по таймауту.
            Схлопывать None в False нельзя: хороший прокси вылетел бы из
            пула Yahoo из-за случайного сбоя DNS.
    """

    def _v(self, profiles):
        v = NetworkValidator(timeout=2, proxies=list(profiles))
        v.set_proxy_profiles(profiles)
        return v

    def _sample(self, v, **kw):
        return {v._pick_best_proxy(**kw) for _ in range(60)}

    def test_confirmed_ptr_preferred_over_unknown(self):
        v = self._v({
            "yes": {"exit_ip": "1.1.1.1", "has_ptr": True,  "in_dnsbl": False},
            "unk": {"exit_ip": "2.2.2.2", "has_ptr": None,  "in_dnsbl": False},
            "no":  {"exit_ip": "3.3.3.3", "has_ptr": False, "in_dnsbl": False},
        })
        self.assertEqual(self._sample(v, need_ptr=True), {"yes"})

    def test_unknown_used_when_no_confirmed(self):
        # Попытка стоит одного пинга, отказ гарантирует ноль результатов
        v = self._v({
            "unk": {"exit_ip": "2.2.2.2", "has_ptr": None,  "in_dnsbl": False},
            "no":  {"exit_ip": "3.3.3.3", "has_ptr": False, "in_dnsbl": False},
        })
        self.assertEqual(self._sample(v, need_ptr=True), {"unk"})
        self.assertTrue(v.has_ptr_proxies())

    def test_definitely_no_ptr_never_used_for_yahoo(self):
        v = self._v({
            "no1": {"exit_ip": "3.3.3.3", "has_ptr": False, "in_dnsbl": False},
            "no2": {"exit_ip": "4.4.4.4", "has_ptr": False, "in_dnsbl": False},
        })
        self.assertIsNone(v._pick_best_proxy(need_ptr=True))
        self.assertFalse(v.has_ptr_proxies())

    def test_such_proxies_still_serve_other_domains(self):
        # Для Gmail и Yandex отсутствие PTR не помеха — пул не должен простаивать
        v = self._v({
            "no1": {"exit_ip": "3.3.3.3", "has_ptr": False, "in_dnsbl": False},
            "no2": {"exit_ip": "4.4.4.4", "has_ptr": False, "in_dnsbl": False},
        })
        self.assertEqual(self._sample(v), {"no1", "no2"})

    def test_unprofiled_pool_has_no_restrictions(self):
        # Обратная совместимость: без профилирования ограничений быть не должно
        v = NetworkValidator(timeout=2, proxies=["a:1", "b:1"])
        self.assertIn(v._pick_best_proxy(need_ptr=True), ["a:1", "b:1"])
        self.assertFalse(v._profiled)

    def test_all_ptr_absent_is_not_confused_with_unprofiled(self):
        # Регресс: когда PTR нет НИ У КОГО, все множества пусты — и раньше это
        # было неотличимо от "профилирование не проводилось"
        v = self._v({"no": {"exit_ip": "3.3.3.3", "has_ptr": False, "in_dnsbl": False}})
        self.assertTrue(v._profiled)
        self.assertIsNone(v._pick_best_proxy(need_ptr=True))


class TestDedupeProxies(unittest.TestCase):
    """Повторы в списке проверялись бы дважды и занимали два места в ротации."""

    def test_same_proxy_written_differently_collapses(self):
        from core.network import dedupe_proxies
        dup = ["1.2.3.4:1080", "socks5://1.2.3.4:1080", "  1.2.3.4:1080  "]
        self.assertEqual(len(dedupe_proxies(dup)), 1)

    def test_different_proxies_kept(self):
        from core.network import dedupe_proxies
        self.assertEqual(len(dedupe_proxies(["1.2.3.4:1080", "5.6.7.8:1080"])), 2)

    def test_order_preserved(self):
        from core.network import dedupe_proxies
        got = dedupe_proxies(["b:1080", "a:1080", "b:1080"])
        self.assertEqual(got, ["b:1080", "a:1080"])

    def test_garbage_ignored(self):
        from core.network import dedupe_proxies
        self.assertEqual(dedupe_proxies(None), [])
        self.assertEqual(dedupe_proxies("строка"), [])
        self.assertEqual(dedupe_proxies(["", "   ", None, 5]), [])


class TestDirtyRdns(unittest.TestCase):
    """Имя в PTR почтовики читают: proxy/vpn/tor/pool штрафуются."""

    def test_dirty_names_detected(self):
        from core.network import is_dirty_rdns
        for h in ["vpn-exit-12.host.net", "node-tor-exit.org",
                  "pool-71-105.fios.verizon.net", "dynamic-ip-55.isp.com",
                  "some-proxy-server.net"]:
            with self.subTest(host=h):
                self.assertTrue(is_dirty_rdns(h))

    def test_normal_mail_hosts_clean(self):
        from core.network import is_dirty_rdns
        for h in ["mail.corp.com", "mx1.google.com", "dns.google",
                  "one.one.one.one", "smtp.company.ru"]:
            with self.subTest(host=h):
                self.assertFalse(is_dirty_rdns(h))

    def test_degenerate(self):
        from core.network import is_dirty_rdns
        for bad in [None, "", 0, [], object()]:
            with self.subTest(bad=bad):
                self.assertFalse(is_dirty_rdns(bad))


class TestReputationFromThreeSignals(unittest.TestCase):
    """Пригодность для Outlook/iCloud складывается из трёх независимых признаков.

    Главный — прямая проба: замерено, что Microsoft отвергает IP, которого нет
    ни в одном чёрном списке. У него своя база репутации, и DNSBL её
    предсказывает лишь частично.
    """

    PROFILES = {
        "clean":     {"exit_ip": "1", "has_ptr": True, "in_dnsbl": False,
                      "outlook_ok": True,  "rdns_dirty": False},
        "listed":    {"exit_ip": "2", "has_ptr": True, "in_dnsbl": True,
                      "outlook_ok": True,  "rdns_dirty": False},
        "msblocked": {"exit_ip": "3", "has_ptr": True, "in_dnsbl": False,
                      "outlook_ok": False, "rdns_dirty": False},
        "dirtyname": {"exit_ip": "4", "has_ptr": True, "in_dnsbl": False,
                      "outlook_ok": True,  "rdns_dirty": True},
    }

    def setUp(self):
        self.v = NetworkValidator(timeout=2, proxies=list(self.PROFILES))
        self.v.set_proxy_profiles(self.PROFILES)

    def test_all_three_signals_mark_proxy_unusable_for_outlook(self):
        self.assertEqual(set(self.v._dirty_proxies),
                         {"listed", "msblocked", "dirtyname"})

    def test_outlook_gets_only_the_clean_one(self):
        picked = {self.v._pick_best_proxy(need_clean=True) for _ in range(60)}
        self.assertEqual(picked, {"clean"})

    def test_other_domains_still_use_whole_pool(self):
        # Для Gmail и Yandex репутация не помеха — пул не должен простаивать
        picked = {self.v._pick_best_proxy() for _ in range(120)}
        self.assertGreater(len(picked), 1)

    def test_direct_probe_outweighs_clean_blocklists(self):
        # msblocked чист по спискам, но Microsoft его отверг — значит непригоден
        self.assertIn("msblocked", self.v._dirty_proxies)


if __name__ == '__main__':
    unittest.main()
