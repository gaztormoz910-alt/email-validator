"""P1/P2/P5: что на самом деле представляет собой пул прокси.

Гейты выбирают тесты по -k: exit_dedup, asn, port25.
"""

import asyncio
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.proxy_profile import (classify_org, group_by_exit_ip, lookup_ip_meta,
                                pick_one_per_exit_ip, rotation_report)
from core.async_proxy import AsyncProxyChecker


def profile(exit_ip, latency=100, **extra):
    base = {"exit_ip": exit_ip, "latency_ms": latency, "has_ptr": None,
            "rdns": None, "rdns_dirty": False, "in_dnsbl": False,
            "outlook_ok": None, "ip_type": "unknown"}
    base.update(extra)
    return base


class TestExitIpDedup(unittest.TestCase):
    """P1: ротация из ста прокси через один IP — это ротация из одного."""

    def test_exit_dedup_counts_real_rotation_size(self):
        profiles = {
            "p1:1": profile("1.1.1.1"),
            "p2:2": profile("1.1.1.1"),
            "p3:3": profile("1.1.1.1"),
            "p4:4": profile("2.2.2.2"),
            "p5:5": profile("3.3.3.3"),
        }
        report = rotation_report(profiles)
        self.assertEqual(report["total"], 5)
        self.assertEqual(report["unique_ips"], 3,
                         "настоящий размер ротации посчитан неверно")
        self.assertEqual(report["duplicates"], 2,
                         "лишние прокси не посчитаны — пользователь думает, что их пять")
        self.assertEqual(report["largest_group"], 3)

    def test_exit_dedup_reports_honestly_when_all_unique(self):
        """Негативный контроль: у честного пула дублей быть не должно."""
        profiles = {f"p{i}:{i}": profile(f"10.0.0.{i}") for i in range(1, 6)}
        report = rotation_report(profiles)
        self.assertEqual(report["unique_ips"], 5)
        self.assertEqual(report["duplicates"], 0)

    def test_exit_dedup_groups_by_exit_ip(self):
        profiles = {"a:1": profile("1.1.1.1"), "b:2": profile("1.1.1.1"),
                    "c:3": profile("2.2.2.2")}
        groups = group_by_exit_ip(profiles)
        self.assertEqual(sorted(groups), ["1.1.1.1", "2.2.2.2"])
        self.assertEqual(sorted(groups["1.1.1.1"]), ["a:1", "b:2"])

    def test_exit_dedup_keeps_fastest_of_each_group(self):
        profiles = {
            "slow:1": profile("1.1.1.1", latency=900),
            "fast:2": profile("1.1.1.1", latency=80),
            "solo:3": profile("2.2.2.2", latency=300),
        }
        chosen, spare = pick_one_per_exit_ip(profiles)
        self.assertIn("fast:2", chosen, "из группы выбран не самый быстрый прокси")
        self.assertNotIn("slow:1", chosen)
        self.assertIn("solo:3", chosen)
        self.assertEqual(spare["1.1.1.1"], ["slow:1"],
                         "медленный дубль выброшен насовсем вместо запаса")

    def test_exit_dedup_never_drops_proxies_with_unknown_ip(self):
        """Про прокси без известного IP мы ничего не знаем — выбрасывать нельзя."""
        profiles = {"known:1": profile("1.1.1.1"), "unknown:2": profile(None)}
        chosen, _ = pick_one_per_exit_ip(profiles)
        self.assertIn("unknown:2", chosen,
                      "прокси без выходного IP схлопнут по догадке")

    def test_exit_dedup_survives_broken_input(self):
        for bad in (None, {}, {"p": None}, {"p": "строка"}):
            with self.subTest(bad=bad):
                report = rotation_report(bad)
                self.assertEqual(report["unique_ips"], 0)


class TestAsnAndGeo(unittest.TestCase):
    """P2: датацентровый адрес отличается от резидентного."""

    def test_asn_classifies_datacenter(self):
        for org in ("Amazon Data Services", "Hetzner Online GmbH",
                    "DigitalOcean, LLC", "M247 Europe SRL", "Some Hosting Ltd"):
            with self.subTest(org=org):
                self.assertEqual(classify_org(org), "datacenter")

    def test_asn_classifies_residential_and_mobile(self):
        self.assertEqual(classify_org("Comcast Cable Communications"), "residential")
        self.assertEqual(classify_org("Deutsche Telekom AG"), "residential")
        self.assertEqual(classify_org("T-Mobile USA Mobile"), "mobile")
        self.assertEqual(classify_org("Vodafone Cellular"), "mobile")

    def test_asn_datacenter_wins_over_telecom_wording(self):
        """«Hosting Telecom Ltd» — это датацентр, а не домашний интернет."""
        self.assertEqual(classify_org("Hosting Telecom Ltd"), "datacenter")

    def test_asn_unknown_org_is_not_guessed(self):
        for org in ("", None, "   ", "Zzz Qqq"):
            with self.subTest(org=org):
                self.assertEqual(classify_org(org), "unknown")

    def test_asn_lookup_parses_rdap_answer(self):
        sample = {
            "handle": "AS16509",
            "country": "us",
            "entities": [{"vcardArray": ["vcard", [
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", "Amazon Data Services"],
            ]]}],
        }
        meta = lookup_ip_meta("8.8.8.8", fetcher=lambda ip: sample)
        self.assertEqual(meta["asn"], 16509)
        self.assertEqual(meta["asn_country"], "US")
        self.assertEqual(meta["asn_org"], "Amazon Data Services")
        self.assertEqual(meta["ip_type"], "datacenter")

    def test_asn_lookup_survives_broken_answer(self):
        for bad in (None, {}, "не словарь", []):
            with self.subTest(bad=bad):
                meta = lookup_ip_meta("9.9.9.9", fetcher=lambda ip, b=bad: b)
                self.assertEqual(meta["ip_type"], "unknown")
                self.assertIsNone(meta["asn"])

    def test_asn_lookup_skips_private_addresses(self):
        """Приватный адрес спрашивать бессмысленно — это трата запроса."""
        asked = []
        for ip in ("127.0.0.1", "192.168.1.1", "10.0.0.5", "не-ip"):
            with self.subTest(ip=ip):
                meta = lookup_ip_meta(ip, fetcher=lambda i: asked.append(i))
                self.assertEqual(meta["ip_type"], "unknown")
        self.assertEqual(asked, [], "для приватного адреса ушёл сетевой запрос")

    def test_asn_appears_in_profile_contract(self):
        """Поля обязаны быть в профиле, иначе маршрутизация их не увидит."""
        import inspect
        from core import network
        source = inspect.getsource(network.profile_proxies)
        for field in ("asn", "asn_country", "asn_org", "ip_type"):
            with self.subTest(field=field):
                self.assertIn(f'"{field}"', source,
                              f"поле {field} не попадает в профиль прокси")


class TestPort25Diagnosis(unittest.TestCase):
    """P5: «прокси мёртв» и «25 закрыт» — разные диагнозы и разные действия."""

    def test_port25_checker_has_three_verdicts(self):
        checker = AsyncProxyChecker(["1.2.3.4:1080"], mode="smtp")
        self.assertEqual(checker.diagnosis_report(),
                         {"live": 0, "port25_blocked": 0, "dead": 0})

    def test_port25_control_target_is_not_the_smtp_target(self):
        checker = AsyncProxyChecker(["1.2.3.4:1080"], mode="smtp")
        self.assertEqual(checker.target_port, 25)
        self.assertEqual(checker.control_port, 443)
        self.assertNotEqual(checker.control_host, checker.target_host)

    def test_port25_blocked_when_control_port_answers(self):
        """Прокси ответил по 443, но не по 25 — виноват порт, а не прокси."""
        checker = AsyncProxyChecker([], mode="smtp")

        async def yes(*_a, **_kw):
            return True

        checker._control_reachable = yes
        verdict = asyncio.run(checker._diagnose_failure("socks5", "1.1.1.1", 1080,
                                                        None, None))
        self.assertEqual(verdict, "port25_blocked")

    def test_port25_dead_when_control_port_also_silent(self):
        """Негативный контроль: молчит и по 443 — значит действительно мёртв."""
        checker = AsyncProxyChecker([], mode="smtp")

        async def no(*_a, **_kw):
            return False

        checker._control_reachable = no
        verdict = asyncio.run(checker._diagnose_failure("socks5", "1.1.1.1", 1080,
                                                        None, None))
        self.assertEqual(verdict, "dead")

    def test_port25_control_probe_is_skipped_in_http_mode(self):
        """В режиме парсера контрольная проба — лишнее соединение."""
        checker = AsyncProxyChecker([], mode="http")
        called = []

        async def spy(*_a, **_kw):
            called.append(1)
            return True

        checker._control_reachable = spy
        verdict = asyncio.run(checker._diagnose_failure("socks5", "1.1.1.1", 1080,
                                                        None, None))
        self.assertEqual(verdict, "dead")
        self.assertEqual(called, [], "в режиме http потрачена лишняя проба")

    def test_port25_tunnel_and_target_check_are_separate(self):
        """Разделение нужно, чтобы контрольная проба не дублировала протоколы."""
        checker = AsyncProxyChecker([], mode="smtp")
        for name in ("_open_socks4_tunnel", "_open_socks5_tunnel",
                     "_open_http_tunnel", "_check_socks4", "_check_socks5"):
            with self.subTest(name=name):
                self.assertTrue(hasattr(checker, name), f"нет метода {name}")


if __name__ == "__main__":
    unittest.main()
