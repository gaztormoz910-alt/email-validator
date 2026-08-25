"""Системные проверки, а не точечные.

Здесь три автоматических прогона, которые ловят целые КЛАССЫ ошибок:
  1. Фаззинг — ни одна публичная функция не падает на мусорном входе.
  2. Инварианты — свойства, которые обязаны выполняться при любых данных.
  3. Гонки — общее состояние переживает параллельную нагрузку.

Смысл файла в том, что он гоняется на КАЖДОМ прогоне тестов. Точечные
проверки ловят только то, на что смотрят; эти — то, о чём никто не подумал.
"""
import inspect
import itertools
import random
import threading
import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import core.network as N
import core.cleaner as C
import core.heuristics as H
import core.provider as P
import core.scoring as S
import core.disposable as D
# Модули, появившиеся позже. Их обязательно держать в этом же списке: сито
# ловит только то, что в него положили, и новый модуль без обстрела — это
# ровно тот случай, когда падение на мусоре находят уже на живой базе.
import core.baseops as BO
import core.cache as CA
import core.filters as FL
import core.github_parser as GP
import core.parser.names_index as NIX
import core.parser.translit as TRL
from core.network import NetworkValidator, PROXY_MAX_CONSECUTIVE_FAILS as MAXF
from core.scoring import calculate_engagement_score as score
from core.cleaner import EmailCleaner, normalize_for_dedup

# Мусор, которым обстреливаем каждую функцию
GARBAGE = [
    None, "", "   ", 0, -1, 3.5, [], {}, (), set(), True, b"bytes", object(),
    "мусор", "@", "a@", "@b", "a@b", "a" * 400, "a@" * 50, "\x00",
    "a@b@c.com", "..@..", "a@[1.2.3.4]", "иван@почта.рф",
    "a@b.", ".a@b.com", "a@.b.com",
]

CONTRACT_ERRORS = (TypeError, ValueError, AttributeError, KeyError, IndexError,
                   UnboundLocalError, ZeroDivisionError, RecursionError)


class TestNoCrashOnGarbage(unittest.TestCase):
    """Публичная функция не должна падать на мусорном входе.

    Падение здесь означает, что где-то в пайплайне неожиданный None или
    пустая строка уронит обработку адреса — а исключение будет проглочено
    и адрес молча выпадет из выдачи.
    """

    def _targets(self):
        v = NetworkValidator(timeout=2)
        targets = []
        for mod in (N, C, H, P, S, D, BO, CA, FL, GP, NIX, TRL):
            for name, fn in vars(mod).items():
                if (inspect.isfunction(fn) and not name.startswith("__")
                        and getattr(fn, "__module__", "") == mod.__name__):
                    targets.append((mod.__name__ + "." + name, fn))
        for name in ["_parse_smtp_response", "_is_server_outdated",
                     "has_proxies_configured", "get_live_proxy_count",
                     "all_proxies_dead", "has_ptr_proxies", "has_clean_proxies",
                     "_pick_best_proxy", "set_ptr_proxies", "set_proxy_profiles",
                     "_update_proxy_score", "_choose_from", "check_dnsbl_ip"]:
            fn = getattr(v, name, None)
            if fn:
                targets.append(("NetworkValidator." + name, fn))
        return targets

    def test_every_public_function_survives_garbage(self):
        crashes = []
        for label, fn in self._targets():
            try:
                required = [p for p in inspect.signature(fn).parameters.values()
                            if p.kind in (p.POSITIONAL_OR_KEYWORD, p.POSITIONAL_ONLY)
                            and p.default is p.empty]
            except (ValueError, TypeError):
                continue
            n = len(required)
            if n == 0:
                combos = [()]
            elif n == 1:
                combos = [(g,) for g in GARBAGE]
            else:
                combos = list(itertools.islice(
                    itertools.product(GARBAGE, repeat=n), 150))
            for args in combos:
                try:
                    fn(*args)
                except CONTRACT_ERRORS as e:
                    crashes.append(label + " -> " + type(e).__name__ + ": " + str(e)[:60])
                    break
                except Exception:
                    pass  # сетевые и прочие — не нарушение контракта
        self.assertEqual(crashes, [], "функции падают на мусоре: " + str(crashes[:6]))


class TestScoringInvariants(unittest.TestCase):
    """Свойства скоринга, которые обязаны держаться при любых входах."""

    def test_score_always_within_bounds(self):
        for st in ["Valid", "Risky", "Unknown", "Invalid/Bounce", "Role-based"]:
            for dns in range(4):
                for age in [-1, 5, 60, 400, 4000]:
                    r = score(email="a@corp.com", smtp_status=st,
                              dns_health_score=dns, domain_age_days=age)
                    with self.subTest(status=st, dns=dns, age=age):
                        self.assertGreaterEqual(r["score"], 0)
                        self.assertLessEqual(r["score"], 100)

    def test_confirmed_bounce_is_always_zero(self):
        # Ни один положительный сигнал не может воскресить подтверждённый bounce
        for kw in itertools.islice(itertools.product([True, False], repeat=6), 64):
            r = score(email="a@corp.com", smtp_status="Invalid/Bounce",
                      has_gravatar=kw[0], dns_health_score=3, domain_age_days=9000,
                      name_extracted="X" if kw[1] else "", has_ptr=kw[2],
                      has_starttls=kw[3], machine_generated=kw[4],
                      is_parked_domain=kw[5])
            self.assertEqual((r["score"], r["grade"]), (0, "Dead"))

    def test_penalties_never_raise_score(self):
        base = score(email="a@corp.com", smtp_status="Valid")["score"]
        for pen in ["is_disposable", "is_role_based", "server_outdated",
                    "in_dnsbl", "machine_generated", "is_parked_domain"]:
            with self.subTest(penalty=pen):
                r = score(email="a@corp.com", smtp_status="Valid", **{pen: True})
                self.assertLessEqual(r["score"], base)

    def test_bonuses_never_lower_score(self):
        base = score(email="a@corp.com", smtp_status="Valid")["score"]
        for bon, val in [("has_gravatar", True), ("dns_health_score", 3),
                         ("name_extracted", "Ivan"), ("domain_age_days", 9000)]:
            with self.subTest(bonus=bon):
                r = score(email="a@corp.com", smtp_status="Valid", **{bon: val})
                self.assertGreaterEqual(r["score"], base)


class TestSmtpInvariants(unittest.TestCase):
    """invalid ставится ТОЛЬКО при доказанном отсутствии получателя."""

    PROOF = ["does not exist", "no such user", "user unknown", "unknown user",
             "invalid recipient", "mailbox unavailable", "recipient address rejected",
             "user not found", "recipient rejected"]

    def test_invalid_requires_proof(self):
        v = NetworkValidator(timeout=2)
        for code in [250, 421, 450, 451, 452, 500, 501, 502, 503, 504, 521,
                     530, 535, 550, 551, 552, 553, 554, 571, 599]:
            for txt in [b"", b"error", b"try again", b"blocked",
                        b"sender rejected", b"quota", b"storage"]:
                r = v._parse_smtp_response(code, txt, "a@b.com", "b.com")
                if r["status"] == "invalid":
                    low = txt.decode().lower() + r["reason"].lower()
                    with self.subTest(code=code, txt=txt):
                        self.assertTrue(
                            any(p in low for p in self.PROOF) or code in (551, 553),
                            str(code) + " -> invalid без доказательства: " + r["reason"])

    def test_status_always_from_known_set(self):
        v = NetworkValidator(timeout=2)
        allowed = {"valid", "invalid", "risky", "unknown", "greylisted", "catchall"}
        for code in range(200, 600, 7):
            r = v._parse_smtp_response(code, b"whatever", "a@b.com", "b.com")
            self.assertIn(r["status"], allowed)


class TestCleanerInvariants(unittest.TestCase):
    SAMPLES = ["Bob@Gmail.COM", "bob@gmail.comtelefoon", "bob@yandex.rublahblah",
               "a.b@corp.co.uk", "bob@x.gmail.com.y.yahoo.com.z",
               "...bob...@gmail.com", "bob@mail.ruXXX"]

    def test_cleaning_is_idempotent(self):
        c = EmailCleaner()
        for e in self.SAMPLES:
            once = c.clean_email(e)
            if once:
                with self.subTest(email=e):
                    self.assertEqual(c.clean_email(once), once)

    def test_normalization_is_idempotent(self):
        for e in self.SAMPLES:
            key = normalize_for_dedup(e)
            with self.subTest(email=e):
                self.assertEqual(normalize_for_dedup(key), key)


class TestProxyStateUnderConcurrency(unittest.TestCase):
    """Общее состояние прокси переживает параллельную нагрузку.

    Валидатор ходит в 100-300 потоков, и все они дёргают один и тот же пул.
    """

    def test_no_exceptions_and_bans_hold(self):
        pool = ["p%d:1080" % i for i in range(20)]
        v = NetworkValidator(timeout=2, proxies=list(pool))
        v.set_proxy_profiles({p: {"exit_ip": "1.1.1.%d" % i,
                                  "has_ptr": i % 3 == 0,
                                  "in_dnsbl": i % 5 == 0}
                              for i, p in enumerate(pool)})
        errors = []

        def hammer():
            try:
                for _ in range(1500):
                    p = random.choice(pool)
                    v._update_proxy_score(p, random.random() < 0.5)
                    v._pick_best_proxy(need_ptr=random.random() < 0.5,
                                       need_clean=random.random() < 0.5)
                    v.get_live_proxy_count()
                    v.has_ptr_proxies()
                    v.has_clean_proxies()
            except Exception as e:
                errors.append(type(e).__name__ + ": " + str(e))

        threads = [threading.Thread(target=hammer) for _ in range(12)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], "исключения в гонке: " + str(errors[:3]))

        banned = set(v._proxy_banned)
        picks = {v._pick_best_proxy() for _ in range(200)} - {None}
        self.assertFalse(picks & banned, "забаненный прокси всё же выбран")
        self.assertEqual(v.get_live_proxy_count(), len(set(pool) - banned))

    def test_success_resets_consecutive_failures(self):
        v = NetworkValidator(timeout=2, proxies=["a:1", "b:1"])
        for _ in range(MAXF - 1):
            v._update_proxy_score("a:1", False)
        v._update_proxy_score("a:1", True)      # успех обнуляет счётчик
        for _ in range(MAXF - 1):
            v._update_proxy_score("a:1", False)
        self.assertEqual(v.get_live_proxy_count(), 2)


class TestDeadlineBounds(unittest.TestCase):
    def test_deadline_always_bounded(self):
        # Даже при абсурдном таймауте один адрес не должен висеть вечно
        for t in [1, 5, 10, 30, 60, 300, 10000]:
            with self.subTest(timeout=t):
                v = NetworkValidator(timeout=t)
                self.assertGreaterEqual(v.address_deadline, 30)
                self.assertLessEqual(v.address_deadline, 180)


if __name__ == '__main__':
    unittest.main()
