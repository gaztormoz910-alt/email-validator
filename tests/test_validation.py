import unittest
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


class TestEngagementScore(unittest.TestCase):
    def setUp(self):
        from core.scoring import calculate_engagement_score
        self.score = calculate_engagement_score

    def test_valid_smtp_with_good_server(self):
        r = self.score(email='test@corp.com', smtp_status='Valid', has_ptr=True, has_starttls=True)
        self.assertGreaterEqual(r['score'], 30)

    def test_full_inbox_with_good_server(self):
        r = self.score(email='test@corp.com', smtp_status='Mailbox Full', smtp_reason='452 OK (Mailbox Full)', has_ptr=True, has_starttls=True)
        plain = self.score(email='test@corp.com', smtp_status='Valid', smtp_reason='250 OK', has_ptr=True, has_starttls=True)
        self.assertLess(r['score'], plain['score'])

    def test_valid_without_ptr_starttls_gets_penalized(self):
        r = self.score(email='test@corp.com', smtp_status='Valid', has_ptr=False, has_starttls=False)
        clean = self.score(email='test@corp.com', smtp_status='Valid', has_ptr=True, has_starttls=True)
        self.assertLess(r['score'], clean['score'])

    def test_unmeasured_ptr_starttls_not_penalized(self):
        r = self.score(email='test@corp.com', smtp_status='Valid', has_ptr=None, has_starttls=None)
        signals = ' '.join(r['signals'])
        self.assertNotIn('PTR', signals)
        self.assertNotIn('STARTTLS', signals)

    def test_confirmed_valid_mailbox_never_graded_dead(self):
        r = self.score(email='john@acme-corp.com', smtp_status='Valid', dns_health_score=3,
                       domain_age_days=3000, name_extracted='John',
                       has_ptr=False, has_starttls=False)
        self.assertNotIn(r['grade'], ('Dead', 'Cold'))

    def test_disposable_heavy_penalty(self):
        r = self.score(email='x@tempmail.com', smtp_status='Valid', is_disposable=True)
        self.assertLessEqual(r['score'], 30)

    def test_dnsbl_penalty(self):
        r = self.score(email='x@spam.com', smtp_status='Valid', in_dnsbl=True)
        self.assertIn('-40', ' '.join(r['signals']))

    def test_no_ptr_penalty(self):
        r = self.score(email='x@sketchy.com', smtp_status='Valid', has_ptr=False)
        self.assertIn('-10', ' '.join(r['signals']))

    def test_no_starttls_penalty(self):
        r = self.score(email='x@old.com', smtp_status='Valid', has_starttls=False)
        self.assertIn('-5', ' '.join(r['signals']))

    def test_gravatar_gives_10_not_20(self):
        r = self.score(email='x@test.com', smtp_status='Valid', has_gravatar=True)
        self.assertIn('+10', ' '.join(r['signals']))

    def test_role_based_preserves_smtp_score(self):
        r = self.score(email='info@corp.com', smtp_status='Role-based', is_role_based=True, original_smtp_status='Valid')
        signals = ' '.join(r['signals'])
        self.assertIn('SMTP 250 OK', signals)
        self.assertIn('Role-based', signals)

    def test_alive_free_provider_can_reach_hot(self):
        r = self.score(email='ivan.petrov@gmail.com', smtp_status='Valid',
                       smtp_reason='250 OK', dns_health_score=3,
                       domain_age_days=11330, name_extracted='Ivan')
        self.assertGreaterEqual(r['score'], 70)
        self.assertEqual(r['grade'], 'Hot')

    def test_bare_alive_gmail_is_at_least_warm(self):
        r = self.score(email='qzx48213@gmail.com', smtp_status='Valid',
                       smtp_reason='250 OK', dns_health_score=3)
        self.assertGreaterEqual(r['score'], 50)

    def test_full_inbox_ranks_below_plain_ok(self):
        full = self.score(email='a@gmail.com', smtp_status='Valid',
                          smtp_reason='452 OK (Mailbox Full)', dns_health_score=3)
        plain = self.score(email='a@gmail.com', smtp_status='Valid',
                           smtp_reason='250 OK', dns_health_score=3)
        self.assertLess(full['score'], plain['score'])

    def test_machine_generated_alive_stays_below_warm(self):
        r = self.score(email='xk3n9fj2q4@gmail.com', smtp_status='Valid',
                       smtp_reason='250 OK', dns_health_score=3,
                       machine_generated=True)
        self.assertLess(r['score'], 50)

    def test_confirmed_bounce_is_dead_despite_healthy_domain(self):
        r = self.score(email='nosuchuser@gmail.com', smtp_status='Invalid/Bounce',
                       smtp_reason='5.1.1 550 User Does Not Exist',
                       dns_health_score=3, domain_age_days=9000, name_extracted='John')
        self.assertEqual(r['grade'], 'Dead')
        self.assertEqual(r['score'], 0)

    def test_grade_dead(self):
        r = self.score(email='x@temp.com', smtp_status='Invalid/Bounce', is_disposable=True)
        self.assertEqual(r['grade'], 'Dead')

    def test_young_domain_penalty(self):
        r = self.score(email='x@new.com', smtp_status='Valid', domain_age_days=15)
        self.assertIn('-20', ' '.join(r['signals']))

    def test_old_domain_bonus(self):
        r = self.score(email='x@old.com', smtp_status='Valid', domain_age_days=2000)
        self.assertIn('+5', ' '.join(r['signals']))

    def test_score_clamped_0_100(self):
        r = self.score(email='x@trash.com', smtp_status='Invalid/Bounce', is_disposable=True, in_dnsbl=True)
        self.assertGreaterEqual(r['score'], 0)
        self.assertLessEqual(r['score'], 100)

    def test_grade_hot(self):
        r = self.score(email='ceo@company.com', smtp_status='Valid', smtp_reason='250 OK', has_gravatar=True, dns_health_score=3, domain_age_days=2000, name_extracted='John', has_ptr=True, has_starttls=True)
        self.assertEqual(r['grade'], 'Hot')
        self.assertGreaterEqual(r['score'], 70)

    def test_no_website_penalty_corporate(self):
        r = self.score(email='x@deadcorp.biz', smtp_status='Valid', has_live_website=False)
        self.assertIn('-5', ' '.join(r['signals']))


class TestDisposable(unittest.TestCase):
    def setUp(self):
        from core.disposable import is_disposable
        self.check = is_disposable

    def test_known_disposable(self):
        self.assertTrue(self.check('user@guerrillamail.com'))
        self.assertTrue(self.check('user@mailinator.com'))

    def test_legit_provider(self):
        self.assertFalse(self.check('user@gmail.com'))
        self.assertFalse(self.check('user@yahoo.com'))

    def test_privacy_relays_not_disposable(self):
        self.assertFalse(self.check('user@duck.com'))

    def test_subdomain_of_disposable(self):
        self.assertTrue(self.check('user@sub.mailinator.com'))

    def test_corporate_not_disposable(self):
        self.assertFalse(self.check('admin@tesla.com'))


class TestGravatar(unittest.TestCase):
    def setUp(self):
        from core.gravatar import GravatarChecker
        self.checker = GravatarChecker(timeout=2)

    def test_cache_is_ordered_dict(self):
        from collections import OrderedDict
        self.assertIsInstance(self.checker._cache, OrderedDict)


class TestFreeProviderClassification(unittest.TestCase):

    def setUp(self):
        from core.scoring import calculate_engagement_score, _is_free_provider
        self.score = calculate_engagement_score
        self.is_free = _is_free_provider

    def test_major_free_providers_recognised(self):
        for d in ["gmail.com", "yandex.ru", "mail.ru", "bk.ru", "protonmail.com",
                  "gmx.com", "qq.com", "outlook.com", "icloud.com"]:
            with self.subTest(domain=d):
                self.assertTrue(self.is_free(d))

    def test_corporate_domains_stay_corporate(self):
        for d in ["tesla.com", "acme-corp.ru", "some-startup.io"]:
            with self.subTest(domain=d):
                self.assertFalse(self.is_free(d))

    def test_free_providers_score_equally(self):
        scores = {}
        for e in ["postmaster@gmail.com", "postmaster@yandex.ru", "postmaster@mail.ru"]:
            r = self.score(email=e, smtp_status="Valid", smtp_reason="250 OK",
                           dns_health_score=2, has_ptr=True)
            scores[e] = r["score"]
            self.assertEqual(r["provider_type"], "Free")
        self.assertEqual(len(set(scores.values())), 1, f"скоры разошлись: {scores}")


class TestAuditSubsystemsCoverage(unittest.TestCase):

    def test_gravatar_lru_move_to_end(self):
        from core.gravatar import GravatarChecker
        checker = GravatarChecker()
        with checker._cache_lock:
            checker._cache.clear()
            checker._cache["first@test.com"] = False
            checker._cache["second@test.com"] = True
            self.assertEqual(list(checker._cache.keys()), ["first@test.com", "second@test.com"])

        res = checker.has_gravatar("first@test.com")
        self.assertFalse(res)
        with checker._cache_lock:
            self.assertEqual(list(checker._cache.keys())[-1], "first@test.com")

    def test_spam_filter_loaded_and_detects(self):
        from core.filters import SpamFilter
        sf = SpamFilter()
        self.assertGreater(sf.get_count(), 0)
        self.assertTrue(sf.is_spam_or_disposable("trash@mailinator.com"))
        self.assertFalse(sf.is_spam_or_disposable("valid@gmail.com"))

    def test_domain_age_datetime_utc_safety(self):
        import datetime
        from core.pipeline import _utc_now, _as_utc
        now = _utc_now()
        self.assertIsNotNone(now.tzinfo)

        naive = datetime.datetime(2020, 1, 1, 12, 0, 0)
        aware_converted = _as_utc(naive)
        self.assertIsNotNone(aware_converted.tzinfo)
        diff_naive = (now - aware_converted).days
        self.assertGreater(diff_naive, 365)

        aware = datetime.datetime(2020, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)
        diff_aware = (now - _as_utc(aware)).days
        self.assertEqual(diff_naive, diff_aware)

    def test_mail_from_pool_no_strict_spf(self):
        from core.network import MAIL_FROM_POOL
        self.assertGreaterEqual(len(MAIL_FROM_POOL), 3)
        for sender in MAIL_FROM_POOL:
            self.assertNotIn("@outlook.com", sender.lower())
            self.assertNotIn("@yahoo.com", sender.lower())


if __name__ == '__main__':
    unittest.main()

