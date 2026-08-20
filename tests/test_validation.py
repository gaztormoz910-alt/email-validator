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
        r = self.score(email='test@corp.com', smtp_status='Valid', smtp_reason='452 OK (Mailbox Full)', has_ptr=True, has_starttls=True)
        self.assertGreaterEqual(r['score'], 40)

    def test_valid_without_ptr_starttls_gets_penalized(self):
        r = self.score(email='test@corp.com', smtp_status='Valid', has_ptr=False, has_starttls=False)
        clean = self.score(email='test@corp.com', smtp_status='Valid', has_ptr=True, has_starttls=True)
        self.assertLess(r['score'], clean['score'])

    def test_unmeasured_ptr_starttls_not_penalized(self):
        # None = проверить не удалось. Отсутствие данных не должно наказывать почту.
        r = self.score(email='test@corp.com', smtp_status='Valid', has_ptr=None, has_starttls=None)
        signals = ' '.join(r['signals'])
        self.assertNotIn('PTR', signals)
        self.assertNotIn('STARTTLS', signals)

    def test_confirmed_valid_mailbox_never_graded_dead(self):
        # Гигиена сервера не должна перебивать прямое SMTP 250 OK.
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
        self.assertIn('+30', signals)
        self.assertIn('-15', signals)

    def test_confirmed_bounce_is_dead_despite_healthy_domain(self):
        # 550 на живом gmail.com: домен здоров, но ящика не существует.
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
        r = self.score(email='ceo@company.com', smtp_status='Valid', smtp_reason='Mailbox Full', has_gravatar=True, dns_health_score=3, domain_age_days=2000, name_extracted='John', has_ptr=True, has_starttls=True)
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


if __name__ == '__main__':
    unittest.main()

