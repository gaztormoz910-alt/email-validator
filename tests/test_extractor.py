import unittest
import sys
import os

# Add the project root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.parser.extractor import EmailExtractor

class TestEmailExtractor(unittest.TestCase):
    def setUp(self):
        self.extractor = EmailExtractor()

    def test_basic_emails(self):
        text = "Contact us at support@example.com or sales@example.co.uk."
        emails = self.extractor.extract(text)
        self.assertEqual(emails, {'support@example.com', 'sales@example.co.uk'})

    def test_html_tags_and_urls(self):
        text = '''
        <a href="mailto:info@startup.io">Email us</a>
        <p>Another one is ceo@startup.io</p>
        <div>Contact: <a href="mailto:contact@domain.com">contact@domain.com</a></div>
        '''
        emails = self.extractor.extract(text)
        self.assertEqual(emails, {'info@startup.io', 'ceo@startup.io', 'contact@domain.com'})

    def test_garbage_and_punctuation(self):
        text = "Emails: john.doe@gmail.com, test1@test.com! (test2@test.com) <test3@test.com> test4@test.com."
        emails = self.extractor.extract(text)
        self.assertEqual(emails, {'john.doe@gmail.com', 'test1@test.com', 'test2@test.com', 'test3@test.com', 'test4@test.com'})

    def test_false_positives(self):
        text = '''
        Please do not extract image.png@2x or script.js@v1.
        Ignore sentry@1.0.0 and version@2.0.0.
        Skip username@domain or test@example or example@test.
        But keep real.email@gmail.com.
        '''
        emails = self.extractor.extract(text)
        self.assertEqual(emails, {'real.email@gmail.com'})

    def test_deduplication(self):
        text = "Duplicate valid.email@test.com and valid.email@test.com and VALID.EMAIL@TEST.COM."
        emails = self.extractor.extract(text)
        self.assertEqual(emails, {'valid.email@test.com'})

    def test_empty_and_no_emails(self):
        self.assertEqual(self.extractor.extract(""), set())
        self.assertEqual(self.extractor.extract("Just some random text with no emails."), set())

if __name__ == '__main__':
    unittest.main()
