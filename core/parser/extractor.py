import re

from core.email_syntax import harvest_pattern


class EmailExtractor:
    def __init__(self):
        self.pattern = harvest_pattern(wide=False)
        
        self.bad_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.css', '.js', '.mp4', '.mp3', 'duckduckgo.com', 'duck.com'}
        
        self.bad_prefixes = {'sentry', '1.0.0', 'example', 'test', 'username', 'name', 'yourname', 'email'}

    def extract(self, text):
        if not text:
            return set()
            
        import html
        text = html.unescape(text)

        mailto_matches = [m.group(1) for m in re.finditer(
            r'mailto:(' + self.pattern.pattern + r')', text, flags=re.IGNORECASE)]

        text = re.sub(r'</?(b|i|em|strong|span|u|a)[^>]*>', '', text, flags=re.IGNORECASE)
        text = text.replace('"', '')
        text = re.sub(r'</?[a-zA-Z][a-zA-Z0-9]*(?:\s[^<>]*)?>', ' ', text)

        found_emails = set()
        raw_matches = self.pattern.findall(text) + mailto_matches
        
        for email in raw_matches:
            email = email.lower().strip()
            
            while email and email[-1] in {'.', ',', ';', ':', '>', '<', '"', "'"}:
                email = email[:-1]
                
            while email and email[0] in {'_', '.', '-', ',', ';', ':', '>', '<', '"', "'"}:
                email = email[1:]
                
            if len(email) < 6 or '@' not in email or '.' not in email:
                continue
                
            local_part, domain_part = email.rsplit('@', 1)
            
            if local_part in self.bad_prefixes:
                continue
                
            is_bad_ext = False
            for ext in self.bad_extensions:
                if domain_part.endswith(ext) or ext + '@' in email:
                    is_bad_ext = True
                    break
            
            if is_bad_ext:
                continue
                
            if '.' not in domain_part:
                continue
                
            tld = domain_part.rsplit('.', 1)[-1]
            if len(tld) < 2 or not (tld.isalpha() or tld.startswith('xn--')):
                continue
                
            found_emails.add(email)
            
        return found_emails

if __name__ == "__main__":
    extractor = EmailExtractor()
    test_text = '''
    Here are some emails: john.doe@gmail.com, test@example.com (don't use this).
    Also an image: profile.png@2x and some html <a href="mailto:support@company.co.uk">Contact Us</a>
    And some garbage sentry@1.0.0 or email@email.com.
    Let's catch this one: ceo@startup.io!
    '''
    results = extractor.extract(test_text)
    print("Found emails:")
    for e in results:
        print(f"- {e}")
