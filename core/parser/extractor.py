import re

class EmailExtractor:
    def __init__(self):
        # Lite14 Style Regex: Extremely robust, ignoring surrounding HTML/garbage
        # Matches: anything@anything.anything
        self.pattern = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')
        
        # Extensions that are commonly false positives (e.g., from images or files)
        self.bad_extensions = {'.png', '.jpg', '.jpeg', '.gif', '.webp', '.svg', '.css', '.js', '.mp4', '.mp3', 'duckduckgo.com', 'duck.com'}
        
        # Common false positive prefixes
        self.bad_prefixes = {'sentry', '1.0.0', 'example', 'test', 'username', 'name', 'yourname', 'email'}

    def extract(self, text):
        """
        Extracts valid emails from a massive chunk of raw text/HTML.
        Returns a set of unique valid emails.
        """
        if not text:
            return set()
            
        import html
        text = html.unescape(text)
        # Strip inline tags that might break emails apart in search snippets (like <b>email@...</b>)
        text = re.sub(r'</?(b|i|em|strong|span|u|a)[^>]*>', '', text, flags=re.IGNORECASE)
        # DuckDuckGo often highlights search terms including quotes, e.g. tom.hovey"@gmail.com"
        # We must remove quotes so they don't split the email prefix from the domain
        text = text.replace('"', '').replace("'", '')
        # Replace other formatting/layout tags with spaces to prevent merging unrelated words
        text = re.sub(r'<[^>]+>', ' ', text)
            
        found_emails = set()
        raw_matches = self.pattern.findall(text)
        
        for email in raw_matches:
            email = email.lower().strip()
            
            # 1. Clean trailing dots, commas, or common punctuation that might get caught
            while email and email[-1] in {'.', ',', ';', ':', '>', '<', '"', "'"}:
                email = email[:-1]
                
            # NEW: Clean leading underscores and punctuation (from markdown/formatting)
            while email and email[0] in {'_', '.', '-', ',', ';', ':', '>', '<', '"', "'"}:
                email = email[1:]
                
            # 2. Basic length validation
            if len(email) < 6 or '@' not in email or '.' not in email:
                continue
                
            local_part, domain_part = email.rsplit('@', 1)
            
            # 3. Filter bad prefixes (like username@, example@)
            if local_part in self.bad_prefixes:
                continue
                
            # 4. Filter bad extensions (image.png@2x -> image.png)
            is_bad_ext = False
            for ext in self.bad_extensions:
                if domain_part.endswith(ext) or ext + '@' in email:
                    is_bad_ext = True
                    break
            
            if is_bad_ext:
                continue
                
            # 5. Domain must have at least one dot and valid TLD length
            if '.' not in domain_part:
                continue
                
            tld = domain_part.rsplit('.', 1)[-1]
            if len(tld) < 2 or not tld.isalpha():
                continue
                
            # If it passed all filters, it's a solid hit
            found_emails.add(email)
            
        return found_emails

if __name__ == "__main__":
    # Test the extractor
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
