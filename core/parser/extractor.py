import re

from core.email_syntax import harvest_pattern


class EmailExtractor:
    def __init__(self):
        # Образец общий с проверкой синтаксиса — в режиме «текст со ссылками».
        #
        # Свой набор символов был уже: из него выпадали ! # $ % & ' * + / = ?
        # ^ _ ` { | } ~, которые RFC 5322 в имени ящика разрешает. Адрес не
        # пропадал, а ОБРЕЗАЛСЯ до другого, тоже существующего: собранный
        # o'brien@gmail.com попадал в базу как brien@gmail.com.
        self.pattern = harvest_pattern(wide=False)
        
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

        # Pull mailto: hrefs first - they live inside tag attributes and would
        # otherwise be lost once the tag itself gets stripped below.
        mailto_matches = [m.group(1) for m in re.finditer(
            r'mailto:(' + self.pattern.pattern + r')', text, flags=re.IGNORECASE)]

        # Strip inline tags that might break emails apart in search snippets (like <b>email@...</b>)
        text = re.sub(r'</?(b|i|em|strong|span|u|a)[^>]*>', '', text, flags=re.IGNORECASE)
        # DuckDuckGo подсвечивает найденное кавычками: tom.hovey"@gmail.com".
        # Двойные убираем — в адресе они без экранирования не встречаются.
        #
        # А ОДИНАРНУЮ трогать нельзя, хотя раньше убирали и её: апостроф в
        # o'brien@gmail.com — часть фамилии, и без него получается obrien@ —
        # чужой существующий ящик. Подменить адрес хуже, чем потерять.
        text = text.replace('"', '')
        # Replace other formatting/layout tags with spaces to prevent merging unrelated words.
        # Only matches real tags (name starts with a letter, then whitespace/attrs or '>')
        # so plain text incidentally wrapped in <angle brackets>, like <foo@bar.com>, survives.
        text = re.sub(r'</?[a-zA-Z][a-zA-Z0-9]*(?:\s[^<>]*)?>', ' ', text)

        found_emails = set()
        raw_matches = self.pattern.findall(text) + mailto_matches
        
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
            # Punycode-зона (xn--p1ai для .рф) состоит не из одних букв, и
            # проверка на isalpha() выбрасывала КАЖДЫЙ адрес на кириллическом
            # домене — молча, без единой строки в логе.
            if len(tld) < 2 or not (tld.isalpha() or tld.startswith('xn--')):
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
