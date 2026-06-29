import requests
from core.parser.extractor import EmailExtractor

session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html"
})
url = "https://search.yahoo.com/yhs/search?hspart=aol&hsimp=yhs-aol_catchall&p=site:linkedin.com/in/+%22CEO%22+%22%40gmail.com%22"
res = session.get(url)
print("Status code:", res.status_code)
if res.status_code == 200:
    html = res.text
    print("HTML length:", len(html))
    print("Found 'captcha':", 'captcha' in html.lower())
    
    extractor = EmailExtractor()
    emails = extractor.extract(html)
    print("Extracted emails:", emails)
    
    with open("test_yahoo_raw.html", "w", encoding="utf-8") as f:
        f.write(html)
