import urllib.request
import re

url = "https://search.yahoo.com/yhs/search?hspart=aol&hsimp=yhs-aol_catchall&p=email&b=11"
req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
try:
    html = urllib.request.urlopen(req).read().decode('utf-8')
    print("Contains 'pagination':", 'pagination' in html.lower())
    print("Contains 'next':", 'next' in html.lower())
    
    # Try to find Next link
    next_links = re.findall(r'<a[^>]+class=["\'][^"\']*next[^"\']*["\'][^>]*href=["\']([^"\']+)["\']', html, re.IGNORECASE)
    print("Next Links (class):", next_links)
    
    # Just look for Next text
    next_text_links = re.findall(r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>Next</a>', html, re.IGNORECASE)
    print("Next Links (text):", next_text_links)
    
    # Extract ALL b= values from hrefs
    b_values = re.findall(r'href=["\'][^"\']*b=(\d+)[^"\']*["\']', html)
    print("b= values in hrefs:", sorted(list(set(int(b) for b in b_values))))
except Exception as e:
    print(f"Error: {e}")
