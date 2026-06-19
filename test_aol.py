import requests
try:
    res = requests.get("https://aol.com", timeout=10)
    print(res.text[:500])
except Exception as e:
    print(e)
