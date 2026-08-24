import hashlib
import json
import urllib.request
import urllib.error


class OSINTOperator:
    """Публичный профиль Gravatar по адресу.

    Про прокси. Раньше этот модуль ходил на gravatar.com голым urlopen — и
    когда пользователь включал обогащение (а оно включено по умолчанию), MD5
    каждого адреса базы уезжал наружу с его РЕАЛЬНОГО IP. Соседний
    core/gravatar.py при этом давно ходил через прокси, так что канал был
    закрыт лишь наполовину. Теперь оба пути используют один и тот же
    proxy_provider.
    """

    def __init__(self, proxy_provider=None, timeout=5.0):
        # Отдаёт словарь прокси для requests или None, если прокси не заданы
        self.proxy_provider = proxy_provider
        self.timeout = timeout

    def _fetch_profile(self, email):
        """Публичный JSON-профиль Gravatar или None."""
        if not email:
            return None
        email_hash = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
        url = f"https://en.gravatar.com/{email_hash}.json"

        proxies = None
        try:
            if self.proxy_provider:
                proxies = self.proxy_provider()
        except Exception:
            proxies = None

        try:
            if proxies:
                import requests
                resp = requests.get(url, timeout=self.timeout, proxies=proxies,
                                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code != 200:
                    return None
                data = resp.json()
            else:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    data = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError:
            return None   # 404 — профиля нет, это норма
        except Exception:
            return None

        entries = (data or {}).get("entry") or []
        return entries[0] if entries else None

    def get_profile(self, email):
        """Разбирает профиль в {'name', 'location', 'accounts'}.

        Раньше бралось только имя, а остальное выбрасывалось. Между тем
        location — страна точнее любого TLD, а привязанные соцсети сами по
        себе сильное доказательство живого человека: аватар можно поставить
        и забыть, а связанные аккаунты просто так не появляются.
        """
        profile = self._fetch_profile(email)
        if not profile:
            return {}

        name = ""
        name_block = profile.get("name")
        if isinstance(name_block, dict):
            name = name_block.get("formatted") or ""
        elif isinstance(name_block, str):
            name = name_block
        if not name:
            name = profile.get("displayName") or ""

        accounts = []
        for account in profile.get("accounts") or []:
            if isinstance(account, dict):
                label = account.get("shortname") or account.get("domain") or ""
                if label:
                    accounts.append(label)

        return {
            "name": name.strip(),
            "location": (profile.get("currentLocation") or "").strip(),
            "accounts": accounts,
        }

    def get_name_from_gravatar(self, email):
        """Только имя — оставлено для обратной совместимости."""
        return self.get_profile(email).get("name") or None

    def search_name(self, email):
        """Оркестратор OSINT-методов. Сейчас источник один — Gravatar."""
        return self.get_name_from_gravatar(email)


if __name__ == '__main__':
    operator = OSINTOperator()
    print("Testing OSINT Operator...")
    test_email = "beau@automattic.com"  # Публичный тестовый профиль
    print(f"{test_email} -> {operator.get_profile(test_email)}")
