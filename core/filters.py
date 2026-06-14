# core/filters.py
import os

class SpamFilter:
    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        self.blacklist_domains = set() # Хеш-множество для O(1) поиска
        self._load_blacklists()

    def _load_blacklists(self):
        """Загружает все скачанные .txt файлы в массив для мгновенного поиска."""
        if not os.path.exists(self.data_dir):
            return

        for filename in os.listdir(self.data_dir):
            if filename.endswith(".txt"):
                filepath = os.path.join(self.data_dir, filename)
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith("#"):
                            self.blacklist_domains.add(domain)
                            
        # Жестко заданный список популярных одноразовых доменов (на случай, если их нет на GitHub)
        hardcoded_disposables = [
            "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com",
            "yopmail.com", "temp-mail.org", "throwawaymail.com", "sharklasers.com",
            "getnada.com", "dispostable.com", "maildrop.cc", "fakemail.net"
        ]
        for d in hardcoded_disposables:
            self.blacklist_domains.add(d)
                            
        print(f"[Filter] Успешно загружено {len(self.blacklist_domains)} мусорных доменов.")

    def is_spam_or_disposable(self, email: str) -> bool:
        """Возвращает True, если домен находится в черном списке."""
        if "@" not in email:
            return True
            
        domain = email.rsplit("@", 1)[1].lower()
        return domain in self.blacklist_domains
