import os

from core.disposable import _MX_NEVER_DISPOSABLE, NEVER_DISPOSABLE
from core.encoding import open_text
from core.paths import data_dir as data_dir_of_app

FREE_PROVIDERS_FILE = "free_providers.txt"
NON_BLACKLIST_FILES = frozenset({FREE_PROVIDERS_FILE})

BROAD_LISTS = frozenset({"disposable_extra.txt", "disposable_more.txt"})

def _known_live_domains():
    names = set()
    try:
        from core.mail_constants import (AOL_DOMAINS, MICROSOFT_DOMAINS,
                                         NEEDS_CLEAN_IP_DOMAINS,
                                         NICHE_FREE_DOMAINS, YAHOO_DOMAINS)
        for table in (AOL_DOMAINS, MICROSOFT_DOMAINS, NEEDS_CLEAN_IP_DOMAINS,
                      NICHE_FREE_DOMAINS, YAHOO_DOMAINS):
            names |= {str(d).strip().lower() for d in table}
    except Exception:
        pass
    try:
        from core.cleaner import EmailCleaner

        names |= {str(d).strip().lower() for d in EmailCleaner().popular_domains}
    except Exception:
        pass
    try:
        from core.provider import _FREE_MAIL_EXTRA, _ISP_DOMAINS, _PROVIDER_DOMAINS

        for table in (_FREE_MAIL_EXTRA, _ISP_DOMAINS, _PROVIDER_DOMAINS):
            names |= {str(d).strip().lower() for d in table}
    except Exception:
        pass
    names |= {"gmail.com", "googlemail.com", "yahoo.com", "outlook.com",
              "hotmail.com", "live.com", "aol.com", "icloud.com", "me.com",
              "mail.ru", "yandex.ru", "protonmail.com", "proton.me",
              "gmx.com", "gmx.de", "web.de", "qq.com", "163.com",
              "naver.com", "orange.fr", "libero.it", "comcast.net"}
    return frozenset(n for n in names if n and "." in n)


BLACKLIST_SENTINELS = _known_live_domains()

ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ = 0.05


class SpamFilter:
    def __init__(self, data_dir=None, log_callback=None):
        self.data_dir = data_dir or data_dir_of_app()
        self.blacklist_domains = set()
        self.rejected_files = []
        self.dropped_domains = {}
        self.free_conflicts = {}
        self._log = log_callback
        self._load_blacklists()

    def _load_blacklists(self):
        loaded = {}
        if os.path.exists(self.data_dir):
            for filename in sorted(os.listdir(self.data_dir)):
                if not filename.endswith(".txt") or filename in NON_BLACKLIST_FILES:
                    continue
                filepath = os.path.join(self.data_dir, filename)
                domains = self._read_domains(filepath)
                if not domains:
                    continue

                found = BLACKLIST_SENTINELS & domains
                if found and len(found) > ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ * len(domains):
                    self.rejected_files.append((filename, sorted(found)[:5]))
                    if self._log:
                        доля = 100.0 * len(found) / max(1, len(domains))
                        self._log(
                            f"[INFO] Список {filename} пропущен и НЕ применён: "
                            f"живых почтовиков внутри {len(found)} из "
                            f"{len(domains)} ({доля:.0f}%), это не список "
                            f"одноразовых ({', '.join(sorted(found)[:3])}). "
                            "Ваша база не пострадала — именно поэтому список и "
                            "отклонён.", "info")
                    continue

                if found:
                    self.dropped_domains[filename] = sorted(found)
                    domains = domains - found

                loaded[filename] = domains

        free_path = os.path.join(self.data_dir, FREE_PROVIDERS_FILE)
        free = self._read_domains(free_path) if os.path.exists(free_path) else set()
        trusted = set()
        for filename, domains in loaded.items():
            if filename not in BROAD_LISTS:
                trusted |= domains
        for filename in sorted(BROAD_LISTS & set(loaded)):
            conflict = (loaded[filename] & free) - trusted
            if conflict:
                self.free_conflicts[filename] = sorted(conflict)
                loaded[filename] = loaded[filename] - conflict

        for domains in loaded.values():
            self.blacklist_domains |= domains

        self.blacklist_domains.update({
            "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com",
            "yopmail.com", "temp-mail.org", "throwawaymail.com", "sharklasers.com",
            "getnada.com", "dispostable.com", "maildrop.cc", "fakemail.net",
        })

        self.blacklist_domains -= BLACKLIST_SENTINELS
        self.blacklist_domains -= NEVER_DISPOSABLE
        self.blacklist_domains -= _MX_NEVER_DISPOSABLE

    @staticmethod
    def _read_domains(filepath):
        domains = set()
        try:
            with open_text(filepath) as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith("#"):
                        domains.add(domain)
        except Exception:
            return set()
        return domains

    def get_count(self):
        return len(self.blacklist_domains)

    def is_spam_or_disposable(self, email: str) -> bool:
        if not isinstance(email, str) or "@" not in email:
            return False
        domain = email.rsplit("@", 1)[1].strip().lower()
        if not domain:
            return False
        метки = domain.split(".")
        if any(".".join(метки[i:]) in NEVER_DISPOSABLE for i in range(len(метки) - 1)):
            return False
        return domain in self.blacklist_domains
