import os
import json
import urllib.request
import urllib.error
from core.paths import data_dir as data_dir_of_app


class BlacklistDownloader:

    MIN_PLAUSIBLE_DOMAINS = 100

    def __init__(self, data_dir=None):
        self.data_dir = data_dir or data_dir_of_app()
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        self.etag_path = os.path.join(self.data_dir, ".blacklist_etags.json")

        self.sources = {
            "disposable.txt": "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
            "disposable_extra.txt": "https://raw.githubusercontent.com/unkn0w/disposable-email-domain-list/master/domains.txt",
            "disposable_more.txt": "https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt",
            "free_providers.txt": "https://raw.githubusercontent.com/willwhite/freemail/master/data/free.txt",
        }

        self._migrate_legacy_names()

    NON_BLACKLIST_FILES = frozenset({"free_providers.txt"})

    REJECTED_SUFFIX = "#rejected"

    LEGACY_RENAMES = {"spam_traps.txt": "disposable_extra.txt"}

    def _migrate_legacy_names(self):
        for old_name, new_name in self.LEGACY_RENAMES.items():
            old_path = os.path.join(self.data_dir, old_name)
            new_path = os.path.join(self.data_dir, new_name)
            if not os.path.exists(old_path):
                continue
            try:
                if os.path.exists(new_path):
                    os.remove(old_path)
                else:
                    os.replace(old_path, new_path)
            except Exception:
                continue
            try:
                etags = self._load_etags()
                if old_name in etags:
                    etags.setdefault(new_name, etags.pop(old_name))
                    self._save_etags(etags)
            except Exception:
                pass

    def _load_etags(self):
        try:
            with open(self.etag_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_etags(self, etags):
        try:
            with open(self.etag_path, "w", encoding="utf-8") as f:
                json.dump(etags, f)
        except Exception:
            pass

    def _parse_domains(self, content):
        domains = set()
        for line in content.split("\n"):
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            if " " in line or "<" in line:
                continue
            domains.add(line)
        return domains

    def download_all(self, log_callback=None):
        report = []

        def log(msg, tag="info"):
            report.append(msg)
            if log_callback:
                log_callback(msg, tag)

        etags = self._load_etags()

        for filename, url in self.sources.items():
            filepath = os.path.join(self.data_dir, filename)
            exists = os.path.exists(filepath)
            rejected = etags.get(filename + self.REJECTED_SUFFIX)

            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

                known = []
                if exists and etags.get(filename):
                    known.append(etags[filename])
                if rejected:
                    known.append(rejected)
                if known:
                    req.add_header("If-None-Match", ", ".join(known))

                with urllib.request.urlopen(req, timeout=15) as response:
                    content = response.read().decode("utf-8", "ignore")
                    new_etag = response.headers.get("ETag")

            except urllib.error.HTTPError as e:
                if e.code == 304 and rejected:
                    log(f"[INFO] {filename}: новых данных у источника нет, а его "
                        "последняя версия уже отклонена (внутри живые почтовики). "
                        "Работаем на прежнем списке, заново не скачивал.", "info")
                elif e.code == 304:
                    log(f"[INFO] {filename}: новых данных нет, список актуален.", "info")
                else:
                    log(f"[DEAD] {filename}: сервер вернул {e.code}, оставляю старый список.", "dead")
                continue
            except Exception as e:
                log(f"[DEAD] {filename}: скачать не удалось ({type(e).__name__}), оставляю старый список.", "dead")
                continue

            new_domains = self._parse_domains(content)

            if len(new_domains) < self.MIN_PLAUSIBLE_DOMAINS:
                log(f"[DEAD] {filename}: ответ битый ({len(new_domains)} доменов), оставляю старый список.", "dead")
                continue

            if filename not in self.NON_BLACKLIST_FILES:
                from core.filters import BLACKLIST_SENTINELS, ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ
                bad = BLACKLIST_SENTINELS & new_domains
                if bad and len(bad) > ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ * len(new_domains):
                    if new_etag:
                        etags[filename + self.REJECTED_SUFFIX] = new_etag
                    доля = 100.0 * len(bad) / max(1, len(new_domains))
                    log(f"[INFO] {filename}: обновление не взято — внутри живые "
                        f"почтовики: {len(bad)} из {len(new_domains)} ({доля:.0f}%, "
                        f"{', '.join(sorted(bad)[:3])}). "
                        "Работаем на прежнем списке, база не тронута.", "info")
                    continue

            old_count = 0
            if exists:
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        old_count = sum(1 for line in f if line.strip())
                except Exception:
                    pass

            try:
                tmp_path = filepath + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as f:
                    for d in sorted(new_domains):
                        f.write(d + "\n")
                os.replace(tmp_path, filepath)
            except Exception as e:
                log(f"[DEAD] {filename}: не удалось записать ({type(e).__name__}).", "dead")
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
                continue

            if new_etag:
                etags[filename] = new_etag
            etags.pop(filename + self.REJECTED_SUFFIX, None)

            if exists:
                if old_count == len(new_domains):
                    log(f"[INFO] {filename}: переустановлен — {len(new_domains)} доменов.", "info")
                else:
                    log(f"[INFO] {filename}: обновлён — было {old_count}, стало {len(new_domains)} доменов.", "info")
            else:
                log(f"[INFO] {filename}: скачан — {len(new_domains)} доменов.", "info")

        self._save_etags(etags)
        return report
