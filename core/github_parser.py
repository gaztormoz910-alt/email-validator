# core/github_parser.py
import os
import json
import urllib.request
import urllib.error


class BlacklistDownloader:
    """Скачивает disposable/spam-списки с GitHub.

    Принцип: ЗАМЕНА, а не накопление. Старый файл перезаписывается свежим,
    поэтому база не разрастается от запуска к запуску и дублей не возникает.
    Скачивание происходит только если на сервере реально есть новые данные
    (условный GET по If-Modified-Since; на 304 файл не трогаем).
    """

    # Ответ должен содержать хотя бы столько доменов, иначе считаем его
    # битым (страница ошибки, обрыв связи) и НЕ затираем рабочий список.
    MIN_PLAUSIBLE_DOMAINS = 100

    def __init__(self, data_dir="data"):
        self.data_dir = data_dir
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        # Манифест с ETag'ами последних загрузок — по нему понимаем, есть ли новые данные.
        self.etag_path = os.path.join(self.data_dir, ".blacklist_etags.json")

        # Ссылки на GitHub репозитории с базами
        self.sources = {
            "disposable.txt": "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
            "spam_traps.txt": "https://raw.githubusercontent.com/unkn0w/disposable-email-domain-list/master/domains.txt"
        }

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
        """Достаёт домены из скачанного текста, отбрасывая комментарии и мусор."""
        domains = set()
        for line in content.split("\n"):
            line = line.strip().lower()
            if not line or line.startswith("#"):
                continue
            # Строки с пробелами/тегами — не домены (например HTML страницы ошибки)
            if " " in line or "<" in line:
                continue
            domains.add(line)
        return domains

    def download_all(self, log_callback=None):
        """Обновляет все списки. Возвращает список строк-отчётов о том, что произошло."""
        report = []

        def log(msg, tag="info"):
            report.append(msg)
            if log_callback:
                log_callback(msg, tag)

        etags = self._load_etags()

        for filename, url in self.sources.items():
            filepath = os.path.join(self.data_dir, filename)
            exists = os.path.exists(filepath)

            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

                # Условный GET по ETag: GitHub вернёт 304, если данные не менялись,
                # и мы не будем зря перезаписывать файл.
                if exists and etags.get(filename):
                    req.add_header("If-None-Match", etags[filename])

                with urllib.request.urlopen(req, timeout=15) as response:
                    content = response.read().decode("utf-8", "ignore")
                    new_etag = response.headers.get("ETag")

            except urllib.error.HTTPError as e:
                if e.code == 304:
                    log(f"[INFO] {filename}: новых данных нет, список актуален.", "info")
                else:
                    log(f"[DEAD] {filename}: сервер вернул {e.code}, оставляю старый список.", "dead")
                continue
            except Exception as e:
                log(f"[DEAD] {filename}: скачать не удалось ({type(e).__name__}), оставляю старый список.", "dead")
                continue

            new_domains = self._parse_domains(content)

            # Предохранитель: не затираем рабочий список подозрительно пустым ответом.
            if len(new_domains) < self.MIN_PLAUSIBLE_DOMAINS:
                log(f"[DEAD] {filename}: ответ битый ({len(new_domains)} доменов), оставляю старый список.", "dead")
                continue

            old_count = 0
            if exists:
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        old_count = sum(1 for line in f if line.strip())
                except Exception:
                    pass

            # ЗАМЕНА: пишем только свежие домены поверх старого файла.
            try:
                tmp_path = filepath + ".tmp"
                with open(tmp_path, "w", encoding="utf-8") as f:
                    for d in sorted(new_domains):
                        f.write(d + "\n")
                os.replace(tmp_path, filepath)  # Атомарная подмена
            except Exception as e:
                log(f"[DEAD] {filename}: не удалось записать ({type(e).__name__}).", "dead")
                try:
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                except Exception:
                    pass
                continue

            # Запоминаем ETag, чтобы в следующий раз не качать те же данные повторно
            if new_etag:
                etags[filename] = new_etag

            if exists:
                if old_count == len(new_domains):
                    log(f"[INFO] {filename}: переустановлен — {len(new_domains)} доменов.", "info")
                else:
                    log(f"[INFO] {filename}: обновлён — было {old_count}, стало {len(new_domains)} доменов.", "info")
            else:
                log(f"[INFO] {filename}: скачан — {len(new_domains)} доменов.", "info")

        self._save_etags(etags)
        return report
