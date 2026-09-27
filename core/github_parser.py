# core/github_parser.py
import os
import json
import urllib.request
import urllib.error
from core.paths import data_dir as data_dir_of_app


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

    def __init__(self, data_dir=None):
        # См. core/paths.py: списки лежат в пишущейся папке рядом с .exe,
        # потому что этот класс их туда же и перезаписывает.
        self.data_dir = data_dir or data_dir_of_app()
        if not os.path.exists(self.data_dir):
            os.makedirs(self.data_dir)

        # Манифест с ETag'ами последних загрузок — по нему понимаем, есть ли новые данные.
        self.etag_path = os.path.join(self.data_dir, ".blacklist_etags.json")

        # Ссылки на GitHub репозитории с базами.
        #
        # Второй список раньше назывался spam_traps.txt, и имя врало: настоящих
        # спам-ловушек в нём нет и быть не может — опубликованная ловушка
        # перестаёт работать, поэтому такие списки секретны по определению.
        # Внутри лежат обычные одноразовые домены, что видно и по источнику
        # (unkn0w/disposable-email-domain-list). Имя исправлено, чтобы при
        # оценке базы никто не считал, что ловушки отфильтрованы.
        self.sources = {
            "disposable.txt": "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf",
            "disposable_extra.txt": "https://raw.githubusercontent.com/unkn0w/disposable-email-domain-list/master/domains.txt",
            # Третий источник одноразовых: списки пересекаются лишь частично.
            "disposable_more.txt": "https://raw.githubusercontent.com/FGRibreau/mailchecker/master/list.txt",
            # Бесплатные почтовики. Нужен НЕ для отбраковки, а для скоринга:
            # без него mail.com, zoho.com и сотни региональных сервисов
            # считались корпоративными и получали +5, которого нет у gmail.com.
            "free_providers.txt": "https://raw.githubusercontent.com/willwhite/freemail/master/data/free.txt",
        }

        self._migrate_legacy_names()

    # Файлы, которые НЕ являются списками одноразовых доменов и не должны
    # попадать в чёрный список. free_providers.txt — это gmail.com и подобные;
    # загрузи его в SpamFilter, и вся база уедет в Trap/Disposable.
    NON_BLACKLIST_FILES = frozenset({"free_providers.txt"})

    # Ключ манифеста для версии источника, которую скачали и НЕ взяли.
    #
    # Отвергнутая версия раньше не запоминалась ничем, и каждый запуск качал
    # её заново — ради того же «обновление не взято». Замерено прогоном
    # test_1.txt владельца 27.09.2026: три списка одноразовых скачивались и
    # отвергались при каждом старте, 72 с до первой проверки (disposable_more
    # — 58 с из них). Теперь её ETag уходит в If-None-Match вместе с принятым,
    # и неизменившийся источник отвечает 304 без тела.
    REJECTED_SUFFIX = "#rejected"

    # Старое имя -> новое. SpamFilter грузит ВСЕ .txt из data/, поэтому оставить
    # старый файл рядом с новым нельзя: он загрузился бы вторым экземпляром.
    LEGACY_RENAMES = {"spam_traps.txt": "disposable_extra.txt"}

    def _migrate_legacy_names(self):
        """Переименовывает файлы, оставшиеся от старых версий."""
        for old_name, new_name in self.LEGACY_RENAMES.items():
            old_path = os.path.join(self.data_dir, old_name)
            new_path = os.path.join(self.data_dir, new_name)
            if not os.path.exists(old_path):
                continue
            try:
                if os.path.exists(new_path):
                    os.remove(old_path)      # Новый уже есть — старый лишний
                else:
                    os.replace(old_path, new_path)
            except Exception:
                continue
            # Переносим и ETag, иначе список скачается заново без нужды
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
            rejected = etags.get(filename + self.REJECTED_SUFFIX)

            try:
                req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

                # Условный GET по ETag: GitHub вернёт 304, если данные не менялись,
                # и мы не будем зря перезаписывать файл. Отвергнутая версия
                # идёт в тот же заголовок: её мы уже смотрели (см. REJECTED_SUFFIX).
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

            # Предохранитель: не затираем рабочий список подозрительно пустым ответом.
            if len(new_domains) < self.MIN_PLAUSIBLE_DOMAINS:
                log(f"[DEAD] {filename}: ответ битый ({len(new_domains)} доменов), оставляю старый список.", "dead")
                continue

            # Санити-контракт для чёрных списков — ТОТ ЖЕ, что у SpamFilter
            # (core/filters.py, ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ): файл, набитый живыми
            # почтовиками, не берётся; единицы спорных имён (сервисы
            # псевдонимов duck.com, addy.io) — обычное разногласие на краю,
            # и фильтр сам выбрасывает их при загрузке.
            #
            # Раньше здесь не брался список с ОДНИМ таким именем. Фильтр
            # перешёл на долю 12.09.2026, а загрузчик остался на прежнем
            # правиле — и ни одно обновление с тех пор не применилось: прогон
            # 27.09.2026 показал «обновление не взято» у всех трёх списков
            # (два-три спорных имени на тысячи), файлы на диске — от 22.08 до
            # 01.09. Новые одноразовые домены до программы не доходили.
            if filename not in self.NON_BLACKLIST_FILES:
                from core.filters import BLACKLIST_SENTINELS, ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ
                bad = BLACKLIST_SENTINELS & new_domains
                if bad and len(bad) > ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ * len(new_domains):
                    if new_etag:
                        etags[filename + self.REJECTED_SUFFIX] = new_etag
                    # Не «испорчен» и не красным: обновление просто не
                    # взято. Прежний список остался, проверка идёт как шла.
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
            # Взятая версия отменяет память об отвергнутой: следующая будет
            # оцениваться заново, а не отсекаться по старой метке.
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
