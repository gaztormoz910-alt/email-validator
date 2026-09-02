# core/filters.py
import os

from core.encoding import open_text

# Файлы в data/, которые НЕ являются чёрными списками.
#
# SpamFilter загружает все .txt из папки подряд, и это удобно ровно до того
# момента, когда рядом ляжет список БЕСПЛАТНЫХ провайдеров. Тогда gmail.com
# окажется в чёрном списке, и вся база уедет в Trap/Disposable за один прогон.
NON_BLACKLIST_FILES = frozenset({"free_providers.txt"})

# Санити-контракт для чёрного списка.
#
# Ни один добросовестный список одноразовых доменов не содержит крупных
# почтовиков. Если содержит — список либо испорчен, либо это вообще не тот
# файл. Такой список безопаснее не грузить целиком, чем выяснять это по
# результатам прогона на живой базе.
def _known_live_domains():
    """Все домены, о которых программа знает, что они живые почтовики.

    Раньше здесь стоял список из двадцати четырёх имён, набранный руками. Он
    защищал гигантов — и пропускал всё остальное: одна строка `seznam.cz` или
    `t-online.de` в скачанном чужом списке хоронила весь домен целиком (и его
    поддомены) без единого запроса к серверу.

    Теперь страж собирается из тех же таблиц, которыми пользуется сам
    валидатор: если программа знает провайдера настолько, чтобы подбирать под
    него прокси, — она обязана знать и то, что его нельзя объявлять
    одноразовым.
    """
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
        # Самая широкая таблица бесплатных почтовиков в программе: почти две
        # сотни имён, включая seznam.cz, bk.ru, wp.pl и прочие, которых в
        # ручном списке гигантов не было и быть не могло.
        from core.provider import _FREE_MAIL_EXTRA, _ISP_DOMAINS, _PROVIDER_DOMAINS

        for table in (_FREE_MAIL_EXTRA, _ISP_DOMAINS, _PROVIDER_DOMAINS):
            names |= {str(d).strip().lower() for d in table}
    except Exception:
        pass
    # Минимум на случай, если таблицы не прочитались: без него страж мог бы
    # оказаться пустым, и контракт перестал бы что-либо проверять.
    names |= {"gmail.com", "googlemail.com", "yahoo.com", "outlook.com",
              "hotmail.com", "live.com", "aol.com", "icloud.com", "me.com",
              "mail.ru", "yandex.ru", "protonmail.com", "proton.me",
              "gmx.com", "gmx.de", "web.de", "qq.com", "163.com",
              "naver.com", "orange.fr", "libero.it", "comcast.net"}
    return frozenset(n for n in names if n and "." in n)


BLACKLIST_SENTINELS = _known_live_domains()


class SpamFilter:
    def __init__(self, data_dir="data", log_callback=None):
        self.data_dir = data_dir
        self.blacklist_domains = set()  # Хеш-множество для O(1) поиска
        self.rejected_files = []        # Списки, не прошедшие санити-контракт
        self._log = log_callback
        self._load_blacklists()

    def _load_blacklists(self):
        """Загружает чёрные списки из data/*.txt, отбраковывая подозрительные."""
        if os.path.exists(self.data_dir):
            for filename in sorted(os.listdir(self.data_dir)):
                if not filename.endswith(".txt") or filename in NON_BLACKLIST_FILES:
                    continue
                filepath = os.path.join(self.data_dir, filename)
                domains = self._read_domains(filepath)
                if not domains:
                    continue

                # Санити-контракт: крупный почтовик внутри чёрного списка
                # означает, что список нельзя применять вообще.
                found = BLACKLIST_SENTINELS & domains
                if found:
                    self.rejected_files.append((filename, sorted(found)[:5]))
                    if self._log:
                        self._log(
                            f"[DEAD] Список {filename} НЕ загружен: в нём "
                            f"крупные почтовики ({', '.join(sorted(found)[:3])}). "
                            "Загрузить его — значит убить всю базу.", "dead")
                    continue

                self.blacklist_domains |= domains

        # Жёстко заданный минимум на случай, если файлов нет вовсе
        self.blacklist_domains.update({
            "tempmail.com", "10minutemail.com", "guerrillamail.com", "mailinator.com",
            "yopmail.com", "temp-mail.org", "throwawaymail.com", "sharklasers.com",
            "getnada.com", "dispostable.com", "maildrop.cc", "fakemail.net",
        })

    @staticmethod
    def _read_domains(filepath):
        domains = set()
        try:
            # Файл списка владелец правит в блокноте, и одна строка
            # комментария по-русски в cp1251 роняла разбор целиком:
            # UnicodeDecodeError ловился ниже, и ВЕСЬ список молча
            # отбрасывался — вместе с доменами, которые в нём были.
            with open_text(filepath) as f:
                for line in f:
                    domain = line.strip().lower()
                    if domain and not domain.startswith("#"):
                        domains.add(domain)
        except Exception:
            return set()
        return domains

    def get_count(self):
        """Количество доменов в чёрном списке."""
        return len(self.blacklist_domains)

    def is_spam_or_disposable(self, email: str) -> bool:
        """True, если домен адреса числится в чёрном списке.

        Строка без «@» — это не спам, а мусорный ввод: раньше функция
        возвращала на неё True, то есть выносила приговор тому, что даже
        не является адресом.
        """
        if not isinstance(email, str) or "@" not in email:
            return False
        domain = email.rsplit("@", 1)[1].strip().lower()
        return bool(domain) and domain in self.blacklist_domains
