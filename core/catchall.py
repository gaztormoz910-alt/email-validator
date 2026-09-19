# -*- coding: utf-8 -*-
"""Catch-all: домен, который отвечает «да» на ЛЮБОЙ адрес.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. Это самая дорогая ошибка валидатора: сервер отвечает
`250 OK` на выдуманный адрес, и без этой проверки вся база такого домена
уезжает в «Годен». Логика здесь своя и цельная — три разных образца
выдуманных адресов в ОДНОЙ сессии, память о доменах между прогонами, список
гигантов, которые catch-all быть не могут. В core/network.py она лежала
посреди SMTP-диалога и разрасталась незаметно; вынесенная, она читается и
правится отдельно.

ПОЧЕМУ ПРИМЕСЬ, А НЕ ФУНКЦИИ. Состояние (`catchall_cache`, `catchall_lock`,
`_mx_catchall`, `_tarpit_domains`) заводится в `NetworkValidator.__init__` и
общее на весь прогон. Примесь работает с тем же объектом, поэтому переносить
состояние никуда не пришлось — в этом и смысл: файл поделён, поведение нет.
"""
from core.mail_constants import AOL_DOMAINS, MICROSOFT_DOMAINS, YAHOO_DOMAINS

__all__ = ["CatchAllMixin"]


class CatchAllMixin:
    """Обнаружение catch-all и память о нём. Примешивается к NetworkValidator."""

    def is_catch_all_domain(self, domain, mx_record) -> bool:
        """
        Проверяет, является ли домен Catch-All (принимает любой адрес).
        Три разных паттерна — два коротких и UUID-подобный — в ОДНОЙ сессии.
        Результат кэшируется.
        """
        with self.catchall_lock:
            if domain in self.catchall_cache:
                return self.catchall_cache[domain]

        # Ответ, выясненный в прошлый раз. Тройная проба стоит трёх RCPT в
        # отдельной сессии НА КАЖДЫЙ домен базы: спрашивать об одном и том же
        # при каждом запуске — это лишние сессии и лишний повод попасться на
        # глаза почтовику ровно за тот ответ, который уже есть.
        #
        # У записи есть срок (см. core/longterm.py): домен мог перестать быть
        # catch-all, и вечная память была бы хуже её отсутствия.
        if self.memory is not None:
            remembered = self.memory.catchall_get(domain)
            if remembered is not None:
                with self.catchall_lock:
                    self.catchall_cache[domain] = remembered
                return remembered

        # Импорт ЛОКАЛЬНЫЙ: core/network.py импортирует эту примесь, и
        # импорт на уровне файла замкнул бы круг. К моменту вызова
        # core.network уже загружен целиком.
        from core.network import _generate_random_local
        fakes = [
            f"{_generate_random_local('short')}@{domain}",
            f"{_generate_random_local('short')}@{domain}",
            f"{_generate_random_local('uuid')}@{domain}",
        ]
        results = self._probe_recipients(fakes, mx_record,
                                         proxy=self._probe_proxy_for(domain))

        for result in results:
            # Проба сорвалась (мёртвый прокси, таймаут) — вывода сделать нельзя.
            # НЕ кэшируем: иначе catch-all домен потом молча выдаст Valid на всё.
            #
            # `greylisted` попал сюда позже остальных, и вот почему. Серый
            # список — это `450 приходите позже`: сервер ОТКЛАДЫВАЕТ решение,
            # а не отказывает получателю. Ответа о ящике в нём нет ровно так
            # же, как в таймауте. Между тем ветка ниже читала любой не-valid
            # как «выдуманный адрес отвергнут, значит домен не catch-all» — и
            # записывала это в долгую память на тридцать суток. Дальше
            # настоящий адрес того же домена приходил после выдержки, получал
            # честный `250`, и раз домен «доказанно не catch-all», вердикт
            # становился Valid. У домена с catch-all это ложный Valid, и
            # владелец узнаёт правду по отскокам.
            #
            # Greylisting чаще всего стоит как раз на небольших корпоративных
            # доменах — там же, где чаще всего включён и приём на любой адрес.
            if result["status"] in ("unknown", "greylisted"):
                # Но прежде чем сказать «не catch-all», спросим соседей по
                # почтовому серверу. Ответ «нет» здесь опаснее всего: он
                # отправляет несуществующие ящики домена прямиком в Valid, и
                # владелец узнаёт правду по отскокам.
                #
                # Подсказка НЕ заменяет пробу: она читается только когда проба
                # сорвалась, и только если тот же MX-хост уже оказывался
                # catch-all у ДВУХ разных доменов. Один сосед ничего не
                # значит — настройка у доменов на общем сервере своя.
                if self._mx_catchall_suspected(mx_record, domain):
                    return True
                return False
            # Хоть один выдуманный адрес отвергнут — домен точно не catch-all
            if result["status"] != "valid":
                with self.catchall_lock:
                    self.catchall_cache[domain] = False
                self._remember_catchall(domain, False)
                return False

        with self.catchall_lock:
            self.catchall_cache[domain] = True
        self._remember_catchall(domain, True)
        self._note_mx_catchall(mx_record, domain)
        return True
    def _note_mx_catchall(self, mx_record, domain):
        """Запоминает, что этот почтовый сервер уже принимал что угодно."""
        host = (mx_record or "").strip().lower().rstrip(".")
        if not host or not domain:
            return
        with self.catchall_lock:
            seen = self._mx_catchall.get(host)
            if seen is None:
                seen = set()
                self._mx_catchall[host] = seen
            seen.add(domain.strip().lower())
    def _mx_catchall_suspected(self, mx_record, domain):
        """Оказывался ли этот MX-хост catch-all у ДВУХ других доменов.

        Двух, а не одного: у доменов на общем сервере настройки свои, и один
        сосед — совпадение. Возвращает только подозрение и только там, где
        собственная проба ничего не дала.
        """
        host = (mx_record or "").strip().lower().rstrip(".")
        if not host:
            return False
        with self.catchall_lock:
            seen = self._mx_catchall.get(host) or set()
            others = {d for d in seen if d != (domain or "").strip().lower()}
        return len(others) >= 2
    # Домены, у которых catch-all невозможен по устройству. Список ОДИН на
    # весь модуль: пока он был набран прямо в ветке проверки, долгая память о
    # нём не знала — и записывала в себя ровно то, что эта ветка через
    # несколько строк переименовывала в тарпитинг.
    NEVER_CATCHALL = frozenset({
        "gmail.com", "googlemail.com", "yandex.ru", "ya.ru",
        "icloud.com", "me.com", "mac.com",
    })
    def _is_never_catchall(self, domain):
        """Гигант, у которого catch-all не бывает: приём выдуманного адреса
        у него означает тарпитинг, а не настройку домена."""
        low = str(domain or "").lower()
        return (low in self.NEVER_CATCHALL or low in YAHOO_DOMAINS
                or low in MICROSOFT_DOMAINS or low in AOL_DOMAINS)
    def _remember_catchall(self, domain, is_catchall):
        """Кладёт выясненный ответ в память между запусками.

        Тихо: сбой памяти не имеет права влиять на проверку почты.

        У гигантов catch-all не бывает: приняв выдуманный адрес, gmail.com не
        стал принимать всё подряд — он перестал отвечать честно, потому что с
        нашего выхода идёт перебор. Это тарпитинг, и лечится он сменой прокси.

        Раньше запись делалась ДО того, как вызывающий распознавал тарпитинг,
        и в долгой памяти оседало «gmail.com — catch-all» на тридцать суток.
        После этого КАЖДЫЙ адрес на gmail.com в каждом следующем запуске
        получал Unknown, не доходя до сервера, — и владелец терял на этом
        самую большую часть любой базы, ничего не замечая: строка в логе о
        тарпитинге была разовой, а последствие — месячным.
        """
        if self.memory is None:
            return
        if is_catchall and self._is_never_catchall(domain):
            return
        try:
            self.memory.catchall_put(domain, is_catchall)
        except Exception:
            pass
    # Через сколько проверок домена повторять контрольную пробу у гигантов.
    # Двадцать пять — компромисс: лишних RCPT четыре процента, а тарпитинг
    # обнаруживается на первых же десятках адресов, задолго до конца прогона.
    TARPIT_RECHECK_EVERY = 25
    def _time_to_recheck(self, domain):
        """Пора ли проверить, честно ли гигант отвечает СЕЙЧАС.

        Первая проверка домена всегда контрольная: если сервер уже тарпитит,
        узнать об этом надо на первом адресе, а не на двадцать шестом.
        """
        if not domain:
            return False
        with self._domain_checks_lock:
            seen = self._domain_checks.get(domain, 0)
            self._domain_checks[domain] = seen + 1
        return seen == 0 or seen % self.TARPIT_RECHECK_EVERY == 0
    def proven_catchall_domains(self):
        """Домены, про которые ДОКАЗАНО, что они принимают любой адрес.

        Нужны конвейеру в конце прогона: домен мог раскрыться после того, как
        по нему уже выдали Valid (тройная проба сорвалась, а контрольный RCPT
        в середине прогона показал правду).
        """
        with self.catchall_lock:
            return sorted(d for d, yes in self.catchall_cache.items() if yes)
    def tarpit_domains(self):
        """Домены, поймавшие нас на переборе. Для отчёта владельцу."""
        with self.catchall_lock:
            return sorted(self._tarpit_domains)
