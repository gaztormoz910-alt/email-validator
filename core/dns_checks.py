# core/dns_checks.py
"""Проверки домена и адреса по DNS: MX, PTR, FCrDNS, чёрные списки, SPF/DMARC/DKIM.

Вынесено из NetworkValidator: это отдельный слой доказательств, который
собирается ДО SMTP-диалога и живёт по своим правилам.

Главное правило здесь — то же, что и у разбора ответов сервера, только про
другой источник: **«не проверили» не равно «нет».** Различие между `False`
(записи точно нет) и `None` (спросить не удалось) here несёт смысл: PTR,
которого нет, закрывает дорогу к Yahoo, а PTR, который не удалось проверить,
не говорит ни о чём — и штрафовать за него адрес значит наказывать его за
сбой на НАШЕЙ стороне.

Второе правило — про чёрные списки. У каждой зоны DNSBL есть обязательная
тестовая запись: 127.0.0.2 обязана в ней числиться, 127.0.0.1 — нет. Половина
широко цитируемых зон сегодня мертва и отвечает NXDOMAIN на всё, поэтому зона
опрашивается только после того, как прошла этот санитарный контракт: список
из шести зон, три из которых молчат, даёт вдвое меньшее покрытие, чем
кажется по коду.

Примесь, а не отдельный объект: методы пользуются тем же резолвером и теми же
кэшами, что заводит NetworkValidator.__init__.
"""
import socket
import threading
import time

import dns.exception
import dns.resolver
import dns.reversename

from core.dns_resolver import DNSUnavailable, ProxiedResolver
from core.email_syntax import to_ascii_domain
from core.mail_constants import (DNSBL_ZONES, SPAMHAUS_ZONE,
                                 SPAMHAUS_SANITY_LISTED, SPAMHAUS_SANITY_CLEAN,
                                 _dkim_selectors_for)


def system_resolvers():
    """Резолверы, которые прописаны в самой системе.

    Нужны для Spamhaus. Зона не обслуживает КРУПНЫЕ публичные резолверы —
    Google и Cloudflare получают от неё код отказа или NXDOMAIN, — но это не
    значит, что своего резолвера нет. У большинства машин в списке лежит ещё и
    резолвер провайдера или Quad9, а их зона обслуживает.

    Замерено на машине владельца: 1.1.1.1 отвечает 127.255.255.254 (отказ),
    8.8.8.8 — NXDOMAIN на обязательную тестовую запись (тоже отказ), а 9.9.9.9
    отвечает правильно: 127.0.0.2 числится, 127.0.0.1 нет. То есть крупнейший
    чёрный список был доступен всё это время, просто его никто не спросил.

    Порядок сохраняется: система знает, кто ближе.
    """
    try:
        import dns.resolver

        found = list(dns.resolver.Resolver().nameservers or [])
    except Exception:
        return []
    return [str(ns).strip() for ns in found if str(ns).strip()]


class DnsChecksMixin:
    """MX, PTR, FCrDNS, DNSBL и здоровье домена. Состояние — в NetworkValidator."""

    def set_spamhaus_resolver(self, nameservers):
        """Задаёт СВОЙ резолвер для Spamhaus и проверяет его санити-контрактом.

        Без такого резолвера Spamhaus не спрашивается: с публичного DNS он
        отвечает отказом, а отказ, принятый за чистоту, снял бы штраф с
        реально грязного IP. Возвращает True, если зона прошла контракт.
        """
        if not nameservers:
            self._spamhaus_resolver = None
            self._spamhaus_ok = None
            return False

        resolver = ProxiedResolver(
            nameservers=list(nameservers), timeout=self.timeout,
            proxy_provider=self._dns_proxy)

        def listed(reversed_ip):
            """True — числится, False — точно не числится, None — не спросили.

            NXDOMAIN и пустой ответ — это ОТВЕТ зоны «такого IP в списке нет»,
            а не сбой. Схлопывать их в None нельзя: тогда контрольная чистая
            запись никогда не даёт False, и санити-контракт не проходит даже
            у полностью исправного резолвера — то есть Spamhaus не включается
            вообще. Сбоем считается только то, что помешало спросить.
            """
            try:
                answers = resolver.resolve(f"{reversed_ip}.{SPAMHAUS_ZONE}", 'A')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                return False
            except Exception:
                return None
            for rdata in answers:
                code = rdata.to_text()
                seen_codes.append(code)
                if code.startswith('127.0.0.') or code.startswith('127.0.1.'):
                    return True
            return False

        seen_codes = []
        must_be_listed = listed(SPAMHAUS_SANITY_LISTED)
        must_be_clean = listed(SPAMHAUS_SANITY_CLEAN)
        self._spamhaus_codes = list(seen_codes)

        # Контракт: тестовая запись обязана числиться, чистая — нет.
        # Любой другой исход означает, что зона нам не отвечает как надо.
        self._spamhaus_ok = (must_be_listed is True and must_be_clean is False)
        self._spamhaus_resolver = resolver if self._spamhaus_ok else None
        return bool(self._spamhaus_ok)

    def spamhaus_refusal_reason(self):
        """Почему зона не прошла контракт — словами, а не молчанием.

        У Spamhaus есть отдельный код отказа: 127.255.255.x означает «запрос
        пришёл с резолвера, который я не обслуживаю» — это публичные DNS вроде
        8.8.8.8 и резолверы крупных провайдеров. Отличать этот случай от
        «зона недоступна» важно, потому что чинятся они по-разному: первый —
        своим резолвером, второй — сетью.

        Измерено: с публичного резолвера ZEN отвечает 127.255.255.254 и на
        127.0.0.2, и на 127.0.0.1, то есть контракт не проходит НИКОГДА, и
        крупнейший чёрный список молчит, а владелец об этом не знает.
        """
        codes = getattr(self, "_spamhaus_codes", None) or []
        refusals = [c for c in codes if c.startswith("127.255.255.")]
        if refusals:
            return ("зона отказала резолверу (код %s): Spamhaus не обслуживает "
                    "публичные DNS и резолверы крупных провайдеров. Нужен свой "
                    "рекурсивный резолвер — например, на том же VPS, где стоит "
                    "прокси." % refusals[0])
        if not codes:
            return ("зона не ответила вовсе: недоступна сеть, резолвер или сам "
                    "Spamhaus.")
        return ("зона ответила не по контракту (%s): 127.0.0.2 обязана "
                "числиться, 127.0.0.1 — нет." % ", ".join(sorted(set(codes))))

    def autodetect_spamhaus_resolver(self, candidates=None):
        """Ищет резолвер, который зона согласна обслуживать. Возвращает его или None.

        Пробуем по одному и проверяем санитарным контрактом каждый: список из
        пяти адресов, поданный разом, дал бы ответ первого попавшегося, а нам
        нужен тот, который отвечает ПРАВИЛЬНО.

        Ничего не найдено — молчим и работаем без Spamhaus, как раньше. Это
        седьмая зона сверху, а не условие работы.
        """
        for resolver in (candidates if candidates is not None else system_resolvers()):
            try:
                if self.set_spamhaus_resolver([resolver]):
                    return resolver
            except Exception:
                continue
        return None

    def _spamhaus_lists(self, ip):
        """True/False по Spamhaus, None — не спрашивали или не смогли.

        None принципиально отличается от False: «не спросили» не означает
        «чисто», и наверх уходит именно неизвестность.
        """
        if not self._spamhaus_resolver or not self._spamhaus_ok:
            return None
        reversed_ip = '.'.join(reversed(ip.split('.')))
        try:
            answers = self._spamhaus_resolver.resolve(
                f"{reversed_ip}.{SPAMHAUS_ZONE}", 'A')
        # NoAnswer здесь по той же причине, что и в санити-контракте выше:
        # зона ответила «записи нет», то есть IP в ней не числится.
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return False
        except Exception:
            return None
        for rdata in answers:
            code = rdata.to_text()
            if code.startswith('127.0.0.') or code.startswith('127.0.1.'):
                return True
        return False

    def check_dnsbl_ip(self, ip):
        """Проверяет ГОТОВЫЙ IP по чёрным спискам (без резолва имени).

        Нужна для прокси: там уже известен выходной IP, резолвить нечего.
        Листингом считается только 127.0.0.x / 127.0.1.x — см. check_dnsbl.
        """
        if not isinstance(ip, str) or not ip:
            return False
        with self._dnsbl_lock:
            if ip in self._dnsbl_cache:
                return self._dnsbl_cache[ip]

        # Spamhaus спрашиваем первым: он крупнейший, и положительный ответ
        # избавляет от опроса остальных семи зон.
        spamhaus = self._spamhaus_lists(ip)
        if spamhaus is True:
            with self._dnsbl_lock:
                self._dnsbl_cache[ip] = True
            return True

        result = False
        unreachable = 0
        reversed_ip = '.'.join(reversed(ip.split('.')))
        for bl in DNSBL_ZONES:
            try:
                answers = self.resolver.resolve(f"{reversed_ip}.{bl}", 'A')
                for rdata in answers:
                    code = rdata.to_text()
                    if code.startswith('127.0.0.') or code.startswith('127.0.1.'):
                        result = True
                        break
                if result:
                    break
            except DNSUnavailable:
                unreachable += 1
                continue
            except Exception:
                continue

        # Ни одна зона не ответила из-за DNS — это не «чисто», это «не спросили».
        # Не кэшируем, иначе первый же сбой закрепит False на весь прогон.
        if not result and unreachable == len(DNSBL_ZONES):
            return False

        with self._dnsbl_lock:
            self._dnsbl_cache[ip] = result
        return result

    def check_dnsbl(self, mx_host):
        """True = IP сервера реально в чёрном списке.

        ВАЖНО про коды ответов: листингом считается только 127.0.0.x / 127.0.1.x.
        Ответы вида 127.255.255.x — это НЕ листинг, а отказ самого блэклиста
        ("запрос с публичного DNS отклонён", "превышен лимит"). Раньше любой
        ответ трактовался как листинг, и при некоторых DNS каждый почтовый
        сервер получал -40 баллов ни за что.
        """
        with self._dnsbl_lock:
            if mx_host in self._dnsbl_cache:
                return self._dnsbl_cache[mx_host]

        result = False
        unreachable = 0
        try:
            ip = str(self.resolver.resolve(mx_host, 'A')[0])
            reversed_ip = '.'.join(reversed(ip.split('.')))
            for bl in DNSBL_ZONES:
                try:
                    answers = self.resolver.resolve(f"{reversed_ip}.{bl}", 'A')
                    for rdata in answers:
                        code = rdata.to_text()
                        if code.startswith('127.0.0.') or code.startswith('127.0.1.'):
                            result = True
                            break
                    if result:
                        break
                except DNSUnavailable:
                    unreachable += 1
                    continue
                except Exception:
                    continue  # Не в этом списке либо список не ответил
        except DNSUnavailable:
            return False  # Даже A-запись не спросили — вывода нет, не кэшируем
        except Exception:
            result = False

        if not result and unreachable == len(DNSBL_ZONES):
            return False

        with self._dnsbl_lock:
            self._dnsbl_cache[mx_host] = result
        return result

    def check_fcrdns(self, ip):
        """Forward-Confirmed reverse DNS для IP-адреса.

        Yahoo и AOL отшивают на MAIL FROM ошибкой 5.7.25 любой IP, у которого:
          - нет PTR-записи, ЛИБО
          - имя из PTR не резолвится обратно на этот же IP.
        Без FCrDNS проверить почту на Yahoo/AOL физически нельзя — нас не пускают
        до этапа RCPT. С FCrDNS всё работает как у остальных провайдеров.

        True  = FCrDNS в порядке, Yahoo/AOL пустят
        False = FCrDNS нет, Yahoo/AOL отошьют
        None  = проверить не удалось
        """
        if not ip:
            return None
        with self._fcrdns_lock:
            if ip in self._fcrdns_cache:
                return self._fcrdns_cache[ip]

        result = None
        try:
            rev_name = dns.reversename.from_address(ip)
            ptr_answers = self.resolver.resolve(rev_name, 'PTR')
            hostname = str(ptr_answers[0]).rstrip('.')

            # Ключевой шаг: имя из PTR должно резолвиться ОБРАТНО на тот же IP
            forward = self.resolver.resolve(hostname, 'A')
            result = any(str(a) == ip for a in forward)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result = False  # PTR нет вовсе, либо имя никуда не резолвится
        except Exception:
            result = None   # DNS не ответил — вывода сделать нельзя

        # Неудачу не кэшируем: хороший прокси не должен вылететь из пула Yahoo
        # из-за одного таймаута DNS.
        if result is None:
            return None

        with self._fcrdns_lock:
            self._fcrdns_cache[ip] = result
        return result

    def get_ptr_hostname(self, ip):
        """Возвращает имя из PTR-записи IP или None.

        Нужно, чтобы посмотреть НА САМО ИМЯ: почтовики штрафуют хосты вида
        vpn-exit-12.host.net или pool-71-105.fios.verizon.net даже при
        валидном FCrDNS — по имени видно, что это не почтовый сервер.
        """
        if not isinstance(ip, str) or not ip:
            return None
        with self._ptr_lock:
            key = "name:" + ip
            if key in self._ptr_cache:
                return self._ptr_cache[key]
        name = None
        try:
            rev = dns.reversename.from_address(ip)
            name = str(self.resolver.resolve(rev, 'PTR')[0]).rstrip('.')
        except Exception:
            name = None
        with self._ptr_lock:
            self._ptr_cache["name:" + ip] = name
        return name

    def check_ptr(self, mx_host):
        """True = PTR есть, False = PTR точно нет, None = проверить не удалось.

        None важен: раньше любой сбой DNS выглядел как "PTR отсутствует"
        и почта незаслуженно получала штраф в скоринге.
        """
        with self._ptr_lock:
            if mx_host in self._ptr_cache:
                return self._ptr_cache[mx_host]
        try:
            ip_answers = self.resolver.resolve(mx_host, 'A')
            ip = str(ip_answers[0])
            rev_name = dns.reversename.from_address(ip)
            self.resolver.resolve(rev_name, 'PTR')
            result = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result = False
        except Exception:
            result = None
        if result is None:
            return None  # «не проверено» не кэшируем — иначе сбой станет вечным
        with self._ptr_lock:
            self._ptr_cache[mx_host] = result
        return result

    # Единственные два исключения, которые являются ОТВЕТОМ, а не сбоем:
    #
    #   NXDOMAIN — такого домена нет вовсе;
    #   NoAnswer — домен есть, но записей запрошенного типа у него нет.
    #
    # Всё остальное (таймаут, «серверы имён недоступны», обрыв связи) означает
    # «мы не спросили», и путать одно с другим нельзя. Раньше здесь стоял
    # голый `except Exception: pass`, и таймаут резолвера возвращал тот же
    # пустой список, что и несуществующий домен, — то есть ПРИГОВОР ВСЕМУ
    # ДОМЕНУ. Моргнувший интернет хоронил живые адреса целыми доменами, и в
    # логе это выглядело как «No MX/A records (Dead Domain)».
    _ANSWERED_NOTHING = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)

    def get_mx_records(self, domain: str):
        """Ищет MX-записи домена, с фоллбэком на A и AAAA (RFC 5321, п.1.4).

        Возвращает:
          [хосты] — куда слать
          []      — записей нет, домен действительно мёртвый
          None    — СПРОСИТЬ НЕ УДАЛОСЬ (DNS через прокси не ответил)

        Различие между [] и None критично: без него сбой DNS выглядел бы как
        «домена не существует», и живой домен уехал бы в Invalid целиком.
        """
        domain = to_ascii_domain(domain)
        if not domain:
            return []

        with self.mx_lock:
            if domain in self.mx_cache:
                return self.mx_cache[domain]

        dns_failed = False

        try:
            answers = self.resolver.resolve(domain, 'MX')
            records = sorted(answers, key=lambda x: x.preference)

            # 1.1 Null MX Check (RFC 7505)
            if len(records) == 1 and records[0].preference == 0 and str(records[0].exchange) in ['.', '']:
                with self.mx_lock:
                    self.mx_cache[domain] = []
                return []

            result = [str(record.exchange).rstrip('.') for record in records]
            if result:
                with self.mx_lock:
                    self.mx_cache[domain] = result
                return result
        except DNSUnavailable:
            dns_failed = True
        except self._ANSWERED_NOTHING:
            pass                      # это ОТВЕТ: таких записей у домена нет
        except Exception:
            dns_failed = True         # всё прочее — мы не спросили

        # Фоллбэк на A-запись (п.1.4): если MX нет — пробуем сам домен как mail-сервер
        try:
            self.resolver.resolve(domain, 'A')
            # A-запись существует — используем сам домен как почтовый сервер
            result = [domain]
            with self.mx_lock:
                self.mx_cache[domain] = result
            return result
        except DNSUnavailable:
            dns_failed = True
        except self._ANSWERED_NOTHING:
            pass
        except Exception:
            dns_failed = True

        # Фоллбэк на AAAA-запись (IPv6) — п.1 DNS +1 балл
        try:
            self.resolver.resolve(domain, 'AAAA')
            result = [domain]
            with self.mx_lock:
                self.mx_cache[domain] = result
            return result
        except DNSUnavailable:
            dns_failed = True
        except self._ANSWERED_NOTHING:
            pass
        except Exception:
            dns_failed = True

        # DNS не ответил — вывода о домене сделать нельзя. Не кэшируем:
        # иначе один сбой похоронил бы домен на весь прогон.
        if dns_failed:
            return None

        # Ни MX, ни A, ни AAAA — домен мёртвый
        with self.mx_lock:
            self.mx_cache[domain] = []
        return []

    def check_dns_health(self, domain: str, mx_record: str = "") -> dict:
        """
        Проверяет DNS-здоровье домена: наличие SPF, DMARC и DKIM записей (п.2.2+).
        Возвращает {'has_spf': bool, 'has_dmarc': bool, 'has_dkim': bool, 'score': int}
        score: 0 = ничего, 1 = один из трёх, 2 = два из трёх, 3 = все три

        mx_record сужает перебор DKIM-селекторов: если домен сидит на Google,
        селектор точно гугловский, и остальные два десятка спрашивать незачем.
        Через прокси каждый лишний DNS-запрос стоит заметно дороже.
        """
        with self._dns_health_lock:
            if domain in self._dns_health_cache:
                return self._dns_health_cache[domain]

        has_spf = False
        has_dmarc = False
        has_dkim = False
        dns_failed = False

        # Проверяем SPF (TXT-запись с v=spf1)
        try:
            txt_answers = self.resolver.resolve(domain, 'TXT')
            for rdata in txt_answers:
                txt_str = str(rdata).lower()
                if 'v=spf1' in txt_str:
                    has_spf = True
                    break
        except DNSUnavailable:
            dns_failed = True
        except self._ANSWERED_NOTHING:
            pass                      # это ОТВЕТ: записи у домена нет
        except Exception:
            dns_failed = True         # всё прочее — мы не спросили

        # Проверяем DMARC (TXT-запись на _dmarc.domain)
        try:
            dmarc_answers = self.resolver.resolve(f'_dmarc.{domain}', 'TXT')
            for rdata in dmarc_answers:
                txt_str = str(rdata).lower()
                if 'v=dmarc1' in txt_str:
                    has_dmarc = True
                    break
        except DNSUnavailable:
            dns_failed = True
        except self._ANSWERED_NOTHING:
            pass
        except Exception:
            dns_failed = True

        # Проверяем DKIM (п.2 DNS-здоровье +1 балл) — пробуем популярные селекторы
        # Селекторы DKIM. Универсального способа их узнать нет — имя выбирает
        # владелец домена, в DNS оно не перечислено. Раньше список был короче,
        # и крупнейшие провайдеры давали ложное "DKIM нет": у Gmail селектор
        # 20230601, у Mail.ru — mailru, ни того ни другого в списке не было,
        # поэтому Gmail и Mail.ru никогда не получали +10 за полный DNS.
        dkim_selectors = _dkim_selectors_for(mx_record)
        for selector in dkim_selectors:
            try:
                dkim_answers = self.resolver.resolve(f'{selector}._domainkey.{domain}', 'TXT')
                for rdata in dkim_answers:
                    txt_str = str(rdata).lower()
                    if 'v=dkim1' in txt_str or 'p=' in txt_str:
                        has_dkim = True
                        break
                if has_dkim:
                    break
            except DNSUnavailable:
                # DNS недоступен — перебирать остальные 20+ селекторов бессмысленно
                dns_failed = True
                break
            except self._ANSWERED_NOTHING:
                continue              # этого селектора нет, пробуем следующий
            except Exception:
                # Сбой, а не ответ. Перебор продолжаем — вдруг следующий
                # селектор ответит, — но помним, что нуль в конце может
                # оказаться нашим, а не доменным.
                dns_failed = True
                continue

        score = int(has_spf) + int(has_dmarc) + int(has_dkim)
        result = {'has_spf': has_spf, 'has_dmarc': has_dmarc, 'has_dkim': has_dkim, 'score': score}

        # DNS не ответил — кэшировать результат нельзя вообще, а не только
        # при нулевом счёте.
        #
        # Раньше условие требовало score == 0, и частичный ответ запоминался
        # как полный: SPF нашёлся, DMARC отвалился по таймауту — и домен до
        # конца прогона числился «SPF есть, DMARC нет». Это ровно то, за что
        # адрес штрафовать нельзя: «не проверено» — не то же, что «нет».
        if dns_failed:
            return result

        with self._dns_health_lock:
            self._dns_health_cache[domain] = result

        return result
