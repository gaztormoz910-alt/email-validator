import ipaddress
import socket
import threading
import time

import dns.exception
import dns.resolver
import dns.reversename

from core.bounded import BoundedCache
from core.dns_resolver import (DNSUnavailable, ProxiedResolver, UnverifiedNoAnswer,
                               UnverifiedNXDOMAIN)
from core.email_syntax import to_ascii_domain
from core.mxguard import is_ip_literal
from core.mail_constants import (DNSBL_ZONES, DNSBL_ZONES_IPV6, SPAMHAUS_ZONE,
                                 SPAMHAUS_SANITY_LISTED, SPAMHAUS_SANITY_CLEAN,
                                 _dkim_selectors_for)
from core.hostport import ipv6_literal


def _same_address(text, target):
    try:
        return ipaddress.ip_address(text) == target
    except ValueError:
        return False


def system_resolvers():
    try:
        import dns.resolver

        found = list(dns.resolver.Resolver().nameservers or [])
    except Exception:
        return []
    return [str(ns).strip() for ns in found if str(ns).strip()]


MX_DOUBT_WILDCARD = ("У домена нет MX, а A-запись есть у любого выдуманного имени "
                     "(wildcard) — принимает ли он почту, по DNS не понять")
MX_DOUBT_UNVERIFIED = ("DNS через прокси ответил «записей нет», но без "
                       "подтверждения зашифрованным DNS (DoH) — прокси мог "
                       "подменить ответ, домен не проверен")


class DnsChecksMixin:

    def set_spamhaus_resolver(self, nameservers):
        if not nameservers:
            self._spamhaus_resolver = None
            self._spamhaus_ok = None
            return False

        resolver = ProxiedResolver(
            nameservers=list(nameservers), timeout=self.timeout,
            proxy_provider=self._dns_proxy, public_doh=False)

        def listed(reversed_ip):
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

        self._spamhaus_ok = (must_be_listed is True and must_be_clean is False)
        self._spamhaus_resolver = resolver if self._spamhaus_ok else None
        return bool(self._spamhaus_ok)

    def spamhaus_refusal_reason(self):
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
        for resolver in (candidates if candidates is not None else system_resolvers()):
            try:
                if self.set_spamhaus_resolver([resolver]):
                    return resolver
            except Exception:
                continue
        return None

    def _spamhaus_lists(self, ip):
        if not self._spamhaus_resolver or not self._spamhaus_ok:
            return None
        reversed_ip = '.'.join(reversed(ip.split('.')))
        try:
            answers = self._spamhaus_resolver.resolve(
                f"{reversed_ip}.{SPAMHAUS_ZONE}", 'A')
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
        if not isinstance(ip, str) or not ip:
            return False
        if ipv6_literal(ip) is not None:
            return self._dnsbl_ipv6(ip)
        with self._dnsbl_lock:
            if ip in self._dnsbl_cache:
                return self._dnsbl_cache[ip]

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

        if not result and unreachable == len(DNSBL_ZONES):
            return False

        with self._dnsbl_lock:
            self._dnsbl_cache[ip] = result
        return result

    def _dnsbl_ipv6(self, ip):
        if not DNSBL_ZONES_IPV6:
            return None
        nibbles = dns.reversename.from_address(ip).to_text()[:-len("ip6.arpa.")]
        answered = False
        for bl in DNSBL_ZONES_IPV6:
            try:
                answers = self.resolver.resolve(nibbles + bl, 'A')
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                answered = True
                continue
            except Exception:
                continue
            answered = True
            if any(r.to_text().startswith(('127.0.0.', '127.0.1.')) for r in answers):
                return True
        return False if answered else None

    def check_dnsbl(self, mx_host):
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
                    continue
        except DNSUnavailable:
            return False
        except Exception:
            result = False

        if not result and unreachable == len(DNSBL_ZONES):
            return False

        with self._dnsbl_lock:
            self._dnsbl_cache[mx_host] = result
        return result

    def check_fcrdns(self, ip):
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

            forward = self.resolver.resolve(
                hostname, 'AAAA' if ipv6_literal(ip) else 'A')
            target = ipaddress.ip_address(ip)
            result = any(_same_address(str(a), target) for a in forward)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            result = False
        except Exception:
            result = None

        if result is None:
            return None

        with self._fcrdns_lock:
            self._fcrdns_cache[ip] = result
        return result

    def get_ptr_hostname(self, ip):
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
            return None
        with self._ptr_lock:
            self._ptr_cache[mx_host] = result
        return result

    _ANSWERED_NOTHING = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer)

    _WILDCARD_PROBES = 2

    def _is_wildcard_domain(self, domain):
        import secrets

        for _ in range(self._WILDCARD_PROBES):
            выдуманное = "%s.%s" % (secrets.token_hex(8), domain)
            try:
                self.resolver.resolve(выдуманное, "A")
            except Exception:
                return False
        return True

    def mx_hosts_alive(self, hosts):
        if not isinstance(hosts, (list, tuple, set)) or not hosts:
            return None
        все_нет = True
        хоть_что_то_спросили = False
        for host in hosts:
            if not isinstance(host, str) or not host.strip():
                continue
            имя = host.strip().rstrip(".")
            if is_ip_literal(имя):
                return True
            with self._mx_host_lock:
                if имя in self._mx_host_cache:
                    известно = self._mx_host_cache[имя]
                else:
                    известно = "?"
            if известно == "?":
                известно = self._resolve_mx_host(имя)
                if известно != "?":
                    with self._mx_host_lock:
                        self._mx_host_cache[имя] = известно
            if известно == "есть":
                return True
            if известно == "нет":
                хоть_что_то_спросили = True
            else:
                все_нет = False
        if все_нет and хоть_что_то_спросили:
            return False
        return None

    def _resolve_mx_host(self, имя):
        for тип in ("A", "AAAA"):
            try:
                ответ = self.resolver.resolve(имя, тип)
                if ответ:
                    return "есть"
            except UnverifiedNXDOMAIN:
                # «Имени нет» по обычному DNS через чужой прокси: прокси мог
                return self._verify_mx_host(имя, тип)
            except dns.resolver.NXDOMAIN:
                return "нет"
            except dns.resolver.NoAnswer:
                pass
            except Exception:
                return "?"
        return "?"

    def _verify_mx_host(self, имя, тип):
        заверка = getattr(self.resolver, "resolve_verified", None)
        if not callable(заверка):
            return "?"
        try:
            ответ = заверка(имя, тип)
        except (UnverifiedNXDOMAIN, UnverifiedNoAnswer):
            return "?"
        except dns.resolver.NXDOMAIN:
            return "нет"
        except Exception:
            return "?"
        return "есть" if ответ else "?"

    def _mx_doubts(self):
        doubts = getattr(self, "_mx_doubt_store", None)
        if doubts is None:
            doubts = self._mx_doubt_store = BoundedCache()
        return doubts

    def mx_doubt_reason(self, domain):
        return self._mx_doubts().get(to_ascii_domain(domain) or domain)

    def _verify_negative(self, domain):
        заверить = getattr(self.resolver, "resolve_verified", None)
        if not callable(заверить):
            return None
        try:
            ответ = sorted(заверить(domain, 'MX'), key=lambda x: x.preference)
            if (len(ответ) == 1 and ответ[0].preference == 0
                    and str(ответ[0].exchange) in ('.', '')):
                итог = []
            else:
                итог = [str(r.exchange).rstrip('.') for r in ответ] or None
        except (UnverifiedNXDOMAIN, UnverifiedNoAnswer):
            # Подклассы NXDOMAIN/NoAnswer: строка ниже приняла бы их за
            # заверенное «нет» и похоронила бы домен. Сюда их приносить
            return None
        except dns.resolver.NXDOMAIN:
            итог = []
        except dns.resolver.NoAnswer:
            итог = None
            for вид in ('A', 'AAAA'):
                try:
                    заверить(domain, вид)
                except (UnverifiedNXDOMAIN, UnverifiedNoAnswer):
                    return None
                except self._ANSWERED_NOTHING:
                    continue
                except Exception:
                    return None
                if self._is_wildcard_domain(domain):
                    self._mx_doubts()[domain] = MX_DOUBT_WILDCARD
                    with self.mx_lock:
                        self.mx_cache[domain] = None
                    return None
                итог = [domain]
                break
            if итог is None:
                итог = []
        except Exception:
            return None
        if итог is None:
            return None
        with self.mx_lock:
            self.mx_cache[domain] = итог
        return итог

    def get_mx_records(self, domain: str):
        domain = to_ascii_domain(domain)
        if not domain:
            return []

        with self.mx_lock:
            if domain in self.mx_cache:
                return self.mx_cache[domain]
        self._mx_doubts().pop(domain, None)

        dns_failed = False
        unverified = False

        try:
            answers = self.resolver.resolve(domain, 'MX')
            records = sorted(answers, key=lambda x: x.preference)

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
        except UnverifiedNXDOMAIN:
            заверено = self._verify_negative(domain)
            if заверено is not None:
                return заверено
            if domain in self.mx_cache:
                return self.mx_cache[domain]
            self._mx_doubts()[domain] = MX_DOUBT_UNVERIFIED
            return None
        except dns.resolver.NXDOMAIN:
            with self.mx_lock:
                self.mx_cache[domain] = []
            return []
        except UnverifiedNoAnswer:
            unverified = True
        except dns.resolver.NoAnswer:
            pass
        except Exception:
            dns_failed = True

        if dns_failed:
            return None

        # Фоллбэк на A-запись (п.1.4): если MX нет — пробуем сам домен как mail-сервер.
        if self._is_wildcard_domain(domain):
            self._mx_doubts()[domain] = MX_DOUBT_WILDCARD
            with self.mx_lock:
                self.mx_cache[domain] = None
            return None

        try:
            self.resolver.resolve(domain, 'A')
            result = [domain]
            with self.mx_lock:
                self.mx_cache[domain] = result
            return result
        except DNSUnavailable:
            dns_failed = True
        except (UnverifiedNXDOMAIN, UnverifiedNoAnswer):
            unverified = True
        except self._ANSWERED_NOTHING:
            pass
        except Exception:
            dns_failed = True

        try:
            self.resolver.resolve(domain, 'AAAA')
            result = [domain]
            with self.mx_lock:
                self.mx_cache[domain] = result
            return result
        except DNSUnavailable:
            dns_failed = True
        except (UnverifiedNXDOMAIN, UnverifiedNoAnswer):
            unverified = True
        except self._ANSWERED_NOTHING:
            pass
        except Exception:
            dns_failed = True

        if dns_failed:
            return None

        if unverified:
            заверено = self._verify_negative(domain)
            if заверено is not None:
                return заверено
            if domain in self.mx_cache:
                return self.mx_cache[domain]
            self._mx_doubts()[domain] = MX_DOUBT_UNVERIFIED
            return None

        with self.mx_lock:
            self.mx_cache[domain] = []
        return []

    def check_dns_health(self, domain: str, mx_record: str = "") -> dict:
        with self._dns_health_lock:
            if domain in self._dns_health_cache:
                return self._dns_health_cache[domain]

        has_spf = False
        has_dmarc = False
        has_dkim = False
        dns_failed = False

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
            pass
        except Exception:
            dns_failed = True

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
                dns_failed = True
                break
            except self._ANSWERED_NOTHING:
                continue
            except Exception:
                dns_failed = True
                continue

        score = int(has_spf) + int(has_dmarc) + int(has_dkim)
        result = {'has_spf': has_spf, 'has_dmarc': has_dmarc, 'has_dkim': has_dkim, 'score': score}

        if dns_failed:
            return result

        with self._dns_health_lock:
            self._dns_health_cache[domain] = result

        return result
