import dns.resolver
import dns.reversename
import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import smtplib
import socket
import random
import string
import socks
import zlib
import threading
import re

from core.local_rules import (check_local_part, IMPOSSIBLE as LOCAL_IMPOSSIBLE,
                              UNLIKELY as LOCAL_UNLIKELY)
from concurrent.futures import ThreadPoolExecutor
import time

from core.mxguard import filter_mx_hosts, resolves_to_private, REASON_PRIVATE
from core.network_abort import AbortableMixin
from core.mail_constants import (
    YAHOO_DOMAINS, AOL_DOMAINS, NEEDS_CLEAN_IP_DOMAINS, NICHE_FREE_DOMAINS,
    MICROSOFT_DOMAINS, LEGIT_HELO_NAMES, DNSBL_ZONES, SPAMHAUS_ZONE,
    SPAMHAUS_SANITY_LISTED, SPAMHAUS_SANITY_CLEAN,
    PROXY_MAX_CONSECUTIVE_FAILS, MAIL_FROM_POOL, mail_from_for,
    _dkim_selectors_for,
    SECURITY_GATEWAY_MX, _DKIM_BY_MX, _DKIM_FALLBACK,
    reserved_zone,
)

from core.email_syntax import (
    has_quoted_local,
    domain_literal_ip,
    to_ascii_domain, has_non_ascii_local, validate_email_syntax,
    MAX_EMAIL_BYTES, MAX_LOCAL_BYTES, MAX_DOMAIN_BYTES,
)

from core.proxy_transport import (
    PROXY_TYPES as _PROXY_TYPES, SocksSMTP, build_proxy_dict,
    _parse_proxy, _proxy_scheme, _EXIT_IP_RE, PROXY_PROBE_TARGETS,
    EXIT_IP_PROBE_HOST, PROBE_GMAIL, PROBE_OUTLOOK, PROBE_YAHOO, PROBE_ICLOUD,
)

from core.proxy_probe import (
    DIRTY_RDNS_KEYWORDS, probe_proxy_target, get_proxy_exit_ip,
    dedupe_proxies, dedupe_proxies_stream, is_dirty_rdns,
    profile_proxies, filter_live_proxies,
)

from core.whois_client import (
    whois_creation_date, _whois_ask, WHOIS_PORT, WHOIS_IANA,
    _WHOIS_REFER_RE, _WHOIS_CREATED_RE,
)

from core.smtp_codes import (
    IP_REPUTATION_MARKERS as _IP_REPUTATION_MARKERS,
    TRANSIENT_TEXT_MARKERS as _TRANSIENT_TEXT_MARKERS,
    RECIPIENT_NEGATIONS as _RECIPIENT_NEGATIONS,
    classify_smtp_response as _classify_smtp_response,
    looks_transient as _looks_transient,
    looks_like_ip_reputation as _looks_like_ip_reputation,
)


def security_gateway(mx_records):
    if not mx_records:
        return None
    if isinstance(mx_records, str):
        records = [mx_records]
    elif hasattr(mx_records, "__iter__") and not isinstance(mx_records, (bytes, dict)):
        records = list(mx_records)
    else:
        return None
    for record in records:
        if not isinstance(record, str):
            continue
        low = record.lower().rstrip(".")
        for host, vendor in SECURITY_GATEWAY_MX.items():
            if low == host or low.endswith("." + host):
                return vendor
    return None


from core.dns_resolver import (
    _COUNTRY_TO_CODE,
    ProxiedResolver,
    DNSUnavailable,
    DOH_ENDPOINTS,
)

from core.bounded import BoundedCache
from core.proxy_pool import ProxyPoolMixin, UNKNOWN_LATENCY_MS
from core.catchall import CatchAllMixin
from core.second_opinion import SecondOpinionMixin
from core.confirmation import AcceptanceMixin
from core.reject_control import RejectControlMixin
from core.behind_gateway import BehindGatewayMixin
from core.dns_checks import DnsChecksMixin


def country_code_for_domain(domain):
    if not isinstance(domain, str) or "." not in domain:
        return ""
    try:
        from core.provider import country_from_domain
    except Exception:
        return ""
    return _COUNTRY_TO_CODE.get(country_from_domain(domain), "")


_СЛОГИ = ("ma", "ne", "ri", "lo", "ta", "ve", "si", "ko", "da", "le",
          "mi", "no", "ra", "se", "ti", "vo", "ba", "de", "li", "mo",
          "na", "re", "so", "tu", "va", "be", "di", "lu", "ka", "pe",
          "ni", "ro")


def _generate_random_local(style="short"):
    if style == "uuid":
        import uuid
        return str(uuid.uuid4()).replace('-', '')[:24]
    if style == "name":
        часть = lambda: ''.join(random.choices(_СЛОГИ, k=6))
        цифры = ''.join(random.choices(string.digits, k=4))
        return f"{часть()}.{часть()}{цифры}"
    chars = string.ascii_lowercase + string.digits
    prefix = ''.join(random.choices(chars, k=12))
    suffix = ''.join(random.choices(string.digits, k=4))
    return f"{prefix}{suffix}"


def control_probe_address(domain):
    return "%s@%s" % (_generate_random_local("name"), domain)


class NetworkValidator(AbortableMixin, ProxyPoolMixin, DnsChecksMixin,
                       CatchAllMixin, SecondOpinionMixin, AcceptanceMixin,
                       RejectControlMixin, BehindGatewayMixin):

    def __init__(self, from_email="check@example.com", timeout=5, proxies=None,
                 proxy_dns=True):
        self.from_email = from_email
        self.timeout = timeout
        self.proxies = proxies if proxies else []
        self.address_deadline = max(30, min(180, timeout * 6))
        self.abort_event = threading.Event()

        self._proxy_dns = bool(proxy_dns)

        self.resolver = ProxiedResolver(
            nameservers=['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1'],
            timeout=self.timeout,
            proxy_provider=self._dns_proxy,
        )


        self.mx_cache = BoundedCache()
        self.mx_lock = threading.Lock()
        self._mx_host_cache = BoundedCache()
        self._mx_host_lock = threading.Lock()

        self.catchall_cache = BoundedCache()
        self._control_addrs = BoundedCache()

        try:
            from core.longterm import LongTermMemory
            self.memory = LongTermMemory()
        except Exception:
            self.memory = None
        self.catchall_lock = threading.Lock()
        self._domain_checks = {}
        self._domain_checks_lock = threading.Lock()
        self._tarpit_domains = set()
        self._tarpit_pairs = set()

        self._mx_catchall = BoundedCache(max_keys=20_000)

        self._postmaster_cache = BoundedCache()
        self._postmaster_lock = threading.Lock()

        self._dns_health_cache = BoundedCache()
        self._dns_health_lock = threading.Lock()

        self._dnsbl_cache = BoundedCache()
        self._dnsbl_lock = threading.Lock()
        self._ptr_cache = BoundedCache()
        self._ptr_lock = threading.Lock()
        self._fcrdns_cache = BoundedCache()
        self._fcrdns_lock = threading.Lock()

        self._mx_semaphores = BoundedCache()
        self._mx_sem_lock = threading.Lock()
        self._max_concurrent_per_mx = 5

        self._mx_error_counts = BoundedCache()
        self._mx_error_seen = BoundedCache()
        self._mx_narrowed = BoundedCache()
        self._mx_error_lock = threading.Lock()

        self._proxy_scores = {}
        self._proxy_score_lock = threading.Lock()

        self._proxy_semaphores = {}
        self._proxy_sem_lock = threading.Lock()
        self._max_concurrent_per_proxy = 8

        self._ip_load = {}
        self._ip_load_lock = threading.Lock()
        self._ip_load_soft_cap = 800

        self._spamhaus_resolver = None
        self._spamhaus_ok = None
        self._proxy_latency = {}
        self._proxy_consecutive_fails = {}
        self._proxy_fail_hosts = {}
        self._proxy_banned = set()

        self._recent_bans = []
        self._proxy_profiles = {}
        self._mx_country_cache = BoundedCache()
        self._mx_country_lock = threading.Lock()

        self._ptr_proxies = set()
        self._ptr_unknown = set()
        self._profiled = False
        self._dirty_proxies = set()
        self._yahoo_ok = set()
        self._yahoo_bad = set()
        self._icloud_bad = set()
        if self.proxies:
            for p in self.proxies:
                self._proxy_scores[p] = 0
                self._proxy_consecutive_fails[p] = 0

        self.helo_name = random.choice(LEGIT_HELO_NAMES)

    def _is_server_outdated(self, banner_text: str) -> bool:
        if not banner_text:
            return False
        if not isinstance(banner_text, str):
            return False
        b = banner_text.lower()
        
        
        if re.search(r'postfix\s*2\.\d', b):
            return True
        if re.search(r'postfix\s*3\.[012]\b', b):
            return True
        
        if re.search(r'exim\s*4\.[67]\d', b):
            return True
        
        if re.search(r'sendmail\s*8\.1[0-4]', b):
            return True
        
        if 'courier' in b and re.search(r'courier\s*0\.\d', b):
            return True
        
        if re.search(r'hmailserver\s*[0-4]\.', b):
            return True
        
        if 'qmail' in b:
            return True
            
        return False

    def _make_smtp_connection(self, proxy=None):
        if proxy:
            parsed = _parse_proxy(proxy)
            if not parsed:
                raise ValueError("Неверный формат прокси")
            ip, port, user, password = parsed
            return self._track(SocksSMTP(ip, port, proxy_user=user, proxy_pass=password, timeout=self.timeout,
                                         proxy_type=_PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5)))
        else:
            return self._track(smtplib.SMTP(timeout=self.timeout))

    def _ask_vrfy(self, server, email, domain):
        try:
            code, message = server.verify(email)
        except Exception:
            return None
        try:
            numeric = int(code)
        except (TypeError, ValueError):
            return None
        if numeric == 252:
            return None
        verdict = self._parse_smtp_response(numeric, message, email, domain)
        if verdict["status"] == "unknown":
            return None
        verdict["reason"] = "VRFY: %s" % verdict.get("reason", "")
        return verdict

    def _parse_smtp_response(self, code, message, email, domain):
        return _classify_smtp_response(code, message)

    def _helo_for(self, proxy):
        if not proxy:
            return self.helo_name
        try:
            exit_ip = self.exit_ip_of(proxy) or str(proxy)
            index = zlib.crc32(exit_ip.encode("utf-8", "ignore"))
            return LEGIT_HELO_NAMES[index % len(LEGIT_HELO_NAMES)]
        except Exception:
            return self.helo_name

    def _do_single_ping(self, email, mx_record, proxy=None, from_email=None,
                        control_probe=False):
        if proxy is None and self.has_proxies_configured():
            return {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}

        domain = email.split("@")[1].lower() if "@" in email else ""
        from_addr = from_email or mail_from_for(domain)
        server = None

        if self._pause(self._mx_delay(mx_record)):
            return dict(self.ABORTED)

        sem = self._get_mx_semaphore(mx_record, proxy)
        if not self._take(sem):
            return dict(self.ABORTED)

        slot = self.proxy_slot(proxy)
        if slot is not None and not self._take(slot):
            sem.release()
            return dict(self.ABORTED)

        try:
            self.note_ip_use(proxy)

            server = self._make_smtp_connection(proxy)
            _connect_started = time.monotonic()
            banner_code, banner_msg = server.connect(mx_record, 25)
            self._note_latency(proxy, (time.monotonic() - _connect_started) * 1000)
            
            banner_text = banner_msg.decode('utf-8', 'ignore') if isinstance(banner_msg, bytes) else str(banner_msg)

            try:
                helo_name = self._helo_for(proxy)
                ehlo_code, ehlo_msg = server.ehlo(helo_name)
                if ehlo_code >= 500:
                    server.helo(helo_name)
            except Exception:
                ehlo_msg = b""
                server.helo(self._helo_for(proxy))

            has_starttls = False
            try:
                if server.has_extn('starttls'):
                    has_starttls = True
            except Exception:
                ehlo_str = ehlo_msg.decode('utf-8', 'ignore').lower() if isinstance(ehlo_msg, bytes) else str(ehlo_msg).lower()
                if 'starttls' in ehlo_str:
                    has_starttls = True

            mail_options = []
            if has_non_ascii_local(email):
                supports_utf8 = False
                try:
                    supports_utf8 = server.has_extn("smtputf8")
                except Exception:
                    supports_utf8 = False
                if not supports_utf8:
                    return {
                        "status": "unknown",
                        "reason": ("Не-ASCII имя ящика, а сервер не объявил "
                                   "SMTPUTF8 — проверить нечем"),
                        "smtp_banner": banner_text,
                        "server_outdated": self._is_server_outdated(banner_text),
                        "has_starttls": has_starttls,
                    }
                mail_options = ["SMTPUTF8"]
                server.command_encoding = "utf-8"

            if mail_options:
                mail_code, mail_msg = server.mail(from_addr, options=mail_options)
            else:
                mail_code, mail_msg = server.mail(from_addr)
            if mail_code >= 400:
                mail_text = mail_msg.decode('utf-8', 'ignore') if isinstance(mail_msg, bytes) else str(mail_msg)
                low = mail_text.lower()

                if "5.7.25" in mail_text or "reverse dns" in low or "forward-confirmed" in low:
                    reason = ("550 Нет обратного DNS у нашего IP (FCrDNS) — "
                              "Yahoo/AOL не пускают. Нужен прокси с PTR-записью.")
                elif "4.7.23" in mail_text or "ptr record" in low:
                    reason = (f"{mail_code} Нет обратного DNS (PTR) у нашего IP — "
                              "почтовик не пускает. Нужен прокси с PTR-записью.")
                else:
                    reason = f"{mail_code} MAIL FROM Rejected (Email May Exist): {mail_text[:40]}"
                    self._update_proxy_score(proxy, False, mx_record=mx_record)

                return {
                    "status": "unknown",
                    "reason": reason,
                    "smtp_banner": banner_text,
                    "server_outdated": self._is_server_outdated(banner_text),
                    "has_starttls": has_starttls,
                }

            code, message = server.rcpt(email)

            result = self._parse_smtp_response(code, message, email, domain)

            if result["status"] == "unknown":
                verified = self._ask_vrfy(server, email, domain)
                if verified is not None:
                    result = verified
                    result["via_vrfy"] = True

            self._compare_with_fake_reject(server, domain, result, code, message, email)

            # Контрольный вопрос про выдуманный адрес в ТОЙ ЖЕ сессии.
            if control_probe and domain:
                if result["status"] == "valid":
                    self._control_in_session(server, domain, result,
                                             via_vrfy=bool(result.get("via_vrfy")),
                                             proxy=proxy, mx=mx_record)
                elif result["status"] == "greylisted":
                    self._prewarm_control(server, domain)

            result["smtp_banner"] = banner_text
            result["server_outdated"] = self._is_server_outdated(banner_text)
            result["has_starttls"] = has_starttls

            if code == 421:
                self._record_mx_error(mx_record, proxy)

            self._update_proxy_score(proxy, True)
            return result

        except smtplib.SMTPServerDisconnected:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": "Server Disconnected"}
        except socket.timeout:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": "Timeout"}
        except socks.ProxyConnectionError:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": "Proxy Dead"}
        except smtplib.SMTPConnectError:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": "SMTP Connect Error"}
        except smtplib.SMTPException as e:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": f"SMTP Error: {str(e)[:50]}"}
        except Exception as e:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            return {"status": "unknown", "reason": f"Error: {str(e)[:50]}"}
        finally:
            sem.release()
            if slot is not None:
                slot.release()
            if server:
                self._finish(server)

    def _probe_recipients(self, addresses, mx_record, proxy=None, from_email=None):
        if proxy is None and self.has_proxies_configured():
            fail = {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}
            return [dict(fail) for _ in addresses]

        domain = addresses[0].split("@")[1].lower() if addresses and "@" in addresses[0] else ""
        from_addr = from_email or mail_from_for(domain)
        results = []
        server = None

        if self._pause(self._mx_delay(mx_record)):
            return [dict(self.ABORTED) for _ in addresses]

        sem = self._get_mx_semaphore(mx_record, proxy)
        if not self._take(sem):
            return [dict(self.ABORTED) for _ in addresses]
        try:
            server = self._make_smtp_connection(proxy)
            server.connect(mx_record, 25)
            try:
                helo_name = self._helo_for(proxy)
                ehlo_code, _ = server.ehlo(helo_name)
                if ehlo_code >= 500:
                    server.helo(helo_name)
            except Exception:
                server.helo(self._helo_for(proxy))

            mail_code, mail_msg = server.mail(from_addr)
            if mail_code >= 400:
                text = mail_msg.decode('utf-8', 'ignore') if isinstance(mail_msg, bytes) else str(mail_msg)
                self._update_proxy_score(proxy, False, mx_record=mx_record)
                fail = {"status": "unknown",
                        "reason": f"{mail_code} MAIL FROM Rejected: {text[:40]}"}
                return [dict(fail) for _ in addresses]

            for address in addresses:
                code, message = server.rcpt(address)
                results.append(self._parse_smtp_response(code, message, address, domain))
                if code == 421:
                    self._record_mx_error(mx_record, proxy)
                    break
            self._update_proxy_score(proxy, True)
        except Exception as e:
            self._update_proxy_score(proxy, False, mx_record=mx_record)
            results.append({"status": "unknown", "reason": f"Error: {type(e).__name__}"})
        finally:
            sem.release()
            if server:
                self._finish(server)

        while len(results) < len(addresses):
            results.append({"status": "unknown", "reason": "Сессия оборвалась"})
        return results

    def postmaster_is_honored(self, domain, mx_record):
        if not domain:
            return None
        with self._postmaster_lock:
            if domain in self._postmaster_cache:
                return self._postmaster_cache[domain]

        results = self._probe_recipients([f"postmaster@{domain}",
                                          f"abuse@{domain}"], mx_record,
                                         proxy=self._probe_proxy_for(domain))
        verdict = None
        for result in results or []:
            status = (result or {}).get("status")
            if status in ("valid", "catchall"):
                verdict = True
                break
            if status == "invalid":
                verdict = False
                break
        if verdict is None:
            return None

        with self._postmaster_lock:
            self._postmaster_cache[domain] = verdict
        return verdict

    def _probe_proxy_for(self, domain):
        domain = (domain or "").strip().lower()
        needs_ptr = domain in YAHOO_DOMAINS or domain in AOL_DOMAINS
        needs_clean = domain in NEEDS_CLEAN_IP_DOMAINS
        return (self._pick_for_domain(domain, needs_ptr, needs_clean)[0]
                or self._pick_best_proxy(need_ptr=needs_ptr, need_clean=needs_clean))

    def stealth_smtp_ping(self, email: str, mx_records: list,
                          control_probe=False, avoid_exit_of=None,
                          prefer_exit_of=None) -> dict:
        domain = email.split("@")[1].lower() if "@" in email else ""

        needs_ptr = domain in YAHOO_DOMAINS or domain in AOL_DOMAINS
        needs_clean = domain in NEEDS_CLEAN_IP_DOMAINS

        if avoid_exit_of:
            needs_clean = True

        want_country = self.country_for_domain(
            domain, mx_records[0] if mx_records else "")
        if needs_ptr and self.proxies and self._profiled and not self.has_ptr_proxies():
            return {
                "status": "unknown",
                "reason": ("Нет прокси с обратным DNS (PTR) — Yahoo/AOL проверить нечем. "
                           "Нужен прокси или VPS с PTR-записью."),
            }

        if domain in YAHOO_DOMAINS or domain in AOL_DOMAINS:
            max_retries = 15 if self.proxies else 3
        elif domain in MICROSOFT_DOMAINS:
            max_retries = 8 if self.proxies else 2
        else:
            max_retries = 10 if self.proxies else 1

        last_result = {"status": "unknown", "reason": "No Response"}

        deadline = time.monotonic() + self.address_deadline

        for mx_record in mx_records:
            if time.monotonic() > deadline:
                break
            for attempt in range(max_retries):
                if self.aborted():
                    return dict(self.ABORTED)
                if self.all_proxies_dead():
                    return {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}

                if time.monotonic() > deadline:
                    last_result = {
                        "status": "unknown",
                        "reason": f"Timeout: адрес проверялся дольше {self.address_deadline}с",
                    }
                    break

                proxy, все_пойманы = None, False
                if prefer_exit_of and attempt == 0:
                    proxy = self.proxy_still_usable(prefer_exit_of, domain)
                if proxy is None:
                    proxy, все_пойманы = self._pick_for_domain(
                        domain, needs_ptr, needs_clean, want_country, avoid_exit_of)
                if proxy is None and avoid_exit_of and self.has_proxies_configured():
                    proxy, все_пойманы = self._pick_for_domain(
                        domain, needs_ptr, needs_clean, want_country)
                if proxy is None and все_пойманы:
                    return dict(self.ALL_EXITS_CAUGHT)
                result = self._do_single_ping(email, mx_record, proxy=proxy,
                                              control_probe=control_probe)
                if proxy:
                    result["proxy"] = proxy

                if result["status"] == "valid":
                    return result

                if result["status"] == "catchall":
                    return result

                if result["status"] in ("full", "disabled"):
                    return result

                if result["status"] == "invalid":
                    почему = {}
                    confirmed = self._confirm_invalid_on_other_mx(
                        email, mx_record, mx_records, needs_ptr, needs_clean,
                        want_country, deadline, first_proxy=proxy, почему=почему)
                    if confirmed is None:
                        result["second_opinion"] = "unavailable"
                        result["second_opinion_reason"] = почему.get("текст", "")
                        result["reason"] = (
                            "%s [второго мнения не было: %s]"
                            % (result.get("reason", ""),
                               почему.get("текст", "причина не названа")))
                        return result
                    if confirmed:
                        result["second_opinion"] = "agreed"
                        return result
                    return {
                        "status": "risky",
                        "reason": ("Второй ответ противоречит первому: адрес "
                                   "отвергли с одного выхода и приняли с "
                                   "другого. Ящик может существовать."),
                        "smtp_banner": result.get("smtp_banner", ""),
                        "has_starttls": result.get("has_starttls"),
                        "server_outdated": result.get("server_outdated", False),
                    }

                if _looks_like_ip_reputation(result.get("reason", "")):
                    needs_clean = True

                if result["status"] == "greylisted":
                    last_result = result
                    continue

                last_result = result
                continue


        return last_result

    def country_for_domain(self, domain, mx_host=""):
        code = country_code_for_domain(domain)
        if code:
            return code
        if not mx_host or mx_host == "N/A":
            return ""

        key = mx_host.lower()
        with self._mx_country_lock:
            if key in self._mx_country_cache:
                return self._mx_country_cache[key]

        code = ""
        try:
            ip = str(self.resolver.resolve(mx_host, 'A')[0])
            from core.proxy_profile import lookup_ip_meta
            meta = lookup_ip_meta(ip, timeout=self.timeout,
                                  proxies=build_proxy_dict(self._pick_best_proxy() or "")
                                  if self.proxies else None)
            code = (meta.get("asn_country") or "").upper()
        except Exception:
            code = ""

        with self._mx_country_lock:
            self._mx_country_cache[key] = code
        return code


    @staticmethod
    def probe_form(email):
        local, _, raw = str(email or "").rpartition("@")
        if domain_literal_ip(raw) is not None:
            return "%s@%s" % (local, raw.strip().lower())
        domain = to_ascii_domain(raw.lower())
        return "%s@%s" % (local, domain) if domain else ""

    def check_email(self, email: str, avoid_exit_of=None,
                    prefer_exit_of=None) -> dict:
        if self.aborted():
            return dict(self.ABORTED, mx_record="N/A")

        if not validate_email_syntax(email):
            return {"status": "invalid", "reason": "Bad Syntax (RFC 5322)", "mx_record": "N/A"}


        local_part, _, raw_domain = email.rpartition("@")

        литерал = domain_literal_ip(raw_domain)
        if литерал is not None and resolves_to_private(str(литерал)):
            return {"status": "unknown",
                    "reason": "Проверить нечем: %s" % REASON_PRIVATE,
                    "mx_record": "N/A"}

        domain = (raw_domain.strip().lower() if литерал is not None
                  else to_ascii_domain(raw_domain.lower()))
        if not domain:
            return {"status": "invalid", "reason": "Invalid Domain (IDNA Error)", "mx_record": "N/A"}

        зона = reserved_zone(domain)
        if зона:
            return {"status": "invalid",
                    "reason": ("Зона .%s зарезервирована стандартом и не "
                               "существует в интернете — почту такой домен "
                               "принять не может" % зона),
                    "mx_record": "N/A"}

        probe_email = self.probe_form(email)

        rule_verdict, rule_reason = check_local_part(probe_email)
        if rule_verdict == LOCAL_IMPOSSIBLE:
            return {"status": "invalid",
                    "reason": f"Имя не может существовать — {rule_reason}",
                    "mx_record": "N/A"}

        mx_records = ([str(литерал)] if литерал is not None
                      else self.get_mx_records(domain))
        if mx_records is None:
            doubt = self.mx_doubt_reason(domain) if литерал is None else None
            return {"status": "unknown",
                    "reason": doubt or "DNS не удалось спросить через прокси (домен не проверен)",
                    "mx_record": "N/A"}
        if not mx_records:
            return {"status": "invalid", "reason": "No MX/A records (Dead Domain)", "mx_record": "N/A"}

        отброшено = []
        if литерал is None:
            mx_records, отброшено = filter_mx_hosts(mx_records)
        if отброшено and not mx_records:
            return {"status": "unknown",
                    "reason": "Проверить нечем: %s" % отброшено[0][1],
                    "mx_record": "N/A",
                    "mx_rejected": [х for х, _п in отброшено]}

        av_vendors = [
            "fireeye.com",
            "phishline.com", "perimeterwatch.com",
            "agari.com", "emailsecurity.trendmicro.com"
        ]
        for mx in mx_records:
            mx_lower = mx.lower().rstrip(".")
            vendor = next((v for v in av_vendors
                           if mx_lower == v or mx_lower.endswith("." + v)), "")
            if vendor:
                return {"status": "unknown",
                        "reason": ("MX охранного вендора (%s): ящик не проверяется "
                                   "намеренно — проба могла бы занести наш адрес в "
                                   "их списки угроз; есть ли ящик, неизвестно" % vendor),
                        "mx_record": mx, "security_vendor_mx": vendor}

        primary_mx = mx_records[0]

        gateway = security_gateway(mx_records)
        if gateway:
            result = self.stealth_smtp_ping(probe_email, mx_records,
                                            control_probe=True,
                                            avoid_exit_of=avoid_exit_of,
                                            prefer_exit_of=prefer_exit_of)
            result = self._confirm_acceptance(domain, result, mx_records,
                                              gateway=gateway)
            result["mx_record"] = primary_mx
            result["mx_records"] = mx_records
            return self._ask_behind_gateway(domain, probe_email, result, gateway,
                                            original=email)

        skip_catchall = self._is_never_catchall(domain)

        if not skip_catchall:
            is_catchall = self.is_catch_all_domain(domain, primary_mx)
            if is_catchall:
                result = self.stealth_smtp_ping(probe_email, mx_records,
                                                avoid_exit_of=avoid_exit_of,
                                                prefer_exit_of=prefer_exit_of)
                if result["status"] == "valid":
                    result["status"] = "catchall"
                    result["reason"] = "Catch-All Domain (Unverifiable)"
                result["mx_record"] = primary_mx
                result["mx_records"] = mx_records
                return result

        control = not skip_catchall
        if skip_catchall:
            control = self._time_to_recheck(domain)
        result = self.stealth_smtp_ping(probe_email, mx_records,
                                        control_probe=control,
                                        avoid_exit_of=avoid_exit_of,
                                        prefer_exit_of=prefer_exit_of)
        if result.get("aborted") or self.aborted():
            return dict(self.ABORTED, mx_record=primary_mx)

        if skip_catchall and result.get("status") == "catchall":
            result["reason"] = (
                "Сервер принимает любые адреса — похоже, наш IP под "
                "подозрением и почтовик защищается от перебора. Вердикт "
                "недоказуем; нужен чистый прокси")
            with self.catchall_lock:
                self._tarpit_domains.add(domain)
                self._tarpit_pairs.add((str(self.exit_ip_of(result.get("proxy")) or result.get("proxy") or "прямое соединение").lower(), domain))

        if not skip_catchall:
            result = self._confirm_acceptance(domain, result, mx_records)

        if result["status"] == "invalid":
            honored = self.postmaster_is_honored(domain, primary_mx)
            if honored is False:
                result["status"] = "risky"
                result["reason"] = ("550, но сервер отвергает и служебный "
                                    "адрес (postmaster@ / abuse@) — его "
                                    "отказам верить нельзя")
                result["postmaster_honored"] = False

        if (литерал is None
                and result.get("status") in ("unknown", "risky")
                and not result.get("smtp_banner")
                and self.mx_hosts_alive(mx_records) is False):
            result["status"] = "invalid"
            result["reason"] = ("MX-запись есть, но её сервер не существует "
                                "(NXDOMAIN) — домен почту принять не может")
            result["mx_record"] = primary_mx
            result["mx_records"] = mx_records
            return result

        if result["status"] in ("unknown", "greylisted"):
            dns_health = self.check_dns_health(domain)
            if dns_health["score"] >= 1:
                dns_tag = f" [DNS: SPF={'✓' if dns_health['has_spf'] else '✗'}, DMARC={'✓' if dns_health['has_dmarc'] else '✗'}, DKIM={'✓' if dns_health.get('has_dkim') else '✗'}]"
                if result["status"] == "greylisted":
                    result["status"] = "greylisted"
                    result["reason"] += dns_tag
                else:
                    result["status"] = "risky"
                    result["reason"] += dns_tag

        if result["status"] == "greylisted":
            pass

        if rule_verdict == LOCAL_UNLIKELY and result["status"] in ("unknown", "risky"):
            result["status"] = "risky"
            result["reason"] = f"{result.get('reason', '')} | {rule_reason}".strip(" |")

        result["mx_record"] = primary_mx
        result["mx_records"] = mx_records
        return result
