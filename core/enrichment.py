# -*- coding: utf-8 -*-
import json
import datetime
import urllib.request
import urllib.error
from core.verdict import verdict_confidence
from core.parser.name_extractor import split_name
from core.org_role import enrich_org_role
from core.scoring import calculate_engagement_score
from core.provider import classify_domain, country_from_domain, country_from_location, is_free_mail_domain
from core.heuristics import extract_birth_year, looks_machine_generated, is_parked_domain
from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS

AI_SUSPICION_PENALTY = 25
def _enrich_signature(enable_osint, enable_ai):
    try:
        from core.parser.ml_predictor import get_country_mode
        country_mode = get_country_mode()
    except Exception:
        country_mode = "?"
    return f"osint={bool(enable_osint)};ai={bool(enable_ai)};country={country_mode}"
def _has_confirmed_first(name):
    try:
        from core.parser.names_index import is_known_name
    except Exception:
        return False
    for part in (name or "").replace(",", " ").split():
        word = part.strip(".'-").lower()
        if len(word) >= 3 and is_known_name(word):
            return True
    return False


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)
def _as_utc(dt):
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)
def _fmt_stamp(iso_stamp):
    try:
        return _as_utc(datetime.datetime.fromisoformat(iso_stamp)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""


__all__ = ["EnrichmentMixin", "AI_SUSPICION_PENALTY",
           "_enrich_signature", "_utc_now", "_as_utc", "_fmt_stamp"]


class EnrichmentMixin:
    def _get_domain_age_days(self, domain):
        with self._domain_age_lock:
            if domain in self._domain_age_cache:
                return self._domain_age_cache[domain]

        with self._domain_gate("age:" + domain):
            with self._domain_age_lock:
                if domain in self._domain_age_cache:
                    return self._domain_age_cache[domain]
            return self._fetch_domain_age(domain)
    def _fetch_domain_age(self, domain):
        proxies = self._http_proxies()
        try:
            if proxies:
                from core.network import whois_creation_date
                proxy_line = self.network._pick_best_proxy() if self.network else None
                if proxy_line:
                    stamp = whois_creation_date(domain, proxy=proxy_line,
                                                timeout=10)
                    if stamp:
                        dt = datetime.datetime.fromisoformat(
                            stamp.replace("Z", "+00:00").rstrip("."))
                        age = (_utc_now() - _as_utc(dt)).days
                        with self._domain_age_lock:
                            self._domain_age_cache[domain] = age
                        return age
                raise RuntimeError("WHOIS через прокси не ответил — идём в RDAP")
            import whois
            w = whois.whois(domain)
            creation = w.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if creation:
                age = (_utc_now() - _as_utc(creation)).days
                with self._domain_age_lock:
                    self._domain_age_cache[domain] = age
                return age
        except Exception:
            pass
        try:
            url = f"https://rdap.org/domain/{domain}"
            if proxies:
                import requests
                data = requests.get(url, timeout=8, proxies=proxies,
                                    headers={"User-Agent": "Mozilla/5.0"}).json()
            else:
                req = urllib.request.Request(url, method="GET")
                req.add_header("User-Agent", "Mozilla/5.0")
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode())
            for event in data.get("events", []):
                if event.get("eventAction") == "registration":
                    dt = datetime.datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                    age = (_utc_now() - _as_utc(dt)).days
                    with self._domain_age_lock:
                        self._domain_age_cache[domain] = age
                    return age
        except Exception:
            pass
        with self._domain_age_lock:
            self._domain_age_cache[domain] = -1
        return -1
    def _check_http_alive(self, domain):
        with self._http_alive_lock:
            if domain in self._http_alive_cache:
                return self._http_alive_cache[domain]

        with self._domain_gate("http:" + domain):
            with self._http_alive_lock:
                if domain in self._http_alive_cache:
                    return self._http_alive_cache[domain]
            return self._fetch_http_alive(domain)
    def _fetch_http_alive(self, domain):
        proxies = self._http_proxies()
        for scheme in ("https", "http"):
            try:
                url = f"{scheme}://{domain}"
                if proxies:
                    import requests
                    alive = requests.head(url, timeout=6, proxies=proxies,
                                          headers={"User-Agent": "Mozilla/5.0"},
                                          allow_redirects=True).status_code < 400
                else:
                    req = urllib.request.Request(url, method="HEAD")
                    req.add_header("User-Agent", "Mozilla/5.0")
                    with urllib.request.urlopen(req, timeout=5) as resp:
                        alive = resp.status < 400
                with self._http_alive_lock:
                    self._http_alive_cache[domain] = alive
                return alive
            except Exception:
                continue
        with self._http_alive_lock:
            self._http_alive_cache[domain] = False
        return False
    def _подсказать_опечатку(self, email, data, fix_typos):
        if not fix_typos or self.cleaner is None or self.network is None:
            return
        try:
            suggestion = self.cleaner.suggest_domain_fix(email)
        except Exception:
            return
        if not suggestion or suggestion == email:
            return
        data["suggested_email"] = suggestion
        try:
            data["suggested_status"] = self.network.check_email(
                suggestion).get("status", "")
        except Exception:
            data["suggested_status"] = ""
    def _enrich_offline(self, email, data, status_display, enable_ai):
        try:
            score_before = data.get("engagement_score")
            grade_before = data.get("engagement_grade")
            provider_before = data.get("provider_name")
            type_before = data.get("provider_type")
            domain_before = data.get("domain_type")

            self._enrich_and_score(
                email, data,
                {"reason": "", "mx_record": "N/A", "mx_records": []},
                status_display, status_display, False, enable_ai)

            data["engagement_score"] = score_before
            data["engagement_grade"] = grade_before
            data["provider_name"] = provider_before
            data["provider_type"] = type_before
            data["domain_type"] = domain_before
        except Exception:
            pass
    def _enrich_and_score(self, email, data, res, status_display,
                          original_smtp_status, is_role, enable_ai):
        domain = email.rsplit("@", 1)[1].lower() if "@" in email else ""
        mx_host = res.get("mx_record", "")

        name = data.get("name", "")
        name_source = "файл" if name else ""
        if not name:
            name = self.name_extractor.extract_name(email) or ""
            if name:
                узнать = getattr(self.name_extractor, "last_name_source", None)
                name_source = (узнать() if callable(узнать) else "") or "адрес"
            if (name and enable_ai and not _has_confirmed_first(name)
                    and not self.ml_predictor.is_person(name)):
                name, name_source = "", ""

        country = data.get("country", "")
        country_source = "файл" if country else ""
        if not country:
            country = country_from_domain(domain)
            if country:
                country_source = "домен"
        if not country:
            location = (self.name_extractor.last_profile().get("location") or "").strip()
            if location:
                country = country_from_location(location) or ""
                if country:
                    country_source = "Gravatar"
        if not country and name:
            country = self.ml_predictor.predict_country(name)
            if country:
                country_source = "имя"

        gender = data.get("gender", "")
        gender_source = "файл" if gender else ""
        if not gender:
            gender = self.ml_predictor.predict_gender(name, country)
            if gender:
                gender_source = "имя"

        birth_year = data.get("birth_year", "") or extract_birth_year(email) or ""

        data["name"] = name
        first_name, last_name = split_name(name)
        data["first_name"] = first_name
        data["last_name"] = last_name
        data["gender"] = gender
        data["country"] = country
        data["birth_year"] = birth_year
        data["name_source"] = name_source
        accounts = self.name_extractor.last_profile().get("accounts") or []
        if accounts:
            data["social_accounts"] = ", ".join(accounts[:5])
        data["gender_source"] = gender_source
        data["country_source"] = country_source

        has_avatar = False
        if status_display in ("Valid", "Risky", "Role-based"):
            try:
                has_avatar = self.gravatar_checker.has_gravatar(email)
            except Exception:
                pass

        dns_score = 0
        try:
            dns_info = self.network.check_dns_health(domain, mx_record=mx_host)
            dns_score = dns_info.get("score", 0)
        except Exception:
            pass

        in_dnsbl = False
        has_ptr = None
        has_starttls = res.get("has_starttls", None)
        if mx_host and mx_host != "N/A":
            try:
                in_dnsbl = self.network.check_dnsbl(mx_host)
            except Exception:
                pass
            try:
                has_ptr = self.network.check_ptr(mx_host)
            except Exception:
                pass

        domain_age = -1
        has_live_site = True
        if status_display in ("Valid", "Risky", "Role-based"):
            try:
                domain_age = self._get_domain_age_days(domain)
            except Exception:
                pass
            try:
                if domain not in GLOBAL_VERIFIED_DOMAINS and not is_free_mail_domain(domain):
                    has_live_site = self._check_http_alive(domain)
            except Exception:
                pass

        score_result = calculate_engagement_score(
            email=email,
            smtp_status=status_display,
            smtp_reason=res.get("reason", ""),
            has_gravatar=has_avatar,
            is_disposable=False,
            dns_health_score=dns_score,
            domain_age_days=domain_age,
            name_extracted=name,
            is_role_based=is_role,
            server_outdated=res.get("server_outdated", False),
            has_ptr=has_ptr,
            has_starttls=has_starttls,
            in_dnsbl=in_dnsbl,
            has_live_website=has_live_site,
            original_smtp_status=original_smtp_status,
            machine_generated=looks_machine_generated(email),
            is_parked_domain=is_parked_domain(res.get("mx_records") or mx_host),
        )

        confidence, basis = verdict_confidence(
            original_smtp_status or status_display,
            res.get("reason", ""),
            {"control_probe": res.get("control_rcpt") == "rejected",
             "confirmed": res.get("second_opinion") == "agreed",
             "postmaster_honored": res.get("postmaster_honored"),
             "valid_second_opinion": res.get("valid_second_opinion")})
        data["verdict_confidence"] = confidence
        data["verdict_basis"] = basis

        data["engagement_score"] = score_result["score"]
        data["engagement_grade"] = score_result["grade"]
        data["provider_type"] = score_result["provider_type"]
        data["has_gravatar"] = has_avatar

        if data.get("ai_suspicious"):
            try:
                score = int(data.get("engagement_score", 0) or 0)
            except (TypeError, ValueError):
                score = 0
            data["engagement_score"] = max(1, score - AI_SUSPICION_PENALTY) if score else score
            data["ai_note"] = "имя выглядит машинным — проверено сервером, вердикт от него"

        prov_name, dom_type = classify_domain(email, mx_host)
        if (prov_name == "Corporate" and res.get("has_starttls") is True
                and mx_host and mx_host != "N/A"):
            try:
                from core.mx_certificate import provider_by_certificate
                by_cert = provider_by_certificate(self.network, mx_host,
                                                  proxy=res.get("proxy"))
            except Exception:
                by_cert = None
            if by_cert:
                prov_name = by_cert
                data["provider_basis"] = "сертификат MX"
        data["provider_name"] = prov_name
        data["domain_type"] = dom_type

        data.update(enrich_org_role(email, dom_type))

        data["enrich_sig"] = _enrich_signature(
            getattr(self.name_extractor, "enable_osint", False), enable_ai)

        if self.cache:
            cache = self.cache
            if cache is None or getattr(self, "_aborting", False):
                return
            cache.put(email, original_smtp_status, res.get("reason", ""),
                           mx_host or "N/A", data)
