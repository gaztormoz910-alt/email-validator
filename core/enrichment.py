# -*- coding: utf-8 -*-
"""Обогащение записи: возраст домена, сайт, имя, пол, страна, скор.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. Всё здесь происходит ПОСЛЕ того, как вердикт о ящике
уже вынесен, и ни одна строка его не меняет — это данные РЯДОМ с вердиктом.
Держать их вперемешку с разбором ответа сервера опасно ровно тем, что
однажды кто-нибудь свяжет одно с другим: подсказка об опечатке уже пыталась
подменить проверяемый адрес, и владелец получил «Годен» на строку, которой
не загружал.

ПОЧЕМУ ПРИМЕСЬ. Состояние общее (`ValidationPipeline.__init__`), файл
поделён, поведение — нет.
"""
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

# Помощники переехали сюда из core/pipeline.py вместе с кодом,
# который их единственный и зовёт. Конвейер берёт их обратно
# импортом — направление одностороннее, круга нет.
# На сколько подозрение модели опускает оценку. Штраф, а не обнуление:
# обнулить — значит снова выдать догадку за приговор, только тише. Величина
# подобрана так, чтобы подозрительный живой адрес оказывался ниже честных
# живых, но выше всего недоказанного.
AI_SUSPICION_PENALTY = 25
def _enrich_signature(enable_osint, enable_ai):
    """Отпечаток настроек, от которых зависит обогащение.

    Нужен, чтобы кэш не отменял переключатели в окне и при этом оставался
    кэшем. Совпал отпечаток — обогащение из прошлого прогона годится как
    есть, и ни одного сетевого запроса не делается. Не совпал — считаем
    заново, потому что владелец сменил настройку и ждёт другого результата.

    Режим страны сюда входит наравне с тумблерами: именно на нём владелец и
    заметил, что кэш молча всё отменяет.
    """
    try:
        from core.parser.ml_predictor import get_country_mode
        country_mode = get_country_mode()
    except Exception:
        country_mode = "?"
    return f"osint={bool(enable_osint)};ai={bool(enable_ai)};country={country_mode}"
def _utc_now():
    """Текущее время как aware-datetime в UTC."""
    return datetime.datetime.now(datetime.timezone.utc)
def _as_utc(dt):
    """Приводит datetime к aware-UTC. Naive-даты считаем уже записанными в UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=datetime.timezone.utc)
    return dt.astimezone(datetime.timezone.utc)
def _fmt_stamp(iso_stamp):
    """ISO-время из кэша в тот же формат, что и у свежих проверок."""
    try:
        return _as_utc(datetime.datetime.fromisoformat(iso_stamp)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return ""


__all__ = ["EnrichmentMixin", "AI_SUSPICION_PENALTY",
           "_enrich_signature", "_utc_now", "_as_utc", "_fmt_stamp"]


class EnrichmentMixin:
    def _get_domain_age_days(self, domain):
        """Возраст домена в днях через WHOIS/RDAP. Кэшируется, запрос не дублируется."""
        with self._domain_age_lock:
            if domain in self._domain_age_cache:
                return self._domain_age_cache[domain]

        with self._domain_gate("age:" + domain):
            # Пока ждали замок, сосед мог всё посчитать — проверяем кэш снова
            with self._domain_age_lock:
                if domain in self._domain_age_cache:
                    return self._domain_age_cache[domain]
            return self._fetch_domain_age(domain)
    def _fetch_domain_age(self, domain):
        proxies = self._http_proxies()
        try:
            # Библиотека whois ходит по 43 порту голым сокетом и прокси не
            # умеет. Раньше при заданных прокси её просто пропускали, и возраст
            # домена оставался только за RDAP. Теперь тот же протокол говорится
            # вручную через SOCKS: утечки нет, а данные есть.
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
                # WHOIS часто возвращает datetime С таймзоной, а datetime.now() — без неё.
                # Раньше вычитание падало с TypeError, WHOIS-путь был мёртв и каждый
                # домен уходил в медленный RDAP-фоллбэк.
                age = (_utc_now() - _as_utc(creation)).days
                with self._domain_age_lock:
                    self._domain_age_cache[domain] = age
                return age
        except Exception:
            pass
        # Фоллбэк: RDAP через rdap.org
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
        """Есть ли живой сайт на домене (HEAD). Кэшируется, запрос не дублируется."""
        with self._http_alive_lock:
            if domain in self._http_alive_cache:
                return self._http_alive_cache[domain]

        with self._domain_gate("http:" + domain):
            with self._http_alive_lock:
                if domain in self._http_alive_cache:
                    return self._http_alive_cache[domain]
            return self._fetch_http_alive(domain)
    def _fetch_http_alive(self, domain):
        # Без прокси этот запрос оставляет реальный IP в логах самой проверяемой
        # компании — поэтому, если прокси заданы, идём через них.
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
        """Кладёт подсказку об опечатке РЯДОМ с вердиктом, не меняя его.

        ЗАЧЕМ ОТДЕЛЬНО ОТ ОСНОВНОГО ПУТИ. Разбор опечатки живёт после SMTP и
        срабатывает на «нет MX». Домен-опечатка из списка одноразовых до него
        не доходит: вердикт выносится раньше, по списку. Замерено 11.09.2026,
        когда списки наконец заработали: user@gmial.com стал
        «Trap/Disposable» без единого слова о том, что человек метил в
        gmail.com. Вердикт верный, а след настоящего контакта терялся.

        ВЕРДИКТ НЕ МЕНЯЕТСЯ НИКОГДА. Подмена адреса подсказкой однажды уже
        приводила к тому, что в колонке «Годен» оказывалась строка, которой
        владелец не загружал: отправив по ней, он написал бы ЧУЖОМУ человеку.
        Здесь только два поля рядом с вердиктом — решение за владельцем.

        Лишней сессии почти не стоит: suggest_domain_fix отдаёт подсказку
        только для настоящих опечаток известных почтовиков, а их единицы.
        """
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
            # Не удалось спросить — подсказка остаётся без подтверждения.
            # Это честнее, чем выбросить её целиком: адрес виден владельцу.
            data["suggested_status"] = ""
    def _enrich_offline(self, email, data, status_display, enable_ai):
        """Обогащение для адреса, который до сервера не дойдёт.

        Отсеянные по одноразовому домену выходили из обработки сразу и
        оставались без имени, пола и страны: в таблице у них пустые колонки,
        хотя всё это считается локально по самому адресу и не стоит ни одного
        запроса в сеть. Владелец просил, чтобы каждый адрес проходил все
        применимые критерии, — и этот как раз применим.

        Сеть здесь не задействуется вовсе: Gravatar, возраст домена и живой
        сайт спрашиваются только у Valid, Risky и Role-based, а сюда приходят
        совсем другие статусы. Скор при этом не трогаем — он уже выставлен
        вызывающим кодом и означает «слать нельзя».
        """
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

            # Возвращаем то, что решил вызывающий: у одноразового домена
            # оценка равна нулю по определению, и пересчитывать её незачем.
            data["engagement_score"] = score_before
            data["engagement_grade"] = grade_before
            data["provider_name"] = provider_before
            data["provider_type"] = type_before
            data["domain_type"] = domain_before
        except Exception:
            # Обогащение — дополнение к вердикту, а не условие его выдачи.
            # Упасть здесь значит потерять адрес целиком ради колонки с именем.
            pass
    def _enrich_and_score(self, email, data, res, status_display,
                          original_smtp_status, is_role, enable_ai):
        """Обогащение и скоринг одного адреса.

        Раньше этот код был скопирован дважды — в первый проход и в
        перепроверку — и копии успели разойтись. Теперь он один.
        """
        domain = email.rsplit("@", 1)[1].lower() if "@" in email else ""
        mx_host = res.get("mx_record", "")

        # --- Имя -----------------------------------------------------------
        name = data.get("name", "")
        name_source = "файл" if name else ""
        if not name:
            name = self.name_extractor.extract_name(email) or ""
            if name:
                # ЧЕЙ это разбор, а не «всегда адрес». Границы ставит либо
                # человек (точка, подчёркивание, CamelCase), либо наш
                # сегментатор, либо имя вовсе приходит из публичного
                # профиля. Пока источник был один на три случая, догадка
                # «Kava Morasports» показывалась владельцу как факт.
                # getattr, а не прямой вызов: обогащение целиком обёрнуто
                # в except, и экстрактор без нового метода уронил бы не
                # ярлык, а САМО ИМЯ — молча, на всей базе. Поймано
                # полным прогоном: подставной экстрактор в
                # tests/test_result_cache.py этого метода не знает.
                узнать = getattr(self.name_extractor, "last_name_source", None)
                name_source = (узнать() if callable(узнать) else "") or "адрес"
            if name and enable_ai and not self.ml_predictor.is_person(name):
                name, name_source = "", ""   # NER распознал организацию, не человека

        # --- Страна --------------------------------------------------------
        # Порядок принципиален. Домен знает страну ТОЧНО (web.de — Германия),
        # а распределение имени по странам размазано: Ivan даёт Italy 0.235
        # при Mexico 0.135. Раньше имя стояло выше домена и превращало
        # bogdan.petrov@yandex.ru в итальянца.
        country = data.get("country", "")
        country_source = "файл" if country else ""
        if not country:
            country = country_from_domain(domain)
            if country:
                country_source = "домен"
        if not country:
            # Домен молчит (.com/.net). Профиль Gravatar, если он был получен
            # при разборе имени, знает город и страну точнее любой догадки.
            location = (self.name_extractor.last_profile().get("location") or "").strip()
            if location:
                country = country_from_location(location) or ""
                if country:
                    country_source = "Gravatar"
        if not country and name:
            # Последняя попытка — по имени, и только при явной уверенности
            country = self.ml_predictor.predict_country(name)
            if country:
                country_source = "имя"

        # --- Пол -----------------------------------------------------------
        gender = data.get("gender", "")
        gender_source = "файл" if gender else ""
        if not gender:
            # Страна повышает точность на неоднозначных именах:
            # Andrea в Италии — мужское, в Германии — женское.
            gender = self.ml_predictor.predict_gender(name, country)
            if gender:
                gender_source = "имя"

        birth_year = data.get("birth_year", "") or extract_birth_year(email) or ""

        data["name"] = name
        # Отдельные имя и фамилия: сегментация под рассылку («Здравствуйте,
        # {имя}») и под сверку с внешними базами, где колонки раздельные.
        first_name, last_name = split_name(name)
        data["first_name"] = first_name
        data["last_name"] = last_name
        data["gender"] = gender
        data["country"] = country
        data["birth_year"] = birth_year
        # Откуда взято — чтобы в выгрузке отличать данные из файла от догадки
        data["name_source"] = name_source
        accounts = self.name_extractor.last_profile().get("accounts") or []
        if accounts:
            data["social_accounts"] = ", ".join(accounts[:5])
        data["gender_source"] = gender_source
        data["country_source"] = country_source

        # --- Сигналы живости ------------------------------------------------
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
        has_ptr = None  # None = не проверено, чтобы скоринг не штрафовал вслепую
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

        # WHOIS и HTTP-HEAD стоят до 1.9 с и до 6.8 с на новый домен. Тратить
        # их на адрес, по которому вердикта нет, бессмысленно: эти сигналы
        # дают 3-5 баллов, а балл начисляется только Valid и Risky.
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
            is_disposable=False,  # Уже отсеяны выше
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
            # Парковка могла быть и на втором MX, и на A-записи без MX
            is_parked_domain=is_parked_domain(res.get("mx_records") or mx_host),
        )

        # Уверенность в ВЕРДИКТЕ — не то же самое, что скор живости.
        #
        # Скор отвечает «насколько вероятно, что за адресом живой человек»;
        # уверенность — «насколько твёрдо доказано то, что написано в колонке
        # Статус». Подтверждённый ящик на голом домене и адрес на прекрасном
        # домене, чей вердикт держится на одном неподтверждённом 550, раньше
        # выглядели одинаково. См. core/verdict.py.
        confidence, basis = verdict_confidence(
            original_smtp_status or status_display,
            res.get("reason", ""),
            {"control_probe": res.get("control_rcpt") == "rejected",
             "confirmed": res.get("second_opinion") == "agreed",
             "postmaster_honored": res.get("postmaster_honored")})
        data["verdict_confidence"] = confidence
        data["verdict_basis"] = basis

        data["engagement_score"] = score_result["score"]
        data["engagement_grade"] = score_result["grade"]
        data["provider_type"] = score_result["provider_type"]
        data["has_gravatar"] = has_avatar

        # Подозрение модели: понижает оценку, но не выносит приговор.
        #
        # Раньше на этом месте адрес просто помечался ловушкой и до сервера не
        # доходил. Бессмысленное на вид имя ничего не доказывает: люди заводят
        # почту с цифрами и транслитом, а Gmail на вопрос о таком ящике
        # отвечает честно. Поэтому вердикт оставлен серверу, а мнение модели
        # опущено до того, чем оно и является, — сигнала для сортировки.
        #
        # Доказанный вердикт при этом не трогается: живой ящик остаётся
        # «можно слать», просто встанет в списке ниже честных имён. И
        # доказанный Invalid не поднимается: ниже нуля не опускаем.
        if data.get("ai_suspicious"):
            try:
                score = int(data.get("engagement_score", 0) or 0)
            except (TypeError, ValueError):
                score = 0
            data["engagement_score"] = max(1, score - AI_SUSPICION_PENALTY) if score else score
            data["ai_note"] = "имя выглядит машинным — проверено сервером, вердикт от него"

        # Провайдера уточняем теперь, когда известна MX-запись: по ней видно,
        # сидит ли свой домен на Google Workspace или Microsoft 365.
        prov_name, dom_type = classify_domain(email, mx_host)
        data["provider_name"] = prov_name
        data["domain_type"] = dom_type

        # Компания и должность. Оба поля выводятся из самого адреса и потому
        # являются фактами, а не догадками: корпоративный домен куплен
        # организацией, а `sales@` написано в адресе прямым текстом. Считаем
        # ЗДЕСЬ, потому что нужен domain_type — у бесплатного почтовика
        # компании нет, и колонка обязана остаться пустой, а не сообщать,
        # что человек работает в Gmail.
        data.update(enrich_org_role(email, dom_type))

        # Отпечаток настроек, при которых это обогащение посчитано. По нему
        # следующий прогон решает, годится ли оно как есть.
        data["enrich_sig"] = _enrich_signature(
            getattr(self.name_extractor, "enable_osint", False), enable_ai)

        # В кэш уходит SMTP-статус, а не отображаемый: ролевой ящик
        # показывается как Role-based, но доказан-то он как Valid.
        if self.cache:
            self.cache.put(email, original_smtp_status, res.get("reason", ""),
                           mx_host or "N/A", data)
