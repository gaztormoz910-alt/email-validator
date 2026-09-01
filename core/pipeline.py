# core/pipeline.py
import os
import threading
import time
import json
import datetime
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.bounded import BoundedCache
from core.cache import ResultCache
from core.runstate import RunState, run_id_for, DEFAULT_RETRY_DELAY
from core.cleaner import EmailCleaner, normalize_for_dedup
from core.filters import SpamFilter
from core.github_parser import BlacklistDownloader
from core.network import NetworkValidator, PROXY_MAX_CONSECUTIVE_FAILS
from core.ai_engine import EmailAI
from core.parser.name_extractor import NameExtractor, split_name
from core.parser.ml_predictor import MLPredictor
from core.disposable import is_disposable
from core.gravatar import GravatarChecker
from core.org_role import enrich_org_role
from core.scoring import calculate_engagement_score
from core.provider import (classify_domain, country_from_domain,
                           country_from_location, extend_free_domains,
                           is_free_mail_domain)
from core.heuristics import (extract_birth_year, looks_machine_generated,
                             is_parked_domain, is_role_based)
from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS


# Причины Unknown, которые стоит перепроверить: они говорят о сбое НАШЕЙ стороны
# (прокси, сеть, лимит скорости), а не о ящике. Повтор другим прокси часто
# превращает их в однозначный вердикт.
_TRANSIENT_MARKERS = (
    "timeout", "proxy dead", "server disconnected", "smtp connect error",
    "rate limit", "service busy", "all proxies dead", "temp unavailable",
    "temp error", "our ip blocked", "our ip blacklisted", "transaction failed",
    "mail from rejected", "too many recipients",
    # DNS через прокси не ответил — домен не проверен, а не мёртв. Повтор другим
    # прокси обычно решает.
    "dns не удалось спросить",
)

# Эти Unknown повторять бессмысленно — ответ не изменится от смены прокси
_PERMANENT_UNKNOWN_MARKERS = (
    "catch-all", "catchall", "fcrdns", "обратного dns", "не проверяется",
)


def _is_transient_failure(raw_status: str, reason: str) -> bool:
    """True, если Unknown вызван временным сбоем и заслуживает повтора."""
    if raw_status != "unknown":
        return False
    low = (reason or "").lower()
    if any(m in low for m in _PERMANENT_UNKNOWN_MARKERS):
        return False
    return any(m in low for m in _TRANSIENT_MARKERS)


# Что берётся из кэша, кроме самого вердикта: только добытое ПО СЕТИ и
# только если в файле базы этого поля не было. Всё остальное — имя, пол,
# страна, скор, провайдер — вычислимо локально и пересчитывается на текущих
# настройках, иначе кэш молча отменял бы переключатели в окне.
_CACHE_KEEPS = ("birth_year", "company", "job_role", "social_accounts",
                "company_source", "job_role_source")

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


class _DomainGate:
    """Один вход на домен, который убирает себя за собой.

    Отдельным классом, а не замыканием: пайплайн живёт в сотне потоков, и
    вход/выход обязаны быть симметричны даже когда внутри блока вылетело
    исключение. Контекстный менеджер это гарантирует, ручные acquire/release
    по коду — нет.
    """

    __slots__ = ("_owner", "_key", "_lock")

    def __init__(self, owner, key):
        self._owner = owner
        self._key = key
        self._lock = None

    def __enter__(self):
        owner, key = self._owner, self._key
        with owner._inflight_guard:
            entry = owner._inflight.get(key)
            if entry is None:
                entry = [threading.Lock(), 0]
                owner._inflight[key] = entry
            entry[1] += 1                      # ссылок на замок стало больше
            self._lock = entry[0]
        self._lock.acquire()
        return self._lock

    def __exit__(self, exc_type, exc, tb):
        if self._lock is not None:
            self._lock.release()
            self._lock = None
        owner, key = self._owner, self._key
        with owner._inflight_guard:
            entry = owner._inflight.get(key)
            if entry is not None:
                entry[1] -= 1
                if entry[1] <= 0:
                    owner._inflight.pop(key, None)
        return False


class ValidationPipeline:
    def __init__(self, callbacks):
        self.callbacks = callbacks 
        self.is_running = False
        self.is_paused = False
        # Отдельный флаг «остановку запросили», а не одна лишь is_running.
        #
        # is_running взводится в run_pipeline, то есть УЖЕ ВНУТРИ рабочего
        # потока и после подготовки — а подготовка идёт долго: перебор прокси
        # в триста потоков, прогрев модели, загрузка списков. Нажатый в это
        # время «Стоп» сбрасывал is_running, поток доходил до run_pipeline и
        # спокойно взводил его обратно. Прогон продолжался вопреки команде, а
        # окно оставалось запертым до конца проверки.
        self._stop_requested = False
        # Сколько результатов реально ушло наружу. Нужен для проверки
        # «подано = выдано»: в обработке адреса восемнадцать мест, где
        # исключение проглатывается, и без счёта потеря адреса выглядит как
        # его отсутствие во входе. Владелец видит 78 в счётчике и 77 строк —
        # и не знает, чего именно недосчитался.
        self._emitted = 0
        self._emitted_lock = threading.Lock()

        self.cleaner = EmailCleaner()
        self.filter = None
        self.network = None
        self.ai = None
        self.name_extractor = None
        self.ml_predictor = None
        self.gravatar_checker = GravatarChecker(timeout=3, proxy_provider=self._http_proxies)
        # Кэш доказанных вердиктов между прогонами (см. core/cache.py)
        self.cache = None
        self._cache_hits = 0
        self._cache_lock = threading.Lock()
        # Кэши с потолком, а не словари: ключ — домен, и на базе, собранной
        # дорками, разных доменов столько же, сколько адресов. См. core/bounded.py.
        self._domain_age_cache = BoundedCache()
        self._domain_age_lock = threading.Lock()
        self._http_alive_cache = BoundedCache()
        self._http_alive_lock = threading.Lock()
        # Замки «один в полёте» на домен. Без них сто потоков, наткнувшись на
        # новый домен одновременно, делают сто одинаковых запросов WHOIS —
        # кэш спасает только тех, кто пришёл после первого ответа.
        self._inflight = {}
        self._inflight_guard = threading.Lock()

    def _domain_gate(self, key):
        """Замок на конкретный домен: остальные ждут результата, а не дублируют запрос.

        Замок ОСВОБОЖДАЕТСЯ, когда его отпустил последний ждавший. Раньше
        запись оставалась в словаре навсегда, и это был не кэш, а утечка:
        замки нужны только пока запрос в полёте, а копились они по два на
        каждый домен базы. Замерено вместе с двумя кэшами возраста и сайта —
        468 байт на домен, 2.3 ГБ на пяти миллионах доменов.

        Считаем ссылки, а не удаляем сразу после выхода: пока один поток
        держит замок, второй уже мог взять на него ссылку и ждать. Удалить
        запись под ним значило бы, что третий поток создаст ДРУГОЙ замок на
        тот же домен и оба пойдут делать один и тот же запрос — ровно то, ради
        чего замок и заводился.
        """
        return _DomainGate(self, key)
        
    def _http_proxies(self):
        """Прокси для HTTP-проверок (Gravatar, RDAP, HEAD).

        Возвращает None, если прокси не заданы — тогда идём напрямую, как раньше.
        Если заданы, все HTTP-каналы идут через них: иначе реальный IP утекает
        и на gravatar.com, и в WHOIS, и на сайт самой проверяемой компании.
        """
        try:
            if self.network and self.network.has_proxies_configured():
                from core.network import build_proxy_dict
                proxy = self.network._pick_best_proxy()
                if proxy:
                    return build_proxy_dict(proxy)
        except Exception:
            pass
        return None

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
                name_source = "адрес"
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

    def _start_profile_refresher(self, timeout, workers, interval=600):
        """Фоновое обновление профиля прокси раз в interval секунд."""
        self._refresh_stop = threading.Event()

        def loop():
            while not self._refresh_stop.wait(interval):
                if not self.is_running or not self.network:
                    return
                try:
                    stats = self.network.refresh_proxy_profiles(
                        timeout=timeout, workers=workers)
                except Exception:
                    continue
                if not stats.get("checked"):
                    continue
                if stats["ip_changed"] or stats["ptr_lost"] or stats["ptr_gained"]:
                    self.callbacks['on_log'](
                        f"[PROXY] Профиль обновлён: сменили IP — {stats['ip_changed']}, "
                        f"потеряли PTR — {stats['ptr_lost']}, "
                        f"получили PTR — {stats['ptr_gained']}.", "info")

        self._refresh_thread = threading.Thread(target=loop, daemon=True)
        self._refresh_thread.start()

    def _stop_profile_refresher(self):
        stop = getattr(self, "_refresh_stop", None)
        if stop is not None:
            stop.set()

    def setup(self, timeout=5, enable_ai=False, proxies=None, threads=100, use_cache=True):
        # Гибридный режим: Whitelist + DNS-проверка неизвестных доменов
        self.callbacks['on_log']("[INFO] Подготовка валидатора (гибридный режим: Whitelist + DNS)...", "info")

        # Кэш вердиктов прошлых прогонов. Хранит только доказанное — Valid и
        # Invalid/Bounce; Unknown и Risky не кэшируются никогда, иначе сбой
        # нашей стороны закрепился бы за адресом навсегда.
        self.cache = None
        self._cache_hits = 0
        if use_cache:
            try:
                # Путь из настроек: положив кэш в синхронизируемую папку
                # (OneDrive, сетевой диск), два рабочих места перестают
                # проверять одно и то же по второму разу.
                from core.settings import cache_path
                chosen = cache_path()
                cache = ResultCache(path=chosen)
                if cache.enabled:
                    dropped = cache.purge_expired()
                    self.cache = cache
                    msg = f"[INFO] Кэш вердиктов: {cache.size()} адресов из прошлых прогонов."
                    from core.cache import DEFAULT_CACHE_PATH
                    if chosen != DEFAULT_CACHE_PATH:
                        msg += f" Общий кэш: {chosen}."
                    if dropped:
                        msg += f" Просроченных удалено: {dropped}."
                    self.callbacks['on_log'](msg, "info")
                else:
                    self.callbacks['on_log'](
                        "[DEAD] Кэш вердиктов недоступен (не удалось открыть базу) — "
                        "проверяю всё заново.", "dead")
            except Exception as e:
                self.callbacks['on_log'](
                    f"[DEAD] Кэш вердиктов не включён ({type(e).__name__}).", "dead")
        
        # Обновляем disposable/spam-списки ДО загрузки SpamFilter, чтобы он
        # сразу подхватил свежие данные. Списки переустанавливаются (замена, не
        # накопление), а качаются только если на сервере реально есть новое.
        try:
            self.callbacks['on_log']("[INFO] Проверка обновлений disposable-списков...", "info")
            BlacklistDownloader().download_all(log_callback=self.callbacks['on_log'])
        except Exception as e:
            self.callbacks['on_log'](f"[DEAD] Обновление списков не удалось ({type(e).__name__}), использую локальные.", "dead")

        # Список бесплатных почтовиков. Он НЕ для отбраковки, а для скоринга:
        # без него сотни бесплатных сервисов считаются корпоративными и
        # получают +5, которого не получает gmail.com.
        try:
            free_path = os.path.join("data", "free_providers.txt")
            if os.path.exists(free_path):
                with open(free_path, "r", encoding="utf-8") as f:
                    added = extend_free_domains(line.strip() for line in f
                                                if line.strip() and not line.startswith("#"))
                if added:
                    self.callbacks['on_log'](
                        f"[INFO] Бесплатных почтовиков добавлено: {added}. "
                        "Скоринг больше не путает их с корпоративными.", "info")
        except Exception:
            pass

        # Подключаем SpamFilter из внешних файлов
        try:
            self.filter = SpamFilter(log_callback=self.callbacks.get('on_log'))
            self.callbacks['on_log'](f"[INFO] SpamFilter загружен ({self.filter.get_count() if hasattr(self.filter, 'get_count') else '?'} доменов).", "info")
            # Сливаем свежие списки во встроенную базу: она захардкожена и сама
            # не обновляется, зато умеет проверять ПОДДОМЕНЫ (foo.mailinator.com),
            # чего SpamFilter не делает — он сверяет только точное имя домена.
            try:
                from core.disposable import extend_disposable_domains, get_disposable_count
                added = extend_disposable_domains(self.filter.blacklist_domains)
                if added:
                    self.callbacks['on_log'](
                        f"[INFO] В базу одноразовых добавлено {added} доменов "
                        f"(всего {get_disposable_count()}), поддомены тоже ловятся.", "info")
            except Exception:
                pass
        except Exception:
            self.filter = None
        
        # Высокий таймаут вместе с повторами через прокси даёт огромное время на
        # один адрес: до 10 попыток * таймаут. Ползунок не трогаем (это осознанная
        # настройка), но предупреждаем, иначе прогон выглядит как зависание.
        if timeout > 30:
            self.callbacks['on_log'](
                f"[DEAD] Таймаут {timeout}с очень большой — прогон будет медленным. "
                "Обычно хватает 10-20с. (Зависнуть на одном адресе валидатор не даст: "
                "есть общий дедлайн, максимум 180с на адрес.)", "dead")

        proxy_profiles = {}
        if proxies:
            from core.network import filter_live_proxies, dedupe_proxies_stream
            # Прокси приходят ЛЕНИВО: на входе может быть и список, и генератор
            # из файла в миллионы строк. Длину заранее не спрашиваем — это
            # прочитало бы весь вход в память ради одного числа.
            #
            # Повторы схлопываются по ходу чтения: один прокси, записанный
            # дважды, проверялся бы дважды и занимал два места в ротации.
            proxies = dedupe_proxies_stream(proxies)
            self.callbacks['on_log'](
                f"[INFO] Тестирование прокси-серверов потоком "
                f"(потоков: {threads}, таймаут: {timeout}с)...", "info")
            # Теперь таймаут строго подчиняется твоему ползунку (никаких ограничений!)
            # Прогресс прокси идёт СВОИМ каналом, а не в полосу проверки почт.
            #
            # Раньше он шёл в on_progress — тот самый, которым потом двигается
            # проверка адресов. Владелец видел «Проверено 16 891 из 19 590»
            # рядом с карточками, где всюду нули, и читал это как почты. А
            # считались прокси, и «из» было не итогом, а «сколько прочитано на
            # сейчас»: разница между числами на девяти снимках подряд ровно
            # 2699 — постоянный отрыв читателя от проверяющего.
            proxy_progress = self.callbacks.get('on_proxy_progress')
            # «Хватит живых» — настройка владельца, по умолчанию выключена.
            # См. core/settings.py: на бесплатных списках перебор всего файла
            # съедает больше времени, чем сама проверка почт.
            try:
                from core.settings import get as setting
                enough = int(setting("proxy_enough", 0) or 0)
            except Exception:
                enough = 0

            live_proxies, total_seen = filter_live_proxies(
                proxies, timeout=timeout, threads=threads,
                progress_callback=proxy_progress,
                log_callback=self.callbacks.get('on_log'),
                enough=max(0, enough))
            # Итог перебора говорится числом И смыслом. «Найдено 54 из 26390»
            # само по себе не отвечает на вопрос, который у владельца в
            # голове: «а проверятся ли теперь мои почты».
            share = (100.0 * len(live_proxies) / total_seen) if total_seen else 0.0
            self.callbacks['on_log'](
                "[INFO] Проверка прокси закончена: живых %d из %d (%.1f%%)."
                % (len(live_proxies), total_seen, share), "info")
            if 'on_proxies_tested' in self.callbacks:
                self.callbacks['on_proxies_tested'](len(live_proxies), total_seen)
            if not live_proxies:
                self.callbacks['on_log'](
                    "[DEAD] Ни один прокси не отвечает на порт 25. Проверять "
                    "почту через них нечем: почтовые серверы слушают именно "
                    "этот порт, а 587 и 465 к проверке ящиков отношения не "
                    "имеют. Вердиктов не будет — ни одного. Возьми прокси с "
                    "открытым портом 25 или подними свой VPS "
                    "(tools/make_vps_proxy.py), либо запусти без прокси и "
                    "проверь хотя бы Gmail и Яндекс.", "dead")
            elif len(live_proxies) < 10:
                self.callbacks['on_log'](
                    "[DEAD] Живых прокси всего %d. На большой базе этого мало: "
                    "почтовик считает нагрузку по адресу отправителя, и с "
                    "нескольких IP он быстро начнёт отвечать «слишком часто» "
                    "или принимать любые адреса подряд." % len(live_proxies),
                    "dead")
            proxies = live_proxies

            # Профилируем прокси: реальный выходной IP, обратный DNS, чёрные списки.
            # Выходной IP спрашиваем у самого Gmail (он сообщает его в ответе на
            # EHLO) — стороннего сервиса не нужно. Проверять надо именно ЕГО:
            # адрес подключения к прокси совпадает с выходным не всегда.
            proxy_profiles = {}
            if live_proxies:
                try:
                    from core.network import profile_proxies
                    self.callbacks['on_log'](
                        f"[INFO] Профилирование {len(live_proxies)} прокси "
                        "(выходной IP, PTR, чёрные списки)...", "info")

                    def on_prof(done, total, ptr_n, bl_n):
                        self.callbacks['on_log'](
                            f"[PROXY] Профиль... {done}/{total} | с PTR: {ptr_n} | в списках: {bl_n}", "info")

                    # Профили, снятые в прошлый раз, подставляются сразу.
                    #
                    # Снятие — это выходной IP через EHLO у Gmail, обратный
                    # DNS, семь чёрных списков и три прямые пробы почтовиков
                    # НА КАЖДЫЙ прокси. На пуле в несколько сотен — минуты
                    # простоя перед каждой работой, а выходной адрес за сутки
                    # обычно не меняется. Заново снимаем только тех, кого не
                    # помним; фоновое обновление всё равно идёт раз в десять
                    # минут и поправит то, что успело устареть.
                    remembered = self.network.recall_proxy_profiles(live_proxies)
                    fresh_needed = [p for p in live_proxies if p not in remembered]
                    if remembered:
                        self.callbacks['on_log'](
                            "[PROXY] Из прошлого запуска помню профиль %d прокси "
                            "из %d — заново проверяю только остальных."
                            % (len(remembered), len(live_proxies)), "info")

                    # Потоки берём из ползунка: раньше здесь было жёсткое 30, и
                    # список в несколько тысяч прокси профилировался часами.
                    proxy_profiles = dict(remembered)
                    if fresh_needed:
                        proxy_profiles.update(profile_proxies(
                            fresh_needed, timeout=timeout, workers=threads,
                            progress_callback=on_prof))

                    vals = list(proxy_profiles.values())
                    ptr_n = sum(1 for v in vals if v["has_ptr"] is True)
                    bl_n = sum(1 for v in vals if v["in_dnsbl"])
                    known_ip = sum(1 for v in vals if v["exit_ip"])
                    dirty_n = sum(1 for v in vals if v.get("rdns_dirty"))
                    outlook_n = sum(1 for v in vals if v.get("outlook_ok") is True)
                    clean_n = len(live_proxies) - bl_n

                    lats = sorted(v["latency_ms"] for v in vals if v.get("latency_ms"))
                    if lats:
                        median = lats[len(lats) // 2]
                        self.callbacks['on_log'](
                            f"[INFO] Скорость прокси: медиана {median} мс, "
                            f"быстрейший {lats[0]} мс, медленнейший {lats[-1]} мс.", "info")

                    self.callbacks['on_log'](
                        f"[INFO] Профиль готов: выходной IP определён у {known_ip} из "
                        f"{len(live_proxies)}, с PTR — {ptr_n}, в чёрных списках — {bl_n}.", "info")

                    if outlook_n is not None:
                        self.callbacks['on_log'](
                            f"[INFO] Microsoft реально принял {outlook_n} прокси из "
                            f"{len(live_proxies)} (проверено пробой до MAIL FROM, "
                            "а не по спискам).", "info")
                    if dirty_n:
                        self.callbacks['on_log'](
                            f"[DEAD] У {dirty_n} прокси имя в PTR выдаёт прокси/VPN/динамику "
                            "(proxy, vpn, tor, pool...). Почтовики такие штрафуют даже "
                            "при валидном обратном DNS.", "dead")

                    if ptr_n:
                        self.callbacks['on_log'](
                            f"[INFO] Yahoo/AOL пойдут через {ptr_n} прокси с PTR.", "info")
                    else:
                        self.callbacks['on_log'](
                            "[DEAD] Обратного DNS (PTR) нет ни у одного прокси — Yahoo, AOL "
                            "и Verizon проверить не получится. Остальные домены проверятся.", "dead")

                    if clean_n:
                        self.callbacks['on_log'](
                            f"[INFO] Outlook/iCloud/GMX пойдут через {clean_n} прокси "
                            "с чистой репутацией.", "info")
                    else:
                        self.callbacks['on_log'](
                            "[DEAD] ВСЕ прокси числятся в чёрных списках — Outlook, iCloud "
                            "и GMX будут молчать. Нужны прокси с чистым IP.", "dead")

                    # Структурная сводка для окна. Всё перечисленное выше уже
                    # уходило строками лога, но лог прокручивается и теряется,
                    # а решение «хватит ли этих прокси» пользователь принимает
                    # именно по этим числам. Считает их core/proxy_profile.py,
                    # чтобы панель, лог и CLI не могли разойтись.
                    # Готовность — до прогона, а не после.
                    #
                    # Раньше владелец узнавал, что прокси не годятся, из
                    # сплошного «не доказано» через полчаса работы. Причина
                    # при этом лежала в одной строке профиля, которую никто
                    # не читал. Теперь она произносится вслух и с указанием,
                    # что чинить.
                    try:
                        from core.proxy_profile import readiness_report
                        ready = readiness_report(proxy_profiles)
                        self.callbacks['on_log'](
                            ("[INFO] Готовность прокси: %s" if ready["ready"]
                             else "[DEAD] Готовность прокси: %s") % ready["verdict"],
                            "info" if ready["ready"] else "dead")
                        for item in ready["providers"]:
                            if not item["ok"]:
                                self.callbacks['on_log'](
                                    "[DEAD]    %s — 0 годных прокси: %s"
                                    % (item["name"], item["reason"]), "dead")
                    except Exception:
                        pass

                    if 'on_proxy_profile' in self.callbacks:
                        try:
                            from core.proxy_profile import pool_summary
                            self.callbacks['on_proxy_profile'](pool_summary(proxy_profiles))
                        except Exception:
                            pass
                except Exception as e:
                    self.callbacks['on_log'](
                        f"[DEAD] Профилирование прокси не удалось ({type(e).__name__}).", "dead")

        self.network = NetworkValidator(timeout=timeout, proxies=proxies)

        # Spamhaus ZEN — крупнейший чёрный список, и до сих пор он молчал.
        # Код опроса был написан и покрыт тестами, но включался только в них:
        # в рабочем прогоне резолвер никто не задавал, и зона не спрашивалась
        # вовсе. Причина не в лени, а в самом Spamhaus: публичные резолверы
        # он не обслуживает и отвечает NXDOMAIN даже на обязательную тестовую
        # запись. Нужен свой — на том же VPS, где стоит прокси.
        resolvers = []
        try:
            from core.settings import spamhaus_resolvers
            resolvers = spamhaus_resolvers()
        except Exception:
            resolvers = []

        if resolvers and self.network:
            if self.network.set_spamhaus_resolver(resolvers):
                self.callbacks['on_log'](
                    f"[INFO] Spamhaus ZEN подключён через {', '.join(resolvers)} — "
                    "санитарный контракт зоны пройден.", "info")
            else:
                # Причина называется словами. «Не прошла контракт» не говорит
                # владельцу, что чинить: отказ резолверу и недоступная сеть
                # лечатся по-разному.
                try:
                    why = self.network.spamhaus_refusal_reason()
                except Exception:
                    why = "зона не прошла санитарный контракт"
                self.callbacks['on_log'](
                    "[DEAD] Spamhaus ZEN не опрашивается через %s: %s "
                    "Проверяю без него — это значит, что крупнейший чёрный "
                    "список молчит, и репутация IP оценивается по семи "
                    "остальным зонам." % (", ".join(resolvers), why), "dead")
        elif not resolvers and self.network:
            # Резолвер не задан — не повод молчать. Зона не обслуживает
            # КРУПНЫЕ публичные резолверы, но в системном списке обычно лежит
            # ещё и резолвер провайдера или Quad9, а их она обслуживает.
            #
            # Замерено на машине владельца: 1.1.1.1 отвечает кодом отказа
            # 127.255.255.254, 8.8.8.8 — NXDOMAIN даже на обязательную
            # тестовую запись, а 9.9.9.9 отвечает правильно. То есть
            # крупнейший чёрный список был доступен всё это время — его просто
            # никто не спросил.
            found = None
            try:
                found = self.network.autodetect_spamhaus_resolver()
            except Exception:
                found = None
            if found:
                self.callbacks['on_log'](
                    "[INFO] Spamhaus ZEN подключён сам через системный "
                    "резолвер %s — санитарный контракт зоны пройден." % found,
                    "info")
            else:
                self.callbacks['on_log'](
                    "[DEAD] Spamhaus ZEN не опрашивается: ни один резолвер из "
                    "системных зона не обслуживает. Крупнейший чёрный список "
                    "сейчас не участвует в оценке — репутация IP считается по "
                    "семи остальным зонам. Свой резолвер указывается в "
                    "data/settings.json полем spamhaus_resolvers; проще всего "
                    "поднять его на том же VPS, где стоит прокси.", "dead")

        if proxy_profiles:
            self.network.set_proxy_profiles(proxy_profiles)
            # Профиль протухает: у ротирующегося прокси выходной IP меняется
            # по ходу прогона, и маршрутизация продолжает считать, что PTR
            # на месте. Обновляем в фоне, чтобы не держать воркеры.
            self._start_profile_refresher(timeout=timeout, workers=threads)
        
        if enable_ai:
            self.callbacks['on_log']("[INFO] Прогрев и обучение Нейросети (TensorFlow + NaiveBayes)...", "info")
            self.ai = EmailAI()
            self.ai.train_models()
            self.callbacks['on_log']("[INFO] ИИ успешно обучен и готов к бою!", "info")

    def _emit(self, email, status, reason, mx, data):
        """Единственная дверь наружу для результата.

        Отдельным методом, потому что считать надо в ОДНОМ месте: результат
        отправляется из семи разных веток, и счётчик, размазанный по ним,
        разойдётся с действительностью на первой же правке.
        """
        with self._emitted_lock:
            self._emitted += 1
        self.callbacks['on_result'](email, status, reason, mx, data)

    def run_pipeline(self, email_sources, threads=50, fix_typos=True, check_spam=True, deep_ping=True, enable_ai=False, enable_osint=False,
                     resume=False):
        # Пока шла подготовка, могли нажать «Стоп». Тогда работу не начинаем
        # вовсе: взвести is_running здесь значило бы отменить команду.
        if self._stop_requested:
            self.is_running = False
            self.callbacks['on_complete']()
            return

        # Признак уже взведён в start(), синхронно. Здесь он подтверждается на
        # случай прямого вызова run_pipeline в обход start (так делают тесты).
        self.is_running = True
        self.is_paused = False
        with self._emitted_lock:
            self._emitted = 0
        
        from core.streamer import StreamLoader
        # Стартовая ОЦЕНКА по размеру файла, а не точный подсчёт.
        #
        # Раньше здесь стоял count_total_lines(), то есть полный проход по
        # файлу ДО первого проверенного адреса. На базе в сотни мегабайт это
        # минуты, в течение которых не происходит ничего видимого: окно
        # показывает 0/0, лог молчит, и прогон выглядит зависшим ещё до
        # старта. Точность здесь не нужна вовсе — настоящее число уникальных
        # адресов знает только фидер (дедуп ленивый), и он уточняет знаменатель
        # ниже, когда доберётся до конца входа.
        total_emails = StreamLoader(email_sources).estimate_total_lines()
        self.callbacks['on_log'](
            f"[INFO] Запуск обработки — во входе примерно {total_emails} строк. "
            "Точное число уникальных адресов появится по ходу.", "info")

        if 'on_unique_count' in self.callbacks:
            self.callbacks['on_unique_count'](total_emails) # Approximate since dedup is lazy

        self.callbacks['on_progress'](0, total_emails)
        processed_count = 0
        feeder_finished = False

        def refine_total():
            """Уточняет знаменатель точным счётом, пока идёт проверка.

            Оценка по трём пробам ошибается на реальных файлах на два десятка
            процентов — измерено на списке в 712 МБ. Точный счёт при этом
            занимает доли секунды (читаем кусками и считаем переводы строк),
            но эти доли секунды нельзя тратить ДО старта: на холодном диске
            гигабайтный файл читается заметно дольше, и всё это время окно
            выглядит зависшим. Поэтому счёт идёт параллельно работе.

            Если фидер к этому моменту уже дошёл до конца входа, его число
            точнее нашего — оно про уникальные адреса, а не про сырые строки,
            и перебивать его нельзя.
            """
            nonlocal total_emails
            try:
                exact = StreamLoader(email_sources).count_total_lines()
            except Exception:
                return
            if feeder_finished or not exact or not self.is_running:
                return
            total_emails = exact
            try:
                if 'on_unique_count' in self.callbacks:
                    self.callbacks['on_unique_count'](exact)
                self.callbacks['on_progress'](processed_count, exact)
            except Exception:
                pass

        threading.Thread(target=refine_total, daemon=True).start()
        
        # Очередь для Greylisting retry (п.2.4).
        #
        # Теперь у каждой записи есть СРОК готовности. Раньше очередь была
        # обычным мешком, а пайплайн после основного прохода спал ровно 90
        # секунд подряд — и всё это время не делал ничего. Срок ставится в
        # момент откладывания, поэтому к концу основного прохода бОльшая часть
        # адресов уже созрела и ждать не нужно вовсе.
        import queue as queue_module
        # queue.Queue уже потокобезопасна — отдельный лок не нужен
        greylisted_queue = queue_module.Queue()

        def defer(email, data, is_role, delay=DEFAULT_RETRY_DELAY):
            greylisted_queue.put((email, data, is_role,
                                  time.monotonic() + max(0.0, float(delay))))

        # Статистика вердиктов по домену. Если у домена МНОГО адресов и ВСЕ до
        # единого ответили 250 OK — это почти наверняка catch-all, даже когда
        # тройная проба сказала обратное (она могла сорваться на прокси).
        # Тройная проба смотрит 3 выдуманных адреса, а здесь мы видим реальную
        # выборку из самой базы — сигнал сильнее.
        # Статистика по доменам — с потолком, а не голым словарём.
        #
        # Нужна она ровно для одного: найти домены, где ВСЕ адреса ответили
        # «годен», то есть заподозрить catch-all. Для этого важны домены, где
        # адресов много; домен с одним адресом не скажет ничего.
        #
        # А растёт словарь вместе с числом РАЗНЫХ доменов, и на базе, собранной
        # дорками, их столько же, сколько адресов. Замерено: миллион разных
        # доменов — 260 МБ, которые лежат мёртвым грузом до конца прогона.
        # Потолок вытесняет давно не встречавшиеся: у частого домена запись
        # обновляется на каждом адресе и не вытесняется никогда.
        domain_stats = BoundedCache(max_keys=100_000)
        domain_stats_lock = threading.Lock()
        
        # Предзагрузка тяжелых модулей один раз (O(1) вместо O(N) в потоках)
        if not self.name_extractor:
            self.callbacks['on_log']("[INFO] Загрузка модуля извлечения имен...", "info")
            self.name_extractor = NameExtractor(enable_osint=enable_osint,
                                                proxy_provider=self._http_proxies)
        if not self.ml_predictor:
            self.callbacks['on_log']("[INFO] Загрузка предиктора пола/страны...", "info")
            self.ml_predictor = MLPredictor(enable_ml=enable_ai)

        # Предупреждаем один раз, когда прокси закончились посреди прогона
        proxies_dead_warned = threading.Event()

        def warn_if_proxies_dead():
            if (self.network and self.network.all_proxies_dead()
                    and not proxies_dead_warned.is_set()):
                proxies_dead_warned.set()
                self.callbacks['on_log'](
                    "[DEAD] Все прокси выбыли из ротации (каждый сдох "
                    f"{PROXY_MAX_CONSECUTIVE_FAILS} раза подряд). Прямое соединение НЕ используется, "
                    "чтобы не раскрыть твой реальный IP. Загрузи свежие прокси и запусти заново.",
                    "dead")

        def process_single(item):
            if not self.is_running:
                return
            while self.is_paused:
                time.sleep(0.5)

            email, data = item

            # Дата последней валидации (п.30 чек-листа). Ставим в начале, чтобы она
            # попала ВО ВСЕ результаты, включая ранние выходы ниже. Без неё нельзя
            # понять, когда адрес проверяли, и решить, пора ли перепроверять (п.21, п.43).
            data["validated_at"] = _utc_now().strftime("%Y-%m-%d %H:%M")

            # Классификация провайдера и типа домена (п.34, п.35, п.38)
            prov_name, dom_type = classify_domain(email)
            data["provider_name"] = prov_name
            data["domain_type"] = dom_type

            # Шаг 1.1: Проверка на одноразовый/временный домен (Disposable + SpamFilter)
            if is_disposable(email):
                data["engagement_score"] = 0
                data["engagement_grade"] = "Dead"
                data["provider_type"] = "Disposable"
                data["provider_name"] = "Disposable"
                data["domain_type"] = "Disposable"
                self._enrich_offline(email, data, "Trap/Disposable", enable_ai)
                self._emit(email, "Trap/Disposable", "Disposable Email Domain", "N/A", data)
                return

            # Шаг 1.1b: Дополнительная проверка через SpamFilter (внешние чёрные списки)
            if self.filter and hasattr(self.filter, 'is_spam_or_disposable'):
                if self.filter.is_spam_or_disposable(email):
                    data["engagement_score"] = 0
                    data["engagement_grade"] = "Dead"
                    # Не «ловушка»: это совпадение с внешним списком одноразовых
                    # доменов. Настоящих списков спам-ловушек в открытом доступе
                    # нет — опубликованная ловушка перестаёт работать.
                    data["provider_type"] = "Disposable (внешний список)"
                    data["provider_name"] = "Disposable"
                    data["domain_type"] = "Disposable"
                    self._enrich_offline(email, data, "Trap/Disposable", enable_ai)
                    self._emit(email, "Trap/Disposable", "External Blacklist Match", "N/A", data)
                    return

            # Шаг 1.2: Проверка на ролевые ящики (Role-based) — п.2.1
            # НЕ убиваем их! Помечаем как отдельную категорию "Role-based".
            # Общая функция ловит не только точные совпадения (info@), но и
            # sales-team@, info.desk@, noreply2@, do-not-reply@, mailer-daemon@
            is_role = is_role_based(email)

            # Шаг 1.5: подозрение ИИ. ИМЕННО ПОДОЗРЕНИЕ, А НЕ ВЕРДИКТ.
            #
            # Раньше отсюда уходил готовый ответ «Trap/Disposable», и адрес не
            # доходил до сервера вовсе. Так был похоронен, например,
            # mkstring1104@gmail.com: имя показалось модели бессмысленным — и
            # всё, живой ящик на gmail помечен ловушкой без единого запроса.
            #
            # Бессмысленное на вид имя ничего не доказывает. Люди заводят
            # почту с цифрами, аббревиатурами и транслитом, а у Gmail есть
            # ровно один способ узнать правду — спросить сервер, и он на
            # такие вопросы отвечает честно. Модель обучена на строках, а не
            # на ответах почтовиков; её мнение годится для сортировки, но не
            # для приговора.
            #
            # Теперь подозрение живёт в данных: понижает скор и попадает в
            # причину, а вердикт по-прежнему ставит SMTP.
            if enable_ai and self.ai:
                if self.ai.predict(email):
                    data["ai_suspicious"] = True
                    data["provider_type"] = "Suspicious"
                
            # Шаг 2: Кэш прошлых прогонов. Доказанный вердикт SMTP от перезапуска
            # не меняется, поэтому тратить на него прокси и время незачем.
            # В кэше лежат только Valid и Invalid/Bounce — см. core/cache.py.
            if deep_ping and self.cache:
                cached = self.cache.get(email)
                if cached:
                    # Из кэша берётся ТОЛЬКО вердикт SMTP и то, что добыто по
                    # сети: он для этого и заведён. Обогащение — имя, пол,
                    # страна, скор — пересчитывается заново, на текущих
                    # настройках.
                    #
                    # Раньше кэш возвращал и обогащение тоже, и это молча
                    # отменяло настройки окна. Владелец переключал «Страну по
                    # имени» между заполненностью и точностью и видел ОДИН И
                    # ТОТ ЖЕ результат: на свежих адресах режимы дают 11 из 12
                    # против 5 из 12, но 72 адреса из 78 приходили из кэша со
                    # страной, посчитанной в прошлый раз. То же самое было с
                    # тумблером обогащения: включай не включай — у
                    # закэшированных адресов имя оставалось старым.
                    #
                    # Пересчёт бесплатен: имя, пол и страна считаются локально.
                    # По сети ходит только Gravatar, и только когда обогащение
                    # включено — то есть ровно тогда, когда владелец об этом
                    # попросил.
                    cached_data = cached.get("data") or {}
                    # Показываем ДАТУ ИСХОДНОЙ проверки, а не сегодняшнюю:
                    # иначе кэш выглядел бы как свежая проверка.
                    cached_stamp = _fmt_stamp(cached["checked_at"]) or data["validated_at"]
                    data["from_cache"] = True
                    status_display = "Role-based" if is_role else cached["status"]

                    want = _enrich_signature(enable_osint, enable_ai)
                    if cached_data.get("enrich_sig") == want:
                        # Настройки те же — обогащение из прошлого прогона
                        # годится как есть. Ни одного запроса в сеть.
                        # Данные из ФАЙЛА базы важнее кэша: их не трогаем.
                        computed = ("engagement_score", "engagement_grade",
                                    "provider_type", "provider_name",
                                    "domain_type", "has_gravatar")
                        for key, value in cached_data.items():
                            if key in computed or not data.get(key):
                                data[key] = value
                    else:
                        # Владелец сменил настройку обогащения. Считаем заново
                        # — за это и платим сетью, но только здесь.
                        for key, value in cached_data.items():
                            if key in _CACHE_KEEPS and not data.get(key):
                                data[key] = value
                        cached_res = {
                            "status": cached["status"],
                            "reason": cached.get("reason", ""),
                            "mx_record": cached.get("mx", "N/A"),
                            "mx_records": [cached.get("mx")] if cached.get("mx") else [],
                            "has_starttls": None,
                        }
                        # В скоринг идёт ДОКАЗАННЫЙ статус, а не отображаемый.
                        # Ролевой ящик показывается как Role-based, но доказан
                        # он как Valid, и по «Role-based» SMTP-баллы не
                        # начисляются вовсе — скор обнулялся.
                        self._enrich_and_score(email, data, cached_res,
                                               status_display, cached["status"],
                                               is_role, enable_ai)
                        data["enrich_sig"] = want
                    data["validated_at"] = cached_stamp

                    with self._cache_lock:
                        self._cache_hits += 1
                    self._emit(
                        email, status_display,
                        f"{cached['reason']} [из кэша, {cached['age_days']} дн. назад]",
                        cached["mx"], data)
                    state.mark_done(normalize_for_dedup(email))
                    return

            # Шаг 3: Глубокий SMTP Ping
            if deep_ping:
                res = self.network.check_email(email)
                raw_status = res["status"]
                warn_if_proxies_dead()

                # Greylisted — складываем в очередь для повторной проверки (п.2.4)
                if raw_status == "greylisted":
                    defer(email, data, is_role)
                    return False  # Вердикта нет: адрес ждёт перепроверки

                # Временный отказ (таймаут, сдохший прокси, лимит скорости, блок по
                # IP) — это НЕ вердикт о ящике, а сбой нашей стороны. Отправляем в ту
                # же очередь: через паузу лимиты отпускают, прокси восстанавливаются,
                # и повтор другим прокси часто даёт однозначный ответ вместо Unknown.
                if _is_transient_failure(raw_status, res.get("reason", "")):
                    defer(email, data, is_role)
                    return False   # вердикта нет, прогресс не двигаем

                if raw_status == "valid":
                    status_display = "Valid"
                elif raw_status == "catchall":
                    status_display = "Unknown"  # Catch-All — нельзя доверять, кладём в Unknown
                elif raw_status == "risky":
                    status_display = "Risky"
                elif raw_status == "unknown":
                    status_display = "Unknown"
                else:
                    status_display = "Invalid/Bounce"
                
                # Копим статистику по домену для пост-анализа catch-all
                try:
                    dom_key = email.rsplit("@", 1)[1].lower()
                    with domain_stats_lock:
                        st = domain_stats.setdefault(dom_key, {"total": 0, "valid": 0})
                        st["total"] += 1
                        if raw_status == "valid":
                            st["valid"] += 1
                except Exception:
                    pass

                # Сохраняем оригинальный SMTP-статус для скоринга (фикс бага Role-based)
                original_smtp_status = status_display
                
                # Если Role-based — перезаписываем отображаемый статус
                if is_role:
                    status_display = "Role-based"
                
                self._enrich_and_score(email, data, res, status_display,
                                       original_smtp_status, is_role, enable_ai)

                self._emit(email, status_display, res["reason"], res.get("mx_record", "N/A"), data)
                # Журнал сделанного: при возобновлении этот адрес пропустится
                state.mark_done(normalize_for_dedup(email))
            else:
                self._emit(email, "Unverified", "Skipped Ping", "N/A", data)

        # Аппаратное ограничение количества потоков для предотвращения зависания сети и роутера
        safe_threads = min(int(threads), 300)
        
        import queue
        task_queue = queue.Queue(maxsize=safe_threads * 2)

        # Состояние прогона на диске: дедуп и журнал сделанного.
        #
        # Раньше здесь стоял обычный set. Он рос линейно по базе, и на файлах,
        # ради которых затевалось потоковое чтение, в память уже не помещался:
        # файл читался порциями, а рядом копилось множество на сотню миллионов
        # строк. Плюс журнал даёт возобновление — «Стоп» больше не выбрасывает
        # проделанную работу.
        state = RunState(run_id_for(email_sources), resume=resume)
        self.state = state
        if resume and state.resumed_count:
            self.callbacks['on_log'](
                f"[INFO] Продолжаю прерванный прогон: {state.resumed_count} адресов "
                "уже проверены и заново проверяться не будут.", "info")
        elif not state.enabled:
            self.callbacks['on_log'](
                "[DEAD] Состояние прогона недоступно (не открылась база) — дедуп "
                "и возобновление отключены, проверка идёт как раньше.", "dead")

        duplicates_skipped = 0
        already_done = 0
        queued_count = 0

        def feeder_thread():
            nonlocal duplicates_skipped, queued_count, already_done
            from core.streamer import StreamLoader
            for email, data in StreamLoader(email_sources).stream_emails():
                if not self.is_running:
                    break

                if fix_typos:
                    email = self.cleaner.clean_email(email)

                if not email:
                    continue

                # Дедуп по КАНОНИЧЕСКОМУ виду: john.doe@gmail.com и johndoe@gmail.com —
                # один и тот же ящик, и слать туда дважды нельзя (жалобы на спам).
                # В обработку при этом уходит оригинальный адрес.
                dedup_key = normalize_for_dedup(email)
                if not state.add_if_new(dedup_key):
                    duplicates_skipped += 1
                    continue

                # Продолжение прерванного прогона: адрес с вердиктом пропускаем
                if resume and state.is_done(dedup_key):
                    already_done += 1
                    continue

                queued_count += 1
                task_queue.put((email, data))
                
            for _ in range(safe_threads):
                task_queue.put(None)

            # Уточняем знаменатель прогресса: в очередь попали только уникальные
            # адреса, а стартовая оценка считалась по сырым строкам. Без этого
            # бар застревает (например на 5/17) и выглядит как зависание.
            nonlocal total_emails, feeder_finished
            # Флаг ставится ДО присвоения: фоновый уточнитель проверяет именно
            # его, и порядок «сначала флаг, потом число» гарантирует, что он
            # не перезапишет наше число своим, менее точным.
            feeder_finished = True
            total_emails = queued_count
            if 'on_unique_count' in self.callbacks:
                self.callbacks['on_unique_count'](queued_count)

            if already_done:
                self.callbacks['on_log'](
                    f"[INFO] Пропущено как уже проверенное: {already_done} адресов.", "info")

            if duplicates_skipped:
                self.callbacks['on_log'](
                    f"[INFO] Схлопнуто дублей: {duplicates_skipped} "
                    "(один ящик записан по-разному — двойная отправка предотвращена). "
                    f"К проверке: {queued_count}.", "info")

        t_feeder = threading.Thread(target=feeder_thread, daemon=True)
        t_feeder.start()
        
        progress_lock = threading.Lock()
        
        def worker_loop():
            nonlocal processed_count
            while self.is_running:
                item = task_queue.get()
                if item is None:
                    break
                deferred = False
                try:
                    # False означает «адрес отложен на перепроверку»: вердикта
                    # по нему ещё нет, и считать его пройденным нельзя.
                    deferred = process_single(item) is False
                except Exception as e:
                    # Without this the whole worker thread would die and silently
                    # drop every remaining email it was going to handle.
                    email = item[0] if item else "?"
                    self.callbacks['on_log'](f"[DEAD] Ошибка обработки {email}: {type(e).__name__}: {e}", "dead")
                    try:
                        self._emit(email, "Unknown", f"Processing error: {type(e).__name__}", "N/A", item[1])
                    except Exception:
                        pass
                # Прогресс двигают только ОКОНЧАТЕЛЬНЫЕ вердикты.
                #
                # Раньше счётчик рос и для отложенных адресов, поэтому бар
                # доходил до 100% ещё до начала перепроверки — а потом в
                # терминале продолжали появляться результаты. Выглядело как
                # сломанный прогресс, и по сути им и было: показывалось
                # «сколько адресов вынуто из очереди», а не «сколько
                # проверено».
                if not deferred:
                    with progress_lock:
                        processed_count += 1
                        current = processed_count
                    self.callbacks['on_progress'](current, total_emails)

        worker_threads = []
        for _ in range(safe_threads):
            wt = threading.Thread(target=worker_loop, daemon=True)
            wt.start()
            worker_threads.append(wt)
            
        for wt in worker_threads:
            wt.join()
        
        # === Повторная проверка: greylisted + временные отказы (п.2.4) ===
        # Сюда попадают адреса, по которым НЕТ вердикта о ящике: сервер попросил
        # прийти позже (greylisting) либо сбой был на нашей стороне (таймаут,
        # прокси, лимит скорости). Пауза даёт лимитам отпустить, а повтор идёт
        # другим прокси — значительная часть превращается в однозначный ответ.
        greylisted_count = greylisted_queue.qsize()
        if greylisted_count > 0 and self.is_running and deep_ping:
            
            if self.is_running:
                retry_count = 0
                retry_lock = threading.Lock()

                def retry_one(entry):
                    """Обрабатывает один отложенный адрес. Вызывается из пула потоков."""
                    nonlocal retry_count, processed_count
                    email, data, is_role, _due = entry
                    if not self.is_running:
                        return

                    res = self.network.check_email(email)
                    raw_status = res["status"]
                    
                    if raw_status == "valid":
                        status_display = "Valid"
                    elif raw_status == "greylisted":
                        status_display = "Risky"  # Второй раз greylisted — помечаем как Risky
                    elif raw_status == "risky":
                        status_display = "Risky"
                    elif raw_status == "catchall":
                        status_display = "Unknown"
                    elif raw_status == "unknown":
                        status_display = "Unknown"
                    else:
                        status_display = "Invalid/Bounce"
                    
                    # Сохраняем оригинальный SMTP-статус для скоринга (фикс бага Role-based)
                    original_smtp_status = status_display
                    
                    if is_role:
                        status_display = "Role-based"
                    
                    self._enrich_and_score(email, data, res, status_display,
                                           original_smtp_status, is_role, enable_ai)

                    self._emit(email, status_display, res["reason"], res.get("mx_record", "N/A"), data)
                    state.mark_done(normalize_for_dedup(email))
                    with retry_lock:
                        retry_count += 1
                    # Вердикт получен — вот теперь адрес пройден. Прогресс
                    # доходит до 100% в КОНЦЕ работы, а не до перепроверки.
                    with progress_lock:
                        processed_count += 1
                        current = processed_count
                    self.callbacks['on_progress'](current, total_emails)

                # Забираем всё из очереди и обрабатываем ПАРАЛЛЕЛЬНО, но не раньше
                # срока каждой записи.
                #
                # Раньше здесь стояло `time.sleep(1)` девяносто раз подряд — глухая
                # пауза после ВСЕГО основного прохода, во время которой не делалось
                # ничего и не работала даже кнопка «Стоп». Теперь срок ставится в
                # момент откладывания: пока шёл основной проход, он у большинства
                # адресов уже истёк, и ждать нечего. Если ждать всё же приходится,
                # сон идёт короткими шагами, поэтому остановка срабатывает сразу.
                pending = []
                while True:
                    try:
                        pending.append(greylisted_queue.get_nowait())
                    except Exception:
                        break

                pending.sort(key=lambda entry: entry[3])
                total_pending = len(pending)
                retry_workers = max(1, min(safe_threads, total_pending or 1))
                waited = 0.0

                with ThreadPoolExecutor(max_workers=retry_workers) as retry_pool:
                    futures = []
                    index = 0
                    announced = False
                    while index < total_pending and self.is_running:
                        now = time.monotonic()
                        # Всё, что уже созрело, отправляем в пул немедленно
                        launched = 0
                        while index < total_pending and pending[index][3] <= now:
                            futures.append(retry_pool.submit(retry_one, pending[index]))
                            index += 1
                            launched += 1
                        if launched and not announced:
                            announced = True
                            self.callbacks['on_log'](
                                f"[INFO] Перепроверка началась: {launched} из "
                                f"{total_pending} адресов созрели сразу, ждать не пришлось.",
                                "info")
                        if index >= total_pending:
                            break
                        # Ничего не созрело — ждём ровно до ближайшего срока,
                        # но шагами по четверти секунды, чтобы «Стоп» был мгновенным
                        remaining = pending[index][3] - time.monotonic()
                        if remaining > 0:
                            if not announced and waited == 0.0:
                                self.callbacks['on_log'](
                                    f"[INFO] Отложено на перепроверку: {total_pending}. "
                                    f"Ближайший созреет через {int(remaining)}с — ждём только его.",
                                    "info")
                            step = min(0.25, remaining)
                            time.sleep(step)
                            waited += step

                    for fut in as_completed(futures):
                        try:
                            fut.result()
                        except Exception as e:
                            self.callbacks['on_log'](
                                f"[DEAD] Ошибка перепроверки: {type(e).__name__}: {e}", "dead")

                    # Не дождавшиеся своего срока (нажали «Стоп») возвращаются
                    # в очередь — ниже их подберёт страховка и отдаст как Unknown
                    for leftover_entry in pending[index:]:
                        greylisted_queue.put(leftover_entry)

                self.callbacks['on_log'](
                    f"[INFO] Перепроверка завершена: {retry_count} из {total_pending} адресов "
                    f"получили окончательный вердикт. Простой в ожидании: {waited:.1f}с "
                    "(раньше было ровно 90с всегда).", "info")

        # Страховка: всё, что осталось в очереди — не перепроверено (нажали «Стоп»,
        # выключен deep_ping, или прогон прервался). Раньше такие адреса молча
        # исчезали: в выдачу они не попадали ни на первом проходе, ни на втором,
        # а прогресс-бар уже считал их обработанными. Отдаём их как Unknown.
        leftover = 0
        while True:
            try:
                email, data, is_role, _due = greylisted_queue.get_nowait()
            except Exception:
                break
            leftover += 1
            data["validated_at"] = _utc_now().strftime("%Y-%m-%d %H:%M")
            try:
                self._emit(
                    email, "Unknown", "Greylisted (перепроверка не выполнена)", "N/A", data)
            except Exception:
                pass
            # Вердикт выдан (пусть и Unknown) — адрес пройден, бар двигаем.
            with progress_lock:
                processed_count += 1
                current = processed_count
            self.callbacks['on_progress'](current, total_emails)
        if leftover:
            self.callbacks['on_log'](
                f"[INFO] {leftover} greylisted-адресов возвращены как Unknown "
                "(перепроверка не выполнена) — потеряться они не могут.", "info")

        # Тарпитинг: крупный почтовик поймал нас на переборе и начал принимать
        # любые адреса. Это не свойство базы, а состояние НАШЕГО адреса, и
        # сказать об этом надо отдельно от прочих подозрений — иначе владелец
        # пойдёт чистить базу вместо того, чтобы менять прокси.
        try:
            trapped = self.network.tarpit_domains() if self.network else []
        except Exception:
            trapped = []
        if trapped:
            self.callbacks['on_log'](
                "[DEAD] ВНИМАНИЕ: %s перестал отвечать честно — принимает любые "
                "адреса, защищаясь от перебора с нашего IP. Все «Годен» по этим "
                "доменам в этом прогоне НЕДОКАЗУЕМЫ. Нужен чистый прокси, база "
                "тут ни при чём." % ", ".join(trapped), "dead")

        # Пост-анализ: домены, где ВСЕ адреса ответили 250 OK, почти наверняка
        # catch-all — они принимают что угодно, и их Valid ничего не доказывает.
        # Тройная проба смотрит 3 выдуманных адреса и могла сорваться; здесь же
        # выборка из реальной базы, поэтому сигнал надёжнее.
        try:
            suspicious = []
            with domain_stats_lock:
                for dom, st in domain_stats.items():
                    if st["total"] >= 5 and st["valid"] == st["total"]:
                        suspicious.append((dom, st["total"]))
            if suspicious:
                suspicious.sort(key=lambda x: -x[1])
                self.callbacks['on_log'](
                    "[DEAD] Подозрение на catch-all: у этих доменов ВСЕ проверенные "
                    "адреса ответили 250 OK. Их Valid не доказывает существование "
                    "ящика — сегментируйте отдельно:", "dead")
                for dom, cnt in suspicious[:15]:
                    self.callbacks['on_log'](f"[DEAD]    {dom} — {cnt} из {cnt} valid", "dead")
        except Exception:
            pass

        self._stop_profile_refresher()

        if self.cache:
            with self._cache_lock:
                hits = self._cache_hits
            if hits:
                self.callbacks['on_log'](
                    f"[INFO] Из кэша взято {hits} вердиктов — эти адреса заново "
                    "не проверялись. Дата в колонке «Проверено» у них исходная.", "info")
            self.cache.close()
            self.cache = None

        # Состояние дописывается на диск: недописанная пачка иначе потерялась бы,
        # и возобновление не увидело бы последние сотни адресов.
        try:
            state.close()
        except Exception:
            pass

        # Инвариант: сколько адресов приняли в работу, столько результатов и
        # выдали. Расхождение означает, что адрес потерялся молча — сбой внутри
        # обработки, проглоченный одним из except. Раньше такое было видно
        # только внимательному глазу: счётчик показывал одно, таблица другое.
        with self._emitted_lock:
            emitted = self._emitted
        expected = total_emails if isinstance(total_emails, int) else 0
        if expected and emitted != expected:
            lost = expected - emitted
            if lost > 0:
                self.callbacks['on_log'](
                    f"[DEAD] ПОТЕРЯНО АДРЕСОВ: {lost}. Принято в работу "
                    f"{expected}, показано {emitted}. Это сбой внутри обработки, "
                    "а не свойство базы — сообщите о нём.", "dead")
            else:
                self.callbacks['on_log'](
                    f"[DEAD] Результатов больше, чем адресов: показано {emitted} "
                    f"при {expected} принятых. Возможен двойной показ.", "dead")
        elif expected:
            self.callbacks['on_log'](
                f"[INFO] Сверка: принято {expected}, показано {emitted} — сходится.",
                "info")

        self.is_running = False
        self.callbacks['on_complete']()

    def start(self, email_sources, threads, timeout, fix_typos, check_spam, deep_ping, enable_ai, proxies=None, enable_osint=False, use_cache=True,
              resume=False):
        # Новый прогон отменяет прошлую команду остановки.
        self._stop_requested = False

        # Признак взводится ЗДЕСЬ, синхронно, до создания потока.
        #
        # Раньше он взводился внутри рабочего потока и уже после подготовки, а
        # подготовка идёт десятки секунд: перебор трёхсот прокси по десять
        # секунд таймаута, обучение модели, загрузка списков. Всё это время
        # окно считало, что прогон не идёт, и второе нажатие «Начать проверку»
        # запускало ВТОРОЙ конвейер поверх первого. Оба писали в одно
        # хранилище, и каждый адрес попадал в выдачу дважды: у владельца из 78
        # адресов вышло 156 строк, а счётчики удвоились ровно вдвое.
        self.is_running = True
        self.is_paused = False

        def worker():
            try:
                self.setup(timeout=timeout, enable_ai=enable_ai, proxies=proxies, threads=threads,
                           use_cache=use_cache)
                self.run_pipeline(email_sources, threads, fix_typos, check_spam, deep_ping,
                                  enable_ai, enable_osint=enable_osint, resume=resume)
            except Exception as exc:
                # Упавший поток раньше уносил с собой признак «идёт прогон»:
                # is_running оставался взведённым навсегда, и окно запиралось
                # намертво — помогал только перезапуск программы. Теперь
                # падение видно в логе, а окно освобождается.
                self.callbacks['on_log'](
                    "[DEAD] Проверка прервана ошибкой: %s: %s"
                    % (type(exc).__name__, exc), "dead")
            finally:
                if self.is_running:
                    self.is_running = False
                    self.callbacks['on_complete']()

        t = threading.Thread(target=worker, daemon=True)
        t.start()
        return t
        
    def stop(self):
        self._stop_requested = True
        self.is_running = False
        # Остановка снимает и паузу: иначе остановленный на паузе прогон
        # остаётся «на паузе» навсегда, и следующий запуск стартует замершим.
        self.is_paused = False
        
    def pause(self):
        self.is_paused = not self.is_paused
        return self.is_paused
