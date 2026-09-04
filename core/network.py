# core/network.py
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

# Таблицы поведения почтовиков — в core/mail_constants.py: ими пользуются и
# SMTP-диалог, и профилирование прокси, и проверки по DNS, и скоринг.
from core.mxguard import filter_mx_hosts, resolves_to_private, REASON_PRIVATE
from core.mail_constants import (                                 # noqa: E402,F401
    YAHOO_DOMAINS, AOL_DOMAINS, NEEDS_CLEAN_IP_DOMAINS, NICHE_FREE_DOMAINS,
    MICROSOFT_DOMAINS, LEGIT_HELO_NAMES, DNSBL_ZONES, SPAMHAUS_ZONE,
    SPAMHAUS_SANITY_LISTED, SPAMHAUS_SANITY_CLEAN,
    PROXY_MAX_CONSECUTIVE_FAILS, MAIL_FROM_POOL, mail_from_for,
    _dkim_selectors_for,
    SECURITY_GATEWAY_MX, _DKIM_BY_MX, _DKIM_FALLBACK,
)

# Синтаксис адреса и IDN живут в core/email_syntax.py: это единственный
# вердикт, который ставится без обращения к сети, и разбирать его вместе с
# сетевым клиентом значило прятать самое тихое место проверки в самом шумном.
from core.email_syntax import (
    has_quoted_local,                                   # noqa: E402,F401
    domain_literal_ip,
    to_ascii_domain, has_non_ascii_local, validate_email_syntax,
    MAX_EMAIL_BYTES, MAX_LOCAL_BYTES, MAX_DOMAIN_BYTES,
)

# Транспорт через прокси — в core/proxy_transport.py: им пользуются не только
# SMTP-проверка, но и WHOIS, DNS и HTTP-обогащение.
from core.proxy_transport import (                                # noqa: E402,F401
    PROXY_TYPES as _PROXY_TYPES, SocksSMTP, build_proxy_dict,
    _parse_proxy, _proxy_scheme, _EXIT_IP_RE, PROXY_PROBE_TARGETS,
    EXIT_IP_PROBE_HOST, PROBE_GMAIL, PROBE_OUTLOOK, PROBE_YAHOO, PROBE_ICLOUD,
)

# Профилирование прокси — в core/proxy_probe.py. Там же объяснено, почему
# «живой прокси» и «прокси, годный для почты» — разные вещи.
from core.proxy_probe import (                                    # noqa: E402,F401
    DIRTY_RDNS_KEYWORDS, probe_proxy_target, get_proxy_exit_ip,
    dedupe_proxies, dedupe_proxies_stream, is_dirty_rdns,
    profile_proxies, filter_live_proxies,
)

# WHOIS переехал в core/whois_client.py — см. там, почему клиент свой.
from core.whois_client import (                                   # noqa: E402,F401
    whois_creation_date, _whois_ask, WHOIS_PORT, WHOIS_IANA,
    _WHOIS_REFER_RE, _WHOIS_CREATED_RE,
)

# Разбор ответа сервера вынесен в core/smtp_codes.py: это самостоятельная
# область знания (таблица кодов RFC 3463 и формулировки полусотни почтовиков),
# и держать её внутри сетевого клиента значило смешивать «как спросить» с
# «что означает ответ». Имена ниже сохранены как псевдонимы: на них ссылаются
# и тесты, и код проверки прокси.
from core.smtp_codes import (                                     # noqa: E402
    IP_REPUTATION_MARKERS as _IP_REPUTATION_MARKERS,
    TRANSIENT_TEXT_MARKERS as _TRANSIENT_TEXT_MARKERS,
    RECIPIENT_NEGATIONS as _RECIPIENT_NEGATIONS,
    classify_smtp_response as _classify_smtp_response,
    looks_transient as _looks_transient,
    looks_like_ip_reputation as _looks_like_ip_reputation,
)


def security_gateway(mx_records):
    """Имя шлюза безопасности, если почта домена идёт через него, иначе None."""
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


# DKIM-селекторы. Универсального способа их узнать нет — имя выбирает владелец
# домена. Но если известно, на чьей инфраструктуре сидит домен, перебирать все
# два с лишним десятка незачем: у Google селектор гугловский.






# DNS через прокси — в core/dns_resolver.py. Там же объяснено, почему прямой
# запрос к публичному DNS был утечкой, а не мелочью.
from core.dns_resolver import (                                   # noqa: E402
    _COUNTRY_TO_CODE,
    ProxiedResolver,
    DNSUnavailable,
    DOH_ENDPOINTS,
)

# Пул прокси и проверки по DNS — примеси рядом. Разделение по слоям: здесь
# остаётся диалог с почтовым сервером про конкретный ящик, там — через что
# спрашивать и что известно про домен до всякого диалога.
from core.bounded import BoundedCache                          # noqa: E402
from core.proxy_pool import ProxyPoolMixin, UNKNOWN_LATENCY_MS  # noqa: E402
from core.dns_checks import DnsChecksMixin                      # noqa: E402


def country_code_for_domain(domain):
    """Двухбуквенный код страны домена или пусто, если страна неизвестна.

    Пусто — нормальный и частый исход: у .com и .net страны нет, и подбирать
    прокси по гео для них не по чему. В этом случае выбор идёт как раньше.
    """
    if not isinstance(domain, str) or "." not in domain:
        return ""
    try:
        from core.provider import country_from_domain
    except Exception:
        return ""
    return _COUNTRY_TO_CODE.get(country_from_domain(domain), "")


def _generate_random_local(style="short"):
    """Генерирует случайный локальный-адрес для Catch-All теста.
    style='short' — классический (16 символов), style='uuid' — UUID-подобный (п.4 Catch-All)"""
    if style == "uuid":
        import uuid
        return str(uuid.uuid4()).replace('-', '')[:24]
    chars = string.ascii_lowercase + string.digits
    prefix = ''.join(random.choices(chars, k=12))
    suffix = ''.join(random.choices(string.digits, k=4))
    return f"{prefix}{suffix}"


class NetworkValidator(ProxyPoolMixin, DnsChecksMixin):
    """SMTP-проверка ящика: диалог с сервером и сборка вердикта.

    Работа с пулом прокси и проверки по DNS живут в примесях рядом
    (core/proxy_pool.py и core/dns_checks.py). Разделение по слоям, а не по
    размеру: здесь остаётся то, что спрашивает у почтового сервера про
    КОНКРЕТНЫЙ ящик, а в примесях — то, через что спрашивать и что известно
    про домен до всякого диалога.
    """

    def __init__(self, from_email="check@example.com", timeout=5, proxies=None,
                 proxy_dns=True):
        self.from_email = from_email
        self.timeout = timeout
        self.proxies = proxies if proxies else []
        # Потолок времени на ОДИН адрес, независимо от числа MX и повторов.
        # Держит прогон предсказуемым: без него адрес с тремя MX мог висеть минутами.
        self.address_deadline = max(30, min(180, timeout * 6))

        # Пускать ли DNS через прокси. Выключается только там, где запросы не
        # содержат данных пользователя — например при профилировании самих
        # прокси (обратный DNS их собственных IP).
        self._proxy_dns = bool(proxy_dns)

        # Настройка DNS резолвера. С прокси запросы идут через них, без прокси —
        # напрямую, как раньше.
        self.resolver = ProxiedResolver(
            nameservers=['8.8.8.8', '1.1.1.1', '8.8.4.4', '1.0.0.1'],
            timeout=self.timeout,
            proxy_provider=self._dns_proxy,
        )

        # Все кэши ниже — С ПОТОЛКОМ, а не обычные словари. Ключ у них домен
        # или почтовый сервер, и на базе, собранной дорками, разных доменов
        # столько же, сколько адресов. Замерено: обычные словари стоили 468
        # байт на домен, то есть 2.3 ГБ на пяти миллионах — прогон падал по
        # памяти ровно на тех объёмах, ради которых вход читается потоком.
        # Вытеснение по LRU: часто встречающийся домен из кэша не вылетает,
        # одиночный корпоративный вытесняется, а промах стоит одного запроса.
        # Подробности — в core/bounded.py.

        # Кэш MX-записей
        self.mx_cache = BoundedCache()
        self.mx_lock = threading.Lock()

        # Кэш Catch-All доменов — чтобы не делать двойной пинг дважды для одного домена
        self.catchall_cache = BoundedCache()

        # Память между запусками: catch-all доменов, профили прокси, суточная
        # нагрузка на выходные IP. Недоступная база молча отключает память —
        # это ускорение, а не источник истины. См. core/longterm.py.
        try:
            from core.longterm import LongTermMemory
            self.memory = LongTermMemory()
        except Exception:
            self.memory = None
        self.catchall_lock = threading.Lock()
        # Сколько раз проверяли каждый домен. Нужен, чтобы у гигантов
        # контрольная проба шла не на каждый адрес, а изредка: она стоит один
        # лишний RCPT в уже открытой сессии, но на миллионной базе даже это
        # заметно.
        self._domain_checks = {}
        self._domain_checks_lock = threading.Lock()
        # Домены, у которых сервер поймали на приёме выдуманного адреса. Для
        # гиганта это не catch-all, а защита от перебора: разница важна, потому
        # что чинить надо прокси, а не базу.
        self._tarpit_domains = set()

        # Какие почтовые серверы уже принимали что угодно, и у каких доменов.
        # Нужно на случай, когда собственная тройная проба сорвалась: см.
        # _mx_catchall_suspected. С потолком, а не голым словарём: разных
        # MX-хостов на базе, собранной дорками, столько же, сколько доменов.
        self._mx_catchall = BoundedCache(max_keys=20_000)

        # Честен ли сервер домена: принимает ли он обязательный по RFC postmaster@.
        # Спрашивается лениво — только перед тем, как похоронить адрес.
        self._postmaster_cache = BoundedCache()
        self._postmaster_lock = threading.Lock()

        # Кэш DNS-здоровья (SPF/DMARC/DKIM) — п.2.2+
        self._dns_health_cache = BoundedCache()
        self._dns_health_lock = threading.Lock()

        # Дополнительные кэши (п.1.2, п.1.3)
        self._dnsbl_cache = BoundedCache()
        self._dnsbl_lock = threading.Lock()
        self._ptr_cache = BoundedCache()
        self._ptr_lock = threading.Lock()
        # FCrDNS исходящих IP (наших/прокси) — от него зависит доступ к Yahoo/AOL
        self._fcrdns_cache = BoundedCache()
        self._fcrdns_lock = threading.Lock()

        # Rate Limiting: семафоры для ограничения одновременных соединений к одному MX (п.3.3)
        # Тоже с потолком: ключ — пара «почтовый сервер + выходной IP», и на
        # корпоративной базе таких пар столько же, сколько доменов.
        #
        # Размен здесь чуть другой, чем у кэшей, и его стоит назвать вслух.
        # Вытесненный семафор означает, что следующий поток заведёт на ту же
        # пару НОВЫЙ, и потолок в пять соединений на короткое время окажется
        # выше. Это вежливость к чужому серверу, а не корректность: сервер
        # ответит 421, и адаптивное торможение сузит поток обратно. А вот
        # словарь без потолка — это исчерпанная память и оборванный прогон.
        self._mx_semaphores = BoundedCache()
        self._mx_sem_lock = threading.Lock()
        self._max_concurrent_per_mx = 5  # Максимум 5 параллельных соединений к одному MX

        # Адаптивный Rate Limiting: счётчик 421-ошибок по MX (п.5 — adaptive)
        self._mx_error_counts = BoundedCache()
        # Когда этот сервер жаловался в последний раз. Без времени счётчик
        # только рос: одна тугая минута в начале прогона держала паузу в
        # восемь секунд и потолок в одно соединение до самого конца, даже
        # когда сервер давно отвечал нормально. На сотнях тысяч адресов это
        # разница в часы.
        self._mx_error_seen = BoundedCache()
        # Пары «сервер|наш IP», которым поток уже сужен, и до скольких.
        self._mx_narrowed = BoundedCache()
        self._mx_error_lock = threading.Lock()

        # Proxy Health Scoring (п.8): score каждого прокси
        self._proxy_scores = {}
        self._proxy_score_lock = threading.Lock()

        # Лимит ОДНОВРЕМЕННЫХ соединений через один прокси.
        #
        # Семафор стоял только на MX. При 300 потоках и пяти живых прокси в
        # каждый летело по 60 соединений разом — дешёвый SOCKS5 столько не
        # держит, начинает рвать связь и выглядит мёртвым. Валидатор при этом
        # банил его за «три сбоя подряд», хотя убил его сам.
        self._proxy_semaphores = {}
        self._proxy_sem_lock = threading.Lock()
        self._max_concurrent_per_proxy = 8

        # Суточная нагрузка на ВЫХОДНОЙ IP, а не на строку прокси: десять
        # прокси с общим выходом жгут репутацию одного адреса. Счётчик уводит
        # выбор на менее нагруженный, пока такие есть.
        self._ip_load = {}
        self._ip_load_lock = threading.Lock()
        self._ip_load_soft_cap = 800

        # Свой резолвер для Spamhaus. Пусто — Spamhaus не спрашивается вовсе.
        self._spamhaus_resolver = None
        self._spamhaus_ok = None
        # Задержка до баннера, измеренная профилировщиком. Раньше она только
        # логировалась; теперь при равном health score быстрый прокси идёт первым.
        self._proxy_latency = {}
        # Прокси, севший MAX_CONSECUTIVE_FAILS раз ПОДРЯД, выбывает из ротации навсегда.
        # Иначе мёртвый прокси бесконечно тормозит прогон (10 повторов × таймаут на адрес).
        self._proxy_consecutive_fails = {}
        # На каких MX пришлись сбои текущей серии: три неудачи на одном сервере
        # означают мёртвый сервер, а не мёртвый прокси
        self._proxy_fail_hosts = {}
        self._proxy_banned = set()

        # Кто выбыл с прошлого доклада. Список, а не счётчик: владельцу важно
        # ИМЯ выбывшего — по нему видно, что чинить. Раньше прокси уходил из
        # ротации молча, и заметить это можно было, только когда выбывали ВСЕ.
        self._recent_bans = []
        # Полный профиль прокси: нужен, чтобы при переснятии не потерять
        # то, что заново не измеряли (например реакцию Microsoft)
        self._proxy_profiles = {}
        # Страна почтового сервера домена — для гео-подбора прокси там, где
        # зона домена страны не знает (.com, .net, .org)
        self._mx_country_cache = BoundedCache()
        self._mx_country_lock = threading.Lock()

        # Прокси с обратным DNS — единственные, через кого проверяется Yahoo/AOL
        self._ptr_proxies = set()
        # PTR проверить не удалось — не путать с "PTR точно нет"
        self._ptr_unknown = set()
        # Профилировались ли прокси вообще (см. set_proxy_profiles)
        self._profiled = False
        # Прокси, чей выходной IP числится в чёрных списках: Outlook, iCloud и GMX
        # такие отшивают по репутации, а Gmail и Yandex — принимают
        self._dirty_proxies = set()
        # Результаты ПРЯМЫХ проб до Yahoo и iCloud (заполняет set_proxy_profiles)
        self._yahoo_ok = set()
        self._yahoo_bad = set()
        self._icloud_bad = set()
        if self.proxies:
            for p in self.proxies:
                self._proxy_scores[p] = 0  # Начальный score = 0
                self._proxy_consecutive_fails[p] = 0

        # Случайный HELO-хост для этой сессии (выглядит как настоящий почтовый сервер)
        self.helo_name = random.choice(LEGIT_HELO_NAMES)

    def _is_server_outdated(self, banner_text: str) -> bool:
        """
        Анализирует SMTP-баннер и определяет, устарел ли почтовый сервер.
        Устаревшие серверы (Postfix 2.x, Exim 4.6x, Sendmail 8.13 и т.д.)
        часто означают заброшенную инфраструктуру → меньше шансов на живого пользователя.
        """
        if not banner_text:
            return False
        if not isinstance(banner_text, str):
            return False
        b = banner_text.lower()
        
        
        # Postfix 2.x (вышел ~2005-2012, давно не поддерживается)
        if re.search(r'postfix\s*2\.\d', b):
            return True
        # Postfix 3.0-3.2 (2015-2017, устарели)
        if re.search(r'postfix\s*3\.[012]\b', b):
            return True
        
        # Exim 4.6x-4.7x (2006-2012)
        if re.search(r'exim\s*4\.[67]\d', b):
            return True
        
        # Sendmail 8.1x (2005-2010)
        if re.search(r'sendmail\s*8\.1[0-4]', b):
            return True
        
        # Courier MTA (очень старый)
        if 'courier' in b and re.search(r'courier\s*0\.\d', b):
            return True
        
        # hMailServer (популярный на Windows, часто необновляемый)
        if re.search(r'hmailserver\s*[0-4]\.', b):
            return True
        
        # Qmail (не обновляется с 2007 года)
        if 'qmail' in b:
            return True
            
        return False

    def _make_smtp_connection(self, proxy=None):
        """Создает SMTP соединение — либо через прокси, либо напрямую."""
        if proxy:
            parsed = _parse_proxy(proxy)
            if not parsed:
                raise ValueError("Неверный формат прокси")
            ip, port, user, password = parsed
            # Подключаемся тем же протоколом, которым прокси был проверен
            return SocksSMTP(ip, port, proxy_user=user, proxy_pass=password, timeout=self.timeout,
                             proxy_type=_PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5))
        else:
            return smtplib.SMTP(timeout=self.timeout)

    def _ask_vrfy(self, server, email, domain):
        """Спрашивает VRFY. Вердикт или None, если ответа по существу нет.

        Разбор идёт тем же классификатором, что и RCPT: коды и формулировки у
        VRFY те же самые, и заводить для них вторую таблицу правил значило бы
        завести второе место, где эти правила разъезжаются.

        252 отсекается отдельно и до классификатора: по RFC 5321 §3.5.3 это
        «не берусь проверить», а классификатор трактует 2xx как согласие.
        """
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
        """Вердикт о ящике по ответу сервера. Вся логика — в core/smtp_codes.

        Метод оставлен на месте намеренно: на него ссылается и код проверки, и
        полтора десятка тестов, а email с domain нужны будущим правилам,
        зависящим от провайдера.
        """
        return _classify_smtp_response(code, message)

    def _helo_for(self, proxy):
        """Имя для HELO/EHLO, привязанное к ВЫХОДНОМУ адресу.

        Раньше имя выбиралось один раз на процесс, и все прокси
        представлялись почтовику одинаково: для него это подпись прогона —
        десяток разных IP, называющих себя одним и тем же хостом, выглядит
        ровно как то, чем является.

        Привязка к выходу, а не к строке подключения: десять входов в один
        выход — это один отправитель, и назваться он должен одинаково.
        Стабильность обязательна по той же причине, что и у обратного адреса:
        серый список ведётся по тройке, и менять представление между
        попытками значит сбивать её.
        """
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
        """
        Делает один SMTP-пинг к серверу с Rate Limiting + adaptive (п.3.3+п.5).
        Возвращает {'status': ..., 'reason': ...}

        control_probe=True добавляет второй RCPT с выдуманным адресом в ТОЙ ЖЕ
        сессии, если первый вернул 250. Это ловит catch-all, который отдельная
        тройная проба пропустила (она могла сорваться на прокси, и её неудача
        читается как «не catch-all»). Лишних подключений при этом ноль.
        """
        # ЗАЩИТА ОТ УТЕЧКИ IP: если пользователь загрузил прокси, но все они выбыли,
        # НЕЛЬЗЯ молча ходить напрямую — это раскроет реальный IP. Честно сообщаем.
        if proxy is None and self.has_proxies_configured():
            return {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}

        # Ротация MAIL FROM (п.3.2). Стабильная для домена: см. mail_from_for —
        # случайный отправитель ломал тройку серого списка.
        domain = email.split("@")[1].lower() if "@" in email else ""
        from_addr = from_email or mail_from_for(domain)
        server = None

        # Пауза перед запросом. Растёт, если этот сервер уже отвечал 421.
        #
        # Спим ДО захвата семафора, а не после. Раньше было наоборот, и слот
        # параллельности простаивал всё время сна: при back-off до 8 секунд и
        # пяти слотах на MX это резало пропускную способность к серверу до
        # пяти запросов за восемь секунд. Пауза при этом никуда не делась —
        # каждый поток по-прежнему выдерживает свою, — но ждёт он в стороне,
        # не занимая очередь.
        time.sleep(self._mx_delay(mx_record))

        # Rate Limiting: ждём своей очереди к этому MX-серверу (п.3.3)
        sem = self._get_mx_semaphore(mx_record, proxy)
        sem.acquire()

        # И к самому прокси: без этого при 300 потоках и пяти прокси в каждый
        # летело по 60 соединений, дешёвый SOCKS5 рвал связь и получал бан
        # за сбои, которых сам не совершал.
        slot = self.proxy_slot(proxy)
        if slot is not None:
            slot.acquire()

        try:
            # Обращение через выходной IP — считаем нагрузку на его репутацию
            self.note_ip_use(proxy)

            server = self._make_smtp_connection(proxy)
            _connect_started = time.monotonic()
            banner_code, banner_msg = server.connect(mx_record, 25)
            # Задержка, измеренная прямо сейчас. Профилировщик снимает её раз
            # на старте и потом раз в десять минут, а прокси проседает быстрее.
            # Здесь замер бесплатный: соединение всё равно устанавливается.
            self._note_latency(proxy, (time.monotonic() - _connect_started) * 1000)
            
            # Сохраняем SMTP-баннер для анализа версии сервера
            banner_text = banner_msg.decode('utf-8', 'ignore') if isinstance(banner_msg, bytes) else str(banner_msg)

            # Сначала EHLO, если ошибка - фоллбэк на HELO
            try:
                helo_name = self._helo_for(proxy)
                ehlo_code, ehlo_msg = server.ehlo(helo_name)
                if ehlo_code >= 500:
                    server.helo(helo_name)
            except Exception:
                ehlo_msg = b""
                server.helo(self._helo_for(proxy))

            # Проверка STARTTLS
            has_starttls = False
            try:
                if server.has_extn('starttls'):
                    has_starttls = True
            except Exception:
                ehlo_str = ehlo_msg.decode('utf-8', 'ignore').lower() if isinstance(ehlo_msg, bytes) else str(ehlo_msg).lower()
                if 'starttls' in ehlo_str:
                    has_starttls = True

            # Если сервер отверг САМ MAIL FROM (репутация прокси, SPF, требование авторизации),
            # то последующий RCPT вернёт вводящий в заблуждение код вроде "503 Bad sequence",
            # который раньше молча превращался в "невалидный ящик". Проверяем явно.
            # Не-ASCII имя ящика: проверяем, если сервер объявил SMTPUTF8.
            #
            # Раньше мы сдавались на подходе — возвращали «не проверено» ещё до
            # соединения. Но RFC 6531 существует, и серверы его объявляют:
            # тогда команду можно послать в UTF-8 и получить нормальный ответ.
            # Отказываться от ответа, который дают, — это терять адрес на
            # ровном месте.
            #
            # command_encoding у smtplib по умолчанию ASCII, поэтому его
            # переключаем ЯВНО: иначе адрес не влезет в команду и вылетит
            # UnicodeEncodeError.
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

            # options передаются, только когда они есть: у smtplib подпись
            # mail(sender, options=()), но лишний именованный аргумент в
            # обычном ASCII-пути ничего не даёт, а совместимости стоит.
            if mail_options:
                mail_code, mail_msg = server.mail(from_addr, options=mail_options)
            else:
                mail_code, mail_msg = server.mail(from_addr)
            if mail_code >= 400:
                mail_text = mail_msg.decode('utf-8', 'ignore') if isinstance(mail_msg, bytes) else str(mail_msg)
                low = mail_text.lower()

                # Отдельно распознаём FCrDNS: это НЕ проблема почты и не проблема
                # прокси-соединения — у исходящего IP просто нет обратного DNS.
                # Так Yahoo/AOL отшивают всех до этапа RCPT.
                if "5.7.25" in mail_text or "reverse dns" in low or "forward-confirmed" in low:
                    reason = ("550 Нет обратного DNS у нашего IP (FCrDNS) — "
                              "Yahoo/AOL не пускают. Нужен прокси с PTR-записью.")
                else:
                    reason = f"{mail_code} MAIL FROM Rejected (Email May Exist): {mail_text[:40]}"
                    self._update_proxy_score(proxy, False, mx_record=mx_record)  # Похоже на проблему прокси/IP

                return {
                    "status": "unknown",
                    "reason": reason,
                    "smtp_banner": banner_text,
                    "server_outdated": self._is_server_outdated(banner_text),
                    "has_starttls": has_starttls,
                }

            code, message = server.rcpt(email)

            result = self._parse_smtp_response(code, message, email, domain)

            # Сервер не дал вердикта — спрашиваем VRFY, раз он уже на связи.
            #
            # Команда старая и почти везде выключена, но там, где включена, она
            # отвечает о ящике ПРЯМО, без всяких проб: одна строка вместо
            # догадок. Стоит она одного пакета в уже открытой сессии, и пробуем
            # мы её только тогда, когда иначе результатом был бы «неизвестно».
            #
            # Ответ 252 («не могу проверить, но письмо приму») вердиктом НЕ
            # считается — это ровно то же «не знаю», только другими словами.
            if result["status"] == "unknown":
                verified = self._ask_vrfy(server, email, domain)
                if verified is not None:
                    result = verified

            # Контрольный RCPT в ТОЙ ЖЕ сессии.
            #
            # Сервер ответил 250 — но это ничего не значит, если он отвечает 250
            # на что угодно. Тройная проба catch-all делается ОТДЕЛЬНЫМ
            # подключением и до этого момента могла сорваться на прокси, а её
            # неудача трактуется как «не catch-all». Здесь мы спрашиваем прямо
            # в открытой сессии: соединение уже установлено, MAIL FROM принят,
            # и лишняя команда RCPT стоит одного пакета.
            #
            # Оба 250 — домен принимает любой адрес, и Valid ничего не доказывает.
            if control_probe and result["status"] == "valid" and domain:
                fake = f"{_generate_random_local('uuid')}@{domain}"
                try:
                    ctl_code, _ctl_msg = server.rcpt(fake)
                except Exception:
                    ctl_code = None
                if ctl_code is not None and 200 <= ctl_code < 300:
                    result["status"] = "catchall"
                    result["reason"] = ("Catch-All: сервер принял и выдуманный адрес "
                                        "в той же сессии")
                    with self.catchall_lock:
                        self.catchall_cache[domain] = True
                    # Такой же факт, как и от тройной пробы, — и помнить его
                    # надо так же: иначе следующий запуск выяснит его заново.
                    #
                    # НО не у гигантов. gmail.com, принявший выдуманный адрес,
                    # не стал catch-all — он перестал отвечать честно, потому
                    # что с нашего выхода идёт перебор. Вызывающий распознает
                    # это как тарпитинг несколькими строками ниже, а запись в
                    # память делалась ДО того и на тридцать суток. Итог:
                    # каждый следующий запуск отдавал Unknown по ВСЕЙ почте
                    # gmail, не сходив в сеть, — то есть худшая потеря базы
                    # из всех возможных, и молча.
                    if not self._is_never_catchall(domain):
                        self._remember_catchall(domain, True)
                elif ctl_code is not None and ctl_code >= 500:
                    # Выдуманный адрес отвергнут — сервер отвечает честно, и
                    # 250 на реальный адрес это подтверждённый живой ящик.
                    with self.catchall_lock:
                        self.catchall_cache.setdefault(domain, False)
                    result["control_rcpt"] = "rejected"

            # Добавляем информацию о баннере для Engagement Score
            result["smtp_banner"] = banner_text
            result["server_outdated"] = self._is_server_outdated(banner_text)
            result["has_starttls"] = has_starttls

            # Adaptive Rate Limiting (п.5): если 421 — записываем ошибку для этого MX
            if code == 421:
                self._record_mx_error(mx_record, proxy)

            self._update_proxy_score(proxy, True)  # Прокси жив
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
            sem.release()  # Освобождаем слот для следующего потока
            if slot is not None:
                slot.release()
            if server:
                try:
                    server.quit()
                except Exception:
                    pass

    def _probe_recipients(self, addresses, mx_record, proxy=None, from_email=None):
        """Проверяет НЕСКОЛЬКО адресов в ОДНОЙ SMTP-сессии.

        Раньше тройная проба catch-all делала три отдельных подключения
        (connect + quit на каждое). На новом домене три коннекта подряд —
        быстрый путь к ограничению со стороны сервера. Здесь мы соединяемся
        один раз и шлём три RCPT TO, что и дешевле, и незаметнее.

        Возвращает список результатов той же формы, что и _do_single_ping.
        Досрочно прекращает перебор, если сервер отвалился.
        """
        if proxy is None and self.has_proxies_configured():
            fail = {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}
            return [dict(fail) for _ in addresses]

        domain = addresses[0].split("@")[1].lower() if addresses and "@" in addresses[0] else ""
        from_addr = from_email or mail_from_for(domain)
        results = []
        server = None

        # Та же причина, что и в _do_single_ping: сон не должен занимать слот.
        time.sleep(self._mx_delay(mx_record))

        sem = self._get_mx_semaphore(mx_record, proxy)
        sem.acquire()
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
                try:
                    server.quit()
                except Exception:
                    pass

        while len(results) < len(addresses):
            results.append({"status": "unknown", "reason": "Сессия оборвалась"})
        return results

    def postmaster_is_honored(self, domain, mx_record):
        """Принимает ли сервер postmaster@ — то есть можно ли верить его 550.

        RFC 5321 §4.5.1 обязывает каждый принимающий почту домен обслуживать
        адрес postmaster@. Сервер, который отвечает на него 550, нарушает
        обязательный пункт стандарта — и его отказ РЕАЛЬНОМУ адресу после
        этого не доказывает ничего: так же он отвечает всем подряд.

        True  — обязательный адрес принят, вердиктам сервера можно верить
        False — обязательный адрес отвергнут, 550 этого сервера ничего не значит
        None  — спросить не удалось (в этом случае поведение прежнее)

        Спрашиваются два адреса. postmaster@ обязателен безусловно (RFC 5321
        §4.5.1). abuse@ обязателен УСЛОВНО: RFC 2142 §4 требует поддерживать
        имя ящика лишь у того, кто оказывает соответствующую услугу, — и
        потому он здесь запасной свидетель, а не второй голос. Его ответ
        читается только когда первый ничего не сказал, и в той же сессии,
        поэтому цена вопроса прежняя: одна сессия на домен, и та только перед
        тем, как похоронить адрес. Результат кэшируется.
        """
        if not domain:
            return None
        with self._postmaster_lock:
            if domain in self._postmaster_cache:
                return self._postmaster_cache[domain]

        # Спрашиваем два адреса в ОДНОЙ сессии: postmaster@ (RFC 5321 §4.5.1,
        # обязателен безусловно) и abuse@ (RFC 2142 §4, обязателен для тех,
        # кто оказывает услугу). Второй RCPT в уже открытой сессии стоит один
        # пакет — сессия по-прежнему одна на домен.
        #
        # Нужен он затем, что на одной пробе вывод срывался чаще, чем
        # получался: таймаут, мёртвый прокси, отказ по репутации — и функция
        # возвращала None, а вызывающий после этого верил тому самому 550,
        # ради проверки которого сюда и пришёл. Вопрос у обоих адресов один:
        # отвечает ли этот сервер «получателя нет» вообще всем подряд.
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
            # Иначе вывода нет — спрашиваем следующий обязательный адрес.
        if verdict is None:
            # Не кэшируем: иначе один сбой навсегда лишил бы домен проверки.
            return None

        with self._postmaster_lock:
            self._postmaster_cache[domain] = verdict
        return verdict

    def _probe_proxy_for(self, domain):
        """Выход для ПРОБЫ по тому же правилу, что и для основной проверки.

        Раньше пробы (тройная на catch-all и служебные адреса) звали
        _pick_best_proxy() без единого требования, а основная проверка брала
        чистый выход или выход с PTR. Для Outlook, iCloud и GMX это значило,
        что проба уходила с грязного адреса, получала отказ по репутации и
        читалась как «домен не catch-all» — после чего 250 на реальный адрес
        становился Valid. Вывод о домене делался с заблокированного адреса.
        """
        domain = (domain or "").strip().lower()
        needs_ptr = domain in YAHOO_DOMAINS or domain in AOL_DOMAINS
        needs_clean = domain in NEEDS_CLEAN_IP_DOMAINS
        return self._pick_best_proxy(need_ptr=needs_ptr, need_clean=needs_clean)

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
            if result["status"] == "unknown":
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

    def stealth_smtp_ping(self, email: str, mx_records: list,
                          control_probe=False, avoid_exit_of=None,
                          prefer_exit_of=None) -> dict:
        """
        Умный SMTP-пинг с повторными попытками, мульти-MX фоллбэком (п.3.1),
        и кастомной логикой для проблемных почтовиков.

        control_probe пробрасывается в _do_single_ping: при 250 на реальный
        адрес в той же сессии проверяется выдуманный. См. там же почему.
        """
        domain = email.split("@")[1].lower() if "@" in email else ""

        # Yahoo/AOL/Verizon требуют обратный DNS у исходящего IP. Прокси без PTR
        # они отшивают на MAIL FROM, до проверки адреса дело не доходит — поэтому
        # для них берём только PTR-прокси, а остальным доменам PTR не нужен.
        needs_ptr = domain in YAHOO_DOMAINS or domain in AOL_DOMAINS
        needs_clean = domain in NEEDS_CLEAN_IP_DOMAINS

        # Это ПОВТОР после неудачи: берём по возможности чистый выход, а не
        # просто другой. Самая частая причина попасть сюда — отказ по
        # репутации, и менять грязный адрес на такой же грязный значит
        # получить тот же ответ вторым заходом. Требование мягкое: если
        # чистых в пуле нет, выбор вернётся к обычному (см. _pick_best_proxy).
        if avoid_exit_of:
            needs_clean = True

        # Страна домена получателя: при прочих равных берём прокси оттуда же.
        # Проверять web.de через бразильский адрес — лишний повод для отказа.
        # Страна получателя. Для .com и подобных зона молчит, поэтому спрашиваем
        # у его же почтового сервера — иначе гео-подбор прокси не работал бы на
        # большей части базы.
        want_country = self.country_for_domain(
            domain, mx_records[0] if mx_records else "")
        # `self._profiled`, а не `self._ptr_proxies`. Разница решает всё:
        # если профилирование прошло и PTR не нашлось НИ У КОГО, множество
        # _ptr_proxies пусто — и старое условие молча выключало сам
        # предохранитель. Yahoo/AOL после этого проверялись прокси с
        # заведомо отсутствующим PTR: пятнадцать гарантированно холостых
        # попыток на адрес, а в конце ложный диагноз «все прокси мертвы»
        # вместо честного «нечем проверять Yahoo». Владелец шёл чинить
        # живой пул прокси вместо того, чтобы достать PTR.
        if needs_ptr and self.proxies and self._profiled and not self.has_ptr_proxies():
            return {
                "status": "unknown",
                "reason": ("Нет прокси с обратным DNS (PTR) — Yahoo/AOL проверить нечем. "
                           "Нужен прокси или VPS с PTR-записью."),
            }

        # Yahoo/AOL: увеличиваем лимит попыток, они часто сбрасывают соединение
        if domain in YAHOO_DOMAINS or domain in AOL_DOMAINS:
            max_retries = 15 if self.proxies else 3
        elif domain in MICROSOFT_DOMAINS:
            max_retries = 8 if self.proxies else 2
        else:
            max_retries = 10 if self.proxies else 1

        last_result = {"status": "unknown", "reason": "No Response"}

        # Общий дедлайн на АДРЕС. Без него лимит попыток действовал на каждый MX
        # по отдельности: у yahoo.com три MX, то есть до 45 попыток, и при глухих
        # прокси один адрес мог занять несколько минут. Теперь сколько бы ни было
        # MX, дольше дедлайна на одном адресе не сидим.
        deadline = time.monotonic() + self.address_deadline

        # Мульти-MX: пробуем все MX-серверы по очереди (п.3.1) + smart proxy selection (п.8)
        for mx_record in mx_records:
            if time.monotonic() > deadline:
                break
            for attempt in range(max_retries):
                # Прокси кончились — повторять бессмысленно, только время тратить
                if self.all_proxies_dead():
                    return {"status": "unknown", "reason": "All Proxies Dead (прямое соединение запрещено)"}

                if time.monotonic() > deadline:
                    last_result = {
                        "status": "unknown",
                        "reason": f"Timeout: адрес проверялся дольше {self.address_deadline}с",
                    }
                    break

                # Повтор после СЕРОГО СПИСКА идёт тем же выходом намеренно.
                # Сервер ждёт возврата той же тройки (IP, отправитель,
                # получатель); прийти с другого адреса — значит начать
                # выдержку заново и не выйти из неё никогда.
                proxy = None
                if prefer_exit_of and attempt == 0:
                    proxy = self.proxy_still_usable(prefer_exit_of)
                if proxy is None:
                    proxy = self._pick_best_proxy(need_ptr=needs_ptr,
                                                  need_clean=needs_clean,
                                                  want_country=want_country,
                                                  avoid_exit_of=avoid_exit_of)
                if proxy is None and avoid_exit_of and self.has_proxies_configured():
                    # Другого выхода в пуле нет. Это НЕ повод отвечать «прокси
                    # кончились»: они живы, просто все ведут в тот же адрес.
                    # Повтор тем же выходом хуже нового, но несравнимо лучше
                    # выдуманного Unknown — живой ящик остался бы непроверенным.
                    proxy = self._pick_best_proxy(need_ptr=needs_ptr,
                                                  need_clean=needs_clean,
                                                  want_country=want_country)
                result = self._do_single_ping(email, mx_record, proxy=proxy,
                                              control_probe=control_probe)
                # Чей это ответ. Нужно повтору: отложенный адрес переспрашивать
                # ТЕМ ЖЕ выходом бессмысленно — он только что не смог.
                if proxy:
                    result["proxy"] = proxy

                # Живой ящик подтверждён — дальше искать нечего
                if result["status"] == "valid":
                    return result

                # Домен уличён в приёме чего угодно — тоже дальше искать
                # нечего, и по той же причине: ответ уже получен.
                #
                # Раньше этой ветки не было, и catchall проваливался в конец
                # цикла к `last_result = result; continue`. То есть домен,
                # только что доказавший, что принимает выдуманный адрес,
                # переспрашивался следующим прокси — а там контрольная проба
                # могла не сработать (сорвалась, попала на другой MX), и
                # адрес возвращался как VALID. Разоблачение перекрывалось
                # повтором, и владелец получал «Годен» на домене, про который
                # программа за секунду до этого выяснила обратное.
                #
                # Catch-all — свойство ДОМЕНА, а не попытки. Выяснив его один
                # раз, повторять нельзя: любой следующий ответ будет только
                # менее правдивым.
                if result["status"] == "catchall":
                    return result

                # А вот приговор «ящика нет» перед возвратом СВЕРЯЕТСЯ со
                # вторым почтовым сервером домена.
                #
                # Зачем. У домена бывает несколько MX, и они не всегда
                # настроены одинаково: запасной узел часто не знает списка
                # ящиков и отвечает 550 на всё подряд, а бывает и наоборот —
                # основной режет по фильтру, а запасной принимает. Приговор,
                # вынесенный одним сервером, в таких доменах ошибочен, и цена
                # ошибки здесь максимальная: выброшенный живой контакт.
                if result["status"] == "invalid":
                    confirmed = self._confirm_invalid_on_other_mx(
                        email, mx_record, mx_records, needs_ptr, needs_clean,
                        want_country, deadline, first_proxy=proxy)
                    if confirmed is None:
                        # Сверить было НЕ С ЧЕМ: у домена один почтовый сервер
                        # и в пуле нет второго выходного адреса. Приговор
                        # остаётся в силе, но владелец обязан знать, что он
                        # держится на одном ответе.
                        result["second_opinion"] = "unavailable"
                        result["reason"] = (
                            "%s [второго мнения не было: у домена один MX и "
                            "нет другого выхода]" % result.get("reason", ""))
                        return result
                    if confirmed:
                        # Отмечаем ЧЕМ подтверждён: уверенность в вердикте
                        # считается по этому признаку, а не по статусу.
                        result["second_opinion"] = "agreed"
                        return result            # второй сервер согласен
                    # Серверы разошлись: хоронить адрес нельзя.
                    return {
                        "status": "risky",
                        "reason": ("Второй ответ противоречит первому: адрес "
                                   "отвергли с одного выхода и приняли с "
                                   "другого. Ящик может существовать."),
                        "smtp_banner": result.get("smtp_banner", ""),
                        "has_starttls": result.get("has_starttls"),
                        "server_outdated": result.get("server_outdated", False),
                    }

                # Отказ пришёл по репутации нашего IP — значит повторять
                # «следующим по списку» бессмысленно, нужен заведомо чистый.
                # Причина известна точно, глупо ею не воспользоваться.
                if _looks_like_ip_reputation(result.get("reason", "")):
                    needs_clean = True

                # Если greylisted — запоминаем и пробуем ещё
                if result["status"] == "greylisted":
                    last_result = result
                    continue

                # Для unknown — пробуем ещё раз со следующим прокси
                last_result = result
                continue

            # Однозначный ответ (valid/invalid) уже возвращён выше через return,
            # поэтому сюда мы попадаем только с unknown/greylisted и честно
            # пробуем следующий MX.

        return last_result

    def country_for_domain(self, domain, mx_host=""):
        """Страна получателя: сначала по зоне, потом по адресу его почтовика.

        Зачем второй шаг. У .com, .net и .org зоны страны нет вовсе, а это
        большая часть американской и международной базы — то есть гео-подбор
        прокси там раньше не работал НИКОГДА. Но сервер, который эту почту
        принимает, физически где-то стоит, и его адрес страну знает.

        Спрашивается один раз на домен и кэшируется. Пустая строка означает
        «не выяснили» — подбирать прокси наугад в этом случае не надо.
        """
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

        # Неудачу кэшируем тоже, но пустой строкой: иначе на каждый адрес
        # домена шёл бы новый запрос к внешнему сервису.
        with self._mx_country_lock:
            self._mx_country_cache[key] = code
        return code

    def _confirm_invalid_on_other_mx(self, email, decided_on, mx_records,
                                     needs_ptr, needs_clean, want_country,
                                     deadline, first_proxy=None):
        """Второе мнение о приговоре: другой сервер ЛИБО другой выходной IP.

        True  — подтверждено, ящика действительно нет;
        False — второй ответ говорит обратное, хоронить адрес нельзя;
        None  — сверить не с чем: некому спросить или не успели по дедлайну.

        Две оси, и обе нужны.

        ПО СЕРВЕРАМ. У домена бывает несколько MX, настроенных по-разному:
        запасной узел часто не знает списка ящиков и отвечает 550 на всё
        подряд.

        ПО ВЫХОДНОМУ IP. Это добавлено позже и закрывает дыру, которая была
        больше первой: у yandex.ru, mail.ru и почти всей корпоративной почты
        MX ОДИН, и подтверждать приговор было нечем — второе мнение не
        спрашивалось вовсе. А отказ по репутации нашего адреса выглядит для
        нас точно так же, как «ящика нет»: повтори мы его с того же IP, он бы
        подтвердил сам себя.

        Поэтому спрашиваем ВСЕГДА с другого выходного адреса, а сервер берём
        другой, если он есть. Если другого IP нет — второго мнения нет, и это
        честное None, а не молчаливое согласие.
        """
        if time.monotonic() > deadline:
            return None

        # Прокси с ДРУГИМ выходным адресом. Без него спрашивать бессмысленно.
        proxy = self._pick_best_proxy(need_ptr=needs_ptr, need_clean=needs_clean,
                                      want_country=want_country,
                                      avoid_exit_of=first_proxy)
        if first_proxy and proxy is None:
            return None          # другого выхода нет — сверить не с чем

        # Сервер по возможности другой: две независимые оси лучше одной.
        others = [mx for mx in (mx_records or []) if mx != decided_on]
        target = others[0] if others else decided_on
        if not others and not first_proxy:
            return None          # ни другого MX, ни другого IP — сверять нечем

        second = self._do_single_ping(email, target, proxy=proxy)
        status = second.get("status")
        if status == "invalid":
            return True
        if status == "valid":
            return False
        # unknown/greylisted/risky — второй сервер ничего не сказал, и
        # выдавать его молчание за несогласие нельзя.
        return None

    def confirm_valid_from_other_exit(self, email, mx_records,
                                      first_proxy=None, deadline=None):
        """Второе мнение о ПОДТВЕРЖДЕНИИ. Зеркало проверки приговора.

        True  — второй выход тоже принял адрес;
        False — второй выход адрес ОТВЕРГ, «Годен» недоказуем;
        None  — сверить не с чем: другого выходного адреса в пуле нет.

        ЗАЧЕМ. Приговор «ящика нет» сверяется со вторым сервером и вторым
        выходом — цена ошибки высока, живой контакт теряется навсегда. У
        `Valid` второго мнения не было вообще: он держался на одной сессии с
        одного выхода. А цена ошибки здесь тоже высокая, просто она приходит
        позже — письмом на несуществующий ящик и отскоком.

        Что это ловит и чего не ловит контрольная проба. Контрольная проба
        спрашивает выдуманный адрес в той же сессии и ловит catch-all. Она
        НЕ видит случая, когда почтовик принимает всё подряд именно с нашего
        выхода — а с другого отвечает честно. Тогда контрольная проба тоже
        получит `250` на выдуманный, и статус станет `catchall`... но только
        если она в этой сессии была: у гигантов она идёт раз в 25 адресов.

        ПОЧЕМУ ОТКАЗ ВТОРОГО ВЫХОДА НЕ ДЕЛАЕТ АДРЕС INVALID. Отвергнуть могли
        по репутации второго прокси, а не по отсутствию ящика. Два выхода
        разошлись — значит доказательства нет ни у одной стороны, и честный
        ответ здесь `Unknown`, а не приговор.
        """
        if deadline is not None and time.monotonic() > deadline:
            return None
        domain = email.split("@")[1].lower() if "@" in email else ""
        needs_ptr = domain in YAHOO_DOMAINS or domain in AOL_DOMAINS
        needs_clean = domain in NEEDS_CLEAN_IP_DOMAINS

        proxy = self._pick_best_proxy(need_ptr=needs_ptr,
                                      need_clean=needs_clean,
                                      avoid_exit_of=first_proxy)
        if first_proxy and proxy is None:
            return None            # другого выхода нет — сверять нечем
        if not first_proxy and not self.proxies:
            return None            # прямое соединение: выход всего один

        target = (mx_records or [None])[0]
        if not target:
            return None
        second = self._do_single_ping(email, target, proxy=proxy)
        status = second.get("status")
        if status == "valid":
            return True
        if status in ("invalid", "catchall"):
            return False
        # unknown/greylisted/risky — второй выход промолчал. Молчание не
        # опровержение: возвращаем «сверить не удалось».
        return None

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

    @staticmethod
    def probe_form(email):
        """Адрес в том виде, в котором он уйдёт в команду `RCPT TO`.

        Отличается от загруженного ровно одним: домен переведён в punycode.
        На проводе это одна и та же строка — `ivan@почта.рф` и
        `ivan@xn--80a1acny.xn--p1ai` адресуют один ящик, просто SMTP не умеет
        не-ASCII в домене без расширения.

        Отдельной функцией, потому что это значение показывается владельцу в
        строке «Проверен как». Он дважды спрашивал, тот ли адрес проверяется;
        отвечать на это должна программа, а не переписка. Две копии правила
        разошлись бы молча, и строка показывала бы не то, что ушло.
        """
        local, _, raw = str(email or "").rpartition("@")
        # Домен-литерал переводить в punycode нечего: там адрес, а не имя, и
        # он уже ASCII. Прогон через IDNA возвращал пустую строку, то есть
        # адрес терялся бы по дороге к команде RCPT.
        if domain_literal_ip(raw) is not None:
            return "%s@%s" % (local, raw.strip().lower())
        domain = to_ascii_domain(raw.lower())
        return "%s@%s" % (local, domain) if domain else ""

    def check_email(self, email: str, avoid_exit_of=None,
                    prefer_exit_of=None) -> dict:
        """Полная сетевая проверка почты с RFC-валидацией, Catch-All детектором и DNS-здоровьем."""

        # Шаг 0: Проверка синтаксиса (п.1.3). IDN проходит — см. validate_email_syntax.
        if not validate_email_syntax(email):
            # Кавычки в имени ящика больше не повод сдаваться: грамматика
            # RFC 5321 §4.1.2 разбирается, а RCPT с ними строит smtplib —
            # quoteaddr кавычки сохраняет. Сюда доходит только настоящий
            # мусор.
            return {"status": "invalid", "reason": "Bad Syntax (RFC 5322)", "mx_record": "N/A"}

        # Не-ASCII имя ящика ОТСЮДА НЕ РАЗВОРАЧИВАЕТСЯ.
        #
        # Раньше здесь стоял ранний выход «команду с ней не построить», и он
        # делал поддержку SMTPUTF8 недостижимой: код в _do_single_ping умеет
        # переключить кодировку команды и получить нормальный ответ, но адрес
        # до него не доезжал никогда. Проверка расширения — дело сессии, а не
        # догадки на подходе: спросить сервер можно только у сервера.
        #
        # Если расширения у него нет, «не проверено» вернётся из самой сессии,
        # и там оно будет честным ответом, а не отговоркой.

        local_part, _, raw_domain = email.rpartition("@")

        # Домен-литерал: вместо ИМЕНИ домена в адресе стоит сам адрес в
        # квадратных скобках — `user@[192.168.1.1]`. RFC 5321 §4.1.3 это
        # разрешает, а до правки такой получатель отвергался ещё синтаксисом,
        # то есть хоронился без единого запроса в сеть.
        #
        # ЗАЩИТА ОТ ПОХОДА ВНУТРЬ СЕТИ ОСТАЁТСЯ В СИЛЕ. Разница с MX-записью
        # только в том, кто назвал адрес: там его пишет владелец чужого
        # домена, здесь он приходит строкой из базы. Ходить к себе внутрь
        # нельзя ни по чьей указке, поэтому непубличный литерал даёт «не
        # проверено» — но не «мёртвый»: внутренняя почта у кого-то может быть
        # настоящей, мы просто не можем её увидеть снаружи.
        литерал = domain_literal_ip(raw_domain)
        if литерал is not None and resolves_to_private(str(литерал)):
            return {"status": "unknown",
                    "reason": "Проверить нечем: %s" % REASON_PRIVATE,
                    "mx_record": "N/A"}

        domain = (raw_domain.strip().lower() if литерал is not None
                  else to_ascii_domain(raw_domain.lower()))
        if not domain:
            return {"status": "invalid", "reason": "Invalid Domain (IDNA Error)", "mx_record": "N/A"}

        # На проводе домен всегда в punycode: ivan@почта.рф -> ivan@xn--80a1acny.xn--p1ai
        # Собирается ТОЙ ЖЕ функцией, что показывает окно в строке «Проверен
        # как»: два способа собрать одну строку разошлись бы молча.
        probe_email = self.probe_form(email)

        # Шаг 0.5: правила имени пользователя у самого провайдера.
        #
        # RFC разрешает почти что угодно, а Gmail — нет: имя там от шести
        # символов и только из латиницы, цифр и точек. `ca@gmail.com` проходит
        # RFC и не существует физически.
        #
        # Два исхода трактуются ПО-РАЗНОМУ, и это принципиально:
        #   impossible — адресовать нечего: имя ящика пустое. Это единственный
        #                случай, когда вердикт выносится без сети. Предел
        #                ДЛИНЫ сюда больше не относится — он списан с чужой
        #                страницы помощи, а не получен от сервера
        #                (см. core/local_rules.py).
        #   unlikely   — нынешние правила нарушены, но старые аккаунты могли
        #                быть заведены до их введения. Такой адрес проверяем
        #                по сети как обычно: ответ сервера главнее правила.
        #                Правило пригодится ниже, если сети не хватило.
        rule_verdict, rule_reason = check_local_part(probe_email)
        if rule_verdict == LOCAL_IMPOSSIBLE:
            return {"status": "invalid",
                    "reason": f"Имя не может существовать — {rule_reason}",
                    "mx_record": "N/A"}

        # Шаг 1: DNS / MX Check (с A-фоллбэком — п.1.4)
        #
        # У домена-литерала спрашивать некого: цель названа прямо в адресе, и
        # публичность её уже проверена выше. Через filter_mx_hosts такой хост
        # гнать НЕЛЬЗЯ — он отбрасывает голые адреса как нарушение RFC 2181
        # §10.3, и это верно для MX-ЗАПИСИ, но не для литерала, где адрес
        # написан самим отправителем намеренно.
        mx_records = ([str(литерал)] if литерал is not None
                      else self.get_mx_records(domain))
        if mx_records is None:
            # DNS не ответил через прокси. Домен НЕ мёртв — мы просто не спросили.
            return {"status": "unknown",
                    "reason": "DNS не удалось спросить через прокси (домен не проверен)",
                    "mx_record": "N/A"}
        if not mx_records:
            return {"status": "invalid", "reason": "No MX/A records (Dead Domain)", "mx_record": "N/A"}

        # Куда идти НЕЛЬЗЯ. Хозяин чужого домена сам пишет свои DNS-записи, и
        # `MX 0 192.168.1.50` уводит подключение внутрь НАШЕЙ сети. Замерено
        # на живом коде: избирательный сервер внутри сети давал вердикт
        # `valid` на ящик, которого нигде нет. Половину случая закрывала
        # тройная проба catch-all, но только когда внутренний сервер
        # принимает всё подряд.
        #
        # Отброшенные хосты НАЗЫВАЮТСЯ: молчаливое отбрасывание выглядело бы
        # как «у домена нет MX», то есть превратило бы дыру безопасности в
        # ложный Invalid.
        отброшено = []
        if литерал is None:
            mx_records, отброшено = filter_mx_hosts(mx_records)
        if отброшено and not mx_records:
            # Все MX ведут внутрь. Это НЕ приговор ящику: у домена может быть
            # настоящая внутренняя почта, просто снаружи её не проверить.
            return {"status": "unknown",
                    "reason": "Проверить нечем: %s" % отброшено[0][1],
                    "mx_record": "N/A",
                    "mx_rejected": [х for х, _п in отброшено]}

        # Шаг 2: Защита от попадания в Blacklist (AV Honeypot-ловушки)
        av_vendors = [
            "fireeye.com",
            "phishline.com", "perimeterwatch.com",
            "agari.com", "emailsecurity.trendmicro.com"
        ]
        for mx in mx_records:
            mx_lower = mx.lower()
            if any(vendor in mx_lower for vendor in av_vendors):
                return {"status": "trap", "reason": "AV Vendor (Dangerous)", "mx_record": mx}

        primary_mx = mx_records[0]

        # Шаг 2.5: Почтовый шлюз безопасности перед доменом.
        # Proofpoint, Mimecast, IronPort и прочие принимают ЛЮБОЙ адрес и
        # фильтруют письмо позже — домен за таким шлюзом catch-all по
        # конструкции. Тройная проба выяснит то же самое, но потратит три
        # подключения и не объяснит причину.
        gateway = security_gateway(mx_records)
        if gateway:
            result = self.stealth_smtp_ping(probe_email, mx_records,
                                            avoid_exit_of=avoid_exit_of,
                                            prefer_exit_of=prefer_exit_of)
            if result["status"] == "valid":
                result["status"] = "catchall"
                result["reason"] = (f"Catch-All: почтовый шлюз {gateway} "
                                    "принимает любой адрес")
            result["mx_record"] = primary_mx
            result["mx_records"] = mx_records
            return result

        # Шаг 3: Catch-All проверка (не для гигантов — они точно не Catch-All)
        # ОДИН список на весь модуль — см. NEVER_CATCHALL и _is_never_catchall.
        # Пока он был набран здесь отдельно, долгая память о нём не знала и
        # записывала в себя ровно то, что эта ветка переименовывала в
        # тарпитинг несколькими строками ниже. Это и был дефект Б4: две копии
        # одного знания расходятся молча.
        #
        # mail.ru/bk.ru/inbox.ru/list.ru в списке НЕТ намеренно. Проверено
        # вживую: они отвечают 250 на любой случайный адрес, то есть являются
        # настоящим catch-all. Пока они там были, их несуществующие ящики
        # уходили в Valid.
        skip_catchall = self._is_never_catchall(domain)

        if not skip_catchall:
            is_catchall = self.is_catch_all_domain(domain, primary_mx)
            if is_catchall:
                # Для Catch-All доменов: всё равно делаем пинг, но помечаем результат
                result = self.stealth_smtp_ping(probe_email, mx_records,
                                                avoid_exit_of=avoid_exit_of,
                                                prefer_exit_of=prefer_exit_of)
                if result["status"] == "valid":
                    # Сервер принял — но домен Catch-All, так что это ненадёжно
                    result["status"] = "catchall"
                    result["reason"] = "Catch-All Domain (Unverifiable)"
                result["mx_record"] = primary_mx
                result["mx_records"] = mx_records
                return result

        # Шаг 4: Обычный Stealth SMTP Ping (с мульти-MX — п.3.1).
        #
        # control_probe включаем там, где тройная проба могла соврать: на
        # обычном домене её отрицательный ответ мог быть сорвавшейся пробой.
        #
        # У гигантов catch-all исключён по определению — НО «по определению»
        # верно только для чистого исходящего адреса. Столкнувшись с перебором
        # адресов с подозрительного IP, крупные почтовики перестают отвечать
        # честно и начинают принимать ЛЮБОГО получателя: так они не дают
        # выяснить, какие ящики существуют. Для нас это худший из возможных
        # ответов — сплошные Valid, ни один из которых ничего не значит, и
        # владелец узнаёт правду только после рассылки по отскокам.
        #
        # Поэтому у гигантов контроль тоже идёт, но изредка: лишний RCPT в уже
        # открытой сессии стоит один пакет, а на миллионной базе и он заметен.
        control = not skip_catchall
        if skip_catchall:
            control = self._time_to_recheck(domain)
        result = self.stealth_smtp_ping(probe_email, mx_records,
                                        control_probe=control,
                                        avoid_exit_of=avoid_exit_of,
                                        prefer_exit_of=prefer_exit_of)

        # Гигант, принявший выдуманный адрес, — это не catch-all, а тарпитинг.
        # Называть вещи своими именами здесь важнее обычного: «домен catch-all»
        # заставит владельца искать проблему в базе, а искать её надо в прокси.
        if skip_catchall and result.get("status") == "catchall":
            result["reason"] = (
                "Сервер принимает любые адреса — похоже, наш IP под "
                "подозрением и почтовик защищается от перебора. Вердикт "
                "недоказуем; нужен чистый прокси")
            with self.catchall_lock:
                self._tarpit_domains.add(domain)

        # Шаг 4.5: сервер, отвергающий обязательный адрес, теряет право
        # хоронить наш. Спрашиваются postmaster@ и abuse@ — оба обязательны и
        # оба в одной сессии, второй нужен ровно когда первый не ответил.
        #
        # Проверяем ТОЛЬКО перед вердиктом invalid: это одна лишняя сессия на
        # домен, и тратить её на живые адреса незачем. Если сервер нарушает
        # обязательный пункт RFC 5321 §4.5.1, его "550 user unknown" — это не
        # доказательство отсутствия ящика, а привычка отвечать всем одинаково.
        if result["status"] == "invalid":
            honored = self.postmaster_is_honored(domain, primary_mx)
            if honored is False:
                result["status"] = "risky"
                result["reason"] = ("550, но сервер отвергает и служебный "
                                    "адрес (postmaster@ / abuse@) — его "
                                    "отказам верить нельзя")
                result["postmaster_honored"] = False

        # Шаг 5: DNS-здоровье как бонус (п.2.2 + DKIM)
        # Если SMTP дал unknown, но DNS показывает здоровый домен — помечаем как Risky (не Unknown)
        if result["status"] in ("unknown", "greylisted"):
            dns_health = self.check_dns_health(domain)
            if dns_health["score"] >= 1:
                dns_tag = f" [DNS: SPF={'✓' if dns_health['has_spf'] else '✗'}, DMARC={'✓' if dns_health['has_dmarc'] else '✗'}, DKIM={'✓' if dns_health.get('has_dkim') else '✗'}]"
                # Домен имеет SPF/DMARC/DKIM — он точно почтовый, просто SMTP не ответил
                if result["status"] == "greylisted":
                    result["status"] = "greylisted"  # Оставляем для retry в pipeline
                    result["reason"] += dns_tag
                else:
                    result["status"] = "risky"
                    result["reason"] += dns_tag

        # Greylisted без retry оставляем как greylisted — pipeline сделает retry (п.2.4)
        if result["status"] == "greylisted":
            pass  # НЕ меняем на risky — pipeline сам перепроверит

        # Правило имени пользователя вступает в дело ТОЛЬКО здесь и только
        # когда сеть вердикта не дала. Если сервер сказал 250, значит ящик из
        # старых, заведённых до введения правила, — и он живой, спорить не с
        # чем. А вот молчание сервера плюс нарушение правила вместе означают
        # адрес, на который лучше не писать: это risky, а не «неизвестно».
        if rule_verdict == LOCAL_UNLIKELY and result["status"] in ("unknown", "risky"):
            result["status"] = "risky"
            result["reason"] = f"{result.get('reason', '')} | {rule_reason}".strip(" |")

        result["mx_record"] = primary_mx
        result["mx_records"] = mx_records
        return result
