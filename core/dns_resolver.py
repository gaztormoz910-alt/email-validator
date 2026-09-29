# core/dns_resolver.py
"""DNS через прокси — последний канал, по которому утекал настоящий IP.

Обычный резолвер ходит на 8.8.8.8 напрямую по UDP, а SOCKS-прокси UDP чаще
всего не пропускает. Для валидатора это утечка не мелкая: публичный DNS видел
и адрес проверяющего, и ПОЛНЫЙ список доменов проверяемой базы — то есть
ровно то, ради сокрытия чего покупались прокси. SMTP, Gravatar, RDAP и HTTP
уже шли через прокси, а DNS оставался прямым.

Порядок попыток: DoH поверх SOCKS, обычный DNS по TCP через SOCKS, отказ.
Прямого запроса в обход прокси нет вовсе — иначе смысл теряется.

Провайдер прокси передаётся функцией: резолверу не нужно знать, откуда тот
берётся и как выбирается.

Вторая дорожка (выбор владельца 29.09.2026, «вариант В»). На вопрос берётся
один прокси, и все шесть попыток (две DoH и четыре обычные справочные) идут
через него — это «прежняя дорожка», она не изменилась ни в чём. Умер прокси —
каждая её попытка ждёт полный таймаут: замерено 30 с на вопрос при таймауте
5 с и 90 с при 15 с. Поэтому, как только прежняя дорожка прождала впустую
(или её прокси отказал и по DoH, и по обычному DNS), ПАРАЛЛЕЛЬНО с ней
открывается вторая: те же справочные через другие прокси.

Как соединяются дорожки. Прежняя идёт в потоке вызывающего, как в старом
коде. Её ответ, если он есть, возвращается всегда. Ответ второй дорожки
берётся только на стыке попыток прежней, когда очередная попытка ничего не
дала, и только годный: положительный или заверенное DoH «нет такой записи».

Почему так, а не проще. Первая редакция («бросить мёртвый и перейти на
другой») теряла ответ: у прокси разовая заминка или молчит только DoH, а
запасной мёртв (три рецензента, симуляции против старого кода). Вторая
(«кто первым ответил, того и берём», прежняя дорожка в общем пуле) давала
ранний SERVFAIL или подменённое «домена нет» через чужой прокси вместо
верного ответа, а при 300 потоках пул переполнялся и прежняя дорожка
опаздывала (вторая рецензия). Нынешнее устройство закрывает оба: прежняя
дорожка та же и там же, вторая может только добавить ответ.
"""
import concurrent.futures
import inspect
import ipaddress
import queue
import socket
import threading
import time
from collections import OrderedDict

import dns.exception
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename
import socks

from core.proxy_transport import (PROXY_TYPES as _PROXY_TYPES, _parse_proxy,
                                  _proxy_scheme, build_proxy_dict)

__all__ = ["ProxiedResolver", "DNSUnavailable", "DOH_ENDPOINTS"]

# --- DNS через прокси --------------------------------------------------------
#
# Раньше резолвер ходил на 8.8.8.8 напрямую всегда. Это был последний канал, по
# которому реальный IP пользователя уходил наружу: публичный DNS видел и его
# адрес, и ПОЛНЫЙ список доменов проверяемой базы. SMTP, Gravatar, RDAP и HTTP
# уже шли через прокси, а DNS — нет.
#
# Теперь при заданных прокси каждый DNS-запрос идёт через тот же прокси:
#   1. DoH (POST wire-format) через socks5h. Соединение переиспользуется
#      сессией, поэтому 25 DKIM-селекторов на домен не превращаются в 25
#      TLS-рукопожатий.
#   2. Обычный DNS по TCP через SOCKS — если DoH недоступен.
#   3. Отказ. Прямого запроса в обход прокси НЕТ — ради этого всё и делалось.
DOH_ENDPOINTS = (
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
)

# Задержка для прокси, у которого её не измеряли. Ставим заведомо большую, чтобы
# при равном health score измеренные быстрые шли впереди неизвестных.
UNKNOWN_LATENCY_MS = 10000

# Сколько секунд помним, что через прокси DNS прождал впустую.
#
# Память ничего не отнимает у прокси: первым на вопрос он берётся как прежде,
# по здоровью из пула. Она только открывает вторую дорожку СРАЗУ, а не после
# ещё одного таймаута, — иначе каждый вопрос домена (MX, SPF, DMARC, DKIM,
# DNSBL) снова платил бы таймаут за тот же мёртвый прокси. Уводить первый
# выбор с «молчавшего» на «не проверенный» нельзя: рецензия показала, как
# одна заминка хорошего прокси отправляла вопросы в мёртвые, но не
# забаненные прокси пула. Две минуты — чтобы накрыть вопросы доменов, которые
# проверяются сейчас; ошибиться памятью (пометить живой) стоит лишь лишней
# параллельной попытки, а не ответа.
DNS_SILENCE_COOLDOWN_SEC = 120.0

# Сколько сессий requests держит один поток. Со второй дорожкой поток трогает
# больше разных прокси, а словарь сессий раньше не чистился вовсе.
SESSIONS_PER_THREAD = 32

# Предел потоков для параллельных попыток. Потоки создаются по нужде; при
# массовой гибели прокси попытки встают в очередь, а не плодят тысячи потоков.
LANE_THREADS = 256

_BOTH_TRANSPORTS = frozenset({"doh", "tcp"})


def _chain(exc):
    """Все исключения цепочки: причины, контекст, reason и вложенные в args."""
    seen = set()
    stack = [exc]
    while stack:
        error = stack.pop()
        if not isinstance(error, BaseException) or id(error) in seen:
            continue
        seen.add(id(error))
        yield error
        stack.extend((error.__cause__, error.__context__,
                      getattr(error, "reason", None), getattr(error, "socket_err", None),
                      getattr(error, "original_error", None)))
        stack.extend(getattr(error, "args", ()))


def _http_modules():
    """requests и urllib3 — грузятся один раз, около 0.2 с.

    Резолвер с прокси вызывает это при создании: иначе загрузка пришлась бы
    на первую же неудачную попытку первого вопроса и задержала бы его
    (сценарии второй рецензии показали лишние 0.27 с на первом вопросе).
    """
    import requests
    import urllib3
    return requests, urllib3


def _waited_in_vain(exc):
    """True — ответа ждали до конца таймаута либо до прокси не достучались вовсе.

    Только такой сбой открывает вторую дорожку сразу. Быстрый отказ (прокси
    ответил «не могу соединить», DoH вернул ошибку) значит, что прокси жив и
    отвечает, — следующую справочную спрашиваем через него же.

    Смотрим всю цепочку причин, а не верхнее исключение: requests заворачивает
    таймаут SOCKS в ConnectTimeout → MaxRetryError → ProxyConnectionError →
    TimeoutError, и верхний тип от версии к версии разный. Цепочки сняты
    живой пробой на поддельных прокси 29.09.2026 (requests 2.32, urllib3 2.7,
    PySocks 1.7.1).

    Общий urllib3.exceptions.TimeoutError сюда НЕ входит, и это не упущение:
    NewConnectionError («соединение отвергнуто», мгновенный отказ) в urllib3
    ради совместимости унаследован от ConnectTimeoutError. С ним в списке
    живой прокси, ответивший «не могу соединить», считался бы молчащим —
    это поймал тест на поддельном прокси.

    Недостижимый прокси распознаётся одинаково для обоих видов: SOCKS даёт
    socks.ProxyConnectionError, HTTP-прокси в requests — ProxyError, внутри
    которого не удалось само соединение (NewConnectionError). ProxyError с
    ответом прокси («Tunnel connection failed: 407») — это живой прокси.
    """
    requests, urllib3 = _http_modules()
    silence = (TimeoutError, dns.exception.Timeout, socks.ProxyConnectionError,
               requests.exceptions.Timeout, urllib3.exceptions.ReadTimeoutError)
    errors = list(_chain(exc))
    if any(isinstance(error, silence) for error in errors):
        return True
    proxy_error = any(isinstance(error, (requests.exceptions.ProxyError,
                                         urllib3.exceptions.ProxyError)) for error in errors)
    unreachable = any(isinstance(error, urllib3.exceptions.NewConnectionError) for error in errors)
    return proxy_error and unreachable


def _give_up_on(silent, failed_kinds):
    """Пора ли спрашивать через другой прокси.

    Прождали впустую — да. Быстрые отказы — только когда прокси отказал и по
    DoH, и по обычному DNS: такой «живой» прокси для DNS бесполезен (живой
    замер 29.09.2026: после мёртвого прокси вопрос ушёл в прокси, мгновенно
    отказывавший на всё, и потерял ответ, хотя рядом были рабочие). Отказ
    только по DoH ещё ничего не значит: DoH-справочные режут адреса прокси
    чаще, чем обычный DNS.
    """
    return silent or failed_kinds >= _BOTH_TRANSPORTS


def _accepts_exclude(provider):
    """Умеет ли провайдер прокси выдать «любой, кроме этих».

    Провайдер без такого параметра (старые вызовы и тесты с lambda) работает
    по-прежнему: одна дорожка, один прокси на весь вопрос. Спрашивать
    сигнатуру, а не ловить TypeError при вызове: TypeError изнутри самого
    провайдера молча превратился бы в «сменить не на что».
    """
    if provider is None:
        return False
    try:
        params = inspect.signature(provider).parameters.values()
    except (TypeError, ValueError):
        return False
    return any(p.name == "exclude" or p.kind is p.VAR_KEYWORD for p in params)


class _Lanes:
    """Потоки-демоны для второй дорожки.

    Только для второй дорожки: прежняя идёт в потоке вызывающего, как в
    старом коде, и очереди здесь не ждёт никогда. Вторая рецензия показала,
    что при 300 потоках валидации (так по умолчанию в окне) общий пул
    переполнялся, попытки прежней дорожки вставали в очередь, и вопрос шёл
    до 10×таймаут вместо 6. Очередь второй дорожки стоит только скорости,
    а не ответа.

    Не ThreadPoolExecutor: тот при выходе из программы ждёт незаконченные
    задачи, а брошенная попытка через мёртвый прокси висит до двух таймаутов —
    окно закрывалось бы с задержкой до полуминуты.
    """

    def __init__(self, limit):
        self._limit = limit
        self._queue = queue.SimpleQueue()
        self._lock = threading.Lock()
        self._threads = 0
        self._idle = 0
        self._pending = 0

    def submit(self, fn, *args):
        future = concurrent.futures.Future()
        # Поток добавляется, когда задач в очереди больше, чем свободных
        # потоков. Сравнивать только «свободных нет» мало: две задачи, поданные
        # разом при одном свободном потоке, сели бы на него обе, и вторая
        # ждала бы, пока первая досидит таймаут.
        with self._lock:
            self._pending += 1
            spawn = self._pending > self._idle and self._threads < self._limit
            if spawn:
                self._threads += 1
        if spawn:
            try:
                threading.Thread(target=self._work, name="dns-lane", daemon=True).start()
            except Exception as exc:
                # Поток не запустился (кончилась память или предел ОС):
                # вторая дорожка не откроется, прежняя идёт своим ходом.
                with self._lock:
                    self._threads -= 1
                    self._pending -= 1
                future.set_exception(exc)
                return future
        self._queue.put((future, fn, args))
        return future

    def _work(self):
        while True:
            with self._lock:
                self._idle += 1
            future, fn, args = self._queue.get()
            with self._lock:
                self._idle -= 1
                self._pending -= 1
            try:
                if future.set_running_or_notify_cancel():
                    try:
                        future.set_result(fn(*args))
                    except BaseException as exc:
                        future.set_exception(exc)
            finally:
                # Простаивающий поток не должен держать последнюю задачу:
                # через fn держится резолвер, через его провайдера — весь
                # NetworkValidator с кэшами и сессиями прошлого прогона.
                future = fn = args = None


_LANES = _Lanes(LANE_THREADS)


class _Race:
    """Один вопрос, две дорожки: что нашла вторая и когда ей пора выйти."""

    def __init__(self):
        self.cond = threading.Condition()
        self.response = None      # принятый ответ второй дорожки
        self.proxy = None
        self.closed = False       # вопрос кончен — второй дорожке пора выйти

    @property
    def answered(self):
        return self.response is not None

    def offer(self, response, proxy):
        with self.cond:
            if self.response is None and not self.closed:
                self.response = response
                self.proxy = proxy
            self.cond.notify_all()

    def close(self):
        with self.cond:
            self.closed = True
            self.cond.notify_all()

    def poke(self, _future=None):
        with self.cond:
            self.cond.notify_all()


def _is_local_address(host):
    """Адрес, до которого через чужой прокси не дойти: частный, петля, link-local."""
    try:
        address = ipaddress.ip_address(str(host).strip("[]"))
    except ValueError:
        return False
    return (address.is_private or address.is_loopback or address.is_link_local
            or address.is_unspecified or address.is_multicast)


def _has_data(response, rdtype):
    """Положительный ответ: NOERROR и есть записи того вида, о котором спросили."""
    return (response.rcode() == dns.rcode.NOERROR
            and any(rrset.rdtype == rdtype for rrset in response.answer))


def _second_lane_accepts(response, rdtype, kind):
    """Годится ли ответ второй дорожки как ответ на вопрос.

    Положительный — да. «Нет такой записи» (NXDOMAIN или пустой NOERROR) —
    только от DoH: его заверяет TLS Cloudflare или Google, это тот же ответ,
    что прежняя дорожка получила бы первой попыткой. Тот же ответ по обычному
    DNS через чужой бесплатный прокси мог подменить сам прокси, а ложное
    «домена нет» по MX — это ложный «Мёртв». SERVFAIL и прочие коды — не
    ответ, а неудача попытки: вторая рецензия показала, как ранний SERVFAIL
    второй дорожки перебивал верный ответ прежней. «Нет» по обычному DNS
    принимается ещё в одном случае — когда два разных прокси сказали одно и
    то же (это решает сама вторая дорожка, см. _second_lane).
    """
    if _has_data(response, rdtype):
        return True
    return kind == "doh" and response.rcode() in (dns.rcode.NXDOMAIN, dns.rcode.NOERROR)


def _negative_kind(response, rdtype):
    """«Нет такой записи»: 'nx' (домена нет), 'nodata' (домен есть, записи нет) или None."""
    if response.rcode() == dns.rcode.NXDOMAIN:
        return "nx"
    if response.rcode() == dns.rcode.NOERROR and not _has_data(response, rdtype):
        return "nodata"
    return None


class DNSUnavailable(dns.exception.DNSException):
    """DNS спросить не удалось: прокси заданы, но ни один транспорт не ответил.

    Отличать от NXDOMAIN обязательно. «Не смогли проверить» — это не
    «домена не существует»: иначе живой домен уедет в Invalid как мёртвый.
    """


class ProxiedResolver:
    """Резолвер с интерфейсом dns.resolver.Resolver.resolve().

    Без прокси ведёт себя ровно как раньше — обычный резолвер на 8.8.8.8/1.1.1.1.
    С прокси заворачивает запрос в тот же прокси, что и SMTP.

    public_doh=False — для резолвера со СВОИМИ справочными (Spamhaus): вопрос
    идёт только к ним. Публичные DoH (Cloudflare, Google) такому резолверу
    не замена: Spamhaus им отвечает отказом 127.255.255.254, и контракт зоны
    при заданных прокси не проходил никогда.
    """

    def __init__(self, nameservers, timeout, proxy_provider=None, public_doh=True):
        self._plain = dns.resolver.Resolver()
        self._plain.nameservers = list(nameservers)
        self._plain.timeout = timeout
        self._plain.lifetime = timeout
        self.nameservers = self._plain.nameservers
        self.timeout = timeout
        self.lifetime = timeout
        self._proxy_provider = proxy_provider
        self._provider_excludes = _accepts_exclude(proxy_provider)
        self._public_doh = bool(public_doh)
        if proxy_provider is not None:
            _http_modules()
        # Сессии requests не потокобезопасны — держим по одной на поток.
        self._local = threading.local()
        # Прокси, через которые DNS этого резолвера недавно прождал впустую:
        # прокси -> до какого момента (time.monotonic) помнить. Общая для всех
        # потоков этого резолвера; у резолвера Spamhaus — своя.
        self._silent = {}
        self._silent_lock = threading.Lock()

    def resolve(self, qname, rdtype='A'):
        """Контракт proxy_provider(exclude=()):
            None  — прокси не заданы, идём напрямую (прежнее поведение)
            ""    — прокси заданы, но живых нет (или все живые в exclude):
                    спрашивать нельзя, это утечка
            str   — идём через этот прокси
        Параметр exclude необязателен: без него второй дорожки не будет.
        """
        proxy = self._proxy_provider() if self._proxy_provider else None
        if proxy is None:
            return self._plain.resolve(qname, rdtype)
        if not proxy:
            raise DNSUnavailable("прокси заданы, но живых не осталось")

        rd = dns.rdatatype.from_text(rdtype) if isinstance(rdtype, str) else rdtype
        query = dns.message.make_query(qname, rd)
        attempts = self._attempts()
        # Потолок второй дорожки: не начинать попыток позже, чем прежняя
        # дорожка кончилась бы на мёртвом прокси (все попытки по таймауту).
        deadline = time.monotonic() + len(attempts) * self.timeout
        race = _Race()
        second = None

        def open_second(start):
            nonlocal second
            if second is None and self._provider_excludes:
                second = _LANES.submit(self._second_lane, query, rd, attempts, proxy,
                                       start, deadline, race)
                second.add_done_callback(race.poke)

        try:
            if self._provider_excludes and proxy in self._recently_silent():
                open_second(0)

            # Прежняя дорожка: ровно как раньше — все справочные по очереди
            # через один прокси, в этом же потоке. Ответ второй дорожки берётся
            # только на стыке попыток, когда очередная попытка прежней ничего
            # не дала: ответ, который старый код получал в этой попытке, не
            # теряется и не опаздывает.
            failed = set()
            for index, (kind, ask, target) in enumerate(attempts):
                if race.answered:
                    break
                response, silent = self._attempt(ask, target, query, proxy)
                if response is not None:
                    self._forget_silence(proxy)
                    return self._extract(response, rd)
                if silent:
                    self._remember_silence(proxy)
                else:
                    failed.add(kind)
                if _give_up_on(silent, failed):
                    open_second(index + 1)

            if second is not None and not race.answered:
                # Прежняя дорожка кончилась без ответа. Ждём вторую — не дольше
                # потолка и не дольше двух таймаутов сверх конца прежней: если
                # первый прокси отказал на всё мгновенно, старый код сдавался
                # сразу, и ждать за это полные 6×таймаут было бы слишком.
                limit = min(deadline, time.monotonic() + 2 * self.timeout)
                with race.cond:
                    race.cond.wait_for(lambda: race.answered or second.done(),
                                       timeout=max(0.0, limit - time.monotonic()))
            with race.cond:
                found = race.response
            if found is not None:
                return self._extract(found, rd)
            raise DNSUnavailable("ни DoH, ни DNS-over-TCP через прокси не ответили")
        finally:
            race.close()

    def _second_lane(self, query, rd, attempts, first_proxy, start, deadline, race):
        """Вторая дорожка: тот же вопрос через другие прокси.

        Через каждый запасной прокси — сначала обычный DNS по TCP, и только
        если он сразу отказал — DoH. Такой порядок взят из живых замеров
        29.09.2026 на списке владельца: обычный DNS через прокси отвечал у
        ~150 из 1394, а DoH быстро — у 0–4 из 20 самых быстрых. Прежний
        порядок («сначала DoH») тратил запасные прокси на DoH-таймауты, и до
        обычного DNS не доходило.

        Прокси меняется, когда через него прождали впустую (скорее всего,
        он мёртв), когда он отказал по обоим видам или когда его «нет» нужно
        подтвердить другим прокси. Справочные чередуются между прокси.
        Попыток не больше двух на каждую справочную и ни одной после потолка
        или конца вопроса. Сменить не на кого — дорожка кончается: прежняя
        идёт своим ходом.

        Какие ответы принимаются — _second_lane_accepts; «нет» по обычному
        DNS — только подтверждённое вторым прокси (см. ниже).
        """
        tcp = [(kind, ask, target) for kind, ask, target in attempts if kind == "tcp"]
        doh = [(kind, ask, target) for kind, ask, target in attempts if kind == "doh"]
        tried = {first_proxy}
        proxy = self._other_proxy(tried)
        turn = start
        budget = 2 * len(attempts)
        # «Нет такой записи» по обычному DNS через чужой прокси: одно — не
        # доказательство (прокси мог подменить), два одинаковых через разные
        # прокси — доказательство. Тот же принцип, что у второго мнения SMTP с
        # другого выхода. Без этого живой замер 29.09 терял настоящее «нет»
        # (DKIM-селектора нет): заверить «нет» через DoH было нечем.
        heard_no = None
        while proxy and budget > 0:
            tried.add(proxy)
            plan = [pick[turn % len(pick)] for pick in (tcp, doh) if pick]
            turn += 1
            for kind, ask, target in plan:
                if race.closed or race.answered or time.monotonic() >= deadline or budget <= 0:
                    return
                budget -= 1
                response, silent = self._attempt(ask, target, query, proxy)
                if response is not None and _second_lane_accepts(response, rd, kind):
                    self._forget_silence(proxy)
                    race.offer(response, proxy)
                    return
                no = _negative_kind(response, rd) if response is not None else None
                if no is not None:
                    if heard_no is not None and heard_no[0] == no and heard_no[1] != proxy:
                        self._forget_silence(proxy)
                        race.offer(response, proxy)
                        return
                    if heard_no is None:
                        heard_no = (no, proxy)
                    # за подтверждением — к другому прокси
                    break
                if silent:
                    self._remember_silence(proxy)
                    # прождали впустую — прокси, скорее всего, мёртв
                    break
                # Быстрый отказ: прокси жив — пробуем через него другой вид.
            if race.closed or race.answered:
                return
            # Прокси сказал своё (молчание, «нет» или отказ по обоим видам) —
            # дальше через другой.
            proxy = self._other_proxy(tried)

    def _attempts(self):
        doh = [("doh", self._ask_doh, url) for url in DOH_ENDPOINTS] if self._public_doh else []
        return doh + [("tcp", self._ask_tcp, nameserver) for nameserver in self.nameservers]

    def _attempt(self, ask, target, query, proxy):
        """Одна попытка: (ответ или None, прождали ли впустую).

        Исключение попытки — это её исход, а не сбой вопроса: прежний код
        глушил их так же и шёл к следующей справочной.
        """
        try:
            return ask(target, query, proxy), False
        except Exception as exc:
            return None, _waited_in_vain(exc)

    def _other_proxy(self, tried):
        """Прокси для второй дорожки или None — «спросить больше не через кого».

        None никогда не означает «напрямую»: вторая дорожка без прокси не
        открывается. Сначала — среди не молчавших недавно, потом среди всех,
        кроме уже опрошенных в этом вопросе. Ошибка провайдера посреди
        вопроса — тоже «не через кого»: иначе она вышла бы из resolve() не как
        DNSUnavailable, и проверка DNSBL приняла бы её за «IP чист».
        """
        if not self._provider_excludes:
            return None
        avoid = frozenset(tried)
        wider = avoid | self._recently_silent()
        for exclude in ((wider, avoid) if wider != avoid else (avoid,)):
            try:
                other = self._proxy_provider(exclude=exclude)
            except Exception:
                return None
            if other and other not in avoid:
                return other
        return None

    def _recently_silent(self):
        now = time.monotonic()
        with self._silent_lock:
            for proxy in [p for p, until in self._silent.items() if until <= now]:
                del self._silent[proxy]
            return frozenset(self._silent)

    def _remember_silence(self, proxy):
        with self._silent_lock:
            self._silent[proxy] = time.monotonic() + DNS_SILENCE_COOLDOWN_SEC

    def _forget_silence(self, proxy):
        # Ответил — значит жив, и прежнее молчание уже ничего о нём не говорит.
        with self._silent_lock:
            self._silent.pop(proxy, None)

    def _session(self, proxy):
        store = getattr(self._local, "sessions", None)
        if store is None:
            store = OrderedDict()
            self._local.sessions = store
        session = store.get(proxy)
        if session is not None:
            store.move_to_end(proxy)
            return session
        import requests
        session = requests.Session()
        # Переменные HTTPS_PROXY и системный прокси Windows у requests главнее
        # proxies сессии — вопрос ушёл бы не через прокси пула, а мимо него.
        session.trust_env = False
        session.headers.update({
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message",
            "User-Agent": "Mozilla/5.0",
        })
        session.proxies.update(build_proxy_dict(proxy) or {})
        store[proxy] = session
        while len(store) > SESSIONS_PER_THREAD:
            _, old = store.popitem(last=False)
            try:
                old.close()
            except Exception:
                pass
        return session

    # Одна попытка: ответ, None («ответили, но не тем» — прокси жив) или
    # исключение. Исключения не глушатся здесь: по ним _attempt решает,
    # прождали ли впустую.
    def _ask_doh(self, url, query, proxy):
        # Строку прокси не разобрать — не спрашиваем вовсе: сессия без proxies
        # отправила бы вопрос напрямую, с домашнего IP.
        if not build_proxy_dict(proxy):
            return None
        resp = self._session(proxy).post(url, data=query.to_wire(), timeout=self.timeout)
        if resp.status_code == 200 and resp.content:
            return dns.message.from_wire(resp.content)
        return None

    def _ask_tcp(self, nameserver, query, proxy):
        # Частный, петлевой или локальный адрес справочной через чужой прокси
        # не спрашиваем: прокси стучался бы в СВОЮ локальную сеть, а не в
        # нашу. Такие адреса бывают среди системных резолверов, которые
        # перебирает поиск Spamhaus (на машине владельца — два из пяти).
        if _is_local_address(nameserver):
            return None
        parsed = _parse_proxy(proxy)
        if not parsed:
            return None
        pip, pport, puser, ppass = parsed
        ptype = _PROXY_TYPES.get(_proxy_scheme(proxy), socks.SOCKS5)
        sock = socks.socksocket()
        try:
            sock.set_proxy(ptype, pip, pport, username=puser, password=ppass)
            sock.settimeout(self.timeout)
            sock.connect((nameserver, 53))
            # DNS по UDP через SOCKS5 работает не везде, по TCP — везде.
            return dns.query.tcp(query, nameserver, timeout=self.timeout, sock=sock)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    @staticmethod
    def _extract(response, rdtype):
        """Превращает ответ в список rdata — то же, что отдаёт обычный резолвер."""
        rcode = response.rcode()
        if rcode == dns.rcode.NXDOMAIN:
            raise dns.resolver.NXDOMAIN
        if rcode != dns.rcode.NOERROR:
            raise DNSUnavailable(f"DNS rcode {dns.rcode.to_text(rcode)}")
        items = []
        for rrset in response.answer:
            if rrset.rdtype == rdtype:
                items.extend(rrset)
        if not items:
            raise dns.resolver.NoAnswer
        return items


# Домен почтовика -> двухбуквенный код страны. Нужен, чтобы сверить страну
# домена получателя со страной выходного IP прокси (RDAP отдаёт именно код).
#
# Своей таблицы стран здесь нет и быть не должно: core/provider.py уже знает
# страну домена по названию, и держать второй список значило бы обречь их на
# расхождение. Здесь только перевод названия в код.
_COUNTRY_TO_CODE = {
    "Германия": "DE", "Франция": "FR", "Италия": "IT", "Испания": "ES",
    "Великобритания": "GB", "Нидерланды": "NL", "Бельгия": "BE",
    "Польша": "PL", "Россия": "RU", "Украина": "UA", "Беларусь": "BY",
    "Казахстан": "KZ", "Швеция": "SE", "Норвегия": "NO", "Дания": "DK",
    "Финляндия": "FI", "США": "US", "Канада": "CA", "Австралия": "AU",
    "Новая Зеландия": "NZ", "Китай": "CN", "Южная Корея": "KR",
    "Япония": "JP", "Индия": "IN", "Бразилия": "BR", "Мексика": "MX",
    "Аргентина": "AR", "Чехия": "CZ", "Словакия": "SK", "Венгрия": "HU",
    "Румыния": "RO", "Болгария": "BG", "Австрия": "AT", "Швейцария": "CH",
    "Португалия": "PT", "Греция": "GR", "Турция": "TR", "Израиль": "IL",
    "Ирландия": "IE", "Эстония": "EE", "Латвия": "LV", "Литва": "LT",
    "ЮАР": "ZA", "ОАЭ": "AE", "Саудовская Аравия": "SA", "Египет": "EG",
    "Марокко": "MA", "Нигерия": "NG", "Кения": "KE", "Вьетнам": "VN",
    "Таиланд": "TH", "Индонезия": "ID", "Малайзия": "MY", "Сингапур": "SG",
    "Филиппины": "PH", "Пакистан": "PK",
}


