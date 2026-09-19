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
from core.runstate import (RunState, run_id_for, DEFAULT_RETRY_DELAY,
                           GREYLIST_RETRY_DELAY)
from core.canary import CanaryWatch, canary_address
from core.verdict import verdict_confidence
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
# Примеси рядом — по одному файлу на тему. Все три работают с тем же
# объектом и тем же состоянием из __init__: файл поделён, поведение нет.
from core.pipeline_setup import PipelineSetupMixin
from core.enrichment import (EnrichmentMixin, AI_SUSPICION_PENALTY,
                             _enrich_signature, _utc_now, _as_utc, _fmt_stamp)
from core.verdict_revision import VerdictRevisionMixin
from core.heuristics import (extract_birth_year, looks_machine_generated,
                             is_parked_domain, is_role_based)
from core.parser_pipeline import GLOBAL_VERIFIED_DOMAINS
from core.paths import data_path


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
    # Отказ по репутации нашего выходного адреса и отказ отправителю. Это
    # САМЫЕ восстановимые из всех «не проверено»: сервер не сказал про ящик
    # ничего, он отказал НАМ. Раньше такие адреса не повторялись вовсе —
    # маркеры были только английские, а формулировки классификатора русские, —
    # и оставались Unknown навсегда. Теперь повтор идёт с другого выходного
    # адреса (см. defer/retry_one ниже), то есть ровно тем, что здесь и нужно.
    "отказ по политике/репутации",
    "отказ отправителю/релею",
    # На сервере кончилось место — это про ИХ диск, а не про ящик, и через
    # несколько минут проходит.
    "кончилось место",
)

# Сколько РАЗ адрес может уйти на перепроверку.
#
# Один круг закрывает случай «сорвалось у нас, со второго выхода получилось».
# Второй нужен для другого случая: первый повтор тоже не дошёл (лимит на том
# же почтовике, второй грязный выход, вторая выдержка серого списка). Дальше
# смысла нет — на третьем круге те же адреса дают тот же ответ, а хвост
# прогона растёт на каждую попытку.
MAX_RETRY_ROUNDS = 2

# Эти Unknown повторять бессмысленно — ответ не изменится от смены прокси
_PERMANENT_UNKNOWN_MARKERS = (
    "catch-all", "catchall", "fcrdns", "обратного dns", "не проверяется",
)


def _is_transient_failure(raw_status: str, reason: str) -> bool:
    """True, если «не проверено» вызвано сбоем НАШЕЙ стороны и стоит повтора.

    Почему сюда попал ещё и `risky`. Отказ по репутации нашего выходного IP
    приходит из классификатора как `unknown` — но шаг «DNS-здоровье» в
    check_email повышает его до `risky`, если у домена есть SPF или DMARC, то
    есть почти всегда. Это утверждение про ДОМЕН; про ящик по-прежнему не
    сказано ничего, и повтор с другого выхода нужен ровно так же. Пока сюда
    пускали только `unknown`, самые восстановимые отказы не повторялись
    никогда — именно те, где смена выходного адреса и есть весь ответ.

    Настоящие вердикты (`valid`, `invalid`, `catchall`) не повторяются: ответ
    получен. `greylisted` тоже — у него своя очередь и своя выдержка.
    """
    if raw_status not in ("unknown", "risky"):
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


class ValidationPipeline(PipelineSetupMixin, EnrichmentMixin,
                         VerdictRevisionMixin):
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

        # Второе мнение о «Годен» включено С МОМЕНТА СОЗДАНИЯ, а не
        # только после start(). CLI зовёт run_pipeline напрямую, и
        # раньше там читалось getattr(self, 'confirm_valid', False) —
        # то есть из командной строки настройка была выключена
        # всегда, что бы ни стояло в подписи start().
        self.confirm_valid = True

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
        
















    def _phase(self, name, count=0):
        """Сообщает окну, чем конвейер занят сейчас. Необязательный канал.

        Классическое окно этого обработчика не ставит, и это нормально:
        отсутствие канала не должно ронять прогон.
        """
        handler = self.callbacks.get('on_phase')
        if handler is None:
            return
        try:
            handler(str(name or ""), int(count or 0))
        except Exception:
            pass

    def _emit(self, email, status, reason, mx, data):
        """Единственная дверь наружу для результата.

        Отдельным методом, потому что считать надо в ОДНОМ месте: результат
        отправляется из семи разных веток, и счётчик, размазанный по ним,
        разойдётся с действительностью на первой же правке.
        """
        with self._emitted_lock:
            self._emitted += 1
        self.callbacks['on_result'](email, status, reason, mx, data)

    def run_pipeline(self, email_sources, threads=50, fix_typos=True,
                     check_spam=True, deep_ping=True, enable_ai=True,
                     enable_osint=True, resume=True):
        """Прогон базы. ВСЕ ПЯТЬ настроек качества включены по умолчанию.

        Раньше отсев роботов, обогащение и продолжение прерванного прогона
        приходили сюда выключенными, и включались только из окна. Владелец
        просил обратное: включено под капотом, а из окна убрано, чтобы не
        щёлкать вручную перед каждым прогоном. Значит и CLI, и любой другой
        вызов обязаны получать то же поведение — иначе «под капотом» было бы
        неправдой ровно там, где окна нет.
        """
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

        def defer(email, data, is_role, delay=DEFAULT_RETRY_DELAY, proxy=None,
                  reason="", same_exit=False, attempts=0):
            # Пятым полем едет прокси, через который вышел неудачный ответ.
            # Повтор ТЕМ ЖЕ выходом — потраченное время: у greylisting запись
            # ведётся по тройке (IP, отправитель, получатель), а временный
            # отказ по репутации с того же IP повторится дословно.
            #
            # Шестым — причина, по которой адрес сюда попал. Нужна страховке
            # в конце: если до перепроверки дело не дошло (нажали «Стоп»),
            # владелец должен увидеть НАСТОЯЩУЮ причину, а не слово
            # «Greylisted» на адресе, которого серый список не касался.
            greylisted_queue.put((email, data, is_role,
                                  time.monotonic() + max(0.0, float(delay)),
                                  proxy, reason or "", bool(same_exit),
                                  int(attempts)))

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

        # Канарейки живут ОДИН прогон: врущим выход становится не навсегда, а
        # на время, и почтовик отпускает подозрение сам. Запомнив это между
        # запусками, мы повторили бы дефект Б4, где тарпитинг оседал в долгой
        # памяти и хоронил всю почту gmail на месяц.
        self.canary = CanaryWatch()
        
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
            # Сначала — поимённо о тех, кто выбыл с прошлого раза. Прокси
            # уходит из ротации после сбоев на РАЗНЫХ серверах: это либо
            # закрывшийся порт 25, либо мёртвый адрес. Пока об этом молчали,
            # владелец видел лишь замедление, а причину — никогда.
            if self.network is not None:
                try:
                    gone = self.network.take_recent_bans()
                except Exception:
                    gone = []
                for proxy in gone:
                    self.callbacks['on_log'](
                        f"[DEAD] Прокси выбыл из ротации: {proxy}. Сбои шли на "
                        "разных серверах — похоже, закрылся порт 25 или адрес "
                        "перестал отвечать.", "dead")
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
                # Вердикт вынесен НАМИ по списку, а не сервером. Уверенность
                # высокая, но основание должно называть источник: владелец
                # вправе знать, что сюда сеть не привлекалась.
                data["verdict_confidence"] = 95
                data["verdict_basis"] = ("домен из списка одноразовых: ящик "
                                         "живёт минуты и создан, чтобы его "
                                         "бросить")
                data["provider_name"] = "Disposable"
                data["domain_type"] = "Disposable"
                # ПОДСКАЗКА ОБ ОПЕЧАТКЕ НЕ ТЕРЯЕТСЯ. Домены-опечатки вроде
                # gmial.com стоят в списках одноразовых по праву: их заводят
                # ради обмана. Но для владельца это ещё и след настоящего
                # контакта — человек хотел написать на gmail.com. Вердикт
                # «слать нельзя» остаётся, а подсказка кладётся рядом.
                self._подсказать_опечатку(email, data, fix_typos)
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
                    # Та же причина, что и шагом выше: вердикт остаётся, а
                    # след настоящего контакта не выбрасывается.
                    self._подсказать_опечатку(email, data, fix_typos)
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
                                    "domain_type", "has_gravatar",
                                    "verdict_confidence", "verdict_basis")
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
                    # Уверенность у адреса из кэша.
                    #
                    # Когда настройки обогащения не менялись, весь блок выше
                    # проходит мимо _enrich_and_score — и адрес приезжал БЕЗ
                    # уверенности. Пустая колонка ровно там, где вердикт взят
                    # из прошлого прогона, — это та же ложная уверенность,
                    # только молчаливая. Считаем по сохранённому статусу и
                    # причине: сеть для этого не нужна.
                    if not data.get("verdict_basis"):
                        confidence, basis = verdict_confidence(
                            cached["status"], cached.get("reason", ""))
                        data["verdict_confidence"] = confidence
                        data["verdict_basis"] = basis

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

                # Опечатка в домене — ПОДСКАЗКА, а не вердикт.
                #
                # Вердикт выносится о ЗАГРУЖЕННОМ адресе и остаётся при нём.
                # Если у его домена нет MX — адрес мёртв, и это доказано:
                # писать физически некуда. Похожий известный домен мы всё
                # равно спрашиваем, потому что владельцу полезно знать, что
                # за опечаткой стоит живой ящик, — но кладём это в ОТДЕЛЬНЫЕ
                # колонки, а не в статус.
                #
                # Почему так, дословно по жалобе владельца: «ты при проверке
                # ящика меняешь ему домен на другой, потом проверяешь именно
                # почту вместе с изменённым доменом и говоришь мне что он
                # валидный». Так и было: `email = suggestion`, и в колонке
                # «Годен» оказывался адрес, которого он не загружал. Отправив
                # по такой строке, он написал бы ЧУЖОМУ человеку — тому, чей
                # адрес мы угадали, а не тому, кого он собирался достать.
                #
                # Обратная ошибка тут дешевле на порядок: «мёртвый домен» с
                # припиской «похоже на опечатку, на gmail.com такой ящик
                # есть» стоит одного взгляда владельца, а ложный Valid —
                # письма не тому человеку.
                if (raw_status == "invalid"
                        and "No MX" in res.get("reason", "")
                        and fix_typos):
                    suggestion = self.cleaner.suggest_domain_fix(email)
                    if suggestion and suggestion != email:
                        fixed_res = self.network.check_email(suggestion)
                        data["suggested_email"] = suggestion
                        data["suggested_status"] = fixed_res.get("status", "")
                        if fixed_res.get("status") in ("valid", "catchall"):
                            res["reason"] = (
                                "%s. Похоже на опечатку: на %s такой ящик "
                                "есть, но проверяли и хороним МЫ ЗАГРУЖЕННЫЙ "
                                "адрес — решение за вами"
                                % (res.get("reason", ""),
                                   suggestion.rsplit("@", 1)[1]))

                # Greylisted — в очередь на повтор, и ждём столько, сколько
                # серые списки просят: повтор раньше выдержки получает тот же
                # серый ответ, то есть тратится впустую. См. core/runstate.py.
                if raw_status == "greylisted":
                    # ТЕМ ЖЕ выходом: серый список ведётся по тройке
                    # (IP, отправитель, получатель), и прийти с другого
                    # адреса значит начать выдержку заново.
                    defer(email, data, is_role, delay=GREYLIST_RETRY_DELAY,
                          proxy=res.get("proxy"), reason=res.get("reason", ""),
                          same_exit=True)
                    return False  # Вердикта нет: адрес ждёт перепроверки

                # Временный отказ (таймаут, сдохший прокси, лимит скорости, блок по
                # IP) — это НЕ вердикт о ящике, а сбой нашей стороны. Отправляем в ту
                # же очередь: через паузу лимиты отпускают, прокси восстанавливаются,
                # и повтор другим прокси часто даёт однозначный ответ вместо Unknown.
                if _is_transient_failure(raw_status, res.get("reason", "")):
                    defer(email, data, is_role, proxy=res.get("proxy"),
                          reason=res.get("reason", ""))
                    return False   # вердикта нет, прогресс не двигаем

                # Ловушка антивирусного вендора: MX домена ведёт на honeypot
                # (Trend Micro Email Security, FireEye, Agari), и движок
                # НАМЕРЕННО туда не пошёл — попасть в их чёрный список дороже
                # любого вердикта. Значит про ящик не сказано ничего.
                #
                # Раньше этот статус не знала ни одна из двух лестниц ниже, и
                # он проваливался в `else`, то есть в «Invalid/Bounce»: адрес
                # объявлялся несуществующим без единого запроса к серверу,
                # получал скор 0 с подписью «SMTP подтвердил, что ящика нет»
                # и уезжал в кэш на девяносто суток. Между тем за таким
                # шлюзом стоит обычная корпоративная почта, и ящики там
                # живые. «Trap/Disposable» — это «писать нельзя», а не
                # «ящика нет», и в кэш такой статус не кладётся вовсе
                # (см. CACHEABLE_STATUSES в core/cache.py).
                if raw_status == "trap":
                    data["engagement_score"] = 0
                    data["engagement_grade"] = "Dead"
                    data["provider_type"] = "AV Vendor"
                    уверенность, основание = verdict_confidence(
                        "trap", res.get("reason", ""))
                    data["verdict_confidence"] = уверенность
                    data["verdict_basis"] = основание
                    self._enrich_offline(email, data, "Trap/Disposable", enable_ai)
                    self._emit(email, "Trap/Disposable", res.get("reason", ""),
                               res.get("mx_record", "N/A"), data)
                    state.mark_done(normalize_for_dedup(email))
                    return

                if raw_status == "valid":
                    status_display = "Valid"
                elif raw_status == "catchall":
                    status_display = "Unknown"  # Catch-All — нельзя доверять, кладём в Unknown
                elif raw_status == "risky":
                    status_display = "Risky"
                elif raw_status == "unknown":
                    status_display = "Unknown"
                elif raw_status == "invalid":
                    status_display = "Invalid/Bounce"
                else:
                    # ЗАПАСНОЙ ВЫХОД ВЕДЁТ В «НЕ ПРОВЕРЕНО», А НЕ В ПРИГОВОР.
                    #
                    # Здесь стоял `else: Invalid/Bounce`, то есть любой статус,
                    # которого лестница не знает, хоронил адрес. Так и случилось
                    # с `trap`. Правило общее: незнакомое слово — это отсутствие
                    # доказательства, а не доказательство отсутствия.
                    status_display = "Unknown"

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

                # Второе мнение о подтверждении — по требованию владельца.
                # Не на каждом прогоне: это лишняя сессия на КАЖДЫЙ Valid.
                # Включается перед тем прогоном, после которого он собирается
                # рассылать.
                if raw_status == "valid" and getattr(self, "confirm_valid", False):
                    итог = self._second_opinion_on_valid(email, res)
                    if итог is False:
                        raw_status = "unknown"
                        status_display = "Unknown"
                        res["reason"] = (
                            "Второй выход отверг адрес, первый принял — "
                            "доказательства нет ни у одной стороны")

                # Канарейка: заведомо мёртвый адрес отдельной пробой.
                #
                # Контрольная проба спрашивает выдуманный адрес В ТОЙ ЖЕ
                # сессии и ловит catch-all — постоянное свойство домена.
                # Канарейка ловит другое: тарпитинг, включившийся ПОСРЕДИ
                # прогона, и зазор у гигантов, где контрольная проба идёт
                # лишь раз в 25 адресов. Вернувшийся на неё 250 означает, что
                # этот выход на этом домене врёт прямо сейчас.
                if raw_status == "valid":
                    self._fly_canary(email, res)

                # Доля Valid по домену — В СТРОКУ, а не только в лог.
                #
                # «У домена ВСЕ проверенные адреса ответили 250» — сильный
                # признак catch-all, и он уже считался. Но приписывался он к
                # тексту причины, а фильтровать по тексту нельзя. Числом в
                # колонке владелец отложит такие домены одним движением.
                #
                # Считаем на момент строки: к концу прогона число уточнится,
                # но строка уже уехала в таблицу, а пересчитывать всё ради
                # двух знаков после запятой не стоит той памяти.
                try:
                    with domain_stats_lock:
                        st = domain_stats.get(dom_key) or {}
                    всего = int(st.get("total") or 0)
                    if всего:
                        data["domain_valid_ratio"] = round(
                            int(st.get("valid") or 0) / float(всего), 3)
                        data["domain_checked"] = всего
                except Exception:
                    pass

                # Что именно ушло в RCPT TO. Показывается в карточке адреса
                # строкой «Проверен как». Поле читалось окном и не
                # записывалось нигде — строка была всегда пустой, то есть
                # владелец не мог убедиться СВОИМИ ГЛАЗАМИ, что проверяют
                # его адрес. Он спрашивал об этом дважды.
                try:
                    data["checked_as"] = (self.network.probe_form(email)
                                          if self.network is not None else email)
                except Exception:
                    data["checked_as"] = email

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
        # Новый проход по файлу — новый дедуп. Журнал вердиктов при этом цел:
        # проверенное по-прежнему пропускается, а прочитанное-но-непроверенное
        # возвращается в работу вместо того, чтобы молча числиться дублем.
        # Подробно — у RunState.reset_seen.
        state.reset_seen()
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
            # Решения, принятые загрузчиком по форме файла, объявляются в
            # лог. Единственное такое решение сегодня — отбраковка колонки,
            # похожей на пароли; отбраковать колонку молча значит лишить
            # владельца целой колонки данных без единой строки в логе.
            загрузчик = StreamLoader(
                email_sources,
                on_note=lambda текст: self.callbacks['on_log'](текст, "warning"))
            for email, data in загрузчик.stream_emails():
                if not self.is_running:
                    break

                # Что именно лежало в файле. Запоминается ДО очистки и едет
                # с адресом до самой выгрузки: владелец обязан видеть, что он
                # загрузил, даже если мы восстановили склеенный домен.
                loaded_as = email
                if fix_typos:
                    email = self.cleaner.clean_email(email)

                if not email:
                    continue

                if isinstance(data, dict) and loaded_as != email:
                    data["original_email"] = loaded_as

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
        # Фаза наружу: до неё окно показывало «Проверено адресов: N из N» и
        # выглядело зависшим, пока шла перепроверка. Строка в логе про это
        # была, но её надо было заметить.
        self._phase("retry", greylisted_count)
        if greylisted_count > 0 and self.is_running and deep_ping:
            
            if self.is_running:
                retry_count = 0
                retry_lock = threading.Lock()

                def retry_one(entry):
                    """Обрабатывает один отложенный адрес. Вызывается из пула потоков."""
                    nonlocal retry_count, processed_count
                    (email, data, is_role, _due,
                     first_proxy, _reason, same_exit, attempts) = entry
                    if not self.is_running:
                        return

                    # Куда идти повтору, зависит от того, ПОЧЕМУ адрес
                    # отложен. Серый список просит вернуться той же тройкой —
                    # значит тем же выходом. Временный сбой и отказ по
                    # репутации, наоборот, повторятся с того же адреса
                    # дословно — значит любым другим. Если настоять не на
                    # чем, выбор вернётся к обычному.
                    if same_exit:
                        res = self.network.check_email(
                            email, prefer_exit_of=first_proxy)
                    else:
                        res = self.network.check_email(
                            email, avoid_exit_of=first_proxy)
                    raw_status = res["status"]

                    # Второй круг. Повтор мог не дойти по той же причине, по
                    # которой не дошёл первый: лимит на том же почтовике,
                    # второй грязный выход, вторая выдержка серого списка. Тут
                    # адрес по-прежнему БЕЗ вердикта о ящике, и отдавать его
                    # как Unknown рано — если попытки ещё остались.
                    grey = raw_status == "greylisted"
                    if (attempts + 1 < MAX_RETRY_ROUNDS
                            and (grey or _is_transient_failure(
                                raw_status, res.get("reason", "")))):
                        defer(email, data, is_role,
                              delay=GREYLIST_RETRY_DELAY if grey else DEFAULT_RETRY_DELAY,
                              proxy=res.get("proxy") or first_proxy,
                              reason=res.get("reason", ""),
                              same_exit=grey, attempts=attempts + 1)
                        return

                    
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
                    elif raw_status == "trap":
                        # То же, что и на основном проходе: ловушка вендора —
                        # это «писать нельзя», а не «ящика нет».
                        status_display = "Trap/Disposable"
                    elif raw_status == "invalid":
                        status_display = "Invalid/Bounce"
                    else:
                        # Незнакомый статус — отсутствие доказательства.
                        # Подробнее у такой же лестницы основного прохода.
                        status_display = "Unknown"
                    
                    # Что именно ушло в RCPT TO. Показывается в карточке
                    # адреса строкой «Проверен как». Поле читалось окном и не
                    # записывалось нигде — строка была всегда пустой, то есть
                    # владелец не мог убедиться СВОИМИ ГЛАЗАМИ, что проверяют
                    # его адрес. Он спрашивал об этом дважды.
                    try:
                        data["checked_as"] = (self.network.probe_form(email)
                                              if self.network is not None else email)
                    except Exception:
                        data["checked_as"] = email

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
                # Кругов перепроверки может быть несколько: адрес, который
                # и со второго выхода не получил ответа, кладётся обратно в
                # очередь — но не больше MAX_RETRY_ROUNDS раз. Первый круг
                # закрывает случай «сорвалось у нас»; второй — случай, когда
                # и повтор упёрся в то же самое (лимит на том же почтовике,
                # вторая выдержка серого списка, второй грязный выход).
                for retry_round in range(1, MAX_RETRY_ROUNDS + 1):
                    if not self.is_running:
                        break
                    pending = []
                    while True:
                        try:
                            pending.append(greylisted_queue.get_nowait())
                        except Exception:
                            break

                    if not pending:
                        break            # второму кругу нечего делать

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
                        f"[INFO] Круг перепроверки {retry_round} из {MAX_RETRY_ROUNDS}: "
                        f"взято {total_pending}, вердикт получили {retry_count} "
                        "(счёт с начала перепроверки). Простой в ожидании: "
                        f"{waited:.1f}с.", "info")

        self._phase("", 0)

        # Страховка: всё, что осталось в очереди — не перепроверено (нажали «Стоп»,
        # выключен deep_ping, или прогон прервался). Раньше такие адреса молча
        # исчезали: в выдачу они не попадали ни на первом проходе, ни на втором,
        # а прогресс-бар уже считал их обработанными. Отдаём их как Unknown.
        leftover = 0
        while True:
            try:
                (email, data, is_role, _due,
                 _proxy, first_reason, _same, _tries) = greylisted_queue.get_nowait()
            except Exception:
                break
            leftover += 1
            data["validated_at"] = _utc_now().strftime("%Y-%m-%d %H:%M")
            # Причина — та, с которой адрес сюда попал. Раньше здесь стояло
            # «Greylisted» для всех подряд, а в очередь попадают ещё таймауты,
            # мёртвые прокси и отказы по репутации нашего IP. Владелец читает
            # эту строку, чтобы понять, что чинить: серый список ждут, а
            # грязный прокси меняют.
            why = (first_reason or "Перепроверка не выполнена").strip()
            if "перепроверка не выполнена" not in why.lower():
                why = f"{why} (перепроверка не выполнена)"
            try:
                self._emit(email, "Unknown", why, "N/A", data)
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

        # Домены, ДОКАЗАННО принимающие что угодно. Их Valid ничего не значит,
        # и оставлять его в выгрузке нельзя: владелец решает по колонке.
        try:
            proven = self.network.proven_catchall_domains() if self.network else []
        except Exception:
            proven = []
        if proven:
            revised = self._revise(
                proven, "Unknown",
                "домен принимает любой адрес (catch-all) — существование "
                "ящика по SMTP не проверяется")
            if revised:
                self.callbacks['on_log'](
                    f"[INFO] Пересмотрено строк по catch-all доменам: {revised}. "
                    "Их «Годен» ничего не доказывал.", "info")
            self._forget_cached(proven, "catch-all")
        if trapped:
            self._revise(trapped, "Unknown",
                         "домен перестал отвечать честно (тарпитинг) — «Годен» "
                         "по нему недоказуем")
            self._forget_cached(trapped, "тарпитинг")

        # Домены, где канарейка вернулась живой. Тарпитинг мог включиться
        # посреди прогона, и первые сотни адресов проверены честно — но
        # разделить их по времени мы не можем, поэтому пересматриваем все.
        # Ошибиться в сторону «недоказуемо» дешевле: перепроверка стоит
        # одного прогона, разосланное письмо на мёртвый ящик — репутации.
        try:
            подставные = self.canary.compromised_domains() if getattr(
                self, "canary", None) else []
        except Exception:
            подставные = []
        if подставные:
            self._revise(подставные, "Unknown",
                         "канарейка вернулась живой: сервер принял заведомо "
                         "несуществующий адрес — «Годен» недоказуем")
            self._forget_cached(подставные, "канарейка")
            свод = self.canary.summary()
            self.callbacks['on_log'](
                "[DEAD] Канареек выпущено: %d, поймано врущих выходов: %d. "
                "Домены: %s. Это НЕ проблема базы — нужен чистый прокси."
                % (свод["проб"], свод["поймано"], ", ".join(свод["домены"])),
                "dead")
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
                # Подозрение приписывается К ПРИЧИНЕ, но статус не трогает:
                # у честного корпоративного домена все адреса тоже бывают
                # живыми, и снимать с них Valid значило бы терять контакты.
                self._revise([dom for dom, _ in suspicious], None,
                             "домен под подозрением на catch-all: все "
                             "проверенные адреса ответили 250")
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

        # ЛОВУШКА, закрытая здесь.
        #
        # RunState стирает память о прогоне ТОЛЬКО когда продолжение
        # выключено (`if not resume: self.clear()` в core/runstate.py). Раз
        # продолжение теперь включено всегда и убрано из окна, память не
        # стиралась бы никогда: второй запуск того же файла дал бы НОЛЬ
        # адресов к проверке, а починить это было бы нечем — галочки в окне
        # больше нет, остаётся удалять sqlite руками.
        #
        # Поэтому память стирается сама, но ТОЛЬКО после прогона, дошедшего
        # до конца. Нажали «Стоп» — память цела, и продолжение работает
        # ровно так, как обещает его название.
        try:
            if resume and not self._stop_requested:
                state.clear()
        except Exception:
            pass

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

    def start(self, email_sources, threads, timeout, fix_typos, check_spam,
              deep_ping, enable_ai=True, proxies=None, enable_osint=True,
              use_cache=True, resume=True,
              # Второе мнение о каждом «Годен» с другого выходного адреса.
              # Стоит лишней сессии на каждый подтверждённый адрес, но ловит
              # почтовик, который врёт ТОЛЬКО нашему выходу и принимает всё
              # подряд. Владелец включил его насовсем: перед рассылкой цена
              # лишней сессии несравнима с ценой отправки в пустоту.
              confirm_valid=True):
        self.confirm_valid = bool(confirm_valid)
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
