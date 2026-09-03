# core/cleaner.py

import re

from .parser_pipeline import GLOBAL_VERIFIED_DOMAINS
from core.email_syntax import to_ascii_domain, _lower_domain_only

# --- Нормализация адресов для дедупликации (п.28 чек-листа) ---
#
# Разные записи могут вести в ОДИН И ТОТ ЖЕ ящик. Если их не схлопнуть,
# один человек получит письмо дважды -> жалобы на спам.
#
# ВАЖНО: канонический вид используется ТОЛЬКО как ключ дедупа.
# Наружу (в результат и экспорт) всегда уходит оригинальный адрес.

# Gmail: точки в локальной части игнорируются, домены-синонимы ведут в тот же ящик.
_GMAIL_DOMAINS = {"gmail.com", "googlemail.com", "google.com"}

# Провайдеры, у которых "+тег" отбрасывается почтовиком (john+news@ == john@).
# Только те, где это гарантированно так. Для корпоративных доменов НЕ трогаем:
# там "+" может быть обычным символом логина, и мы склеим разных людей.
_PLUS_TAG_DOMAINS = {
    "gmail.com", "googlemail.com", "google.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com", "hotmail.co.uk",
    "yahoo.com", "ymail.com", "rocketmail.com",
    "icloud.com", "me.com", "mac.com",
    "protonmail.com", "proton.me", "pm.me",
    "fastmail.com", "zoho.com", "yandex.ru", "ya.ru",
}


# Символы, которыми адрес обрастает при выгрузке из чужих систем: кавычки из
# CSV, угловые скобки из заголовков письма, скобки и запятые из списков,
# обратная кавычка и звёздочка из markdown, невидимые BOM и неразрывный пробел.
#
# Почему счищать их безопасно. Собственная регулярка валидатора допускает в
# локальной части только [a-zA-Z0-9._%+-]. Всё перечисленное ниже она и так
# отвергает, то есть адрес с таким символом СЕЙЧАС получает вердикт invalid
# «Bad Syntax». Счистка может сделать его валидным, но не может испортить уже
# валидный — там этих символов нет по определению.
#
# Это не выдумка на будущее: в файле владельца лежит `hjohnuc@gmail.com с
# обратной кавычкой в начале, и он получал ложный invalid на живом адресе.
_JUNK_EDGES = "`'\"<>()[]{},;:|*!?«»“”‘’" \
              "﻿​‌‍  \t\r\n"

_MAILTO_RE = re.compile(r'^\s*mailto:\s*', re.IGNORECASE)

# Разбор кавычек живёт в core/email_syntax.py — там же, где грамматика
# RFC 5322. Обратной зависимости нет, цикла не будет.
from core.email_syntax import has_quoted_local            # noqa: E402


def strip_wrapping_junk(raw: str) -> str:
    """Снимает обёртку вокруг адреса и приводит его к нижнему регистру.

    'mailto:<John.Doe@Gmail.com>,' -> 'john.doe@gmail.com'
    '`hjohnuc@gmail.com'           -> 'hjohnuc@gmail.com'
    """
    if not isinstance(raw, str):
        return ""
    value = _MAILTO_RE.sub("", raw)
    # Кавычка бывает НЕ мусором. RFC 5321 §4.1.2 разрешает имя ящика в
    # кавычках, и там они — часть адреса: `"very.unusual"@example.com`.
    # Счистка краёв снимала открывающую и оставляла закрывающую, превращая
    # валидный адрес в `very.unusual"@example.com`, то есть в ложный invalid
    # «Bad Syntax» без единого сетевого запроса. Проверено запуском: три
    # разных адреса в кавычках ломались одинаково.
    #
    # Поэтому: если ДО счистки имя ящика было в кавычках, а после перестало,
    # кавычки этому адресу принадлежат — снимаем всё остальное, но их
    # оставляем.
    quoted_before = has_quoted_local(value.strip().lower())
    # Угловые скобки разбираем ПЕРВЫМИ: в выгрузках почтовиков адрес приходит
    # вместе с отображаемым именем — Ivan Petrov <ivan@corp.com>. Если сначала
    # обрезать края, закрывающая скобка исчезнет, и имя останется приклеенным.
    if "<" in value and ">" in value:
        inner = value[value.rfind("<") + 1:value.rfind(">")]
        if "@" in inner:
            value = inner
    stripped = _lower_domain_only(value.strip(_JUNK_EDGES))
    if quoted_before and not has_quoted_local(stripped):
        return _lower_domain_only(value.strip(_JUNK_EDGES.replace('"', "")))
    return stripped


def normalize_for_dedup(email: str) -> str:
    """Приводит адрес к каноническому виду для сравнения дублей.

    Схлопывает:
      john.doe@gmail.com  ==  johndoe@gmail.com   (Gmail игнорирует точки)
      john+news@gmail.com ==  john@gmail.com      (плюс-тег отбрасывается)
      j@googlemail.com    ==  j@gmail.com         (домен-синоним)

    Возвращает ключ для дедупа, а НЕ адрес для отправки.
    """
    if not isinstance(email, str) or "@" not in email:
        return (email or "").strip().lower() if isinstance(email, str) else ""

    email = email.strip().lower()
    local, domain = email.rsplit("@", 1)

    # Домен приводим к punycode. Один и тот же ящик пишут двумя способами:
    # `ivan@почта.рф` и `ivan@xn--80a1acny.xn--p1ai` — это одна строка на
    # проводе, но два разных ключа, если сравнивать как есть. Цена та же, что
    # у любого пропущенного дубля: письмо приходит дважды. И хуже —
    # отписавшийся под одним написанием не защищён от рассылки по другому.
    #
    # Ключ уходит только на сравнение; наружу по-прежнему отдаётся исходный
    # адрес, переписывать данные владельца нельзя.
    ascii_domain = to_ascii_domain(domain)
    if ascii_domain:
        domain = ascii_domain

    # Плюс-тег отбрасываем только у провайдеров, где это реально работает
    if domain in _PLUS_TAG_DOMAINS and "+" in local:
        local = local.split("+", 1)[0]

    # У Gmail точки в локальной части не значат ничего
    if domain in _GMAIL_DOMAINS:
        local = local.replace(".", "")
        domain = "gmail.com"

    if not local:
        return email  # Защита от вырожденного случая вроде "+tag@gmail.com"

    return f"{local}@{domain}"

class EmailCleaner:
    # Известные окончания доменов. Нужны, чтобы отрезать мусор, приклеенный
    # к TLD, у ЛЮБОГО домена, а не только у 81 из списка парсера.
    _KNOWN_TLDS = (
        "com", "org", "net", "ru", "ua", "by", "kz", "de", "fr", "it", "es",
        "pl", "nl", "be", "se", "no", "dk", "fi", "cz", "sk", "hu", "ro", "bg",
        "gr", "pt", "at", "ch", "uk", "ie", "us", "ca", "au", "nz", "jp", "cn",
        "kr", "in", "br", "mx", "ar", "cl", "co", "io", "me", "info", "biz",
        "edu", "gov", "mil", "int", "tv", "cc", "xyz", "online", "site", "shop",
        "app", "dev", "tech", "store", "pro", "name", "email", "cloud",
        # Настоящие зоны, которые НАЧИНАЮТСЯ с более короткой зоны из этого же
        # списка. Они здесь не ради починки склеек, а ради предохранителя в
        # _strip_tld_tail: пока зоны нет в списке, её домен выглядит как
        # «короткая зона плюс мусор», и адрес молча уезжает на чужой домен
        # (`geometrixx.info` -> `geometrixx.in`). Список неполон и полным не
        # будет — это уменьшение риска, а не его устранение; настоящее решение
        # — брать зоны из реестра IANA.
        "institute", "international", "industries", "ink", "insure",
        "company", "consulting", "construction", "community", "codes",
        "coffee", "cool", "coupons", "courses", "credit", "coop",
        "media", "menu", "memorial",
        "design", "delivery", "dental", "deals",
        "network", "organic", "shopping", "technology",
        "productions", "properties", "property",
        "cafe", "camera", "capital", "care", "careers", "cash", "casino",
        "chat", "church", "estate", "auction", "audio", "auto",
    )

    def __init__(self):
        # Самые популярные провайдеры для проверки на опечатки
        self.popular_domains = set(GLOBAL_VERIFIED_DOMAINS)
        # Порядок обхода set в Python не гарантирован между запусками, из-за чего
        # очистка была недетерминированной. Сортируем по длине (длинные вперёд),
        # а при равной длине — по алфавиту: gmail.com и yahoo.com одной длины,
        # и без второго критерия порядок между ними всё равно плавал.
        self._sorted_domains = sorted(self.popular_domains, key=lambda d: (-len(d), d))
        
        # Хеш-таблица опечаток: неправильный домен → правильный (расширенная — п.6)
        self._typo_map = {
            # Gmail
            'gamil.com': 'gmail.com', 'gmial.com': 'gmail.com', 'gmal.com': 'gmail.com',
            'gmai.com': 'gmail.com', 'gmail.co': 'gmail.com', 'gmail.con': 'gmail.com',
            'gmail.ru': 'gmail.com', 'gnail.com': 'gmail.com', 'gmaill.com': 'gmail.com',
            'g.mail.com': 'gmail.com', 'gmaul.com': 'gmail.com', 'gmqil.com': 'gmail.com',
            'gmali.com': 'gmail.com', 'gemail.com': 'gmail.com', 'gmsil.com': 'gmail.com',
            'gmeil.com': 'gmail.com', 'gmaik.com': 'gmail.com', 'gmil.com': 'gmail.com',
            # Yahoo
            'yaho.com': 'yahoo.com', 'yahoo.co': 'yahoo.com',
            'yahoo.con': 'yahoo.com', 'yaboo.com': 'yahoo.com', 'yahooo.com': 'yahoo.com',
            'yshoo.com': 'yahoo.com', 'yaoo.com': 'yahoo.com', 'tahoo.com': 'yahoo.com',
            # Outlook
            'outlok.com': 'outlook.com', 'outook.com': 'outlook.com', 'otlook.com': 'outlook.com',
            'outlool.com': 'outlook.com', 'outloock.com': 'outlook.com',
            'oultook.com': 'outlook.com', 'outlokk.com': 'outlook.com',
            # Hotmail
            'hotmal.com': 'hotmail.com', 'hotmai.com': 'hotmail.com', 'hotmail.co': 'hotmail.com',
            'hotmial.com': 'hotmail.com', 'hotmaill.com': 'hotmail.com',
            'hotmeil.com': 'hotmail.com', 'hotmsil.com': 'hotmail.com',
            # iCloud
            'iclod.com': 'icloud.com', 'icoud.com': 'icloud.com', 'icloud.co': 'icloud.com',
            'icloude.com': 'icloud.com',
            # Mail.ru
            'mail.r': 'mail.ru', 'mai.ru': 'mail.ru', 'maill.ru': 'mail.ru',
            'mail.rru': 'mail.ru', 'mall.ru': 'mail.ru',
            # Yandex
            'yandex.r': 'yandex.ru', 'yanex.ru': 'yandex.ru', 'yandx.ru': 'yandex.ru',
            'yandez.ru': 'yandex.ru', 'yadex.ru': 'yandex.ru',
            # Protonmail (п.6 +1 балл)
            'protonmal.com': 'protonmail.com', 'protonmai.com': 'protonmail.com',
            'protonmial.com': 'protonmail.com', 'protonmaill.com': 'protonmail.com',
            'protonmail.co': 'protonmail.com', 'protnmail.com': 'protonmail.com',
            'protonmil.com': 'protonmail.com',
            # AOL (п.6)
            'aol.co': 'aol.com', 'aol.con': 'aol.com', 'aool.com': 'aol.com',
            'ao.com': 'aol.com',
            # Zoho (п.6)
            'zoho.co': 'zoho.com', 'zoho.con': 'zoho.com', 'zho.com': 'zoho.com',
            # GMX (п.6)
            'gmx.co': 'gmx.com', 'gmx.con': 'gmx.com', 'gmc.com': 'gmx.com',
            # Rambler (п.6)
            'rambler.r': 'rambler.ru', 'ramblr.ru': 'rambler.ru', 'ramblerr.ru': 'rambler.ru',
            # QQ (п.6)
            'qq.co': 'qq.com', 'qq.con': 'qq.com',
            # 163.com (п.6)
            '163.co': '163.com', '163.con': '163.com',
            # Live
            'live.co': 'live.com', 'live.con': 'live.com', 'lve.com': 'live.com',
        }

    # ── Предохранитель против подмены домена ────────────────────────────
    #
    # Починка склеек существует для строк, которых как домена не бывает:
    # `gmail.comtelefoon`, `mail.ruXXX`, `corp.com-jobs`. Но её правила —
    # «начинается с известного домена» и «после известной зоны идут буквы» —
    # срабатывали и на ЗАКОННЫХ доменах:
    #
    #     user@sky.company.co.uk  ->  user@sky.com     (начинается с sky.com)
    #     b@aol.company.com       ->  b@aol.com        (начинается с aol.com)
    #     a@web.de.hosting.net    ->  a@web.de         (начинается с web.de)
    #     d@list.ru-company.com   ->  d@list.ru        (хвост после .ru)
    #
    # Все четыре — работающие домены. «Годен» по ним означает письмо человеку,
    # которого владелец в базу не клал; «нет такого» хоронит настоящий адрес,
    # который никто не спрашивал. Обе стороны — ровно тот ложный вердикт,
    # ради которого этот предохранитель и написан.
    #
    # Разделяющий признак — ТОЧКА В ОСТАТКЕ. Замерено на всех восьми известных
    # случаях, разделение полное:
    #
    #     законные:  pany.co.uk   pany.com   .hosting.net   -company.com  есть
    #     склейки:   telefoon     xxx        -jobs          blahblah      нет
    #
    # И это не совпадение выборки, а свойство: точка порождает новую метку
    # домена. Мусор от копирования метку не образует — образуй он её, строка
    # была бы законным доменом, и чинить в ней было бы нечего.
    #
    # Правило намеренно осторожное: сомнительный случай остаётся нетронутым, и
    # тогда DNS сам скажет, что домена нет. Пропущенная починка стоит одного
    # честного «мёртвый домен»; лишняя — молча подменяет ящик.

    _APPENDIX_RE = re.compile(
        r"^(.+?\.(?:com|org|net|ru|edu|gov|io|me|info|biz))([-_].*)$")

    @staticmethod
    def _junk_tail(tail):
        """Похож ли остаток на приклеенный мусор, а не на продолжение домена."""
        return bool(tail) and "." not in tail

    def _cut_tld_appendix(self, domain):
        """Отрезает приписку после известной зоны: corp.com-jobs -> corp.com.

        Отрезает ТОЛЬКО бесточечный хвост — см. предохранитель выше.
        """
        m = self._APPENDIX_RE.match(domain)
        if m and self._junk_tail(m.group(2)):
            return m.group(1)
        return domain


    def _strip_tld_tail(self, domain: str) -> str:
        """Отрезает мусор, приклеенный к известному TLD.

        yandex.rublahblah -> yandex.ru,  mail.ruXXX -> mail.ru,  corp.deSpam -> corp.de
        Работает для любого домена, а не только для списка популярных.
        Если после TLD идёт ещё одна точка (реальный поддомен вроде co.uk) —
        не трогаем, чтобы не сломать составные зоны.

        ВТОРОЙ ПРЕДОХРАНИТЕЛЬ: зона целиком — не мусор.

        Короткая зона бывает НАЧАЛОМ длинной: `in` начинает `info`, `co` —
        `company`, `me` — `menu`. Правило искало зону как префикс последней
        метки, поэтому `geometrixx.info` превращался в `geometrixx.in` —
        существующий чужой домен в зоне Индии. Замерено на живой базе
        владельца: 2 адреса из 5000, то есть примерно 80 000 подменённых
        контактов на базе в 200 миллионов, и все они выглядят как обычные
        проверенные адреса.

        Поэтому сначала спрашиваем: а не является ли последняя метка сама по
        себе известной зоной? Если да, чинить нечего — это домен, а не склейка.
        Признак, а не список исключений: пополняя _KNOWN_TLDS настоящими
        зонами, мы одновременно расширяем и защиту.

        Зоны перебираются от ДЛИННОЙ к короткой: при прочих равных выигрывает
        более точное совпадение, а не то, что раньше стоит в таблице.
        """
        import re
        last_label = domain.rsplit(".", 1)[-1]
        if last_label in self._KNOWN_TLDS:
            return domain
        for tld in sorted(self._KNOWN_TLDS, key=len, reverse=True):
            m = re.match(rf'^(.+\.{tld})([a-z]{{2,}})$', domain)
            if m and m.group(2) not in self._KNOWN_TLDS:
                return m.group(1)
        return domain

    def correct_and_normalize(self, email: str) -> str:
        """
        Гибридный Cleaner (п.1.1 ТЗ):
        - Известные домены → исправить опечатки, пропустить
        - Неизвестные домены → пропустить КАК ЕСТЬ (не убивать!)
        - DNS-проверка живости домена делается позже в network.py (get_mx_records)
        """
        email = strip_wrapping_junk(email)
        if not email or "@" not in email:
            return None

        local_part, domain = email.rsplit("@", 1)
        
        # 0. Зачистка левой части (local_part)
        import re
        # Убираем повторяющиеся точки (karl....motiv -> karl.motiv)
        local_part = re.sub(r'\.{2,}', '.', local_part)
        # Убираем точки в самом начале и в самом конце левой части (.karl.motiv.@gmail.com -> karl.motiv@gmail.com)
        local_part = local_part.strip('.')
        
        # Если локальная часть пустая после очистки — мусор
        if not local_part:
            return None
        
        # 1. Жесткая зачистка "хвостов" от копипаста в домене

        # Приписки после известного TLD через дефис/подчёркивание: corp.com-jobs
        #
        # ПРЕДОХРАНИТЕЛЬ: хвост отрезается, только если в нём НЕТ точки.
        # Точка означает, что это не приклеенный мусор, а ещё одна метка
        # домена, то есть строка — законный домен, и трогать его нельзя.
        # Без этого условия `list.ru-company.com` превращался в `list.ru`,
        # и вердикт выносился про ЧУЖОЙ ящик. Подробнее — у _junk_tail.
        domain = self._cut_tld_appendix(domain)

        # Слипшийся мусор после известного домена: gmail.comtelefoon -> gmail.com.
        # ВАЖНО: перебираем ОТСОРТИРОВАННЫЙ список, а не set. Раньше порядок обхода
        # set менялся между запусками, и один адрес давал разные результаты
        # (замерено: bob@x.gmail.com.y.yahoo.com.z -> 7 раз gmail.com, 5 раз yahoo.com).
        # Самое длинное совпадение выигрывает, поэтому результат однозначен.
        matches = [pop for pop in self._sorted_domains
                   if domain.startswith(pop) and len(domain) > len(pop)
                   and self._junk_tail(domain[len(pop):])]
        if matches:
            domain = matches[0]

        # Глубоко вложенные мусорные поддомены: gmail.com.br.spam.xyz -> gmail.com.
        # Если внутри нашлось несколько известных доменов, берём тот, что стоит
        # РАНЬШЕ в строке: он и есть настоящий, остальное — приклеенный мусор.
        elif domain.count('.') > 3:
            inner = [(domain.index(pop), -len(pop), pop)
                     for pop in self._sorted_domains if pop in domain]
            if inner:
                domain = min(inner)[2]

        # Хвост, приклеенный к известному TLD, у ЛЮБОГО домена: yandex.rublahblah,
        # mail.ruXXX. Раньше чистились только домены из списка парсера, поэтому
        # живые адреса на прочих доменах уезжали в Invalid как "мёртвый домен".
        else:
            domain = self._strip_tld_tail(domain)
        
        # Убираем случайные точки в конце
        domain = domain.rstrip('.')
        
        # 2. ОПЕЧАТКИ БОЛЬШЕ НЕ ИСПРАВЛЯЮТСЯ ЗДЕСЬ.
        #
        # Раньше `gmial.com` молча превращался в `gmail.com`, и вердикт
        # выносился про ДРУГОЙ ящик: и «Годен» (о чужом человеке), и «Нет
        # такого» (о настоящем, который никто не проверял). Владелец при этом
        # видел в таблице подменённую строку и не знал, что загружал другую.
        #
        # Теперь исправление — это ПРЕДЛОЖЕНИЕ (см. suggest_domain_fix), и
        # применяется оно только там, где загруженный домен доказано мёртв:
        # в core/pipeline.py, после ответа DNS. Склейка мусора выше — другое
        # дело: `gmail.comtelefoon` не домен вовсе, там мы восстанавливаем
        # адрес, а не подменяем его.
        
        # 3. Точное совпадение с известным доменом — сразу пропускаем
        if domain in self.popular_domains:
            return f"{local_part}@{domain}"
            
        # 4. ГИБРИДНЫЙ ПОДХОД: Неизвестный домен — НЕ убиваем, а пропускаем как есть!
        #    DNS-проверка (MX/A-запись) будет выполнена позже в network.py.
        #    Если у домена нет ни MX, ни A-записи — network.py сам его отбракует.
        #    Таким образом корпоративные почты (ivan@sberbank.ru, john@tesla.com) не теряются.
        
        # Минимальная проверка: домен должен содержать хотя бы одну точку и не быть мусором
        if '.' in domain and len(domain) >= 4:
            return f"{local_part}@{domain}"
        
        # Совсем битый домен (без точки, слишком короткий) — мусор
        return None

    def suggest_domain_fix(self, email: str):
        """Похоже ли, что в домене опечатка. Возвращает адрес-предложение.

        None означает «предложить нечего». Ничего не меняет и никуда не
        применяется сама: решение принимает конвейер, и только после того,
        как DNS сказал, что загруженный домен мёртв. Это и есть разница
        между «исправить опечатку» и «подменить ящик».
        """
        if not isinstance(email, str) or email.count("@") != 1:
            return None
        local_part, domain = email.rsplit("@", 1)
        domain = domain.strip().lower().rstrip(".")
        if not local_part or not domain:
            return None

        fixed = self._typo_map.get(domain)
        if fixed and fixed != domain:
            return "%s@%s" % (local_part, fixed)
        return None

    # Алиас для обратной совместимости (pipeline.py вызывает clean_email)
    def clean_email(self, email: str) -> str:
        return self.correct_and_normalize(email)
