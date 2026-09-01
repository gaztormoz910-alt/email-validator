# core/collectors.py
"""Сбор адресов из ОТКРЫТЫХ API, а не из выдачи поисковиков.

Чем это лучше дорков. Поисковик — враждебная среда: капча, лимиты, разная
выдача на разных прокси, разметка, которая меняется без предупреждения. А
GitHub, npm, PyPI и Hacker News отдают те же данные структурированным JSON,
без капчи и без разбора HTML. Адреса там лежат ровно потому, что люди сами их
опубликовали: в коммитах, в package.json, в метаданных пакета, в профиле.

Что здесь принципиально.

**Никаких ключей и никаких логинов.** Все четыре источника отвечают анонимно.
У GitHub без ключа лимит шестьдесят запросов в час на адрес — мало для
промышленного сбора, но достаточно, чтобы источник работал сразу и без
регистрации. Лимит назван вслух в ответе, а не выясняется молчанием.

**Ответ разбирается тем же образцом, что и всё остальное.** Свой набор
символов уже однажды приносил в базу обрезки чужих адресов; здесь берётся
harvest_pattern из core/email_syntax.

**Мусор отсеивается на месте.** GitHub подставляет
`12345+username@users.noreply.github.com` вместо настоящего адреса — писать
туда бессмысленно, такие отбрасываются. То же с `noreply`, `no-reply` и
адресами вида `action@github.com` у ботов.
"""
import html
import json
import re
import urllib.error
import urllib.parse
import urllib.request

from core.email_syntax import harvest_pattern

# Заголовок представления. Свой, честный: подделываться под браузер там, где
# сервис отвечает всем, незачем.
USER_AGENT = "email-validator/1.0 (+collectors)"

# Сколько ждать ответа. Источники отвечают за доли секунды; всё, что дольше,
# означает лимит или недоступность, и висеть на этом не нужно.
TIMEOUT = 15

# Адреса, которые технически адреса, но писать по ним некуда.
_JUNK_PATTERNS = re.compile(
    r"(users\.noreply\.github\.com$"
    r"|^no-?reply@"
    r"|^action@github\.com$"
    r"|^\d+\+"                       # 12345+username@… — та же заглушка GitHub
    r"|@example\.(com|org|net)$"
    r"|@localhost$)", re.IGNORECASE)

_HARVEST = harvest_pattern(wide=False)


def looks_writable(email):
    """Стоит ли вообще класть этот адрес в базу."""
    if not isinstance(email, str) or "@" not in email:
        return False
    return not _JUNK_PATTERNS.search(email.strip().lower())


def _fetch_json(url, timeout=TIMEOUT, proxies=None):
    """JSON по ссылке. Возвращает (данные, ошибка) — ошибка строкой.

    Ошибка ВОЗВРАЩАЕТСЯ, а не проглатывается: лимит GitHub и упавшая сеть
    выглядят одинаково, только если о них молчать.
    """
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    })
    opener = urllib.request.build_opener()
    if proxies:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler(proxies))
    try:
        with opener.open(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8", "replace")), ""
    except urllib.error.HTTPError as error:
        if error.code == 403:
            return None, ("лимит источника исчерпан (HTTP 403). У GitHub без "
                          "ключа это шестьдесят запросов в час на адрес.")
        return None, "HTTP %s" % error.code
    except Exception as exc:                      # noqa: BLE001
        return None, "%s: %s" % (type(exc).__name__, exc)


def _harvest(text):
    """Все адреса из куска текста, годные для рассылки.

    Текст сначала распаковывается из HTML: Hacker News отдаёт комментарии
    разметкой, и `ivan&#x40;example.com` без распаковки не адрес вовсе, а
    `<i>почта</i>` склеивает соседние слова в одно.
    """
    if not isinstance(text, str) or not text:
        return []
    text = html.unescape(text)
    # Убираются НАСТОЯЩИЕ теги, а не всё в угловых скобках.
    #
    # Первая версия резала `<[^>]*>` — и съедала `Kenneth Reitz
    # <me@kennethreitz.org>`, то есть ровно ту форму, в которой PyPI отдаёт
    # почту автора. Имя тега состоит из букв и цифр, а в адресе есть «@» и
    # точка, поэтому такой образец адрес не трогает.
    text = re.sub(r"</?[a-zA-Z][a-zA-Z0-9]*(?:\s[^<>]*)?>", " ", text)
    if "@" not in text:
        return []
    return [m.group(0) for m in _HARVEST.finditer(text)
            if looks_writable(m.group(0))]


# ────────────────────────────────────────────────────────── GitHub

def collect_github(query="language:python", pages=1, proxies=None):
    """Адреса из авторов последних коммитов по репозиториям поиска.

    Почему из коммитов. В профиле почта скрыта у большинства, а в коммите она
    лежит открыто: git пишет её в каждый объект, и GitHub отдаёт как есть.
    Это публичные данные, которые человек опубликовал сам.
    """
    found, errors = [], []
    for page in range(1, max(1, int(pages)) + 1):
        url = ("https://api.github.com/search/repositories?q=%s&sort=updated"
               "&per_page=10&page=%d" % (urllib.parse.quote(query), page))
        data, error = _fetch_json(url, proxies=proxies)
        if error:
            errors.append("GitHub: " + error)
            break
        for repo in (data or {}).get("items", []):
            full_name = repo.get("full_name")
            if not full_name:
                continue
            commits_url = ("https://api.github.com/repos/%s/commits?per_page=30"
                           % urllib.parse.quote(full_name))
            commits, error = _fetch_json(commits_url, proxies=proxies)
            if error:
                errors.append("GitHub: " + error)
                break
            for entry in commits or []:
                author = ((entry.get("commit") or {}).get("author") or {})
                email = author.get("email")
                if email and looks_writable(email):
                    found.append(email)
    return found, errors


# ────────────────────────────────────────────────────────── npm

def collect_npm(query="email", limit=50, proxies=None):
    """Адреса сопровождающих из метаданных пакетов npm."""
    url = ("https://registry.npmjs.org/-/v1/search?text=%s&size=%d"
           % (urllib.parse.quote(query), max(1, min(int(limit), 250))))
    data, error = _fetch_json(url, proxies=proxies)
    if error:
        return [], ["npm: " + error]
    found = []
    for entry in (data or {}).get("objects", []):
        package = entry.get("package") or {}
        for who in [package.get("author") or {}] + (package.get("maintainers") or []):
            if isinstance(who, dict) and who.get("email"):
                if looks_writable(who["email"]):
                    found.append(who["email"])
    return found, []


# ────────────────────────────────────────────────────────── PyPI

def collect_pypi(packages, proxies=None):
    """Адреса авторов и сопровождающих пакетов PyPI.

    Поиска по API у PyPI нет — только страница пакета, — поэтому имена
    приходят списком. Это не ограничение сборщика, а устройство источника.
    """
    if isinstance(packages, str):
        packages = [packages]
    found, errors = [], []
    for name in (packages or []):
        url = "https://pypi.org/pypi/%s/json" % urllib.parse.quote(str(name))
        data, error = _fetch_json(url, proxies=proxies)
        if error:
            errors.append("PyPI %s: %s" % (name, error))
            continue
        info = (data or {}).get("info") or {}
        for key in ("author_email", "maintainer_email"):
            value = info.get(key)
            if value:
                found.extend(_harvest(value))
    return found, errors


# ────────────────────────────────────────────────────────── Hacker News

def collect_hackernews(query="email", limit=50, proxies=None):
    """Адреса из текстов постов и комментариев Hacker News.

    Люди пишут почту прямо в текст — в тредах «кто нанимает», в подписях, в
    объявлениях. Поиск у HN открытый и без ключа.
    """
    url = ("https://hn.algolia.com/api/v1/search?query=%s&hitsPerPage=%d"
           % (urllib.parse.quote(query), max(1, min(int(limit), 100))))
    data, error = _fetch_json(url, proxies=proxies)
    if error:
        return [], ["Hacker News: " + error]
    found = []
    for hit in (data or {}).get("hits", []):
        for key in ("comment_text", "story_text", "title", "author"):
            found.extend(_harvest(hit.get(key) or ""))
    return found, []


# ────────────────────────────────────────────────────────── Reddit

def collect_reddit(query="contact email", limit=50, proxies=None):
    """Адреса из текстов постов Reddit.

    Поиск отдаётся обычным JSON без ключа и без регистрации — достаточно
    добавить .json к адресу поиска. Люди пишут почту в объявлениях о работе,
    в подписях и в тредах про свои проекты.
    """
    url = ("https://www.reddit.com/search.json?q=%s&limit=%d"
           % (urllib.parse.quote(query), max(1, min(int(limit), 100))))
    data, error = _fetch_json(url, proxies=proxies)
    if error:
        return [], ["Reddit: " + error]
    found = []
    for child in ((data or {}).get("data") or {}).get("children", []) or []:
        item = child.get("data") if isinstance(child, dict) else None
        if not isinstance(item, dict):
            continue
        for key in ("selftext", "title", "url", "author"):
            found.extend(_harvest(item.get(key) or ""))
    return found, []


# ────────────────────────────────────────────────────── Stack Exchange

def collect_stackexchange(query="email", site="stackoverflow", limit=50,
                          proxies=None):
    """Адреса из вопросов Stack Overflow и соседних сайтов.

    API открыт и без ключа терпит небольшие объёмы. Почта попадается в текстах
    вопросов: люди вставляют куски конфигов, логов и писем целиком.
    """
    url = ("https://api.stackexchange.com/2.3/search/advanced"
           "?order=desc&sort=activity&q=%s&site=%s&pagesize=%d&filter=withbody"
           % (urllib.parse.quote(query), urllib.parse.quote(site),
              max(1, min(int(limit), 100))))
    data, error = _fetch_json(url, proxies=proxies)
    if error:
        return [], ["Stack Exchange: " + error]
    found = []
    for item in (data or {}).get("items", []) or []:
        if not isinstance(item, dict):
            continue
        for key in ("body", "title", "link"):
            found.extend(_harvest(item.get(key) or ""))
    return found, []


# ────────────────────────────────────────────────────────── GitLab

def collect_gitlab(query="email", limit=50, proxies=None):
    """Адреса из описаний публичных проектов GitLab.

    Второй по величине хостинг кода после GitHub, и поиск по публичным
    проектам открыт без токена. Почта лежит в описаниях: «связаться со мной».
    """
    url = ("https://gitlab.com/api/v4/projects?search=%s&per_page=%d"
           "&order_by=last_activity_at"
           % (urllib.parse.quote(query), max(1, min(int(limit), 100))))
    data, error = _fetch_json(url, proxies=proxies)
    if error:
        return [], ["GitLab: " + error]
    found = []
    for item in (data or []):
        if not isinstance(item, dict):
            continue
        for key in ("description", "name", "web_url"):
            found.extend(_harvest(item.get(key) or ""))
    return found, []


# ────────────────────────────────────────────────────────── общий вход

SOURCES = {
    "github": collect_github,
    "npm": collect_npm,
    "pypi": collect_pypi,
    "hackernews": collect_hackernews,
    "reddit": collect_reddit,
    "stackexchange": collect_stackexchange,
    "gitlab": collect_gitlab,
}


def collect(source, proxies=None, **kwargs):
    """Собирает адреса одним источником. Возвращает (адреса, ошибки).

    Повторы схлопываются каноническим ключом — тем же, которым сверяются
    дедуп и список отписок. Иначе один и тот же человек, попавший и в
    коммиты, и в npm, приехал бы дважды.
    """
    worker = SOURCES.get(str(source).lower())
    if worker is None:
        return [], ["нет такого источника: %s" % source]

    try:
        found, errors = worker(proxies=proxies, **kwargs)
    except TypeError as exc:
        return [], ["неверные параметры источника %s: %s" % (source, exc)]
    except Exception as exc:                      # noqa: BLE001
        return [], ["%s: %s: %s" % (source, type(exc).__name__, exc)]

    from core.cleaner import normalize_for_dedup

    seen, unique = set(), []
    for email in found:
        key = normalize_for_dedup(email)
        if not key or key in seen:
            continue
        seen.add(key)
        unique.append(email)
    return unique, errors
