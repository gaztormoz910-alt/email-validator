# -*- coding: utf-8 -*-
"""Третий проход: то, что нашлось после «незакрытых багов нет».

Каждая проверка здесь стоит за одним воспроизведённым дефектом, а не за
подозрением. Общее у них одно: все они молчат. Парсер, который не стартует,
пишет одну строчку в лог и уходит в «готово»; кнопка, залипшая навсегда,
отвечает «проверка уже идёт»; таймаут DNS выглядит как отсутствие записи.
"""
import ast
import importlib.util
import io
import os
import re
import sys
import tempfile
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUR_PACKAGES = ("core", "ui", "api", "tools", "audit")


def written(raw, suffix=".txt"):
    path = tempfile.mktemp(suffix=suffix)
    with io.open(path, "wb") as handle:
        handle.write(raw)
    return path


def source_files():
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs
                   if d not in (".git", "__pycache__", "venv", ".venv",
                                "node_modules", "build", "dist", ".unlazy")]
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(base, name)


# ═══════════════════════════════ G1: сбор адресов запускается

def test_parser_starts_when_proxies_are_loaded():
    """Ветка «с прокси» импортировала модуль, которого нет.

    `core.stream_loader` — опечатка: модуль называется `core.streamer`.
    Импорт стоял ВНУТРИ `if proxy_sources`, поэтому без прокси сбор работал,
    а с прокси не запускался никогда: исключение ловилось, в лог уходила
    строчка, состояние становилось «готово».
    """
    from ui import webapp

    source = io.open(webapp.__file__, encoding="utf-8").read()
    assert "core.stream_loader" not in source
    assert importlib.util.find_spec("core.streamer") is not None


def test_parser_starts_every_internal_import_resolves():
    """Сито на весь проект: ни один наш импорт не указывает в пустоту.

    Точечная правка чинит один случай; эта проверка ловит класс. Импорт
    внутри функции никакой запуск не проверяет — до него доходит только тот,
    кто прошёл по этой ветке, а она бывает редкой.
    """
    missing = []
    for path in source_files():
        try:
            tree = ast.parse(io.open(path, encoding="utf-8", errors="replace").read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module]
            for name in names:
                if name.split(".")[0] not in OUR_PACKAGES:
                    continue
                try:
                    found = importlib.util.find_spec(name) is not None
                except Exception:
                    found = False
                if not found:
                    missing.append("%s:%d -> %s" % (os.path.relpath(path, ROOT),
                                                    node.lineno, name))
    assert missing == [], "импорт в пустоту: %s" % missing[:5]


def test_parser_starts_launch_branch_uses_the_real_loader():
    """Именно та ветка, а не соседняя: читатель прокси зовётся по имени."""
    from ui import webapp

    source = io.open(webapp.__file__, encoding="utf-8").read()
    launch = source[source.index("def parser_start"):]
    launch = launch[:launch.index("def parser_pause")]
    assert "from core.streamer import StreamLoader" in launch
    assert "dedupe_proxies_stream" in launch


# ═══════════════════════════════ G2: кнопка «Старт» не залипает

def test_start_flag_survives_a_run_without_sources():
    """Щелчок без базы запирал запуск НАВСЕГДА.

    Признак «идёт запуск» взводился до проверки источников и не снимался при
    раннем выходе. Следующий щелчок получал «проверка уже идёт», хотя не шло
    ничего, и кнопка не оживала до перезапуска программы.
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    answer = api.start({})
    assert answer["ok"] is False
    assert "выберите" in answer["error"].lower()
    assert api._starting is False, "флаг остался взведённым — кнопка мертва"


def test_start_flag_is_released_when_the_launch_raises():
    """Падение подготовки тоже обязано отпустить кнопку."""
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})

    def boom(_payload):
        raise RuntimeError("прокси не читаются")

    api._launch_pipeline = boom
    answer = api.start({})
    assert answer["ok"] is False
    assert "прокси не читаются" in answer["error"]
    assert api._starting is False
    assert api._state == "done"


def test_start_flag_still_blocks_a_second_click():
    """Обратная сторона: настоящий двойной запуск по-прежнему невозможен.

    Ослабить защиту от второго конвейера, чиня залипание, было бы обменом
    одной поломки на другую — ту самую, из-за которой удваивался лог.
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})
    api._starting = True
    assert api.start({})["error"] == "Проверка уже идёт"


# ═══════════════════════════════ G3: сбой DNS ≠ отсутствие записи

class _Resolver(object):
    """Резолвер, который на TXT сначала падает, а потом отвечает."""

    def __init__(self, answers, fail_times=0, error=None):
        self.answers = answers
        self.fail_times = fail_times
        self.error = error or Exception("таймаут")
        self.calls = 0

    def resolve(self, name, rtype, *args, **kwargs):
        self.calls += 1
        if self.fail_times > 0:
            self.fail_times -= 1
            raise self.error
        try:
            return self.answers[(name, rtype)]
        except KeyError:
            import dns.resolver
            raise dns.resolver.NoAnswer()


def _validator():
    from core.network import NetworkValidator
    return NetworkValidator(timeout=2)


def test_dns_health_failure_is_not_cached_as_absence():
    """Таймаут превращался в «SPF нет» и запоминался на весь прогон.

    Домен после одного нашего сбоя терял баллы за DNS до конца работы, и
    вернуть их было нечем: результат лежал в кэше.
    """
    v = _validator()
    answers = {("example.com", "TXT"): ["v=spf1 include:_spf.example.com ~all"]}
    v.resolver = _Resolver(answers, fail_times=99)

    first = v.check_dns_health("example.com")
    assert first["has_spf"] is False, "подготовка теста неверна"

    v.resolver = _Resolver(answers)
    second = v.check_dns_health("example.com")
    assert second["has_spf"] is True, "нуль от сбоя закэширован — домен наказан"


def test_dns_health_partial_failure_is_not_cached_either():
    """Частичный ответ — тоже не ответ.

    SPF нашёлся, DMARC отвалился по таймауту: прежнее условие требовало
    score == 0 и такой результат запоминало. Домен до конца прогона числился
    «SPF есть, DMARC нет» — за чужую запись, которой никто не видел.
    """
    v = _validator()
    full = {("example.com", "TXT"): ["v=spf1 ~all"],
            ("_dmarc.example.com", "TXT"): ["v=DMARC1; p=none"]}

    class Partial(object):
        def resolve(self, name, rtype, *a, **k):
            if name.startswith("_dmarc"):
                raise Exception("таймаут")
            try:
                return full[(name, rtype)]
            except KeyError:
                import dns.resolver
                raise dns.resolver.NoAnswer()

    v.resolver = Partial()
    partial = v.check_dns_health("example.com")
    assert partial["has_spf"] is True and partial["has_dmarc"] is False

    v.resolver = _Resolver(full)
    again = v.check_dns_health("example.com")
    assert again["has_dmarc"] is True, "частичный ответ закэширован как полный"


def test_dns_health_real_absence_is_still_cached():
    """Обратная сторона: настоящее «записей нет» кэшировать НАДО.

    Иначе каждый адрес на домене без SPF стоил бы трёх лишних запросов, а
    через прокси это заметная плата.
    """
    v = _validator()
    empty = _Resolver({})
    v.resolver = empty
    v.check_dns_health("nothing.example")
    after_first = empty.calls
    v.check_dns_health("nothing.example")
    assert empty.calls == after_first, "ответ «записей нет» не запомнился"


# ═══════════════════════════════ G4: кодировка везде, где файл владельца

def test_reads_any_encoding_in_base_operations():
    """Операции над базой читали файл как UTF-8 с выбрасыванием байт."""
    from core.baseops import read_emails

    path = written("ivan@gmail.com\nанна@mail.ru\n".encode("cp1251"))
    try:
        assert read_emails(path) == ["ivan@gmail.com", "анна@mail.ru"]
    finally:
        os.unlink(path)


def test_reads_any_encoding_in_domain_filters():
    """Одна русская строка комментария роняла ВЕСЬ список доменов.

    UnicodeDecodeError ловился обработчиком выше и возвращал пустое
    множество: файл на тысячу одноразовых доменов молча не применялся.
    """
    from core.filters import SpamFilter

    path = written("# мои одноразовые\nтемп.рф\ntempmail.example\n".encode("cp1251"))
    try:
        domains = SpamFilter._read_domains(path)
        assert "tempmail.example" in domains
        assert "темп.рф" in domains
    finally:
        os.unlink(path)


def test_reads_any_encoding_in_the_input_guard():
    """Страж объявлял базу «набранной не в той раскладке»."""
    from core.input_guard import check_file, KIND_EMAIL

    path = written("ivan@gmail.com\nanna@yahoo.com\nпётр@mail.ru\n".encode("cp1251"))
    try:
        assert check_file(path, KIND_EMAIL)["ok"] is True
    finally:
        os.unlink(path)


def test_reads_any_encoding_when_the_file_goes_into_the_text_field():
    """Владелец требовал, чтобы файл попадал в текстовое поле.

    Попадал он туда через отдельный читатель, который про кодировки не знал:
    в поле показывались символы замены, и порча выглядела как порча базы.
    """
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    path = written("анна@mail.ru\n".encode("cp1251"))
    try:
        assert "анна@mail.ru" in api._read_inline(path)
    finally:
        os.unlink(path)


def test_reads_any_encoding_utf8_is_not_broken_by_the_fix():
    """Обратная сторона: UTF-8 обязан остаться UTF-8 во всех этих местах."""
    from core.baseops import read_emails
    from core.filters import SpamFilter

    base = written("анна@mail.ru\n".encode("utf-8"))
    doms = written("почта.рф\n".encode("utf-8"))
    try:
        assert read_emails(base) == ["анна@mail.ru"]
        assert "почта.рф" in SpamFilter._read_domains(doms)
    finally:
        os.unlink(base)
        os.unlink(doms)


# ═══════════════════════════════ G5: отписавшийся не получает письмо

def test_unsubscribe_list_in_cp1251_still_subtracts():
    """Худшая цена ошибки с кодировкой — жалоба от отписавшегося.

    Список отписок читался тем же испорченным читателем: `анна@mail.ru`
    приезжал как `@mail.ru`, ключ не совпадал ни с чем, и человек, прямо
    попросивший его не трогать, получал письмо снова.
    """
    from core.baseops import subtract, suppression_keys, _key

    stop = written("анна@mail.ru\njohn.doe@gmail.com\n".encode("cp1251"))
    try:
        keys = suppression_keys(stop)
        base = ["анна@mail.ru", "johndoe@gmail.com", "ivan@gmail.com"]
        left = [e for e in base if _key(e) not in keys]
        assert left == ["ivan@gmail.com"]
        assert subtract(base, ["анна@mail.ru", "john.doe@gmail.com"]) == ["ivan@gmail.com"]
    finally:
        os.unlink(stop)


def test_unsubscribe_key_still_ignores_dots_only_for_gmail():
    """Правило дедупа не поехало вместе с починкой чтения."""
    from core.baseops import _key

    assert _key("john.doe@gmail.com") == _key("johndoe@gmail.com")
    assert _key("john.doe@outlook.com") != _key("johndoe@outlook.com")


# ═══════════════════════════════ G6: выгрузка открывается в Excel

def test_excel_reads_the_export_without_mojibake():
    """CSV писался в UTF-8 без метки, и Excel читал его в системной кодировке.

    «Иван» превращался в «РІР°РЅ». Признак у Excel ровно один — метка порядка
    байт в начале файла.
    """
    import csv

    from core.baseops import write_chunks_stream
    from core.encoding import open_text

    def writer(handle, rows):
        w = csv.writer(handle)
        w.writerow(["Email", "Name"])
        w.writerows(rows)

    path = tempfile.mktemp(suffix=".csv")
    try:
        write_chunks_stream([["ivan@gmail.com", "Иван"]], path, 0, writer)
        raw = io.open(path, "rb").read()
        assert raw.startswith(b"\xef\xbb\xbf"), "метки нет — Excel покажет кракозябры"
        # А наш собственный читатель метку съедает, а не тащит в первый адрес.
        with open_text(path) as handle:
            assert handle.read().splitlines()[0] == "Email,Name"
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_excel_marker_is_not_added_to_plain_text_lists():
    """В .txt метку не ставим: такой файл уходит в чужой рассыльщик."""
    from core.baseops import export_encoding, write_chunks_stream

    assert export_encoding("out.csv") == "utf-8-sig"
    assert export_encoding("out.txt") == "utf-8"

    path = tempfile.mktemp(suffix=".txt")
    try:
        write_chunks_stream(["ivan@gmail.com"], path, 0,
                            lambda h, rows: h.write(chr(10).join(rows)))
        assert not io.open(path, "rb").read().startswith(b"\xef\xbb\xbf")
    finally:
        if os.path.exists(path):
            os.unlink(path)


# ═══════════════════════════════ G8: определение кодировки и не-путь

def test_not_a_path_does_not_close_our_own_output():
    """detect_encoding(True) открывал дескриптор 1 — стандартный вывод.

    Блок with его закрывал, и программа теряла способность печатать. Замерено
    обстрелом: следующий же print падал с «Bad file descriptor».
    """
    from core.encoding import detect_encoding, read_sample

    assert detect_encoding(True) == "utf-8"
    assert detect_encoding(0) == "utf-8"
    assert read_sample(1) == b""
    print("вывод жив")          # упало бы, будь дескриптор закрыт


def test_not_a_path_answers_instead_of_crashing():
    """Определение кодировки не имеет права падать: оно только отвечает."""
    from core.encoding import detect_encoding

    for junk in (None, 3.5, [], {}, set(), object(), b"", "\x00"):
        assert detect_encoding(junk) in ("utf-8", "cp1251")


def test_not_a_path_still_raises_when_opening_a_missing_file():
    """Обратная сторона: открыть несуществующий файл — по-прежнему ошибка.

    Молча вернуть пустоту здесь означало бы «файл прочитан, в нём ничего
    нет» — то есть потерять базу и не сказать об этом.
    """
    from core.encoding import open_text

    with pytest.raises(FileNotFoundError):
        open_text(os.path.join(tempfile.gettempdir(), "нет-такого-файла.txt"))
    with pytest.raises(TypeError):
        open_text(None)


# ═══════════════════════════════ G9: торможение отпускает

def test_backoff_decay_releases_the_pause():
    """Счётчик 421 не убывал, и пауза оставалась восьмисекундной до конца.

    На сотнях тысяч адресов ранняя тугая минута стоила часов.
    """
    from core.proxy_pool import MX_ERROR_HALF_LIFE_SEC

    v = _validator()
    for _ in range(6):
        v._record_mx_error("mx.example.com")

    slow = v._mx_delay("mx.example.com")
    assert slow > 3.0, "торможение вообще не сработало — тест ничего не мерит"

    # Отматываем время назад: сервер молчит десять периодов полураспада.
    with v._mx_error_lock:
        v._mx_error_seen["mx.example.com"] = time.time() - MX_ERROR_HALF_LIFE_SEC * 10

    assert v._mx_delay("mx.example.com") < 0.5, "пауза не отпустила"


def test_backoff_decay_gives_the_stream_back():
    """Сужение потока тоже было односторонним."""
    from core.proxy_pool import MX_ERROR_HALF_LIFE_SEC

    v = _validator()
    for _ in range(6):
        v._record_mx_error("mx.example.com", proxy="1.2.3.4:8080")

    narrowed = v._get_mx_semaphore("mx.example.com", proxy="1.2.3.4:8080")
    assert narrowed._value == 1, "поток не сужался — тест ничего не мерит"

    with v._mx_error_lock:
        v._mx_error_seen["mx.example.com"] = time.time() - MX_ERROR_HALF_LIFE_SEC * 10

    restored = v._get_mx_semaphore("mx.example.com", proxy="1.2.3.4:8080")
    assert restored._value == v._max_concurrent_per_mx


def test_backoff_decay_keeps_braking_while_the_server_complains():
    """Обратная сторона: пока сервер жалуется, тормозить обязаны.

    Затухание, стирающее свежие жалобы, — это способ получить бан.
    """
    v = _validator()
    for _ in range(6):
        v._record_mx_error("mx.example.com")
    assert v._decayed_mx_errors("mx.example.com") >= 5.0
    assert v._mx_delay("mx.example.com") > 3.0


# ═══════════════════════════════ G10: запасное окно остаётся рабочим

def test_classic_window_still_starts():
    """Владелец решил оставить запасное окно — значит, оно обязано жить."""
    import main
    from ui.gui import ValidatorApp

    assert callable(main.run_classic)
    assert callable(getattr(ValidatorApp, "start_validation", None))
    assert callable(getattr(ValidatorApp, "stop_validation", None))


def test_classic_window_feeds_the_engine_the_same_way():
    """Оба окна обязаны звать движок одинаково.

    Именно расхождение здесь однажды и стоило владельцу прогонов: новое окно
    подавало конвейеру источники вместо строк прокси, и проверка шла с
    домашнего адреса.
    """
    def kwargs_of(path, marker):
        tree = ast.parse(io.open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            target = node.func
            if not isinstance(target, ast.Attribute) or target.attr != "start":
                continue
            names = {kw.arg for kw in node.keywords if kw.arg}
            if marker in names:
                return names
        return set()

    classic = kwargs_of(os.path.join(ROOT, "ui", "gui.py"), "email_sources")
    web = kwargs_of(os.path.join(ROOT, "ui", "webapp.py"), "email_sources")
    assert classic, "в классическом окне не найден запуск движка"
    assert classic - web == set(), "классическое окно передаёт лишнее: %s" % (classic - web)
    for required in ("email_sources", "proxies", "threads", "timeout",
                     "enable_ai", "use_cache"):
        assert required in classic and required in web, required


def test_classic_window_reads_any_encoding_too():
    """Запасное окно читает базу тем же потоковым читателем."""
    source = io.open(os.path.join(ROOT, "ui", "gui.py"), encoding="utf-8").read()
    assert "StreamLoader" in source
    assert 'errors="ignore"' not in source


# ═══════════════════════════════ G12: загрузка базы не подменяет адрес

# Адреса, законные по RFC 5322 §3.2.3, которые прежний образец резал.
TRICKY = [
    ("o'brien@gmail.com", "апостроф в ирландской фамилии"),
    ("john.doe@gmail.com", "точка — самый частый вид адреса"),
    ("a+b@yahoo.com", "плюс-тег"),
    ("peter!1@outlook.com", "восклицательный знак"),
    ("ivan@xn--80a1acny.xn--p1ai", "домен .рф в punycode"),
    ("bob_smith@aol.com", "подчёркивание"),
    ("m&m@icloud.com", "амперсанд"),
    ("x=y@mail.ru", "знак равенства"),
]


@pytest.mark.parametrize("email,why", TRICKY)
def test_harvest_base_keeps_the_whole_address(email, why):
    """Обрезанный адрес — не потерянный, а ЧУЖОЙ.

    `o'brien@gmail.com` приезжал как `brien@gmail.com`: ящик существует,
    принадлежит другому человеку, и признака подмены нет ни одного.
    """
    from core.streamer import _EMAIL_RE

    found = _EMAIL_RE.search(email)
    assert found is not None, why
    assert found.group(0) == email, "%s -> %s (%s)" % (email, found.group(0), why)


@pytest.mark.parametrize("email,why", TRICKY)
def test_harvest_base_recognises_the_field_as_an_address(email, why):
    """Тот же образец решает, адрес ли это поле строки в базе."""
    from core.streamer import _EMAIL_RE

    assert _EMAIL_RE.fullmatch(email) is not None, why


def test_harvest_base_from_a_line_with_columns():
    """Строка из выгрузки: адрес, имя, страна — через разделитель."""
    from core.streamer import _EMAIL_RE

    line = "o'brien@gmail.com;Патрик;Ирландия"
    assert _EMAIL_RE.search(line).group(0) == "o'brien@gmail.com"


def test_harvest_base_does_not_invent_addresses():
    """Обратная сторона: мусор адресом не становится."""
    from core.streamer import _EMAIL_RE

    for junk in ("не адрес", "@gmail.com", "john@", "john@gmail",
                 "trailing.@x.com", "@@"):
        assert _EMAIL_RE.fullmatch(junk) is None, junk


# ═══════════════════════════════ G13: сбор из выдачи поисковика

def test_harvest_web_keeps_the_apostrophe():
    """Апостроф выбрасывался вместе с кавычками подсветки поисковика.

    Кавычки убирать надо — DuckDuckGo пишет `tom.hovey"@gmail.com"`. Но
    убирали заодно и одинарную, а она в фамилии — часть адреса.
    """
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract("пишите на o'brien@gmail.com сегодня")
    assert "o'brien@gmail.com" in found
    assert "obrien@gmail.com" not in found


def test_harvest_web_keeps_punycode_domains():
    """Проверка «зона состоит из букв» отсеивала ВСЕ кириллические домены."""
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract("контакт: ivan@xn--80a1acny.xn--p1ai")
    assert "ivan@xn--80a1acny.xn--p1ai" in found


def test_harvest_web_still_strips_search_highlighting():
    """Обратная сторона: двойные кавычки подсветки по-прежнему убираются."""
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract('нашлось tom.hovey"@gmail.com"')
    assert "tom.hovey@gmail.com" in found


def test_harvest_web_does_not_swallow_url_parameters():
    """Знаки, которыми устроен адрес ссылки, в адрес не входят.

    Иначе из `?email=john@gmail.com` приехало бы `?email=john@gmail.com` —
    по RFC законное имя ящика, но не то, что написано на странице.
    """
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract("ссылка /page?email=john@gmail.com&ref=1")
    assert "john@gmail.com" in found


def test_harvest_web_reads_mailto_links():
    """Адрес из mailto достаётся тем же образцом, а не отдельным."""
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract('<a href="mailto:o\'brien@company.co.uk">Contact</a>')
    assert "o'brien@company.co.uk" in found


def test_harvest_web_still_drops_the_usual_false_positives():
    """Обратная сторона: картинки и заглушки в базу по-прежнему не идут."""
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract("profile.png@2x example@example.com sentry@1.0.0")
    assert not any(e.endswith(".png") or e.startswith("example@") for e in found)


# ═══════════════════════════════ G14: страж не отвергает punycode-зону

def test_punycode_zone_is_recognised_as_an_address():
    """База, уже переведённая в punycode, объявлялась «не списком адресов».

    Проверка зоны требовала одних букв, а `.рф` на проводе выглядит как
    `xn--p1ai`. Именно в таком виде адрес отдаёт любой экспорт — и весь файл
    отвергался целиком, ещё до проверки.
    """
    from core.input_guard import KIND_EMAIL, detect_kind, looks_like_email

    assert looks_like_email("ivan@xn--80a1acny.xn--p1ai") is True
    assert detect_kind("ivan@xn--80a1acny.xn--p1ai") == KIND_EMAIL


def test_punycode_zone_file_passes_the_guard():
    """Тот же случай целым файлом, как его увидит владелец."""
    from core.input_guard import KIND_EMAIL, check_file

    path = written("ivan@xn--80a1acny.xn--p1ai\nanna@xn--80a1acny.xn--p1ai\n".encode("utf-8"))
    try:
        assert check_file(path, KIND_EMAIL)["ok"] is True
    finally:
        os.unlink(path)


def test_punycode_zone_does_not_open_the_door_to_junk():
    """Обратная сторона: «xn--» само по себе зоной не становится."""
    from core.input_guard import looks_like_email

    assert looks_like_email("ivan@x.xn--") is False
    assert looks_like_email("ivan@xn--") is False
    assert looks_like_email("ivan@x.!!") is False


# ═══════════════════════════════ G15: один ящик — один ключ

def test_idn_dedup_treats_both_spellings_as_one_mailbox():
    """`ivan@почта.рф` и `ivan@xn--80a1acny.xn--p1ai` — ОДИН ящик.

    Ключи были разные, и человек получал письмо дважды. Хуже: отписавшийся
    под одним написанием не был защищён от рассылки по другому.
    """
    from core.cleaner import normalize_for_dedup

    assert (normalize_for_dedup("ivan@почта.рф")
            == normalize_for_dedup("ivan@xn--80a1acny.xn--p1ai"))


def test_idn_dedup_subtracts_the_unsubscribed_in_either_spelling():
    """Тот же ключ обязан работать и в вычитании отписок."""
    from core.baseops import subtract

    left = subtract(["ivan@xn--80a1acny.xn--p1ai", "ivan@gmail.com"],
                    ["ivan@почта.рф"])
    assert left == ["ivan@gmail.com"]


def test_idn_dedup_returns_the_original_address_untouched():
    """Ключ — только для сравнения. Наружу идёт то, что дал владелец."""
    from core.baseops import dedupe

    assert dedupe(["ivan@почта.рф", "ivan@xn--80a1acny.xn--p1ai"]) == ["ivan@почта.рф"]


def test_idn_dedup_keeps_the_old_rules_intact():
    """Обратная сторона: прежние правила ключа не поехали."""
    from core.cleaner import normalize_for_dedup as key

    assert key("john.doe@gmail.com") == key("johndoe@gmail.com")
    assert key("j@googlemail.com") == key("j@gmail.com")
    assert key("john.doe@outlook.com") != key("johndoe@outlook.com")
    assert key("ivan@почта.рф") != key("anna@почта.рф")


# ═══════════════════════════════ G16: имя, которому неоткуда взяться

def test_undefined_names_nowhere_in_the_project():
    """Использованное имя без импорта — то же молчание, что и импорт в пустоту.

    В классическом окне так и было: `StreamLoader` вызывался в сборе адресов,
    а импорта не было. Сбор с прокси падал NameError внутри потока — без
    строки в логе, без окна с ошибкой. Проверка на импорты этого не ловит:
    там имя модуля неверное, здесь имени нет вовсе.
    """
    from pyflakes.api import check
    from pyflakes.reporter import Reporter

    class Collect(io.StringIO):
        pass

    out, err = Collect(), Collect()
    reporter = Reporter(out, err)
    for path in source_files():
        rel = os.path.relpath(path, ROOT)
        if rel.startswith(("tests" + os.sep, ".unlazy" + os.sep)):
            continue
        check(io.open(path, encoding="utf-8", errors="replace").read(), rel, reporter)

    # Имена из ui/colors.py приходят звёздным импортом: pyflakes их не видит,
    # но они настоящие. Их сомнения отбрасываем, чужие — нет.
    import ui.colors as colors
    known = set(dir(colors))

    bad = []
    for line in out.getvalue().splitlines():
        # Само по себе «здесь есть звёздный импорт» — предупреждение о
        # способе, а не находка. Отбрасываем именно его, а не все подряд.
        if "unable to detect undefined names" in line:
            continue
        if "undefined name" not in line and "may be undefined" not in line:
            continue
        found = re.search(r"'([A-Za-z_][A-Za-z0-9_]*)'", line)
        if found and found.group(1) in known:
            continue
        bad.append(line)
    assert bad == [], "имени неоткуда взяться: %s" % bad[:5]


def test_undefined_names_check_can_actually_fail():
    """Отрицательный контроль: сито обязано ловить подставленную ошибку."""
    from pyflakes.api import check
    from pyflakes.reporter import Reporter

    out, err = io.StringIO(), io.StringIO()
    check("def f():\n    return ThisNameDoesNotExist\n", "проба.py", Reporter(out, err))
    assert "undefined name" in out.getvalue()


def test_classic_parser_tab_reads_proxies():
    """Тот самый случай, названный по имени."""
    import ui.parser_tab as tab

    source = io.open(tab.__file__, encoding="utf-8").read()
    assert "from core.streamer import StreamLoader" in source


# ═══════════════════════════════ G17: нумерация в начале строки

NUMBERED = [
    ("1. ivan@gmail.com", "ivan@gmail.com"),
    ("2) anna@mail.ru", "anna@mail.ru"),
    ("100: bob@yahoo.com", "bob@yahoo.com"),
    ("3-й petr@aol.com", "petr@aol.com"),
    ("5 kate@icloud.com", "kate@icloud.com"),
    ("7. 1.2.3.4:8080", "1.2.3.4:8080"),
]


@pytest.mark.parametrize("line,expected", NUMBERED)
def test_numbering_is_actually_stripped(line, expected):
    """Образец не снимал НИЧЕГО: лишняя косая закрывала класс символов.

    Он требовал после цифр буквального «:й». Списки, скопированные с форума
    или из документа, нумерованы почти всегда, и нумерованный прокси
    `1. 1.2.3.4:8080` прокси не является — он терялся построчно.
    """
    from core.streamer import clean_input_line_fast

    assert clean_input_line_fast(line) == expected


def test_numbering_leaves_a_clean_line_alone():
    """Обратная сторона: то, что не нумерация, не трогаем."""
    from core.streamer import clean_input_line_fast

    for line in ("ivan@gmail.com", "1.2.3.4:8080", "1234567890@mail.ru",
                 "site:vk.com @mail.ru"):
        assert clean_input_line_fast(line) == line


def test_numbering_has_one_definition_for_the_whole_program():
    """Копий образца было три, и рабочей — одна.

    Окно чистило вставку своей копией, движок — своей испорченной, а третья
    лежала в gui.py и не использовалась вовсе.
    """
    from core.streamer import clean_input_line_fast
    from ui.widgets import clean_input_line

    assert clean_input_line("1. ivan@gmail.com") == "ivan@gmail.com"
    assert clean_input_line.__module__ != clean_input_line_fast.__module__
    assert clean_input_line("1. ivan@gmail.com") == clean_input_line_fast("1. ivan@gmail.com")

    gui = io.open(os.path.join(ROOT, "ui", "gui.py"), encoding="utf-8").read()
    assert "CLEAN_PREFIX_RE = re.compile" not in gui


def test_numbering_survives_a_whole_numbered_file():
    """Как это выглядит у владельца: файл, скопированный с нумерацией."""
    from core.streamer import StreamLoader

    path = written("1. ivan@gmail.com\n2. анна@mail.ru\n3. bob@yahoo.com\n".encode("cp1251"))
    try:
        lines = list(StreamLoader([{"type": "file", "path": path}]).stream_lines())
        assert lines == ["ivan@gmail.com", "анна@mail.ru", "bob@yahoo.com"]
    finally:
        os.unlink(path)


# ═══════════════════════════════ G18: ячейка CSV — не формула

def test_csv_cell_does_not_become_a_formula_in_excel():
    """База собрана со страниц в интернете, то есть её пишет кто угодно.

    Ячейка, начинающаяся со знака равенства, в Excel не показывается, а
    ВЫПОЛНЯЕТСЯ.
    """
    from core.baseops import csv_cell

    for danger in ("=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)"):
        assert csv_cell(danger).startswith("'"), danger


def test_csv_cell_leaves_ordinary_values_alone():
    """Обратная сторона: обычное значение не портим."""
    from core.baseops import csv_cell

    for ok in ("ivan@gmail.com", "Иван", "Россия", "85", ""):
        assert csv_cell(ok) == ok
    assert csv_cell(None) is None
    assert csv_cell(42) == 42


def test_csv_export_puts_the_guard_on_every_column():
    """Проверяется выгрузка целиком, а не одна функция."""
    import csv

    from core.baseops import write_chunks_stream, csv_row

    def writer(handle, rows):
        w = csv.writer(handle)
        w.writerow(["Email", "Name"])
        for row in rows:
            w.writerow(csv_row(row))

    path = tempfile.mktemp(suffix=".csv")
    try:
        write_chunks_stream([["ivan@gmail.com", "=HYPERLINK(\"http://x\")"]],
                            path, 0, writer)
        text = io.open(path, encoding="utf-8-sig").read()
        assert "'=HYPERLINK" in text
    finally:
        if os.path.exists(path):
            os.unlink(path)
