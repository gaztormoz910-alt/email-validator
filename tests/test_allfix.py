# -*- coding: utf-8 -*-
from исходники import исходник_окна
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
                                "node_modules", "build", "dist")]
        for name in files:
            if name.endswith(".py"):
                yield os.path.join(base, name)


def test_parser_starts_when_proxies_are_loaded():
    from ui import webapp

    source = io.open(webapp.__file__, encoding="utf-8").read()
    assert "core.stream_loader" not in source
    assert importlib.util.find_spec("core.streamer") is not None


def test_parser_starts_every_internal_import_resolves():
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
    source = исходник_окна()
    launch = source[source.index("def parser_start"):]
    launch = launch[:launch.index("def parser_pause")]
    assert "from core.streamer import StreamLoader" in launch
    assert "dedupe_proxies_stream" in launch


def test_start_flag_survives_a_run_without_sources():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    answer = api.start({})
    assert answer["ok"] is False
    assert "выберите" in answer["error"].lower()
    assert api._starting is False, "флаг остался взведённым — кнопка мертва"


def test_start_flag_is_released_when_the_launch_raises():
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
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": "ivan@gmail.com"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:8080"})
    api._starting = True
    assert api.start({})["error"] == "Проверка уже идёт"


class _Resolver(object):

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
    v = _validator()
    answers = {("example.com", "TXT"): ["v=spf1 include:_spf.example.com ~all"]}
    v.resolver = _Resolver(answers, fail_times=99)

    first = v.check_dns_health("example.com")
    assert first["has_spf"] is False, "подготовка теста неверна"

    v.resolver = _Resolver(answers)
    second = v.check_dns_health("example.com")
    assert second["has_spf"] is True, "нуль от сбоя закэширован — домен наказан"


def test_dns_health_partial_failure_is_not_cached_either():
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
    v = _validator()
    empty = _Resolver({})
    v.resolver = empty
    v.check_dns_health("nothing.example")
    after_first = empty.calls
    v.check_dns_health("nothing.example")
    assert empty.calls == after_first, "ответ «записей нет» не запомнился"


def test_reads_any_encoding_in_base_operations():
    from core.baseops import read_emails

    path = written("ivan@gmail.com\nанна@mail.ru\n".encode("cp1251"))
    try:
        assert read_emails(path) == ["ivan@gmail.com", "анна@mail.ru"]
    finally:
        os.unlink(path)


def test_reads_any_encoding_in_domain_filters():
    from core.filters import SpamFilter

    path = written("# мои одноразовые\nтемп.рф\ntempmail.example\n".encode("cp1251"))
    try:
        domains = SpamFilter._read_domains(path)
        assert "tempmail.example" in domains
        assert "темп.рф" in domains
    finally:
        os.unlink(path)


def test_reads_any_encoding_in_the_input_guard():
    from core.input_guard import check_file, KIND_EMAIL

    path = written("ivan@gmail.com\nanna@yahoo.com\nпётр@mail.ru\n".encode("cp1251"))
    try:
        assert check_file(path, KIND_EMAIL)["ok"] is True
    finally:
        os.unlink(path)


def test_reads_any_encoding_when_the_file_goes_into_the_text_field():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    path = written("анна@mail.ru\n".encode("cp1251"))
    try:
        assert "анна@mail.ru" in api._read_inline(path)
    finally:
        os.unlink(path)


def test_reads_any_encoding_utf8_is_not_broken_by_the_fix():
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


def test_unsubscribe_list_in_cp1251_still_subtracts():
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
    from core.baseops import _key

    assert _key("john.doe@gmail.com") == _key("johndoe@gmail.com")
    assert _key("john.doe@outlook.com") != _key("johndoe@outlook.com")


def test_excel_reads_the_export_without_mojibake():
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
        with open_text(path) as handle:
            assert handle.read().splitlines()[0] == "Email,Name"
    finally:
        if os.path.exists(path):
            os.unlink(path)


def test_excel_marker_is_not_added_to_plain_text_lists():
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


def test_not_a_path_does_not_close_our_own_output():
    from core.encoding import detect_encoding, read_sample

    assert detect_encoding(True) == "utf-8"
    assert detect_encoding(0) == "utf-8"
    assert read_sample(1) == b""
    print("вывод жив")


def test_not_a_path_answers_instead_of_crashing():
    from core.encoding import detect_encoding

    for junk in (None, 3.5, [], {}, set(), object(), b"", "\x00"):
        assert detect_encoding(junk) in ("utf-8", "cp1251")


def test_not_a_path_still_raises_when_opening_a_missing_file():
    from core.encoding import open_text

    with pytest.raises(FileNotFoundError):
        open_text(os.path.join(tempfile.gettempdir(), "нет-такого-файла.txt"))
    with pytest.raises(TypeError):
        open_text(None)


def test_backoff_decay_releases_the_pause():
    from core.proxy_pool import MX_ERROR_HALF_LIFE_SEC

    v = _validator()
    for _ in range(6):
        v._record_mx_error("mx.example.com")

    slow = v._mx_delay("mx.example.com")
    assert slow > 3.0, "торможение вообще не сработало — тест ничего не мерит"

    with v._mx_error_lock:
        v._mx_error_seen["mx.example.com"] = time.time() - MX_ERROR_HALF_LIFE_SEC * 10

    assert v._mx_delay("mx.example.com") < 0.5, "пауза не отпустила"


def test_backoff_decay_gives_the_stream_back():
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
    v = _validator()
    for _ in range(6):
        v._record_mx_error("mx.example.com")
    assert v._decayed_mx_errors("mx.example.com") >= 5.0
    assert v._mx_delay("mx.example.com") > 3.0


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
    from core.streamer import _EMAIL_RE

    found = _EMAIL_RE.search(email)
    assert found is not None, why
    assert found.group(0) == email, "%s -> %s (%s)" % (email, found.group(0), why)


@pytest.mark.parametrize("email,why", TRICKY)
def test_harvest_base_recognises_the_field_as_an_address(email, why):
    from core.streamer import _EMAIL_RE

    assert _EMAIL_RE.fullmatch(email) is not None, why


def test_harvest_base_from_a_line_with_columns():
    from core.streamer import _EMAIL_RE

    line = "o'brien@gmail.com;Патрик;Ирландия"
    assert _EMAIL_RE.search(line).group(0) == "o'brien@gmail.com"


def test_harvest_base_does_not_invent_addresses():
    from core.streamer import _EMAIL_RE

    for junk in ("не адрес", "@gmail.com", "john@", "john@gmail",
                 "trailing.@x.com", "@@"):
        assert _EMAIL_RE.fullmatch(junk) is None, junk


def test_harvest_web_keeps_the_apostrophe():
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract("пишите на o'brien@gmail.com сегодня")
    assert "o'brien@gmail.com" in found
    assert "obrien@gmail.com" not in found


def test_harvest_web_keeps_punycode_domains():
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract("контакт: ivan@xn--80a1acny.xn--p1ai")
    assert "ivan@xn--80a1acny.xn--p1ai" in found


def test_harvest_web_still_strips_search_highlighting():
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract('нашлось tim.harrow"@gmail.com"')
    assert "tim.harrow@gmail.com" in found


def test_harvest_web_does_not_swallow_url_parameters():
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract("ссылка /page?email=john@gmail.com&ref=1")
    assert "john@gmail.com" in found


def test_harvest_web_reads_mailto_links():
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract('<a href="mailto:o\'brien@company.co.uk">Contact</a>')
    assert "o'brien@company.co.uk" in found


def test_harvest_web_still_drops_the_usual_false_positives():
    from core.parser.extractor import EmailExtractor

    found = EmailExtractor().extract("profile.png@2x example@example.com sentry@1.0.0")
    assert not any(e.endswith(".png") or e.startswith("example@") for e in found)


def test_punycode_zone_is_recognised_as_an_address():
    from core.input_guard import KIND_EMAIL, detect_kind, looks_like_email

    assert looks_like_email("ivan@xn--80a1acny.xn--p1ai") is True
    assert detect_kind("ivan@xn--80a1acny.xn--p1ai") == KIND_EMAIL


def test_punycode_zone_file_passes_the_guard():
    from core.input_guard import KIND_EMAIL, check_file

    path = written("ivan@xn--80a1acny.xn--p1ai\nanna@xn--80a1acny.xn--p1ai\n".encode("utf-8"))
    try:
        assert check_file(path, KIND_EMAIL)["ok"] is True
    finally:
        os.unlink(path)


def test_punycode_zone_does_not_open_the_door_to_junk():
    from core.input_guard import looks_like_email

    assert looks_like_email("ivan@x.xn--") is False
    assert looks_like_email("ivan@xn--") is False
    assert looks_like_email("ivan@x.!!") is False


def test_idn_dedup_treats_both_spellings_as_one_mailbox():
    from core.cleaner import normalize_for_dedup

    assert (normalize_for_dedup("ivan@почта.рф")
            == normalize_for_dedup("ivan@xn--80a1acny.xn--p1ai"))


def test_idn_dedup_subtracts_the_unsubscribed_in_either_spelling():
    from core.baseops import subtract

    left = subtract(["ivan@xn--80a1acny.xn--p1ai", "ivan@gmail.com"],
                    ["ivan@почта.рф"])
    assert left == ["ivan@gmail.com"]


def test_idn_dedup_returns_the_original_address_untouched():
    from core.baseops import dedupe

    assert dedupe(["ivan@почта.рф", "ivan@xn--80a1acny.xn--p1ai"]) == ["ivan@почта.рф"]


def test_idn_dedup_keeps_the_old_rules_intact():
    from core.cleaner import normalize_for_dedup as key

    assert key("john.doe@gmail.com") == key("johndoe@gmail.com")
    assert key("j@googlemail.com") == key("j@gmail.com")
    assert key("john.doe@outlook.com") != key("johndoe@outlook.com")
    assert key("ivan@почта.рф") != key("anna@почта.рф")


def test_undefined_names_nowhere_in_the_project():
    from pyflakes.api import check
    from pyflakes.reporter import Reporter

    class Collect(io.StringIO):
        pass

    out, err = Collect(), Collect()
    reporter = Reporter(out, err)
    for path in source_files():
        rel = os.path.relpath(path, ROOT)
        if rel.startswith("tests" + os.sep):
            continue
        check(io.open(path, encoding="utf-8", errors="replace").read(), rel, reporter)

    import ui.colors as colors
    known = set(dir(colors))

    bad = []
    for line in out.getvalue().splitlines():
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
    from pyflakes.api import check
    from pyflakes.reporter import Reporter

    out, err = io.StringIO(), io.StringIO()
    check("def f():\n    return ThisNameDoesNotExist\n", "проба.py", Reporter(out, err))
    assert "undefined name" in out.getvalue()


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
    from core.streamer import clean_input_line_fast

    assert clean_input_line_fast(line) == expected


def test_numbering_leaves_a_clean_line_alone():
    from core.streamer import clean_input_line_fast

    for line in ("ivan@gmail.com", "1.2.3.4:8080", "1234567890@mail.ru",
                 "site:vk.com @mail.ru"):
        assert clean_input_line_fast(line) == line


def test_numbering_survives_a_whole_numbered_file():
    from core.streamer import StreamLoader

    path = written("1. ivan@gmail.com\n2. анна@mail.ru\n3. bob@yahoo.com\n".encode("cp1251"))
    try:
        lines = list(StreamLoader([{"type": "file", "path": path}]).stream_lines())
        assert lines == ["ivan@gmail.com", "анна@mail.ru", "bob@yahoo.com"]
    finally:
        os.unlink(path)


def test_csv_cell_does_not_become_a_formula_in_excel():
    from core.baseops import csv_cell

    for danger in ("=HYPERLINK(\"http://x\")", "+1+1", "-2+3", "@SUM(A1)"):
        assert csv_cell(danger).startswith("'"), danger


def test_csv_cell_leaves_ordinary_values_alone():
    from core.baseops import csv_cell

    for ok in ("ivan@gmail.com", "Иван", "Россия", "85", ""):
        assert csv_cell(ok) == ok
    assert csv_cell(None) is None
    assert csv_cell(42) == 42


def test_csv_export_puts_the_guard_on_every_column():
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
