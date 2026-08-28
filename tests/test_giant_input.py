"""Гигантский вход: почты, прокси и дорки грузятся, не подвешивая окно.

Требование владельца было буквальным: «чтобы я мог ЛЮБЫЕ даже ГИГАНТСКИЕ
объёмы данных загружать и чтобы при этом софт не лагал и не зависал вообще —
и не важно, запущен ли софт и уже работает полноценно или нет».

Отсюда три разных свойства, и каждое проверяется отдельно:

1. **Главный поток не читает файлы.** Обработчик кнопки обязан вернуться
   мгновенно независимо от размера файла. Раньше он читал файл прямо в
   обработчике, а в двух путях из четырёх — ЦЕЛИКОМ: проверка `if idx < 5000`
   стояла внутри цикла, а `break` отсутствовал, поэтому первые пять тысяч
   строк показывались, а остальные читались молча и в никуда.

2. **Предпросмотр ограничен.** Сколько бы строк ни было в файле, читается
   ровно потолок и ни строкой больше.

3. **Знаменатель прогресса не стоит полного прохода до старта.** Оценка по
   размеру файла даёт число мгновенно, точный счёт уточняет его потом.

Тесты не требуют Tk: методы окна вызываются на подставном объекте, потому что
проверяется поведение с файлами, а не отрисовка.
"""
import os
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.streamer import StreamLoader

# Столько строк пишем во временный файл. Достаточно, чтобы полное чтение
# заняло заметно больше времени, чем разрешено обработчику кнопки.
BIG_LINES = 400_000

# Имена берём НАСТОЯЩИЕ, а не Name0/Name1. Выдуманное «Name7» — это буквы с
# цифрой без пробела, то есть по форме неотличимо от пароля из связки
# email:password, и классификатор колонок обязан считать такое мусором. Тест
# на выдуманных данных проверял бы не разбор доп. полей, а поведение на
# паролях, и требовал бы от кода неправильного.
SAMPLE_NAMES = ("Anna", "John Smith", "Mohammed Ali", "Elena", "Wei Chen",
                "Carlos Ruiz", "Priya", "Ivan Petrov", "Yuki", "Sofia Rossi")
SAMPLE_GENDERS = ("female", "male", "male", "female", "male",
                  "male", "female", "male", "female", "female")
SAMPLE_COUNTRIES = ("US", "UK", "Egypt", "Russia", "China",
                    "Spain", "India", "Russia", "Japan", "Italy")


def make_big_file(kind="emails"):
    handle, path = tempfile.mkstemp(suffix=".txt")
    with os.fdopen(handle, "w", encoding="utf-8") as f:
        for i in range(BIG_LINES):
            if kind == "emails":
                f.write(f"user{i}@example{i % 97}.com,{SAMPLE_NAMES[i % 10]},"
                        f"{SAMPLE_GENDERS[i % 10]},{SAMPLE_COUNTRIES[i % 10]}\n")
            elif kind == "proxies":
                f.write(f"192.168.{i % 250}.{i % 251}:{1080 + i % 900}\n")
            else:
                f.write(f'site:example{i}.com intext:"@gmail.com" inurl:contact{i}\n')
    return path


class FakeTextbox:
    def __init__(self):
        self.lines = []
        self.cleared = 0

    def delete(self, *_a):
        self.cleared += 1
        self.lines = []

    def insert(self, _where, text):
        self.lines.append(text)


class FakeSelector:
    def __init__(self):
        self.textbox = FakeTextbox()
        self.text = None
        self.appended = []

    def set_text(self, value):
        self.text = value

    def append_to_textbox(self, lines):
        self.appended.extend(lines)


class FakeLabel:
    def __init__(self):
        self.text = None

    def configure(self, text=None, **_kw):
        self.text = text


class FakeApp:
    """Подставное окно: помнит отложенные вызовы и умеет их выполнить."""

    from ui.gui import ValidatorApp as _real
    PREVIEW_LINES = _real.PREVIEW_LINES
    BREATHE_EVERY = _real.BREATHE_EVERY
    _attach_sources = _real._attach_sources
    # _ui_call берётся у настоящего окна, а не подменяется: через него идут
    # ВСЕ обращения фонового потока к главному, и подставная копия скрыла бы
    # ошибку именно в том месте, ради которого проверка и написана.
    _ui_call = _real._ui_call
    del _real

    def __init__(self):
        self.deferred = []
        self.logged = []

    def after(self, _delay, callback):
        self.deferred.append(callback)

    def log(self, message, _tag=None):
        self.logged.append(message)

    def run_deferred(self, timeout=60):
        """Ждёт фоновый поток и выполняет то, что он отложил на главный поток."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for thread in threading.enumerate():
                if thread is not threading.current_thread() and thread.daemon:
                    thread.join(0.05)
            if len(self.deferred) >= 2:      # показ предпросмотра и подпись счёта
                break
            time.sleep(0.05)
        for callback in list(self.deferred):
            callback()


class TestLoadingDoesNotBlockTheWindow(unittest.TestCase):
    """Обработчик кнопки обязан вернуться мгновенно на файле любого размера."""

    # Потолок на главный поток. Полное чтение файла на 400k строк занимает
    # сотни миллисекунд — то есть выйти за этот порог можно только начав
    # читать файл там, где читать нельзя.
    MAIN_THREAD_BUDGET_S = 0.15

    @classmethod
    def setUpClass(cls):
        cls.paths = {kind: make_big_file(kind)
                     for kind in ("emails", "proxies", "dorks")}

    @classmethod
    def tearDownClass(cls):
        for path in cls.paths.values():
            try:
                os.remove(path)
            except OSError:
                pass

    def _attach(self, kind, mode):
        app = FakeApp()
        sources, selector, label = [], FakeSelector(), FakeLabel()
        started = time.perf_counter()
        app._attach_sources([self.paths[kind]], sources, selector, label,
                            "{count}", app.log, mode=mode)
        elapsed = time.perf_counter() - started
        app.run_deferred()
        return app, sources, selector, label, elapsed

    def test_emails_attach_returns_immediately(self):
        _app, sources, _sel, _lbl, elapsed = self._attach("emails", "emails")
        self.assertEqual(len(sources), 1)
        self.assertLess(
            elapsed, self.MAIN_THREAD_BUDGET_S,
            f"главный поток занят {elapsed*1000:.0f} мс на файле в {BIG_LINES} строк "
            "— значит файл читается в обработчике кнопки")

    def test_proxies_attach_returns_immediately(self):
        _app, _s, _sel, _lbl, elapsed = self._attach("proxies", "lines")
        self.assertLess(elapsed, self.MAIN_THREAD_BUDGET_S)

    def test_dorks_attach_returns_immediately(self):
        _app, _s, _sel, _lbl, elapsed = self._attach("dorks", "lines")
        self.assertLess(elapsed, self.MAIN_THREAD_BUDGET_S)

    def test_positive_control_full_read_would_blow_the_budget(self):
        """Контроль: полное чтение того же файла обязано не уложиться в бюджет.

        Без него первая проверка была бы зелёной и на пустом файле, то есть
        не доказывала бы ничего.
        """
        started = time.perf_counter()
        total = sum(1 for _ in StreamLoader(
            [{"type": "file", "path": self.paths["emails"]}]).stream_emails())
        elapsed = time.perf_counter() - started
        self.assertEqual(total, BIG_LINES)
        self.assertGreater(
            elapsed, self.MAIN_THREAD_BUDGET_S,
            f"полное чтение заняло всего {elapsed*1000:.0f} мс — бюджет выбран "
            "слишком мягким и проверка ничего не доказывает")

    def test_preview_stops_at_the_cap(self):
        app, _s, selector, _lbl, _e = self._attach("emails", "emails")
        self.assertEqual(len(selector.appended), app.PREVIEW_LINES,
                         "предпросмотр не оборвался на потолке")
        self.assertTrue(selector.appended[0].startswith("user0@"))

    def test_counter_is_filled_in_afterwards(self):
        _app, _s, _sel, label, _e = self._attach("dorks", "lines")
        self.assertEqual(label.text, str(BIG_LINES),
                         f"подпись счётчика осталась {label.text!r}")

    def test_small_file_shows_everything(self):
        """Ограничение предпросмотра не должно врать на маленьком файле."""
        handle, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            for i in range(20):
                f.write(f"a{i}@example.com\n")
        self.addCleanup(os.remove, path)

        app = FakeApp()
        sources, selector, label = [], FakeSelector(), FakeLabel()
        app._attach_sources([path], sources, selector, label, "{count}",
                            app.log, mode="emails")
        app.run_deferred()
        self.assertEqual(len(selector.appended), 20)
        self.assertEqual(label.text, "20")


class TestCountingIsCheap(unittest.TestCase):
    """Знаменатель прогресса не должен стоить полного прохода по файлу."""

    @classmethod
    def setUpClass(cls):
        cls.path = make_big_file("dorks")
        cls.source = [{"type": "file", "path": cls.path}]

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(cls.path)
        except OSError:
            pass

    def test_exact_count_is_correct(self):
        self.assertEqual(StreamLoader(self.source).count_total_lines(), BIG_LINES)

    def test_estimate_is_much_faster_than_exact(self):
        started = time.perf_counter()
        StreamLoader(self.source).estimate_total_lines()
        fast = time.perf_counter() - started

        started = time.perf_counter()
        StreamLoader(self.source).count_total_lines()
        slow = time.perf_counter() - started

        self.assertLess(fast, max(slow, 0.001),
                        f"оценка ({fast*1000:.1f} мс) не быстрее точного счёта "
                        f"({slow*1000:.1f} мс) — значит она тоже читает файл целиком")

    def test_estimate_is_in_the_right_ballpark(self):
        estimate = StreamLoader(self.source).estimate_total_lines()
        error = abs(estimate - BIG_LINES) / BIG_LINES
        self.assertLess(error, 0.5,
                        f"оценка {estimate} против настоящих {BIG_LINES} — "
                        f"ошибка {error*100:.0f}%")

    def test_exact_count_handles_missing_trailing_newline(self):
        handle, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            f.write("a@example.com\nb@example.com")     # без перевода в конце
        self.addCleanup(os.remove, path)
        self.assertEqual(
            StreamLoader([{"type": "file", "path": path}]).count_total_lines(), 2)

    def test_counting_survives_missing_and_broken_sources(self):
        broken = [{"type": "file", "path": "/nope/missing.txt"},
                  {"type": "text", "content": "a@b.com\n\nc@d.com\n"},
                  {"type": "weird"}]
        self.assertEqual(StreamLoader(broken).count_total_lines(), 2)
        self.assertEqual(StreamLoader(broken).estimate_total_lines(), 2)

    def test_empty_input_is_zero_not_a_crash(self):
        self.assertEqual(StreamLoader([]).count_total_lines(), 0)
        self.assertEqual(StreamLoader([]).estimate_total_lines(), 0)


class TestStreamingStaysLazy(unittest.TestCase):
    """Поток обязан отдавать первую строку, не дочитав файл до конца."""

    @classmethod
    def setUpClass(cls):
        cls.path = make_big_file("emails")

    @classmethod
    def tearDownClass(cls):
        try:
            os.remove(cls.path)
        except OSError:
            pass

    def test_first_email_arrives_fast(self):
        source = [{"type": "file", "path": self.path}]
        started = time.perf_counter()
        first = next(StreamLoader(source).stream_emails())
        elapsed = time.perf_counter() - started
        self.assertEqual(first[0], "user0@example0.com")
        self.assertLess(elapsed, 0.15,
                        f"первая строка пришла через {elapsed*1000:.0f} мс — "
                        "генератор материализует файл")

    def test_extra_columns_are_parsed_not_dropped(self):
        source = [{"type": "file", "path": self.path}]
        _email, data = next(StreamLoader(source).stream_emails())
        self.assertEqual(data.get("name"), SAMPLE_NAMES[0])
        self.assertEqual(data.get("gender"), SAMPLE_GENDERS[0])
        self.assertEqual(data.get("country"), SAMPLE_COUNTRIES[0])

    def test_plain_list_without_extra_columns_also_works(self):
        handle, path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(handle, "w", encoding="utf-8") as f:
            f.write("solo@example.com\nother@example.com\n")
        self.addCleanup(os.remove, path)
        rows = list(StreamLoader([{"type": "file", "path": path}]).stream_emails())
        self.assertEqual([r[0] for r in rows],
                         ["solo@example.com", "other@example.com"])


if __name__ == "__main__":
    unittest.main()
