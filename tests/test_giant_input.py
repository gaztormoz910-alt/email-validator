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

from core.provider import canonical_country, canonical_gender
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


# Класс TestLoadingDoesNotBlockTheWindow и обвязка под него удалены
# 06.09.2026 вместе со старым окном: они звали ValidatorApp._attach_sources,
# то есть проверяли предпросмотр ИМЕННО того окна.
#
# Смысл их не потерян. То же самое на веб-окне сторожит
# tests/test_web_ui.py: большой файл подключается, в поле не
# показывается, и владельцу это сказано в логе. А что подсчёт строк идёт
# в фоне — audit/verify_gaps_closed.py, проверка web_counting_is_background.


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
        # Пол и страна приводятся к одному написанию ещё в загрузчике.
        # Значение при этом не выдумывается: `female` и `US` из файла — это
        # ровно «Женский» и «США», просто записанные так же, как их называют
        # предиктор и домен. Без приведения в фильтре окна получались четыре
        # кучки по стране вместо одной (ЗАМЕРЕНО на базе владельца: USA
        # 314 561, united states 66 536, United States 5 096) и девять по
        # полу вместо двух.
        self.assertEqual(data.get("gender"),
                         canonical_gender(SAMPLE_GENDERS[0]))
        self.assertEqual(data.get("country"),
                         canonical_country(SAMPLE_COUNTRIES[0]))
        # Явные значения рядом с выводом функции: иначе проверка стала бы
        # тавтологией и молчала бы, если приведение сломается целиком.
        self.assertEqual(data.get("gender"), "Женский")
        self.assertEqual(data.get("country"), "США")

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
