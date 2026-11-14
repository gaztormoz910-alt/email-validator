"""Границы кусков имени — после замера на настоящих базах (13–14.11.2026).

Владелец спросил, не выдаёт ли обогатитель неверные имена. Замер на его
базах (27 753 адреса, режим «Точность») показал около одного неверного
имени из пяти, и большая часть ошибок была про границы кусков: редкая
фамилия дробилась на короткие «имена» и буквы, слово-занятие в хвосте
липло фамилией, запись «буква + фамилия» терялась, кусок после точки
резался заново. Правила — в core/parser/name_split.py.

Здесь те же виды ошибок на ВЫДУМАННЫХ адресах: настоящие адреса владельца
в отслеживаемые файлы не попадают. Тест с именем test_fixed_* закрепляет
новое поведение — на коде коммита eeb29dc каждый его случай давал другое
(сверено выгрузкой коммита 14.11.2026); test_kept_* — то, что работало и
раньше и не должно сломаться.

Решение владельца 14.11.2026: в «Точности» угаданное имя — только из
кусков, которые база знает (confirmed_name в core/parser/name_split.py).

Чего правка НЕ закрыла (замер на отложенной выборке из 200 имён): слитная
строка, которую разбор режет на известные базе, но неверные куски
(`sofiaferrinelli` -> «Sofia Ferri Nelli»), и занятие на чужом языке как
фамилия. Неверных имён в «Точности» около 15% (до правки около 20%).
"""
import io
import os
import subprocess
import sys
import unittest

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser.name_extractor import NameExtractor
from core.parser.ml_predictor import get_country_mode, set_country_mode
from core.parser import name_split

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_cache = {}


def extractor():
    """Один экземпляр на файл: конструктор грузит базу на 138 млн имён."""
    if "ex" not in _cache:
        _cache["ex"] = NameExtractor(enable_osint=False)
    return _cache["ex"]


class _Accuracy(unittest.TestCase):
    """Режим «Точность» на время теста; глобальная настройка возвращается."""

    MODE = "accuracy"

    def setUp(self):
        was = get_country_mode()
        self.addCleanup(set_country_mode, was)
        set_country_mode(self.MODE)

    def name(self, local):
        return extractor().extract_name(local + "@example.com") or ""

    def check(self, rows):
        for local, expected in rows:
            with self.subTest(local=local):
                self.assertEqual(self.name(local), expected)


class TestBoundaries(_Accuracy):

    def test_fixed_accuracy_does_not_guess_an_unknown_surname(self):
        # Решение владельца 14.11.2026: в «Точности» угаданное имя — только
        # из кусков, которые база знает. Редкая фамилия, которой в ней нет,
        # даёт пусто, хотя её и можно было бы угадать. На eeb29dc: «Elena Cor
        # Etti», «Emma Birdi», «Daniel Grumbach».
        self.check([("elenacorvetti", ""), ("emmabirdie", ""), ("danielgrumbach", "")])

    def test_kept_short_east_asian_surname_counts_as_known(self):
        # Li и Ly короче четырёх букв, но проект знает их отдельным перечнем;
        # строгость «Точности» их не хоронит.
        self.check([("jingli", "Jing Li"), ("hungly", "Hung Ly")])

    def test_fixed_occupation_in_the_tail_goes(self):
        # Art и Dev — имена, поэтому в общий перечень ролей их не положишь;
        # последним после имени это занятие. На eeb29dc: «Anna Lopez Dev»,
        # «Maria Garcia Art».
        self.check([("annalopezdev", "Anna Lopez"),
                    ("maria.garcia.art", "Maria Garcia")])

    def test_kept_occupation_word_that_is_a_name_stays_in_front(self):
        self.check([("dev.patel", "Dev Patel")])

    def test_fixed_initial_and_surname_that_the_index_also_knows_as_a_name(self):
        # Boyd и Archer индекс знает именами, но фамилией каждое намного чаще.
        # На eeb29dc запись «И. Фамилия» терялась целиком.
        self.check([("kboyd", "K Boyd"), ("tarcher", "T Archer")])

    def test_fixed_common_surname_that_is_an_english_word(self):
        # Black — 145-я фамилия и словарное слово; порог стоял на 100-й.
        self.check([("laurablack", "Laura Black")])

    def test_fixed_part_after_a_dot_is_not_cut_again(self):
        # Человек уже разделил имя и фамилию точкой. На eeb29dc: «Ivan D Orlov».
        self.check([("ivan.dorlov", "Ivan Dorlov")])

    def test_kept_names_next_to_the_new_rules(self):
        # Контроль: правила не косят всё подряд.
        self.check([("peter.dagnov", "Peter Dagnov"),
                    ("kevinhallbgx", "Kevin Hall"),
                    ("maria.lopez.tech", "Maria Lopez")])

    def test_kept_business_names_stay_empty(self):
        self.check([("GoldenPeakAcademy", ""), ("BlueRiverStudio", ""),
                    ("lucypowersbiz", "")])


class TestBoundariesCoverage(_Accuracy):
    """«Заполненность» угаданную фамилию оставляет — и режет её теперь верно."""

    MODE = "coverage"

    def test_fixed_rare_surname_is_not_cut_into_pieces(self):
        # Редкая фамилия, которой база не знает, дробилась на известные
        # обломки. На eeb29dc в «Заполненности»: «Elena Cor Etti», «Emma Birdi».
        self.check([("elenacorvetti", "Elena Corvetti"),
                    ("emmabirdie", "Emma Birdie")])

    def test_kept_rare_surname_guess(self):
        # Эти и раньше разбирались верно — и не должны сломаться.
        self.check([("tomasvarelli", "Tomas Varelli"),
                    ("danielgrumbach", "Daniel Grumbach")])


class TestNameShape(unittest.TestCase):
    """Признаки «похоже на имя» — на данных из tools/build_name_trigrams.py."""

    def setUp(self):
        self.q = extractor().quality

    def test_known_names_and_surnames_are_name_shaped(self):
        for word in ("varelli", "corvetti", "dorlov", "lindqvist", "okonkwo"):
            with self.subTest(word=word):
                self.assertTrue(self.q.name_shaped(word))

    def test_keyboard_junk_is_not_name_shaped(self):
        # Контроль: признак вообще что-то отвергает.
        for word in ("mqtzk", "bgxq", "xqzvt"):
            with self.subTest(word=word):
                self.assertFalse(self.q.name_shaped(word))

    def test_consonant_groups(self):
        self.assertTrue(self.q.cluster_shaped("varelli"))
        self.assertFalse(self.q.cluster_shaped("bcavel"))     # с «bc» имена не начинаются
        self.assertFalse(self.q.cluster_shaped("navetc"))     # на «tc» не кончаются
        self.assertFalse(self.q.cluster_shaped("bcdfg"))      # одни согласные

    def test_missing_data_file_keeps_the_rule_quiet(self):
        # Без файла признак молчит (всё «похоже на имя»), а не хоронит всё.
        saved = name_split._TRIGRAMS
        self.addCleanup(setattr, name_split, "_TRIGRAMS", saved)
        name_split._TRIGRAMS = frozenset()
        self.assertTrue(self.q.name_shaped("mqtzk"))


class TestPackaging(unittest.TestCase):

    def test_installer_ships_the_shape_data(self):
        # Без этих строк собранная программа молча теряла бы проверку формы:
        # файл не найден — признак молчит (см. выше).
        spec = io.open(os.path.join(ROOT, "MailFact.spec"), encoding="utf-8").read()
        for name in ("name_trigrams.txt", "name_clusters.txt"):
            with self.subTest(name=name):
                self.assertTrue(os.path.getsize(os.path.join(ROOT, "core", "parser", name)) > 0)
                self.assertIn('("core/parser/%s", "core/parser")' % name, spec)

    @pytest.mark.slow
    def test_shape_data_matches_its_builder(self):
        # Файлы собираются из базы имён; правка порога без пересборки — ошибка.
        done = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "build_name_trigrams.py"),
                               "--check"], cwd=ROOT, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              env=dict(os.environ, PYTHONIOENCODING="utf-8"))
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn("NAME-TRIGRAMS-OK", done.stdout)


if __name__ == "__main__":
    unittest.main()
