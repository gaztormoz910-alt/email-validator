# -*- coding: utf-8 -*-
import os
import sys
import unittest

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, КОРЕНЬ)

from ui.result_store import ResultStore

ДАННЫЕ = {"engagement_score": 70, "name": "Ivan Petrov", "gender": "male",
          "country": "RU", "provider": "Gmail"}


def положить(хранилище, адрес, статус="Valid"):
    return хранилище.append(адрес, статус, "250 OK", "mx.example.com", ДАННЫЕ)


class TestПовторНеСоздаётВторуюСтроку(unittest.TestCase):

    def setUp(self):
        self.хранилище = ResultStore(drop_repeats=True)
        self.addCleanup(self.хранилище.close)

    def всего(self):
        return self.хранилище.counts()["total"]

    def test_один_и_тот_же_адрес_ложится_один_раз(self):
        положить(self.хранилище, "ivan@gmail.com")
        положить(self.хранилище, "ivan@gmail.com")
        self.assertEqual(self.всего(), 1)

    def test_повтор_возвращает_прежнюю_группу(self):
        первая = положить(self.хранилище, "ivan@gmail.com", "Valid")
        вторая = положить(self.хранилище, "ivan@gmail.com", "Invalid")
        self.assertEqual(вторая, первая)

    def test_регистр_и_пробелы_не_создают_нового_ящика(self):
        положить(self.хранилище, "ivan@gmail.com")
        положить(self.хранилище, "  IVAN@Gmail.com  ")
        self.assertEqual(self.всего(), 1)

    def test_разные_адреса_не_склеиваются(self):
        положить(self.хранилище, "ivan@gmail.com")
        положить(self.хранилище, "anna@gmail.com")
        положить(self.хранилище, "ivan@yandex.ru")
        self.assertEqual(self.всего(), 3)

    def test_повтор_после_сброса_на_диск_тоже_виден(self):
        положить(self.хранилище, "ivan@gmail.com")
        self.хранилище._flush_locked()
        положить(self.хранилище, "ivan@gmail.com")
        self.assertEqual(self.всего(), 1)


class TestКонтрольЗащитуВидно(unittest.TestCase):

    def test_без_защиты_адрес_ложится_дважды(self):
        хранилище = ResultStore(drop_repeats=False)
        try:
            положить(хранилище, "ivan@gmail.com")
            положить(хранилище, "ivan@gmail.com")
            self.assertEqual(хранилище.counts()["total"], 2)
        finally:
            хранилище.close()

    def test_защита_по_умолчанию_выключена(self):
        хранилище = ResultStore()
        try:
            self.assertFalse(хранилище._drop_repeats)
        finally:
            хранилище.close()


if __name__ == "__main__":
    unittest.main()
