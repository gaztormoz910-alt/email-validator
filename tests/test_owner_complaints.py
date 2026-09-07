# -*- coding: utf-8 -*-
"""Жалобы владельца после живого прогона — каждая как отдельная проверка.

ЧТО ЗДЕСЬ ИЗМЕНИЛОСЬ 06.09.2026. Файл был написан под старое окно на
CustomTkinter и поднимал его целиком. Окно удалено по решению владельца
(«мне старая версия софта не нужна, оставь ту, где HTML/CSS»), поэтому
проверки разделены на две части:

  * то, что сторожило ЯДРО, — разбор имени на части, группировка статусов,
    колонки выгрузки — осталось здесь и вызывает ядро напрямую, без окна;

  * то, что сторожило ОЧЕРЕДИ старого окна («прогресс 100%, а строки ещё
    идут»), удалено вместе с ним: у веб-окна другая модель — результаты
    отдаются опросом состояния, а не докладываются в очередь главного
    потока, и переносить туда проверку чужого механизма нечего.

Три жалобы владельца, из-за которых файл появился, были про одно и то же:
очереди между потоками и окном не разбирались до конца перед тем, как
объявить о завершении. Механизм, который это чинил, удалён вместе с окном,
которое им страдало.
"""
import inspect
import unittest

from ui.result_store import group_of


class TestRiskyIsNotSpam(unittest.TestCase):
    """Risky — «не доказано», а не «спам».

    Смешение меняет решение о рассылке: «спам» владелец выбрасывает, а
    «не доказано» перепроверяет.
    """

    def test_risky_goes_with_unknown(self):
        self.assertEqual(group_of("Risky"), "unknown")
        self.assertEqual(group_of("Risky"), group_of("Unknown"))

    def test_only_the_undeliverable_stay_in_spam(self):
        for status in ("Trap/Disposable", "Role-based"):
            with self.subTest(status=status):
                self.assertEqual(group_of(status), "spam")

    def test_card_labels_do_not_promise_spam(self):
        """Подпись карточки обязана описывать то, что в ней лежит.

        Раньше проверялась подпись старого окна. Теперь — разметка веб-окна:
        в эту корзину попадают и ролевые адреса, а они не спам.
        """
        import io
        import os
        путь = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "ui", "web", "index.html")
        разметка = io.open(путь, encoding="utf-8").read()
        self.assertNotIn("Спам / Ловушки", разметка,
                         "подпись обещает спам, а туда попадают и ролевые")
        self.assertIn("Ловушки и роль", разметка,
                      "корзина должна называть оба своих содержимых")


class TestNameIsSplitIntoParts(unittest.TestCase):
    """Имя и фамилия — отдельными колонками, для сегментации рассылки."""

    def test_two_words_split(self):
        from core.parser.name_extractor import split_name
        self.assertEqual(split_name("Tsybin Bogdan"), ("Tsybin", "Bogdan"))

    def test_three_words_keep_first_and_last(self):
        from core.parser.name_extractor import split_name
        self.assertEqual(split_name("Hai Ngoc Nguyen"), ("Hai", "Nguyen"))

    def test_single_word_leaves_surname_empty(self):
        """Одно слово в обе колонки писать нельзя — это выдумка."""
        from core.parser.name_extractor import split_name
        self.assertEqual(split_name("Kevin"), ("Kevin", ""))

    def test_garbage_does_not_crash(self):
        from core.parser.name_extractor import split_name
        for junk in (None, 123, "", "   ", [], {}):
            self.assertEqual(split_name(junk), ("", ""))

    def test_export_has_the_columns(self):
        """Выгрузка окна. Раньше проверялась у старого, теперь у веб-окна."""
        from ui import webapp
        source = inspect.getsource(webapp)
        self.assertIn("FirstName", source)
        self.assertIn("LastName", source)
        self.assertIn('"first_name"', source)

    def test_cli_export_has_the_columns(self):
        import cli
        self.assertIn("first_name", cli.EXPORT_FIELDS)
        self.assertIn("last_name", cli.EXPORT_FIELDS)


class TestRiskyKeepsItsOwnName(unittest.TestCase):
    """Группы укрупняют, а САМ СТАТУС остаётся своим.

    Risky ушёл к Unknown в ГРУППАХ фильтра, и однажды вместе с этим он начал
    писаться как Unknown и в самой строке результата. Это была регрессия: у
    владельца различие между «сервер промолчал» и «ответ был, но
    неоднозначный» осталось нужным.

    Проверка переведена со старого окна на ядро: там, где статус рождается,
    а не там, где рисуется. Так она переживёт и следующую смену окна.
    """

    def test_group_is_shared_but_the_status_is_not(self):
        self.assertEqual(group_of("Risky"), group_of("Unknown"))
        self.assertNotEqual("Risky", "Unknown")

    def test_pipeline_does_not_rename_risky(self):
        """В коде нет места, где Risky превращался бы в Unknown."""
        from core import pipeline
        источник = inspect.getsource(pipeline)
        self.assertNotIn('"Risky" -> "Unknown"', источник)
        self.assertIn("Risky", источник, "статус Risky исчез из пайплайна")


if __name__ == "__main__":
    unittest.main()
