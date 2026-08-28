"""Закрытие окна во время выгрузки не должно молча обрезать файл.

Выгрузка пишется фоновым потоком, а выход из программы идёт через
`os._exit(0)` — он не ждёт никого. Оборванный файл при этом выглядит целым:
строки в нём настоящие, просто не все. Отправка по такому файлу — это
«прошло хорошо» на половине базы и молчание про вторую.

Поэтому перед выходом спрашивают. Здесь проверяется, что вопрос задаётся и
что ответ «нет» действительно отменяет выход.

`os._exit` и `destroy` подменяются: первый убил бы процесс с тестами, второй
— общее окно, на котором работают остальные проверки.
"""
import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import ui.gui as gui_mod
from tests.gui_fixture import shared_app


class Answers:
    """Подставные диалоги: помнят вопросы и отвечают заранее заданным."""

    def __init__(self, answer):
        self.answer = answer
        self.asked = []

    def askyesno(self, title, text):
        self.asked.append((title, text))
        return self.answer

    def showinfo(self, *a, **kw):
        pass

    showwarning = showerror = showinfo


class TestClosingDuringExport(unittest.TestCase):

    def setUp(self):
        try:
            self.app = shared_app()
        except RuntimeError as exc:
            self.skipTest(str(exc))

        self.exits = []
        self.destroyed = []
        self._real_messagebox = gui_mod.messagebox
        self._real_exit = os._exit
        self._real_destroy = type(self.app).destroy

        os._exit = lambda code=0: self.exits.append(code)
        type(self.app).destroy = lambda instance: self.destroyed.append(True)

        def restore():
            gui_mod.messagebox = self._real_messagebox
            os._exit = self._real_exit
            type(self.app).destroy = self._real_destroy
            self.app._export_busy = False
        self.addCleanup(restore)

    def test_answering_no_cancels_the_exit(self):
        answers = Answers(False)
        gui_mod.messagebox = answers
        self.app._export_busy = True

        self.app.on_closing()

        self.assertTrue(answers.asked, "про незаконченную выгрузку не спросили")
        self.assertIn("выгрузка", answers.asked[0][0].lower())
        self.assertEqual(self.exits, [], "программа вышла вопреки ответу «нет»")
        self.assertEqual(self.destroyed, [], "окно уничтожено вопреки ответу «нет»")

    def test_answering_yes_lets_it_exit(self):
        answers = Answers(True)
        gui_mod.messagebox = answers
        self.app._export_busy = True

        self.app.on_closing()

        self.assertTrue(answers.asked)
        self.assertEqual(self.exits, [0], "после согласия программа не вышла")

    def test_positive_control_no_question_without_an_export(self):
        """Без выгрузки лишнего вопроса быть не должно — иначе он надоест."""
        answers = Answers(True)
        gui_mod.messagebox = answers
        self.app._export_busy = False

        self.app.on_closing()

        self.assertEqual(answers.asked, [],
                         "спросили про выгрузку, которой не было")
        self.assertEqual(self.exits, [0])


if __name__ == "__main__":
    unittest.main()
