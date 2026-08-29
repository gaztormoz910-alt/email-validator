"""Жалобы владельца после живого прогона — каждая как отдельная проверка.

Все четыре пришли из одного прогона на его базе, и три из них оказались
одним и тем же дефектом:

  «прогресс 100%, а в терминале ещё идут почты»
  «в карточке ноль валидных, хотя в таблице они есть»
  «строки появляются ПОСЛЕ „Валидация завершена"»

Причина общая: очереди между рабочими потоками и окном не разбирались до
конца перед тем, как объявить о завершении. Отчёт уходил в лог через
after(0) и обгонял результаты, лежащие в очереди.

Четвёртая — про обогащение: «переключаю Заполненность/Точность, результат
одинаковый». Кэш вердиктов возвращал вместе со статусом ещё и имя, пол и
страну, посчитанные в прошлый раз, — то есть молча отменял настройки окна.
"""
import os
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tests.gui_fixture import shared_app
from ui.result_store import group_of


class TestNothingIsShownAfterCompletion(unittest.TestCase):
    """К моменту «Валидация завершена» показано ВСЁ, что насчитал прогон."""

    def setUp(self):
        try:
            self.app = shared_app()
        except RuntimeError as exc:
            self.skipTest(str(exc))

    def _terminal_lines(self):
        text = self.app.terminal_box.get("1.0", "end-1c")
        return [line for line in text.splitlines() if line.strip()]

    def test_last_results_are_printed_before_the_completion_line(self):
        for i in range(5):
            self.app.safe_add_result(f"late{i}@example.com", "Valid", "250 OK",
                                     "mx.example.com", {})
        self.app.on_pipeline_complete()
        self.app.update()

        lines = self._terminal_lines()
        done_at = next((i for i, l in enumerate(lines) if "завершена" in l), None)
        self.assertIsNotNone(done_at, "строки о завершении нет вовсе")
        for i in range(5):
            with self.subTest(address=i):
                at = next((n for n, l in enumerate(lines)
                           if f"late{i}@example.com" in l), None)
                self.assertIsNotNone(at, f"результат late{i} не показан вовсе")
                self.assertLess(at, done_at,
                                f"результат late{i} встал ПОСЛЕ отчёта о завершении")

    def test_cards_count_the_last_batch_too(self):
        """Карточка не имеет права показывать ноль при полной таблице."""
        for i in range(7):
            self.app.safe_add_result(f"card{i}@example.com", "Valid", "250 OK",
                                     "mx.example.com", {})
        self.app.on_pipeline_complete()
        self.app.update()

        self.assertEqual(self.app.stat_1.cget("text"), "7",
                         "карточка «Валидные» разошлась с хранилищем")
        self.assertEqual(len(self.app.result_store), 7)

    def test_positive_control_without_draining_the_card_would_lag(self):
        """Контроль: без разбора очередей карточка и правда отстаёт.

        Иначе проверка выше зелёная просто потому, что очередь успела
        разобраться сама, и ничего не доказывает.
        """
        for i in range(7):
            self.app.safe_add_result(f"ctl{i}@example.com", "Valid", "250 OK",
                                     "mx.example.com", {})
        # Обновляем карточки БЕЗ разбора очередей — как было до починки.
        self.app._refresh_stat_cards()
        self.assertEqual(self.app.stat_1.cget("text"), "0",
                         "замер не видит отставания — он слеп")

    def test_cards_are_zeroed_when_a_new_run_starts(self):
        """Карточки не должны показывать числа ПРОШЛОГО прогона."""
        for i in range(4):
            self.app.safe_add_result(f"old{i}@example.com", "Valid", "250 OK", "mx", {})
        self.app.on_pipeline_complete()
        self.app.update()
        self.assertEqual(self.app.stat_1.cget("text"), "4")

        # То же, что делает start_validation перед запуском.
        self.app.result_store.clear()
        self.app._refresh_stat_cards()
        self.assertEqual(self.app.stat_1.cget("text"), "0",
                         "после очистки наверху остались числа прошлого прогона")


class TestRiskyIsNotSpam(unittest.TestCase):
    """Risky — «не доказано», а не «спам». Смешение меняет решение о рассылке."""

    def test_risky_goes_with_unknown(self):
        self.assertEqual(group_of("Risky"), "unknown")
        self.assertEqual(group_of("Risky"), group_of("Unknown"))

    def test_only_the_undeliverable_stay_in_spam(self):
        for status in ("Trap/Disposable", "Role-based"):
            with self.subTest(status=status):
                self.assertEqual(group_of(status), "spam")

    def test_log_still_says_RISKY_not_UNKNOWN(self):
        """Группы укрупняют, терминал — нет.

        Risky ушёл к Unknown в ГРУППАХ фильтра, и вместе с этим строка в
        терминале стала писаться как [UNKNOWN]. Это регрессия: у владельца в
        логах было [RISKY], и различие между «сервер промолчал» и «ответ был,
        но неоднозначный» ему нужно.
        """
        app = shared_app()
        app.safe_add_result("r@example.com", "Risky", "таймаут", "mx", {})
        app.safe_add_result("u@example.com", "Unknown", "нет ответа", "mx", {})
        app.on_pipeline_complete()
        app.update()

        text = app.terminal_box.get("1.0", "end-1c")
        self.assertIn("[RISKY] r@example.com", text,
                      "Risky в терминале потерял свою метку")
        self.assertIn("[UNKNOWN] u@example.com", text)

    def test_card_labels_do_not_promise_spam(self):
        """Подпись карточки обязана описывать то, что в ней лежит."""
        import inspect
        from ui.panels import PanelsMixin
        source = inspect.getsource(PanelsMixin)
        self.assertNotIn("Спам / Ловушки", source,
                         "подпись обещает спам, а туда попадают и ролевые адреса")


class TestNameIsSplitIntoParts(unittest.TestCase):
    """Имя и фамилия — отдельными колонками, для сегментации рассылки."""

    def test_two_words_split(self):
        from core.parser.name_extractor import split_name
        self.assertEqual(split_name("Kovbin Bogdan"), ("Kovbin", "Bogdan"))

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
        import inspect
        from ui.gui import ValidatorApp
        source = inspect.getsource(ValidatorApp._export_to_disk)
        self.assertIn("FirstName", source)
        self.assertIn("LastName", source)

    def test_cli_export_has_the_columns(self):
        import cli
        self.assertIn("first_name", cli.EXPORT_FIELDS)
        self.assertIn("last_name", cli.EXPORT_FIELDS)


if __name__ == "__main__":
    unittest.main()
