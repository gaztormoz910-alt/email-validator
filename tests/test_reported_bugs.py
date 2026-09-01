"""Баги, найденные владельцем на живом прогоне 2026-08-25.

Каждый тест воспроизводит СИМПТОМ так, как его увидел владелец, и падает на
том коде, который этот симптом давал. Это не проверки «функция существует»:
все три бага прошли предыдущие наборы тестов насквозь и всплыли только на
реальном прогоне по базе из одних гуглов.

Гейты выбирают по -k: stat_cards, progress, names.
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.parser.name_extractor import NameExtractor
from core.network import NetworkValidator


class TestStatCards(unittest.TestCase):
    """Карточка «Валидные» показывала ноль при полной таблице валидных.

    Как это выглядело у владельца: в терминале шесть строк [VALID], во
    вкладке «Результаты» шесть строк Valid, а карточка вверху — 0. И так
    оставалось МИНУТАМИ, пока не приходил следующий результат.

    Причина была в том, что обновление карточек стояло под двойным условием
    «пришли новые результаты И разрешил throttle». Если пачка приходила
    раньше, чем через 0.25с после предыдущей, throttle её пропускал, а
    второго шанса не было: следующего результата на базе из одного домена
    приходилось ждать минуты.
    """

    def setUp(self):
        # Окно берётся общее на весь прогон. Своё окно с уничтожением в
        # tearDown ломало все последующие тесты с Tk: второй корень в этом
        # процессе уже не поднимается. См. tests/gui_fixture.py.
        from tests.gui_fixture import shared_app
        try:
            self.app = shared_app()
        except RuntimeError as exc:
            self.skipTest(str(exc))

    def _tick(self):
        self.app._poll_validator_queues()
        self.app.update()

    def test_stat_cards_catch_up_after_throttled_batch(self):
        # Тик 1: один результат — throttle пропускает его и «тратит» окно
        self.app.safe_add_result("a@gmail.com", "Trap/Disposable", "AI", "N/A", {})
        self._tick()

        # Тик 2 сразу следом: пачка валидных, throttle её НЕ пропустит
        for letter in "bcdefg":
            self.app.safe_add_result(f"{letter}@gmail.com", "Valid", "250 OK",
                                     "mx", {"name": "X"})
        self._tick()

        # Дальше новых результатов нет — ровно как при затыке SMTP
        for _ in range(20):
            self._tick()
            time.sleep(0.03)

        counts = self.app.result_store.counts()
        self.assertEqual(counts["valid"], 6, "в хранилище должно быть 6 валидных")
        self.assertEqual(
            self.app.stat_1.cget("text"), "6",
            "карточка «Валидные» так и не догнала хранилище — тот самый ноль "
            "при полной таблице валидных адресов")

    def test_stat_cards_refresh_on_tab_switch(self):
        """Переключение вкладки показывает счётчики сразу, без ожидания тика."""
        for letter in "abc":
            self.app.safe_add_result(f"{letter}@gmail.com", "Valid", "250 OK", "mx", {})
        self._tick()
        self.app._switch_tab("Результаты")
        self.app.update()
        self.assertEqual(self.app.stat_1.cget("text"), "3")

    def test_stat_cards_positive_control_counts_are_not_frozen(self):
        """Контроль: карточка вообще умеет меняться, иначе тест выше пуст."""
        self.assertEqual(self.app.stat_1.cget("text"), "0")
        self.app.safe_add_result("z@gmail.com", "Valid", "250 OK", "mx", {})
        self._tick()
        self.assertEqual(self.app.stat_1.cget("text"), "1")


class TestProgress(unittest.TestCase):
    """Бар доходил до 100%, а результаты продолжали идти.

    Причина: отложенные на перепроверку адреса считались обработанными сразу,
    хотя вердикта по ним ещё не было. Показывалось «сколько адресов вынуто из
    очереди», а не «сколько проверено».
    """

    def test_progress_defers_do_not_advance_the_bar(self):
        import inspect
        from core.pipeline import ValidationPipeline
        source = inspect.getsource(ValidationPipeline.run_pipeline)

        # Контроль: обе точки откладывания на месте — значит смотрим туда.
        # Якорь без закрывающей скобки: у вызова прибавились именованные
        # аргументы (прокси неудачной попытки и причина), и точное совпадение
        # проверяло бы форму строки, а не то, что адрес откладывается.
        self.assertIn("defer(email, data, is_role", source)
        self.assertGreaterEqual(source.count("return False"), 2,
                                "откладывание перестало сообщать о себе вызывающему")
        self.assertIn("if not deferred:", source,
                      "прогресс снова двигается независимо от того, получен "
                      "вердикт или адрес только отложен")

    def test_progress_retry_advances_the_bar(self):
        """Перепроверка обязана досчитывать бар до 100%, а не оставлять его."""
        import inspect
        from core.pipeline import ValidationPipeline
        source = inspect.getsource(ValidationPipeline.run_pipeline)
        after_retry = source[source.index("retry_count += 1"):]
        self.assertIn("processed_count += 1", after_retry[:600],
                      "после перепроверки прогресс не двигается — бар "
                      "остановится, не дойдя до конца")


class TestSemaphoreScope(unittest.TestCase):
    """Вся база на одном домене шла в пять потоков, сколько бы их ни ставили."""

    def test_semaphore_is_per_exit_ip_not_per_mx(self):
        v = NetworkValidator(timeout=1, proxies=["p1:1", "p2:2"])
        v.set_proxy_profiles({
            "p1:1": {"exit_ip": "1.1.1.1"},
            "p2:2": {"exit_ip": "2.2.2.2"},
        })
        first = v._get_mx_semaphore("gmail-smtp-in.l.google.com", "p1:1")
        second = v._get_mx_semaphore("gmail-smtp-in.l.google.com", "p2:2")
        self.assertIsNot(first, second,
                         "два разных выходных IP делят один лимит к серверу — "
                         "база из одних гуглов упрётся в пять соединений")

    def test_semaphore_same_proxy_shares_one_slot(self):
        """Контроль: с ОДНОГО адреса лимит по-прежнему общий."""
        v = NetworkValidator(timeout=1, proxies=["p1:1"])
        v.set_proxy_profiles({"p1:1": {"exit_ip": "1.1.1.1"}})
        a = v._get_mx_semaphore("mx.example.com", "p1:1")
        b = v._get_mx_semaphore("mx.example.com", "p1:1")
        self.assertIs(a, b, "лимит на один выходной адрес перестал действовать")

    def test_semaphore_adaptive_limit_uses_the_same_key(self):
        """Снижение при 421 обязано попадать в тот же семафор, что и отправка."""
        v = NetworkValidator(timeout=1, proxies=["p1:1"])
        v.set_proxy_profiles({"p1:1": {"exit_ip": "1.1.1.1"}})
        before = v._get_mx_semaphore("mx.example.com", "p1:1")
        for _ in range(3):
            v._record_mx_error("mx.example.com", "p1:1")
        after = v._get_mx_semaphore("mx.example.com", "p1:1")
        self.assertIsNot(before, after,
                         "адаптивное торможение создало семафор под другим "
                         "ключом — снижение никуда не применилось")


class TestNames(unittest.TestCase):
    """Славянская фамилия разваливалась на обломки английским сегментатором."""

    @classmethod
    def setUpClass(cls):
        cls.ex = NameExtractor(enable_osint=False)

    def test_names_slavic_surname_is_kept_whole(self):
        self.assertEqual(self.ex.extract_name("tsybinbogdan1@gmail.com"),
                         "Tsybin Bogdan",
                         "фамилия снова разваливается на обломки")

    def test_names_surname_with_initial(self):
        self.assertEqual(self.ex.extract_name("tsybinb@gmail.com"), "Tsybin B")

    def test_names_short_syllables_survive(self):
        """Вьетнамские слоги короткие ПО ПРИРОДЕ — склеивать их нельзя."""
        self.assertEqual(self.ex.extract_name("haingocnguyen21@gmail.com"),
                         "Hai Ngoc Nguyen",
                         "починка обломков склеила настоящие короткие имена")

    def test_names_english_cases_unchanged(self):
        """Негативный контроль: то, что работало, работать не перестало."""
        cases = {
            "robertanderson@gmail.com": "Robert Anderson",
            "mohammedlahlali@yahoo.fr": "Mohammed Lahlali",
            "john.doe@gmail.com": "John Doe",
            "j.smith@gmail.com": "J Smith",
            "sarah.jones91@outlook.com": "Sarah Jones",
        }
        for email, expected in cases.items():
            with self.subTest(email=email):
                self.assertEqual(self.ex.extract_name(email), expected)

    def test_names_role_accounts_are_still_not_people(self):
        for email in ("info@corp.com", "noreply@corp.com", "support@corp.com"):
            with self.subTest(email=email):
                self.assertFalse(self.ex.extract_name(email),
                                 f"{email} снова стал именем человека")

    def test_names_repair_helper_is_index_aware(self):
        """Ремонт спрашивает чистый индекс, а не шумную базу на 138 млн."""
        repaired = self.ex._repair_oversegmentation(["tsy", "bin", "bogdan"])
        self.assertEqual(repaired, ["tsybin", "bogdan"])
        kept = self.ex._repair_oversegmentation(["hai", "ngoc", "nguyen"])
        self.assertEqual(kept, ["hai", "ngoc", "nguyen"])


if __name__ == "__main__":
    unittest.main()
