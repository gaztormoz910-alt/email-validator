# -*- coding: utf-8 -*-
"""Запуск не упирается в перепись процессов, и отметки времени честны.

ЧТО ЗДЕСЬ СТОРОЖИТСЯ. Владелец сказал: «кликаю по иконке — запускается через
полминуты». Замерено 12.09.2026 снаружи: 24.2 и 24.0 секунды до появления
окна. Разбор по шагам изнутри программы показал виновника:

    снимок чужих процессов движка   31.44 с
    окно показалось                  0.92 с

`WebViewReaper.snapshot()` обходил процессы по одному через
`psutil.process_iter`. На машине владельца процессов 4038 (из них 3672 —
осиротевшие rundll32), и на каждый уходило около шести миллисекунд.
Один системный снимок отдаёт то же самое за 0.09 секунды.

ПОЧЕМУ ПРОВЕРКА НЕ ПРО ВРЕМЯ. Порог в секундах на чужой машине означает
другое: там может быть и двести процессов, и сорок тысяч. Здесь сторожится
УСТРОЙСТВО — что перепись делается одним вызовом, — и ПРАВИЛЬНОСТЬ ответа.
Время меряет отдельный гейт на настоящей сборке.
"""
import io
import os
import sys
import time
import unittest

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, КОРЕНЬ)

from core.winnoise import WebViewReaper  # noqa: E402


class TestПереписьПроцессов(unittest.TestCase):
    """Обход обязан быть быстрым И правильным. Второе важнее."""

    def test_видит_сам_себя(self):
        """ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: обход находит процесс, который точно есть.

        Без него «быстро» ничего не значит: пустой ответ тоже мгновенный, а
        уборка сочла бы своими ВСЕ процессы движка на машине, включая чужие.
        """
        все = WebViewReaper._все_процессы()
        self.assertIn(os.getpid(), все, "обход не нашёл сам себя")
        self.assertIn("python", все[os.getpid()].lower())

    def test_процессов_больше_одного(self):
        """Ещё один контроль: обход возвращает систему, а не один процесс."""
        self.assertGreater(len(WebViewReaper._все_процессы()), 10)

    def test_имена_приведены_к_нижнему_регистру(self):
        """Отбор движка идёт подстрокой, и регистр решает.

        `MSEDGEWEBVIEW2.EXE` не совпал бы с `msedgewebview2`, и уборка молча
        перестала бы находить свои процессы.
        """
        все = WebViewReaper._все_процессы()
        плохие = [и for и in все.values() if и != и.lower()]
        self.assertEqual(плохие[:5], [])

    def test_живые_это_подмножество_всех(self):
        все = WebViewReaper._все_процессы()
        живые = WebViewReaper._живые()
        self.assertTrue(all(isinstance(p, int) for p in живые))
        self.assertTrue(живые <= set(все), "живые не из общего обхода")

    def test_живые_отбирают_по_имени_движка(self):
        все = WebViewReaper._все_процессы()
        живые = WebViewReaper._живые()
        for pid in живые:
            self.assertIn(WebViewReaper.ИМЯ, все[pid])

    @unittest.skipUnless(sys.platform == "win32", "проверка про Windows")
    def test_на_windows_обход_не_зависит_от_psutil(self):
        """Быстрый путь обязан работать САМ, без psutil.

        Это и есть суть правки: psutil обходил процессы по одному. Если
        быстрый путь незаметно свалится обратно на него, запуск снова станет
        тридцатисекундным, а проверка «нашёл себя» останется зелёной.
        """
        было = WebViewReaper._все_процессы_через_psutil
        WebViewReaper._все_процессы_через_psutil = staticmethod(
            lambda: (_ for _ in ()).throw(AssertionError("свалились в psutil")))
        try:
            все = WebViewReaper._все_процессы()
        finally:
            WebViewReaper._все_процессы_через_psutil = было
        self.assertIn(os.getpid(), все)

    @unittest.skipUnless(sys.platform == "win32", "проверка про Windows")
    def test_при_отказе_windows_есть_запасной_путь(self):
        """А если системный вызов не удался — не пустота, а запасной обход.

        Пустой ответ здесь опаснее медленного: уборка сочла бы чужие процессы
        движка своими и сняла бы их.
        """
        import ctypes

        звали = []
        было_dll = ctypes.WinDLL
        было_зап = WebViewReaper._все_процессы_через_psutil
        ctypes.WinDLL = lambda *a, **k: (_ for _ in ()).throw(OSError("нет"))
        WebViewReaper._все_процессы_через_psutil = staticmethod(
            lambda: звали.append(1) or {1: "заглушка.exe"})
        try:
            все = WebViewReaper._все_процессы()
        finally:
            ctypes.WinDLL = было_dll
            WebViewReaper._все_процессы_через_psutil = было_зап
        self.assertEqual(звали, [1], "запасной путь не позвали")
        self.assertEqual(все, {1: "заглушка.exe"})

    def test_снимок_быстрый(self):
        """Грубый потолок, который ловит возврат к обходу по одному.

        Десять секунд — не «норматив скорости», а граница между «один вызов»
        и «четыре тысячи». Прежний способ занимал здесь 23-31 секунду.
        """
        начало = time.perf_counter()
        WebViewReaper().snapshot()
        self.assertLess(time.perf_counter() - начало, 10.0)


class TestОтметкиВремени(unittest.TestCase):
    """Замер, который сам врёт, хуже отсутствия замера."""

    def setUp(self):
        from core import timing

        self.timing = timing
        self.было = (timing._отметки, timing._начало)

    def tearDown(self):
        self.timing._отметки, self.timing._начало = self.было

    def test_пока_не_включено_ничего_не_пишется(self):
        """Обычный запуск не должен платить за диагностику ни миллисекунды."""
        self.timing._отметки = None
        self.timing.отметить("шаг")
        self.assertFalse(self.timing.включено())

    def test_самый_долгий_шаг_назван_верно(self):
        """ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: подсаженный медленный шаг обязан всплыть."""
        import tempfile

        self.timing.включить(time.perf_counter())
        self.timing.отметить("быстрый")
        time.sleep(0.25)
        self.timing.отметить("медленный")
        self.timing.отметить("тоже быстрый")
        файл = os.path.join(tempfile.mkdtemp(), "t.log")
        всего = self.timing.записать(файл)
        текст = io.open(файл, encoding="utf-8").read()

        self.assertIn("САМЫЙ ДОЛГИЙ ШАГ: медленный", текст)
        self.assertIn("TIMING_OK", текст)
        self.assertGreater(всего, 0.25)

    def test_столбец_шага_это_разница_а_не_сумма(self):
        """Суммарное время растёт всегда; виноват один шаг, и видно его
        только в разнице. Перепутать столбцы — значит спрятать виновника."""
        import tempfile

        self.timing.включить(time.perf_counter())
        time.sleep(0.2)
        self.timing.отметить("первый")
        self.timing.отметить("второй")
        файл = os.path.join(tempfile.mkdtemp(), "t.log")
        self.timing.записать(файл)
        строки = [с for с in io.open(файл, encoding="utf-8").read().splitlines()
                  if с.startswith("второй")]
        self.assertTrue(строки)
        числа = [float(ч.replace(",", ".")) for ч in строки[0].split()
                 if ч.replace(".", "").isdigit()]
        self.assertGreaterEqual(числа[0], 0.2, "столбец «от старта» неверен")
        self.assertLess(числа[1], 0.1, "столбец «сам шаг» показывает сумму")

if __name__ == "__main__":
    unittest.main()
