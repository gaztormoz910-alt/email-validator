# -*- coding: utf-8 -*-
"""Списки одноразовых доменов применяются, а живые почтовики не страдают.

ЗАЧЕМ ЭТОТ ФАЙЛ. Прежнее правило отбраковывало список целиком, если внутри
нашёлся хоть один живой почтовик. Замерено 11.09.2026, во что это обошлось: в
трёх поставляемых списках 25 таких имён на 68 685 строк (0.036%), и из-за них
не работал ни один список — фильтрация шла по двенадцати встроенным доменам.

Новое правило смотрит на ДОЛЮ. Мало охраняемых имён — разногласие на краю:
спорные выбрасываются, остальное применяется. Много — файл не является списком
одноразовых (например, чужой список провайдеров, положенный в data/), и вот
его применять нельзя вовсе: он похоронит домены, о которых предупредить
некому.

Здесь сторожатся ОБЕ половины этого правила. Проверка, следящая только за
первой, была бы зелёной и у политики «грузить всё подряд» — то есть у той,
которая убила бы базу владельца.
"""
import io
import os
import sys
import unittest

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, КОРЕНЬ)

from core.filters import (BLACKLIST_SENTINELS, SpamFilter,  # noqa: E402
                          ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ)

# Заведомо живой почтовик и заведомо одноразовый — берём из самих таблиц
# программы, а не выдумываем: выдуманное имя завтра разойдётся с кодом.
ЖИВОЙ = "gmail.com"
ЕЩЁ_ЖИВОЙ = "yandex.ru"


def положить(папка, имя, домены):
    путь = os.path.join(папка, имя)
    with io.open(путь, "w", encoding="utf-8", newline="") as ф:
        ф.write("# список для проверки" + chr(10))
        for д in домены:
            ф.write(д + chr(10))
    return путь


def выдуманные(сколько, начало=0):
    """Заведомо не живые имена: их нет ни в одной таблице программы."""
    return ["одноразовый-%d.example" % i for i in range(начало, начало + сколько)]


class TestМалоСпорныхИменСписокПрименяется(unittest.TestCase):
    """Разногласие на краю не должно выключать весь список."""

    def setUp(self):
        import tempfile

        self.папка = tempfile.mkdtemp(prefix="blacklist-")

    def фильтр(self):
        return SpamFilter(data_dir=self.папка)

    def test_список_применён_а_спорное_имя_выброшено(self):
        домены = выдуманные(200) + [ЖИВОЙ]
        положить(self.папка, "spisok.txt", домены)
        ф = self.фильтр()

        self.assertEqual(ф.rejected_files, [], "список отбракован целиком")
        self.assertIn("одноразовый-0.example", ф.blacklist_domains,
                      "список не применён — а спорное имя было одно на двести")
        self.assertNotIn(ЖИВОЙ, ф.blacklist_domains,
                         "живой почтовик попал в чёрный список")
        self.assertEqual(ф.dropped_domains.get("spisok.txt"), [ЖИВОЙ])

    def test_применено_именно_столько_сколько_в_файле_минус_спорное(self):
        """Число, а не «что-то попало»: потеря половины списка так не видна."""
        домены = выдуманные(200)
        положить(self.папка, "spisok.txt", домены + [ЖИВОЙ])
        ф = self.фильтр()
        своих = {д for д in ф.blacklist_domains if д.endswith(".example")}
        self.assertEqual(len(своих), 200)

    def test_ни_одного_охраняемого_имени_в_итоге(self):
        """Последний рубеж: охраняемых не должно быть вообще ниоткуда.

        Ни из файла, ни из жёсткого минимума, ни от будущей правки, которая
        забудет про отсев.
        """
        положить(self.папка, "spisok.txt",
                 выдуманные(200) + [ЖИВОЙ, ЕЩЁ_ЖИВОЙ])
        ф = self.фильтр()
        просочились = BLACKLIST_SENTINELS & ф.blacklist_domains
        self.assertEqual(просочились, set(), "охраняемые в чёрном списке")


class TestМногоСпорныхИменСписокОтбраковывается(unittest.TestCase):
    """Вторая половина правила, без которой первая опасна."""

    def setUp(self):
        import tempfile

        self.папка = tempfile.mkdtemp(prefix="blacklist-bad-")

    def test_файл_из_живых_почтовиков_не_применяется_вовсе(self):
        """Чужой список провайдеров, положенный в data/, обязан быть отвергнут.

        Опасны в нём не только знакомые имена: рядом с ними лежат живые
        домены, которых программа не знает, и предупредить о них некому.
        """
        живые = sorted(BLACKLIST_SENTINELS)[:60]
        чужое = "неизвестный-живой.example"
        положить(self.папка, "provajdery.txt", живые + [чужое])
        ф = SpamFilter(data_dir=self.папка)

        self.assertTrue(ф.rejected_files, "испорченный список применён")
        self.assertEqual(ф.rejected_files[0][0], "provajdery.txt")
        self.assertNotIn(чужое, ф.blacklist_domains,
                         "незнакомое имя из отвергнутого файла всё равно попало "
                         "в чёрный список — именно этого правило и не допускает")

    def test_порог_срабатывает_там_где_объявлен(self):
        """Проверяем ГРАНИЦУ, а не «где-то между».

        Порог, который не проверен с обеих сторон, легко сдвинуть правкой и не
        заметить: проверка останется зелёной и при пороге «никогда».
        """
        import tempfile

        живых = 10
        # Чуть ниже порога: живых ровно столько, что доля меньше предела.
        всего_мало = int(живых / ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ) + 50
        папка1 = tempfile.mkdtemp(prefix="porog-nizhe-")
        положить(папка1, "a.txt",
                 sorted(BLACKLIST_SENTINELS)[:живых]
                 + выдуманные(всего_мало - живых))
        self.assertEqual(SpamFilter(data_dir=папка1).rejected_files, [],
                         "ниже порога список обязан применяться")

        # Чуть выше порога: те же живые, но файл вдвое меньше.
        всего_много = int(живых / ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ) - 50
        папка2 = tempfile.mkdtemp(prefix="porog-vyshe-")
        положить(папка2, "a.txt",
                 sorted(BLACKLIST_SENTINELS)[:живых]
                 + выдуманные(всего_много - живых))
        self.assertTrue(SpamFilter(data_dir=папка2).rejected_files,
                        "выше порога список обязан отбраковываться")


class TestПоставляемыеСпискиРаботают(unittest.TestCase):
    """Главное, ради чего всё менялось: у владельца фильтрация включена."""

    МИНИМУМ = 50_000

    def setUp(self):
        self.ф = SpamFilter(data_dir=os.path.join(КОРЕНЬ, "data"))

    def test_доменов_десятки_тысяч_а_не_дюжина(self):
        self.assertGreater(
            self.ф.get_count(), self.МИНИМУМ,
            "поставляемые списки снова не применяются: доменов всего %d"
            % self.ф.get_count())

    def test_ни_один_поставляемый_список_не_отбракован(self):
        self.assertEqual(self.ф.rejected_files, [],
                         "отбракованы целиком: %s" % (self.ф.rejected_files,))

    def test_спорные_имена_всё_же_нашлись_и_выброшены(self):
        """Контроль к проверке выше: если бы конфликтов не было вовсе, она
        была бы зелёной и у прежней политики, которая всё отбраковывала."""
        всего = sum(len(v) for v in self.ф.dropped_domains.values())
        self.assertGreater(всего, 0, "конфликтов не нашлось — проверка пуста")

    def test_живой_почтовик_не_считается_одноразовым(self):
        self.assertFalse(self.ф.is_spam_or_disposable("ivan@" + ЖИВОЙ))
        self.assertFalse(self.ф.is_spam_or_disposable("ivan@" + ЕЩЁ_ЖИВОЙ))

    def test_настоящий_одноразовый_ловится(self):
        """Обратная сторона: список должен не только не вредить, но и работать."""
        self.assertTrue(self.ф.is_spam_or_disposable("a@mailinator.com"))




class TestОпечаткаНеТеряетсяНаОдноразовомДомене(unittest.TestCase):
    """След настоящего контакта переживает вердикт «одноразовый».

    Домены-опечатки вроде gmial.com стоят в списках одноразовых по праву: их
    заводят ради обмана. Но для владельца это ещё и указание на живого
    человека — он метил в gmail.com. Пока списки не работали, адрес доходил до
    разбора опечатки и подсказку получал. Стоило их включить — вердикт стал
    выноситься раньше, и подсказка пропала.

    Здесь сторожится, что она вернулась и что вердикт при этом НЕ подменён.
    """

    def setUp(self):
        from core.disposable import extend_disposable_domains
        from core.filters import SpamFilter

        # Подмешиваем списки, как это делает pipeline.setup(). Обратно всё
        # вернёт общая ловушка из conftest.
        extend_disposable_domains(
            SpamFilter(data_dir=os.path.join(КОРЕНЬ, "data")).blacklist_domains)

    def прогнать(self, адрес, живые):
        import tests.test_trust as доверие

        class _Заглушка:
            def setattr(self, объект, имя, значение):
                setattr(объект, имя, значение)

        сеть = доверие._DomainAware(живые)
        строки, _ = доверие._run(адрес, сеть, _Заглушка())
        self.assertTrue(строки, "адрес пропал")
        return строки[0]

    def test_домен_опечатка_признан_одноразовым(self):
        """Контроль: без него проверка ниже была бы про другой сценарий."""
        from core.disposable import is_disposable

        self.assertTrue(is_disposable("user@gmial.com"),
                        "gmial.com не в списках — сценарий не воспроизведён")

    def test_подсказка_лежит_рядом_с_вердиктом(self):
        строка = self.прогнать("user@gmial.com", {"gmail.com"})
        адрес, статус, данные = строка[0], строка[1], строка[4]
        self.assertEqual(адрес, "user@gmial.com", "адрес подменён подсказкой")
        self.assertEqual(статус, "Trap/Disposable", статус)
        self.assertEqual(данные.get("suggested_email"), "user@gmail.com",
                         "подсказка об опечатке потеряна")
        self.assertEqual(данные.get("suggested_status"), "valid",
                         данные.get("suggested_status"))

    def test_у_обычного_одноразового_подсказки_нет(self):
        """Обратная сторона: подсказка не выдумывается там, где опечатки нет.

        Проверка, дающая подсказку всем подряд, вернула бы владельцу мусор и
        была бы зелёной при полностью сломанном разборе опечаток.
        """
        строка = self.прогнать("a@mailinator.com", {"gmail.com"})
        self.assertEqual(строка[1], "Trap/Disposable")
        self.assertIsNone(строка[4].get("suggested_email"))


if __name__ == "__main__":
    unittest.main()
