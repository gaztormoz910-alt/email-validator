# -*- coding: utf-8 -*-
import io
import os
import sys
import unittest

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, КОРЕНЬ)

from core.filters import (BLACKLIST_SENTINELS, SpamFilter,
                          ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ)

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
    return ["одноразовый-%d.example" % i for i in range(начало, начало + сколько)]


class TestМалоСпорныхИменСписокПрименяется(unittest.TestCase):

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
        домены = выдуманные(200)
        положить(self.папка, "spisok.txt", домены + [ЖИВОЙ])
        ф = self.фильтр()
        своих = {д for д in ф.blacklist_domains if д.endswith(".example")}
        self.assertEqual(len(своих), 200)

    def test_ни_одного_охраняемого_имени_в_итоге(self):
        положить(self.папка, "spisok.txt",
                 выдуманные(200) + [ЖИВОЙ, ЕЩЁ_ЖИВОЙ])
        ф = self.фильтр()
        просочились = BLACKLIST_SENTINELS & ф.blacklist_domains
        self.assertEqual(просочились, set(), "охраняемые в чёрном списке")


class TestМногоСпорныхИменСписокОтбраковывается(unittest.TestCase):

    def setUp(self):
        import tempfile

        self.папка = tempfile.mkdtemp(prefix="blacklist-bad-")

    def test_файл_из_живых_почтовиков_не_применяется_вовсе(self):
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
        import tempfile

        живых = 10
        всего_мало = int(живых / ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ) + 50
        папка1 = tempfile.mkdtemp(prefix="porog-nizhe-")
        положить(папка1, "a.txt",
                 sorted(BLACKLIST_SENTINELS)[:живых]
                 + выдуманные(всего_мало - живых))
        self.assertEqual(SpamFilter(data_dir=папка1).rejected_files, [],
                         "ниже порога список обязан применяться")

        всего_много = int(живых / ДОЛЯ_ОХРАНЫ_ПРЕДЕЛ) - 50
        папка2 = tempfile.mkdtemp(prefix="porog-vyshe-")
        положить(папка2, "a.txt",
                 sorted(BLACKLIST_SENTINELS)[:живых]
                 + выдуманные(всего_много - живых))
        self.assertTrue(SpamFilter(data_dir=папка2).rejected_files,
                        "выше порога список обязан отбраковываться")


class TestПоставляемыеСпискиРаботают(unittest.TestCase):

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
        всего = sum(len(v) for v in self.ф.dropped_domains.values())
        self.assertGreater(всего, 0, "конфликтов не нашлось — проверка пуста")

    def test_живой_почтовик_не_считается_одноразовым(self):
        self.assertFalse(self.ф.is_spam_or_disposable("ivan@" + ЖИВОЙ))
        self.assertFalse(self.ф.is_spam_or_disposable("ivan@" + ЕЩЁ_ЖИВОЙ))

    def test_настоящий_одноразовый_ловится(self):
        self.assertTrue(self.ф.is_spam_or_disposable("a@mailinator.com"))


class TestОпечаткаНеТеряетсяНаОдноразовомДомене(unittest.TestCase):

    def setUp(self):
        from core.disposable import extend_disposable_domains
        from core.filters import SpamFilter

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
        строка = self.прогнать("a@mailinator.com", {"gmail.com"})
        self.assertEqual(строка[1], "Trap/Disposable")
        self.assertIsNone(строка[4].get("suggested_email"))


if __name__ == "__main__":
    unittest.main()
