# -*- coding: utf-8 -*-
"""Поломки, найденные в логах прогона владельца от 05.09.2026.

Каждый класс здесь начинается со строки его лога. Тест существует не ради
покрытия, а потому что владелец увидел эту строку своими глазами и она
означала потерю денег или потерю контакта.
"""
import re
import time
import unittest
from unittest import mock

from core.pipeline import ValidationPipeline
from core.network import NetworkValidator


def _пайплайн():
    """Пайплайн с перехватом лога. Возвращает (объект, список строк)."""
    строки = []
    callbacks = {
        'on_log': lambda текст, вид="info": строки.append(текст),
        'on_result': lambda *a, **k: None,
        'on_progress': lambda *a, **k: None,
        'on_complete': lambda *a, **k: None,
    }
    return ValidationPipeline(callbacks), строки


ФЕЙКОВЫЙ_ПРОФИЛЬ = {
    "exit_ip": "203.0.113.7", "has_ptr": True, "ptr_name": "mail.example.net",
    "in_dnsbl": False, "dnsbl_zones": [], "rdns_dirty": False,
    "outlook_ok": True, "latency_ms": 120,
}


# ══════════════════ [DEAD] Профилирование прокси не удалось (AttributeError)

class TestProfilingSurvives(unittest.TestCase):
    """Профилирование падало КАЖДЫЙ прогон, и в логе была одна строка.

    Причина: self.network создавался ПОСЛЕ блока профилирования, а блок
    спрашивал у него профили с прошлого запуска. Ценой была не одна строка —
    у всего пула оставались неизвестны выходной IP, PTR и чёрные списки, то
    есть маршрутизация Yahoo/AOL (нужен PTR) и Outlook/iCloud (нужна чистая
    репутация) работала вслепую.
    """

    ПРОКСИ = ["socks5://203.0.113.7:1080", "socks5://198.51.100.9:1080"]

    def _прогнать(self, сеть):
        p, строки = _пайплайн()
        p.network = сеть
        with mock.patch("core.network.profile_proxies",
                        return_value={x: dict(ФЕЙКОВЫЙ_ПРОФИЛЬ) for x in self.ПРОКСИ}):
            профили = p._profile_live_proxies(self.ПРОКСИ, 5, 10)
        провал = [s for s in строки if "Профилирование прокси не удалось" in s]
        return профили, строки, провал

    def test_profiling_completes_when_network_exists(self):
        сеть = NetworkValidator(timeout=5, proxies=list(self.ПРОКСИ))
        профили, строки, провал = self._прогнать(сеть)

        self.assertEqual(провал, [], "профилирование снова провалилось: %s" % провал)
        self.assertEqual(set(профили), set(self.ПРОКСИ),
                         "профиль снят не для всех прокси: %r" % (профили,))
        # Профиль должен быть не только снят, но и ПРОИЗНЕСЁН: владелец
        # принимает по этим числам решение, хватит ли ему прокси.
        self.assertTrue(any("Профиль готов" in s for s in строки),
                        "итог профилирования не сказан владельцу: %r" % строки)
        self.assertTrue(any("PTR" in s for s in строки),
                        "про PTR не сказано ничего, а от него зависит Yahoo/AOL")

    def test_profiling_failure_is_detectable(self):
        """ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: проверка выше умеет краснеть.

        Воспроизводим ровно прежний порядок — сеть ещё не создана. Если бы
        проверка не умела это поймать, зелёный результат выше не значил бы
        ничего.
        """
        профили, строки, провал = self._прогнать(None)
        self.assertTrue(провал, "прежняя поломка НЕ ловится — проверка бесполезна")
        self.assertIn("AttributeError", провал[0],
                      "в логе не названа настоящая причина: %s" % провал[0])
        self.assertEqual(профили, {}, "при провале профили не должны быть выдуманы")

    def test_setup_makes_network_before_profiling(self):
        """Порядок в самом setup(): сеть создаётся раньше, чем спрашивается.

        Отдельно от прогона выше: тот проверяет метод, этот — что метод
        вызывается уже с готовой сетью.
        """
        import inspect
        код = inspect.getsource(ValidationPipeline.setup)
        создание = код.index("self.network = NetworkValidator")
        вызов = код.index("self._profile_live_proxies")
        self.assertLess(создание, вызов,
                        "сеть создаётся ПОСЛЕ профилирования — прежняя поломка вернулась")


if __name__ == "__main__":
    unittest.main()


# ══════════════════ «Я ставил Точность, а он заполняет мусором» ═══════════

class _РежимИмён(unittest.TestCase):
    """Общая часть: глобальный режим ОБЯЗАН вернуться на место.

    Режим — глобальная настройка модуля. Тест, оставивший «Точность»
    включённой, тихо меняет поведение всех тестов, которые пойдут следом,
    и разбираться потом будет уже не с чем.
    """

    def setUp(self):
        from core.parser.ml_predictor import get_country_mode, set_country_mode
        from core.parser.name_extractor import NameExtractor
        было = get_country_mode()
        self.addCleanup(set_country_mode, было)
        self.режим = set_country_mode
        self.ne = NameExtractor(enable_osint=False)

    def имя(self, локальная, режим):
        self.режим(режим)
        return self.ne.extract_name(локальная + "@gmail.com")


class TestNameModeSeparatesGuessFromFact(_РежимИмён):
    """Сегментатор придумывал границы и выдавал результат за имя.

    `kavamorasports` -> «Kava Morasports», `anjuewww` -> «Anjue Www»,
    `whitebullclothingco` -> «White Bullclothingco». База имён на 138 млн
    записей подтверждает почти любой обломок ('kava', 'white', 'upscale' и
    даже 'aaa' в ней чьи-то имена), поэтому она такое не ловит.
    """

    МУСОР = ["kavamorasports", "anjuewww", "whitebullclothingco",
             "upscaleinstallations415", "oneontaymcagymnastics",
             "battlegroundfitnesssaratoga", "nodnorkus99", "gitsmt111"]

    # Границы поставил человек — его разметку не пересуживаем ни в каком режиме.
    ЧЕЛОВЕК = ["john.doe", "maria.ivanova", "moein.zargarzadeh",
               "berwin.turlach", "rollbusch.henley"]

    # Склеено, но словарь популярных имён подтверждает — остаётся.
    ЖИВЫЕ = ["aminagimba", "simonesorbi0", "jennifermabe", "satishtomer"]

    def test_name_mode_accuracy_drops_invented_splits(self):
        for л in self.МУСОР:
            self.assertTrue(self.имя(л, "coverage"),
                            "%s: в обычном режиме имя должно ставиться" % л)
            self.assertEqual(self.имя(л, "accuracy"), "",
                             "%s: «Точность» оставила догадку сегментатора" % л)

    def test_name_mode_keeps_boundaries_drawn_by_the_person(self):
        """ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: строгость не косит всё подряд."""
        for л in self.ЧЕЛОВЕК:
            for режим in ("coverage", "accuracy"):
                self.assertTrue(
                    self.имя(л, режим),
                    "%s: имя потеряно в режиме %s, а границы ставил человек"
                    % (л, режим))

    def test_name_mode_keeps_names_the_dictionary_confirms(self):
        for л in self.ЖИВЫЕ:
            self.assertTrue(self.имя(л, "accuracy"),
                            "%s: словарь имя подтверждает, а его убрали" % л)

    def test_name_mode_coverage_is_untouched(self):
        """В обычном режиме не изменился НИ ОДИН из проверяемых адресов.

        Режим по умолчанию — «Заполненность». Менять поведение тому, кто
        ничего не переключал, нельзя.
        """
        ожидалось = {
            "kavamorasports": "Kava Morasports",
            "anjuewww": "Anjue Www",
            "whitebullclothingco": "White Bullclothingco",
            "john.doe": "John Doe",
            "aminagimba": "Amina Gimba",
            "oneontaymcagymnastics": "Oneonta Ymcagymnastics",
        }
        for л, ждём in ожидалось.items():
            self.assertEqual(self.имя(л, "coverage"), ждём,
                             "%s: поведение обычного режима изменилось" % л)


class TestNameSourceIsHonest(_РежимИмён):
    """Догадка сегментатора показывалась владельцу как «факт».

    В карточке адреса стояло «из самого адреса — факт» и для `john.doe`
    (границы поставил человек), и для `kavamorasports` (границы придумали мы).
    """

    def test_name_source_marks_the_segmenter_as_a_guess(self):
        self.имя("kavamorasports", "coverage")
        self.assertEqual(self.ne.last_name_source(), "разбор",
                         "догадка сегментатора помечена не как догадка")

    def test_name_source_marks_human_separators_as_fact(self):
        self.имя("john.doe", "coverage")
        self.assertEqual(self.ne.last_name_source(), "адрес",
                         "разметку человека перестали считать фактом")

    def test_name_source_camelcase_counts_as_human(self):
        self.имя("JohnDoe", "coverage")
        self.assertEqual(self.ne.last_name_source(), "адрес")

    def test_name_source_is_shown_in_the_window(self):
        """Ярлык бесполезен, если окно его не знает и печатает сырое слово."""
        import io
        app = io.open("ui/web/app.js", encoding="utf-8").read()
        подписи = app[app.index("const SOURCE_TEXT"):app.index("function sourceNote")]
        for ключ in ('"разбор"', '"адрес"', '"профиль"'):
            self.assertIn(ключ, подписи,
                          "окно не знает источника %s и напечатает сырое слово" % ключ)
        self.assertIn("догадка", подписи.split('"разбор"')[1].split("\n")[0],
                      "«разбор» подписан не как догадка")

    def test_name_source_reaches_the_pipeline(self):
        """Пайплайн обязан спрашивать источник, а не ставить «адрес» всем."""
        import inspect
        from core.pipeline import ValidationPipeline
        код = inspect.getsource(ValidationPipeline)
        # Ищем ИМЯ метода, а не буквальный вызов со скобками: спрашивается
        # он через getattr (подставной экстрактор в чужом тесте этого метода
        # не знает, и прямой вызов ронял бы не ярлык, а само имя).
        self.assertIn("last_name_source", код,
                      "пайплайн не спрашивает источник имени — ярлык не доедет")
        self.assertIn('name_source = (узнать()', код,
                      "источник не кладётся в поле, которое уезжает в окно")


# ══ [DEAD] u200fhjuffairy@… 550   рядом с   [VALID] hjuffairy@… 250 OK ════

class TestEscapeResidueDoesNotBuryPeople(unittest.TestCase):
    """Базы из JSON приезжают с экранированием без обратного слэша.

    `u003cstanhu@gmail.com` выглядит обычным ящиком, честно проверяется и
    получает 550. В окне это «мёртв», и владелец удаляет ЖИВОГО человека.
    В его логе пара видна прямо: `u200fhjuffairy@gmail.com -> 550` и
    `hjuffairy@gmail.com -> 250 OK`.
    """

    ЧИНИТСЯ = {
        "u003cstanhu@gmail.com": "stanhu@gmail.com",
        "u200fhjuffairy@gmail.com": "hjuffairy@gmail.com",
        "u003elegal-notices@google.com": "legal-notices@google.com",
        "u003dmailer@example.com": "mailer@example.com",
        "u003cu200fbob@mail.ru": "bob@mail.ru",          # два остатка подряд
    }

    # ОБРАТНЫЕ КОНТРОЛИ. Без них зелёная проверка выше значила бы только то,
    # что правило умеет резать, а не то, что оно режет по делу.
    НЕ_ТРОГАЕМ = [
        "u003c@gmail.com",        # под остатком нет адреса — чинить нечего
        "u003cxyz",               # это вообще не адрес
        "u0061bc@gmail.com",      # буква: снять значило бы подменить ящик
        "myu003cname@gmail.com",  # в СЕРЕДИНЕ имени — законный текст
        "bob@u003cmail.ru",       # в домене, а не по краю
        "john.doe@gmail.com",
        "uma.thurman@gmail.com",  # начинается на «u», но это имя
        "user@example.com",
    ]

    def test_escape_residue_is_removed(self):
        from core.inputnorm import normalize_input
        for грязный, чистый in self.ЧИНИТСЯ.items():
            self.assertEqual(normalize_input(грязный), чистый,
                             "%s не починен" % грязный)

    def test_escape_residue_leaves_everything_else_alone(self):
        from core.inputnorm import normalize_input
        for строка in self.НЕ_ТРОГАЕМ:
            self.assertEqual(normalize_input(строка), строка,
                             "%s переписан, а не должен был" % строка)

    def test_escape_residue_survives_the_loader(self):
        """Через ЗАГРУЗЧИК, а не только через функцию.

        Прошлый раз ровно так и вскрылось: модульные проверки были зелёные,
        а строка от файла до вердикта приходила другой.
        """
        import tempfile, os
        from core.streamer import StreamLoader
        fd, путь = tempfile.mkstemp(suffix=".txt", text=True)
        os.close(fd)
        self.addCleanup(os.unlink, путь)
        with open(путь, "w", encoding="utf-8") as f:
            f.write("\n".join(list(self.ЧИНИТСЯ) + ["ok@example.com"]))
        источник = [{"type": "file", "path": путь}]
        вышло = [адрес for адрес, _ in StreamLoader(источник).stream_emails()]
        for чистый in self.ЧИНИТСЯ.values():
            self.assertIn(чистый, вышло, "загрузчик не отдал %s" % чистый)
        self.assertEqual(len(вышло), len(self.ЧИНИТСЯ) + 1,
                         "загрузчик потерял или размножил строки: %r" % вышло)


# ══ «550 … [второго мнения не было: у домена один MX]» — на gmail.com ═════

class TestSecondOpinionReasonIsTrue(unittest.TestCase):
    """Ярлык врал ровно там, где владелец решает, удалять ли контакт.

    Причин у «второго мнения не было» четыре, а печаталась всегда одна: «у
    домена один MX и нет другого выхода». В его логе она стояла на десятках
    адресов @gmail.com — у которого MX ПЯТЬ. Владелец читает этот ярлык,
    чтобы понять, чинить ли прокси или верить приговору, и получал ответ,
    указывающий не туда.
    """

    ПЯТЬ_MX = ["gmail-smtp-in.l.google.com", "alt1.gmail-smtp-in.l.google.com",
               "alt2.gmail-smtp-in.l.google.com"]

    def _сеть(self, proxies=None, profiles=None):
        v = NetworkValidator(timeout=2, proxies=proxies or [])
        if profiles:
            v.set_proxy_profiles(profiles)
        return v

    def test_second_opinion_names_the_exhausted_pool(self):
        """Прокси с другим выходом нет — так и говорим, а не про MX."""
        v = self._сеть(proxies=["a:1"], profiles={"a:1": {"exit_ip": "1.1.1.1"}})
        почему = {}
        ответ = v._confirm_invalid_on_other_mx(
            "u@gmail.com", self.ПЯТЬ_MX[0], self.ПЯТЬ_MX,
            False, False, "", deadline=float("inf"), first_proxy="a:1",
            почему=почему)
        self.assertIsNone(ответ)
        self.assertIn("выходным IP", почему["текст"])
        self.assertNotIn("один MX", почему["текст"])
        self.assertNotIn("один почтовый сервер", почему["текст"])

    def test_second_opinion_names_the_deadline(self):
        v = self._сеть(proxies=["a:1", "b:2"],
                       profiles={"a:1": {"exit_ip": "1.1.1.1"},
                                 "b:2": {"exit_ip": "2.2.2.2"}})
        почему = {}
        ответ = v._confirm_invalid_on_other_mx(
            "u@gmail.com", self.ПЯТЬ_MX[0], self.ПЯТЬ_MX,
            False, False, "", deadline=0.0, first_proxy="a:1", почему=почему)
        self.assertIsNone(ответ)
        self.assertIn("срок", почему["текст"])

    def test_second_opinion_names_a_silent_second_server(self):
        """Второй сервер промолчал — это НЕ «одного MX не хватило»."""
        v = self._сеть(proxies=["a:1", "b:2"],
                       profiles={"a:1": {"exit_ip": "1.1.1.1"},
                                 "b:2": {"exit_ip": "2.2.2.2"}})
        v._do_single_ping = lambda *a, **k: {"status": "unknown",
                                             "reason": "Socket error: timed out"}
        почему = {}
        ответ = v._confirm_invalid_on_other_mx(
            "u@gmail.com", self.ПЯТЬ_MX[0], self.ПЯТЬ_MX,
            False, False, "", deadline=float("inf"), first_proxy="a:1",
            почему=почему)
        self.assertIsNone(ответ)
        self.assertIn("неопределённо", почему["текст"])
        self.assertIn("alt1.gmail-smtp-in.l.google.com", почему["текст"],
                      "не сказано, какой именно сервер промолчал")

    def test_second_opinion_still_says_single_mx_when_it_is_true(self):
        """ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: правдивый случай не потерян.

        Один MX и работа без прокси — тогда «один почтовый сервер» верно, и
        так и должно печататься. Иначе правка просто выкинула бы формулировку.
        """
        v = self._сеть()
        почему = {}
        ответ = v._confirm_invalid_on_other_mx(
            "u@single.example", "mx.single.example", ["mx.single.example"],
            False, False, "", deadline=float("inf"), first_proxy=None,
            почему=почему)
        self.assertIsNone(ответ)
        self.assertIn("один почтовый сервер", почему["текст"])

    def test_second_opinion_reason_reaches_the_verdict_text(self):
        """Причина обязана доехать до строки, которую видит владелец."""
        import inspect
        from core.network import NetworkValidator as NV
        # Вызов живёт в stealth_smtp_ping; берём класс целиком,
        # чтобы проверка не сломалась от переезда между методами.
        код = inspect.getsource(NV)
        self.assertIn("почему=почему", код,
                      "причина не запрашивается — в вердикт попадёт заглушка")
        self.assertNotIn("у домена один MX и", код,
                         "прежний неверный ярлык всё ещё зашит в вердикт")


# ═══════════ Перебор прокси: у него есть тормоз, и он работает ═══════════

class TestProxySweepBrake(unittest.TestCase):
    """Параметр `enough` у перебора прокси существовал и раньше.

    Проверка добавлена, потому что цена перебора ЗАМЕРЕНА и велика: 300
    заведомо мёртвых адресов при 300 потоках и таймауте 30с занимают 42.3 с,
    900 — 126.5 с (ровно линейно). В списке владельца 34839 адресов, живых
    55, то есть около 82 минут простоя перед запуском.

    Тормоз задаётся полем `proxy_enough` в data/settings.json. В окна он
    намеренно НЕ выведен: сколько прокси держать в ротации — решение
    владельца, а узкая ротация означает, что каждый выходной IP чаще
    попадается почтовику на глаза.
    """

    def test_proxy_sweep_stops_early_when_enough_are_found(self):
        """Поведение, а не проводка: перебор ДЕЙСТВИТЕЛЬНО обрывается."""
        import core.async_proxy as ap
        from core.network import filter_live_proxies

        прочитано = {"n": 0}

        def fake_checker(proxies=None, workers=0, timeout=0, mode="",
                         progress_callback=None, **kw):
            живые = []
            for адрес in proxies:            # генератор с тормозом внутри
                прочитано["n"] += 1
                живые.append(адрес)          # считаем живым каждого
                if progress_callback:
                    progress_callback(len(живые), прочитано["n"], len(живые))
            return живые

        было = ap.run_async_checker
        ap.run_async_checker = fake_checker
        self.addCleanup(setattr, ap, "run_async_checker", было)

        список = ["socks5://198.51.100.%d:1080" % i for i in range(1, 201)]

        живые, всего = filter_live_proxies(список, timeout=1, threads=10, enough=5)
        self.assertLessEqual(всего, 12,
                             "тормоз не сработал: прочитано %d из 200" % всего)

        прочитано["n"] = 0
        живые, всего = filter_live_proxies(список, timeout=1, threads=10, enough=0)
        self.assertEqual(всего, 200,
                         "ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: без тормоза перебраны не все")


# ══════ Пять настроек качества: включены в ядре, убраны из окна ══════════

ПЯТЬ = ("enable_ai", "enable_osint", "use_cache", "resume", "confirm_valid")


class TestQualityDefaultsOn(unittest.TestCase):
    """Владелец не хочет щёлкать пять галочек перед каждым прогоном.

    05.09.2026: «сделай все пять включёнными по умолчанию под капотом и убери
    их из интерфейса». Значит включено должно быть В ЯДРЕ, а не в окне: иначе
    CLI и любой другой вызов остались бы со старым поведением, и «под капотом»
    оказалось бы неправдой ровно там, где окна нет.
    """

    def test_quality_defaults_on_in_the_core_signatures(self):
        import inspect
        параметры = inspect.signature(ValidationPipeline.start).parameters
        for имя in ПЯТЬ:
            self.assertIn(имя, параметры, "ядро не принимает настройку %s" % имя)
            self.assertIs(параметры[имя].default, True,
                          "%s выключена по умолчанию" % имя)

        # run_pipeline — второй вход в ядро, им пользуется CLI.
        параметры = inspect.signature(ValidationPipeline.run_pipeline).parameters
        for имя in ("enable_ai", "enable_osint", "resume"):
            self.assertIs(параметры[имя].default, True,
                          "run_pipeline: %s выключена по умолчанию" % имя)

    def test_quality_defaults_on_reach_a_fresh_object(self):
        """Подпись можно поменять и не подключить — так уже было со SMTPUTF8."""
        p, _ = _пайплайн()
        self.assertIs(getattr(p, "confirm_valid", False), True,
                      "второе мнение выключено у свежесозданного конвейера — "
                      "из командной строки оно не заработает")

    def test_quality_defaults_on_are_switchable_from_the_command_line(self):
        """Выключить всё же должно быть можно — но осознанно, флагом."""
        import io as _io
        cli = _io.open("cli.py", encoding="utf-8").read()
        for флаг in ("--no-ai", "--no-osint", "--no-cache",
                     "--no-resume", "--no-confirm-valid"):
            self.assertIn(флаг, cli, "нечем выключить: %s" % флаг)
        self.assertIn("pipeline.confirm_valid =", cli,
                      "флаг объявлен, но ни к чему не подключён")


class TestQualityTogglesGoneFromWindow(unittest.TestCase):
    """Пяти переключателей в окне нет, и окно не может их выключить."""

    def test_toggles_gone_from_the_markup_and_the_script(self):
        import io as _io
        html = _io.open("ui/web/index.html", encoding="utf-8").read()
        app = _io.open("ui/web/app.js", encoding="utf-8").read()
        for ид in ("optAi", "optOsint", "optResume", "optConfirm", "optCache"):
            self.assertNotIn(ид, html, "переключатель %s вернулся в окно" % ид)
            self.assertNotIn(ид, app, "скрипт снова читает %s" % ид)

    def test_toggles_gone_and_the_bridge_stops_overriding(self):
        """Мост не должен передавать значения — иначе окно снова их выключит."""
        import io as _io
        мост = _io.open("ui/webapp.py", encoding="utf-8").read()
        for ключ in ('payload.get("ai"', 'payload.get("osint"',
                     'payload.get("cache"', 'payload.get("confirm"',
                     'payload.get("resume"'):
            self.assertNotIn(ключ, мост,
                             "мост снова принимает из окна: %s" % ключ)


class TestResumeTrap(unittest.TestCase):
    """ЛОВУШКА, которую пришлось закрыть вместе с включением продолжения.

    `RunState` стирает память о прогоне ТОЛЬКО когда продолжение выключено
    (`if not resume: self.clear()` в core/runstate.py). Раз оно включено
    всегда, а галочка из окна убрана, память не стиралась бы никогда: второй
    запуск того же файла проверил бы НОЛЬ адресов, и починить это было бы
    нечем, кроме удаления sqlite руками.

    Поэтому память стирается сама, но ТОЛЬКО после прогона, дошедшего до
    конца. Нажали «Стоп» — память цела, и продолжение работает ровно так,
    как обещает его название.
    """

    АДРЕСА = ["one@example.com", "two@example.com", "three@example.com"]

    def setUp(self):
        import functools
        import shutil
        import tempfile
        from core.runstate import RunState, resumable_count

        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.журнал = __import__("os").path.join(self.tmp, "state.sqlite")

        # Журнал прогонов общий на всю программу (data/run_state.sqlite).
        # Уводим его в свою папку: иначе тест лез бы в настоящий и мог бы
        # как испортить его, так и зазеленеть из-за чужих записей.
        import core.pipeline as pipe_mod
        было = pipe_mod.RunState
        pipe_mod.RunState = functools.partial(RunState, path=self.журнал)
        self.addCleanup(setattr, pipe_mod, "RunState", было)
        self._счёт = functools.partial(resumable_count, path=self.журнал)

    def _конвейер(self, ронять_на=None):
        """Конвейер с подставной сетью. ронять_на — «нажать Стоп» на N-м адресе.

        Заглушки берутся из tests/test_result_cache.py, а не пишутся заново:
        своя тонкая заглушка уже один раз сделала эту проверку ПУСТОЙ. Адреса
        падали на TypeError, до журнала дело не доходило, и «журнал пуст»
        зеленело не от починки, а от поломки.

        И name_extractor с ml_predictor обязаны быть ПОДСТАВЛЕНЫ, а не None:
        при None конвейер грузит настоящие — база имён на 138 млн записей,
        девятнадцать секунд на каждый тест.
        """
        from tests.test_result_cache import (_StubNetwork, _StubNames,
                                             _StubML, _StubGravatar)
        p, логи = _пайплайн()
        звонки = []

        class Сеть(_StubNetwork):
            def check_email(self_, email):
                звонки.append(email)
                if ронять_на is not None and len(звонки) >= ронять_на:
                    p._stop_requested = True
                    p.is_running = False
                return {"status": "valid", "reason": "2.1.5 250 OK",
                        "mx_record": "mx.example.com",
                        "mx_records": ["mx.example.com"]}

        p.network = Сеть()
        p.name_extractor = _StubNames()
        p.ml_predictor = _StubML()
        p.gravatar_checker = _StubGravatar()
        p.filter = None
        p.ai = None
        p.cache = None
        p._get_domain_age_days = lambda d: -1
        p._check_http_alive = lambda d: True
        return p, звонки

    def _источник(self):
        return [{"type": "text", "content": "\n".join(self.АДРЕСА)}]

    def test_resume_trap_finished_run_wipes_the_journal(self):
        p, звонки = self._конвейер()
        p.run_pipeline(self._источник(), threads=2, fix_typos=False,
                       check_spam=False, deep_ping=True, enable_ai=False,
                       enable_osint=False)
        self.assertTrue(звонки, "конвейер вообще не дошёл до адресов")
        self.assertEqual(
            self._счёт(self._источник()), 0,
            "память о завершённом прогоне цела — второй запуск того же файла "
            "проверит НОЛЬ адресов, и починить это будет нечем")

    def test_resume_trap_interrupted_run_keeps_the_journal(self):
        """ОБРАТНЫЙ КОНТРОЛЬ: иначе стирание убило бы сам смысл продолжения."""
        # Роняем на ВТОРОМ адресе: первый обязан успеть попасть в журнал,
        # иначе продолжать было бы нечего и по-честному.
        p, звонки = self._конвейер(ронять_на=2)
        p.run_pipeline(self._источник(), threads=1, fix_typos=False,
                       check_spam=False, deep_ping=True, enable_ai=False,
                       enable_osint=False)
        self.assertTrue(p._stop_requested, "остановка не сработала")
        self.assertGreater(
            self._счёт(self._источник()), 0,
            "прерванный прогон тоже стёр память — продолжать стало нечего, "
            "и настройка «продолжить прерванный прогон» стала обманом")

    def test_resume_trap_second_run_of_the_same_file_checks_it_again(self):
        """Сквозная проверка того, чего боялся владелец: повтор работает."""
        p1, звонки1 = self._конвейер()
        p1.run_pipeline(self._источник(), threads=2, fix_typos=False,
                        check_spam=False, deep_ping=True, enable_ai=False,
                        enable_osint=False)
        p2, звонки2 = self._конвейер()
        p2.run_pipeline(self._источник(), threads=2, fix_typos=False,
                        check_spam=False, deep_ping=True, enable_ai=False,
                        enable_osint=False)
        self.assertEqual(
            len(звонки2), len(звонки1),
            "второй прогон того же файла проверил %d адресов вместо %d"
            % (len(звонки2), len(звонки1)))


# ═══════ Состав базы печатается и в веб-окне, а не только в старом ═══════

class TestBaseScanInWebWindow(unittest.TestCase):
    """Владелец не видел в терминале ни состава базы, ни разбивки по доменам.

    Причина оказалась не в поломке: отчёт `scan_base_providers` жив, но
    подключён был только к КЛАССИЧЕСКОМУ окну (ui/gui.py) и к командной
    строке (--scan-only). В веб-окне его не было ни одной строкой, а работает
    владелец именно в нём.
    """

    ПОЧТЫ = "\n".join(["a%d@gmail.com" % i for i in range(60)]
                      + ["b%d@yahoo.com" % i for i in range(30)]
                      + ["c%d@outlook.com" % i for i in range(10)])

    def _окно(self):
        from ui.webapp import ValidatorApi
        api = ValidatorApi()
        строки = []
        было = api._on_log
        api._on_log = lambda текст, тег="info": (строки.append(текст),
                                                 было(текст, тег))[0]
        return api, строки

    def _дождаться(self, строки, кусок, секунд=20.0):
        предел = time.monotonic() + секунд
        while time.monotonic() < предел:
            if any(кусок in с for с in строки):
                return True
            time.sleep(0.05)
        return False

    def test_basescan_prints_after_loading_the_base(self):
        """ПОВЕДЕНИЕ: загрузили базу — состав напечатан."""
        api, строки = self._окно()
        api.paste({"kind": "emails", "text": self.ПОЧТЫ})

        self.assertTrue(self._дождаться(строки, "Состав базы"),
                        "состав базы не напечатан: %r" % строки[-6:])
        отчёт = "\n".join(строки)
        self.assertIn("Gmail", отчёт, "провайдеры не перечислены")
        self.assertIn("Yahoo", отчёт, "провайдеры не перечислены")
        # Ровно то, о чём владелец спрашивал: чем какой домен проверять.
        self.assertIn("Проверю с текущего IP", отчёт)
        self.assertIn("PTR", отчёт, "не сказано, каким доменам нужен PTR")

    def test_basescan_prints_nothing_for_proxies(self):
        """ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: разбивка по почтовикам у прокси бессмысленна."""
        api, строки = self._окно()
        api.paste({"kind": "proxies", "text": "1.2.3.4:1080\n5.6.7.8:1080"})
        time.sleep(1.0)
        self.assertFalse(any("Состав базы" in с for с in строки),
                         "состав базы посчитан для списка прокси: %r" % строки)

    def test_basescan_once_not_on_every_panel_poll(self):
        """Скан не должен висеть в _recount.

        _recount зовётся из sources() при КАЖДОМ опросе панели, если файл
        изменился на диске. Скан оттуда означал бы перечитывание
        полумиллионного файла снова и снова, пока окно открыто.
        """
        import inspect
        from ui.webapp import ValidatorApi
        self.assertNotIn("_rescan_base", inspect.getsource(ValidatorApi._recount),
                         "скан повешен на пересчёт строк — он будет повторяться")
        self.assertNotIn("_rescan_base", inspect.getsource(ValidatorApi.sources),
                         "скан повешен на опрос панели — он будет повторяться")

        # И поведением: опрос панели отчёт не печатает.
        api, строки = self._окно()
        api.paste({"kind": "emails", "text": self.ПОЧТЫ})
        self.assertTrue(self._дождаться(строки, "Состав базы"))
        было = sum(1 for с in строки if "Состав базы" in с)
        for _ in range(5):
            api.sources()
        time.sleep(1.0)
        стало = sum(1 for с in строки if "Состав базы" in с)
        self.assertEqual(стало, было,
                         "опрос панели пересчитал состав ещё %d раз" % (стало - было))

    def test_basescan_async_does_not_block_loading(self):
        """Загрузка обязана вернуться сразу: скан идёт в фоне.

        Классическое окно на этом уже обжигалось — 344 мс без отклика, хотя
        обработчик давно вернулся, потому что фоновый поток на чистом Python
        не отпускал GIL.
        """
        import inspect
        from ui.webapp import ValidatorApi
        исходник = inspect.getsource(ValidatorApi._rescan_base)
        self.assertIn("threading.Thread", исходник, "скан идёт в главном потоке")
        self.assertIn("breathe_every", исходник,
                      "скан не отпускает GIL — панель перестанет отвечать")

        api, строки = self._окно()
        крупно = "\n".join("u%d@gmail.com" % i for i in range(60000))
        начало = time.monotonic()
        api.paste({"kind": "emails", "text": крупно})
        ушло = time.monotonic() - начало
        self.assertLess(ушло, 1.0,
                        "загрузка держала окно %.2f с — скан не в фоне" % ушло)

    def test_basescan_shared_constants_keep_both_windows_equal(self):
        """Оба окна берут передышку из ОДНОГО места и НЕ режут базу выборкой.

        Разъехавшиеся числа означали бы разный отчёт по одной и той же базе.
        """
        import io as _io
        from core.provider import BASE_SCAN_BREATHE
        self.assertGreater(BASE_SCAN_BREATHE, 0)
        for файл in ("ui/gui.py", "ui/webapp.py"):
            текст = _io.open(файл, encoding="utf-8").read()
            self.assertIn("BASE_SCAN_BREATHE", текст,
                          "%s не берёт передышку из ядра" % файл)
            свои = re.search(r"^\s*BASE_SCAN_BREATHE\s*=\s*\d", текст, re.M)
            self.assertIsNone(свои,
                              "%s снова задаёт своё число вместо импорта" % файл)
            # Выборки быть не должно вовсе: она бралась С НАЧАЛА и описывала
            # первый файл, выдавая его состав за состав всей базы.
            кусок = текст[текст.index("scan_base_providers("):]
            кусок = кусок[:кусок.index(")")]
            self.assertNotIn("limit", кусок,
                             "%s снова режет базу выборкой: %r" % (файл, кусок))


# ═══ Состав считается по ВСЕЙ базе, а не по первым 200 000 адресам ══════

class TestWholeBaseScan(unittest.TestCase):
    """Выборка бралась С НАЧАЛА и описывала первый файл.

    Владелец загрузил 3 614 531 строку восемью файлами и увидел отчёт по
    200 000. ЗАМЕРЕНО на его файлах: выборка говорила «Gmail 0», а в базе
    Gmail 1 499 557 — 41.5%. При этом печаталась строка «VPS с PTR ничего
    не добавит — таких адресов в базе нет»: уверенное утверждение обо всей
    базе, выведенное из одного файла.
    """

    # Yahoo лежит ВТОРЫМ источником и только там. Головная выборка его не
    # увидит — на этом проверка и держится.
    ПЕРВЫЙ = "\n".join("g%d@gmail.com" % i for i in range(3000))
    ВТОРОЙ = "\n".join("y%d@yahoo.com" % i for i in range(1500))

    def _окно(self):
        from ui.webapp import ValidatorApi
        api = ValidatorApi()
        строки = []
        было = api._on_log
        api._on_log = lambda текст, тег="info": (строки.append(текст),
                                                 было(текст, тег))[0]
        return api, строки

    def _дождаться(self, строки, кусок, секунд=25.0):
        предел = time.monotonic() + секунд
        while time.monotonic() < предел:
            if any(кусок in с for с in строки):
                return True
            time.sleep(0.05)
        return False

    def test_wholebase_counts_sources_beyond_the_first(self):
        from core.provider import scan_base_providers
        источники = [{"type": "text", "content": self.ПЕРВЫЙ},
                     {"type": "text", "content": self.ВТОРОЙ}]
        скан = scan_base_providers(источники)
        self.assertEqual(скан["total"], 4500,
                         "посчитаны не все источники: %d" % скан["total"])
        self.assertEqual(скан["providers"].get("Yahoo"), 1500,
                         "второй источник не увиден вовсе: %r" % скан["providers"])

        # ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: с прежней головной выборкой Yahoo пропадал.
        головной = scan_base_providers(источники, limit=3000)
        self.assertIsNone(головной["providers"].get("Yahoo"),
                          "выборка с начала внезапно видит второй источник — "
                          "тогда проверка выше ничего не доказывает")

    def test_wholebase_same_whether_loaded_at_once_or_in_parts(self):
        """«Не важно, за один подход или несколько» — прямое требование."""
        from core.provider import scan_base_providers

        разом, _ = self._окно(), None
        api, строки = разом
        api.paste({"kind": "emails", "text": self.ПЕРВЫЙ + "\n" + self.ВТОРОЙ})
        self.assertTrue(self._дождаться(строки, "Состав базы"))
        один = [с for с in строки if "Состав базы" in с][-1]

        api2, строки2 = self._окно()
        api2.paste({"kind": "emails", "text": self.ПЕРВЫЙ})
        self.assertTrue(self._дождаться(строки2, "Состав базы"))
        строки2.clear()
        api2.paste({"kind": "emails", "text": self.ВТОРОЙ})
        self.assertTrue(self._дождаться(строки2, "Состав базы"))
        два = [с for с in строки2 if "Состав базы" in с][-1]

        self.assertEqual(один, два,
                         "итог зависит от того, как загружали: %r против %r"
                         % (один, два))
        self.assertIn("4500", один, "посчитаны не все адреса: %r" % один)

    def test_wholebase_cancels_a_superseded_scan(self):
        """Восемь загрузок подряд не должны означать восемь полных проходов."""
        from core.provider import scan_base_providers

        просмотрено = {"n": 0}
        источник = [{"type": "text",
                     "content": "\n".join("a%d@gmail.com" % i
                                          for i in range(50000))}]

        def бросить_сразу():
            просмотрено["n"] += 1
            return True

        from core.provider import BASE_SCAN_BREATHE
        скан = scan_base_providers(источник, breathe_every=BASE_SCAN_BREATHE,
                                   should_stop=бросить_сразу)
        self.assertTrue(скан.get("stopped"), "скан не сообщил, что брошен")
        self.assertLessEqual(скан["total"], BASE_SCAN_BREATHE * 2,
                             "скан прошёл %d адресов вместо того чтобы "
                             "броситься" % скан["total"])

        # ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: без отказа проходится всё.
        целиком = scan_base_providers(источник, breathe_every=BASE_SCAN_BREATHE)
        self.assertEqual(целиком["total"], 50000)
        self.assertFalse(целиком.get("stopped"))

    def test_wholebase_speaks_before_and_after(self):
        """Минута молчания читается как зависание. Окно обязано говорить."""
        api, строки = self._окно()
        api.paste({"kind": "emails", "text": self.ПЕРВЫЙ})
        self.assertTrue(self._дождаться(строки, "Считаю состав базы"),
                        "окно не сказало, что считает: %r" % строки[-4:])
        self.assertTrue(self._дождаться(строки, "по ВСЕЙ базе"),
                        "окно не сказало, что посчитало всё: %r" % строки[-4:])
        итог = [с for с in строки if "по ВСЕЙ базе" in с][-1]
        self.assertIn("3000", итог, "не назван размер: %r" % итог)
        self.assertRegex(итог, r"за \d+\.\d с", "не сказано, сколько заняло")
