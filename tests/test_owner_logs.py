# -*- coding: utf-8 -*-
from исходники import исходник_конвейера
import re
import time
import unittest
from unittest import mock

from core.pipeline import ValidationPipeline
from core.network import NetworkValidator


def _пайплайн():
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


class TestProfilingSurvives(unittest.TestCase):

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
        self.assertTrue(any("Профиль готов" in s for s in строки),
                        "итог профилирования не сказан владельцу: %r" % строки)
        self.assertTrue(any("PTR" in s for s in строки),
                        "про PTR не сказано ничего, а от него зависит Yahoo/AOL")

    def test_profiling_failure_is_detectable(self):
        профили, строки, провал = self._прогнать(None)
        self.assertTrue(провал, "прежняя поломка НЕ ловится — проверка бесполезна")
        self.assertIn("AttributeError", провал[0],
                      "в логе не названа настоящая причина: %s" % провал[0])
        self.assertEqual(профили, {}, "при провале профили не должны быть выдуманы")

    def test_setup_makes_network_before_profiling(self):
        import inspect
        код = inspect.getsource(ValidationPipeline.setup)
        создание = код.index("self.network = NetworkValidator")
        вызов = код.index("self._profile_live_proxies")
        self.assertLess(создание, вызов,
                        "сеть создаётся ПОСЛЕ профилирования — прежняя поломка вернулась")


if __name__ == "__main__":
    unittest.main()


class _РежимИмён(unittest.TestCase):

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

    МУСОР = ["kavaterasports", "greenowlclothingco", "elmvaleymcagymnastics"]

    ДОГАДКА_С_ИМЕНЕМ = ["johnbirchly"]

    МУСОР_ОДНИМ_СЛОВОМ = ["anliewww", "premiuminstallations318",
                          "battlegroundfitnesslakeport", "podvorkus77", "gitprx222"]

    ЧЕЛОВЕК = ["john.doe", "maria.ivanova", "moein.farsadzadeh",
               "berwin.tolmach", "kolbusch.hensley"]

    ЖИВЫЕ = ["aminabello", "jenniferkline", "satishverma"]

    НЕИЗВЕСТНАЯ_ФАМИЛИЯ = ["simonevarelli"]

    def test_name_mode_accuracy_drops_invented_splits(self):
        for л in self.МУСОР:
            self.assertEqual(self.имя(л, "coverage"), "",
                             "%s: догадка без имени впереди осталась в обычном режиме" % л)
            self.assertEqual(self.имя(л, "accuracy"), "",
                             "%s: «Точность» оставила догадку сегментатора" % л)
        for л in self.ДОГАДКА_С_ИМЕНЕМ:
            self.assertTrue(self.имя(л, "coverage"),
                            "%s: в обычном режиме догадка с именем впереди должна ставиться" % л)
            self.assertEqual(self.имя(л, "accuracy"), "",
                             "%s: «Точность» оставила догадку сегментатора" % л)

    def test_one_unconfirmed_word_is_not_a_name_in_any_mode(self):
        for л in self.МУСОР_ОДНИМ_СЛОВОМ:
            for режим in ("coverage", "accuracy"):
                self.assertEqual(self.имя(л, режим), "",
                                 "%s: одно неподтверждённое слово стало именем (%s)"
                                 % (л, режим))

    def test_name_mode_keeps_boundaries_drawn_by_the_person(self):
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

    def test_accuracy_drops_a_guess_with_an_unknown_surname(self):
        for л in self.НЕИЗВЕСТНАЯ_ФАМИЛИЯ:
            self.assertEqual(self.имя(л, "accuracy"), "",
                             "%s: «Точность» оставила неподтверждённую фамилию" % л)
            self.assertTrue(self.имя(л, "coverage"),
                            "%s: «Заполненность» потеряла имя" % л)

    def test_name_mode_coverage_is_untouched(self):
        ожидалось = {
            "kavaterasports": "",
            "anliewww": "",
            "greenowlclothingco": "",
            "john.doe": "John Doe",
            "aminaduku": "Amina Duku",
            "elmvaleymcagymnastics": "",
            "johnbirchly": "John Birchly",
        }
        for л, ждём in ожидалось.items():
            self.assertEqual(self.имя(л, "coverage"), ждём,
                             "%s: поведение обычного режима изменилось" % л)


class TestNameSourceIsHonest(_РежимИмён):

    def test_name_source_marks_the_segmenter_as_a_guess(self):
        self.имя("johnbirchly", "coverage")
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
        import io
        app = io.open("ui/web/app.js", encoding="utf-8").read()
        подписи = app[app.index("const SOURCE_TEXT"):app.index("function sourceNote")]
        for ключ in ('"разбор"', '"адрес"', '"профиль"'):
            self.assertIn(ключ, подписи,
                          "окно не знает источника %s и напечатает сырое слово" % ключ)
        self.assertIn("догадка", подписи.split('"разбор"')[1].split("\n")[0],
                      "«разбор» подписан не как догадка")

    def test_name_source_reaches_the_pipeline(self):
        import inspect
        from core.pipeline import ValidationPipeline
        код = исходник_конвейера()
        self.assertIn("last_name_source", код,
                      "пайплайн не спрашивает источник имени — ярлык не доедет")
        self.assertIn('name_source = (узнать()', код,
                      "источник не кладётся в поле, которое уезжает в окно")


class TestEscapeResidueDoesNotBuryPeople(unittest.TestCase):

    ЧИНИТСЯ = {
        "u003cmarlowk@gmail.com": "marlowk@gmail.com",
        "u200fdelvinor@gmail.com": "delvinor@gmail.com",
        "u003elegal-notices@google.com": "legal-notices@google.com",
        "u003dmailer@example.com": "mailer@example.com",
        "u003cu200fbob@mail.ru": "bob@mail.ru",
    }

    НЕ_ТРОГАЕМ = [
        "u003c@gmail.com",
        "u003cxyz",
        "u0061bc@gmail.com",
        "myu003cname@gmail.com",
        "bob@u003cmail.ru",
        "john.doe@gmail.com",
        "uma.thurman@gmail.com",
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


class TestSecondOpinionReasonIsTrue(unittest.TestCase):

    ПЯТЬ_MX = ["gmail-smtp-in.l.google.com", "alt1.gmail-smtp-in.l.google.com",
               "alt2.gmail-smtp-in.l.google.com"]

    def _сеть(self, proxies=None, profiles=None):
        v = NetworkValidator(timeout=2, proxies=proxies or [])
        if profiles:
            v.set_proxy_profiles(profiles)
        return v

    def test_second_opinion_names_the_exhausted_pool(self):
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
        v = self._сеть()
        почему = {}
        ответ = v._confirm_invalid_on_other_mx(
            "u@single.example", "mx.single.example", ["mx.single.example"],
            False, False, "", deadline=float("inf"), first_proxy=None,
            почему=почему)
        self.assertIsNone(ответ)
        self.assertIn("один почтовый сервер", почему["текст"])

    def test_second_opinion_reason_reaches_the_verdict_text(self):
        import inspect
        from core.network import NetworkValidator as NV
        код = inspect.getsource(NV)
        self.assertIn("почему=почему", код,
                      "причина не запрашивается — в вердикт попадёт заглушка")
        self.assertNotIn("у домена один MX и", код,
                         "прежний неверный ярлык всё ещё зашит в вердикт")


class TestProxySweepBrake(unittest.TestCase):

    def test_proxy_sweep_stops_early_when_enough_are_found(self):
        import core.async_proxy as ap
        from core.network import filter_live_proxies

        прочитано = {"n": 0}

        def fake_checker(proxies=None, workers=0, timeout=0, mode="",
                         progress_callback=None, **kw):
            живые = []
            for адрес in proxies:
                прочитано["n"] += 1
                живые.append(адрес)
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


ПЯТЬ = ("enable_ai", "enable_osint", "use_cache", "resume", "confirm_valid")


class TestQualityDefaultsOn(unittest.TestCase):

    def test_quality_defaults_on_in_the_core_signatures(self):
        import inspect
        параметры = inspect.signature(ValidationPipeline.start).parameters
        for имя in ПЯТЬ:
            self.assertIn(имя, параметры, "ядро не принимает настройку %s" % имя)
            self.assertIs(параметры[имя].default, True,
                          "%s выключена по умолчанию" % имя)

        параметры = inspect.signature(ValidationPipeline.run_pipeline).parameters
        for имя in ("enable_ai", "enable_osint", "resume"):
            self.assertIs(параметры[имя].default, True,
                          "run_pipeline: %s выключена по умолчанию" % имя)

    def test_quality_defaults_on_reach_a_fresh_object(self):
        p, _ = _пайплайн()
        self.assertIs(getattr(p, "confirm_valid", False), True,
                      "второе мнение выключено у свежесозданного конвейера — "
                      "из командной строки оно не заработает")

    def test_quality_defaults_on_are_switchable_from_the_command_line(self):
        import io as _io
        cli = _io.open("cli.py", encoding="utf-8").read()
        for флаг in ("--no-ai", "--no-osint", "--no-cache",
                     "--no-resume", "--no-confirm-valid"):
            self.assertIn(флаг, cli, "нечем выключить: %s" % флаг)
        self.assertIn("pipeline.confirm_valid =", cli,
                      "флаг объявлен, но ни к чему не подключён")


class TestQualityTogglesGoneFromWindow(unittest.TestCase):

    def test_toggles_gone_from_the_markup_and_the_script(self):
        import io as _io
        html = _io.open("ui/web/index.html", encoding="utf-8").read()
        app = _io.open("ui/web/app.js", encoding="utf-8").read()
        for ид in ("optAi", "optOsint", "optResume", "optConfirm", "optCache"):
            self.assertNotIn(ид, html, "переключатель %s вернулся в окно" % ид)
            self.assertNotIn(ид, app, "скрипт снова читает %s" % ид)

    def test_toggles_gone_and_the_bridge_stops_overriding(self):
        import io as _io
        мост = _io.open("ui/webapp.py", encoding="utf-8").read()
        for ключ in ('payload.get("ai"', 'payload.get("osint"',
                     'payload.get("cache"', 'payload.get("confirm"',
                     'payload.get("resume"'):
            self.assertNotIn(ключ, мост,
                             "мост снова принимает из окна: %s" % ключ)


class TestResumeTrap(unittest.TestCase):

    АДРЕСА = ["one@example.com", "two@example.com", "three@example.com"]

    def setUp(self):
        import functools
        import shutil
        import tempfile
        from core.runstate import RunState, resumable_count

        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.журнал = __import__("os").path.join(self.tmp, "state.sqlite")

        import core.pipeline as pipe_mod
        было = pipe_mod.RunState
        pipe_mod.RunState = functools.partial(RunState, path=self.журнал)
        self.addCleanup(setattr, pipe_mod, "RunState", было)
        self._счёт = functools.partial(resumable_count, path=self.журнал)

    def _конвейер(self, ронять_на=None):
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


class TestBaseScanInWebWindow(unittest.TestCase):

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
        api, строки = self._окно()
        api.paste({"kind": "emails", "text": self.ПОЧТЫ})

        self.assertTrue(self._дождаться(строки, "Состав базы"),
                        "состав базы не напечатан: %r" % строки[-6:])
        отчёт = "\n".join(строки)
        self.assertIn("Gmail", отчёт, "провайдеры не перечислены")
        self.assertIn("Yahoo", отчёт, "провайдеры не перечислены")
        self.assertIn("Проверю с текущего IP", отчёт)
        self.assertIn("PTR", отчёт, "не сказано, каким доменам нужен PTR")

    def test_basescan_prints_nothing_for_proxies(self):
        api, строки = self._окно()
        api.paste({"kind": "proxies", "text": "1.2.3.4:1080\n5.6.7.8:1080"})
        time.sleep(1.0)
        self.assertFalse(any("Состав базы" in с for с in строки),
                         "состав базы посчитан для списка прокси: %r" % строки)

    def test_basescan_once_not_on_every_panel_poll(self):
        import inspect
        from ui.webapp import ValidatorApi
        self.assertNotIn("_rescan_base", inspect.getsource(ValidatorApi._recount),
                         "скан повешен на пересчёт строк — он будет повторяться")
        self.assertNotIn("_rescan_base", inspect.getsource(ValidatorApi.sources),
                         "скан повешен на опрос панели — он будет повторяться")

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


class TestWholeBaseScan(unittest.TestCase):

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

        головной = scan_base_providers(источники, limit=3000)
        self.assertIsNone(головной["providers"].get("Yahoo"),
                          "выборка с начала внезапно видит второй источник — "
                          "тогда проверка выше ничего не доказывает")

    def test_wholebase_same_whether_loaded_at_once_or_in_parts(self):
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

        целиком = scan_base_providers(источник, breathe_every=BASE_SCAN_BREATHE)
        self.assertEqual(целиком["total"], 50000)
        self.assertFalse(целиком.get("stopped"))

    def test_wholebase_speaks_before_and_after(self):
        api, строки = self._окно()
        api.paste({"kind": "emails", "text": self.ПЕРВЫЙ})
        self.assertTrue(self._дождаться(строки, "Считаю состав базы"),
                        "окно не сказало, что считает: %r" % строки[-4:])
        self.assertTrue(self._дождаться(строки, "по ВСЕЙ базе"),
                        "окно не сказало, что посчитало всё: %r" % строки[-4:])
        итог = [с for с in строки if "по ВСЕЙ базе" in с][-1]
        self.assertIn("3000", итог, "не назван размер: %r" % итог)
        self.assertRegex(итог, r"за \d+\.\d с", "не сказано, сколько заняло")
