# -*- coding: utf-8 -*-
import io
import os
import sys
import time
import traceback

ОБРАЗЕЦ = [
    "Ivan Petrov,Мужской,Россия,ivan.petrov@gmail.com",
    "Anna Schmidt,Женский,Германия,anna.schmidt@web.de",
    "Support Team,,,info@mailinator.com",
]


def _пиши(лог, текст):
    лог.write(текст + "\n")
    лог.flush()


def run(путь_лога):
    каталог = os.path.dirname(os.path.abspath(путь_лога))
    if каталог:
        os.makedirs(каталог, exist_ok=True)
    лог = io.open(путь_лога, "w", encoding="utf-8", newline="")


    провалы = []

    def шаг(ок, текст):
        _пиши(лог, "  %s %s" % ("ok  " if ок else "НЕТ ", текст))
        if not ок:
            провалы.append(текст)
        return ок

    начало = time.time()
    try:
        from core.paths import (app_version, data_dir, is_frozen,
                                resource_path, seed_data)
        _пиши(лог, "MailFact selftest")
        _пиши(лог, "  версия: %s" % app_version())
        _пиши(лог, "  собран: %s" % is_frozen())
        _пиши(лог, "  данные: %s" % data_dir())
        _пиши(лог, "  ресурсы: %s" % resource_path(""))

        for имя_потока in ("stdout", "stderr"):
            поток = getattr(sys, имя_потока, None)
            _пиши(лог, "  sys.%s: %s" % (имя_потока, type(поток).__name__
                                         if поток is not None else None))
            шаг(hasattr(поток, "write"),
                "sys.%s пригоден для записи" % имя_потока)
        try:
            print("проба вывода")
            шаг(True, "print() из чужой библиотеки не падает")
        except Exception as беда:
            шаг(False, "print() падает: %s: %s"
                % (type(беда).__name__, беда))

        шаг(os.path.exists(resource_path("ui", "web", "index.html")),
            "разметка окна ui/web/index.html найдена")
        шаг(app_version() != "0.0.0", "VERSION прочитан из сборки")

        скопировано = seed_data()
        _пиши(лог, "  поставляемые списки скопированы: %s" % (скопировано or "уже были"))
        проба = os.path.join(data_dir(), ".selftest-write")
        try:
            with io.open(проба, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(проба)
            шаг(True, "в папку данных можно писать")
        except OSError as e:
            шаг(False, "в папку данных писать нельзя: %s" % e)

        from core.streamer import StreamLoader
        источники = [{"type": "text", "content": "\n".join(ОБРАЗЕЦ)}]
        загружено = list(StreamLoader(источники).stream_emails())
        шаг(len(загружено) == len(ОБРАЗЕЦ),
            "разобрано адресов: %d из %d" % (len(загружено), len(ОБРАЗЕЦ)))

        from core.cleaner import EmailCleaner
        from core.email_syntax import validate_email_syntax
        чистильщик = EmailCleaner()
        адреса = []
        for адрес, _мета in загружено:
            готовый = чистильщик.clean_email(адрес) or адрес
            адреса.append(готовый)
            шаг(bool(validate_email_syntax(готовый)),
                "синтаксис принят: %s" % готовый)

        from core.disposable import is_disposable
        from core.org_role import enrich_org_role
        from core.provider import is_free_mail_domain
        шаг(is_disposable("info@mailinator.com") is True,
            "список одноразовых доменов загружен")
        роль = enrich_org_role("info@mailinator.com")
        шаг(bool(роль.get("job_role")),
            "ролевой адрес опознан: job_role=%r" % роль.get("job_role"))
        шаг(is_free_mail_domain("gmail.com") is True,
            "список бесплатных почтовиков загружен")

        from core.parser.ml_predictor import MLPredictor
        предсказатель = MLPredictor()
        шаг(предсказатель.nd is not None, "names_dataset поднялся")
        шаг(предсказатель.nlp is not None,
            "модель spaCy en_core_web_sm загрузилась")
        шаг(предсказатель.is_person("Ivan Petrov") is True,
            "NER считает 'Ivan Petrov' человеком")
        пол, страна = предсказатель.predict("Anna", email="anna@web.de")
        шаг(bool(пол) or bool(страна),
            "обогащение вернуло пол=%r страна=%r" % (пол, страна))

        from core.parser.name_extractor import NameExtractor, split_name
        NameExtractor()
        шаг(split_name("Ivan Petrov") == ("Ivan", "Petrov"),
            "имя делится на имя и фамилию")

        from core.scoring import calculate_engagement_score
        оценка = calculate_engagement_score(
            email="ivan.petrov@gmail.com", smtp_status="Valid",
            smtp_reason="250 OK", has_gravatar=False, dns_health_score=0,
            in_dnsbl=False, has_ptr=None, has_starttls=None,
            domain_age_days=-1, has_live_website=True,
            name_extracted="Ivan Petrov")
        балл = оценка.get("score") if isinstance(оценка, dict) else оценка
        шаг(isinstance(балл, (int, float)), "скоринг вернул число: %r" % балл)

        from ui.result_store import ResultStore
        хранилище = ResultStore()
        try:
            for адрес in адреса:
                хранилище.append(адрес, "Unverified", "selftest", "",
                                 {"score": балл})
            всего = хранилище.counts()["total"]
            шаг(всего == len(адреса),
                "в хранилище легло строк: %d из %d" % (всего, len(адреса)))
        finally:
            хранилище.close()

        import tempfile
        from ui.webapp import ValidatorApi
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8", newline="") as вх:
            НС = chr(10)
            вх.write(НС.join(ОБРАЗЕЦ) + НС)
            путь_базы = вх.name
        try:
            окно_api = ValidatorApi()
            окно_api._pick_files = lambda вид: [путь_базы]
            итог_выбора = окно_api.choose({"kind": "emails"})
            шаг(not итог_выбора.get("error"),
                "загрузка файла без ошибки: %r" % итог_выбора.get("error"))
            ведро = итог_выбора.get("emails", {})
            шаг(ведро.get("count", 0) >= 1,
                "источник подключён: count=%s" % ведро.get("count"))
            шаг(ведро.get("lines", 0) >= len(ОБРАЗЕЦ),
                "строк в поле: %s, ждали не меньше %d"
                % (ведро.get("lines"), len(ОБРАЗЕЦ)))
            шаг(bool(ведро.get("text")),
                "текст файла подтянулся в поле ввода")
        finally:
            try:
                os.remove(путь_базы)
            except OSError:
                pass

        from core.baseops import csv_row, export_encoding
        ячейки = csv_row(["ivan.petrov@gmail.com", "Valid", "100"])
        шаг(isinstance(ячейки, list) and "ivan.petrov@gmail.com" in ячейки,
            "строка выгрузки собирается: %r" % (ячейки,))
        шаг(export_encoding("out.csv") == "utf-8-sig",
            "кодировка выгрузки для .csv определена")

        import dns.resolver
        шаг(hasattr(dns.resolver, "Resolver"), "dnspython собран")
        import socks
        шаг(hasattr(socks, "socksocket"), "PySocks собран")

        try:
            from ddgs import DDGS
        except ImportError:
            from duckduckgo_search import DDGS
        DDGS()
        шаг(True, "клиент поиска DDGS собирается и создаётся")

    except Exception:
        _пиши(лог, "ИСКЛЮЧЕНИЕ:")
        _пиши(лог, traceback.format_exc())
        провалы.append("исключение при прогоне")

    _пиши(лог, "")
    _пиши(лог, "время: %.1f с" % (time.time() - начало))
    if провалы:
        _пиши(лог, "ПРОВАЛОВ: %d" % len(провалы))
        for т in провалы:
            _пиши(лог, "   - %s" % т)
        лог.close()
        return 1
    _пиши(лог, "SELFTEST_OK")
    лог.close()
    return 0
