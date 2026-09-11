# -*- coding: utf-8 -*-
"""Настоящий прогон внутри собранной программы: `MailFact.exe --selftest ЛОГ`.

ЗАЧЕМ ЭТО ЕСТЬ. Запуск окна не доказывает почти ничего. Окно открывается на
голом Python: движок проверки, словари имён, модель spaCy, корпус wordsegment,
запись sqlite и выгрузка подключаются ПОЗЖЕ, каждый своим ленивым импортом или
своим файлом данных. Ровно там PyInstaller и промахивается — он не падает на
отсутствующей зависимости, он просто её не кладёт. Сборка стартует, окно
рисуется, а посреди работы у человека вылезает трассировка.

Поэтому здесь проходится ТОТ ЖЕ путь, что у основного сценария, но на трёх
адресах вместо базы: разбор входа -> очистка -> синтаксис -> списки доменов ->
обогащение (имя, пол, страна) -> скоринг -> запись в хранилище -> выгрузка.
Сети не касаемся: без прокси программа по своему же правилу к почтовикам не
ходит, и проверять здесь надо не сеть, а то, что все её части собрались.

ПРО ВЫВОД. Раньше самотест ПЕРВЫМ действием подменял `sys.stdout` и
`sys.stderr` своим журналом — у сборки с `console=False` они равны None, и
казалось, что иначе нельзя. Следствие оказалось обратным замыслу: подменённый
поток ЧИНИЛ условие, которое самотест обязан был проверять. Выпуск 1.1.8
прошёл эту проверку зелёным, а у владельца не открывался ни один из четырёх
диалогов — ровно из-за отсутствия потоков.

Теперь потоки заводит `main.ensure_streams` до всех импортов, самотест ведёт
свой журнал отдельной ручкой и НЕ трогает потоки вовсе. Программа остаётся в
том же состоянии, в каком её видит человек, а состояние потоков само стало
проверяемым пунктом.

Код возврата: 0 — всё прошло, 1 — что-то не собралось.
"""
import io
import os
import sys
import time
import traceback

# Разделитель в одном файле ОДИН на все строки: так устроен разбор колонок.
# Смешивать запятую и точку с запятой внутри образца нельзя — это сломает не
# продукт, а сам образец.
ОБРАЗЕЦ = [
    # Обычный человек: имя, пол, страна должны определиться.
    "Ivan Petrov,Мужской,Россия,ivan.petrov@gmail.com",
    # Женское имя на немецком домене: страну берём из домена, не из имени.
    "Anna Schmidt,Женский,Германия,anna.schmidt@web.de",
    # Ролевой адрес на одноразовом домене: обязан быть опознан списками.
    "Support Team,,,info@mailinator.com",
]


def _пиши(лог, текст):
    лог.write(текст + "\n")
    лог.flush()


def run(путь_лога):
    """Возвращает 0 при успехе, 1 при провале. Пишет отчёт в путь_лога."""
    каталог = os.path.dirname(os.path.abspath(путь_лога))
    if каталог:
        os.makedirs(каталог, exist_ok=True)
    лог = io.open(путь_лога, "w", encoding="utf-8", newline="")

    # ПОТОКИ НЕ ТРОГАЕМ — см. объяснение наверху. Проверка, которая чинит
    # под собой проверяемое условие, зелена всегда и не значит ничего.

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

        # 0. ПОТОКИ ВЫВОДА. Их отсутствие сломало все четыре диалога в 1.1.8,
        #    и самотест обязан уметь это УВИДЕТЬ. Печатаем тем же способом,
        #    каким печатает чужая библиотека, — обычным print.
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

        # 1. Ресурсы сборки на месте.
        шаг(os.path.exists(resource_path("ui", "web", "index.html")),
            "разметка окна ui/web/index.html найдена")
        шаг(app_version() != "0.0.0", "VERSION прочитан из сборки")

        # 2. Пишущаяся папка: и создалась, и в неё можно писать.
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

        # 3. Разбор входа — тот же StreamLoader, что у окна.
        from core.streamer import StreamLoader
        источники = [{"type": "text", "content": "\n".join(ОБРАЗЕЦ)}]
        загружено = list(StreamLoader(источники).stream_emails())
        шаг(len(загружено) == len(ОБРАЗЕЦ),
            "разобрано адресов: %d из %d" % (len(загружено), len(ОБРАЗЕЦ)))

        # 4. Очистка и синтаксис.
        from core.cleaner import EmailCleaner
        from core.email_syntax import validate_email_syntax
        чистильщик = EmailCleaner()
        адреса = []
        for адрес, _мета in загружено:
            готовый = чистильщик.clean_email(адрес) or адрес
            адреса.append(готовый)
            шаг(bool(validate_email_syntax(готовый)),
                "синтаксис принят: %s" % готовый)

        # 5. Списки доменов — те самые файлы, что кладутся в сборку.
        from core.disposable import is_disposable
        from core.org_role import enrich_org_role
        from core.provider import is_free_mail_domain
        # Полный адрес, а не голый домен: функция ждёт именно адрес, и на
        # домене молча вернёт False — то есть проверка бы «прошла», ничего
        # не проверив.
        шаг(is_disposable("info@mailinator.com") is True,
            "список одноразовых доменов загружен")
        роль = enrich_org_role("info@mailinator.com")
        шаг(bool(роль.get("job_role")),
            "ролевой адрес опознан: job_role=%r" % роль.get("job_role"))
        шаг(is_free_mail_domain("gmail.com") is True,
            "список бесплатных почтовиков загружен")

        # 6. Обогащение. Здесь поднимаются names_dataset, gender_guesser,
        #    wordsegment и модель spaCy — тяжёлое, что чаще всего и теряется
        #    при сборке.
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
        NameExtractor()          # поднимает корпус wordsegment
        шаг(split_name("Ivan Petrov") == ("Ivan", "Petrov"),
            "имя делится на имя и фамилию")

        # 7. Скоринг.
        from core.scoring import calculate_engagement_score
        оценка = calculate_engagement_score(
            email="ivan.petrov@gmail.com", smtp_status="Valid",
            smtp_reason="250 OK", has_gravatar=False, dns_health_score=0,
            in_dnsbl=False, has_ptr=None, has_starttls=None,
            domain_age_days=-1, has_live_website=True,
            name_extracted="Ivan Petrov")
        балл = оценка.get("score") if isinstance(оценка, dict) else оценка
        шаг(isinstance(балл, (int, float)), "скоринг вернул число: %r" % балл)

        # 8. Хранилище результатов — sqlite В ПИШУЩЕЙСЯ папке. Именно здесь
        #    вылезла бы ошибка пути, если бы data_path указывал не туда.
        from ui.result_store import ResultStore
        хранилище = ResultStore()
        try:
            for адрес in адреса:
                хранилище.append(адрес, "Unverified", "selftest", "",
                                 {"score": балл})
            # СТРОК, а не суммы всех счётчиков: в counts() есть ещё
            # `total` и `names`, и сумма считает одни и те же строки
            # трижды. Печаталось вшестеро больше положенного, а порог
            # «не меньше трёх» проходил бы и при одной уцелевшей строке.
            всего = хранилище.counts()["total"]
            # Сравнение ТОЧНОЕ: сколько положили, столько и должно лечь.
            шаг(всего == len(адреса),
                "в хранилище легло строк: %d из %d" % (всего, len(адреса)))
        finally:
            хранилище.close()

        # 8а. ЗАГРУЗКА ФАЙЛА ТЕМ ЖЕ ПУТЁМ, ЧТО И КНОПКА В ОКНЕ.
        #
        # Это самый ходовой сценарий программы, и его не проверяло НИЧТО:
        # selftest трогал разбор, а окно — только открывалось. Владелец нажал
        # кнопку в собранной программе и получил «choose: 500», а причина
        # осталась в журнале, который удалился вместе с установкой.
        #
        # Диалог здесь не открывается: подменяется ровно его результат, то
        # есть список выбранных путей. Всё, что идёт ПОСЛЕ выбора — проверка
        # файла, чтение, пересчёт, пересканирование базы — выполняется
        # настоящее, тем же кодом окна.
        import tempfile
        from ui.webapp import ValidatorApi
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False,
                                         encoding="utf-8", newline="") as вх:
            # Перевод строки — кодом символа, а не escape-последовательностью:
            # обратный слэш не переживает автоматическую правку файла.
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
            # count — это число ПОДКЛЮЧЁННЫХ ИСТОЧНИКОВ, а строки лежат в
            # lines. Спутать их значит проверять не то: один файл даёт count=1
            # при любом числе адресов внутри.
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

        # 9. Выгрузка: строка CSV собирается тем же кодом, что и в окне.
        from core.baseops import csv_row, export_encoding
        ячейки = csv_row(["ivan.petrov@gmail.com", "Valid", "100"])
        шаг(isinstance(ячейки, list) and "ivan.petrov@gmail.com" in ячейки,
            "строка выгрузки собирается: %r" % (ячейки,))
        # utf-8-sig для .csv — Excel без BOM показывает кириллицу кракозябрами.
        шаг(export_encoding("out.csv") == "utf-8-sig",
            "кодировка выгрузки для .csv определена")

        # 10. DNS-часть: сама библиотека и её обработчики типов записей.
        import dns.resolver
        шаг(hasattr(dns.resolver, "Resolver"), "dnspython собран")
        import socks
        шаг(hasattr(socks, "socksocket"), "PySocks собран")

        # 11. Клиент поиска для вкладки «Сбор адресов». Импортируется лениво,
        #     то есть при открытии окна не выполняется вовсе — и его пропажу
        #     видно было бы только тогда, когда человек нажмёт «Начать сбор».
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
