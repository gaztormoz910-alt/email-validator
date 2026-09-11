#!/usr/bin/env python3
"""Окно валидатора на веб-стеке: pywebview поверх WebView2.

Стек взят у youtube-parser и по той же причине, что и там: страница
общается с питоном по локальному HTTP на 127.0.0.1, а НЕ через встроенный
мост pywebview (window.pywebview.api). Мост исполняет каждый вызов на потоке
интерфейса, и на winforms он в какой-то момент намертво блокирует
интерпретатор — окно рисуется, а питоновские потоки стоят. Обычный HTTP-сервер
живёт в своих потоках и интерфейсного не касается вовсе.

Сервер слушает только петлевой адрес и требует токен, который выдаётся
странице при загрузке: чтобы к нему не мог обратиться никто посторонний.

Почему интерфейс переехал с Tkinter. Четыре дефекта со скриншотов владельца
не чинились в Tkinter разумной ценой, а в вебе они не существуют по
устройству:

  * боковая панель обрезалась, до нижних настроек было не добраться —
    в вебе это одна строка `overflow-y: auto`;
  * кнопка «Сохранить отмеченные» обрезалась панелью инструментов —
    в вебе панель переносится на вторую строку;
  * заголовки таблицы слипались в «КачествоПочтовик» — в вебе ширины
    колонок задаются раз и соблюдаются;
  * пустые вкладки были чёрной пустотой — в вебе пустое состояние это
    обычный блок с объяснением.

Движок проверки не тронут: страница ходит в тот же ValidationPipeline и тот
же ResultStore, что и прежнее окно.
"""

import hashlib
import io
import json
import mimetypes
import os
import secrets
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from core import input_guard
from core.parser_pipeline import SEARCH_ENGINES
from core.winnoise import (install_webview_noise_filter,
                           quiet_chromium, WebViewReaper)
from core.crashlog import (crash_log_path, log_crash,  # noqa: F401
                           recent_crashes)
from ui.result_store import normalize_filters
from core.encoding import open_text
from core.baseops import csv_row, export_encoding

from core.paths import app_version, resource_path, seed_data

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Через resource_path, а не от __file__: в собранном .exe модуль лежит внутри
# архива, и относительный путь к разметке ведёт в никуда.
WEB_DIR = resource_path("ui", "web")

APP_NAME = "MailFact"

PAGE_SIZE = 100


def _тип_диалога(имя):
    """Константа диалога по НЫНЕШНЕМУ API pywebview.

    `webview.OPEN_DIALOG` и соседи — не константы, а СВОЙСТВА МОДУЛЯ: каждое
    обращение пишет предупреждение об устаревании через logging. У собранной
    программы потоков вывода нет, запись падала с AttributeError, и он уезжал
    наружу — так ломались все четыре диалога. Нынешний `FileDialog.OPEN`
    ничего не печатает.

    Запасной путь оставлен для старых версий pywebview, где перечисления ещё
    нет: там мы сознательно берём устаревшее имя, потому что другого нет.
    """
    import webview

    перечисление = getattr(webview, "FileDialog", None)
    if перечисление is not None and hasattr(перечисление, имя):
        return getattr(перечисление, имя)
    return getattr(webview, {"OPEN": "OPEN_DIALOG", "SAVE": "SAVE_DIALOG",
                             "FOLDER": "FOLDER_DIALOG"}[имя])


class ValidatorApi:
    """То, что страница может попросить у питона.

    Каждый публичный метод — одна конечная точка. Возвращают обычные
    словари: сервер сам превратит их в JSON.
    """

    def __init__(self):
        from ui.result_store import ResultStore, group_of
        from ui.log_buffer import LogBuffer
        from core.pipeline import ValidationPipeline

        self._group_of = group_of
        # Повтор по уже показанному ящику в таблицу не попадает: строка здесь
        # означает предложение отправить письмо, и один ящик двумя строками —
        # это двойная отправка и жалоба на спам.
        self.store = ResultStore(drop_repeats=True)
        self.log = LogBuffer(capacity=4000)

        # Четыре вида источников: два у проверки, два у сбора адресов.
        # Раньше вид определялся сравнением kind == "emails", и всё, что не
        # адреса, считалось прокси — с приездом дорков это молча смешало бы
        # два разных списка в один.
        self._sources = {"emails": [], "proxies": [], "dorks": [], "pproxy": []}
        self.suppress_path = None

        self.window = None                  # ставится при создании окна
        self._lock = threading.Lock()
        self._progress = (0, 0)
        # Проверка прокси идёт ДО проверки почт и своим счётом: (проверено,
        # прочитано). Второе число — не итог: источник ещё читается.
        self._proxy_progress = (0, 0)
        # Чем занят конвейер прямо сейчас: "" — обычная проверка,
        # "retry" — перепроверка отложенных.
        self._phase = ("", 0)
        # Сколько строк в каждом наборе источников. None означает «ещё считаю»:
        # на гигабайтном файле счёт занимает десятки секунд, и делать его в
        # потоке, который обслуживает страницу, нельзя.
        self._line_counts = {"emails": 0, "proxies": 0, "dorks": 0, "pproxy": 0}
        self._count_jobs = {}
        self._count_lock = threading.Lock()
        # Отдельный счётчик поколений для скана состава базы. Общий со
        # счётом строк не годится: строки пересчитываются при каждой правке
        # файла на диске, а состав — только при смене набора источников.
        self._scan_job = 0
        self._scan_lock = threading.Lock()
        self._state = "idle"                # idle | running | paused | done
        self._proxy_summary = None
        self._pending = []                  # строки лога, ещё не отданные
        # Сквозной номер строки. Без него «хвост» и «очередь» не согласовать:
        # хвост отдаёт всё подряд, а очередь — только новое, и общие строки
        # приходят дважды. Замерено: из 290 показанных строк 129 были дублями.
        self._log_seq = 0
        # Хвост лога хранится отдельно: страница может перезагрузиться (F5,
        # переоткрытие окна), а уже отданные строки к тому моменту стёрты из
        # очереди. Без хвоста после перезагрузки терминал оказывается пустым,
        # хотя прогон идёт и позади сотни строк.
        self._history = []
        self._history_cap = 1500
        # Отпечаток файлов (размер + время правки) на момент подсчёта строк.
        # Нужен, чтобы заметить правку базы в редакторе и пересчитать.
        self._file_stamps = {}
        self._export_busy = False

        # Сбор адресов: свой конвейер, свой лог, свои счётчики.
        self.parser = None
        # «Запуск уже нажали, конвейер ещё не успел объявить себя идущим».
        # Промежуток между этими двумя событиями и был дырой для второго
        # прогона.
        self._starting = False
        self._parser_state = "idle"
        self._parser_progress = (0, 0, 0, "Парсинг")
        self._parser_stats = {"dorksDone": 0, "dorksTotal": 0,
                              "pages": 0, "snippets": 0, "emails": 0}
        self._parser_pending = []
        self._parser_history = []
        self._parser_rows = []          # (адрес, дорк) в порядке находки
        self._parser_seen = set()       # один адрес не показывается дважды

        self.pipeline = ValidationPipeline(callbacks={
            "on_log": self._on_log,
            "on_progress": self._on_progress,
            "on_phase": self._on_phase,
            "on_revise": self._on_revise,
            "on_proxy_progress": self._on_proxy_progress,
            "on_result": self._on_result,
            "on_complete": self._on_complete,
            "on_unique_count": lambda count: None,
            "on_proxies_tested": lambda live, total: self._on_log(
                f"[INFO] Прокси: рабочих {live} из {total}.", "info"),
            "on_proxy_profile": self._on_proxy_profile,
        })

    @property
    def email_sources(self):
        return self._sources["emails"]

    @property
    def proxy_sources(self):
        return self._sources["proxies"]

    # До какого размера файл читается в поле ввода целиком.
    #
    # Владелец просил полной равнозначности: «софту должно быть срать, как я
    # данные загружаю». Она и сделана — но у показа в поле есть физический
    # потолок. Строка на десять миллионов адресов, положенная в textarea,
    # вешает окно намертво: браузер держит её целиком, считает переносы и
    # перерисовывает на каждое нажатие клавиши. Поэтому крупный файл остаётся
    # файлом, и об этом сказано прямо, а не умолчано.
    #
    # На сам ПРОГОН это не влияет никак: движок читает оба вида источника
    # одинаково и потоково.
    INLINE_LIMIT = 5 * 1024 * 1024

    # Вид источника -> что в нём ожидается. Нужно проверке ввода: положить
    # список прокси в поле адресов проще простого, а всплывает ошибка только
    # через минуту прогона тысячами непонятных отказов.
    _EXPECTED_KIND = {
        "emails": "email",
        "proxies": "proxy",
        "dorks": "dork",
        "pproxy": "proxy",
        "suppress": "email",
    }

    def _busy(self):
        """Идёт ли сейчас прогон — валидатор или сбор адресов.

        Одна точка на весь мост: пока она врёт, любая блокировка на странице
        остаётся рисунком, который обходится одним запросом мимо неё.

        Про признаки. У валидатора это `is_running`, у сбора — `is_alive()`:
        ParserPipeline наследует threading.Thread, и своего `is_running` у
        него нет. Спрашивать у него `is_running` — значит всегда получать
        «не идёт» и не запирать ввод во время сбора вовсе. Тот же признак,
        что и в parser_start, где решается, можно ли запускать второй раз.
        """
        if self._starting or getattr(self.pipeline, "is_running", False):
            return True
        parser = getattr(self, "parser", None)
        if parser is None:
            return False

        # Остановку у сбора уже запросили — считаем свободным, не дожидаясь
        # смерти потока. Он может ещё долго закрывать Tor и отпускать
        # соединения, и всё это время окно оставалось бы запертым, хотя
        # команда отдана. Источники конвейер забрал копией при запуске,
        # так что менять их в этот момент безопасно.
        stopping = getattr(parser, "_stop_event", None)
        if stopping is not None and stopping.is_set():
            return False

        alive = getattr(parser, "is_alive", None)
        if callable(alive):
            return bool(alive())
        return bool(getattr(parser, "is_running", False))

    _BUSY_REFUSAL = ("Идёт проверка — менять исходные данные нельзя. "
                     "Остановите прогон или дождитесь конца.")

    #: Что отвечаем на запрос, который не разобрали. Отдельной строкой,
    #: потому что её ждут сразу три обработчика и она должна быть одинаковой.
    _BAD_KIND = ("Не понял, куда это класть: поле не названо или названо "
                 "неизвестно как. Выберите поле и попробуйте ещё раз.")

    def _bucket(self, kind):
        """Ведро источников по имени, либо None, если имя незнакомое.

        Раньше отсюда летело исключение. Оно доходило до моста, тот отвечал
        пятисоткой с текстом «ValueError: неизвестный вид источника», и для
        владельца это выглядело как «нажал и ничего»: страница показать такое
        не умеет. Незнакомое имя — это ОТКАЗ с причиной, а не поломка.

        Молча сваливать список в первое попавшееся ведро тоже нельзя: так
        адреса однажды уехали в поле прокси.
        """
        if not isinstance(kind, str):
            return None
        return self._sources.get(kind)

    # ---------------------------------------------------- от движка ----
    def _on_log(self, text, tag="info"):
        with self._lock:
            self._log_seq += 1
            line = {"text": str(text), "tag": tag, "n": self._log_seq}
            self._pending.append(line)
            self._history.append(line)
            if len(self._history) > self._history_cap:
                del self._history[:len(self._history) - self._history_cap]

    def resume_info(self, payload=None):
        """Есть ли что продолжать по нынешним файлам базы.

        Ноль значит «нечего»: страница тогда прячет предложение вовсе, чтобы
        не звать нажимать на пустое.
        """
        from core.runstate import resumable_count

        try:
            done = resumable_count(list(self.email_sources))
        except Exception:
            done = 0
        return {"done": int(done)}

    def _on_revise(self, domains, new_status, note):
        """Пересмотр уже показанных строк по разоблачённым доменам.

        Домен раскрывается не сразу: тройная проба могла сорваться, а
        тарпитинг начинается после сотни проверенных адресов. Их «Годен» уже
        в таблице — и без этого канала так там и оставался.
        """
        moved = 0
        for domain in domains or []:
            try:
                moved += self.store.revise_domain(domain, new_status, note)
            except Exception:
                continue
        return moved

    # Когда окно в последний раз о себе напомнило. Ноль означает «ещё ни
    # разу»: до первого запроса судить о тишине не по чему.
    last_seen_at = 0.0
    # Сколько всего запросов пришло от окна. По приросту видно ТЕМП, а темп
    # отличает работающее окно от подавленного.
    request_count = 0

    def _on_phase(self, name, count):
        self._phase = (str(name or ""), int(count or 0))

    def _on_progress(self, current, total):
        self._progress = (int(current or 0), int(total or 0))

    def _on_proxy_progress(self, checked, seen):
        """Проверка прокси. Второе число — прочитано, а НЕ итог.

        Держится отдельно от прогресса почт намеренно: это разные вещи, и
        показывать их одной полосой значит врать. Владелец читал «Проверено
        16 891 из 19 590» как адреса, хотя это были прокси, и «из» росло по
        мере чтения файла.
        """
        self._proxy_progress = (int(checked or 0), int(seen or 0))

    def _on_result(self, email, status, reason, mx, data=None):
        data = data if isinstance(data, dict) else {}
        group = self.store.append(email, status, reason, mx, data)
        label = {"valid": "VALID", "invalid": "DEAD"}.get(group)
        if label is None:
            label = str(status).upper()
        tag = {"valid": "valid", "invalid": "dead"}.get(group, "trap")
        self._on_log(f"[{label}] {email} -> {reason}", tag)

    def _on_complete(self):
        self._state = "done"
        self._on_log("[INFO] Проверка завершена.", "info")

    def _on_proxy_profile(self, summary):
        self._proxy_summary = summary

    # ------------------------------------------------------ источники --
    def _pick_files(self, title):
        """Родной диалог выбора файлов. Пустой ответ — пользователь передумал."""
        if self.window is None:
            return []
        chosen = self.window.create_file_dialog(
            _тип_диалога("OPEN"), allow_multiple=True,
            file_types=("Списки (*.txt;*.csv)", "Все файлы (*.*)"))
        return list(chosen or [])

    def choose(self, payload):
        """Выбор файлов для базы или для прокси."""
        payload = payload if isinstance(payload, dict) else {}
        kind = payload.get("kind")
        target = self._bucket(kind)
        if target is None:
            return dict(self.sources(), error=self._BAD_KIND)
        if self._busy():
            return dict(self.sources(), error=self._BUSY_REFUSAL)

        paths = self._pick_files(kind)
        expected = self._EXPECTED_KIND.get(kind)
        accepted, refused, oversized = [], [], []
        for path in paths:
            # Проверяется КАЖДЫЙ файл, а не первый: владелец выбирает их
            # пачкой, и прокси среди пяти баз иначе проедут незамеченными.
            #
            # Весь разбор ОДНОГО файла обёрнут: неожиданная беда на нём не
            # имеет права обвалить весь запрос. Иначе один странный файл из
            # пяти выбранных отменяет загрузку остальных четырёх, а человек
            # видит голый код ошибки вместо имени виноватого файла.
            try:
                verdict = (input_guard.check_file(path, expected)
                           if expected else {"ok": True})
            except Exception as беда:
                refused.append("Не удалось разобрать %s (%s: %s)"
                               % (os.path.basename(path),
                                  type(беда).__name__, беда))
                continue
            if not verdict["ok"]:
                refused.append(verdict["reason"])
                continue

            accepted.append(path)
            # Небольшой файл становится ТЕКСТОМ — ровно тем же, что получилось
            # бы от вставки руками. Дальше он и правится в поле, и уходит в
            # движок одинаково: разницы между двумя способами загрузки больше
            # нет.
            text = self._read_inline(path)
            if text is None:
                target.append({"type": "file", "path": path})
                oversized.append(os.path.basename(path))
            else:
                target.append({"type": "text", "content": text,
                               "title": os.path.basename(path)})

        if accepted:
            self._on_log(f"[INFO] Подключено файлов: {len(accepted)}.", "info")
            self._recount(kind)
            self._rescan_base(kind)
        for reason in refused:
            self._on_log(f"[DEAD] Файл отклонён: {reason}", "dead")
        for name in oversized:
            self._on_log(
                f"[INFO] {name} больше {self.INLINE_LIMIT // (1024 * 1024)} МБ — "
                "в поле ввода не показан, но в проверку пойдёт целиком.", "info")

        result = self.sources()
        if refused:
            result["error"] = refused[0]
        return result

    def _read_inline(self, path):
        """Текст файла, если он не слишком велик для поля ввода.

        None означает «слишком большой» — тогда файл остаётся файлом. Это не
        отговорка: строка на десять миллионов адресов в текстовом поле вешает
        окно, а движку она в поле и не нужна.
        """
        try:
            if os.path.getsize(path) > self.INLINE_LIMIT:
                return None
            # Тот же определитель кодировки, что и у движка: иначе файл
            # из Excel показывался бы в поле замещающими символами, и
            # владелец видел бы порчу там, где её нет.
            with open_text(path) as handle:
                return handle.read()
        except Exception as беда:
            # ЛОВИМ ВСЁ, а не только OSError.
            #
            # input_guard.check_file читает ВЫБОРКУ первых строк, а здесь файл
            # читается ЦЕЛИКОМ. Один плохой байт в середине большой базы
            # проходит проверку и взрывается тут: UnicodeDecodeError — это
            # ValueError, не OSError, и он улетал наружу необработанным. Мост
            # отвечал 500, окно показывало «choose: 500», и человек не мог
            # загрузить файл вообще, не понимая почему.
            #
            # Не показать файл в поле ввода — не беда: он остаётся источником
            # и уходит в проверку целиком, потоковым чтением, которое к
            # плохим байтам устойчиво. Беда — молча отказать в загрузке.
            self._on_log("[INFO] %s в поле ввода не показан (%s: %s), "
                         "но в проверку пойдёт целиком."
                         % (os.path.basename(path), type(беда).__name__, беда),
                         "info")
            return None

    def paste(self, payload):
        """Список, вставленный текстом вместо файла."""
        payload = payload if isinstance(payload, dict) else {}
        kind = payload.get("kind")
        bucket = self._bucket(kind)
        if bucket is None:
            return dict(self.sources(), error=self._BAD_KIND)
        if self._busy():
            return dict(self.sources(), error=self._BUSY_REFUSAL)

        text = str(payload.get("text") or "")
        if not text.strip():
            return dict(self.sources(), error="Пусто — нечего добавлять.")

        expected = self._EXPECTED_KIND.get(kind)
        if expected:
            verdict = input_guard.check_text(text, expected)
            if not verdict["ok"]:
                self._on_log(f"[DEAD] Вставка отклонена: {verdict['reason']}", "dead")
                return dict(self.sources(), error=verdict["reason"])

        bucket.append({"type": "text", "content": text, "title": "вставленный текст"})
        self._recount(kind)
        self._rescan_base(kind)
        return self.sources()

    def clear(self, payload):
        payload = payload if isinstance(payload, dict) else {}
        bucket = self._bucket(payload.get("kind"))
        if bucket is None:
            return dict(self.sources(), error=self._BAD_KIND)
        if self._busy():
            return dict(self.sources(), error=self._BUSY_REFUSAL)
        bucket.clear()
        self._recount(payload.get("kind"))
        # И при очистке тоже: она обязана отменить отчёт, начатый для
        # прошлого набора, иначе он допечатается уже после неё.
        self._rescan_base(payload.get("kind"))
        return self.sources()

    @staticmethod
    def _stat_of(path, field):
        try:
            info = os.stat(path)
            return int(getattr(info, field))
        except OSError:
            return -1

    def _recount(self, kind):
        """Пересчитывает строки в источниках вида kind — в фоне.

        Зачем фон. count_total_lines() читает файлы целиком: на списке в
        миллионы строк это десятки секунд. В потоке, который обслуживает
        страницу, они превратились бы в зависшее окно сразу после выбора
        файла. Пока идёт счёт, наружу отдаётся None — страница пишет
        «считаю…», а не ноль: ноль владелец прочитал бы как «файл пустой».
        """
        snapshot = list(self._sources.get(kind) or [])
        with self._count_lock:
            job = self._count_jobs.get(kind, 0) + 1
            self._count_jobs[kind] = job
            self._line_counts[kind] = 0 if not snapshot else None

        if not snapshot:
            return

        def work():
            from core.streamer import StreamLoader

            try:
                total = StreamLoader(snapshot).count_total_lines()
            except Exception:
                total = 0
            with self._count_lock:
                # Пока считали, владелец мог добавить ещё файл. Тогда наш
                # ответ устарел, и записывать его нельзя: на экране осталось
                # бы число от прошлого набора.
                if self._count_jobs.get(kind) == job:
                    self._line_counts[kind] = int(total)
                    # Отпечаток берётся ПОСЛЕ счёта: иначе правка, случившаяся
                    # во время чтения, осталась бы незамеченной.
                    self._file_stamps[kind] = [
                        (item.get("path") or "",
                         self._stat_of(item.get("path"), "st_size"),
                         self._stat_of(item.get("path"), "st_mtime"))
                        for item in snapshot if item.get("type") == "file"]

        threading.Thread(target=work, daemon=True).start()

    def _rescan_base(self, kind):
        """Состав базы в лог — сразу после загрузки, как в классическом окне.

        Отвечает на вопрос, который владелец задаёт ДО запуска: сколько
        адресов, каких провайдеров, что из этого проверится с текущего IP, а
        чему нужен адрес с PTR или чистой репутацией. Ни одного сетевого
        запроса — только чтение выборки.

        ЗОВЁТСЯ ТОЛЬКО ПРИ СМЕНЕ НАБОРА ИСТОЧНИКОВ, а не из _recount.
        _recount дёргается из sources() при каждом опросе панели, если файл
        изменился на диске; повесить скан туда значило бы перечитывать
        полумиллионный файл снова и снова, пока окно открыто.

        Прокси и дорки не сканируются: разбивка по почтовым провайдерам для
        них бессмысленна.
        """
        if kind != "emails":
            return

        snapshot = list(self._sources.get(kind) or [])
        with self._scan_lock:
            # Поколение растёт и при очистке: скан, начатый для прошлого
            # набора, не должен допечатать свой отчёт после неё.
            self._scan_job += 1
            job = self._scan_job
        if not snapshot:
            return

        def устарел():
            with self._scan_lock:
                return self._scan_job != job

        def work():
            import time as _time
            from core.provider import (scan_base_providers, format_base_scan,
                                       BASE_SCAN_BREATHE)
            self._on_log("[INFO] Считаю состав базы по ВСЕМ подключённым "
                         "источникам — это чтение без единого запроса в сеть.",
                         "info")
            начало = _time.monotonic()
            try:
                # breathe_every заставляет скан отпускать GIL. Без него этот
                # поток — сплошной чистый Python, и панель перестаёт отвечать
                # на опрос, хотя загрузка давно вернулась.
                #
                # limit НЕ ПЕРЕДАЁТСЯ намеренно: выборка бралась с начала и
                # описывала первый файл, выдавая его состав за состав базы.
                scan = scan_base_providers(snapshot,
                                           breathe_every=BASE_SCAN_BREATHE,
                                           should_stop=устарел)
            except Exception as e:
                self._on_log("[DEAD] Скан состава базы не удался: %s: %s"
                             % (type(e).__name__, e), "dead")
                return
            if scan.get("stopped") or устарел():
                return          # набор сменился, наш отчёт устарел
            for line in format_base_scan(scan):
                self._on_log(line, "info")
            self._on_log("[INFO] Состав посчитан по ВСЕЙ базе (%d адресов) "
                         "за %.1f с." % (scan.get("total", 0),
                                         _time.monotonic() - начало), "info")

        threading.Thread(target=work, daemon=True,
                         name="скан-состава-базы").start()

    def _files_changed_on_disk(self, kind):
        """Изменились ли файлы этого набора с момента подсчёта.

        Владелец правит базу в текстовом редакторе и удивляется, что счётчик
        не меняется: строки посчитаны один раз при загрузке, и о правке файла
        программа узнать неоткуда. Сравнение размера и времени правки стоит
        одного системного вызова на файл — это не чтение, окно не подвиснет
        даже на гигабайтном списке.
        """
        stamp = []
        for source in self._sources.get(kind) or []:
            if source.get("type") != "file":
                continue
            path = source.get("path") or ""
            try:
                info = os.stat(path)
                stamp.append((path, int(info.st_size), int(info.st_mtime)))
            except OSError:
                stamp.append((path, -1, -1))
        with self._count_lock:
            known = self._file_stamps.get(kind)
            self._file_stamps[kind] = stamp
        return known is not None and known != stamp

    def sources(self, payload=None):
        """Что сейчас подключено. Считается лениво — файл не читается."""
        # Файл мог измениться на диске после загрузки. Проверяем это на
        # каждом опросе панели: один stat на файл, зато число на экране
        # перестаёт врать.
        for kind in ("emails", "proxies", "dorks", "pproxy"):
            if self._files_changed_on_disk(kind):
                self._on_log(
                    "[INFO] Файл изменился на диске — пересчитываю строки.", "info")
                self._recount(kind)
        def describe(sources, kind):
            if not sources:
                return {"count": 0, "title": "Выберите файл", "detail": "",
                        "text": "", "editable": True, "lines": 0}
            names = [s.get("title") or os.path.basename(s["path"])
                     if s["type"] == "file" else (s.get("title") or "вставленный текст")
                     for s in sources]
            title = names[0] if len(names) == 1 else f"{len(names)} источника"

            # Текст для поля ввода. Он есть, только если ВСЕ источники —
            # текстовые: показать половину и дать её править значило бы тихо
            # потерять вторую половину при сохранении.
            editable = all(s["type"] == "text" for s in sources)
            text = "\n".join(s.get("content", "") for s in sources) if editable else ""
            # `count` — сколько ФАЙЛОВ, `lines` — сколько СТРОК. Раньше
            # наружу уходило только первое, и окно писало «13 источника» —
            # число, по которому нельзя понять, сколько прокси загружено.
            with self._count_lock:
                lines = self._line_counts.get(kind, 0)
            return {"count": len(sources), "title": title,
                    "detail": ", ".join(names[:3]),
                    "text": text, "editable": editable, "lines": lines}

        # Прокси — НЕ обязательное условие запуска.
        #
        # Движок умеет идти напрямую и честно об этом предупреждает, а окно
        # требовало прокси и дальше не пускало. Владелец загружал двадцать
        # шесть тысяч бесплатных прокси, из которых живых оказывалось
        # полсотни, ждал двадцать минут перебора — и до проверки почт дело не
        # доходило вовсе. Со стороны это выглядит как «SMTP-проверки нет».
        missing = []
        if not self._sources["emails"]:
            missing.append("адреса")
        direct = not self._sources["proxies"]
        return {
            "emails": describe(self._sources["emails"], "emails"),
            "proxies": describe(self._sources["proxies"], "proxies"),
            "dorks": describe(self._sources["dorks"], "dorks"),
            "pproxy": describe(self._sources["pproxy"], "pproxy"),
            "ready": not missing,
            # Прямой прогон возможен, но цена названа прямо: почтовики увидят
            # домашний адрес владельца, а Yahoo, AOL, Outlook и iCloud с него
            # вообще не отвечают — им нужен IP с обратным DNS и чистой
            # репутацией.
            "direct": direct,
            "hint": ("Не хватает: " + " и ".join(missing) if missing
                     else ("Всё готово — можно запускать" if not direct
                           else "Прокси нет: проверка пойдёт с твоего IP. "
                                "Gmail и Яндекс ответят, Yahoo/AOL/Outlook/iCloud — нет")),
            # У сбора адресов прокси необязательны: DuckDuckGo Lite ходит
            # напрямую, а Tor-движки поднимают собственный выход.
            "parserReady": bool(self._sources["dorks"]),
            "parserHint": ("Всё готово — можно собирать"
                           if self._sources["dorks"] else "Не хватает: дорки"),
        }

    def choose_suppression(self, payload=None):
        """Список отписок. Проверяется строже прочих.

        Цена ошибки здесь выше, чем у базы: по этому списку решают, кому НЕ
        слать. Подсунутый вместо него список прокси не вычтет никого, и
        письмо уйдёт человеку, который прямо попросил его не трогать, —
        а это уже жалоба на спам, а не просто лишняя проверка.
        """
        paths = self._pick_files("suppress")
        if not paths:
            self.suppress_path = None
            return {"path": ""}

        verdict = input_guard.check_file(paths[0], "email")
        if not verdict["ok"]:
            self._on_log(f"[DEAD] Список отписок отклонён: {verdict['reason']}", "dead")
            return {"path": os.path.basename(self.suppress_path or ""),
                    "error": verdict["reason"]}

        self.suppress_path = paths[0]
        return {"path": os.path.basename(self.suppress_path)}

    # --------------------------------------------------------- прогон --
    @staticmethod
    def _number(payload, key, default, low, high):
        """Число из поля страницы, загнанное в допустимые границы.

        Голый int() падает на «abc» и пропускает 999999 потоков дальше в
        движок. Поле ввода на странице ограничено атрибутами min и max, но
        запрос может прийти и мимо страницы.
        """
        try:
            value = float(payload.get(key, default))
        except (TypeError, ValueError):
            return default
        if value != value:            # NaN
            return default
        return int(max(low, min(high, value)))

    def start(self, payload):
        # Признак «идёт прогон» у конвейера взводится ПОЗДНО — внутри рабочего
        # потока и уже после подготовки, а она длится минутами: перебор прокси,
        # прогрев модели. Всё это время повторный щелчок по кнопке проходил бы
        # проверку и запускал ВТОРОЙ конвейер: строки лога удваивались, а
        # счётчики показывали один прогон, потому что второй очищал хранилище.
        # Владелец принимал это за неудалённые дубликаты.
        if self._busy() or self._starting:
            return {"ok": False, "error": "Проверка уже идёт"}
        # Проверка источников идёт ДО взведения флага. Раньше флаг ставился
        # раньше, и выход «сначала выберите адреса и прокси» оставлял его
        # взведённым навсегда: следующий щелчок получал «проверка уже идёт»,
        # хотя не шло ничего, и кнопка не оживала до перезапуска программы.
        if not self.email_sources:
            return {"ok": False, "error": "Сначала выберите адреса"}
        if not self.proxy_sources and not payload.get("allowDirect"):
            # Молча ходить напрямую нельзя: это раскрывает домашний IP
            # владельца почтовым серверам, и согласие на такое должно быть
            # осознанным, а не побочным следствием пустого поля.
            return {"ok": False, "direct": True,
                    "error": "Прокси не заданы. Проверка пойдёт с твоего "
                             "домашнего IP — подтверди, если это осознанно."}
        self._starting = True

        from core.parser.ml_predictor import set_country_mode
        set_country_mode(payload.get("country") or "coverage")

        if not self.proxy_sources:
            self._on_log(
                "[DEAD] Прокси не заданы: проверка идёт с твоего домашнего IP. "
                "Gmail и Яндекс ответят честно; Yahoo, AOL, Outlook и iCloud "
                "почти наверняка откажут — им нужен адрес с обратным DNS и "
                "чистой репутацией.", "dead")

        self.store.clear()
        self._progress = (0, 0)
        self._phase = ("", 0)
        self._state = "running"
        self._proxy_summary = None

        try:
            thread = self._launch_pipeline(payload)
        except Exception as exc:
            # Без этого исключение внутри подготовки запирало запуск до
            # перезапуска: флаг остался бы взведённым, а сторож ниже —
            # неустановленным.
            self._starting = False
            self._state = "done"
            return {"ok": False, "error": "Запуск не удался: %s" % exc}

        # Сторож снимает запрет, как только поток кончился: без него упавшая
        # подготовка запирала бы запуск до перезапуска программы.
        def release():
            if thread is not None:
                thread.join()
            self._starting = False

        threading.Thread(target=release, daemon=True).start()
        return {"ok": True}

    def _launch_pipeline(self, payload):
        """Собственно запуск. Вынесен, чтобы сброс флага был в одном месте."""
        from core.streamer import StreamLoader

        return self.pipeline.start(
            email_sources=list(self.email_sources),
            threads=self._number(payload, "threads", 100, 1, 500),
            timeout=self._number(payload, "timeout", 5, 1, 300),
            fix_typos=True, check_spam=True, deep_ping=True,
            # ПЯТЬ НАСТРОЕК КАЧЕСТВА ОКНО БОЛЬШЕ НЕ ПЕРЕДАЁТ.
            #
            # Владелец убрал их из интерфейса: щёлкать пять галочек
            # перед каждым прогоном он не хочет, а забытая галочка —
            # это молча ухудшенный результат. Значения по умолчанию
            # живут в ядре (core/pipeline.py), и здесь мы их просто не
            # трогаем. Именно НЕ ПЕРЕДАЁМ, а не передаём True: тогда
            # ядро остаётся единственным местом, где это решается, и
            # два места не смогут разойтись.
            # ИСТОЧНИКИ, а не строки прокси, конвейеру подавать нельзя.
            #
            # Он ждёт поток строк вида «1.2.3.4:8080», а получал список
            # словарей {"type": ..., "content": ...}. Ни одна такая запись
            # прокси не является, поэтому проверка честно отвечала «рабочих
            # 0 из 0» — и прогон шёл БЕЗ ЕДИНОГО ПРОКСИ, с домашнего адреса.
            # В логе это выглядит как сплошные RISKY: Yahoo отказывает по
            # FCrDNS, Outlook по репутации, а владелец видит «валидатор врёт».
            #
            # Прежнее окно читало источники через StreamLoader и подавало
            # строки; при переезде на веб-стек этот шаг потерялся. Читаем
            # лениво: список прокси бывает на миллионы строк.
            proxies=StreamLoader(list(self.proxy_sources)).stream_lines(),
            )

    def pause(self, payload=None):
        self.pipeline.pause()
        self._state = "paused" if self.pipeline.is_paused else "running"
        return {"state": self._state}

    def stop(self, payload=None):
        self.pipeline.stop()
        self._state = "done"
        return {"state": self._state}

    # ---------------------------------------------------------- показ --
    def state(self, payload=None):
        """Всё, что нужно странице для перерисовки. Один запрос на тик."""
        counts = self.store.counts()
        current, total = self._progress
        proxy_checked, proxy_seen = self._proxy_progress
        with self._lock:
            since = payload.get("logSince") if isinstance(payload, dict) else None
            if since is None:
                lines, self._pending = self._pending, []
            else:
                # Страница says, что уже видела всё до этого номера. Берём из
                # хвоста строго новое — так ответ не зависит от того, кто
                # успел первым, хвост или опрос.
                try:
                    since = int(since)
                except (TypeError, ValueError):
                    since = 0
                lines = [line for line in self._history if line.get("n", 0) > since]
                self._pending = []
        return {
            "state": self._state,
            "running": bool(self.pipeline.is_running),
            "counts": {
                "valid": counts["valid"], "invalid": counts["invalid"],
                "spam": counts["spam"], "unknown": counts["unknown"],
                "total": counts["total"], "names": counts["names"],
            },
            "progress": {"current": current, "total": total,
                         "pct": int(current * 100 / total) if total else 0},
            # Проверка прокси — отдельно и БЕЗ процента: пока источник
            # читается, целого не существует, и делить не на что.
            "proxyProgress": {"checked": proxy_checked, "seen": proxy_seen,
                              "running": bool(proxy_seen) and not total},
            "phase": {"name": self._phase[0], "count": self._phase[1]},
            "log": lines,
            "logSeq": self._log_seq,
            "dropped": self.log.dropped,
            "proxy": self._proxy_summary,
            "exportBusy": self._export_busy,
        }

    def log_tail(self, payload=None):
        """Последние строки лога — для страницы, которая только открылась.

        Очередь при этом опустошается: всё, что в ней лежало, уже есть в
        хвосте, и без сброса те же строки пришли бы вторым экземпляром
        ближайшим опросом.
        """
        with self._lock:
            # Отдаём хвост и СРАЗУ говорим, на каком номере он кончается.
            # Страница дальше просит только строки после него, поэтому
            # порядок «хвост против опроса» перестаёт что-либо значить.
            tail = list(self._history)
            self._pending = []
            return {"log": tail, "seq": self._log_seq}

    def page(self, payload):
        """Страница таблицы. Берётся из того же хранилища, что и раньше."""
        payload = payload if isinstance(payload, dict) else {}
        picked = self._filters(payload)
        # Номер страницы приходит со страницы и может быть чем угодно. Голый
        # int() падает на «abc», и таблица не показывается вовсе.
        try:
            number = max(1, int(payload.get("page") or 1))
        except (TypeError, ValueError):
            number = 1

        total = self.store.matching_count(filters=picked)
        pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        number = min(number, pages)
        rows = self.store.page(filters=picked, page=number, size=PAGE_SIZE)

        out = []
        for row in rows:
            data = row.get("data") or {}
            out.append({
                "email": row["email"],
                # Хеш для аватарки, и только когда обогащение её нашло.
                # Слать хеш для всех подряд значило бы дёргать чужой сервер на
                # каждую строку таблицы и рассказывать ему всю базу.
                "avatar": (_gravatar_hash(row["email"])
                           if data.get("has_gravatar") else ""),
                "status": row["status"],
                "group": self._group_of(row["status"]),
                "reason": row["reason"],
                "score": data.get("engagement_score", ""),
                # Исходная строка из файла — рядом с проверенной.
                "original": data.get("original_email", ""),
                # Уверенность в ВЕРДИКТЕ и её основание — не скор живости.
                # Показываются рядом со статусом: без них «Годен» на
                # catch-all домене выглядит так же твёрдо, как «Годен»,
                # подтверждённый контрольной пробой.
                "confidence": data.get("verdict_confidence", ""),
                "basis": data.get("verdict_basis", ""),
                "provider": data.get("provider_name", ""),
                "name": data.get("name", ""),
                "gender": data.get("gender", ""),
                "country": data.get("country", ""),
                "when": data.get("validated_at", ""),
                # Всё, что движок знает про адрес, но в девять колонок не
                # влезает. Едет в карточку строки — иначе обогащение,
                # посчитанное на каждом адресе, видно только в выгрузке и в
                # консоли, то есть для владельца его как бы нет.
                #
                # Источники (откуда взято имя, пол, страна) стоят здесь не для
                # полноты: именно они делают видимым переключатель «Точность /
                # Заполненность». Без них «Италия» из файла и «Италия»,
                # угаданная по имени, выглядят одинаково твёрдо, а это разные
                # вещи — на 1600 частых именах строгий режим даёт 50.1% верных
                # при 8.7% неверных, а «брать лидера всегда» — 66.4% при 33.6%.
                "more": {
                    "domain_type": data.get("domain_type", ""),
                    "provider_type": data.get("provider_type", ""),
                    "grade": data.get("engagement_grade", ""),
                    "company": data.get("company", ""),
                    "job_role": data.get("job_role", ""),
                    "birth_year": data.get("birth_year", ""),
                    "first_name": data.get("first_name", ""),
                    "last_name": data.get("last_name", ""),
                    "social": data.get("social_accounts", ""),
                    "name_source": data.get("name_source", ""),
                    "gender_source": data.get("gender_source", ""),
                    "country_source": data.get("country_source", ""),
                    "company_source": data.get("company_source", ""),
                    "job_role_source": data.get("job_role_source", ""),
                    "ai_note": data.get("ai_note", ""),
                    # Адрес, который в итоге ушёл на сервер. Совпадает с
                    # колонкой «Адрес» и заполнен только когда сработало
                    # исправление опечатки, — но показать его надо: это и
                    # есть вторая половина пары «загружено / проверено».
                    "checked_as": data.get("checked_as", ""),
                    # Вердикт взят из прошлого прогона, а не спрошен сейчас.
                    # Владельцу это важно знать: дата в колонке «Когда» у
                    # такой строки исходная, а не сегодняшняя.
                    "from_cache": bool(data.get("from_cache")),
                    # Похожий домен, который мы спросили ОТДЕЛЬНО, когда
                    # загруженный оказался мёртвым. Подсказка, а не подмена:
                    # вердикт в строке остаётся про загруженный адрес.
                    # Без этих двух полей владелец видел «мёртвый домен» и не
                    # знал, что рядом есть работающий похожий ящик.
                    "suggested_email": data.get("suggested_email", ""),
                    "suggested_status": data.get("suggested_status", ""),
                    "mx": row.get("mx", ""),
                },
                # Насколько вердикту можно верить сегодня. Ящик могли удалить
                # через день после проверки, и «Годен» месячной давности —
                # уже не то же самое, что «Годен» сегодняшний.
                "age": _verdict_age(data.get("validated_at", "")),
            })
        return {"rows": out, "page": number, "pages": pages, "total": total}

    @staticmethod
    def _filters(payload):
        """Разбор запроса страницы. Один разбор на все запросы к выборке."""
        payload = payload if isinstance(payload, dict) else {}
        return normalize_filters({
            "groups": payload.get("groups") or ("valid",),
            "minScore": payload.get("minScore"),
            "country": payload.get("country"),
            "gender": payload.get("gender"),
            "provider": payload.get("provider"),
            "search": payload.get("search"),
        })

    def facets(self, payload=None):
        """Какие страны, полы и почтовики встретились — для списков фильтра.

        Считается по запросу страницы, а не по всей базе: список должен
        показывать то, что найдётся при текущем наборе фильтров.
        """
        picked = self._filters(payload)
        values = self.store.facet_values(filters=picked)
        return {"facets": values, "total": self.store.matching_count(filters=picked)}

    def export(self, payload):
        """Выгрузка в фоне: на многомиллионной базе она идёт минутами."""
        if self._export_busy:
            return {"ok": False, "error": "Выгрузка уже идёт"}
        if self.window is None:
            return {"ok": False, "error": "Окно недоступно"}
        target = self.window.create_file_dialog(
            _тип_диалога("SAVE"), save_filename="valid_emails.csv")
        if not target:
            return {"ok": False, "cancelled": True}
        path = target if isinstance(target, str) else target[0]

        picked = self._filters(payload)
        # Ноль означает «одним файлом»; потолок — чтобы опечатка в поле не
        # превратила выгрузку в миллион файлов по одной строке.
        chunk = self._number(payload, "chunk", 0, 0, 100_000_000)

        self._export_busy = True
        threading.Thread(target=self._export_worker,
                         args=(path, picked, chunk),
                         daemon=True).start()
        return {"ok": True}

    def _export_worker(self, path, picked, chunk):
        import csv
        from core import baseops
        from core.cleaner import normalize_for_dedup
        try:
            drop = set()
            if self.suppress_path:
                try:
                    drop = baseops.suppression_keys(self.suppress_path)
                except Exception as exc:
                    self._on_log(f"[DEAD] Отписки не применены: {exc}", "dead")

            def write_csv(handle, rows):
                writer = csv.writer(handle)
                # Набор полей ТОТ ЖЕ, что у командной строки (cli.EXPORT_FIELDS).
                #
                # Раньше окно отдавало пятнадцать полей против двадцати пяти в
                # консоли, и получалось наоборот здравому смыслу: чем удобнее
                # поверхность, тем меньше она отдаёт. Владелец, работающий
                # окном, терял компанию, должность, год рождения, тип домена,
                # грейд и все источники — то есть ровно то новое, ради чего
                # обогащение и считается на каждом адресе.
                #
                # Тест рядом сверяет два списка: разойдутся — набор упадёт.
                writer.writerow(["Email", "OriginalEmail", "Status", "Reason",
                                 "MX", "Name",
                                 "FirstName", "LastName", "Gender", "Country",
                                 "BirthYear", "Company", "JobRole",
                                 "Score", "Grade",
                                 "Confidence", "ConfidenceBasis",
                                 "Provider", "DomainType",
                                 "NameSource", "GenderSource", "CountrySource",
                                 "CompanySource", "JobRoleSource",
                                 "SocialAccounts", "ValidatedAt",
                                 # Доля Valid по домену: 1.0 при пяти и более
                                 # проверенных — подпись catch-all.
                                 "DomainValidRatio", "DomainChecked",
                                 # Вердикт взят из прошлого прогона и в этом
                                 # не перепроверялся. Дата рядом исходная, но
                                 # 29-дневный «Годен» выглядит как свежий,
                                 # если на неё не смотреть.
                                 "FromCache"])
                for row in rows:
                    data = row.get("data") or {}
                    # csv_row, а не голый список: база собрана со страниц в
                    # интернете, и ячейка, начинающаяся со знака равенства,
                    # в Excel не показывается, а выполняется.
                    writer.writerow(csv_row([
                        row["email"],
                        # Что лежало в файле. Пусто, если очистка ничего не
                        # меняла: тогда это та же строка.
                        data.get("original_email", ""),
                        row["status"], row["reason"], row["mx"],
                        data.get("name", ""), data.get("first_name", ""),
                        data.get("last_name", ""), data.get("gender", ""),
                        data.get("country", ""),
                        data.get("birth_year", ""), data.get("company", ""),
                        data.get("job_role", ""),
                        data.get("engagement_score", ""),
                        data.get("engagement_grade", ""),
                        data.get("verdict_confidence", ""),
                        data.get("verdict_basis", ""),
                        data.get("provider_name", ""),
                        data.get("domain_type", ""),
                        data.get("name_source", ""), data.get("gender_source", ""),
                        data.get("country_source", ""),
                        data.get("company_source", ""),
                        data.get("job_role_source", ""),
                        data.get("social_accounts", ""),
                        data.get("validated_at", ""),
                        data.get("domain_valid_ratio", ""),
                        data.get("domain_checked", ""),
                        "да" if data.get("from_cache") else "",
                    ]))

            skipped = {"n": 0}

            def rows():
                for row in self.store.iter_matching(filters=picked):
                    if drop and normalize_for_dedup(row["email"]) in drop:
                        skipped["n"] += 1
                        continue
                    yield row

            written, saved = baseops.write_chunks_stream(rows(), path, chunk, write_csv)
            note = f"[INFO] Сохранено строк: {saved}."
            if skipped["n"]:
                note += f" Вычтено по отпискам: {skipped['n']}."
            if len(written) > 1:
                note += f" Файлов: {len(written)}."
            self._on_log(note, "valid")
        except Exception as exc:
            self._on_log(f"[DEAD] Выгрузка не удалась: {type(exc).__name__}: {exc}", "dead")
        finally:
            self._export_busy = False

    # ================================================== сбор адресов ==
    #
    # Конвейер сбора — core/parser_pipeline.py. Обратные вызовы складывают
    # всё в очереди, а страница забирает их опросом. Когда-то кнопка «Сбор
    # адресов» здесь просто советовала перезапустить программу с другим
    # окном; того окна больше нет, и советовать нечего.

    # Поисковики и открытые API в одном списке.
    #
    # У API нет ни капчи, ни разбора разметки, ни разной выдачи на разных
    # прокси: они отдают структурированный ответ. Поле «Поисковые запросы»
    # для них означает запрос к источнику, а для PyPI — имя пакета.
    # Список движков собирается из ОДНОГО места. Раньше имена API-источников
    # были переписаны сюда руками, и добавленный в конвейер источник в окне не
    # появлялся: список в двух местах расходится всегда, вопрос лишь когда.
    # Список берётся из конвейера, а не переписывается здесь. Две копии
    # одного списка расходятся молча: окно предлагает движок, которого
    # конвейер уже не знает.
    PARSER_ENGINES = list(SEARCH_ENGINES)

    def _parser_log(self, message, tag="info"):
        line = {"text": str(message), "tag": tag}
        with self._lock:
            self._parser_pending.append(line)
            self._parser_history.append(line)
            if len(self._parser_history) > self._history_cap:
                del self._parser_history[:len(self._parser_history) - self._history_cap]

    def _parser_progress_cb(self, current, total, pct, label="Парсинг"):
        self._parser_progress = (int(current or 0), int(total or 0),
                                 int(pct or 0), str(label))

    def _parser_stats_cb(self, dorks_tot, dorks_done, pages, snippets, emails):
        self._parser_stats = {"dorksTotal": int(dorks_tot or 0),
                              "dorksDone": int(dorks_done or 0),
                              "pages": int(pages or 0),
                              "snippets": int(snippets or 0),
                              "emails": int(emails or 0)}

    def _parser_result_cb(self, email, dork, *args, **kwargs):
        # Повторы отсекаются здесь: один и тот же адрес выпадает из разных
        # дорков, и без этого он занимал бы место в списке столько раз,
        # сколько раз попался.
        key = str(email).strip().lower()
        if not key:
            return
        with self._lock:
            if key in self._parser_seen:
                return
            self._parser_seen.add(key)
            self._parser_rows.append((str(email), str(dork or "")))

    def _parser_complete_cb(self, aborted=False):
        self._parser_state = "done"
        self._parser_log("[Система] Сбор адресов завершён." if not aborted
                         else "[Система] Сбор адресов остановлен.", "info")

    def parser_start(self, payload):
        if self.parser is not None and self.parser.is_alive():
            return {"ok": False, "error": "Сбор уже идёт"}
        if not self._sources["dorks"]:
            return {"ok": False, "error": "Сначала загрузите дорки"}

        engine = payload.get("engine") or self.PARSER_ENGINES[0]
        if engine not in self.PARSER_ENGINES:
            return {"ok": False, "error": "Неизвестный поисковик"}
        threads = self._number(payload, "threads", 20, 1, 500)
        timeout = self._number(payload, "timeout", 15, 1, 120)

        with self._lock:
            self._parser_rows = []
            self._parser_seen = set()
        self._parser_stats = {"dorksDone": 0, "dorksTotal": 0,
                              "pages": 0, "snippets": 0, "emails": 0}
        self._parser_progress = (0, 0, 0, "Парсинг")
        self._parser_state = "running"

        dork_sources = list(self._sources["dorks"])
        proxy_sources = list(self._sources["pproxy"])

        def launch():
            """Чтение прокси и запуск — в фоне.

            Файл прокси на большом пуле читается заметное время, и в потоке,
            который обслуживает страницу, это была бы пауза между нажатием
            кнопки и первой строчкой лога.
            """
            try:
                proxies = []
                if proxy_sources:
                    from core.network import dedupe_proxies_stream
                    from core.streamer import StreamLoader
                    proxies = list(dedupe_proxies_stream(
                        StreamLoader(proxy_sources).stream_lines()))

                from core.parser_pipeline import ParserPipeline
                pipeline = ParserPipeline(
                    dork_sources=dork_sources,
                    proxies=proxies,
                    max_threads=threads,
                    timeout=timeout,
                    on_log=self._parser_log,
                    on_progress=self._parser_progress_cb,
                    on_stats_update=self._parser_stats_cb,
                    on_result_found=self._parser_result_cb,
                    on_complete=self._parser_complete_cb,
                    engine_name=engine,
                )
                self.parser = pipeline
                pipeline.start()
            except Exception as exc:
                # Молча упавший поток выглядел бы как «нажал и ничего»:
                # состояние осталось бы running навсегда.
                self._parser_state = "done"
                self._parser_log("[Ошибка] Сбор не запустился: %s" % exc, "dead")

        threading.Thread(target=launch, daemon=True).start()
        return {"ok": True}

    def parser_pause(self, payload=None):
        pipeline = self.parser
        if pipeline is None or not pipeline.is_alive():
            return {"state": self._parser_state}
        if pipeline._pause_event.is_set():
            pipeline.resume()
            self._parser_state = "running"
            self._parser_log("[Система] Сбор возобновлён.", "info")
        else:
            pipeline.pause()
            self._parser_state = "paused"
            self._parser_log("[Система] Сбор приостановлен.", "info")
        return {"state": self._parser_state}

    def parser_stop(self, payload=None):
        pipeline = self.parser
        if pipeline is not None and pipeline.is_alive():
            pipeline.stop()
            self._parser_log("[Система] Остановка сбора.", "info")
        self._parser_state = "done"
        return {"state": self._parser_state}

    def parser_state(self, payload=None):
        with self._lock:
            lines, self._parser_pending = self._parser_pending, []
            found = len(self._parser_rows)
        current, total, pct, label = self._parser_progress
        alive = self.parser is not None and self.parser.is_alive()
        stats = dict(self._parser_stats)
        stats["found"] = found
        return {"state": self._parser_state,
                "running": bool(alive),
                "engines": list(self.PARSER_ENGINES),
                "stats": stats,
                "progress": {"current": current, "total": total,
                             "pct": pct, "label": label},
                "log": lines}

    def parser_log_tail(self, payload=None):
        with self._lock:
            self._parser_pending = []
            return {"log": list(self._parser_history)}

    def parser_page(self, payload=None):
        """Страница найденных адресов."""
        payload = payload or {}
        number = max(1, int(payload.get("page") or 1))
        with self._lock:
            rows = list(self._parser_rows)
        total = len(rows)
        pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
        number = min(number, pages)
        start = (number - 1) * PAGE_SIZE
        chunk = rows[start:start + PAGE_SIZE]
        return {"rows": [{"email": e, "dork": d} for e, d in chunk],
                "page": number, "pages": pages, "total": total}

    def client_error(self, payload=None):
        """Сбой в САМОМ окне: ошибка JS или неперехваченный отказ обещания.

        Половина случаев «программа наебнулась» приходится сюда, а не на
        питон: журнал событий Windows краха процесса не показывал, то есть
        ломалось окно, а не движок. Без этого канала такой сбой не оставлял
        следа нигде — консоль WebView2 владельцу не видна.

        Возвращает путь к журналу, чтобы окно могло назвать его владельцу.
        """
        payload = payload if isinstance(payload, dict) else {}
        message = str(payload.get("message") or "")[:500]
        where = str(payload.get("where") or "")[:300]
        stack = str(payload.get("stack") or "")[:4000]

        # Ни слова описания — записывать нечего.
        #
        # Раньше здесь стояла подстановка «Ошибка в окне», и в журнале
        # владельца скопилось двадцать таких записей: место занято, разобрать
        # нельзя, а программа при запуске о них ещё и докладывала. Пустая
        # улика хуже отсутствия улики.
        if not (message.strip() or where.strip() or stack.strip()):
            return {"ok": False, "error": "пустое сообщение — записывать нечего"}

        # Текст приходит ИЗ ОКНА, то есть из места, где выполняется наш же
        # JavaScript. Обрезаем длины и кладём как данные, ничего не исполняя.
        body = message
        if stack:
            body += "\n" + stack
        log_crash("окно", body, context=where or None)

        # В ЖУРНАЛ ТОЙ ВКЛАДКИ, ГДЕ СБОЙ И СЛУЧИЛСЯ. Раньше сюда шёл только
        # _on_log, то есть журнал проверки базы: владелец нажимал кнопку во
        # вкладке «Сбор адресов», а ошибка вылезала в соседней. Выглядело
        # это так, будто ломается не то, что он трогал, — и он потратил
        # время, разбираясь, при чём тут валидатор.
        куда = (self._parser_log if str(payload.get("mode") or "") == "parser"
                else self._on_log)
        куда("[DEAD] Сбой в окне: %s. Записано в %s"
             % (message, crash_log_path()), "dead")
        return {"ok": True, "path": crash_log_path()}

    def parser_copy(self, payload=None):
        limit = 200_000
        with self._lock:
            rows = self._parser_rows[:limit]
        return {"text": chr(10).join(e for e, _ in rows), "count": len(rows),
                "capped": len(rows) >= limit}

    def parser_export(self, payload=None):
        """Сохранение найденного. Запись идёт в фоне: список бывает большим."""
        if self.window is None:
            return {"ok": False, "error": "Окно недоступно"}
        with self._lock:
            rows = list(self._parser_rows)
        if not rows:
            return {"ok": False, "error": "Пока нечего сохранять"}

        path = self.window.create_file_dialog(
            _тип_диалога("SAVE"), save_filename="parsed_emails.txt",
            file_types=("Текст (*.txt)", "CSV (*.csv)"))
        if not path:
            return {"ok": False, "error": ""}
        path = path if isinstance(path, str) else path[0]

        def write():
            try:
                with open(path, "w", encoding=export_encoding(path),
                          newline="") as handle:
                    if path.lower().endswith(".csv"):
                        import csv
                        writer = csv.writer(handle)
                        writer.writerow(["email", "dork"])
                        writer.writerows(csv_row(r) for r in rows)
                    else:
                        for email, _dork in rows:
                            handle.write(email + chr(10))
                self._parser_log("[Система] Сохранено адресов: %d." % len(rows), "info")
            except OSError as exc:
                self._parser_log("[Ошибка] Не удалось сохранить: %s" % exc, "dead")

        threading.Thread(target=write, daemon=True).start()
        return {"ok": True, "path": os.path.basename(path), "count": len(rows)}

    def export_segments(self, payload):
        """Раскладывает выборку по сегментам в отдельные файлы.

        Смысл в том, чтобы не делать десять ручных выгрузок: письмо женщинам
        из США и письмо мужчинам из Индии — разные письма, и разбирать базу
        руками владелец будет каждый раз заново.
        """
        if self._export_busy:
            return {"ok": False, "error": "Выгрузка уже идёт"}

        key = str(payload.get("by") or "country").strip()
        if key not in ("country", "gender", "provider"):
            return {"ok": False, "error": "Неизвестный признак: %s" % key}

        if self.window is None:
            return {"ok": False, "error": "Окно недоступно"}
        chosen = self.window.create_file_dialog(_тип_диалога("FOLDER"))
        if not chosen:
            return {"ok": False, "cancelled": True}
        folder = chosen if isinstance(chosen, str) else chosen[0]

        picked = self._filters(payload)
        self._export_busy = True
        threading.Thread(target=self._segments_worker,
                         args=(folder, key, picked), daemon=True).start()
        return {"ok": True}

    def _segments_worker(self, folder, key, picked):
        import csv

        from core.baseops import segment_filename, split_by_segment
        try:
            rows = list(self.store.iter_matching(filters=picked))
            buckets = split_by_segment(rows, key)
            if not buckets:
                self._on_log("[DEAD] В выборке нечего раскладывать.", "dead")
                return

            written = 0
            for value, group in sorted(buckets.items(),
                                       key=lambda kv: -len(kv[1])):
                name = "%s-%s.csv" % (key, segment_filename(value))
                path = os.path.join(folder, name)
                with io.open(path, "w", encoding=export_encoding(path),
                             newline="") as handle:
                    writer = csv.writer(handle)
                    writer.writerow(["Email", "Status", "Name", "Gender",
                                     "Country", "Score", "ValidatedAt"])
                    for row in group:
                        data = row.get("data") or {}
                        writer.writerow(csv_row([
                            row["email"], row["status"], data.get("name", ""),
                            data.get("gender", ""), data.get("country", ""),
                            data.get("engagement_score", ""),
                            data.get("validated_at", ""),
                        ]))
                written += 1
                self._on_log("[VALID] %s — %d адресов." % (name, len(group)), "valid")

            self._on_log("[INFO] Разложено файлов: %d. Папка: %s"
                         % (written, folder), "info")
        except Exception as exc:
            self._on_log("[DEAD] Раскладка не удалась: %s: %s"
                         % (type(exc).__name__, exc), "dead")
        finally:
            self._export_busy = False

    def copy_rows(self, payload):
        """Адреса выборки текстом — страница положит их в буфер обмена."""
        picked = self._filters(payload)
        limit = 200_000        # больше в буфер обмена всё равно не кладут
        out = []
        for row in self.store.iter_matching(filters=picked):
            out.append(row["email"])
            if len(out) >= limit:
                break
        return {"text": "\n".join(out), "count": len(out), "capped": len(out) >= limit}


# ============================================================ HTTP-мост

class _Handler(BaseHTTPRequestHandler):
    api: ValidatorApi = None
    token: str = ""

    # HTTP/1.1 — то есть ОДНО соединение на много запросов.
    #
    # По умолчанию BaseHTTPRequestHandler говорит HTTP/1.0, а это новое
    # TCP-соединение на КАЖДЫЙ запрос. Окно опрашивает состояние четыре раза
    # в секунду плюс два раза от сбора адресов — то есть шесть соединений в
    # секунду, и каждое Windows держит в TIME_WAIT ещё четыре минуты после
    # закрытия. Замерено на машине владельца: 923 занятых порта на 127.0.0.1
    # при динамическом диапазоне в 16384. Тысяча портов, сожжённых ни за что,
    # и постоянная нагрузка на сетевой стек там, где хватает одного
    # соединения.
    #
    # Включать безопасно: keep-alive требует, чтобы у каждого ответа была
    # длина, а весь вывод идёт через _send, и он Content-Length ставит
    # всегда. Тест рядом считает РЕАЛЬНО открытые соединения, а не наличие
    # этой строки.
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):          # тишина в консоли
        pass

    def handle_one_request(self):
        """То же, что у родителя, но без крика при обрыве со стороны браузера.

        Браузер обрывает незавершённый запрос всякий раз, когда уходит со
        страницы, перезагружается или отменяет опрос, — это его нормальное
        поведение, а не авария сервера. Родительский класс на такой обрыв
        печатает в консоль полную трассировку `ConnectionAbortedError
        [WinError 10053]`, и владелец видит красное полотно там, где ничего
        не сломалось.

        Глушится ТОЛЬКО обрыв связи. Любая другая ошибка проходит наверх как
        раньше и попадает в журнал сбоев.
        """
        try:
            BaseHTTPRequestHandler.handle_one_request(self)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            self.close_connection = True

    def _authorised(self):
        header = self.headers.get("X-Token")
        query = parse_qs(urlparse(self.path).query)
        given = header or (query.get("token") or [""])[0]
        return secrets.compare_digest(given or "", self.token)

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        raw = body if isinstance(body, bytes) else str(body).encode("utf-8")
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(raw)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(raw)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError):
            # Браузер ушёл, не дочитав ответ. Писать некому — и это не повод
            # печатать трассировку: отменённый запрос штатное дело.
            self.close_connection = True

    # Оформление отдаётся без токена, всё остальное — только с ним.
    #
    # Иначе не работает вовсе: браузер не добавляет наши заголовки к
    # подгружаемым style.css и app.js, а дописать токен в href значит
    # напечатать его в разметке. Эти два файла статичны и не содержат ни
    # одного пользовательского байта, поэтому открывать их безопасно;
    # index.html же несёт токен внутри и потому по-прежнему закрыт.
    PUBLIC = {"/style.css", "/app.js"}

    def do_GET(self):
        path = urlparse(self.path).path
        if path not in self.PUBLIC and not self._authorised():
            self._send(403, json.dumps({"error": "forbidden"}))
            return

        name = "index.html" if path in ("/", "/index.html") else path.lstrip("/")
        # Никаких путей наружу: страница лежит ровно в одной папке.
        safe = os.path.normpath(os.path.join(WEB_DIR, name))
        # Сравнение с разделителем на конце обязательно: без него сосед
        # ui/webapp.py проходит проверку на «лежит внутри ui/web», потому
        # что его путь начинается с той же строки. Запрос /../webapp.py
        # так отдавал исходник.
        inside = safe.startswith(WEB_DIR + os.sep)
        if not inside or not os.path.isfile(safe):
            self._send(404, json.dumps({"error": "not found"}))
            return

        with open(safe, "rb") as handle:
            body = handle.read()
        if name == "index.html":
            body = body.replace(b"__TOKEN__", self.token.encode())
        ctype = mimetypes.guess_type(safe)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype += "; charset=utf-8"
        self._send(200, body, ctype)

    def do_POST(self):
        # ТЕЛО ЗАПРОСА ВЫЧИТЫВАЕТСЯ ВСЕГДА — даже когда ответом будет отказ.
        #
        # Иначе соединение закрывается с непрочитанными байтами, Windows
        # отвечает на это сбросом (RST), и клиент получает
        # ConnectionAbortedError [WinError 10053] ВМЕСТО нашего 403. То есть
        # причину отказа не видит никто: ни человек, ни проверка.
        #
        # Замерено 11.09.2026: тест про отказ без токена падал именно так —
        # не «сервер не отказал», а «отказ не доехал».
        try:
            length = int(self.headers.get("Content-Length") or 0)
            сырое = self.rfile.read(length) if length else b""
        except Exception:
            сырое = b""

        if not self._authorised():
            self._send(403, json.dumps({"error": "forbidden"}))
            return
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            self._send(404, json.dumps({"error": "not found"}))
            return

        # Отметка «окно живо». Ставится на запросах, которые идут и так,
        # поэтому не стоит ни одного лишнего обращения. По ней сторож
        # отличает работу от тишины — а тишина и есть зависание.
        try:
            self.api.last_seen_at = time.time()
            # Считаем ЧИСЛО запросов, а не только время последнего: окно,
            # подавленное браузером, продолжает спрашивать — просто вчетверо
            # реже. Тишины не наступает, и сторож по паузе такое пропускает.
            self.api.request_count += 1
        except Exception:
            pass

        method = path[len("/api/"):]
        handler = getattr(self.api, method, None)
        if handler is None or method.startswith("_") or not callable(handler):
            self._send(404, json.dumps({"error": "unknown method"}))
            return

        try:
            payload = json.loads(сырое or b"{}")
        except Exception:
            payload = {}

        try:
            result = handler(payload)
        except Exception as exc:
            # Раньше здесь ошибка ИСЧЕЗАЛА: окно получало 500, показывало
            # пустоту и выглядело зависшим, а причина не попадала никуда —
            # ни в файл, ни на экран. Разбирать такой сбой было нечем.
            log_crash("мост", "Обработчик метода не выполнился",
                      exc, context="метод %s" % method)
            self._send(500, json.dumps({"error": f"{type(exc).__name__}: {exc}"}))
            return
        self._send(200, json.dumps(result, ensure_ascii=False, default=str))


def start_api_server(api):
    """Поднимает мост на свободном порту петлевого адреса."""
    token = secrets.token_urlsafe(24)
    handler = type("Handler", (_Handler,), {"api": api, "token": token})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1], token


def _verdict_age(stamp):
    """Сколько дней вердикту и пора ли перепроверять.

    Возвращает {"days": n, "stale": bool} либо пустой словарь, если даты нет.
    Порог берётся из настроек: у базы, которую рассылают раз в квартал, и у
    базы, которую жгут еженедельно, «свежесть» разная.
    """
    import datetime

    text = str(stamp or "").strip()
    if not text:
        return {}
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%d"):
        try:
            when = datetime.datetime.strptime(text, fmt)
            break
        except ValueError:
            when = None
    if when is None:
        return {}

    # Время берётся без привязки к зоне: метки в базе пишутся в UTC тем же
    # способом, и сравнивать их проще всего между собой.
    days = (datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None) - when).days
    if days < 0:
        days = 0
    try:
        from core.settings import get
        limit = int(get("verdict_fresh_days", 30) or 30)
    except Exception:
        limit = 30
    return {"days": days, "stale": days > max(1, limit)}


def _gravatar_hash(email):
    """Хеш адреса в том виде, в каком его ждёт gravatar.com."""
    try:
        return hashlib.md5(str(email).strip().lower().encode("utf-8")).hexdigest()
    except Exception:
        return ""


def _storage_path():
    """Своё хранилище WebView2 рядом с настройками пользователя.

    Без него pywebview включает приватный режим и отдаёт WebView2 путь во
    временной папке, которую Windows умеет чистить под ногами у работающего
    процесса — это зависшее окно и осиротевшие msedgewebview2.
    """
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    path = os.path.join(base, "EmailValidatorPro", "webview")
    os.makedirs(path, exist_ok=True)
    return path


class WindowWatchdog:
    """Замечает, что окно ЗАМОЛЧАЛО, и записывает это в журнал сбоев.

    Зачем нужен отдельно от перехватчиков ошибок. Зависание — это не
    исключение: окно не падает, а перестаёт отвечать, и `window.onerror` в
    нём не срабатывает никогда. Владелец видит замерший интерфейс, а в
    журнале при этом пусто, потому что ловить было нечего.

    Живое окно спрашивает состояние четыре раза в секунду — этого хватает,
    чтобы отличить работу от тишины, и не нужно ни одного лишнего запроса:
    отметка ставится на тех, что и так идут.

    Записывается ОДИН раз на период тишины: окно, замолчавшее на час, должно
    дать одну запись, а не четырнадцать тысяч.
    """

    # Ниже скольких запросов в секунду окно считается подавленным.
    #
    # Живое окно спрашивает шесть раз в секунду: четыре тика валидатора и два
    # тика сбора. Браузер, признавший страницу невидимой, зажимает таймеры и
    # даёт один-два запроса в секунду — замерено дважды: 1.1/с в одном опыте
    # и ровно 2.0/с в другом.
    #
    # Порог 3.0, а не 2.0. Двойка стояла ВПРИТЫК к измеренному значению:
    # живой замер дал 2.0 при пороге 2.0, и срабатывание оказалось делом
    # округления. Тройка разводит случаи с запасом в обе стороны — подавленное
    # окно не даёт больше двух, а занятая машина не роняет живое ниже трёх.
    SLOW_RATE = 3.0

    def __init__(self, api, silence_seconds=20.0, check_every=5.0):
        self.api = api
        self.silence = float(silence_seconds)
        self.check_every = float(check_every)
        self._stop = threading.Event()
        self._reported = False
        self._slow_reported = False
        self._last_count = 0
        self._last_rate_at = 0.0

    def check_once(self, now=None):
        """Одна проверка. Возвращает True, если тишина только что записана.

        Отдельным методом, а не только внутри цикла: иначе проверить сторожа
        можно было бы лишь ожиданием в двадцать секунд.
        """
        now = time.time() if now is None else now
        seen = getattr(self.api, "last_seen_at", 0.0) or 0.0
        if not seen:
            return False                      # окно ещё ни разу не спрашивало
        quiet = now - seen
        if quiet < self.silence:
            self._reported = False            # окно ожило — сторож взводится
            return False
        if self._reported:
            return False
        self._reported = True
        log_crash("окно",
                  "Окно перестало отвечать: за %.0f секунд ни одного запроса. "
                  "Питон при этом жив — значит замер сам интерфейс."
                  % quiet,
                  context="последний раз окно отвечало в %s"
                          % time.strftime("%H:%M:%S", time.localtime(seen)))
        self.api._on_log(
            "[DEAD] Окно молчит %.0f с. Запись в %s" % (quiet, crash_log_path()),
            "dead")
        return True

    def check_rate(self, now=None):
        """Не подавлено ли окно. Возвращает True, если подавление записано.

        Отдельно от проверки тишины, потому что случай ДРУГОЙ: подавленное
        окно не молчит, оно отвечает — просто вшестеро реже. Тишины не
        наступает никогда, и проверка по паузе такое пропускает полностью.

        Именно этот случай владелец показывал четыре раза подряд: интерфейс
        замирает, питон жив, ошибок нет, журнал пуст.
        """
        now = time.time() if now is None else now
        count = int(getattr(self.api, "request_count", 0) or 0)
        if not self._last_rate_at:
            self._last_rate_at, self._last_count = now, count
            return False

        elapsed = now - self._last_rate_at
        if elapsed < self.check_every:
            return False
        rate = (count - self._last_count) / elapsed
        self._last_rate_at, self._last_count = now, count

        # Ноль запросов — это тишина, у неё своя проверка. Здесь нас
        # интересует именно «отвечает, но еле-еле».
        if rate <= 0 or rate >= self.SLOW_RATE:
            self._slow_reported = False
            return False
        if self._slow_reported:
            return False
        self._slow_reported = True
        log_crash("окно",
                  "Окно отвечает намного реже обычного: %.1f запроса в "
                  "секунду вместо шести. Так выглядит страница, которую "
                  "браузер счёл невидимой: таймеры зажаты, отрисовка "
                  "остановлена. Программа при этом исправна." % rate,
                  context="темп ниже порога %.1f/с" % self.SLOW_RATE)
        self.api._on_log(
            "[DEAD] Окно подавлено браузером (%.1f запр/с вместо 6): картинка "
            "не обновляется, хотя программа работает. Запись в %s"
            % (rate, crash_log_path()), "dead")
        return True

    def start(self):
        def loop():
            while not self._stop.wait(self.check_every):
                try:
                    self.check_once()
                    self.check_rate()
                except Exception:
                    # Сторож не имеет права уронить программу: он про разбор
                    # аварий, а не про проверку почты.
                    pass

        threading.Thread(target=loop, daemon=True, name="сторож-окна").start()
        return self

    def stop(self):
        self._stop.set()


def _announce_past_crashes(api, within_hours=24):
    """Говорит в лог окна, что за последние сутки был сбой, и где он записан.

    Отдельной функцией, а не строкой внутри run(): её надо проверять тестом,
    а run() открывает настоящее окно и в тесте не вызывается.

    Возвращает число объявленных записей — по нему тест отличает «сказали»
    от «промолчали».
    """
    try:
        found = recent_crashes(within_hours=within_hours)
    except Exception:
        return 0
    if not found:
        return 0
    # Одна строка и метка INFO, а не красное полотно.
    #
    # Первая версия кричала «[DEAD]» и перечисляла каждую запись отдельной
    # красной строкой. У владельца это дало три красные строки без единого
    # слова содержания сразу после запуска — на месте, где ничего не
    # сломалось прямо сейчас. Сообщение о ПРОШЛОЙ аварии не должно выглядеть
    # как авария текущая, а перечислять нечитаемое незачем.
    api._on_log(
        "[INFO] Прошлый запуск оставил записи о сбоях: %d за сутки. "
        "Смотреть здесь: %s" % (len(found), crash_log_path()),
        "info")
    return len(found)


# Ключи, которыми WebView2 просят не душить «фоновую» страницу.
#
# Зачем. Замерено на живой странице: когда браузер считает её невидимой, он
# зажимает setInterval до ОДНОГО раза в секунду (вместо четырёх) и полностью
# останавливает requestAnimationFrame — то есть перестаёт перерисовывать
# окно. Клики при этом доходят и обработчики срабатывают, но картинка не
# меняется, и со стороны это неотличимо от «зависло намертво».
#
# Ни перехватчик ошибок, ни сторож тишины такого не ловят: ошибки нет, а
# запросы идут — просто вчетверо реже.
#
# WebView2 включает это подавление, когда считает окно перекрытым или
# свёрнутым, и ошибается в этом известным образом. Три ключа ниже выключают
# ровно три части этого поведения и ничего больше.
WEBVIEW_NO_THROTTLE = (
    "--disable-background-timer-throttling "
    "--disable-renderer-backgrounding "
    "--disable-backgrounding-occluded-windows"
)


def apply_no_throttle(environ=None):
    """Дописывает ключи в WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS.

    Дописывает, а не перезаписывает: владелец мог задать свои ключи, и
    затирать их значит молча отменять его настройку. Уже добавленное второй
    раз не добавляется — иначе при каждом запуске строка росла бы.

    Отдельной функцией, потому что run() открывает настоящее окно и в тесте
    не вызывается, а проверить это надо.
    """
    environ = os.environ if environ is None else environ
    key = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"
    current = environ.get(key, "")
    missing = [flag for flag in WEBVIEW_NO_THROTTLE.split()
               if flag not in current]
    if not missing:
        return current
    environ[key] = (current + " " + " ".join(missing)).strip()
    return environ[key]


def run(selftest_close=None):
    """Поднимает мост и открывает окно.

    selftest_close — секунды, через которые окно закроется само. Нужен
    проверке про осиротевшие процессы движка: она обязана пройти настоящий
    путь вместе с `finally`, а снятие процесса по таймауту до `finally` не
    доходит — то есть проверяло бы ровно не то, что чинили.
    """
    # ДО импорта webview: WebView2 читает переменную окружения в момент
    # создания движка, и выставленная позже она уже ни на что не влияет.
    apply_no_throttle()
    # Туда же — уровень логов Chromium. Он пишет в stderr сам, мимо logging
    # Python, и через фильтр его не поймать.
    quiet_chromium()

    import webview

    api = ValidatorApi()
    _server, port, token = start_api_server(api)

    # Поставляемые списки кладутся в пишущуюся папку до первого обращения к
    # ним: иначе первый же запуск установленной копии не найдёт своих данных.
    seed_data()

    window = webview.create_window(
        f"{APP_NAME} {app_version()}",
        f"http://127.0.0.1:{port}/?token={token}",
        width=1440, height=900, min_size=(900, 620),
        background_color="#0A0E14",
    )
    api.window = window

    # Красная стена при старте — это одно сообщение pywebview с трассировкой
    # .NET на девять строк. Показываем вместо неё одну строку по-русски и
    # уводим её в лог ОКНА, где владелец её и прочтёт. Всё прочее pywebview
    # печатает как раньше: фильтр трогает ровно это сообщение.
    install_webview_noise_filter(
        on_hint=lambda текст: api._on_log("[WARN] " + текст, "trap"))

    api._on_log("[INFO] Валидатор готов к работе.", "info")
    api._on_log("[INFO] Выберите базу адресов и список прокси.", "info")

    # Про вчерашнюю аварию владелец должен УЗНАТЬ, а не наткнуться на файл
    # случайно. Раньше сбой не оставлял следа вовсе, и разбирать его
    # приходилось по журналу событий Windows — который про поломку ВНУТРИ
    # процесса не знает ничего.
    _announce_past_crashes(api)
    WindowWatchdog(api).start()

    # Кого не трогать при уборке: всё, что уже крутилось до нас. Снимок
    # обязан быть СЕЙЧАС — после старта наши и чужие процессы неразличимы.
    reaper = WebViewReaper()
    reaper.snapshot()

    if selftest_close:
        # Закрываем окно из отдельного потока: webview.start() владеет
        # главным, и попросить его изнутри неоткуда.
        def _закрыть_потом():
            time.sleep(float(selftest_close))
            try:
                window.destroy()
            except Exception:
                pass

        threading.Thread(target=_закрыть_потом, daemon=True).start()

    # Иконку ставим после старта: HWND появляется только когда движок
    # WebView2 создаст окно, и до этого ставить её просто некуда.
    from core.winicon import apply_when_shown
    apply_when_shown(resource_path("assets", "MailFact.ico"))

    try:
        webview.start(storage_path=_storage_path(), private_mode=False)
    finally:
        # Не убрав за собой, следующий запуск получит «ресурс занят» и ту
        # самую красную стену: папку профиля держат наши же сироты. Замерено
        # запуском: шесть штук после закрытия окна.
        reaper.reap()


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ROOT)
    run()
