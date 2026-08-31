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
from ui.result_store import normalize_filters
from core.encoding import open_text
from core.baseops import csv_row, export_encoding

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")

PAGE_SIZE = 100


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
        # Сколько строк в каждом наборе источников. None означает «ещё считаю»:
        # на гигабайтном файле счёт занимает десятки секунд, и делать его в
        # потоке, который обслуживает страницу, нельзя.
        self._line_counts = {"emails": 0, "proxies": 0, "dorks": 0, "pproxy": 0}
        self._count_jobs = {}
        self._count_lock = threading.Lock()
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

    def _bucket(self, kind):
        """Ведро источников по имени. Незнакомое имя — не повод молча
        свалить список в прокси, как было раньше."""
        try:
            return self._sources[kind]
        except KeyError:
            raise ValueError("неизвестный вид источника: %r" % (kind,))

    # ---------------------------------------------------- от движка ----
    def _on_log(self, text, tag="info"):
        with self._lock:
            self._log_seq += 1
            line = {"text": str(text), "tag": tag, "n": self._log_seq}
            self._pending.append(line)
            self._history.append(line)
            if len(self._history) > self._history_cap:
                del self._history[:len(self._history) - self._history_cap]

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
        import webview
        if self.window is None:
            return []
        chosen = self.window.create_file_dialog(
            webview.OPEN_DIALOG, allow_multiple=True,
            file_types=("Списки (*.txt;*.csv)", "Все файлы (*.*)"))
        return list(chosen or [])

    def choose(self, payload):
        """Выбор файлов для базы или для прокси."""
        kind = payload.get("kind")
        target = self._bucket(kind)
        if self._busy():
            return dict(self.sources(), error=self._BUSY_REFUSAL)

        paths = self._pick_files(kind)
        expected = self._EXPECTED_KIND.get(kind)
        accepted, refused, oversized = [], [], []
        for path in paths:
            # Проверяется КАЖДЫЙ файл, а не первый: владелец выбирает их
            # пачкой, и прокси среди пяти баз иначе проедут незамеченными.
            verdict = input_guard.check_file(path, expected) if expected else {"ok": True}
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
        except OSError:
            return None

    def paste(self, payload):
        """Список, вставленный текстом вместо файла."""
        kind = payload.get("kind")
        bucket = self._bucket(kind)
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
        return self.sources()

    def clear(self, payload):
        bucket = self._bucket(payload.get("kind"))
        if self._busy():
            return dict(self.sources(), error=self._BUSY_REFUSAL)
        bucket.clear()
        self._recount(payload.get("kind"))
        return self.sources()

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

        threading.Thread(target=work, daemon=True).start()

    def sources(self, payload=None):
        """Что сейчас подключено. Считается лениво — файл не читается."""
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

        missing = []
        if not self._sources["emails"]:
            missing.append("адреса")
        if not self._sources["proxies"]:
            missing.append("прокси")
        return {
            "emails": describe(self._sources["emails"], "emails"),
            "proxies": describe(self._sources["proxies"], "proxies"),
            "dorks": describe(self._sources["dorks"], "dorks"),
            "pproxy": describe(self._sources["pproxy"], "pproxy"),
            "ready": not missing,
            "hint": ("Всё готово — можно запускать" if not missing
                     else "Не хватает: " + " и ".join(missing)),
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
        if not self.email_sources or not self.proxy_sources:
            return {"ok": False, "error": "Сначала выберите адреса и прокси"}
        self._starting = True

        from core.parser.ml_predictor import set_country_mode
        set_country_mode(payload.get("country") or "coverage")

        self.store.clear()
        self._progress = (0, 0)
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
            enable_ai=bool(payload.get("ai", True)),
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
            enable_osint=bool(payload.get("osint", True)),
            use_cache=bool(payload.get("cache", True)),
            resume=False)

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
        picked = self._filters(payload)
        number = max(1, int(payload.get("page") or 1))

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
                "provider": data.get("provider_name", ""),
                "name": data.get("name", ""),
                "gender": data.get("gender", ""),
                "country": data.get("country", ""),
                "when": data.get("validated_at", ""),
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
        import webview
        if self.window is None:
            return {"ok": False, "error": "Окно недоступно"}
        target = self.window.create_file_dialog(
            webview.SAVE_DIALOG, save_filename="valid_emails.csv")
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
                writer.writerow(["Email", "Status", "Reason", "MX", "Name",
                                 "FirstName", "LastName", "Gender", "Country",
                                 "Score", "Provider", "ValidatedAt"])
                for row in rows:
                    data = row.get("data") or {}
                    # csv_row, а не голый список: база собрана со страниц в
                    # интернете, и ячейка, начинающаяся со знака равенства,
                    # в Excel не показывается, а выполняется.
                    writer.writerow(csv_row([
                        row["email"], row["status"], row["reason"], row["mx"],
                        data.get("name", ""), data.get("first_name", ""),
                        data.get("last_name", ""), data.get("gender", ""),
                        data.get("country", ""), data.get("engagement_score", ""),
                        data.get("provider_name", ""), data.get("validated_at", ""),
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
    # Тот же конвейер, что и в прежнем окне (core/parser_pipeline.py), только
    # обратные вызовы складывают всё в очереди, а страница забирает их
    # опросом. Раньше кнопка «Сбор адресов» в этом окне просто советовала
    # запустить программу заново с флагом --classic.

    PARSER_ENGINES = ["DuckDuckGo Lite", "AOL (Tor)", "Yahoo (Tor)",
                      "AOL (Proxies)", "Yahoo (Proxies)"]

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

    def parser_copy(self, payload=None):
        limit = 200_000
        with self._lock:
            rows = self._parser_rows[:limit]
        return {"text": chr(10).join(e for e, _ in rows), "count": len(rows),
                "capped": len(rows) >= limit}

    def parser_export(self, payload=None):
        """Сохранение найденного. Запись идёт в фоне: список бывает большим."""
        import webview
        if self.window is None:
            return {"ok": False, "error": "Окно недоступно"}
        with self._lock:
            rows = list(self._parser_rows)
        if not rows:
            return {"ok": False, "error": "Пока нечего сохранять"}

        path = self.window.create_file_dialog(
            webview.SAVE_DIALOG, save_filename="parsed_emails.txt",
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

        import webview
        if self.window is None:
            return {"ok": False, "error": "Окно недоступно"}
        chosen = self.window.create_file_dialog(webview.FOLDER_DIALOG)
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

    def log_message(self, *args):          # тишина в консоли
        pass

    def _authorised(self):
        header = self.headers.get("X-Token")
        query = parse_qs(urlparse(self.path).query)
        given = header or (query.get("token") or [""])[0]
        return secrets.compare_digest(given or "", self.token)

    def _send(self, code, body, ctype="application/json; charset=utf-8"):
        raw = body if isinstance(body, bytes) else str(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(raw)

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
        if not self._authorised():
            self._send(403, json.dumps({"error": "forbidden"}))
            return
        path = urlparse(self.path).path
        if not path.startswith("/api/"):
            self._send(404, json.dumps({"error": "not found"}))
            return

        method = path[len("/api/"):]
        handler = getattr(self.api, method, None)
        if handler is None or method.startswith("_") or not callable(handler):
            self._send(404, json.dumps({"error": "unknown method"}))
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}") if length else {}
        except Exception:
            payload = {}

        try:
            result = handler(payload)
        except Exception as exc:
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


def run():
    """Поднимает мост и открывает окно."""
    import webview

    api = ValidatorApi()
    _server, port, token = start_api_server(api)

    window = webview.create_window(
        "Email Validator Pro",
        f"http://127.0.0.1:{port}/?token={token}",
        width=1440, height=900, min_size=(900, 620),
        background_color="#0A0E14",
    )
    api.window = window
    api._on_log("[INFO] Валидатор готов к работе.", "info")
    api._on_log("[INFO] Выберите базу адресов и список прокси.", "info")

    webview.start(storage_path=_storage_path(), private_mode=False)


if __name__ == "__main__":
    import sys
    sys.path.insert(0, ROOT)
    run()
