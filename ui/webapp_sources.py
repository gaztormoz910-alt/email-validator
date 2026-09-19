# -*- coding: utf-8 -*-
"""Источники: выбор файлов, вставка текста, пересчёт и пересканирование базы.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. Всё, что происходит ДО нажатия «Старт»: какие файлы
взяты, сколько в них строк, не изменились ли они на диске, что вставили
руками. Это отдельная тема и отдельная половина жалоб владельца — здесь же
живут пересчёт строк и разбор того, что именно положили в поле ввода.

ПОЧЕМУ ПРИМЕСЬ. Состояние окна общее и заводится в `ValidatorApi.__init__`.
Примесь работает с тем же объектом: файл поделён, поведение нет.
"""
import os
import threading
from core import input_guard
from core.encoding import open_text

__all__ = ["SourcesMixin", "_тип_диалога"]


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


class SourcesMixin:
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
