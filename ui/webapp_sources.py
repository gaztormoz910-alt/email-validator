# -*- coding: utf-8 -*-
import os
import threading
from core import input_guard
from core.encoding import open_text

__all__ = ["SourcesMixin", "_тип_диалога"]


def _тип_диалога(имя):
    import webview

    перечисление = getattr(webview, "FileDialog", None)
    if перечисление is not None and hasattr(перечисление, имя):
        return getattr(перечисление, имя)
    return getattr(webview, {"OPEN": "OPEN_DIALOG", "SAVE": "SAVE_DIALOG",
                             "FOLDER": "FOLDER_DIALOG"}[имя])


class SourcesMixin:
    def _pick_files(self, title):
        if self.window is None:
            return []
        chosen = self.window.create_file_dialog(
            _тип_диалога("OPEN"), allow_multiple=True,
            file_types=("Списки (*.txt;*.csv)", "Все файлы (*.*)"))
        return list(chosen or [])
    def choose(self, payload):
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
        try:
            if os.path.getsize(path) > self.INLINE_LIMIT:
                return None
            with open_text(path) as handle:
                return handle.read()
        except Exception as беда:
            self._on_log("[INFO] %s в поле ввода не показан (%s: %s), "
                         "но в проверку пойдёт целиком."
                         % (os.path.basename(path), type(беда).__name__, беда),
                         "info")
            return None
    def paste(self, payload):
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
                if self._count_jobs.get(kind) == job:
                    self._line_counts[kind] = int(total)
                    self._file_stamps[kind] = [
                        (item.get("path") or "",
                         self._stat_of(item.get("path"), "st_size"),
                         self._stat_of(item.get("path"), "st_mtime"))
                        for item in snapshot if item.get("type") == "file"]

        threading.Thread(target=work, daemon=True).start()
    def _rescan_base(self, kind):
        if kind != "emails":
            return

        начать = getattr(self, "_base_feeder", None)
        приёмник = начать() if callable(начать) else None

        snapshot = list(self._sources.get(kind) or [])
        with self._scan_lock:
            self._scan_job += 1
            job = self._scan_job
        if not snapshot:
            if приёмник is not None:
                приёмник.finish()
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
                scan = scan_base_providers(
                    snapshot, breathe_every=BASE_SCAN_BREATHE, should_stop=устарел,
                    on_row=приёмник.add if приёмник is not None else None)
            except Exception as e:
                if приёмник is not None:
                    приёмник.fail(e)
                self._on_log("[DEAD] Скан состава базы не удался: %s: %s"
                             % (type(e).__name__, e), "dead")
                return
            if приёмник is not None:
                приёмник.finish()
            if scan.get("stopped") or устарел():
                return
            for line in format_base_scan(scan):
                self._on_log(line, "info")
            self._on_log("[INFO] Состав посчитан по ВСЕЙ базе (%d адресов) "
                         "за %.1f с." % (scan.get("total", 0),
                                         _time.monotonic() - начало), "info")

        threading.Thread(target=work, daemon=True,
                         name="скан-состава-базы").start()
    def _files_changed_on_disk(self, kind):
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
    FIELD_LIMIT = 64 * 1024

    def sources(self, payload=None):
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

            editable = (all(s["type"] == "text" for s in sources)
                        and sum(len(s.get("content", "")) for s in sources)
                        <= self.FIELD_LIMIT)
            text ="\n".join(s.get("content", "") for s in sources) if editable else ""
            with self._count_lock:
                lines = self._line_counts.get(kind, 0)
            return {"count": len(sources), "title": title,
                    "detail": ", ".join(names[:3]),
                    "text": text, "editable": editable, "lines": lines}

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
            "direct": direct,
            "hint": ("Не хватает: " + " и ".join(missing) if missing
                     else ("Всё готово — можно запускать" if not direct
                           else "Прокси нет: проверка пойдёт с твоего IP. "
                                "Gmail и Яндекс ответят, Yahoo/AOL/Outlook/iCloud — нет")),
            "parserReady": bool(self._sources["dorks"]),
            "parserHint": ("Всё готово — можно собирать"
                           if self._sources["dorks"] else "Не хватает: дорки"),
        }
    def choose_suppression(self, payload=None):
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
