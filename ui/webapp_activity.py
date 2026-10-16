# -*- coding: utf-8 -*-
"""Мост журнала активности: полоса «работает / ждёт / встал» для окна.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. ui/webapp.py стоит у потолка размера модуля
(tools/verify_module_sizes.py), а у темы «жив ли движок» свой смысл и свои
части: снимок проверки, снимок сбора адресов, наблюдение за колбэками сбора
и его пульс. Здесь они вместе; в webapp.py — по одной строке подключения.

Сами слова («Работает», «Похоже на зависание», …) рождаются не здесь, а в
core/activity.py — тот же текст пишет пульс в журнал и CLI в консоль.
"""
from core.activity import ActivityMonitor, Pulse, payload

__all__ = ["ActivityBridgeMixin"]


class ActivityBridgeMixin:
    # ─────────────────────────── проверка почт ──────────────────────────
    def _validator_activity(self):
        """Снимок движка проверки для полосы состояния. Не бросает."""
        pipeline = getattr(self, "pipeline", None)
        try:
            snap = pipeline.activity.snapshot(
                paused=bool(getattr(pipeline, "is_paused", False)),
                alive=pipeline._worker_alive())
            return payload(snap)
        except Exception as exc:
            # Полоса — не условие работы окна: сбой снимка не должен ронять
            # ответ state(), иначе вместе с ней пропали бы счётчики и журнал.
            return {"level": "idle", "title": "Состояние недоступно",
                    "detail": "Не удалось снять состояние движка: %s" % exc,
                    "trail": []}

    # ─────────────────────────── сбор адресов ───────────────────────────
    @property
    def parser_activity(self):
        mon = self.__dict__.get("_parser_activity")
        if mon is None:
            mon = ActivityMonitor(kind="parser", emit=self._parser_stage_line)
            self.__dict__["_parser_activity"] = mon
        return mon

    def _parser_stage_line(self, text, tag):
        # Строка этапа — настоящее событие, в отличие от пульса.
        self.parser_activity.beat()
        self._parser_log(text, tag)

    def _parser_activity_payload(self):
        pipeline = getattr(self, "parser", None)
        alive = None
        paused = False
        # Пока новый сбор запускается (читаются прокси, создаётся конвейер),
        # self.parser — ещё ПРОШЛЫЙ, завершённый поток. Спросить живость у
        # него — получить «Движок остановился… Это сбой» на каждом повторном
        # сборе. Живость нового пока неизвестна, и это честно.
        if self.__dict__.get("_parser_launching"):
            pipeline = None
        if pipeline is not None:
            try:
                alive = bool(pipeline.is_alive())
                paused = bool(pipeline._pause_event.is_set())
            except Exception:
                pass
        try:
            return payload(self.parser_activity.snapshot(paused=paused, alive=alive))
        except Exception as exc:
            return {"level": "idle", "title": "Состояние недоступно",
                    "detail": "Не удалось снять состояние сбора: %s" % exc,
                    "trail": []}

    def _observed_parser_callbacks(self):
        """Колбэки сбора, каждый вызов которых — событие для монитора.

        Обёртки, а не правка ParserPipeline: у него свои сигнатуры
        (on_log с одним аргументом, прогресс с подписью этапа), и разбирать
        их удобнее здесь, рядом с тем, что окно из них показывает.
        """
        mon = self.parser_activity

        def on_log(message, *args):
            mon.beat()
            self._parser_log(message, *args)

        def on_progress(current, total, pct=0, label="Парсинг"):
            # Пока идёт проверка прокси, прогресс — про прокси, и в счёт
            # дорков его класть нельзя.
            if label == "Проверка прокси":
                mon.aux(current, total)
            else:
                mon.beat()
            self._parser_progress_cb(current, total, pct, label)

        def on_stats(dorks_tot, dorks_done, pages, snippets, emails):
            mon.progress(dorks_done, dorks_tot)
            mon.set_found(emails)
            self._parser_stats_cb(dorks_tot, dorks_done, pages, snippets, emails)

        def on_result(email, dork, *args, **kwargs):
            mon.beat()
            self._parser_result_cb(email, dork, *args, **kwargs)

        return {"on_log": on_log, "on_progress": on_progress,
                "on_stats_update": on_stats, "on_result_found": on_result}

    def _start_parser_pulse(self, pipeline):
        """Пульс сбора — пока жив его поток. Пишет СЫРЫМ журналом."""
        pulse = Pulse(self.parser_activity,
                      emit=lambda text, tag: self._parser_log(text, tag),
                      paused=lambda: pipeline._pause_event.is_set(),
                      alive=pipeline.is_alive)
        pulse.start()
        self.__dict__["_parser_pulse"] = pulse
        return pulse

    def _finish_parser_activity(self, aborted):
        """Итог сбора. «Прервано» бывает двух видов: вы нажали «Стоп» или
        работать было нечем (Tor не поднялся, ни один прокси не ожил)."""
        pipeline = getattr(self, "parser", None)
        stopped = False
        failed = ""
        try:
            stopped = pipeline is not None and pipeline._stop_event.is_set()
            failed = getattr(pipeline, "failed_reason", "") or ""
        except Exception:
            pass
        # Провал проверяется первым: оборванное чтение файла дорков раньше
        # выглядело как «Готово», а исключение — как «не смог начаться».
        if failed:
            outcome, note = "failed", failed
        elif not aborted:
            outcome, note = "done", ""
        elif stopped:
            outcome, note = "stopped", ""
        else:
            outcome, note = "blocked", "сбор не смог начаться — причина строкой выше"
        self.parser_activity.finish(outcome, note)
        pulse = self.__dict__.get("_parser_pulse")
        if pulse is not None:
            pulse.stop()
