# -*- coding: utf-8 -*-
"""«Стоп» в окне: бросить прогон и вернуть окно к первому открытию.

ЗАЧЕМ ОТДЕЛЬНЫЙ ФАЙЛ. ui/webapp.py стоит у потолка размера модуля
(tools/verify_module_sizes.py), а у сброса свой смысл: что именно окно
показывает «как при первом открытии» и чего сброс НЕ трогает (файлы на
диске). Обе кнопки «Стоп» — проверки и сбора адресов — сбрасывают окно
одинаково; идущую работу второго экрана сброс не трогает.
"""

import threading

__all__ = ["ResetMixin"]


class ResetMixin:
    def _quiet_after_stop(self, handler):
        """Колбэк движка, который молчит, пока окно сброшено «Стопом».

        Колбэки общие на весь процесс, а не на прогон: без отсева брошенный
        прогон досылал бы в чистое окно результаты, пульс и итоги.

        Проверка и сам обработчик — под одним замком со «Стопом»
        (_mute_engine): поток, который проверку прошёл ДО «Стопа», иначе
        дописывал строку в таблицу и журнал уже ПОСЛЕ сброса окна (рецензия
        08.11.2026). Замок повторно входимый: обработчик может звать другой.
        """
        gate = self._view_gate()

        def wrapped(*args, **kwargs):
            with gate:
                if self._discarding:
                    return False
                return handler(*args, **kwargs)
        return wrapped

    def _view_gate(self):
        """Замок «событие движка пишется в окно / окно сбрасывается»."""
        return self.__dict__.setdefault("_view_gate_lock", threading.RLock())

    def _mute_engine(self):
        """С этой строки события движка в окно не попадают.

        Берётся тот же замок, что держит обработчик события: «Стоп» ждёт
        обработчики, которые уже пишут, и только потом чистит окно.
        """
        with self._view_gate():
            self._discarding = True

    def _claim_start(self, payload):
        """Проверки «Начать» и взведение флага «запускаюсь» — одним шагом.

        Возвращает ответ-отказ или None. Мост многопоточный, и между проверкой
        «не идёт ли прогон» и взведением флага раньше стояла очистка таблицы:
        после прогона на миллион строк она длится 0,4 с, и второй щелчок за
        это время проходил проверку — запускались два движка (рецензия
        08.11.2026). Под замком второй запрос ждёт первого и видит флаг.

        Флаг взводится ПОСЛЕ проверок источников: отказ «сначала выберите
        адреса» не должен оставлять его взведённым — иначе следующий щелчок
        получал бы «проверка уже идёт» до перезапуска программы.
        """
        with self.__dict__.setdefault("_start_gate_lock", threading.Lock()):
            if self._busy() or self._starting:
                return {"ok": False, "error": self._start_refusal()}
            if not self.email_sources:
                return {"ok": False, "error": "Сначала выберите адреса"}
            if not self.proxy_sources and not payload.get("allowDirect"):
                # Молча ходить напрямую нельзя: это раскрывает домашний IP
                # владельца почтовым серверам, и согласие на такое должно быть
                # осознанным, а не побочным следствием пустого поля.
                return {"ok": False, "direct": True,
                        "error": "Прокси не заданы. Проверка пойдёт с твоего "
                                 "домашнего IP — подтверди, если это осознанно."}
            if not self._start_clears_the_table():
                return {"ok": False, "error": "Идёт выгрузка таблицы — дождитесь её конца."}
            self._starting = True
            return None

    def _start_refusal(self):
        """Почему «Начать» сейчас отказывает — честно, а не «уже идёт»."""
        if self._starting and self._discarding:
            # Окно уже чистое, а движок ещё бросает прошлый прогон. Новый
            # поверх него запускать нельзя: атрибуты конвейера общие, и
            # старые потоки писали бы в новую таблицу.
            return self._ENGINE_FREEING
        return "Проверка уже идёт"

    def _run_flags(self):
        """(идёт ли прогон для окна, бежит ли полоса проверки прокси).

        Бегущая полоса — ТОЛЬКО пока идёт этап проверки прокси. Раньше
        признак считался по двум счётчикам («прокси видели, а адресов ещё
        нет»), не связанным ни с прогоном, ни с этапом, и не обнулялся
        нигде: после «Стопа» на подготовке или блокировки («ни один прокси
        не ожил») полоса бежала до закрытия программы.
        """
        running = bool(self.pipeline.is_running) and not self._discarding
        stage = getattr(getattr(self.pipeline, "activity", None), "stage_key", "")
        return running, running and stage == "proxies"

    _ENGINE_FREEING = ("Движок ещё завершает остановленную проверку — это займёт "
                       "несколько секунд. Нажмите «Начать проверку» чуть позже.")

    #: Строки журнала окна при первом открытии (run() ниже пишет их же).
    START_LINES = (("[INFO] Валидатор готов к работе.", "info"),
                   ("[INFO] Выберите базу адресов и список прокси.", "info"))

    def stop(self, payload=None):
        """«Стоп»: бросить прогон и вернуть окно к первому открытию.

        Так попросил владелец 06.11.2026: после «Стопа» сбрасывается вообще
        всё, как если бы программу только что открыли и ничего не загружали,
        и полоса прогресса не бежит. Раньше «Стоп» только отдавал команду
        движку: окно продолжало показывать досылаемые результаты, «Остана-
        вливаю» минутами, а полоса после «Стопа» на подготовке бежала до
        закрытия программы.

        Что НЕ трогается: кэш вердиктов, долгая память, выгрузки и входные
        файлы владельца. Отметки «сделано» в журнале продолжения этой базы
        брошенный прогон стирает сразу (core/runstate.py, freeze): окно уже
        не показывает выданное до «Стопа», и продолжение пропустило бы его
        навсегда — следующий запуск той же базы выдаст всё, а готовые
        вердикты возьмёт из кэша без сети (рецензии 07 и 08.11.2026).
        """
        # Сначала глушим окно, потом бросаем прогон: всё, что движок пришлёт
        # после этой строки, — события брошенного прогона.
        self._mute_engine()
        self.pipeline.stop(abort=True)
        self._reset_validator_view()
        if not self._parser_running():
            self._reset_parser_view()
        return {"ok": True, "state": self._state, "seq": self._log_seq,
                "engineBusy": bool(self._starting)}

    def _parser_running(self):
        parser = getattr(self, "parser", None)
        if self.__dict__.get("_parser_launching"):
            return True
        if parser is None or not callable(getattr(parser, "is_alive", None)):
            return False
        stopping = getattr(parser, "_stop_event", None)
        if stopping is not None and stopping.is_set():
            return False
        return bool(parser.is_alive())

    def _export_gate(self):
        """Замок «выгрузка идёт / выгрузка кончилась».

        Без него «Стоп» мог проверить «идёт» в тот миг, когда выгрузка как раз
        кончалась: таблица не очищалась, а отложенная очистка висела до
        СЛЕДУЮЩЕЙ выгрузки и стирала таблицу уже другого прогона (рецензия
        07.11.2026). setdefault атомарен: замок один на мост.
        """
        return self.__dict__.setdefault("_export_gate_lock", threading.Lock())

    def _export_done(self):
        """Выгрузка кончилась: снять признак и дочистить таблицу после «Стопа»."""
        with self._export_gate():
            self._export_busy = False
            if self._clear_store_after_export:
                self._clear_store_after_export = False
                self.store.clear()

    def _reset_validator_view(self):
        """Экран проверки — как при первом открытии. Диск не трогается."""
        with self._export_gate():
            if self._export_busy:
                self._clear_store_after_export = True
            else:
                self.store.clear()
        self._progress = (0, 0)
        self._proxy_progress = (0, 0)
        self._phase = ("", 0)
        self._state = "idle"
        self._proxy_summary = None
        with self._lock:
            # Номер строки НЕ обнуляется: окно просит строки «после номера N»,
            # и с обнулённым счётом новые строки не показывались бы, пока
            # номер не догонит старый.
            self._history = []
            self._pending = []
        for text, tag in self.START_LINES:
            self._on_log(text, tag)
        for kind in ("emails", "proxies"):
            self._forget_sources(kind)
        self.suppress_path = None

    def _forget_sources(self, kind):
        """Источник забыт, как после «Очистить», но без отказа «идёт проверка».

        Движок держит свою копию, так что его это не задевает. Отпечаток
        файлов обнуляется: иначе пустое ведро против прошлого отпечатка
        дало бы в чистый журнал «Файл изменился на диске — пересчитываю».
        """
        bucket = self._sources.get(kind)
        if bucket is None:
            return
        bucket.clear()
        with self._count_lock:
            self._file_stamps[kind] = []
        self._recount(kind)
        self._rescan_base(kind)

    def _start_clears_the_table(self):
        """«Начать» чистит таблицу сам — отложенная очистка больше не нужна.

        Иначе выгрузка, начатая до «Стопа», кончалась уже ПОСЛЕ нового
        запуска и стирала таблицу нового прогона (рецензия 07.11.2026).
        Возвращает False, если выгрузка ещё идёт: она читает эту таблицу, и
        чистить её под ней нельзя.
        """
        with self._export_gate():
            if self._export_busy:
                return False
            self._clear_store_after_export = False
            self.store.clear()
            return True

    def _validator_running(self):
        pipeline = getattr(self, "pipeline", None)
        if pipeline is not None and getattr(pipeline, "is_running", False):
            return True
        return bool(getattr(self, "_starting", False)) and not getattr(self, "_discarding", False)

    def _reset_parser_view(self):
        """Экран сбора адресов — как при первом открытии. Диск не трогается."""
        self.__dict__["_parser_discarding"] = True
        with self._lock:
            self._parser_rows = []
            self._parser_seen = set()
            self._parser_history = []
            self._parser_pending = []
        self._parser_stats = {"dorksDone": 0, "dorksTotal": 0,
                              "pages": 0, "snippets": 0, "emails": 0}
        self._parser_progress = (0, 0, 0, "Парсинг")
        self._parser_state = "idle"
        for kind in ("dorks", "pproxy"):
            self._forget_sources(kind)
