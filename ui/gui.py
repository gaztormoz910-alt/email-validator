# ui/gui.py
import customtkinter as ctk
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import itertools
import psutil
import socket
import os
import re
import threading
from ui.colors import *
from ui.result_store import ResultStore, group_of
from ui.log_buffer import LogBuffer, Throttle
# Окно собрано из примесей: разметка, вкладка парсера и переиспользуемые
# виджеты живут в отдельных файлах. Разделение по роду работы, а не по
# размеру: правка разметки не должна задевать логику прогона.
from ui.panels import PanelsMixin
from ui.parser_tab import ParserTabMixin
from ui.widgets import (ProxyHunterInputSelector, ProxyHunterSlider,
                        clean_input_line, _format_sources)
from core.pipeline import ValidationPipeline
from core.streamer import StreamLoader

CLEAN_PREFIX_RE = re.compile(r'^\d+[-.)\]:й]*\s+')

class ValidatorApp(PanelsMixin, ParserTabMixin, ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Email Validator Pro")
        self.geometry("1300x850")
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=BG_MAIN)
        
        try:
            import ctypes
            hwnd = ctypes.windll.user32.GetParent(self.winfo_id())
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(2)), 4)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 35, ctypes.byref(ctypes.c_int(0x00140E0B)), 4)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 33, ctypes.byref(ctypes.c_int(0x00140E0B)), 4)
        except Exception:
            pass
        
        self.app_mode = "Валидатор"
        self.email_sources = [] # [{"type": "text", "content": "..."}, {"type": "file", "path": "..."}]
        self.proxy_sources = []
        self.stats = {"valid": 0, "invalid": 0, "spam": 0, "unknown": 0}
        # Результаты живут в индексированном хранилище: выборка страницы больше
        # не перебирает всю базу (см. ui/result_store.py).
        self.result_store = ResultStore()
        # Сводка по прокси для панели — заполняется после профилирования
        self.proxy_summary = None
        # Идёт ли выгрузка. Вторая кнопка поверх первой писала бы в тот
        # же файл двумя потоками сразу.
        self._export_busy = False
        
        self.dork_sources = []
        self.parser_proxy_sources = []
        self.parser_results_data = []
        self.parser_pipeline = None
        
        self.validator_page = 1
        self.validator_page_size = 100
        
        import queue
        self.log_queue = queue.Queue()
        self.stats_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self.validator_result_queue = queue.Queue()
        # Лог с ЖЁСТКИМ потолком. Раньше здесь стояла обычная очередь, и на
        # большой базе она росла быстрее, чем окно успевала её разгребать:
        # каждый проверенный адрес добавлял строку, а видно всё равно только
        # последнюю тысячу. Теперь лишнее отбрасывается сразу, до Tk.
        self.validator_log_queue = LogBuffer(capacity=4000)

        # Как часто интерфейсу вообще позволено дёргать виджеты. Опрос очередей
        # идёт двадцать раз в секунду, но перерисовывать таблицу и счётчики с
        # такой частотой незачем — глаз столько не берёт, а Tk на это тратит
        # весь главный поток.
        self._stats_throttle = Throttle(0.25)
        self._table_throttle = Throttle(0.5)
        self._table_dirty = False
        self._stats_dirty = False
        self._active_tab = "Терминал"
        self._poll_queues()
        self._poll_validator_queues()

        self.pipeline = ValidationPipeline(callbacks={
            'on_log': self.safe_log,
            'on_progress': self.safe_update_progress,
            'on_result': self.safe_add_result,
            'on_complete': self.on_pipeline_complete,
            'on_unique_count': self.safe_update_unique_count,
            'on_proxies_tested': self.safe_update_proxies_count,
            'on_proxy_profile': self.safe_proxy_profile,
        })

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0, minsize=550)
        self.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        self._build_main_workspace()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        
        # Fix for Cyrillic keyboard layout shortcuts using hardware keycodes (Windows)
        self.bind_all("<Control-KeyPress>", self._ru_shortcuts)

    def _ru_shortcuts(self, event):
        # 67=C, 86=V, 88=X, 65=A, 90=Z (Windows Virtual Key Codes)
        if event.keycode == 67:
            event.widget.event_generate("<<Copy>>")
            return "break"
        elif event.keycode == 86:
            event.widget.event_generate("<<Paste>>")
            return "break"
        elif event.keycode == 88:
            event.widget.event_generate("<<Cut>>")
            return "break"
        elif event.keycode == 65:
            if hasattr(event.widget, 'tag_add'):
                event.widget.tag_add("sel", "1.0", "end")
            elif hasattr(event.widget, 'select_range'):
                event.widget.select_range(0, 'end')
            return "break"
        elif event.keycode == 90:
            try:
                event.widget.event_generate("<<Undo>>")
            except: pass
            return "break"

    def on_closing(self):
        import os
        # Выгрузка пишет файл в фоновом потоке. Выход по os._exit обрывает её
        # на середине, и на диске остаётся ОБРЕЗАННЫЙ файл, который выглядит
        # целым: строки в нём настоящие, просто не все. Спросить дешевле, чем
        # потом отправлять по половине базы, считая её полной.
        if getattr(self, "_export_busy", False):
            if not messagebox.askyesno(
                    "Идёт выгрузка",
                    "Файл ещё сохраняется. Если выйти сейчас, он останется "
                    "обрезанным.\n\nВсё равно выйти?"):
                return
        if hasattr(self, 'pipeline') and self.pipeline.is_running:
            if messagebox.askyesno("Внимание", "Проверка сейчас запущена!\nВы уверены, что хотите прервать работу и закрыть программу?"):
                self.pipeline.is_running = False
                self.destroy()
                os._exit(0)
        elif hasattr(self, 'parser_pipeline') and self.parser_pipeline and self.parser_pipeline.is_alive():
            if messagebox.askyesno("Внимание", "Парсинг сейчас запущен!\nВы уверены, что хотите прервать работу и закрыть программу?"):
                self.parser_pipeline.stop()
                self.destroy()
                os._exit(0)
        else:
            self.destroy()
            os._exit(0)

    def _switch_app_mode(self, mode):
        self.app_mode = mode
        if mode == "Валидатор":
            self.parser_sidebar_frame.pack_forget()
            self.validator_sidebar_frame.pack(fill="both", expand=True)
            self.parser_workspace.pack_forget()
            self.validator_workspace.pack(fill="both", expand=True)
            self.main_title_lbl.configure(text="EMAIL VALIDATOR PRO")
            self.sub_title_lbl.configure(text="v4.0 - Продвинутая фильтрация")
        else:
            self.validator_sidebar_frame.pack_forget()
            self.parser_sidebar_frame.pack(fill="both", expand=True)
            self.validator_workspace.pack_forget()
            self.parser_workspace.pack(fill="both", expand=True)
            self.main_title_lbl.configure(text="OSINT EMAIL PARSER")
            
            # Update subtitle based on search engine
            engine = self.engine_var.get()
            self.sub_title_lbl.configure(text=f"{engine} Dork Engine")

    def _on_engine_change(self, value):
        tor_engines = ["AOL (Tor)", "Yahoo (Tor)"]
        
        if value in tor_engines:
            # Tor mode: cap threads to 50 (will be further limited by alive instances)
            max_t = min(self.max_hw_threads, 50)
            self.parser_threads_slider.label.configure(text="Потоки (Tor)")
            self.parser_threads_slider.to = max_t
            self.parser_threads_slider.slider.configure(to=max_t)
            self.parser_threads_slider.val = min(self.parser_threads_slider.val, max_t)
            self.parser_threads_slider._update_all()
            
            # Cap timeout to 20 for Tor
            self.parser_timeout_slider.label.configure(text="Таймаут Tor (сек)")
            self.parser_timeout_slider.to = 30
            self.parser_timeout_slider.slider.configure(to=30)
            self.parser_timeout_slider.val = min(self.parser_timeout_slider.val, 15)
            self.parser_timeout_slider._update_all()
            
            self.parser_proxy_frame.pack_forget()
            self.parser_proxy_selector.clear_btn.invoke()
        else:
            # Non-Tor mode: restore original limits
            max_t = min(self.max_hw_threads, 500)
            self.parser_threads_slider.label.configure(text="Потоки (Dorks)")
            self.parser_threads_slider.to = max_t
            self.parser_threads_slider.slider.configure(to=max_t)
            self.parser_threads_slider._update_all()
            
            self.parser_timeout_slider.label.configure(text="Таймаут прокси (сек)")
            self.parser_timeout_slider.to = 300
            self.parser_timeout_slider.slider.configure(to=300)
            self.parser_timeout_slider._update_all()
            
            self.parser_proxy_frame.pack(fill="x", before=self.engine_frame)
            
        if self.app_mode == "Парсер":
            self.sub_title_lbl.configure(text=f"{value} Dork Engine")

    def clear_emails(self):
        self.email_sources.clear()
        self.loaded_lbl.configure(text="Загружено: 0")
        self.db_selector.set_text("")
        self.db_selector.textbox.delete("1.0", "end")
        self.safe_log("[INFO] База Email адресов очищена.", "trap")
        
    def clear_proxies(self):
        self.proxy_sources.clear()
        self.loaded_proxies_lbl.configure(text="Прокси: 0")
        self.proxy_selector.set_text("")
        self.proxy_selector.textbox.delete("1.0", "end")
        self.safe_log("[INFO] SOCKS5 прокси очищены.", "trap")
        
    def _on_country_mode_change(self, value):
        """Переключает пороги предсказания страны по имени.

        Действует сразу, без перезапуска: пороги читаются на каждом
        предсказании, а не защёлкиваются при старте прогона.
        """
        from core.parser.ml_predictor import set_country_mode
        mode = "accuracy" if value == "Точность" else "coverage"
        set_country_mode(mode)
        if mode == "accuracy":
            self.country_mode_hint.configure(
                text="неуверенная страна остаётся пустой (верно ~50%, пусто ~42%)")
            self.safe_log(
                "[INFO] Страна по имени: режим ТОЧНОСТЬ. Слабое распределение "
                "отбрасывается — колонка будет заполнена реже, но вернее.", "info")
        else:
            self.country_mode_hint.configure(
                text="заполнено почти всегда, ~треть стран — догадка")
            self.safe_log(
                "[INFO] Страна по имени: режим ЗАПОЛНЕННОСТЬ. Колонка заполняется "
                "почти всегда; догадку видно по колонке «Источник».", "info")

    # Сколько строк показывать в предпросмотре. Больше человек всё равно не
    # читает, а Tk тратит на каждую строку и память, и время отрисовки.
    PREVIEW_LINES = 2000

    # Через сколько элементов фоновый разбор отпускает GIL. Любой фоновый
    # поток на чистом Python держит GIL почти непрерывно, и главный поток Tk
    # получает его так редко, что окно подмерзает — при том, что обработчик
    # кнопки вернулся мгновенно и «всё в фоне». Тысяча элементов между
    # вдохами стоит около миллисекунды на тысячу и снимает подморозку.
    BREATHE_EVERY = 1000

    def _ui_call(self, fn):
        """Ставит работу в очередь главного потока. Закрытое окно — не ошибка.

        Фоновые чтения переживают закрытие окна: пользователь выбрал файл на
        гигабайт и передумал. Раньше поток в этот момент падал с RuntimeError
        («main thread is not in main loop»), вываливал стек в консоль и умирал,
        не закрыв файл. Здесь это штатный исход, а не сбой.
        """
        try:
            self.after(0, fn)
            return True
        except (RuntimeError, tk.TclError):
            return False

    def _attach_sources(self, paths, sources, selector, label, template,
                        log, mode="lines"):
        """Подключает файлы как источник, НЕ трогая диск в главном потоке.

        Здесь исправлены сразу три причины, по которым окно замирало на
        больших файлах, и все три жили в четырёх почти одинаковых копиях:

        1. **Предпросмотр читал файл целиком.** В двух копиях из четырёх
           стояло `for idx, line in enumerate(...)` с проверкой `if idx <
           5000` ВНУТРИ цикла и без `break`. То есть первые пять тысяч строк
           показывались, а остальные пятьдесят миллионов всё равно
           прочитывались — просто молча, в никуда.

        2. **Всё это происходило в главном потоке.** Даже правильный
           предпросмотр с обрывом читает файл, а чтение с диска в обработчике
           кнопки — это замершее окно ровно на время чтения.

        3. **Порог «файл больше 20 МБ» решал не ту задачу.** Файл на 19 МБ из
           одних коротких строк — это миллион записей, и он подвешивал окно
           точно так же, просто не попадал под порог. Размер вообще не нужен:
           если предпросмотр ограничен и уехал в фон, большой файл ничем не
           отличается от маленького.

        Главный поток здесь делает только две вещи: кладёт словари в список и
        ставит подпись «читаю…». Ни одного обращения к диску — даже getsize,
        который на сетевом диске тоже умеет блокировать.
        """
        if not paths:
            return
        for path in paths:
            sources.append({"type": "file", "path": path})

        selector.set_text("Несколько файлов" if len(paths) > 1 else paths[0])
        label.configure(text=template.format(count="считаю..."))
        try:
            selector.textbox.delete("1.0", "end")
            selector.textbox.insert("1.0", "Читаю первые строки..." + chr(10))
        except Exception:
            pass

        snapshot = list(sources)

        def work():
            preview = []
            try:
                loader = StreamLoader([{"type": "file", "path": p} for p in paths])
                stream = (loader.stream_emails() if mode == "emails"
                          else loader.stream_lines())
                for item in stream:
                    preview.append(item[0] if mode == "emails" else item)
                    if len(preview) >= self.PREVIEW_LINES:
                        break   # обрыв ОБЯЗАТЕЛЕН: файл может быть на гигабайты
            except Exception:
                pass

            def show():
                try:
                    selector.textbox.delete("1.0", "end")
                    selector.append_to_textbox(preview)
                    if len(preview) >= self.PREVIEW_LINES:
                        selector.textbox.insert(
                            "end",
                            chr(10) + f"...показаны первые {self.PREVIEW_LINES}; "
                            "остальное читается потоком во время работы...")
                except Exception:
                    pass
            self._ui_call(show)

            try:
                total = StreamLoader(snapshot).count_total_lines()
            except Exception:
                total = 0
            self._ui_call(lambda: label.configure(text=template.format(count=total)))

        threading.Thread(target=work, daemon=True).start()
        if log:
            log("[INFO] Файлы подключены, читаю их в фоне — окно не ждёт.", "info")

    def _count_lines_async(self, sources, label, template):
        """Считает строки источников в фоне и подписывает результат.

        Зачем фон. count_total_lines() читает файлы целиком. На гигабайтном
        списке это десятки секунд, и раньше они проходили в ГЛАВНОМ потоке —
        то есть окно на всё это время переставало отзываться сразу после того,
        как пользователь выбрал файл. Само чтение быстрее не стало, но окно
        больше не висит, а подпись обновляется, когда счёт закончен.
        """
        label.configure(text=template.format(count="считаю..."))

        def work():
            try:
                total = StreamLoader(list(sources)).count_total_lines()
            except Exception:
                total = 0
            self._ui_call(lambda: label.configure(text=template.format(count=total)))

        threading.Thread(target=work, daemon=True).start()

    def safe_proxy_profile(self, summary):
        """Колбэк пайплайна: сводка приходит из рабочего потока."""
        self._ui_call(lambda: self._store_proxy_summary(summary))

    def _store_proxy_summary(self, summary):
        self.proxy_summary = summary if isinstance(summary, dict) else None
        if self.proxy_summary:
            rotation = self.proxy_summary.get("unique_ips", 0)
            duplicates = self.proxy_summary.get("duplicates", 0)
            if duplicates:
                # Это то самое, чего раньше не было видно вообще: ротация
                # меньше, чем кажется по числу строк в файле.
                self.safe_log(
                    f"[DEAD] Реальная ротация — {rotation} адресов, а не "
                    f"{self.proxy_summary.get('total', 0)} прокси: {duplicates} из них "
                    "выходят через уже занятый IP. Почтовик видит адреса, а не строки.",
                    "dead")
        if self._active_tab == "Прокси":
            self._render_proxy_panel()

    def _switch_tab(self, value):
        # Активная вкладка запоминается: таблица перерисовывается только когда
        # она видна. На вкладке терминала эта работа не видна никому, а стоит
        # ровно столько же — именно она и съедала главный поток.
        self._active_tab = value
        # Показ по требованию: пользователь только что попросил посмотреть,
        # ждать очередного тика незачем.
        self._stats_dirty = False
        self._stats_throttle.reset()
        self._refresh_stat_cards()
        for view in (self.terminal_view, self.table_view, self.proxy_view):
            view.pack_forget()
        if value == "Терминал":
            self.terminal_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        elif value == "Прокси":
            self.proxy_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
            self._render_proxy_panel()
        else:
            self.table_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
            # При переходе на вкладку показываем СРАЗУ, не дожидаясь таймера
            self._table_dirty = False
            self._table_throttle.reset()
            self.refresh_validator_tree(force=True)

    def get_hardware_limits(self):
        cores = psutil.cpu_count(logical=True) or 2
        ram_gb = psutil.virtual_memory().total / (1024 ** 3)
        max_threads = int((cores * 150) + (ram_gb * 100))
        if max_threads < 500: max_threads = 500
        if max_threads > 5000: max_threads = 5000
        rank = "ULTRA" if max_threads >= 3000 else "HIGH" if max_threads >= 1500 else "MEDIUM" if max_threads >= 800 else "LOW"
        color = ACCENT_SUCCESS if rank == "ULTRA" else ACCENT_PRIMARY if rank == "HIGH" else ACCENT_WARNING if rank == "MEDIUM" else ACCENT_ERROR
        return max_threads, rank, color

    def load_file(self):
        filepaths = filedialog.askopenfilenames(
            filetypes=[("Text/CSV Files", "*.txt *.csv")])
        if not filepaths:
            return
        self._attach_sources(filepaths, self.email_sources, self.db_selector,
                             self.loaded_lbl, "Загружено строк: {count}",
                             self.safe_log, mode="emails")
        self._scan_base_composition()

    # Сколько адресов нюхать для отчёта о составе базы. Это доли, а не
    # абсолютные числа: на двухстах тысячах адресов доля Gmail отличается от
    # доли на пятидесяти миллионах в третьем знаке после запятой, а времени
    # уходит в двести раз меньше.
    BASE_SCAN_SAMPLE = 200_000

    def _scan_base_composition(self):
        """Показывает состав базы по провайдерам. Без сети — только чтение файла.

        Читается ВЫБОРКА, а не вся база. Раньше здесь стоял разбор всего входа
        целиком: на файле в сотни мегабайт это минуты чтения и разбора ради
        отчёта, который весь состоит из процентов, — и запускался он заново на
        каждое добавление файла и каждую вставку текста.
        """
        if not self.email_sources:
            return

        sources = list(self.email_sources)

        def worker():
            try:
                from core.provider import scan_base_providers, format_base_scan
                # breathe_every заставляет скан отпускать GIL. Без него этот
                # поток — сплошной чистый Python, и окно подмерзает на треть
                # секунды, хотя обработчик кнопки давно вернулся. См. пояснение
                # в самой scan_base_providers.
                scan = scan_base_providers(sources, limit=self.BASE_SCAN_SAMPLE,
                                           breathe_every=self.BREATHE_EVERY)
                for line in format_base_scan(scan):
                    self.safe_log(line, "info")
                if scan.get("total", 0) >= self.BASE_SCAN_SAMPLE:
                    self.safe_log(
                        f"[INFO] Состав посчитан по первым {self.BASE_SCAN_SAMPLE} "
                        "адресам — на долях это не сказывается.", "info")
            except Exception as e:
                self.safe_log(f"[DEAD] Скан состава базы не удался: {type(e).__name__}", "dead")

        # В отдельном потоке: на большом файле чтение займёт время, а UI морозить нельзя
        threading.Thread(target=worker, daemon=True).start()

    def on_emails_pasted(self, text):
        self.email_sources.append({"type": "text", "content": text})
        self._count_lines_async(self.email_sources, self.loaded_lbl,
                                "Загружено строк: {count}")
        self._scan_base_composition()

    def load_proxies(self):
        # Предпросмотр показывает ровно то, что пойдёт в работу. Раньше здесь
        # отсеивались socks4 и HTTP — и получалось враньё: валидация их
        # использует, а в окне пользователь их не видит, хотя счётчик ниже
        # считает все строки файла.
        filepaths = filedialog.askopenfilenames(filetypes=[("Text Files", "*.txt")])
        self._attach_sources(filepaths, self.proxy_sources, self.proxy_selector,
                             self.loaded_proxies_lbl, "Прокси (оценка): {count}",
                             self.safe_log)

    def on_proxies_pasted(self, text):
        self.proxy_sources.append({"type": "text", "content": text})
        self._count_lines_async(self.proxy_sources, self.loaded_proxies_lbl,
                                "Прокси (оценка): {count}")

    def _set_sidebar_state(self, state):
        if hasattr(self, 'engine_selector'):
            self.engine_selector.configure(state=state)
        self.db_selector.configure(state=state)
        self.proxy_selector.configure(state=state)
        self.threads_slider.configure(state=state)
        self.timeout_slider.configure(state=state)
        self.chk_ai.configure(state=state)
        self.chk_osint_val.configure(state=state)
        self.chk_cache.configure(state=state)
        self.dork_selector.configure(state=state)
        self.parser_proxy_selector.configure(state=state)
        self.parser_threads_slider.configure(state=state)
        self.parser_timeout_slider.configure(state=state)

    def _set_playback_state(self, state):
        if state == "running":
            self.start_btn.configure(state="disabled")
            self.pause_btn.configure(state="normal", text="⏸", fg_color=ACCENT_WARNING)
            self.stop_btn.configure(state="normal")
        elif state == "stopped":
            self.start_btn.configure(state="normal")
            self.pause_btn.configure(state="disabled", text="⏸", fg_color=ACCENT_WARNING)
            self.stop_btn.configure(state="disabled")

    def start_process(self):
        if self.app_mode == "Валидатор":
            self.start_validation()
        else:
            self.start_parsing()

    def pause_process(self):
        if self.app_mode == "Валидатор":
            self.pause_validation()
        else:
            self.pause_parsing()

    def stop_process(self):
        if self.app_mode == "Валидатор":
            self.stop_validation()
        else:
            self.stop_parsing()

    def start_validation(self):
        if not self.email_sources:
            self.safe_log("[DEAD] Ошибка: Загрузите базу перед стартом!", "dead")
            return
        if not self.proxy_sources:
            self.safe_log("[DEAD] Ошибка: Загрузите прокси перед стартом!", "dead")
            return
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=1.5)
        except OSError:
            messagebox.showerror("Ошибка сети", "Нет подключения к интернету!\nПроверьте ваше сетевое подключение.")
            self.safe_log("[DEAD] Ошибка: Отсутствует подключение к интернету.", "dead")
            return
            
        self.stats = {"valid": 0, "invalid": 0, "spam": 0, "unknown": 0, "names": 0}
        self.result_store.clear()
        # Карточки — это виджеты, они хранят прошлый текст сами. Пустое
        # хранилище их не обнуляет, и до первого результата наверху висели
        # числа ПРЕДЫДУЩЕГО прогона.
        self._shown_emails = None
        self._page_key = None
        self._page_was_full = False
        self.validator_page = 1
        self._refresh_stat_cards()
        self.refresh_validator_tree(force=True)
        
        self.stat_0.configure(text="0")
        self.stat_1.configure(text="0")
        self.stat_2.configure(text="0")
        self.stat_3.configure(text="0")
        self.stat_4.configure(text="0")
        self.stat_names.configure(text="0")
        
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        self._set_sidebar_state("disabled")
        self._set_playback_state("running")
            
        self.terminal_box.configure(state="normal")
        self.terminal_box.delete("1.0", "end")
        self.terminal_box.configure(state="disabled")
        self.safe_log("[INFO] Инициализация конвейера валидации...", "info")

        # Берём прокси ЛЮБОГО поддерживаемого протокола. Раньше здесь
        # отсеивалось всё, кроме socks5 и голого host:port, хотя и чекер, и
        # соединение давно умеют socks4 и HTTP CONNECT — часть купленного
        # пула просто не доходила до валидатора.
        # Прокси идут в пайплайн ЛЕНИВО. Раньше здесь строился список из всего
        # файла, и на списке в миллионы строк окно замирало ещё до старта
        # проверки. Теперь читается по строке, а материализуются только те,
        # что оказались живыми.
        from core.network import dedupe_proxies_stream
        proxy_stream = dedupe_proxies_stream(
            StreamLoader(self.proxy_sources).stream_lines())

        # Заглядываем ровно на один элемент: это отличает пустой источник от
        # непустого, не читая остальное.
        try:
            first_proxy = next(proxy_stream)
        except StopIteration:
            first_proxy = None

        if first_proxy is None:
            self.safe_log("[DEAD] Ошибка: в загруженных источниках нет ни одного прокси!", "dead")
            self._set_playback_state("stopped")
            self._set_sidebar_state("normal")
            return

        import itertools
        actual_proxies = itertools.chain([first_proxy], proxy_stream)

        threads = int(self.threads_slider.get())
        timeout = int(self.timeout_slider.get())
        
        self.pipeline.start(
            email_sources=self.email_sources,
            threads=threads,
            timeout=timeout,
            fix_typos=True,
            check_spam=True,
            deep_ping=True,
            enable_ai=self.chk_ai.get() == 1,
            enable_osint=self.chk_osint_val.get() == 1,
            proxies=actual_proxies,
            use_cache=self.chk_cache.get() == 1
        )

    def pause_validation(self):
        is_paused = self.pipeline.pause()
        if is_paused:
            self.pause_btn.configure(text="▶", fg_color=ACCENT_SUCCESS)
            self.safe_log("[INFO] Процесс приостановлен (PAUSE).", "info")
        else:
            self.pause_btn.configure(text="⏸", fg_color=ACCENT_WARNING)
            self.safe_log("[INFO] Процесс возобновлен (RESUMED).", "info")

    def stop_validation(self):
        self.pipeline.stop()
        self.safe_log("[INFO] Процесс остановлен пользователем (STOP).", "info")
        self.on_pipeline_complete()

    def safe_log(self, text, tag="info"):
        self.validator_log_queue.put(text, tag)

    def _flush_log_ui(self, chunk):
        """Вставляет пачку строк ОДНИМ обращением к виджету.

        Раньше на каждую строку приходилось: снять блокировку, вставить,
        посчитать общее число строк, обрезать лишние, прокрутить, вернуть
        блокировку. Шесть операций Tk на строку и сто тысяч строк за прогон —
        столько главный поток просто не успевает, и окно замирает. Теперь
        накопленное за тик склеивается и вставляется целиком.
        """
        if not chunk:
            return
        self.terminal_box.configure(state="normal")
        # Теги разные, поэтому склеиваем подряд идущие строки с одинаковым
        # тегом: обычно весь тик — это один тег, и вставка получается одна.
        run_tag = chunk[0][1]
        run = []
        for text, tag in chunk:
            if tag != run_tag and run:
                self.terminal_box.insert("end", "\n".join(run) + "\n", run_tag)
                run, run_tag = [], tag
            run.append(text)
        if run:
            self.terminal_box.insert("end", "\n".join(run) + "\n", run_tag)

        # Обрезка тоже раз в тик, а не на каждой строке
        try:
            line_count = int(self.terminal_box.index('end-1c').split('.')[0])
            if line_count > 1000:
                self.terminal_box.delete("1.0", f"{line_count - 1000}.0")
        except Exception:
            pass

        self.terminal_box.see("end")
        self.terminal_box.configure(state="disabled")

    def safe_update_unique_count(self, count):
        self._ui_call(lambda: self.stat_0.configure(text=str(count)))

    def safe_update_proxies_count(self, live_count, total_count):
        self._ui_call(lambda: self.loaded_proxies_lbl.configure(text=f"Прокси: {live_count} / {total_count} (Рабочих)"))

    def safe_update_progress(self, current, total):
        self._ui_call(lambda: self._update_progress_ui(current, total))
        
    def _update_progress_ui(self, current, total):
        pct = int((current / total) * 100) if total > 0 else 0
        status_text = "Завершено" if pct == 100 else "Проверка..."
        self.progress_lbl.configure(text=f"{status_text} ({current}/{total})")
        self.percent_lbl.configure(text=f"{pct}%")
        self.progress_bar.set(pct / 100.0)
        
        if total > 0 and pct == 100:
            self.progress_bar.configure(progress_color=ACCENT_SUCCESS)
        else:
            self.progress_bar.configure(progress_color=ACCENT_PRIMARY)

    def _drain_validator_queues(self):
        """Разбирает всё, что накопили рабочие потоки, и обновляет виджеты.

        Вынесено из тика отдельно, потому что вызывать это надо не только по
        таймеру, но и в момент завершения прогона. Иначе последняя пачка
        результатов остаётся в очереди, а отчёт «Валидация завершена» уходит
        в лог раньше неё — и владелец видит строки ПОСЛЕ завершения, бар на
        100% при идущих проверках и ноль в карточке при полной таблице.
        Три разные жалобы, причина одна.

        Порядок внутри тоже исправлен. Раньше лог сливался ПЕРВЫМ, а строки
        результатов рождаются при их разборе — то есть попадали в уже слитый
        буфер и показывались лишь на следующем тике. Теперь сначала разбор,
        потом слив: строка результата и её показ происходят в одном тике.
        """
        import queue

        added = 0
        for _ in range(2000):
            try:
                email, status, reason, mx, data = self.validator_result_queue.get_nowait()
            except queue.Empty:
                break
            self._add_result_ui(email, status, reason, mx, data)
            added += 1

        if added:
            self._table_dirty = True
            self._stats_dirty = True

        self._flush_log_ui(self.validator_log_queue.drain(limit=400))
        return added

    def _finish_validator_view(self):
        """Показывает ВСЁ, что осталось в очередях. Зовётся при завершении.

        Крутится до опустошения очередей, а не один раз: пока идёт разбор,
        рабочие потоки могли дописать ещё. Потолок на число кругов есть —
        подвесить окно наглухо нельзя даже при сбое.
        """
        for _ in range(200):
            if not self._drain_validator_queues():
                break
        self._stats_dirty = False
        self._refresh_stat_cards()
        if self._active_tab == "Результаты":
            self._table_dirty = False
            self.refresh_validator_tree(force=True)

    def _poll_validator_queues(self):
        """Тик интерфейса. Здесь была главная причина зависаний.

        Что было. На КАЖДОМ тике (двадцать раз в секунду) вызывался
        refresh_validator_tree(), а он звал _get_filtered_results(), который
        перебирал ВСЮ базу результатов, чтобы показать сотню строк. Сто тысяч
        итераций двадцать раз в секунду в главном потоке Tk — окно переставало
        отзываться тем сильнее, чем дольше шёл прогон.

        Что стало. Данные кладутся в индексированное хранилище (дёшево),
        а виджеты трогаются по таймеру и только если есть что показывать:
        таблица — не чаще двух раз в секунду и только на своей вкладке,
        счётчики — четыре раза в секунду, лог — одной пачкой.
        """
        # Результаты забираем пачкой и кладём в хранилище — это чистый Python
        # без единого обращения к Tk, поэтому предел там щедрый. Сам разбор
        # живёт в _drain_validator_queues: им же пользуется завершение прогона.
        self._drain_validator_queues()

        # Счётчики обновляются по ТОМУ ЖЕ правилу, что и таблица: флаг
        # «есть что показать» живёт до тех пор, пока показ не состоится.
        #
        # Раньше здесь стояло `if added and throttle.ready()`, и это был баг:
        # если пачка результатов приходила раньше, чем через 0.25с после
        # предыдущей, throttle её пропускал — а следующего шанса не было,
        # потому что обновление было привязано к приходу НОВЫХ результатов.
        # На базе из одного домена (все адреса Gmail) следующий результат
        # приходил через минуты, и всё это время карточка «Валидные»
        # показывала ноль при полной таблице валидных адресов.
        if self._stats_dirty and self._stats_throttle.ready():
            self._stats_dirty = False
            self._refresh_stat_cards()

        # Таблицу перерисовываем, только когда она видна: на вкладке терминала
        # эта работа не видна никому, а стоит столько же.
        if (self._table_dirty and self._active_tab == "Результаты"
                and self._table_throttle.ready()):
            self._table_dirty = False
            self.refresh_validator_tree()

        self.after(50, self._poll_validator_queues)

    def _refresh_stat_cards(self):
        """Переносит готовые счётчики хранилища в карточки."""
        counts = self.result_store.counts()
        self.stat_1.configure(text=str(counts["valid"]))
        self.stat_2.configure(text=str(counts["invalid"]))
        self.stat_3.configure(text=str(counts["spam"]))
        self.stat_4.configure(text=str(counts["unknown"]))
        self.stat_names.configure(text=str(counts["names"]))
        dropped = self.validator_log_queue.dropped
        if dropped and hasattr(self, "log_note_lbl"):
            # Молча терять строки лога нельзя — иначе по терминалу нельзя
            # судить о прогоне. Говорим, сколько не поместилось.
            self.log_note_lbl.configure(
                text=f"строк лога пропущено: {dropped} (потолок буфера)")

    def safe_add_result(self, email, status, reason, mx, data=None):
        if data is None:
            data = {}
        self.validator_result_queue.put((email, status, reason, mx, data))
        
    def _add_result_ui(self, email, status, reason, mx, data):
        """Кладёт результат в хранилище и в лог. Виджеты здесь НЕ трогаются.

        Раньше каждая строка результата дёргала .configure() у карточки
        статистики — то есть на сто тысяч адресов приходилось сто тысяч
        перерисовок виджета, каждая из которых заставляла Tk пересчитывать
        раскладку. Теперь счётчики хранятся в самом хранилище и переносятся
        в карточки по таймеру, пачкой.
        """
        data = data if isinstance(data, dict) else {}
        group = self.result_store.append(email, status, reason, mx, data)

        # Строка лога по-прежнему пишется на каждый адрес: живой поток в
        # терминале — это то, ради чего окно и открыто. Дорогой её делала не
        # запись, а немедленная вставка в Tk; вставка теперь идёт пачками,
        # а буфер имеет потолок и не может съесть память.
        if group == "valid":
            self.safe_log(f"[VALID] {email} -> {reason}", "valid")
        elif group == "spam":
            label = "ROLE" if status == "Role-based" else str(status).upper()
            self.safe_log(f"[{label}] {email} -> {reason}", "trap")
        elif group == "unknown":
            self.safe_log(f"[UNKNOWN] {email} -> {reason}", "trap")
        elif group == "invalid":
            self.safe_log(f"[DEAD] {email} -> {reason}", "dead")
        else:
            self.safe_log(f"[SKIP] {email} -> {reason}", "info")
            
    def _on_filter_change(self):
        self.validator_page = 1
        self.refresh_validator_tree(force=True)
        
    def prev_validator_page(self):
        if self.validator_page > 1:
            self.validator_page -= 1
            self.refresh_validator_tree(force=True)
            
    def next_validator_page(self):
        import math
        # Число страниц берётся у счётчиков хранилища. Раньше здесь стояла
        # _get_filtered_results() — она собирает ВСЮ выборку списком в память,
        # то есть нажатие «След.» на многомиллионной базе означало собрать её
        # целиком ради одного деления. Ровно то, ради чего хранилище и
        # сделано потоковым, и ровно там, где это отменялось.
        total = self.result_store.matching_count(self._selected_groups(),
                                                 min_score=self._get_min_score())
        total_pages = max(1, math.ceil(total / self.validator_page_size))
        if self.validator_page < total_pages:
            self.validator_page += 1
            self.refresh_validator_tree(force=True)
            
    def refresh_validator_tree(self, force=False):
        import math
        groups = self._selected_groups()
        min_score = self._get_min_score()

        # Число страниц: без порога по скору оно берётся из готовых счётчиков
        # и не стоит ничего. Раньше ради него материализовалась вся выборка.
        total = self.result_store.matching_count(groups, min_score=min_score)
        total_pages = max(1, math.ceil(total / self.validator_page_size))

        if self.validator_page > total_pages:
            self.validator_page = max(1, total_pages)

        self.lbl_page.configure(text=f"Стр. {self.validator_page} / {total_pages}")

        # ЗАПОЛНЕННАЯ страница больше не меняется, и перебирать её заново
        # незачем. Строки нумеруются по порядку прихода, а новые результаты
        # всегда получают номер БОЛЬШЕ всех прежних — значит попасть на уже
        # набранную страницу они не могут в принципе. Меняется только
        # последняя, неполная.
        #
        # Экономия не косметическая: на трёх миллионах строк выборка глубокой
        # страницы стоит 0.85 с (SQL с большим OFFSET перебирает всё, что до
        # неё). Дважды в секунду, пока идёт прогон, — это стоящее колом окно у
        # того, кто просто пролистал таблицу далеко.
        page_key = (tuple(groups), min_score, self.validator_page)
        if (not force
                and getattr(self, "_page_key", None) == page_key
                and getattr(self, "_page_was_full", False)):
            return

        page_data = self.result_store.page(
            groups, page=self.validator_page,
            size=self.validator_page_size, min_score=min_score)
        self._page_key = page_key
        self._page_was_full = len(page_data) >= self.validator_page_size

        # Сравнение «а изменилось ли что-нибудь» раньше дёргало tree.item()
        # на каждой видимой строке — сотня обращений к Tk только чтобы решить
        # НЕ перерисовывать. Держим прошлый список у себя.
        new_emails = [r["email"] for r in page_data]
        if not force and getattr(self, "_shown_emails", None) == new_emails:
            return
        self._shown_emails = new_emails

        for child in self.tree.get_children():
            self.tree.delete(child)

        for r in page_data:
            email = r["email"]
            status = r["status"]
            reason = r["reason"]
            mx = r["mx"]
            data = r.get("data", {})
            
            tag = ""
            if status == "Valid": tag = "valid"
            elif status == "Trap/Disposable": tag = "trap"
            elif status == "Role-based": tag = "trap"
            elif status == "Unknown": tag = "unknown"
            else: tag = "dead"
            
            status_display = f"● {status}"
            score = data.get("engagement_score", "")
            grade = data.get("engagement_grade", "")
            score_display = f"{score} {grade}".strip() if score != "" else ""
            self.tree.insert("", "end", values=(
                email,
                status_display,
                score_display,
                data.get("provider_name", ""),
                data.get("domain_type", ""),
                reason,
                mx,
                data.get("name", ""),
                data.get("gender", ""),
                data.get("country", ""),
                data.get("birth_year", ""),
                _format_sources(data),
                data.get("validated_at", ""),
            ), tags=(tag,))

    def on_pipeline_complete(self):
        self._ui_call(self._reset_ui_after_complete)
        
    def _reset_ui_after_complete(self):
        # Сначала показать всё, что рабочие потоки успели положить в очереди,
        # и только потом объявлять о завершении. Иначе отчёт обгоняет
        # результаты: они лежат в очереди, а в терминале уже «завершена».
        self._finish_validator_view()
        self._set_playback_state("stopped")
        self._set_sidebar_state("normal")
        self.safe_log("[INFO] Валидация базы полностью завершена.", "info")
        # Ещё один слив — ради самой этой строки: она положена в буфер лога
        # только что и иначе ждала бы следующего тика.
        self._flush_log_ui(self.validator_log_queue.drain(limit=400))

    def copy_terminal_logs(self):
        text = self.terminal_box.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Скопировано", "Логи терминала скопированы в буфер обмена.")

    def _get_min_score(self):
        """Порог Engagement Score из поля ввода. Мусор во вводе трактуем как 0."""
        try:
            return max(0, min(100, int(self.min_score_var.get().strip() or 0)))
        except (ValueError, AttributeError):
            return 0

    def _selected_groups(self):
        """Группы, отмеченные галочками фильтра."""
        groups = []
        if self.chk_valid_var.get():
            groups.append("valid")
        if self.chk_invalid_var.get():
            groups.append("invalid")
        if self.chk_spam_var.get():
            groups.append("spam")
        if self.chk_unknown_var.get():
            groups.append("unknown")
        return tuple(groups)

    # Потолок на копирование в буфер обмена. Больше в него всё равно не
    # вставляют, а Tk на многомиллионной строке подвешивает окно.
    CLIPBOARD_LIMIT = 200_000

    def _get_filtered_results(self, limit=None):
        """Выборка списком. Только для маленьких выборок и тестов.

        Для ПОКАЗА и для ЭКСПОРТА этим пользоваться нельзя: здесь
        материализуется вся база. Таблица ходит в result_store.page(),
        который обрывается на нужной странице, а выгрузка — в
        result_store.iter_matching(), который отдаёт строки порциями.
        """
        stream = self.result_store.iter_matching(
            self._selected_groups(), min_score=self._get_min_score())
        if limit:
            return list(itertools.islice(stream, limit))
        return list(stream)

    def export_results(self):
        if not len(self.result_store):
            messagebox.showwarning("Пусто", "Нет данных для экспорта.")
            return
            
        if not self.result_store.matching_count(self._selected_groups(),
                                                min_score=self._get_min_score()):
            messagebox.showwarning("Пусто", "По выбранным критериям не найдено ни одного адреса.")
            return

        if self._export_busy:
            messagebox.showinfo("Идёт выгрузка",
                                "Предыдущая выгрузка ещё не закончилась.")
            return

        try:
            chunk_size = int(self.chunk_entry.get().strip() or 0)
        except ValueError:
            chunk_size = 0

        file_types = [("Text File (Только Email)", "*.txt"), ("CSV File (Email+Причина+MX)", "*.csv")]
        default_name = "results_filtered"
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=file_types, initialfile=default_name)

        if filepath:
            self._run_export(filepath, chunk_size)

    def _run_export(self, filepath, chunk_size):
        """Готовит выгрузку и уводит саму запись в фоновый поток.

        Почему в фон. Здесь читается вся выборка и пишется на диск, и раньше
        это происходило прямо в обработчике кнопки: замерено 6.6 с на миллионе
        строк, то есть больше минуты на десяти миллионах — всё это время окно
        не отвечает вовсе. Ровно тот случай, ради которого хранилище и сделано
        потоковым: память не растёт, а окно всё равно замирало.

        Диалоги остаются в главном потоке — и выбор файла до, и сообщение
        после. В фон уходит только чтение выборки и запись на диск.
        """
        try:
            groups = self._selected_groups()
            min_score = self._get_min_score()
            suppress_path = self.suppress_path
        except Exception as e:
            messagebox.showerror("Ошибка",
                                 f"Не удалось собрать параметры выгрузки: {e}")
            return

        self._export_busy = True
        try:
            self.export_btn.configure(state="disabled", text="Сохраняю...")
        except Exception:
            pass
        self.safe_log("[INFO] Выгрузка пошла в фоне — окно не ждёт.", "info")

        def finish(kind, title, text):
            self._export_busy = False
            try:
                self.export_btn.configure(state="normal", text="Сохранить")
            except Exception:
                pass
            {"info": messagebox.showinfo,
             "warn": messagebox.showwarning,
             "error": messagebox.showerror}.get(kind, messagebox.showinfo)(title, text)

        def work():
            try:
                note = self._export_to_disk(filepath, chunk_size, groups,
                                            min_score, suppress_path)
            except Exception as e:
                text = f"Не удалось сохранить файл: {type(e).__name__}: {e}"
                self._ui_call(lambda: finish("error", "Ошибка", text))
                return
            if note is None:
                self._ui_call(lambda: finish(
                    "warn", "Пусто",
                    "После вычитания отписок не осталось ни одного адреса."))
                return
            self._ui_call(lambda: finish("info", "Успех", note))

        threading.Thread(target=work, daemon=True).start()

    def _export_to_disk(self, filepath, chunk_size, groups, min_score,
                        suppress_path):
        """Сама выгрузка. Живёт в фоновом потоке и виджеты не трогает.

        Возвращает текст отчёта либо None, если после вычитания отписок не
        осталось ни строки. Ни одного обращения к Tk отсюда быть не может —
        иначе фон перестанет быть фоном.
        """
        from core import baseops

        # Список отписок читается ЦЕЛИКОМ (он ограничен файлом отписок,
        # а не базой), а выгрузка идёт потоком. Сравнение — по
        # каноническому ключу: человек отписался как John.Doe@Gmail.com,
        # а в базе лежит johndoe@gmail.com, и это один ящик. Письмо
        # тому, кто прямо просил его не трогать, стоит жалобы на спам.
        drop_keys = set()
        if suppress_path:
            try:
                drop_keys = baseops.suppression_keys(suppress_path)
            except Exception as e:
                self.safe_log("[DEAD] Список отписок не применён: "
                              f"{type(e).__name__}: {e}", "dead")

        def write_csv(f, rows):
            import csv
            # csv.writer обязателен: reason содержит запятые (напр. "[DNS: SPF=..., DMARC=...]"),
            # из-за чего ручная склейка через "," разъезжала колонки в Excel.
            writer = csv.writer(f)
            writer.writerow(["Email", "Status", "Reason", "MX-Record",
                             "Name", "FirstName", "LastName", "Gender", "Country",
                             "BirthYear", "Company", "JobRole", "Score", "Grade",
                             "Provider", "DomainType",
                             "NameSource", "GenderSource", "CountrySource",
                             "CompanySource", "JobRoleSource",
                             "SocialAccounts", "ValidatedAt"])
            for r in rows:
                data = r.get("data", {})
                writer.writerow([
                    r["email"], r["status"], r["reason"], r["mx"],
                    data.get("name", ""),
                    data.get("first_name", ""), data.get("last_name", ""),
                    data.get("gender", ""), data.get("country", ""),
                    data.get("birth_year", ""),
                    data.get("company", ""), data.get("job_role", ""),
                    data.get("engagement_score", ""), data.get("engagement_grade", ""),
                    data.get("provider_name", ""), data.get("domain_type", ""),
                    data.get("name_source", ""), data.get("gender_source", ""),
                    data.get("country_source", ""),
                    data.get("company_source", ""), data.get("job_role_source", ""),
                    data.get("social_accounts", ""),
                    data.get("validated_at", ""),
                ])

        def write_txt(f, rows):
            for r in rows:
                data = r.get("data", {})
                name = data.get("name", "")
                gender = data.get("gender", "")
                country = data.get("country", "")
                if name or gender or country:
                    f.write(f"{r['email']}:{name}:{gender}:{country}\n")
                else:
                    f.write(f"{r['email']}\n")

        writer_fn = write_csv if filepath.endswith(".csv") else write_txt

        # Выгрузка идёт ПОТОКОМ: строки берутся у хранилища порциями и
        # сразу уходят на диск. Раньше здесь стоял список, то есть вся
        # выборка собиралась в память — на многомиллионной базе это
        # ровно тот случай, ради которого всё остальное делалось
        # потоковым, и именно он падал.
        from core.cleaner import normalize_for_dedup
        counters = {"suppressed": 0}

        def selected_rows():
            for row in self.result_store.iter_matching(
                    groups, min_score=min_score):
                if drop_keys and normalize_for_dedup(row["email"]) in drop_keys:
                    counters["suppressed"] += 1
                    continue
                yield row

        written, saved = baseops.write_chunks_stream(
            selected_rows(), filepath, chunk_size, writer_fn)

        if not saved:
            return None

        note = f"Сохранено {saved} строк."
        if counters["suppressed"]:
            note += f"\nВычтено по списку отписок: {counters['suppressed']}."
        if len(written) > 1:
            note += f"\nРазбито на файлов: {len(written)} (по {chunk_size})."
        else:
            note += f"\nФайл: {os.path.basename(written[0] if written else filepath)}"
        self.safe_log(f"[INFO] Выгрузка закончена: {saved} строк.", "info")
        return note

    def choose_suppression(self):
        """Выбирает файл отписок. Повторное нажатие сбрасывает выбор."""
        if self.suppress_path:
            self.suppress_path = None
            self.suppress_btn.configure(text="Отписки", border_color=BORDER_STRONG)
            self.safe_log("[INFO] Список отписок отключён.", "info")
            return

        path = filedialog.askopenfilename(
            title="Файл с адресами отписавшихся",
            filetypes=[("Text/CSV", "*.txt *.csv"), ("Все файлы", "*.*")])
        if not path:
            return
        try:
            from core import baseops
            count = len(baseops.read_emails(path))
        except Exception:
            count = 0
        if not count:
            messagebox.showwarning("Отписки", "В файле не нашлось ни одного адреса.")
            return
        self.suppress_path = path
        self.suppress_btn.configure(text=f"Отписки: {count}", border_color=ACCENT_SUCCESS)
        self.safe_log(f"[INFO] Список отписок загружен: {count} адресов. "
                      "Они будут вычтены при сохранении.", "info")

    def copy_results(self):
        if not len(self.result_store):
            messagebox.showwarning("Пусто", "Нет данных для копирования.")
            return
            
        # Буфер обмена — не место для многомиллионной базы: и Tk, и сама
        # Windows на таком объёме встают колом, а вставить его человеку всё
        # равно некуда. Берём потоком и обрываемся на потолке, честно об этом
        # сообщая; для всей выборки есть «Сохранить».
        lines = []
        for r in self.result_store.iter_matching(self._selected_groups(),
                                                 min_score=self._get_min_score()):
            data = r.get("data", {})
            name = data.get("name", "")
            gender = data.get("gender", "")
            country = data.get("country", "")
            if name or gender or country:
                lines.append(f"{r['email']}:{name}:{gender}:{country}")
            else:
                lines.append(r['email'])
            if len(lines) >= self.CLIPBOARD_LIMIT:
                break

        if not lines:
            messagebox.showwarning("Пусто", "По выбранным критериям не найдено ни одного адреса.")
            return

        self.clipboard_clear()
        self.clipboard_append("\n".join(lines))
        note = f"Успешно скопировано {len(lines)} адресов в буфер обмена."
        if len(lines) >= self.CLIPBOARD_LIMIT:
            note += (f"\n\nЭто потолок буфера ({self.CLIPBOARD_LIMIT}). "
                     "Вся выборка целиком — кнопкой «Сохранить».")
        messagebox.showinfo("Скопировано", note)
