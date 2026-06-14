# ui/gui.py
import customtkinter as ctk
from tkinter import ttk, filedialog
import threading
from ui.colors import *
from core.pipeline import ValidationPipeline

class ValidatorApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Email Validator Pro")
        self.geometry("1200x800")
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=BG_MAIN)
        
        self.raw_emails = []
        self.proxies = []
        self.stats = {"valid": 0, "invalid": 0, "spam": 0, "risky": 0}
        
        # Инициализация Pipeline с коллбэками
        self.pipeline = ValidationPipeline(callbacks={
            'on_log': self.safe_log,
            'on_progress': self.safe_update_progress,
            'on_result': self.safe_add_result,
            'on_complete': self.on_pipeline_complete,
            'on_unique_count': self.safe_update_unique_count
        })

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0, minsize=280)
        self.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        self._build_main_workspace()

    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, fg_color=BG_CARD_1, border_color=BORDER, border_width=1, corner_radius=0)
        self.sidebar.grid(row=0, column=0, sticky="nsew")

        self.logo_label = ctk.CTkLabel(self.sidebar, text="EMAIL VALIDATOR PRO", font=ctk.CTkFont(size=18, weight="bold"), text_color=TEXT_MAIN)
        self.logo_label.pack(pady=(20, 10), padx=20, anchor="w")
        
        self.separator = ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER)
        self.separator.pack(fill="x", padx=20, pady=(0, 20))

        self.load_btn = ctk.CTkButton(self.sidebar, text="Load Database (.txt)", command=self.load_file, fg_color="transparent", border_color=BORDER, border_width=1, text_color=TEXT_MAIN, hover_color=BORDER)
        self.load_btn.pack(fill="x", padx=20, pady=(0, 5))
        
        self.loaded_lbl = ctk.CTkLabel(self.sidebar, text="Loaded: 0 emails", text_color=TEXT_MUTED, font=ctk.CTkFont(size=12))
        self.loaded_lbl.pack(padx=20, anchor="w", pady=(0, 10))

        self.load_proxies_btn = ctk.CTkButton(self.sidebar, text="Load Proxies (.txt)", command=self.load_proxies, fg_color="transparent", border_color=BORDER, border_width=1, text_color=TEXT_MAIN, hover_color=BORDER)
        self.load_proxies_btn.pack(fill="x", padx=20, pady=(0, 5))

        self.loaded_proxies_lbl = ctk.CTkLabel(self.sidebar, text="Proxies: 0", text_color=TEXT_MUTED, font=ctk.CTkFont(size=12))
        self.loaded_proxies_lbl.pack(padx=20, anchor="w", pady=(0, 20))

        self.threads_lbl = ctk.CTkLabel(self.sidebar, text="Threads: 150", text_color=TEXT_MAIN)
        self.threads_lbl.pack(padx=20, anchor="w")
        self.threads_slider = ctk.CTkSlider(self.sidebar, from_=1, to=500, fg_color=BORDER, progress_color=ACCENT_PRIMARY, button_color=ACCENT_PRIMARY, button_hover_color="#60A5FA", command=self.update_threads_label)
        self.threads_slider.set(150)
        self.threads_slider.pack(fill="x", padx=20, pady=(0, 15))

        self.timeout_lbl = ctk.CTkLabel(self.sidebar, text="Timeout: 5s", text_color=TEXT_MAIN)
        self.timeout_lbl.pack(padx=20, anchor="w")
        self.timeout_slider = ctk.CTkSlider(self.sidebar, from_=1, to=30, fg_color=BORDER, progress_color=ACCENT_PRIMARY, button_color=ACCENT_PRIMARY, button_hover_color="#60A5FA", command=self.update_timeout_label)
        self.timeout_slider.set(5)
        self.timeout_slider.pack(fill="x", padx=20, pady=(0, 20))

        # Базовые проверки теперь всегда включены под капотом.
        # Оставляем только кнопку включения нейросети.

        self.chk_ai = ctk.CTkCheckBox(self.sidebar, text="Enable AI Filter (TF+ML)", text_color=TEXT_MAIN, fg_color=ACCENT_PRIMARY, border_color=BORDER, hover_color="#60A5FA")
        self.chk_ai.select()
        self.chk_ai.pack(padx=20, anchor="w", pady=(5, 20))

        self.bottom_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.bottom_frame.pack(side="bottom", fill="x", padx=20, pady=20)

        self.start_btn = ctk.CTkButton(self.bottom_frame, text="START", command=self.start_validation, fg_color=ACCENT_PRIMARY, text_color=TEXT_MAIN, hover_color="#60A5FA", height=40, font=ctk.CTkFont(weight="bold"))
        self.start_btn.pack(fill="x", pady=(0, 10))

        self.controls_subframe = ctk.CTkFrame(self.bottom_frame, fg_color="transparent")
        self.controls_subframe.pack(fill="x")
        self.controls_subframe.grid_columnconfigure((0, 1), weight=1)

        self.pause_btn = ctk.CTkButton(self.controls_subframe, text="PAUSE", command=self.pause_validation, fg_color=ACCENT_WARNING, text_color=TEXT_MAIN, hover_color="#FBBF24", state="disabled")
        self.pause_btn.grid(row=0, column=0, padx=(0, 5), sticky="ew")

        self.stop_btn = ctk.CTkButton(self.controls_subframe, text="STOP", command=self.stop_validation, fg_color=ACCENT_ERROR, text_color=TEXT_MAIN, hover_color="#F87171", state="disabled")
        self.stop_btn.grid(row=0, column=1, padx=(5, 0), sticky="ew")

    def _build_main_workspace(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=20)
        
        self.main_frame.grid_rowconfigure(2, weight=1)
        self.main_frame.grid_columnconfigure(0, weight=1)

        self.dashboard_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.dashboard_frame.grid(row=0, column=0, sticky="ew", pady=(0, 20))
        self.dashboard_frame.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)

        self._create_stat_card(self.dashboard_frame, 0, "Total Unique", "0", TEXT_MAIN)
        self._create_stat_card(self.dashboard_frame, 1, "Valid Emails", "0", ACCENT_SUCCESS)
        self._create_stat_card(self.dashboard_frame, 2, "Invalid / Bounced", "0", ACCENT_ERROR)
        self._create_stat_card(self.dashboard_frame, 3, "Spam / Catch-All", "0", ACCENT_WARNING)
        self._create_stat_card(self.dashboard_frame, 4, "Unknown / Timeout", "0", "#94A3B8")

        self.progress_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.progress_frame.grid(row=1, column=0, sticky="ew", pady=(0, 20))
        
        self.progress_text_frame = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        self.progress_text_frame.pack(fill="x", pady=(0, 5))
        
        self.progress_lbl = ctk.CTkLabel(self.progress_text_frame, text="Processing... 0 / 0", text_color=TEXT_MAIN)
        self.progress_lbl.pack(side="left")
        
        self.percent_lbl = ctk.CTkLabel(self.progress_text_frame, text="0%", text_color=ACCENT_PRIMARY, font=ctk.CTkFont(weight="bold"))
        self.percent_lbl.pack(side="right")

        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, height=6, fg_color=BORDER, progress_color=ACCENT_PRIMARY)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x")

        self.tabview = ctk.CTkTabview(self.main_frame, fg_color=BG_CARD_1, border_color=BORDER, border_width=1, segmented_button_fg_color=BG_CARD_2, segmented_button_selected_color=ACCENT_PRIMARY, segmented_button_selected_hover_color="#60A5FA", segmented_button_unselected_color=BG_CARD_1, text_color=TEXT_MAIN)
        self.tabview.grid(row=2, column=0, sticky="nsew")
        
        self.tab_terminal = self.tabview.add("Terminal Logs")
        self.tab_table = self.tabview.add("Results Table")

        self.tab_terminal.grid_rowconfigure(0, weight=1)
        self.tab_terminal.grid_columnconfigure(0, weight=1)
        self.terminal_box = ctk.CTkTextbox(self.tab_terminal, fg_color=BG_CARD_2, text_color=TEXT_MAIN, font=ctk.CTkFont(family="Consolas", size=12), border_color=BORDER, border_width=1)
        self.terminal_box.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        self.terminal_box.tag_config("info", foreground=TEXT_MUTED)
        self.terminal_box.tag_config("valid", foreground=ACCENT_SUCCESS)
        self.terminal_box.tag_config("trap", foreground=ACCENT_WARNING)
        self.terminal_box.tag_config("dead", foreground=ACCENT_ERROR)
        
        # Setup ttk.Treeview for Data Grid
        self.tab_table.grid_rowconfigure(0, weight=1)
        self.tab_table.grid_columnconfigure(0, weight=1)
        
        # Стилизация таблицы в премиальном стиле 3-го скриншота (Deep Dark Blue)
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", 
                        background="#090E17", 
                        foreground="#E2E8F0", 
                        rowheight=28, 
                        fieldbackground="#090E17", 
                        borderwidth=0, 
                        font=("Inter", 10))
        style.configure("Treeview.Heading", 
                        background="#131B2F", 
                        foreground="#FFFFFF", 
                        font=("Inter", 10, "bold"),
                        borderwidth=1,
                        relief="flat")
        style.map("Treeview.Heading", background=[('active', '#1E293B')])
        style.map('Treeview', background=[('selected', '#3B82F6')])

        # Создаем специальный фрейм, чтобы таблица и скроллбар жили вместе
        self.table_frame = ctk.CTkFrame(self.tab_table, fg_color="transparent")
        self.table_frame.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        columns = ("email", "status", "reason", "mx")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        
        self.tree.heading("email", text="Email", anchor="w")
        self.tree.heading("status", text="Status", anchor="center")
        self.tree.heading("reason", text="Reason", anchor="w")
        self.tree.heading("mx", text="MX-Record", anchor="w")
        
        self.tree.column("email", width=280, anchor="w")
        self.tree.column("status", width=120, anchor="center")
        self.tree.column("reason", width=250, anchor="w")
        self.tree.column("mx", width=200, anchor="w")
        
        self.tree.grid(row=0, column=0, sticky="nsew")

        # Добавляем современный кастомный скроллбар справа от таблицы (Сделан ЯРКИМ, чтобы его было видно)
        self.scrollbar = ctk.CTkScrollbar(self.table_frame, orientation="vertical", command=self.tree.yview, fg_color="transparent", button_color="#3B82F6", button_hover_color="#60A5FA")
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.grid(row=0, column=1, sticky="ns")

    def _create_stat_card(self, parent, col, title, value, val_color):
        card = ctk.CTkFrame(parent, fg_color=BG_CARD_1, border_color=BORDER, border_width=1, corner_radius=8)
        card.grid(row=0, column=col, sticky="ew", padx=5)
        
        lbl_title = ctk.CTkLabel(card, text=title, text_color=TEXT_MUTED, font=ctk.CTkFont(size=12))
        lbl_title.pack(pady=(15, 5), padx=15, anchor="w")
        
        lbl_val = ctk.CTkLabel(card, text=value, text_color=val_color, font=ctk.CTkFont(size=24, weight="bold"))
        lbl_val.pack(pady=(0, 15), padx=15, anchor="w")
        
        setattr(self, f"stat_{col}", lbl_val)

    def update_threads_label(self, value):
        self.threads_lbl.configure(text=f"Threads: {int(value)}")
        
    def update_timeout_label(self, value):
        self.timeout_lbl.configure(text=f"Timeout: {int(value)}s")

    def load_file(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filepath:
            with open(filepath, "r", encoding="utf-8") as f:
                self.raw_emails = [line.strip() for line in f if line.strip()]
            self.loaded_lbl.configure(text=f"Loaded: {len(self.raw_emails)} emails")
            self.stat_0.configure(text=str(len(self.raw_emails)))
            self.safe_log(f"[INFO] Успешно загружено {len(self.raw_emails)} строк из файла.", "info")

    def load_proxies(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filepath:
            with open(filepath, "r", encoding="utf-8") as f:
                raw_proxies = [line.strip() for line in f if line.strip()]
                
            self.proxies = []
            for p in raw_proxies:
                p_lower = p.lower()
                # Жестко отсеиваем все протоколы, кроме socks5
                if p_lower.startswith("http://") or p_lower.startswith("https://") or p_lower.startswith("socks4://"):
                    continue
                self.proxies.append(p)
                
            ignored_count = len(raw_proxies) - len(self.proxies)
            self.loaded_proxies_lbl.configure(text=f"Proxies: {len(self.proxies)}")
            
            self.safe_log(f"[INFO] Успешно загружено {len(self.proxies)} SOCKS5 прокси-серверов.", "info")
            if ignored_count > 0:
                self.safe_log(f"[WARNING] Отброшено {ignored_count} прокси (HTTP/HTTPS/SOCKS4).", "trap")

    def start_validation(self):
        if not self.raw_emails:
            self.safe_log("[DEAD] Ошибка: Загрузите базу перед стартом!", "dead")
            return
            
        self.start_btn.configure(state="disabled", fg_color=BORDER, text_color=TEXT_MUTED)
        self.pause_btn.configure(state="normal")
        self.stop_btn.configure(state="normal")
        self.progress_bar.configure(progress_color=ACCENT_PRIMARY)
        
        # Сброс статистики
        self.stats = {"valid": 0, "invalid": 0, "spam": 0, "unknown": 0}
        self.stat_1.configure(text="0")
        self.stat_2.configure(text="0")
        self.stat_3.configure(text="0")
        self.stat_4.configure(text="0")
        
        # Очистка таблицы
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        self.terminal_box.delete("1.0", "end")
        self.safe_log("[INFO] Инициализация конвейера валидации...", "info")

        threads = int(self.threads_slider.get())
        timeout = int(self.timeout_slider.get())
        
        self.pipeline.start(
            raw_emails=self.raw_emails,
            threads=threads,
            timeout=timeout,
            fix_typos=True,
            check_spam=True,
            deep_ping=True,
            enable_ai=self.chk_ai.get() == 1,
            proxies=self.proxies
        )

    def pause_validation(self):
        is_paused = self.pipeline.pause()
        if is_paused:
            self.pause_btn.configure(text="RESUME", fg_color=ACCENT_SUCCESS)
            self.safe_log("[INFO] Процесс приостановлен (PAUSE).", "info")
        else:
            self.pause_btn.configure(text="PAUSE", fg_color=ACCENT_WARNING)
            self.safe_log("[INFO] Процесс возобновлен (RESUMED).", "info")

    def stop_validation(self):
        self.pipeline.stop()
        self.safe_log("[INFO] Процесс остановлен пользователем (STOP).", "info")
        self.on_pipeline_complete()

    # --- Thread-Safe методы обновления интерфейса ---
    def safe_log(self, message, tag="info"):
        self.after(0, lambda: self._update_log(message, tag))
        
    def _update_log(self, message, tag):
        self.terminal_box.insert("end", message + "\n", tag)
        self.terminal_box.see("end")

    def safe_update_unique_count(self, count):
        self.after(0, lambda: self.stat_0.configure(text=str(count)))

    def safe_update_progress(self, current, total):
        self.after(0, lambda: self._update_progress_ui(current, total))
        
    def _update_progress_ui(self, current, total):
        pct = int((current / total) * 100) if total > 0 else 0
        self.progress_lbl.configure(text=f"Processing... {current} / {total}")
        self.percent_lbl.configure(text=f"{pct}%")
        self.progress_bar.set(pct / 100.0)
        if pct == 100:
            self.progress_bar.configure(progress_color=ACCENT_SUCCESS)

    def safe_add_result(self, email, status, reason, mx):
        self.after(0, lambda: self._add_result_ui(email, status, reason, mx))
        
    def _add_result_ui(self, email, status, reason, mx):
        self.tree.insert("", "end", values=(email, status, reason, mx))
        
        # Обновление дашборда
        if status == "Valid":
            self.stats["valid"] += 1
            self.stat_1.configure(text=str(self.stats["valid"]))
            self.safe_log(f"[VALID] {email} -> {reason}", "valid")
        elif "Trap" in status or "Disposable" in status:
            self.stats["spam"] += 1
            self.stat_3.configure(text=str(self.stats["spam"]))
            self.safe_log(f"[TRAP] {email} -> {reason}", "trap")
        elif status == "Risky":
            self.stats["spam"] += 1
            self.stat_3.configure(text=str(self.stats["spam"]))
            self.safe_log(f"[RISKY] {email} -> {reason}", "trap")
        elif status == "Unknown":
            if "unknown" not in self.stats: self.stats["unknown"] = 0
            self.stats["unknown"] += 1
            self.stat_4.configure(text=str(self.stats["unknown"]))
            self.safe_log(f"[UNKNOWN] {email} -> {reason}", "trap")
        elif status == "Unverified":
            # Не засчитываем как мертвые, просто логируем пропуск
            self.safe_log(f"[SKIP] {email} -> {reason}", "info")
        else:
            self.stats["invalid"] += 1
            self.stat_2.configure(text=str(self.stats["invalid"]))
            self.safe_log(f"[DEAD] {email} -> {reason}", "dead")

    def on_pipeline_complete(self):
        self.after(0, self._reset_ui_after_complete)
        
    def _reset_ui_after_complete(self):
        self.start_btn.configure(state="normal", fg_color=ACCENT_PRIMARY, text_color=TEXT_MAIN)
        self.pause_btn.configure(state="disabled", text="PAUSE", fg_color=ACCENT_WARNING)
        self.stop_btn.configure(state="disabled")
        self.safe_log("[INFO] Валидация базы полностью завершена.", "info")
