# ui/gui.py
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
import psutil
import socket
import os
from ui.colors import *
from core.pipeline import ValidationPipeline

class ProxyHunterInputSelector(ctk.CTkFrame):
    def __init__(self, parent, label_text, button_text, command=None, on_paste=None):
        super().__init__(parent, fg_color="transparent")
        
        self.command = command
        self.on_paste = on_paste
        
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", pady=(0, 5))
        
        self.label = ctk.CTkLabel(self.header_frame, text=label_text, text_color=TEXT_MUTED, font=ctk.CTkFont(size=12))
        self.label.pack(side="left")
        
        self.seg_btn = ctk.CTkSegmentedButton(self.header_frame, values=["Файл", "Текст"], command=self._switch_mode, height=22, fg_color=BG_CARD_2, selected_color=ACCENT_PRIMARY, selected_hover_color="#60A5FA", unselected_color=BG_CARD_2, unselected_hover_color=BORDER, text_color=TEXT_MAIN, font=ctk.CTkFont(size=11))
        self.seg_btn.pack(side="right")
        self.seg_btn.set("Файл")
        
        self.file_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.file_frame.pack(fill="x")
        
        self.entry = ctk.CTkEntry(self.file_frame, fg_color=BG_CARD_2, border_color=BORDER, text_color=TEXT_MAIN, state="disabled", height=30)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        self.btn = ctk.CTkButton(self.file_frame, text=button_text, command=self._browse_file, fg_color=ACCENT_PRIMARY, hover_color="#2563EB", text_color="#FFFFFF", width=70, height=30, corner_radius=6)
        self.btn.pack(side="right")
        
        self.text_frame = ctk.CTkFrame(self, fg_color="transparent")
        
        self.textbox = ctk.CTkTextbox(self.text_frame, height=80, fg_color=BG_CARD_2, border_color=BORDER, border_width=1, text_color=TEXT_MAIN, font=ctk.CTkFont(size=11))
        self.textbox.pack(fill="x")
        self.textbox.bind("<KeyRelease>", self._text_modified)
        
    def _switch_mode(self, mode):
        if mode == "Файл":
            self.text_frame.pack_forget()
            self.file_frame.pack(fill="x")
        else:
            self.file_frame.pack_forget()
            self.text_frame.pack(fill="x")
            
    def _browse_file(self):
        if self.command:
            self.command()
            
    def _text_modified(self, event):
        if self.on_paste:
            text = self.textbox.get("1.0", "end")
            self.on_paste(text)
            
    def set_text(self, text):
        self.entry.configure(state="normal")
        self.entry.delete(0, "end")
        self.entry.insert(0, text)
        self.entry.configure(state="disabled")

class ProxyHunterSlider(ctk.CTkFrame):
    def __init__(self, parent, label_text, from_, to, initial, command=None):
        super().__init__(parent, fg_color="transparent")
        self.command = command
        self.from_ = from_
        self.to = to
        self.val = initial
        
        self.top_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.top_frame.pack(fill="x", pady=(0, 5))
        
        self.label = ctk.CTkLabel(self.top_frame, text=label_text, text_color=TEXT_MUTED, font=ctk.CTkFont(size=12))
        self.label.pack(side="left")
        
        self.controls_frame = ctk.CTkFrame(self.top_frame, fg_color="transparent")
        self.controls_frame.pack(side="right")
        
        self.btn_minus = ctk.CTkButton(self.controls_frame, text="-", width=26, height=26, corner_radius=6, fg_color=BG_CARD_2, hover_color=BORDER, text_color=TEXT_MAIN, font=ctk.CTkFont(weight="bold", size=14), command=self._minus)
        self.btn_minus.pack(side="left", padx=(0, 4))
        
        self.entry = ctk.CTkEntry(self.controls_frame, width=50, height=26, justify="center", fg_color=BG_CARD_2, border_color=BORDER, text_color=ACCENT_PRIMARY, font=ctk.CTkFont(weight="bold"))
        self.entry.insert(0, str(int(initial)))
        self.entry.pack(side="left", padx=0)
        self.entry.bind("<Return>", self._manual_entry)
        
        self.btn_plus = ctk.CTkButton(self.controls_frame, text="+", width=26, height=26, corner_radius=6, fg_color=BG_CARD_2, hover_color=BORDER, text_color=TEXT_MAIN, font=ctk.CTkFont(weight="bold", size=14), command=self._plus)
        self.btn_plus.pack(side="left", padx=(4, 0))
        
        self.slider = ctk.CTkSlider(self, from_=from_, to=to, height=12, fg_color=BG_CARD_2, progress_color=ACCENT_PRIMARY, button_color=ACCENT_PRIMARY, button_hover_color="#60A5FA", command=self._slider_moved)
        self.slider.set(initial)
        self.slider.pack(fill="x")
        
    def _minus(self):
        self.val = max(self.from_, self.val - 1)
        self._update_all()
        
    def _plus(self):
        self.val = min(self.to, self.val + 1)
        self._update_all()
        
    def _slider_moved(self, value):
        self.val = int(value)
        self.entry.delete(0, "end")
        self.entry.insert(0, str(self.val))
        if self.command:
            self.command(self.val)
            
    def _manual_entry(self, event=None):
        try:
            val = int(self.entry.get())
            self.val = max(self.from_, min(self.to, val))
        except ValueError:
            pass
        self._update_all()
        
    def _update_all(self):
        self.entry.delete(0, "end")
        self.entry.insert(0, str(int(self.val)))
        self.slider.set(self.val)
        if self.command:
            self.command(self.val)

    def get(self):
        return self.val

    def set(self, val):
        self.val = val
        self._update_all()


class ValidatorApp(ctk.CTk):
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
        
        self.raw_emails = []
        self.proxies = []
        self.stats = {"valid": 0, "invalid": 0, "spam": 0, "unknown": 0}
        self.results_data = []
        
        self.pipeline = ValidationPipeline(callbacks={
            'on_log': self.safe_log,
            'on_progress': self.safe_update_progress,
            'on_result': self.safe_add_result,
            'on_complete': self.on_pipeline_complete,
            'on_unique_count': self.safe_update_unique_count,
            'on_proxies_tested': self.safe_update_proxies_count
        })

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0, minsize=300)
        self.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        self._build_main_workspace()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        if hasattr(self, 'pipeline') and self.pipeline.is_running:
            if messagebox.askyesno("Внимание", "Проверка сейчас запущена!\nВы уверены, что хотите прервать работу и закрыть программу?"):
                self.pipeline.is_running = False
                self.destroy()
        else:
            self.destroy()

    def _build_sidebar(self):
        self.sidebar_container = ctk.CTkFrame(self, fg_color="transparent")
        self.sidebar_container.grid(row=0, column=0, sticky="nsew", padx=(15, 0), pady=15)
        
        self.sidebar = ctk.CTkFrame(self.sidebar_container, fg_color=BG_SIDEBAR, border_color=BORDER, border_width=1, corner_radius=12)
        self.sidebar.pack(fill="both", expand=True)

        header_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        header_frame.pack(fill="x", pady=20, padx=20)
        
        self.logo_label = ctk.CTkLabel(header_frame, text="⚙ Конфигурация", font=ctk.CTkFont(size=16, weight="bold"), text_color=TEXT_MAIN)
        self.logo_label.pack(anchor="w")
        
        self.separator = ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER)
        self.separator.pack(fill="x", padx=20, pady=(0, 20))

        self.db_selector = ProxyHunterInputSelector(self.sidebar, "База Email адресов:", "Выбрать", command=self.load_file, on_paste=self.on_emails_pasted)
        self.db_selector.pack(fill="x", padx=20, pady=(0, 5))
        
        self.loaded_lbl = ctk.CTkLabel(self.sidebar, text="Загружено: 0", text_color=TEXT_MUTED, font=ctk.CTkFont(size=11))
        self.loaded_lbl.pack(padx=20, anchor="w", pady=(0, 15))
        
        self.proxy_selector = ProxyHunterInputSelector(self.sidebar, "SOCKS5 Прокси:", "Выбрать", command=self.load_proxies, on_paste=self.on_proxies_pasted)
        self.proxy_selector.pack(fill="x", padx=20, pady=(0, 5))
        
        self.loaded_proxies_lbl = ctk.CTkLabel(self.sidebar, text="Прокси: 0", text_color=TEXT_MUTED, font=ctk.CTkFont(size=11))
        self.loaded_proxies_lbl.pack(padx=20, anchor="w", pady=(0, 25))

        self.max_hw_threads, self.hw_rank, self.hw_color = self.get_hardware_limits()

        self.threads_slider = ProxyHunterSlider(self.sidebar, "Потоки", 1, self.max_hw_threads, self.max_hw_threads)
        self.threads_slider.pack(fill="x", padx=20, pady=(0, 20))
        
        self.timeout_slider = ProxyHunterSlider(self.sidebar, "Таймаут (сек)", 1, 300, 5)
        self.timeout_slider.pack(fill="x", padx=20, pady=(0, 25))

        self.chk_ai = ctk.CTkSwitch(self.sidebar, text="Использовать AI фильтр (ML)", text_color=TEXT_MAIN, progress_color=ACCENT_PRIMARY, button_color="#FFFFFF", button_hover_color="#E2E8F0")
        self.chk_ai.select()
        self.chk_ai.pack(padx=20, anchor="w", pady=(0, 20))

    def _build_main_workspace(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=15)

        # 1. Верхняя шапка
        self.header_main = ctk.CTkFrame(self.main_frame, fg_color="transparent", height=50)
        self.header_main.pack(fill="x", pady=(0, 20))
        
        self.title_frame = ctk.CTkFrame(self.header_main, fg_color="transparent")
        self.title_frame.pack(side="left")
        
        self.shield_frame = ctk.CTkFrame(self.title_frame, fg_color=ACCENT_PRIMARY, corner_radius=10, width=40, height=40)
        self.shield_frame.pack(side="left", padx=(0, 10))
        self.shield_frame.pack_propagate(False)
        self.shield_lbl = ctk.CTkLabel(self.shield_frame, text="🛡", font=ctk.CTkFont(size=20), text_color="#FFFFFF")
        self.shield_lbl.place(relx=0.5, rely=0.5, anchor="center")
        
        self.title_text_frame = ctk.CTkFrame(self.title_frame, fg_color="transparent")
        self.title_text_frame.pack(side="left")
        
        self.main_title_lbl = ctk.CTkLabel(self.title_text_frame, text="EMAIL VALIDATOR PRO", font=ctk.CTkFont(size=22, weight="bold"), text_color=TEXT_MAIN)
        self.main_title_lbl.pack(anchor="w", pady=0)
        self.sub_title_lbl = ctk.CTkLabel(self.title_text_frame, text="v4.0 - Продвинутая фильтрация", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED)
        self.sub_title_lbl.pack(anchor="w", pady=0)
        
        self.controls_frame = ctk.CTkFrame(self.header_main, fg_color="transparent")
        self.controls_frame.pack(side="right")
        
        self.start_btn = ctk.CTkButton(self.controls_frame, text="▶", width=40, height=40, corner_radius=10, font=ctk.CTkFont(size=18), fg_color=ACCENT_PRIMARY, hover_color="#2563EB", text_color="#FFFFFF", command=self.start_validation)
        self.start_btn.pack(side="left", padx=(0, 8))
        
        self.pause_btn = ctk.CTkButton(self.controls_frame, text="⏸", width=40, height=40, corner_radius=10, font=ctk.CTkFont(size=18), fg_color=ACCENT_WARNING, hover_color="#D97706", text_color="#000000", command=self.pause_validation)
        self.pause_btn.pack(side="left", padx=(0, 8))
        
        self.stop_btn = ctk.CTkButton(self.controls_frame, text="⏹", width=40, height=40, corner_radius=10, font=ctk.CTkFont(size=18), fg_color=ACCENT_ERROR, hover_color="#DC2626", text_color="#FFFFFF", command=self.stop_validation)
        self.stop_btn.pack(side="left")

        # 2. Карточки статистики (2 строки)
        self.dashboard_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.dashboard_frame.pack(fill="x", pady=(0, 20))
        self.dashboard_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="card")

        self._create_stat_card(self.dashboard_frame, 0, 0, "Всего собрано", "0", ACCENT_PRIMARY, "🌐")
        self._create_stat_card(self.dashboard_frame, 0, 1, "Валидные", "0", ACCENT_SUCCESS, "⚡")
        self._create_stat_card(self.dashboard_frame, 0, 2, "Невалидные", "0", ACCENT_ERROR, "🗑")
        self._create_stat_card(self.dashboard_frame, 1, 0, "Спам / Ловушки", "0", ACCENT_WARNING, "⚠️")
        self._create_stat_card(self.dashboard_frame, 1, 1, "Неизвестно", "0", TEXT_MUTED, "❓")

        # 3. Прогресс-бар
        self.progress_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.progress_frame.pack(fill="x", pady=(0, 20))
        
        self.progress_text_frame = ctk.CTkFrame(self.progress_frame, fg_color="transparent")
        self.progress_text_frame.pack(fill="x", pady=(0, 5))
        
        self.progress_lbl = ctk.CTkLabel(self.progress_text_frame, text="Проверка... (0/0)", text_color=TEXT_MUTED, font=ctk.CTkFont(size=12))
        self.progress_lbl.pack(side="left")
        
        self.percent_lbl = ctk.CTkLabel(self.progress_text_frame, text="0%", text_color=ACCENT_PRIMARY, font=ctk.CTkFont(size=12, weight="bold"))
        self.percent_lbl.pack(side="right")

        self.progress_bar = ctk.CTkProgressBar(self.progress_frame, height=8, corner_radius=4, fg_color=BORDER, progress_color=ACCENT_PRIMARY)
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x")

        # 4. Основной контейнер (Терминал / Таблица)
        self.bottom_container = ctk.CTkFrame(self.main_frame, fg_color="transparent", border_color=BORDER, border_width=1, corner_radius=12)
        self.bottom_container.pack(fill="both", expand=True)
        
        self.tabs_frame = ctk.CTkFrame(self.bottom_container, fg_color="transparent")
        self.tabs_frame.pack(fill="x", pady=(15, 10))
        
        self.tab_seg = ctk.CTkSegmentedButton(self.tabs_frame, values=["Терминал", "Результаты"], command=self._switch_tab, fg_color=BG_SIDEBAR, selected_color=ACCENT_PRIMARY, selected_hover_color="#60A5FA", unselected_color=BG_SIDEBAR, unselected_hover_color=BG_CARD_2, text_color=TEXT_MAIN)
        self.tab_seg.set("Терминал")
        self.tab_seg.pack(anchor="center")
        
        self.terminal_view = ctk.CTkFrame(self.bottom_container, fg_color="transparent")
        self.table_view = ctk.CTkFrame(self.bottom_container, fg_color="transparent")
        
        self.terminal_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self.terminal_header = ctk.CTkFrame(self.terminal_view, fg_color="transparent")
        self.terminal_header.pack(fill="x", pady=(0, 10))
        
        self.copy_logs_btn = ctk.CTkButton(self.terminal_header, text="📋 Копировать", width=120, height=28, corner_radius=6, font=ctk.CTkFont(size=12), command=self.copy_terminal_logs, fg_color=ACCENT_PRIMARY, hover_color="#2563EB", text_color="#FFFFFF")
        self.copy_logs_btn.pack(side="right")
        
        self.terminal_box = ctk.CTkTextbox(self.terminal_view, fg_color=BG_CARD_2, text_color=TEXT_MAIN, font=ctk.CTkFont(family="Consolas", size=12), border_width=0, corner_radius=8)
        self.terminal_box.pack(fill="both", expand=True)
        
        self.terminal_box.tag_config("info", foreground=TEXT_MUTED)
        self.terminal_box.tag_config("valid", foreground=ACCENT_SUCCESS)
        self.terminal_box.tag_config("trap", foreground=ACCENT_WARNING)
        self.terminal_box.tag_config("dead", foreground=ACCENT_ERROR)
        self.terminal_box.configure(state="disabled")

        self.table_export_frame = ctk.CTkFrame(self.table_view, fg_color="transparent")
        self.table_export_frame.pack(fill="x", pady=(0, 10))
        
        self.filter_var = ctk.StringVar(value="All Results")
        self.filter_dropdown = ctk.CTkOptionMenu(self.table_export_frame, variable=self.filter_var, values=["All Results", "Valid", "Invalid/Bounced", "Spam/Catch-All", "Unknown"], fg_color=BG_CARD_2, button_color=BORDER, button_hover_color=ACCENT_PRIMARY, height=28)
        self.filter_dropdown.pack(side="left", padx=(0, 10))
        
        self.export_btn = ctk.CTkButton(self.table_export_frame, text="💾 Экспорт", command=self.export_results, width=100, height=28, fg_color=ACCENT_SUCCESS, hover_color="#22C55E", corner_radius=6)
        self.export_btn.pack(side="left")
        
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview", 
                        background=BG_CARD_2, 
                        foreground=TEXT_MAIN, 
                        rowheight=28, 
                        fieldbackground=BG_CARD_2, 
                        borderwidth=0, 
                        font=("Inter", 10))
        style.configure("Treeview.Heading", 
                        background=BG_SIDEBAR, 
                        foreground="#FFFFFF", 
                        font=("Inter", 10, "bold"),
                        borderwidth=1,
                        relief="flat")
        style.map("Treeview.Heading", background=[('active', BORDER)])
        style.map('Treeview', background=[('selected', ACCENT_PRIMARY)])

        self.table_frame = ctk.CTkFrame(self.table_view, fg_color="transparent")
        self.table_frame.pack(fill="both", expand=True)
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        columns = ("email", "status", "reason", "mx")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        self.tree.heading("email", text="Email", anchor="w")
        self.tree.heading("status", text="Status", anchor="center")
        self.tree.heading("reason", text="Reason", anchor="w")
        self.tree.heading("mx", text="MX-Record", anchor="w")
        
        self.tree.column("email", width=300, minwidth=200, stretch=True, anchor="w")
        self.tree.column("status", width=120, minwidth=100, stretch=False, anchor="center")
        self.tree.column("reason", width=300, minwidth=200, stretch=True, anchor="w")
        self.tree.column("mx", width=250, minwidth=150, stretch=True, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")

        self.scrollbar = ctk.CTkScrollbar(self.table_frame, orientation="vertical", command=self.tree.yview, fg_color="transparent", button_color=ACCENT_PRIMARY, button_hover_color="#60A5FA")
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.grid(row=0, column=1, sticky="ns")

    def _switch_tab(self, value):
        if value == "Терминал":
            self.table_view.pack_forget()
            self.terminal_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        else:
            self.terminal_view.pack_forget()
            self.table_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def _create_stat_card(self, parent, row, col, title, value, val_color, icon):
        pad_x = (0, 10) if col < 2 else (0, 0)
        pad_y = (0, 10) if row == 0 else (0, 0)
        
        card = ctk.CTkFrame(parent, fg_color=BG_CARD_1, border_color=BORDER, border_width=1, corner_radius=10)
        card.grid(row=row, column=col, sticky="nsew", padx=pad_x, pady=pad_y)
        
        inner = ctk.CTkFrame(card, fg_color="transparent")
        inner.pack(fill="both", expand=True, padx=15, pady=15)
        
        title_frame = ctk.CTkFrame(inner, fg_color="transparent")
        title_frame.pack(fill="x", anchor="w")
        
        lbl_icon = ctk.CTkLabel(title_frame, text=icon, font=ctk.CTkFont(size=14), text_color=TEXT_MUTED)
        lbl_icon.pack(side="left", padx=(0, 8))
        
        lbl_title = ctk.CTkLabel(title_frame, text=title, text_color=TEXT_MUTED, font=ctk.CTkFont(size=13))
        lbl_title.pack(side="left")
        
        lbl_val = ctk.CTkLabel(inner, text=value, text_color=val_color, font=ctk.CTkFont(size=36, weight="bold"))
        lbl_val.pack(anchor="w", pady=(10, 0))
        
        idx = row * 3 + col
        setattr(self, f"stat_{idx}", lbl_val)

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
        filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filepath:
            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if file_size_mb > 100:
                if not messagebox.askyesno("Огромный файл", f"Размер файла: {file_size_mb:.1f} МБ.\n\nЗагрузка гигантских файлов целиком в ОЗУ может привести к зависанию.\nПродолжить?"):
                    return
            with open(filepath, "r", encoding="utf-8") as f:
                self.raw_emails = [line.strip() for line in f if line.strip()]
            if not self.raw_emails:
                messagebox.showerror("Ошибка загрузки", "Файл пуст или содержит только пустые строки!")
                self.db_selector.set_text("")
                self.loaded_lbl.configure(text="Загружено: 0")
                return
            self.db_selector.set_text(filepath)
            self.loaded_lbl.configure(text=f"Загружено: {len(self.raw_emails)}")
            self.safe_log(f"[INFO] Успешно загружено {len(self.raw_emails)} строк из файла.", "info")

    def on_emails_pasted(self, text):
        lines = [line.strip() for line in text.split("\n") if line.strip()]
        self.raw_emails = lines
        self.loaded_lbl.configure(text=f"Загружено: {len(self.raw_emails)}")

    def load_proxies(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filepath:
            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if file_size_mb > 50:
                if not messagebox.askyesno("Огромный файл", f"Размер файла прокси: {file_size_mb:.1f} МБ.\nПродолжить?"):
                    return
            with open(filepath, "r", encoding="utf-8") as f:
                raw_proxies = list(set([line.strip() for line in f if line.strip()]))
            self.proxies = []
            for p in raw_proxies:
                p_lower = p.lower()
                if p_lower.startswith("http://") or p_lower.startswith("https://") or p_lower.startswith("socks4://"):
                    continue
                self.proxies.append(p)
            ignored_count = len(raw_proxies) - len(self.proxies)
            if not self.proxies:
                if ignored_count > 0:
                    messagebox.showerror("Ошибка прокси", "В файле не найдено SOCKS5 прокси!\nВсе адреса были отброшены.")
                else:
                    messagebox.showerror("Ошибка загрузки", "Файл с прокси абсолютно пуст!")
                self.proxy_selector.set_text("")
                self.loaded_proxies_lbl.configure(text="Прокси: 0")
                return
            self.proxy_selector.set_text(filepath)
            self.loaded_proxies_lbl.configure(text=f"Прокси: {len(self.proxies)}")
            self.safe_log(f"[INFO] Успешно загружено {len(self.proxies)} SOCKS5 прокси-серверов.", "info")
            if ignored_count > 0:
                self.safe_log(f"[WARNING] Отброшено {ignored_count} прокси (HTTP/HTTPS/SOCKS4).", "trap")

    def on_proxies_pasted(self, text):
        raw_proxies = list(set([line.strip() for line in text.split("\n") if line.strip()]))
        self.proxies = []
        for p in raw_proxies:
            p_lower = p.lower()
            if p_lower.startswith("http://") or p_lower.startswith("https://") or p_lower.startswith("socks4://"):
                continue
            self.proxies.append(p)
        self.loaded_proxies_lbl.configure(text=f"Прокси: {len(self.proxies)}")

    def start_validation(self):
        if not self.raw_emails:
            self.safe_log("[DEAD] Ошибка: Загрузите базу перед стартом!", "dead")
            return
        if not self.proxies:
            self.safe_log("[DEAD] Ошибка: Загрузите прокси перед стартом!", "dead")
            return
        try:
            socket.create_connection(("8.8.8.8", 53), timeout=1.5)
        except OSError:
            messagebox.showerror("Ошибка сети", "Нет подключения к интернету!\nПроверьте ваше сетевое подключение.")
            self.safe_log("[DEAD] Ошибка: Отсутствует подключение к интернету.", "dead")
            return
            
        pass
        
        self.stats = {"valid": 0, "invalid": 0, "spam": 0, "unknown": 0}
        self.results_data.clear()
        
        self.stat_0.configure(text="0")
        self.stat_1.configure(text="0")
        self.stat_2.configure(text="0")
        self.stat_3.configure(text="0")
        self.stat_4.configure(text="0")
        
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        self.db_selector.btn.configure(state="disabled")
        self.db_selector.textbox.configure(state="disabled")
        self.db_selector.seg_btn.configure(state="disabled")
        self.proxy_selector.btn.configure(state="disabled")
        self.proxy_selector.textbox.configure(state="disabled")
        self.proxy_selector.seg_btn.configure(state="disabled")
        self.chk_ai.configure(state="disabled")
            
        self.terminal_box.configure(state="normal")
        self.terminal_box.delete("1.0", "end")
        self.terminal_box.configure(state="disabled")
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
            self.pause_btn.configure(text="▶", fg_color=ACCENT_SUCCESS)
            self.safe_log("[INFO] Процесс приостановлен (PAUSE).", "info")
        else:
            self.pause_btn.configure(text="⏸", fg_color=ACCENT_WARNING)
            self.safe_log("[INFO] Процесс возобновлен (RESUMED).", "info")

    def stop_validation(self):
        self.pipeline.stop()
        self.safe_log("[INFO] Процесс остановлен пользователем (STOP).", "info")
        self.on_pipeline_complete()

    def safe_log(self, message, tag="info"):
        self.after(0, lambda: self._update_log(message, tag))
        
    def _update_log(self, message, tag):
        self.terminal_box.configure(state="normal")
        self.terminal_box.insert("end", message + "\n", tag)
        self.terminal_box.see("end")
        self.terminal_box.configure(state="disabled")

    def safe_update_unique_count(self, count):
        self.after(0, lambda: self.stat_0.configure(text=str(count)))

    def safe_update_proxies_count(self, live_count, total_count):
        self.after(0, lambda: self.loaded_proxies_lbl.configure(text=f"Прокси: {live_count} / {total_count} (Рабочих)"))

    def safe_update_progress(self, current, total):
        self.after(0, lambda: self._update_progress_ui(current, total))
        
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

    def safe_add_result(self, email, status, reason, mx):
        self.after(0, lambda: self._add_result_ui(email, status, reason, mx))
        
    def _add_result_ui(self, email, status, reason, mx):
        self.results_data.append({"email": email, "status": status, "reason": reason, "mx": mx})
        self.tree.insert("", "end", values=(email, status, reason, mx))
        
        if status == "Valid":
            self.stats["valid"] += 1
            self.stat_1.configure(text=str(self.stats["valid"]))
            self.safe_log(f"[VALID] {email} -> {reason}", "valid")
        elif "Trap" in status or "Disposable" in status or status == "Risky":
            self.stats["spam"] += 1
            self.stat_3.configure(text=str(self.stats["spam"]))
            self.safe_log(f"[{status.upper()}] {email} -> {reason}", "trap")
        elif status == "Unknown":
            if "unknown" not in self.stats: self.stats["unknown"] = 0
            self.stats["unknown"] += 1
            self.stat_4.configure(text=str(self.stats["unknown"]))
            self.safe_log(f"[UNKNOWN] {email} -> {reason}", "trap")
        elif status == "Unverified":
            self.safe_log(f"[SKIP] {email} -> {reason}", "info")
        else:
            self.stats["invalid"] += 1
            self.stat_2.configure(text=str(self.stats["invalid"]))
            self.safe_log(f"[DEAD] {email} -> {reason}", "dead")

    def on_pipeline_complete(self):
        self.after(0, self._reset_ui_after_complete)
        
    def _reset_ui_after_complete(self):
        self.pause_btn.configure(text="⏸")
        
        self.db_selector.btn.configure(state="normal")
        self.db_selector.textbox.configure(state="normal")
        self.db_selector.seg_btn.configure(state="normal")
        self.proxy_selector.btn.configure(state="normal")
        self.proxy_selector.textbox.configure(state="normal")
        self.proxy_selector.seg_btn.configure(state="normal")
        self.chk_ai.configure(state="normal")
        self.safe_log("[INFO] Валидация базы полностью завершена.", "info")

    def copy_terminal_logs(self):
        text = self.terminal_box.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Скопировано", "Логи терминала скопированы в буфер обмена.")

    def export_results(self):
        if not hasattr(self, 'results_data') or not self.results_data:
            messagebox.showwarning("Пусто", "Нет данных для экспорта.")
            return
            
        filter_val = self.filter_var.get()
        export_data = []
        for r in self.results_data:
            st = r["status"]
            if filter_val == "All Results":
                export_data.append(r)
            elif filter_val == "Valid" and st == "Valid":
                export_data.append(r)
            elif filter_val == "Invalid/Bounced" and "Invalid" in st:
                export_data.append(r)
            elif filter_val == "Spam/Catch-All" and ("Trap" in st or "Disposable" in st or "Risky" in st):
                export_data.append(r)
            elif filter_val == "Unknown" and st == "Unknown":
                export_data.append(r)
                
        if not export_data:
            messagebox.showwarning("Пусто", f"По фильтру '{filter_val}' не найдено ни одного адреса.")
            return
            
        file_types = [("Text File (Только Email)", "*.txt"), ("CSV File (Email+Причина+MX)", "*.csv")]
        default_name = f"results_{filter_val.replace('/', '_').lower()}"
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=file_types, initialfile=default_name)
        
        if filepath:
            try:
                with open(filepath, "w", encoding="utf-8") as f:
                    if filepath.endswith(".csv"):
                        f.write("Email,Status,Reason,MX-Record\n")
                        for r in export_data:
                            f.write(f"{r['email']},{r['status']},{r['reason']},{r['mx']}\n")
                    else:
                        for r in export_data:
                            f.write(f"{r['email']}\n")
                messagebox.showinfo("Успех", f"Успешно экспортировано {len(export_data)} строк!\nФайл: {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")
