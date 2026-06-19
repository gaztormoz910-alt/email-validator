# ui/gui.py
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
import psutil
import socket
import os
import re
from ui.colors import *
from core.pipeline import ValidationPipeline

def clean_input_line(line):
    # Убирает нумерацию типа "1. ", "2)", "1-й ", "100:", "1 ", оставляя только суть.
    return re.sub(r'^\d+[-.)\]:й]*\s+', '', line.strip())


class ProxyHunterInputSelector(ctk.CTkFrame):
    def __init__(self, parent, label_text, button_text, command=None, on_paste=None, on_clear=None):
        super().__init__(parent, fg_color="transparent")
        
        self.command = command
        self.on_paste = on_paste
        self.on_clear = on_clear
        
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.header_frame.pack(fill="x", pady=(0, 5))
        
        self.label = ctk.CTkLabel(self.header_frame, text=label_text, text_color=TEXT_MUTED, font=ctk.CTkFont(size=12))
        self.label.pack(side="left")
        
        self.seg_btn = ctk.CTkSegmentedButton(self.header_frame, values=["Файл", "Текст"], command=self._switch_mode, height=22, fg_color=BG_CARD_2, selected_color=ACCENT_PRIMARY, selected_hover_color="#60A5FA", unselected_color=BG_CARD_2, unselected_hover_color=BORDER, text_color=TEXT_MAIN, font=ctk.CTkFont(size=11))
        self.seg_btn.pack(side="right")
        self.seg_btn.set("Файл")
        
        self.clear_btn = ctk.CTkButton(self.header_frame, text="🗑", width=26, height=22, corner_radius=6, fg_color=BG_CARD_2, hover_color=ACCENT_ERROR, text_color=TEXT_MAIN, command=self._clear_data)
        self.clear_btn.pack(side="right", padx=(0, 5))
        
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
        
        # Explicit paste bindings for English
        self.textbox.bind("<Control-v>", self._paste)
        self.textbox.bind("<Control-V>", self._paste)
        self.textbox.bind("<Control-c>", self._copy_cyrillic)
        self.textbox.bind("<Control-C>", self._copy_cyrillic)
        self.textbox.bind("<Control-x>", self._cut_cyrillic)
        self.textbox.bind("<Control-X>", self._cut_cyrillic)
        self.textbox.bind("<Control-a>", self._select_all_cyrillic)
        self.textbox.bind("<Control-A>", self._select_all_cyrillic)

        # Generic binding for Russian layout compatibility
        self.textbox.bind("<Control-KeyPress>", self._handle_ctrl_keypress)
        
        # Right click menu
        self.textbox.bind("<Button-3>", self._show_menu)
        
    def _show_menu(self, event):
        # We can't easily do a native popup menu in CTk without tkinter.Menu, but tkinter.Menu looks bad.
        # Let's just use standard tkinter Menu for right click.
        import tkinter as tk
        m = tk.Menu(self.textbox, tearoff=0, bg=BG_CARD_2, fg=TEXT_MAIN, activebackground=ACCENT_PRIMARY)
        m.add_command(label="Вставить", command=self._paste_from_menu)
        m.add_command(label="Копировать", command=self._copy_from_menu)
        m.add_command(label="Выбрать все", command=self._select_all_from_menu)
        m.tk_popup(event.x_root, event.y_root)

    def _paste_from_menu(self):
        try:
            text = self.clipboard_get()
            cleaned_text = "\n".join([clean_input_line(line) for line in text.split("\n") if line.strip()])
            self.textbox.insert("insert", cleaned_text)
            self._text_modified(None)
        except Exception:
            pass

    def _copy_from_menu(self):
        try:
            text = self.textbox.get("sel.first", "sel.last")
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception:
            pass

    def _select_all_from_menu(self):
        self.textbox.tag_add("sel", "1.0", "end")

    def _paste(self, event):
        try:
            text = self.clipboard_get()
            cleaned_text = "\n".join([clean_input_line(line) for line in text.split("\n") if line.strip()])
            self.textbox.insert("insert", cleaned_text)
            self._text_modified(None)
            return "break"
        except Exception:
            pass

    def _copy_cyrillic(self, event):
        try:
            text = self.textbox.get("sel.first", "sel.last")
            self.clipboard_clear()
            self.clipboard_append(text)
            return "break"
        except Exception:
            pass

    def _cut_cyrillic(self, event):
        try:
            text = self.textbox.get("sel.first", "sel.last")
            self.clipboard_clear()
            self.clipboard_append(text)
            self.textbox.delete("sel.first", "sel.last")
            self._text_modified(None)
            return "break"
        except Exception:
            pass

    def _select_all_cyrillic(self, event):
        self.textbox.tag_add("sel", "1.0", "end")
        return "break"

    def _handle_ctrl_keypress(self, event):
        char = getattr(event, 'char', '').lower()
        if not char:
            return
            
        if char == 'м': # Paste
            return self._paste(event)
        elif char == 'с': # Copy
            return self._copy_cyrillic(event)
        elif char == 'ч': # Cut
            return self._cut_cyrillic(event)
        elif char == 'ф': # Select All
            return self._select_all_cyrillic(event)
        
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
            
    def configure(self, state):
        self.btn.configure(state=state)
        self.clear_btn.configure(state=state)
        self.seg_btn.configure(state=state)
        if state == "disabled":
            self.textbox.configure(state="disabled")
        else:
            self.textbox.configure(state="normal")

    def set_text(self, text):
        self.entry.configure(state="normal")
        self.entry.delete(0, "end")
        self.entry.insert(0, text)
        self.entry.configure(state="disabled")
        
    def _clear_data(self):
        self.set_text("")
        self.textbox.delete("1.0", "end")
        if self.on_clear:
            self.on_clear()
            
    def append_to_textbox(self, lines):
        if not lines: return
        self.textbox.insert("end", "\n".join(lines) + "\n")

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

    def configure(self, state):
        self.btn_minus.configure(state=state)
        self.btn_plus.configure(state=state)
        self.entry.configure(state=state)
        self.slider.configure(state=state)

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
        
        self.app_mode = "Валидатор"
        self.raw_emails = []
        self.proxies = []
        self.stats = {"valid": 0, "invalid": 0, "spam": 0, "unknown": 0}
        self.results_data = []
        
        self.parser_raw_dorks = []
        self.parser_proxies = []
        self.parser_results_data = []
        self.parser_pipeline = None
        
        import queue
        self.log_queue = queue.Queue()
        self.stats_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.result_queue = queue.Queue()
        self._poll_queues()
        

        self.pipeline = ValidationPipeline(callbacks={
            'on_log': self.safe_log,
            'on_progress': self.safe_update_progress,
            'on_result': self.safe_add_result,
            'on_complete': self.on_pipeline_complete,
            'on_unique_count': self.safe_update_unique_count,
            'on_proxies_tested': self.safe_update_proxies_count
        })

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=0, minsize=550)
        self.grid_columnconfigure(1, weight=1)

        self._build_sidebar()
        self._build_main_workspace()
        self.protocol("WM_DELETE_WINDOW", self.on_closing)

    def on_closing(self):
        import os
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

    def _build_sidebar(self):
        self.sidebar_container = ctk.CTkFrame(self, fg_color="transparent")
        self.sidebar_container.grid(row=0, column=0, sticky="nsew", padx=(15, 0), pady=15)
        
        self.sidebar = ctk.CTkFrame(self.sidebar_container, fg_color=BG_SIDEBAR, border_color=BORDER, border_width=1, corner_radius=12)
        self.sidebar.pack(fill="both", expand=True)

        header_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        header_frame.pack(fill="x", pady=(20, 10), padx=20)
        
        self.logo_label = ctk.CTkLabel(header_frame, text="⚙ Конфигурация", font=ctk.CTkFont(size=16, weight="bold"), text_color=TEXT_MAIN)
        self.logo_label.pack(anchor="center", pady=(0, 10))

        self.mode_switcher = ctk.CTkSegmentedButton(
            header_frame, 
            values=["Валидатор", "Парсер"], 
            command=self._switch_app_mode,
            fg_color=BG_CARD_2, 
            selected_color=ACCENT_PRIMARY, 
            selected_hover_color="#60A5FA", 
            unselected_color=BG_CARD_2, 
            unselected_hover_color=BORDER, 
            text_color=TEXT_MAIN,
            font=ctk.CTkFont(size=12, weight="bold")
        )
        self.mode_switcher.set("Валидатор")
        self.mode_switcher.pack(fill="x")
        
        self.separator = ctk.CTkFrame(self.sidebar, height=1, fg_color=BORDER)
        self.separator.pack(fill="x", padx=20, pady=(0, 20))

        # --- VALIDATOR SIDEBAR CONTENT ---
        self.validator_sidebar_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        self.validator_sidebar_frame.pack(fill="both", expand=True)

        self.db_selector = ProxyHunterInputSelector(self.validator_sidebar_frame, "База Email адресов:", "Выбрать", command=self.load_file, on_paste=self.on_emails_pasted, on_clear=self.clear_emails)
        self.db_selector.pack(fill="x", padx=20, pady=(0, 5))
        
        self.loaded_lbl = ctk.CTkLabel(self.validator_sidebar_frame, text="Загружено: 0", text_color=TEXT_MUTED, font=ctk.CTkFont(size=11))
        self.loaded_lbl.pack(padx=20, anchor="w", pady=(0, 15))
        
        self.proxy_selector = ProxyHunterInputSelector(self.validator_sidebar_frame, "SOCKS5 Прокси:", "Выбрать", command=self.load_proxies, on_paste=self.on_proxies_pasted, on_clear=self.clear_proxies)
        self.proxy_selector.pack(fill="x", padx=20, pady=(0, 5))
        
        self.loaded_proxies_lbl = ctk.CTkLabel(self.validator_sidebar_frame, text="Прокси: 0", text_color=TEXT_MUTED, font=ctk.CTkFont(size=11))
        self.loaded_proxies_lbl.pack(padx=20, anchor="w", pady=(0, 25))

        self.max_hw_threads, self.hw_rank, self.hw_color = self.get_hardware_limits()

        self.threads_slider = ProxyHunterSlider(self.validator_sidebar_frame, "Потоки", 1, self.max_hw_threads, self.max_hw_threads)
        self.threads_slider.pack(fill="x", padx=20, pady=(0, 20))
        
        self.timeout_slider = ProxyHunterSlider(self.validator_sidebar_frame, "Таймаут (сек)", 1, 300, 5)
        self.timeout_slider.pack(fill="x", padx=20, pady=(0, 25))

        self.chk_ai = ctk.CTkSwitch(self.validator_sidebar_frame, text="Использовать AI фильтр (ML)", text_color=TEXT_MAIN, progress_color=ACCENT_PRIMARY, button_color="#FFFFFF", button_hover_color="#E2E8F0")
        self.chk_ai.select()
        self.chk_ai.pack(padx=20, anchor="w", pady=(0, 20))
        
        # --- PARSER SIDEBAR CONTENT ---
        self.parser_sidebar_frame = ctk.CTkFrame(self.sidebar, fg_color="transparent")
        
        self.dork_selector = ProxyHunterInputSelector(self.parser_sidebar_frame, "Dork-запросы:", "Выбрать", command=self.load_dorks, on_paste=self.on_dorks_pasted, on_clear=self.clear_dorks)
        self.dork_selector.pack(fill="x", padx=20, pady=(0, 5))
        
        self.loaded_dorks_lbl = ctk.CTkLabel(self.parser_sidebar_frame, text="Загружено: 0", text_color=TEXT_MUTED, font=ctk.CTkFont(size=11))
        self.loaded_dorks_lbl.pack(padx=20, anchor="w", pady=(0, 15))
        
        self.parser_proxy_frame = ctk.CTkFrame(self.parser_sidebar_frame, fg_color="transparent")
        self.parser_proxy_frame.pack(fill="x", pady=0)
        
        self.parser_proxy_selector = ProxyHunterInputSelector(self.parser_proxy_frame, "SOCKS5 Прокси:", "Выбрать", command=self.load_parser_proxies, on_paste=self.on_parser_proxies_pasted, on_clear=self.clear_parser_proxies)
        self.parser_proxy_selector.pack(fill="x", padx=20, pady=(0, 5))
        
        self.loaded_parser_proxies_lbl = ctk.CTkLabel(self.parser_proxy_frame, text="Прокси: 0", text_color=TEXT_MUTED, font=ctk.CTkFont(size=11))
        self.loaded_parser_proxies_lbl.pack(padx=20, anchor="w", pady=(0, 20))

        self.engine_frame = ctk.CTkFrame(self.parser_sidebar_frame, fg_color="transparent")
        self.engine_frame.pack(fill="x", pady=0)

        self.engine_lbl = ctk.CTkLabel(self.engine_frame, text="Поисковик:", text_color=TEXT_MAIN, font=ctk.CTkFont(size=12))
        self.engine_lbl.pack(padx=20, anchor="w", pady=(0, 5))
        
        self.engine_var = ctk.StringVar(value="DuckDuckGo Lite")
        self.engine_selector = ctk.CTkOptionMenu(self.engine_frame, variable=self.engine_var, values=["DuckDuckGo Lite", "AOL (Tor)", "Yahoo", "Bing"], fg_color=BG_CARD_2, button_color=BORDER, button_hover_color=ACCENT_PRIMARY, command=self._on_engine_change)
        self.engine_selector.pack(fill="x", padx=20, pady=(0, 20))

        parser_max_threads = min(self.max_hw_threads, 500)
        self.parser_threads_slider = ProxyHunterSlider(self.parser_sidebar_frame, "Потоки (Dorks)", 1, parser_max_threads, parser_max_threads)
        self.parser_threads_slider.pack(fill="x", padx=20, pady=(0, 20))

        self.parser_timeout_slider = ProxyHunterSlider(self.parser_sidebar_frame, "Таймаут прокси (сек)", 1, 300, 5)
        self.parser_timeout_slider.pack(fill="x", padx=20, pady=(0, 20))

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
        tor_engines = ["AOL (Tor)"]
        if value in tor_engines:
            self.parser_proxy_frame.pack_forget()
            self.parser_proxy_selector.clear_btn.invoke() # Also clear the loaded proxies for safety
        else:
            self.parser_proxy_frame.pack(fill="x", before=self.engine_frame)
            
        if self.app_mode == "Парсер":
            self.sub_title_lbl.configure(text=f"{value} Dork Engine")

    def clear_emails(self):
        self.raw_emails.clear()
        self.loaded_lbl.configure(text="Загружено: 0")
        self.db_selector.set_text("")
        self.safe_log("[INFO] База Email адресов очищена.", "trap")
        
    def clear_proxies(self):
        self.proxies.clear()
        self.loaded_proxies_lbl.configure(text="Прокси: 0")
        self.proxy_selector.set_text("")
        self.safe_log("[INFO] SOCKS5 прокси очищены.", "trap")
        
    def clear_dorks(self):
        self.parser_raw_dorks.clear()
        self.loaded_dorks_lbl.configure(text="Загружено: 0")
        self.dork_selector.set_text("")
        if hasattr(self, 'safe_parser_log'):
            self.safe_parser_log("[INFO] Dork-запросы очищены.", "trap")
        
    def clear_parser_proxies(self):
        self.parser_proxies.clear()
        self.loaded_parser_proxies_lbl.configure(text="Прокси: 0")
        self.parser_proxy_selector.set_text("")
        if hasattr(self, 'safe_parser_log'):
            self.safe_parser_log("[INFO] SOCKS5 прокси для парсера очищены.", "trap")

    # --- DUMMY HANDLERS FOR PARSER (to be fully implemented later) ---
    def load_dorks(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filepath:
            with open(filepath, "r", encoding="utf-8") as f:
                new_dorks = [clean_input_line(line) for line in f if line.strip()]
            self.parser_raw_dorks = list(set(self.parser_raw_dorks + new_dorks))
            if not self.parser_raw_dorks:
                messagebox.showerror("Ошибка загрузки", "Файл пуст или содержит только пустые строки!")
                self.dork_selector.set_text("")
                self.loaded_dorks_lbl.configure(text="Загружено: 0")
                return
            self.dork_selector.set_text("Несколько файлов" if len(self.parser_raw_dorks) > len(new_dorks) else filepath)
            self.dork_selector.append_to_textbox(new_dorks)
            self.loaded_dorks_lbl.configure(text=f"Загружено: {len(self.parser_raw_dorks)}")
            self.safe_parser_log(f"[INFO] Добавлено {len(new_dorks)} Dork-запросов. Всего: {len(self.parser_raw_dorks)}", "info")

    def on_dorks_pasted(self, text):
        new_dorks = [clean_input_line(line) for line in text.split("\n") if line.strip()]
        self.parser_raw_dorks = list(set(self.parser_raw_dorks + new_dorks))
        self.loaded_dorks_lbl.configure(text=f"Загружено: {len(self.parser_raw_dorks)}")

    def load_parser_proxies(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filepath:
            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if file_size_mb > 50:
                if not messagebox.askyesno("Огромный файл", f"Размер файла прокси: {file_size_mb:.1f} МБ.\nПродолжить?"):
                    return
            with open(filepath, "r", encoding="utf-8") as f:
                raw_proxies = list(set([clean_input_line(line) for line in f if line.strip()]))
            
            new_proxies = []
            for p in raw_proxies:
                p_lower = p.lower()
                if p_lower.startswith("http://") or p_lower.startswith("https://") or p_lower.startswith("socks4://"):
                    continue
                new_proxies.append(p)
                
            self.parser_proxies = list(set(self.parser_proxies + new_proxies))
            ignored_count = len(raw_proxies) - len(new_proxies)
            
            if not self.parser_proxies:
                if ignored_count > 0:
                    messagebox.showerror("Ошибка прокси", "В файлах не найдено SOCKS5 прокси!\nВсе адреса были отброшены.")
                else:
                    messagebox.showerror("Ошибка загрузки", "Файлы с прокси абсолютно пусты!")
                self.parser_proxy_selector.set_text("")
                self.loaded_parser_proxies_lbl.configure(text="Прокси: 0")
                return
                
            self.parser_proxy_selector.set_text("Несколько файлов" if len(self.parser_proxies) > len(new_proxies) else filepath)
            self.parser_proxy_selector.append_to_textbox(new_proxies)
            self.loaded_parser_proxies_lbl.configure(text=f"Прокси: {len(self.parser_proxies)}")
            self.safe_parser_log(f"[INFO] Добавлено {len(new_proxies)} SOCKS5 прокси. Всего: {len(self.parser_proxies)}", "info")
            if ignored_count > 0:
                self.safe_parser_log(f"[WARNING] Отброшено {ignored_count} прокси (HTTP/HTTPS/SOCKS4).", "trap")

    def on_parser_proxies_pasted(self, text):
        raw_proxies = list(set([clean_input_line(line) for line in text.split("\n") if line.strip()]))
        new_proxies = []
        for p in raw_proxies:
            p_lower = p.lower()
            if p_lower.startswith("http://") or p_lower.startswith("https://") or p_lower.startswith("socks4://"):
                continue
            new_proxies.append(p)
        self.parser_proxies = list(set(self.parser_proxies + new_proxies))
        self.loaded_parser_proxies_lbl.configure(text=f"Прокси: {len(self.parser_proxies)}")

    def _build_main_workspace(self):
        self.main_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.main_frame.grid(row=0, column=1, sticky="nsew", padx=20, pady=15)

        # 1. Верхняя шапка (общая для обоих режимов)
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
        
        self.start_btn = ctk.CTkButton(self.controls_frame, text="▶", width=40, height=40, corner_radius=10, font=ctk.CTkFont(size=18), fg_color=ACCENT_PRIMARY, hover_color="#2563EB", text_color="#FFFFFF", command=self.start_process)
        self.start_btn.pack(side="left", padx=(0, 8))
        
        self.pause_btn = ctk.CTkButton(self.controls_frame, text="⏸", width=40, height=40, corner_radius=10, font=ctk.CTkFont(size=18), fg_color=ACCENT_WARNING, hover_color="#D97706", text_color="#000000", command=self.pause_process, state="disabled")
        self.pause_btn.pack(side="left", padx=(0, 8))
        
        self.stop_btn = ctk.CTkButton(self.controls_frame, text="⏹", width=40, height=40, corner_radius=10, font=ctk.CTkFont(size=18), fg_color=ACCENT_ERROR, hover_color="#DC2626", text_color="#FFFFFF", command=self.stop_process, state="disabled")
        self.stop_btn.pack(side="left")

        # --- VALIDATOR WORKSPACE ---
        self.validator_workspace = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.validator_workspace.pack(fill="both", expand=True)
        
        # Карточки статистики (Validator)
        self.dashboard_frame = ctk.CTkFrame(self.validator_workspace, fg_color="transparent")
        self.dashboard_frame.pack(fill="x", pady=(0, 20))
        self.dashboard_frame.grid_columnconfigure((0, 1, 2), weight=1, uniform="card")

        self._create_stat_card(self.dashboard_frame, 0, 0, "Всего собрано", "0", ACCENT_PRIMARY, "🌐", "stat_0")
        self._create_stat_card(self.dashboard_frame, 0, 1, "Валидные", "0", ACCENT_SUCCESS, "⚡", "stat_1")
        self._create_stat_card(self.dashboard_frame, 0, 2, "Невалидные", "0", ACCENT_ERROR, "🗑", "stat_2")
        self._create_stat_card(self.dashboard_frame, 1, 0, "Спам / Ловушки", "0", ACCENT_WARNING, "⚠️", "stat_3")
        self._create_stat_card(self.dashboard_frame, 1, 1, "Неизвестно", "0", TEXT_MUTED, "❓", "stat_4")

        # Прогресс-бар (Validator)
        self.progress_frame = ctk.CTkFrame(self.validator_workspace, fg_color="transparent")
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

        # Терминал / Таблица (Validator)
        self.bottom_container = ctk.CTkFrame(self.validator_workspace, fg_color="transparent", border_color=BORDER, border_width=1, corner_radius=12)
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
        
        self.chk_valid_var = ctk.BooleanVar(value=True)
        self.chk_invalid_var = ctk.BooleanVar(value=False)
        self.chk_spam_var = ctk.BooleanVar(value=False)
        self.chk_unknown_var = ctk.BooleanVar(value=False)
        
        self.chk_valid = ctk.CTkCheckBox(self.table_export_frame, text="Valid", variable=self.chk_valid_var, fg_color=ACCENT_SUCCESS, hover_color="#22C55E", text_color=TEXT_MAIN, font=ctk.CTkFont(size=12))
        self.chk_valid.pack(side="left", padx=(0, 10))
        
        self.chk_invalid = ctk.CTkCheckBox(self.table_export_frame, text="Invalid", variable=self.chk_invalid_var, fg_color=ACCENT_ERROR, hover_color="#EF4444", text_color=TEXT_MAIN, font=ctk.CTkFont(size=12))
        self.chk_invalid.pack(side="left", padx=(0, 10))
        
        self.chk_spam = ctk.CTkCheckBox(self.table_export_frame, text="Spam/Trap", variable=self.chk_spam_var, fg_color=ACCENT_WARNING, hover_color="#F59E0B", text_color=TEXT_MAIN, font=ctk.CTkFont(size=12))
        self.chk_spam.pack(side="left", padx=(0, 10))
        
        self.chk_unknown = ctk.CTkCheckBox(self.table_export_frame, text="Unknown", variable=self.chk_unknown_var, fg_color=BORDER, hover_color="#4B5563", text_color=TEXT_MAIN, font=ctk.CTkFont(size=12))
        self.chk_unknown.pack(side="left", padx=(0, 15))
        
        self.export_btn = ctk.CTkButton(self.table_export_frame, text="💾 Сохранить", command=self.export_results, width=100, height=28, fg_color=ACCENT_SUCCESS, hover_color="#22C55E", corner_radius=6)
        self.export_btn.pack(side="left", padx=(0, 5))
        
        self.copy_btn = ctk.CTkButton(self.table_export_frame, text="📋 Копировать", command=self.copy_results, width=110, height=28, fg_color=ACCENT_PRIMARY, hover_color="#2563EB", corner_radius=6)
        self.copy_btn.pack(side="left")
        
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

        # --- PARSER WORKSPACE ---
        self.parser_workspace = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        
        # Карточки статистики (Parser)
        self.parser_dashboard_frame = ctk.CTkFrame(self.parser_workspace, fg_color="transparent")
        self.parser_dashboard_frame.pack(fill="x", pady=(0, 20))
        self.parser_dashboard_frame.grid_columnconfigure((0, 1), weight=1, uniform="card")

        self._create_stat_card(self.parser_dashboard_frame, 0, 0, "Всего Подзапросов", "0", ACCENT_PRIMARY, "🔍", "parser_stat_dorks")
        self._create_stat_card(self.parser_dashboard_frame, 0, 1, "Страниц (Пагинация)", "0", TEXT_MUTED, "📄", "parser_stat_pages")
        self._create_stat_card(self.parser_dashboard_frame, 1, 0, "Проверено Сниппетов", "0", TEXT_MUTED, "👁", "parser_stat_snippets")
        self._create_stat_card(self.parser_dashboard_frame, 1, 1, "Найдено Email-ов", "0", ACCENT_SUCCESS, "📬", "parser_stat_emails")

        # Прогресс-бар (Parser)
        self.parser_progress_frame = ctk.CTkFrame(self.parser_workspace, fg_color="transparent")
        self.parser_progress_frame.pack(fill="x", pady=(0, 20))
        
        self.parser_progress_text_frame = ctk.CTkFrame(self.parser_progress_frame, fg_color="transparent")
        self.parser_progress_text_frame.pack(fill="x", pady=(0, 5))
        
        self.parser_progress_lbl = ctk.CTkLabel(self.parser_progress_text_frame, text="Парсинг... (0/0)", text_color=TEXT_MUTED, font=ctk.CTkFont(size=12))
        self.parser_progress_lbl.pack(side="left")
        
        self.parser_percent_lbl = ctk.CTkLabel(self.parser_progress_text_frame, text="0%", text_color=ACCENT_PRIMARY, font=ctk.CTkFont(size=12, weight="bold"))
        self.parser_percent_lbl.pack(side="right")

        self.parser_progress_bar = ctk.CTkProgressBar(self.parser_progress_frame, height=8, corner_radius=4, fg_color=BORDER, progress_color=ACCENT_PRIMARY)
        self.parser_progress_bar.set(0)
        self.parser_progress_bar.pack(fill="x")

        # Терминал / Таблица (Parser)
        self.parser_bottom_container = ctk.CTkFrame(self.parser_workspace, fg_color="transparent", border_color=BORDER, border_width=1, corner_radius=12)
        self.parser_bottom_container.pack(fill="both", expand=True)
        
        self.parser_tabs_frame = ctk.CTkFrame(self.parser_bottom_container, fg_color="transparent")
        self.parser_tabs_frame.pack(fill="x", pady=(15, 10))
        
        self.parser_tab_seg = ctk.CTkSegmentedButton(self.parser_tabs_frame, values=["Терминал", "Собранные Email"], command=self._switch_parser_tab, fg_color=BG_SIDEBAR, selected_color=ACCENT_PRIMARY, selected_hover_color="#60A5FA", unselected_color=BG_SIDEBAR, unselected_hover_color=BG_CARD_2, text_color=TEXT_MAIN)
        self.parser_tab_seg.set("Терминал")
        self.parser_tab_seg.pack(anchor="center")
        
        self.parser_terminal_view = ctk.CTkFrame(self.parser_bottom_container, fg_color="transparent")
        self.parser_table_view = ctk.CTkFrame(self.parser_bottom_container, fg_color="transparent")
        
        self.parser_terminal_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self.parser_terminal_header = ctk.CTkFrame(self.parser_terminal_view, fg_color="transparent")
        self.parser_terminal_header.pack(fill="x", pady=(0, 10))
        
        self.parser_copy_logs_btn = ctk.CTkButton(self.parser_terminal_header, text="📋 Копировать", width=120, height=28, corner_radius=6, font=ctk.CTkFont(size=12), command=self.copy_parser_logs, fg_color=ACCENT_PRIMARY, hover_color="#2563EB", text_color="#FFFFFF")
        self.parser_copy_logs_btn.pack(side="right")
        
        self.parser_terminal_box = ctk.CTkTextbox(self.parser_terminal_view, fg_color=BG_CARD_2, text_color=TEXT_MAIN, font=ctk.CTkFont(family="Consolas", size=12), border_width=0, corner_radius=8)
        self.parser_terminal_box.pack(fill="both", expand=True)
        self.parser_terminal_box.configure(state="disabled")

        self.parser_table_export_frame = ctk.CTkFrame(self.parser_table_view, fg_color="transparent")
        self.parser_table_export_frame.pack(fill="x", pady=(0, 10))
        
        self.parser_export_btn = ctk.CTkButton(self.parser_table_export_frame, text="💾 Сохранить", command=self.export_parser_results, width=100, height=28, fg_color=ACCENT_SUCCESS, hover_color="#22C55E", corner_radius=6)
        self.parser_export_btn.pack(side="left", padx=(0, 5))
        
        self.parser_copy_btn = ctk.CTkButton(self.parser_table_export_frame, text="📋 Копировать", command=self.copy_parser_results, width=110, height=28, fg_color=ACCENT_PRIMARY, hover_color="#2563EB", corner_radius=6)
        self.parser_copy_btn.pack(side="left")

        self.parser_table_frame = ctk.CTkFrame(self.parser_table_view, fg_color="transparent")
        self.parser_table_frame.pack(fill="both", expand=True)
        self.parser_table_frame.grid_rowconfigure(0, weight=1)
        self.parser_table_frame.grid_columnconfigure(0, weight=1)

        p_columns = ("email", "dork")
        self.parser_tree = ttk.Treeview(self.parser_table_frame, columns=p_columns, show="headings")
        self.parser_tree.heading("email", text="Email", anchor="w")
        self.parser_tree.heading("dork", text="Dork Source", anchor="w")
        
        self.parser_tree.column("email", width=300, minwidth=200, stretch=True, anchor="w")
        self.parser_tree.column("dork", width=400, minwidth=250, stretch=True, anchor="w")
        self.parser_tree.grid(row=0, column=0, sticky="nsew")

        self.parser_scrollbar = ctk.CTkScrollbar(self.parser_table_frame, orientation="vertical", command=self.parser_tree.yview, fg_color="transparent", button_color=ACCENT_PRIMARY, button_hover_color="#60A5FA")
        self.parser_tree.configure(yscrollcommand=self.parser_scrollbar.set)
        self.parser_scrollbar.grid(row=0, column=1, sticky="ns")

    def _switch_tab(self, value):
        if value == "Терминал":
            self.table_view.pack_forget()
            self.terminal_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        else:
            self.terminal_view.pack_forget()
            self.table_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def _switch_parser_tab(self, value):
        if value == "Терминал":
            self.parser_table_view.pack_forget()
            self.parser_terminal_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        else:
            self.parser_terminal_view.pack_forget()
            self.parser_table_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))

    def copy_parser_logs(self):
        text = self.parser_terminal_box.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Скопировано", "Логи терминала парсера скопированы в буфер обмена.")

    def export_parser_results(self):
        if not hasattr(self, 'parser_results_data') or not self.parser_results_data:
            messagebox.showwarning("Пусто", "Нет собранных Email адресов для экспорта.")
            return
            
        file_types = [("Text File (Только Email)", "*.txt"), ("CSV File (Email+Dork)", "*.csv")]
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=file_types, initialfile="parsed_emails.txt")
        if filepath:
            try:
                import csv
                if filepath.endswith(".csv"):
                    with open(filepath, "w", newline="", encoding="utf-8") as f:
                        writer = csv.writer(f)
                        writer.writerow(["Email", "Dork Source"])
                        for r in self.parser_results_data:
                            writer.writerow([r["email"], r["dork"]])
                else:
                    # Txt mode: just distinct emails to save the user from deduplicating
                    distinct_emails = list(set([r["email"] for r in self.parser_results_data]))
                    with open(filepath, "w", encoding="utf-8") as f:
                        for e in distinct_emails:
                            f.write(e + "\n")
                messagebox.showinfo("Экспорт", f"Успешно сохранено!\n\nВсего адресов в файле: {len(self.parser_results_data) if filepath.endswith('.csv') else len(distinct_emails)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

    def copy_parser_results(self):
        if not hasattr(self, 'parser_results_data') or not self.parser_results_data:
            messagebox.showwarning("Пусто", "Нет собранных Email адресов для копирования.")
            return
            
        distinct_emails = list(set([r["email"] for r in self.parser_results_data]))
        text = "\n".join(distinct_emails)
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Скопировано", f"Успешно скопировано {len(distinct_emails)} уникальных адресов в буфер обмена.")

    def _create_stat_card(self, parent, row, col, title, value, val_color, icon, attr_name):
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
        
        setattr(self, attr_name, lbl_val)

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
                new_emails = [clean_input_line(line) for line in f if line.strip()]
            
            self.raw_emails.extend(new_emails)
            self.raw_emails = list(dict.fromkeys(self.raw_emails))
            
            if not self.raw_emails:
                messagebox.showerror("Ошибка загрузки", "Файл пуст или содержит только пустые строки!")
                self.db_selector.set_text("")
                self.loaded_lbl.configure(text="Загружено: 0")
                return
            self.db_selector.set_text("Несколько файлов" if len(self.raw_emails) > len(new_emails) else filepath)
            self.db_selector.append_to_textbox(new_emails)
            self.loaded_lbl.configure(text=f"Загружено: {len(self.raw_emails)}")
            self.safe_log(f"[INFO] Добавлено {len(new_emails)} строк. Всего: {len(self.raw_emails)}", "info")

    def on_emails_pasted(self, text):
        lines = [clean_input_line(line) for line in text.split("\n") if line.strip()]
        self.raw_emails.extend(lines)
        self.raw_emails = list(dict.fromkeys(self.raw_emails))
        self.loaded_lbl.configure(text=f"Загружено: {len(self.raw_emails)}")

    def load_proxies(self):
        filepath = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if filepath:
            file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
            if file_size_mb > 50:
                if not messagebox.askyesno("Огромный файл", f"Размер файла прокси: {file_size_mb:.1f} МБ.\nПродолжить?"):
                    return
            with open(filepath, "r", encoding="utf-8") as f:
                raw_proxies = list(set([clean_input_line(line) for line in f if line.strip()]))
            
            new_proxies = []
            for p in raw_proxies:
                p_lower = p.lower()
                if p_lower.startswith("http://") or p_lower.startswith("https://") or p_lower.startswith("socks4://"):
                    continue
                new_proxies.append(p)
                
            self.proxies = list(set(self.proxies + new_proxies))
            ignored_count = len(raw_proxies) - len(new_proxies)
            
            if not self.proxies:
                if ignored_count > 0:
                    messagebox.showerror("Ошибка прокси", "В файлах не найдено SOCKS5 прокси!\nВсе адреса были отброшены.")
                else:
                    messagebox.showerror("Ошибка загрузки", "Файл с прокси абсолютно пуст!")
                self.proxy_selector.set_text("")
                self.loaded_proxies_lbl.configure(text="Прокси: 0")
                return
                
            self.proxy_selector.set_text("Несколько файлов" if len(self.proxies) > len(new_proxies) else filepath)
            self.proxy_selector.append_to_textbox(new_proxies)
            self.loaded_proxies_lbl.configure(text=f"Прокси: {len(self.proxies)}")
            self.safe_log(f"[INFO] Добавлено {len(new_proxies)} SOCKS5 прокси. Всего: {len(self.proxies)}", "info")
            if ignored_count > 0:
                self.safe_log(f"[WARNING] Отброшено {ignored_count} прокси (HTTP/HTTPS/SOCKS4).", "trap")

    def on_proxies_pasted(self, text):
        raw_proxies = list(set([clean_input_line(line) for line in text.split("\n") if line.strip()]))
        new_proxies = []
        for p in raw_proxies:
            p_lower = p.lower()
            if p_lower.startswith("http://") or p_lower.startswith("https://") or p_lower.startswith("socks4://"):
                continue
            new_proxies.append(p)
        self.proxies = list(set(self.proxies + new_proxies))
        self.loaded_proxies_lbl.configure(text=f"Прокси: {len(self.proxies)}")

    def _set_sidebar_state(self, state):
        if hasattr(self, 'engine_selector'):
            self.engine_selector.configure(state=state)
        self.db_selector.configure(state=state)
        self.proxy_selector.configure(state=state)
        self.threads_slider.configure(state=state)
        self.timeout_slider.configure(state=state)
        self.chk_ai.configure(state=state)
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
            
        self.stats = {"valid": 0, "invalid": 0, "spam": 0, "unknown": 0}
        self.results_data.clear()
        
        self.stat_0.configure(text="0")
        self.stat_1.configure(text="0")
        self.stat_2.configure(text="0")
        self.stat_3.configure(text="0")
        self.stat_4.configure(text="0")
        
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        self._set_sidebar_state("disabled")
        self._set_playback_state("running")
            
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

    def start_parsing(self):
        if hasattr(self, 'parser_pipeline') and self.parser_pipeline and self.parser_pipeline.is_alive():
            return
            
        if not self.parser_raw_dorks:
            self.safe_parser_log("[Ошибка] Загрузите дорки перед стартом!", "dead")
            return
            
        self.parser_results_data.clear()
        
        self.parser_stat_dorks.configure(text="0")
        self.parser_stat_pages.configure(text="0")
        self.parser_stat_snippets.configure(text="0")
        self.parser_stat_emails.configure(text="0")
        
        for item in self.parser_tree.get_children():
            self.parser_tree.delete(item)
            
        self._set_sidebar_state("disabled")
        self._set_playback_state("running")
            
        self.parser_terminal_box.configure(state="normal")
        self.parser_terminal_box.delete("1.0", "end")
        self.parser_terminal_box.configure(state="disabled")
        self.safe_parser_log("[Система] Инициализация конвейера парсера...", "info")

        threads = int(self.parser_threads_slider.get())
        timeout = float(self.parser_timeout_slider.get())
        
        from core.parser_pipeline import ParserPipeline
        self.parser_pipeline = ParserPipeline(
            dorks=self.parser_raw_dorks,
            proxies=self.parser_proxies,
            max_threads=threads,
            timeout=timeout,
            on_log=self.safe_parser_log,
            on_progress=self.safe_update_parser_progress,
            on_stats_update=self.safe_update_parser_stats,
            on_result_found=self.safe_add_parser_result,
            on_complete=self.on_parser_complete,
            engine_name=self.engine_var.get()
        )
        self.parser_pipeline.start()

    def pause_parsing(self):
        if hasattr(self, 'parser_pipeline') and self.parser_pipeline and self.parser_pipeline.is_alive():
            if self.parser_pipeline._pause_event.is_set():
                self.parser_pipeline.resume()
                self.pause_btn.configure(text="⏸", fg_color=ACCENT_WARNING)
                self.safe_parser_log("[Система] Парсинг возобновлен (RESUMED).", "info")
            else:
                self.parser_pipeline.pause()
                self.pause_btn.configure(text="▶", fg_color=ACCENT_SUCCESS)
                self.safe_parser_log("[Система] Парсинг приостановлен (PAUSE).", "info")

    def stop_parsing(self):
        if hasattr(self, 'parser_pipeline') and self.parser_pipeline and self.parser_pipeline.is_alive():
            self.parser_pipeline.stop()
            self.safe_parser_log("[Система] Остановка парсинга пользователем (STOP).", "info")

    def _poll_queues(self):
        import queue
        
        # Batch process logs to prevent UI freeze
        logs_to_insert = []
        for _ in range(1000): # Process up to 1000 logs per tick
            try:
                msg, tag = self.log_queue.get_nowait()
                logs_to_insert.append((msg, tag))
            except queue.Empty:
                break
                
        if logs_to_insert:
            self.parser_terminal_box.configure(state="normal")
            for msg, tag in logs_to_insert:
                self.parser_terminal_box.insert("end", msg + "\n", tag)
            
            # Keep only the last 1000 lines
            try:
                line_count = int(self.parser_terminal_box.index('end-1c').split('.')[0])
                if line_count > 1000:
                    self.parser_terminal_box.delete("1.0", f"{line_count - 1000}.0")
            except Exception:
                pass
                
            self.parser_terminal_box.see("end")
            self.parser_terminal_box.configure(state="disabled")

        # Process stats (only the latest matters)
        latest_stats = None
        while True:
            try:
                latest_stats = self.stats_queue.get_nowait()
            except queue.Empty:
                break
        if latest_stats:
            self._update_parser_stats_ui(*latest_stats)

        # Process progress (only the latest matters)
        latest_prog = None
        while True:
            try:
                latest_prog = self.progress_queue.get_nowait()
            except queue.Empty:
                break
        if latest_prog:
            if len(latest_prog) == 3:
                cur, tot, pct = latest_prog
                label = "Парсинг"
            else:
                cur, tot, pct, label = latest_prog
            self._update_parser_progress_ui(cur, tot, pct, label)

        # Batch process results
        results_to_insert = []
        for _ in range(500):
            try:
                email, dork = self.result_queue.get_nowait()
                results_to_insert.append((email, dork))
            except queue.Empty:
                break
                
        if results_to_insert:
            for email, dork in results_to_insert:
                self.parser_results_data.append({"email": email, "dork": dork})
                self.parser_tree.insert("", "end", values=(email, dork))
            # Auto-scroll to the latest result
            children = self.parser_tree.get_children()
            if children:
                self.parser_tree.see(children[-1])

        self.after(50, self._poll_queues)

    def safe_parser_log(self, message, tag="info"):
        self.log_queue.put((message, tag))
        
    def _update_parser_log(self, message, tag):
        self.parser_terminal_box.configure(state="normal")
        self.parser_terminal_box.insert("end", message + "\n", tag)
        
        # Keep only the last 1000 lines to prevent Tkinter from freezing
        try:
            line_count = int(self.parser_terminal_box.index('end-1c').split('.')[0])
            if line_count > 1000:
                self.parser_terminal_box.delete("1.0", f"{line_count - 1000}.0")
        except Exception:
            pass
            
        self.parser_terminal_box.see("end")
        self.parser_terminal_box.configure(state="disabled")

    def safe_update_parser_stats(self, dorks_tot, dorks_done, pages, snippets, emails):
        self.stats_queue.put((dorks_tot, dorks_done, pages, snippets, emails))

    def _update_parser_stats_ui(self, dorks_tot, dorks_done, pages, snippets, emails):
        self.parser_stat_dorks.configure(text=str(dorks_tot))
        self.parser_stat_pages.configure(text=f"{pages:.0f}")
        self.parser_stat_snippets.configure(text=str(int(snippets)))
        self.parser_stat_emails.configure(text=str(emails))

    def safe_update_parser_progress(self, current, total, pct, label="Парсинг"):
        self.progress_queue.put((current, total, pct, label))
        
    def _update_parser_progress_ui(self, current, total, pct, label="Парсинг"):
        status_text = "Завершено" if pct == 100 else f"{label}..."
        self.parser_progress_lbl.configure(text=f"{status_text} ({current}/{total})")
        self.parser_percent_lbl.configure(text=f"{pct}%")
        self.parser_progress_bar.set(pct / 100.0)
        
        if total > 0 and pct == 100:
            self.parser_progress_bar.configure(progress_color=ACCENT_SUCCESS)
        else:
            self.parser_progress_bar.configure(progress_color=ACCENT_PRIMARY)

    def safe_add_parser_result(self, email, dork):
        self.result_queue.put((email, dork))
        
    def _add_parser_result_ui(self, email, dork):
        self.parser_results_data.append({"email": email, "dork": dork})
        self.parser_tree.insert("", "end", values=(email, dork))

    def on_parser_complete(self, aborted=False):
        self.after(0, self._reset_ui_after_parser_complete)
        
    def _reset_ui_after_parser_complete(self):
        self._set_playback_state("stopped")
        self._set_sidebar_state("normal")

    def on_pipeline_complete(self):
        self.after(0, self._reset_ui_after_complete)
        
    def _reset_ui_after_complete(self):
        self._set_playback_state("stopped")
        self._set_sidebar_state("normal")
        self.safe_log("[INFO] Валидация базы полностью завершена.", "info")

    def copy_terminal_logs(self):
        text = self.terminal_box.get("1.0", "end-1c")
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Скопировано", "Логи терминала скопированы в буфер обмена.")

    def _get_filtered_results(self):
        export_data = []
        for r in self.results_data:
            st = r["status"]
            if self.chk_valid_var.get() and st == "Valid":
                export_data.append(r)
            elif self.chk_invalid_var.get() and "Invalid" in st:
                export_data.append(r)
            elif self.chk_spam_var.get() and ("Trap" in st or "Disposable" in st or "Risky" in st):
                export_data.append(r)
            elif self.chk_unknown_var.get() and st == "Unknown":
                export_data.append(r)
        return export_data

    def export_results(self):
        if not hasattr(self, 'results_data') or not self.results_data:
            messagebox.showwarning("Пусто", "Нет данных для экспорта.")
            return
            
        export_data = self._get_filtered_results()
                
        if not export_data:
            messagebox.showwarning("Пусто", "По выбранным критериям не найдено ни одного адреса.")
            return
            
        file_types = [("Text File (Только Email)", "*.txt"), ("CSV File (Email+Причина+MX)", "*.csv")]
        default_name = "results_filtered"
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
                messagebox.showinfo("Успех", f"Успешно сохранено {len(export_data)} строк!\nФайл: {os.path.basename(filepath)}")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

    def copy_results(self):
        if not hasattr(self, 'results_data') or not self.results_data:
            messagebox.showwarning("Пусто", "Нет данных для копирования.")
            return
            
        export_data = self._get_filtered_results()
                
        if not export_data:
            messagebox.showwarning("Пусто", "По выбранным критериям не найдено ни одного адреса.")
            return
            
        text = "\n".join([r['email'] for r in export_data])
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Скопировано", f"Успешно скопировано {len(export_data)} адресов в буфер обмена.")
