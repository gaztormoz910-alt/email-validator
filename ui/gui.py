# ui/gui.py
import customtkinter as ctk
from tkinter import ttk, filedialog, messagebox
import psutil
import socket
import os
import re
import threading
from ui.colors import *
from core.pipeline import ValidationPipeline
from core.streamer import StreamLoader

CLEAN_PREFIX_RE = re.compile(r'^\d+[-.)\]:й]*\s+')

def clean_input_line(line):
    # Убирает нумерацию типа "1. ", "2)", "1-й ", "100:", "1 ", оставляя только суть.
    return CLEAN_PREFIX_RE.sub('', line.strip())


def _format_sources(data):
    """Коротко: откуда взяты имя, пол и страна.

    «файл» означает, что значение пришло из исходной базы и является фактом.
    Всё остальное — предсказание, и пользователь должен видеть разницу:
    раньше догадка ML стояла в колонке наравне с данными из файла.
    """
    marks = []
    for field, label in (("name_source", "имя"), ("gender_source", "пол"),
                         ("country_source", "гео")):
        source = data.get(field)
        if source:
            marks.append(f"{label}:{source}")
    return " ".join(marks)


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
        
        self.seg_btn = ctk.CTkSegmentedButton(self.header_frame, values=["Файл", "Текст"], command=self._switch_mode, height=22, fg_color=BG_CARD_2, selected_color=ACCENT_PRIMARY, selected_hover_color=ACCENT_PRIMARY_HOVER, unselected_color=BG_CARD_2, unselected_hover_color=BORDER, text_color=TEXT_MAIN, font=ctk.CTkFont(size=11))
        self.seg_btn.pack(side="right")
        self.seg_btn.set("Файл")
        
        self.clear_btn = ctk.CTkButton(self.header_frame, text="🗑", width=26, height=22, corner_radius=6, fg_color=BG_CARD_2, hover_color=ACCENT_ERROR, text_color=TEXT_MAIN, command=self._clear_data)
        self.clear_btn.pack(side="right", padx=(0, 5))
        
        self.file_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.file_frame.pack(fill="x")
        
        self.entry = ctk.CTkEntry(self.file_frame, fg_color=BG_CARD_2, border_color=BORDER, text_color=TEXT_MAIN, state="disabled", height=30)
        self.entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        self.btn = ctk.CTkButton(self.file_frame, text=button_text, command=self._browse_file, fg_color=ACCENT_PRIMARY, hover_color=ACCENT_PRIMARY_HOVER, text_color=TEXT_ON_ACCENT, width=70, height=30, corner_radius=6)
        self.btn.pack(side="right")
        
        self.text_frame = ctk.CTkFrame(self, fg_color="transparent")
        
        self.textbox = ctk.CTkTextbox(self.text_frame, height=80, fg_color=BG_CARD_2, border_color=BORDER, border_width=1, text_color=TEXT_MAIN, font=ctk.CTkFont(size=11), wrap="none")
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
        # self.seg_btn.configure(state=state) # Keep toggle active so user can switch tabs
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
        
        self.slider = ctk.CTkSlider(self, from_=from_, to=to, height=12, fg_color=BG_CARD_2, progress_color=ACCENT_PRIMARY, button_color=ACCENT_PRIMARY, button_hover_color=ACCENT_PRIMARY_HOVER, command=self._slider_moved)
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
        self.email_sources = [] # [{"type": "text", "content": "..."}, {"type": "file", "path": "..."}]
        self.proxy_sources = []
        self.stats = {"valid": 0, "invalid": 0, "spam": 0, "unknown": 0}
        self.results_data = []
        
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
        self.validator_log_queue = queue.Queue()
        self._poll_queues()
        self._poll_validator_queues()

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
            selected_hover_color=ACCENT_PRIMARY_HOVER, 
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

        # Максимальное значение ползунка ограничено 300 — максимальное безопасное число для домашней сети
        safe_max_threads = min(self.max_hw_threads, 300)
        self.threads_slider = ProxyHunterSlider(self.validator_sidebar_frame, "Потоки", 1, safe_max_threads, safe_max_threads)
        self.threads_slider.pack(fill="x", padx=20, pady=(0, 20))
        
        self.timeout_slider = ProxyHunterSlider(self.validator_sidebar_frame, "Таймаут (сек)", 1, 300, 5)
        self.timeout_slider.pack(fill="x", padx=20, pady=(0, 25))

        self.chk_ai = ctk.CTkSwitch(self.validator_sidebar_frame, text="Использовать AI фильтр (ML)", text_color=TEXT_MAIN, progress_color=ACCENT_PRIMARY, button_color=TEXT_ON_ACCENT, button_hover_color=TEXT_MAIN)
        self.chk_ai.select()
        self.chk_ai.pack(padx=20, anchor="w", pady=(0, 20))
        
        self.chk_osint_val = ctk.CTkSwitch(self.validator_sidebar_frame, text="Обогащение данных (OSINT)", text_color=TEXT_MAIN, progress_color=ACCENT_PRIMARY, button_color=TEXT_ON_ACCENT, button_hover_color=TEXT_MAIN)
        self.chk_osint_val.select()
        self.chk_osint_val.pack(padx=20, anchor="w", pady=(0, 20))

        # Кэш вердиктов прошлых прогонов. Выключай, если базу нужно проверить
        # заново целиком (например, спустя месяцы или после смены прокси).
        self.chk_cache = ctk.CTkSwitch(self.validator_sidebar_frame, text="Кэш вердиктов (не перепроверять)", text_color=TEXT_MAIN, progress_color=ACCENT_PRIMARY, button_color=TEXT_ON_ACCENT, button_hover_color=TEXT_MAIN)
        self.chk_cache.select()
        self.chk_cache.pack(padx=20, anchor="w", pady=(0, 20))

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
        self.engine_selector = ctk.CTkOptionMenu(self.engine_frame, variable=self.engine_var, values=["DuckDuckGo Lite", "AOL (Tor)", "Yahoo (Tor)", "AOL (Proxies)", "Yahoo (Proxies)"], fg_color=BG_CARD_2, button_color=BORDER, button_hover_color=ACCENT_PRIMARY, command=self._on_engine_change)
        self.engine_selector.pack(fill="x", padx=20, pady=(0, 20))

        # Максимальное значение ползунка парсера ограничено 300 — чтобы не давить роутер
        parser_max_threads = min(self.max_hw_threads, 300)
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
        
    def clear_dorks(self):
        self.dork_sources.clear()
        self.loaded_dorks_lbl.configure(text="Загружено: 0")
        self.dork_selector.set_text("")
        self.dork_selector.textbox.delete("1.0", "end")
        if hasattr(self, 'safe_parser_log'):
            self.safe_parser_log("[INFO] Dork-запросы очищены.", "trap")
        
    def clear_parser_proxies(self):
        self.parser_proxy_sources.clear()
        self.loaded_parser_proxies_lbl.configure(text="Прокси: 0")
        self.parser_proxy_selector.set_text("")
        self.parser_proxy_selector.textbox.delete("1.0", "end")
        if hasattr(self, 'safe_parser_log'):
            self.safe_parser_log("[INFO] SOCKS5 прокси для парсера очищены.", "trap")

    # --- DUMMY HANDLERS FOR PARSER (to be fully implemented later) ---
    def load_dorks(self):
        filepaths = filedialog.askopenfilenames(filetypes=[("Text Files", "*.txt")])
        if filepaths:
            is_massive = False
            for filepath in filepaths:
                file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
                if file_size_mb > 20:
                    is_massive = True
                self.dork_sources.append({"type": "file", "path": filepath})
            
            if is_massive:
                self.dork_selector.textbox.delete("1.0", "end")
                self.dork_selector.textbox.insert("1.0", "[ПРЕДПРОСМОТР ОТКЛЮЧЕН]\nОдин или несколько файлов слишком велики (>20 МБ).\nВключен режим потокового чтения (Lazy Loading).")
                self.loaded_dorks_lbl.configure(text=f"Dorks источников: {len(self.dork_sources)}")
                if hasattr(self, 'safe_parser_log'):
                    self.safe_parser_log(f"[INFO] Добавлены массивные файлы Dorks (>{len(filepaths)} шт.).", "info")
            else:
                loader = StreamLoader([{"type": "file", "path": fp} for fp in filepaths])
                preview_dorks = []
                for idx, line in enumerate(loader.stream_lines()):
                    if idx < 5000:
                        preview_dorks.append(line)
                
                self.dork_selector.append_to_textbox(preview_dorks)
                if len(preview_dorks) == 5000:
                    self.dork_selector.textbox.insert("end", "\n...и другие (показаны первые 5000)...")
                
                total_loader = StreamLoader(self.dork_sources)
                total_count = total_loader.count_total_lines()
                self.loaded_dorks_lbl.configure(text=f"Загружено: {total_count}")
                if hasattr(self, 'safe_parser_log'):
                    self.safe_parser_log(f"[INFO] Dork-запросы добавлены. Строк: {total_count}", "info")
            
            self.dork_selector.set_text("Несколько файлов" if len(filepaths) > 1 else filepaths[0])

    def on_dorks_pasted(self, text):
        self.dork_sources.append({"type": "text", "content": text})
        total_loader = StreamLoader(self.dork_sources)
        total_count = total_loader.count_total_lines()
        self.loaded_dorks_lbl.configure(text=f"Загружено: {total_count}")

    def load_parser_proxies(self):
        filepaths = filedialog.askopenfilenames(filetypes=[("Text Files", "*.txt")])
        if filepaths:
            is_massive = False
            for filepath in filepaths:
                file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
                if file_size_mb > 20:
                    is_massive = True
                self.parser_proxy_sources.append({"type": "file", "path": filepath})
            
            if is_massive:
                self.parser_proxy_selector.textbox.delete("1.0", "end")
                self.parser_proxy_selector.textbox.insert("1.0", "[ПРЕДПРОСМОТР ОТКЛЮЧЕН]\nОдин или несколько файлов слишком велики (>20 МБ).\nВключен режим потокового чтения (Lazy Loading).")
                self.loaded_parser_proxies_lbl.configure(text=f"Прокси источников: {len(self.parser_proxy_sources)}")
                if hasattr(self, 'safe_parser_log'):
                    self.safe_parser_log(f"[INFO] Добавлены массивные файлы прокси парсера (>{len(filepaths)} шт.).", "info")
            else:
                # Парсер умеет все три протокола: чекер работает в режиме HTTP
                # (socks4, socks5 и CONNECT), а ProxyManager сам дописывает
                # схему. Отсеивать socks4 и HTTP значило выбрасывать часть
                # купленного пула без причины.
                loader = StreamLoader([{"type": "file", "path": fp} for fp in filepaths])
                preview_proxies = []
                for p in loader.stream_lines():
                    preview_proxies.append(p)
                    if len(preview_proxies) >= 5000:
                        break

                self.parser_proxy_selector.append_to_textbox(preview_proxies)
                if len(preview_proxies) == 5000:
                    self.parser_proxy_selector.textbox.insert("end", "\n...и другие (показаны первые 5000)...")
                
                total_loader = StreamLoader(self.parser_proxy_sources)
                total_count = total_loader.count_total_lines()
                self.loaded_parser_proxies_lbl.configure(text=f"Прокси (оценка): {total_count}")
                if hasattr(self, 'safe_parser_log'):
                    self.safe_parser_log(f"[INFO] Прокси парсера добавлены. Строк: {total_count}", "info")
            
            self.parser_proxy_selector.set_text("Несколько файлов" if len(filepaths) > 1 else filepaths[0])
    def on_parser_proxies_pasted(self, text):
        self.parser_proxy_sources.append({"type": "text", "content": text})
        total_loader = StreamLoader(self.parser_proxy_sources)
        total_count = total_loader.count_total_lines()
        self.loaded_parser_proxies_lbl.configure(text=f"Прокси (оценка): {total_count}")

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
        self.shield_lbl = ctk.CTkLabel(self.shield_frame, text="🛡", font=ctk.CTkFont(size=20), text_color=TEXT_ON_ACCENT)
        self.shield_lbl.place(relx=0.5, rely=0.5, anchor="center")
        
        self.title_text_frame = ctk.CTkFrame(self.title_frame, fg_color="transparent")
        self.title_text_frame.pack(side="left")
        
        self.main_title_lbl = ctk.CTkLabel(self.title_text_frame, text="EMAIL VALIDATOR PRO", font=ctk.CTkFont(size=22, weight="bold"), text_color=TEXT_MAIN)
        self.main_title_lbl.pack(anchor="w", pady=0)
        self.sub_title_lbl = ctk.CTkLabel(self.title_text_frame, text="v4.0 - Продвинутая фильтрация", font=ctk.CTkFont(size=11), text_color=TEXT_MUTED)
        self.sub_title_lbl.pack(anchor="w", pady=0)
        
        self.controls_frame = ctk.CTkFrame(self.header_main, fg_color="transparent")
        self.controls_frame.pack(side="right")
        
        self.start_btn = ctk.CTkButton(self.controls_frame, text="▶", width=40, height=40, corner_radius=10, font=ctk.CTkFont(size=18), fg_color=ACCENT_PRIMARY, hover_color=ACCENT_PRIMARY_HOVER, text_color=TEXT_ON_ACCENT, command=self.start_process)
        self.start_btn.pack(side="left", padx=(0, 8))
        
        self.pause_btn = ctk.CTkButton(self.controls_frame, text="⏸", width=40, height=40, corner_radius=10, font=ctk.CTkFont(size=18), fg_color=ACCENT_WARNING, hover_color=ACCENT_WARNING_HOVER, text_color=TEXT_ON_WARNING, command=self.pause_process, state="disabled")
        self.pause_btn.pack(side="left", padx=(0, 8))
        
        self.stop_btn = ctk.CTkButton(self.controls_frame, text="⏹", width=40, height=40, corner_radius=10, font=ctk.CTkFont(size=18), fg_color=ACCENT_ERROR, hover_color=ACCENT_ERROR_HOVER, text_color=TEXT_ON_ACCENT, command=self.stop_process, state="disabled")
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
        self._create_stat_card(self.dashboard_frame, 1, 2, "Имена найдены", "0", ACCENT_PURPLE, "👤", "stat_names")

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
        
        self.tab_seg = ctk.CTkSegmentedButton(self.tabs_frame, values=["Терминал", "Результаты"], command=self._switch_tab, fg_color=BG_SIDEBAR, selected_color=ACCENT_PRIMARY, selected_hover_color=ACCENT_PRIMARY_HOVER, unselected_color=BG_SIDEBAR, unselected_hover_color=BG_CARD_2, text_color=TEXT_MAIN)
        self.tab_seg.set("Терминал")
        self.tab_seg.pack(anchor="center")
        
        self.terminal_view = ctk.CTkFrame(self.bottom_container, fg_color="transparent")
        self.table_view = ctk.CTkFrame(self.bottom_container, fg_color="transparent")
        
        self.terminal_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self.terminal_header = ctk.CTkFrame(self.terminal_view, fg_color="transparent")
        self.terminal_header.pack(fill="x", pady=(0, 10))
        
        self.copy_logs_btn = ctk.CTkButton(self.terminal_header, text="Копировать", width=120, height=28, corner_radius=8, font=ctk.CTkFont(size=12), command=self.copy_terminal_logs, fg_color="transparent", border_width=1, border_color=BORDER_STRONG, hover_color=BG_CARD_HOVER, text_color=TEXT_MAIN)
        self.copy_logs_btn.pack(side="right")
        
        self.terminal_box = ctk.CTkTextbox(self.terminal_view, fg_color=BG_CARD_2, text_color=TEXT_MAIN, font=ctk.CTkFont(family="Consolas", size=12), border_width=0, corner_radius=8, wrap="none")
        self.terminal_box.pack(fill="both", expand=True)
        
        self.terminal_box.tag_config("info", foreground=TEXT_MUTED)
        self.terminal_box.tag_config("valid", foreground=ACCENT_SUCCESS)
        self.terminal_box.tag_config("trap", foreground=ACCENT_WARNING)
        self.terminal_box.tag_config("dead", foreground=ACCENT_ERROR)
        self.terminal_box.configure(state="disabled")

        self.table_export_frame = ctk.CTkFrame(self.table_view, fg_color="transparent")
        self.table_export_frame.pack(fill="x", pady=(0, 12))

        # Left zone: pagination, grouped in its own pill
        self.pagination_frame = ctk.CTkFrame(self.table_export_frame, fg_color=BG_CARD_1, corner_radius=8)
        self.pagination_frame.pack(side="left")

        self.btn_prev_page = ctk.CTkButton(self.pagination_frame, text="‹", width=28, height=28, corner_radius=6, fg_color="transparent", hover_color=BG_CARD_HOVER, text_color=TEXT_MAIN, command=self.prev_validator_page)
        self.btn_prev_page.pack(side="left", padx=(4, 0), pady=4)

        self.lbl_page = ctk.CTkLabel(self.pagination_frame, text="Стр. 1 / 1", text_color=TEXT_MUTED, font=ctk.CTkFont(size=12), width=64)
        self.lbl_page.pack(side="left", padx=2)

        self.btn_next_page = ctk.CTkButton(self.pagination_frame, text="›", width=28, height=28, corner_radius=6, fg_color="transparent", hover_color=BG_CARD_HOVER, text_color=TEXT_MAIN, command=self.next_validator_page)
        self.btn_next_page.pack(side="left", padx=(0, 4), pady=4)

        # Center zone: status filter chips, grouped in their own pill
        self.filter_frame = ctk.CTkFrame(self.table_export_frame, fg_color=BG_CARD_1, corner_radius=8)
        self.filter_frame.pack(side="left", padx=(10, 0))

        self.chk_valid_var = ctk.BooleanVar(value=True)
        self.chk_invalid_var = ctk.BooleanVar(value=False)
        self.chk_spam_var = ctk.BooleanVar(value=False)
        self.chk_unknown_var = ctk.BooleanVar(value=False)

        self.chk_valid = ctk.CTkCheckBox(self.filter_frame, text="Valid", variable=self.chk_valid_var, command=self._on_filter_change, fg_color=ACCENT_SUCCESS, hover_color=ACCENT_SUCCESS_HOVER, border_color=BORDER_STRONG, text_color=TEXT_MAIN, font=ctk.CTkFont(size=12), checkbox_width=16, checkbox_height=16)
        self.chk_valid.pack(side="left", padx=(12, 10), pady=8)

        self.chk_invalid = ctk.CTkCheckBox(self.filter_frame, text="Invalid", variable=self.chk_invalid_var, command=self._on_filter_change, fg_color=ACCENT_ERROR, hover_color=ACCENT_ERROR_HOVER, border_color=BORDER_STRONG, text_color=TEXT_MAIN, font=ctk.CTkFont(size=12), checkbox_width=16, checkbox_height=16)
        self.chk_invalid.pack(side="left", padx=(0, 10), pady=8)

        self.chk_spam = ctk.CTkCheckBox(self.filter_frame, text="Spam/Trap", variable=self.chk_spam_var, command=self._on_filter_change, fg_color=ACCENT_WARNING, hover_color=ACCENT_WARNING_HOVER, border_color=BORDER_STRONG, text_color=TEXT_MAIN, font=ctk.CTkFont(size=12), checkbox_width=16, checkbox_height=16)
        self.chk_spam.pack(side="left", padx=(0, 10), pady=8)

        self.chk_unknown = ctk.CTkCheckBox(self.filter_frame, text="Unknown", variable=self.chk_unknown_var, command=self._on_filter_change, fg_color=TEXT_MUTED, hover_color=BORDER_STRONG, border_color=BORDER_STRONG, text_color=TEXT_MAIN, font=ctk.CTkFont(size=12), checkbox_width=16, checkbox_height=16)
        self.chk_unknown.pack(side="left", padx=(0, 12), pady=8)

        # Порог Engagement Score (п.37): отсекает слабые адреса при показе и экспорте
        self.score_filter_frame = ctk.CTkFrame(self.table_export_frame, fg_color=BG_CARD_1, corner_radius=8)
        self.score_filter_frame.pack(side="left", padx=(8, 0))

        ctk.CTkLabel(self.score_filter_frame, text="Score ≥", text_color=TEXT_MAIN,
                     font=ctk.CTkFont(size=12)).pack(side="left", padx=(12, 6), pady=8)

        self.min_score_var = ctk.StringVar(value="0")
        self.min_score_entry = ctk.CTkEntry(self.score_filter_frame, textvariable=self.min_score_var,
                                            width=48, height=26, corner_radius=6,
                                            fg_color=BG_CARD_2, border_color=BORDER_STRONG,
                                            text_color=TEXT_MAIN, font=ctk.CTkFont(size=12),
                                            justify="center")
        self.min_score_entry.pack(side="left", padx=(0, 12), pady=8)
        self.min_score_entry.bind("<Return>", lambda e: self._on_filter_change())
        self.min_score_entry.bind("<FocusOut>", lambda e: self._on_filter_change())

        # Right zone: actions, anchored to the right edge instead of trailing after the filters
        self.actions_frame = ctk.CTkFrame(self.table_export_frame, fg_color="transparent")
        self.actions_frame.pack(side="right")

        self.copy_btn = ctk.CTkButton(self.actions_frame, text="Копировать", command=self.copy_results, width=110, height=32, corner_radius=8, fg_color="transparent", border_width=1, border_color=BORDER_STRONG, hover_color=BG_CARD_HOVER, text_color=TEXT_MAIN)
        self.copy_btn.pack(side="left", padx=(0, 8))

        # Список отписок вычитается при экспорте: повторное письмо тому, кто
        # уже отписался, стоит жалобы на спам.
        self.suppress_path = None
        self.suppress_btn = ctk.CTkButton(self.actions_frame, text="Отписки", command=self.choose_suppression, width=90, height=32, corner_radius=8, fg_color="transparent", border_width=1, border_color=BORDER_STRONG, hover_color=BG_CARD_HOVER, text_color=TEXT_MAIN)
        self.suppress_btn.pack(side="left", padx=(0, 8))

        # Нарезка выгрузки под лимиты ESP. 0 — одним файлом.
        ctk.CTkLabel(self.actions_frame, text="по", text_color=TEXT_MUTED,
                     font=ctk.CTkFont(size=12)).pack(side="left", padx=(0, 4))
        self.chunk_entry = ctk.CTkEntry(self.actions_frame, width=64, height=32,
                                        corner_radius=8, justify="center",
                                        placeholder_text="0")
        self.chunk_entry.pack(side="left", padx=(0, 8))

        self.export_btn = ctk.CTkButton(self.actions_frame, text="Сохранить", command=self.export_results, width=110, height=32, corner_radius=8, fg_color=ACCENT_SUCCESS, hover_color=ACCENT_SUCCESS_HOVER, text_color=TEXT_ON_ACCENT)
        self.export_btn.pack(side="left")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background=BG_CARD_1,
                        foreground=TEXT_MAIN,
                        rowheight=32,
                        fieldbackground=BG_CARD_1,
                        borderwidth=0,
                        relief="flat",
                        font=("Segoe UI", 10))
        style.configure("Treeview.Heading",
                        background=BG_TABLE_HEADER,
                        foreground=TEXT_MUTED,
                        font=("Segoe UI", 10, "bold"),
                        borderwidth=0,
                        relief="flat")
        style.map("Treeview.Heading", background=[('active', BG_TABLE_HEADER)], foreground=[('active', TEXT_MAIN)])
        style.map('Treeview', background=[('selected', BG_SELECTED)], foreground=[('selected', TEXT_MAIN)])

        self.table_frame = ctk.CTkFrame(self.table_view, fg_color="transparent")
        self.table_frame.pack(fill="both", expand=True)
        self.table_frame.grid_rowconfigure(0, weight=1)
        self.table_frame.grid_columnconfigure(0, weight=1)

        columns = ("email", "status", "score", "provider", "domain_type", "reason", "mx",
                   "name", "gender", "country", "birth_year", "source", "validated")
        self.tree = ttk.Treeview(self.table_frame, columns=columns, show="headings")
        self.tree.heading("email", text="Email", anchor="w")
        self.tree.heading("status", text="Status", anchor="center")
        self.tree.heading("score", text="Score", anchor="center")
        self.tree.heading("provider", text="Provider", anchor="w")
        self.tree.heading("domain_type", text="Тип домена", anchor="w")
        self.tree.heading("reason", text="Reason", anchor="w")
        self.tree.heading("mx", text="MX-Record", anchor="w")
        self.tree.heading("name", text="Name", anchor="w")
        self.tree.heading("gender", text="Gender", anchor="w")
        self.tree.heading("country", text="Country", anchor="w")
        self.tree.heading("birth_year", text="Год рожд.", anchor="center")
        # Откуда взяты имя, пол и страна: «файл» — из исходника, всё остальное
        # предсказано. Раньше догадка ML показывалась как факт.
        self.tree.heading("source", text="Источник", anchor="w")
        self.tree.heading("validated", text="Проверено", anchor="w")
        
        self.tree.column("email", width=210, minwidth=150, stretch=True, anchor="w")
        self.tree.column("status", width=95, minwidth=80, stretch=False, anchor="center")
        self.tree.column("score", width=55, minwidth=45, stretch=False, anchor="center")
        self.tree.column("provider", width=115, minwidth=80, stretch=False, anchor="w")
        self.tree.column("domain_type", width=95, minwidth=70, stretch=False, anchor="w")
        self.tree.column("reason", width=190, minwidth=140, stretch=True, anchor="w")
        self.tree.column("mx", width=180, minwidth=130, stretch=True, anchor="w")
        self.tree.column("name", width=110, minwidth=80, stretch=True, anchor="w")
        self.tree.column("gender", width=70, minwidth=55, stretch=False, anchor="w")
        self.tree.column("country", width=85, minwidth=55, stretch=False, anchor="w")
        self.tree.column("birth_year", width=70, minwidth=55, stretch=False, anchor="center")
        self.tree.column("source", width=130, minwidth=90, stretch=False, anchor="w")
        self.tree.column("validated", width=110, minwidth=90, stretch=False, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")

        self.tree.tag_configure("valid", foreground=ACCENT_SUCCESS)
        self.tree.tag_configure("trap", foreground=ACCENT_WARNING)
        self.tree.tag_configure("unknown", foreground=TEXT_MUTED)
        self.tree.tag_configure("dead", foreground=ACCENT_ERROR)

        self.scrollbar = ctk.CTkScrollbar(self.table_frame, orientation="vertical", command=self.tree.yview, fg_color="transparent", button_color=ACCENT_PRIMARY, button_hover_color=ACCENT_PRIMARY_HOVER)
        self.tree.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.grid(row=0, column=1, sticky="ns")

        # --- PARSER WORKSPACE ---
        self.parser_workspace = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        
        # Карточки статистики (Parser)
        self.parser_dashboard_frame = ctk.CTkFrame(self.parser_workspace, fg_color="transparent")
        self.parser_dashboard_frame.pack(fill="x", pady=(0, 20))
        self.parser_dashboard_frame.grid_columnconfigure((0, 1), weight=1, uniform="card")

        self._create_stat_card(self.parser_dashboard_frame, 0, 0, "Обработано Дорков", "0", ACCENT_PRIMARY, "🔍", "parser_stat_dorks")
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
        
        self.parser_tab_seg = ctk.CTkSegmentedButton(self.parser_tabs_frame, values=["Терминал", "Собранные Email"], command=self._switch_parser_tab, fg_color=BG_SIDEBAR, selected_color=ACCENT_PRIMARY, selected_hover_color=ACCENT_PRIMARY_HOVER, unselected_color=BG_SIDEBAR, unselected_hover_color=BG_CARD_2, text_color=TEXT_MAIN)
        self.parser_tab_seg.set("Терминал")
        self.parser_tab_seg.pack(anchor="center")
        
        self.parser_terminal_view = ctk.CTkFrame(self.parser_bottom_container, fg_color="transparent")
        self.parser_table_view = ctk.CTkFrame(self.parser_bottom_container, fg_color="transparent")
        
        self.parser_terminal_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        
        self.parser_terminal_header = ctk.CTkFrame(self.parser_terminal_view, fg_color="transparent")
        self.parser_terminal_header.pack(fill="x", pady=(0, 10))
        
        self.parser_copy_logs_btn = ctk.CTkButton(self.parser_terminal_header, text="Копировать", width=120, height=28, corner_radius=8, font=ctk.CTkFont(size=12), command=self.copy_parser_logs, fg_color="transparent", border_width=1, border_color=BORDER_STRONG, hover_color=BG_CARD_HOVER, text_color=TEXT_MAIN)
        self.parser_copy_logs_btn.pack(side="right")
        
        self.parser_terminal_box = ctk.CTkTextbox(self.parser_terminal_view, fg_color=BG_CARD_2, text_color=TEXT_MAIN, font=ctk.CTkFont(family="Consolas", size=12), border_width=0, corner_radius=8)
        self.parser_terminal_box.pack(fill="both", expand=True)
        self.parser_terminal_box.configure(state="disabled")

        self.parser_table_export_frame = ctk.CTkFrame(self.parser_table_view, fg_color="transparent")
        self.parser_table_export_frame.pack(fill="x", pady=(0, 12))

        self.parser_actions_frame = ctk.CTkFrame(self.parser_table_export_frame, fg_color="transparent")
        self.parser_actions_frame.pack(side="right")

        self.parser_copy_btn = ctk.CTkButton(self.parser_actions_frame, text="Копировать", command=self.copy_parser_results, width=110, height=32, corner_radius=8, fg_color="transparent", border_width=1, border_color=BORDER_STRONG, hover_color=BG_CARD_HOVER, text_color=TEXT_MAIN)
        self.parser_copy_btn.pack(side="left", padx=(0, 8))

        self.parser_export_btn = ctk.CTkButton(self.parser_actions_frame, text="Сохранить", command=self.export_parser_results, width=110, height=32, corner_radius=8, fg_color=ACCENT_SUCCESS, hover_color=ACCENT_SUCCESS_HOVER, text_color=TEXT_ON_ACCENT)
        self.parser_export_btn.pack(side="left")

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

        self.parser_scrollbar = ctk.CTkScrollbar(self.parser_table_frame, orientation="vertical", command=self.parser_tree.yview, fg_color="transparent", button_color=ACCENT_PRIMARY, button_hover_color=ACCENT_PRIMARY_HOVER)
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
        filepaths = filedialog.askopenfilenames(filetypes=[("Text/CSV Files", "*.txt *.csv")])
        if filepaths:
            is_massive = False
            for filepath in filepaths:
                file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
                if file_size_mb > 20:
                    is_massive = True
                self.email_sources.append({"type": "file", "path": filepath})
            
            if is_massive:
                self.db_selector.textbox.delete("1.0", "end")
                self.db_selector.textbox.insert("1.0", "[ПРЕДПРОСМОТР ОТКЛЮЧЕН]\nОдин или несколько файлов слишком велики (>20 МБ).\nВключен режим потокового чтения (Lazy Loading).")
                self.loaded_lbl.configure(text=f"Загружено источников: {len(self.email_sources)}")
                self.safe_log(f"[INFO] Добавлены массивные файлы (>{len(filepaths)} шт.).", "info")
            else:
                loader = StreamLoader([{"type": "file", "path": fp} for fp in filepaths])
                preview_emails = []
                for idx, (email, _) in enumerate(loader.stream_emails()):
                    if idx < 5000:
                        preview_emails.append(email)
                
                self.db_selector.append_to_textbox(preview_emails)
                if len(preview_emails) == 5000:
                    self.db_selector.textbox.insert("end", "\n...и другие (показаны первые 5000)...")
                
                total_loader = StreamLoader(self.email_sources)
                total_count = total_loader.count_total_lines()
                self.loaded_lbl.configure(text=f"Загружено строк: {total_count}")
                self.safe_log(f"[INFO] Файлы добавлены. Всего строк: {total_count}", "info")

            self.db_selector.set_text("Несколько файлов" if len(filepaths) > 1 else filepaths[0])
            self._scan_base_composition()

    def _scan_base_composition(self):
        """Показывает состав базы по провайдерам. Без сети — только чтение файла."""
        if not self.email_sources:
            return

        def worker():
            try:
                from core.provider import scan_base_providers, format_base_scan
                scan = scan_base_providers(self.email_sources)
                for line in format_base_scan(scan):
                    self.safe_log(line, "info")
            except Exception as e:
                self.safe_log(f"[DEAD] Скан состава базы не удался: {type(e).__name__}", "dead")

        # В отдельном потоке: на большом файле чтение займёт время, а UI морозить нельзя
        threading.Thread(target=worker, daemon=True).start()

    def on_emails_pasted(self, text):
        self.email_sources.append({"type": "text", "content": text})
        total_loader = StreamLoader(self.email_sources)
        total_count = total_loader.count_total_lines()
        self.loaded_lbl.configure(text=f"Загружено строк: {total_count}")
        self._scan_base_composition()

    def load_proxies(self):
        filepaths = filedialog.askopenfilenames(filetypes=[("Text Files", "*.txt")])
        if filepaths:
            is_massive = False
            for filepath in filepaths:
                file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
                if file_size_mb > 20:
                    is_massive = True
                self.proxy_sources.append({"type": "file", "path": filepath})
            
            if is_massive:
                self.proxy_selector.textbox.delete("1.0", "end")
                self.proxy_selector.textbox.insert("1.0", "[ПРЕДПРОСМОТР ОТКЛЮЧЕН]\nОдин или несколько файлов слишком велики (>20 МБ).\nВключен режим потокового чтения (Lazy Loading).")
                self.loaded_proxies_lbl.configure(text=f"Прокси источников: {len(self.proxy_sources)}")
                self.safe_log(f"[INFO] Добавлены массивные файлы прокси (>{len(filepaths)} шт.).", "info")
            else:
                # Предпросмотр показывает ровно то, что пойдёт в работу.
                # Раньше здесь отсеивались socks4 и HTTP — и получалось враньё:
                # валидация их использует, а в окне пользователь их не видит,
                # хотя счётчик ниже считает все строки файла.
                loader = StreamLoader([{"type": "file", "path": fp} for fp in filepaths])
                preview_proxies = []
                for p in loader.stream_lines():
                    preview_proxies.append(p)
                    if len(preview_proxies) >= 5000:
                        break   # дальше не читаем: файл может быть огромным

                self.proxy_selector.append_to_textbox(preview_proxies)
                if len(preview_proxies) == 5000:
                    self.proxy_selector.textbox.insert("end", "\n...и другие (показаны первые 5000)...")
                
                total_loader = StreamLoader(self.proxy_sources)
                total_count = total_loader.count_total_lines()
                self.loaded_proxies_lbl.configure(text=f"Прокси (оценка): {total_count}")
                self.safe_log(f"[INFO] Прокси добавлены. Строк: {total_count}", "info")
            
            self.proxy_selector.set_text("Несколько файлов" if len(filepaths) > 1 else filepaths[0])

    def on_proxies_pasted(self, text):
        self.proxy_sources.append({"type": "text", "content": text})
        total_loader = StreamLoader(self.proxy_sources)
        total_count = total_loader.count_total_lines()
        self.loaded_proxies_lbl.configure(text=f"Прокси (оценка): {total_count}")

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
        self.results_data.clear()
        
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
        from core.network import dedupe_proxies
        actual_proxies = dedupe_proxies(
            list(StreamLoader(self.proxy_sources).stream_lines()))
        
        if not actual_proxies:
            self.safe_log("[DEAD] Ошибка: в загруженных источниках нет ни одного прокси!", "dead")
            self._set_playback_state("stopped")
            self._set_sidebar_state("normal")
            return

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
        self.validator_log_queue.put((text, tag))
        
    def _log_ui(self, text, tag):
        self.terminal_box.configure(state="normal")
        self.terminal_box.insert("end", text + "\n", tag)
        
        # Keep only the last 1000 lines
        try:
            line_count = int(self.terminal_box.index('end-1c').split('.')[0])
            if line_count > 1000:
                self.terminal_box.delete("1.0", f"{line_count - 1000}.0")
        except Exception:
            pass
            
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

    def _poll_validator_queues(self):
        import queue
        # Process logs
        for _ in range(500):
            try:
                msg, tag = self.validator_log_queue.get_nowait()
                self._log_ui(msg, tag)
            except queue.Empty:
                break
                
        # Batch process results
        results_to_insert = []
        for _ in range(500):
            try:
                item = self.validator_result_queue.get_nowait()
                results_to_insert.append(item)
            except queue.Empty:
                break
                
        if results_to_insert:
            for email, status, reason, mx, data in results_to_insert:
                self._add_result_ui(email, status, reason, mx, data)
                
            self.refresh_validator_tree()
                
        self.after(50, self._poll_validator_queues)

    def safe_add_result(self, email, status, reason, mx, data=None):
        if data is None:
            data = {}
        self.validator_result_queue.put((email, status, reason, mx, data))
        
    def _add_result_ui(self, email, status, reason, mx, data):
        self.results_data.append({"email": email, "status": status, "reason": reason, "mx": mx, "data": data})
        
        if status == "Valid":
            self.stats["valid"] += 1
            self.stat_1.configure(text=str(self.stats["valid"]))
            if data.get("name"):
                self.stats["names"] += 1
                self.stat_names.configure(text=str(self.stats["names"]))
            self.safe_log(f"[VALID] {email} -> {reason}", "valid")
        elif "Trap" in status or "Disposable" in status or status == "Risky":
            self.stats["spam"] += 1
            self.stat_3.configure(text=str(self.stats["spam"]))
            self.safe_log(f"[{status.upper()}] {email} -> {reason}", "trap")
        elif status == "Role-based":
            self.stats["spam"] += 1
            self.stat_3.configure(text=str(self.stats["spam"]))
            self.safe_log(f"[ROLE] {email} -> {reason}", "trap")
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
            
    def _on_filter_change(self):
        self.validator_page = 1
        self.refresh_validator_tree(force=True)
        
    def prev_validator_page(self):
        if self.validator_page > 1:
            self.validator_page -= 1
            self.refresh_validator_tree(force=True)
            
    def next_validator_page(self):
        filtered = self._get_filtered_results()
        import math
        total_pages = max(1, math.ceil(len(filtered) / self.validator_page_size))
        if self.validator_page < total_pages:
            self.validator_page += 1
            self.refresh_validator_tree(force=True)
            
    def refresh_validator_tree(self, force=False):
        filtered = self._get_filtered_results()
        import math
        total_pages = max(1, math.ceil(len(filtered) / self.validator_page_size))
        
        if self.validator_page > total_pages:
            self.validator_page = max(1, total_pages)
            
        self.lbl_page.configure(text=f"Стр. {self.validator_page} / {total_pages}")
        
        start_idx = (self.validator_page - 1) * self.validator_page_size
        end_idx = start_idx + self.validator_page_size
        page_data = filtered[start_idx:end_idx]
        
        current_emails = [self.tree.item(child)["values"][0] for child in self.tree.get_children()]
        new_emails = [r["email"] for r in page_data]
        
        if not force and current_emails == new_emails:
            return
            
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

    def start_parsing(self):
        if hasattr(self, 'parser_pipeline') and self.parser_pipeline and self.parser_pipeline.is_alive():
            return
            
        if not self.dork_sources:
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
        
        # Как и у валидатора: берём прокси любого поддерживаемого протокола
        # и схлопываем повторы по разобранным частям, а не по строке —
        # один прокси, записанный дважды, занимал два места в ротации.
        from core.network import dedupe_proxies
        actual_proxies = dedupe_proxies(
            list(StreamLoader(self.parser_proxy_sources).stream_lines()))

        from core.parser_pipeline import ParserPipeline
        self.parser_pipeline = ParserPipeline(
            dork_sources=self.dork_sources,
            proxies=actual_proxies,
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
                item = self.result_queue.get_nowait()
                if len(item) == 2:
                    email, dork = item
                else:
                    email, dork = item[0], item[1]
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
        self.parser_stat_dorks.configure(text=f"{dorks_done}/{dorks_tot}")
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

    def safe_add_parser_result(self, email, dork, *args, **kwargs):
        self.result_queue.put((email, dork))
        
    def _add_parser_result_ui(self, email, dork, *args, **kwargs):
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

    def _get_min_score(self):
        """Порог Engagement Score из поля ввода. Мусор во вводе трактуем как 0."""
        try:
            return max(0, min(100, int(self.min_score_var.get().strip() or 0)))
        except (ValueError, AttributeError):
            return 0

    def _get_filtered_results(self):
        export_data = []
        min_score = self._get_min_score()
        for r in self.results_data:
            st = r["status"]
            matched = False
            if self.chk_valid_var.get() and st == "Valid":
                matched = True
            elif self.chk_invalid_var.get() and "Invalid" in st:
                matched = True
            elif self.chk_spam_var.get() and ("Trap" in st or "Disposable" in st or "Risky" in st or st == "Role-based"):
                matched = True
            elif self.chk_unknown_var.get() and st == "Unknown":
                matched = True

            if not matched:
                continue

            # Отсекаем слабые адреса по порогу скора (п.37)
            if min_score > 0:
                try:
                    if int(r.get("data", {}).get("engagement_score", 0) or 0) < min_score:
                        continue
                except (TypeError, ValueError):
                    continue

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
            
        # Вычитаем список отписок ДО записи: письмо тому, кто уже отписался,
        # стоит жалобы на спам, а сравнивать надо по каноническому виду —
        # John.Doe@Gmail.com и johndoe@gmail.com это один ящик.
        suppressed = 0
        if self.suppress_path:
            try:
                from core import baseops
                removals = baseops.read_emails(self.suppress_path)
                keep = {e.lower() for e in
                        baseops.subtract([r["email"] for r in export_data], removals)}
                before = len(export_data)
                export_data = [r for r in export_data if r["email"].lower() in keep]
                suppressed = before - len(export_data)
            except Exception as e:
                messagebox.showwarning("Отписки", f"Список отписок не применён:\n{e}")

        if not export_data:
            messagebox.showwarning("Пусто", "После вычитания отписок не осталось ни одного адреса.")
            return

        try:
            chunk_size = int(self.chunk_entry.get().strip() or 0)
        except ValueError:
            chunk_size = 0

        file_types = [("Text File (Только Email)", "*.txt"), ("CSV File (Email+Причина+MX)", "*.csv")]
        default_name = "results_filtered"
        filepath = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=file_types, initialfile=default_name)

        if filepath:
            try:
                from core import baseops

                def write_csv(f, rows):
                    import csv
                    # csv.writer обязателен: reason содержит запятые (напр. "[DNS: SPF=..., DMARC=...]"),
                    # из-за чего ручная склейка через "," разъезжала колонки в Excel.
                    writer = csv.writer(f)
                    writer.writerow(["Email", "Status", "Reason", "MX-Record", "Name", "Gender", "Country",
                                     "BirthYear", "Score", "Grade", "Provider", "DomainType",
                                     "NameSource", "GenderSource", "CountrySource",
                                     "SocialAccounts", "ValidatedAt"])
                    for r in rows:
                        data = r.get("data", {})
                        writer.writerow([
                            r["email"], r["status"], r["reason"], r["mx"],
                            data.get("name", ""), data.get("gender", ""), data.get("country", ""),
                            data.get("birth_year", ""),
                            data.get("engagement_score", ""), data.get("engagement_grade", ""),
                            data.get("provider_name", ""), data.get("domain_type", ""),
                            data.get("name_source", ""), data.get("gender_source", ""),
                            data.get("country_source", ""), data.get("social_accounts", ""),
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
                written = baseops.write_chunks(export_data, filepath, chunk_size, writer_fn)

                note = f"Сохранено {len(export_data)} строк."
                if suppressed:
                    note += f"\nВычтено по списку отписок: {suppressed}."
                if len(written) > 1:
                    note += f"\nРазбито на файлов: {len(written)} (по {chunk_size})."
                else:
                    note += f"\nФайл: {os.path.basename(written[0] if written else filepath)}"
                messagebox.showinfo("Успех", note)
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось сохранить файл:\n{e}")

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
        if not hasattr(self, 'results_data') or not self.results_data:
            messagebox.showwarning("Пусто", "Нет данных для копирования.")
            return
            
        export_data = self._get_filtered_results()
                
        if not export_data:
            messagebox.showwarning("Пусто", "По выбранным критериям не найдено ни одного адреса.")
            return
            
        lines = []
        for r in export_data:
            data = r.get("data", {})
            name = data.get("name", "")
            gender = data.get("gender", "")
            country = data.get("country", "")
            if name or gender or country:
                lines.append(f"{r['email']}:{name}:{gender}:{country}")
            else:
                lines.append(r['email'])
        text = "\n".join(lines)
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Скопировано", f"Успешно скопировано {len(export_data)} адресов в буфер обмена.")
