# ui/widgets.py
"""Составные виджеты окна: селектор источника и слайдер с полем ввода.

Отдельный файл, потому что это переиспользуемые кирпичи, а не часть логики
приложения: селектор одинаково обслуживает почты, прокси и дорки, а слайдер —
потоки и таймаут. Внутри нет ни одного решения про валидацию.
"""
import re

import customtkinter as ctk
from tkinter import filedialog

from ui.colors import *

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
