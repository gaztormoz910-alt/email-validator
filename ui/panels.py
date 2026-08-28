# ui/panels.py
"""Сборка окна: боковая панель, рабочая область, вкладка прокси, плитки.

Вынесено из gui.py, потому что это отдельный род работы. Здесь только
РАЗМЕТКА — какие виджеты создать, куда положить, как подписать; ни одного
решения о том, что считать валидным адресом, здесь нет и быть не должно.
Пока разметка лежала вперемешку с логикой прогона, файл окна перевалил за две
тысячи строк, и найти в нём обработчик события было труднее, чем написать
новый.

Примесь, а не отдельный объект: методы создают атрибуты прямо на окне
(self.db_selector, self.threads_slider и десятки других), и разрывать это
надвое значило бы завести объект, единственная работа которого — держать
ссылки на чужие виджеты.
"""
import os
import threading

import customtkinter as ctk
import psutil
from tkinter import ttk, filedialog, messagebox

from ui.colors import *
from ui.widgets import ProxyHunterInputSelector, ProxyHunterSlider



class PanelsMixin:

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

        # Режим колонки «Страна». Раньше выбор между заполненностью и точностью
        # был правкой двух чисел в исходнике, хотя это решение про ДЕНЬГИ: гнать
        # гео-таргет по колонке, где треть значений выдумана, — не то же самое,
        # что по неполной, но верной. Замеры обоих режимов лежат в
        # core/parser/ml_predictor.py рядом с порогами.
        ctk.CTkLabel(self.validator_sidebar_frame, text="Колонка «Страна» по имени:",
                     text_color=TEXT_MAIN, font=ctk.CTkFont(size=12)).pack(
            padx=20, anchor="w", pady=(0, 4))

        self.country_mode_var = ctk.StringVar(value="Заполненность")
        self.country_mode_seg = ctk.CTkSegmentedButton(
            self.validator_sidebar_frame, values=["Заполненность", "Точность"],
            variable=self.country_mode_var, command=self._on_country_mode_change,
            fg_color=BG_CARD_2, selected_color=ACCENT_PRIMARY,
            selected_hover_color=ACCENT_PRIMARY_HOVER, unselected_color=BG_CARD_2,
            unselected_hover_color=BORDER, text_color=TEXT_MAIN,
            font=ctk.CTkFont(size=11))
        self.country_mode_seg.pack(fill="x", padx=20, pady=(0, 4))

        self.country_mode_hint = ctk.CTkLabel(
            self.validator_sidebar_frame,
            text="заполнено почти всегда, ~треть стран — догадка",
            text_color=TEXT_DIM, font=ctk.CTkFont(size=10), justify="left")
        self.country_mode_hint.pack(padx=20, anchor="w", pady=(0, 20))

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
        
        self.tab_seg = ctk.CTkSegmentedButton(self.tabs_frame, values=["Терминал", "Результаты", "Прокси"], command=self._switch_tab, fg_color=BG_SIDEBAR, selected_color=ACCENT_PRIMARY, selected_hover_color=ACCENT_PRIMARY_HOVER, unselected_color=BG_SIDEBAR, unselected_hover_color=BG_CARD_2, text_color=TEXT_MAIN)
        self.tab_seg.set("Терминал")
        self.tab_seg.pack(anchor="center")
        
        self.terminal_view = ctk.CTkFrame(self.bottom_container, fg_color="transparent")
        self.table_view = ctk.CTkFrame(self.bottom_container, fg_color="transparent")
        self.proxy_view = ctk.CTkFrame(self.bottom_container, fg_color="transparent")
        self._build_proxy_panel()

        self.terminal_view.pack(fill="both", expand=True, padx=15, pady=(0, 15))

        self.terminal_header = ctk.CTkFrame(self.terminal_view, fg_color="transparent")
        self.terminal_header.pack(fill="x", pady=(0, 10))

        # Сколько строк лога не поместилось в буфер. Пустая метка при обычной
        # работе; заполняется, только если поток результатов обогнал окно —
        # молча терять лог нельзя, иначе по терминалу нельзя судить о прогоне.
        self.log_note_lbl = ctk.CTkLabel(self.terminal_header, text="",
                                         text_color=TEXT_DIM,
                                         font=ctk.CTkFont(size=11))
        self.log_note_lbl.pack(side="left")

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

    def _build_proxy_panel(self):
        """Вкладка «Прокси»: что за пул загружен и что им можно проверить.

        Зачем она нужна. Валидатор умеет много такого, о чём по окну догадаться
        было нельзя: он выясняет РЕАЛЬНЫЙ выходной IP каждого прокси, схлопывает
        дубли (десять строк с одним выходом — это ротация из одного адреса),
        определяет тип адреса и страну, спрашивает у почтовиков напрямую, пустят
        ли они. Всё это уходило строчками в лог и прокручивалось наверх. Здесь
        оно лежит на виду и не исчезает.
        """
        wrapper = ctk.CTkScrollableFrame(self.proxy_view, fg_color="transparent")
        wrapper.pack(fill="both", expand=True)
        self.proxy_panel_body = wrapper

        self.proxy_panel_hint = ctk.CTkLabel(
            wrapper,
            text=("Профиль появится после запуска: валидатор сам определит\n"
                  "выходной IP каждого прокси, схлопнет дубли и спросит\n"
                  "у почтовиков, пустят ли они этот адрес."),
            text_color=TEXT_MUTED, font=ctk.CTkFont(size=12), justify="left")
        self.proxy_panel_hint.pack(anchor="w", padx=4, pady=8)

        self.proxy_cards = {}

    def _proxy_metric(self, parent, key, title, hint):
        """Одна плитка сводки. Значение обновляется, не пересоздаётся."""
        card = ctk.CTkFrame(parent, fg_color=BG_CARD_1, corner_radius=10,
                            border_width=1, border_color=BORDER)
        ctk.CTkLabel(card, text=title, text_color=TEXT_MUTED,
                     font=ctk.CTkFont(size=11)).pack(anchor="w", padx=14, pady=(10, 0))
        value = ctk.CTkLabel(card, text="—", text_color=TEXT_MAIN,
                             font=ctk.CTkFont(size=20, weight="bold"))
        value.pack(anchor="w", padx=14, pady=(2, 0))
        note = ctk.CTkLabel(card, text=hint, text_color=TEXT_DIM,
                            font=ctk.CTkFont(size=10), justify="left")
        note.pack(anchor="w", padx=14, pady=(0, 10))
        self.proxy_cards[key] = (value, note)
        return card

    def _render_proxy_panel(self):
        """Перерисовывает панель. Вызывается по событию, а не по таймеру."""
        summary = self.proxy_summary
        if not summary:
            return

        for child in self.proxy_panel_body.winfo_children():
            child.destroy()
        self.proxy_cards = {}

        total = summary.get("total", 0)
        unique = summary.get("unique_ips", 0)
        duplicates = summary.get("duplicates", 0)

        grid = ctk.CTkFrame(self.proxy_panel_body, fg_color="transparent")
        grid.pack(fill="x", pady=(0, 14))
        grid.grid_columnconfigure((0, 1, 2), weight=1, uniform="pcard")

        self._proxy_metric(grid, "rotation", "Реальная ротация",
                           "разных выходных IP — столько адресов видит почтовик"
                           ).grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._proxy_metric(grid, "dupes", "Дубли по выходу",
                           "прокси, выходящих через уже занятый адрес"
                           ).grid(row=0, column=1, sticky="ew", padx=8)
        self._proxy_metric(grid, "speed", "Скорость (медиана)",
                           "задержка до баннера, участвует в выборе прокси"
                           ).grid(row=0, column=2, sticky="ew", padx=(8, 0))

        self.proxy_cards["rotation"][0].configure(text=f"{unique} / {total}")
        dup_value, dup_note = self.proxy_cards["dupes"]
        dup_value.configure(text=str(duplicates),
                            text_color=ACCENT_ERROR if duplicates else ACCENT_SUCCESS)
        if duplicates:
            dup_note.configure(
                text=f"самая крупная группа — {summary.get('largest_group', 0)} прокси "
                     "с одним IP")
        median = summary.get("latency_median")
        self.proxy_cards["speed"][0].configure(
            text=f"{median} мс" if median is not None else "—")
        if summary.get("latency_min") is not None:
            self.proxy_cards["speed"][1].configure(
                text=f"от {summary['latency_min']} до {summary['latency_max']} мс")

        self._proxy_section(
            "Пригодность по провайдерам",
            "Спрошено у самих почтовиков пробой до MAIL FROM, а не выведено из списков.",
            [(label, f"годны {c['ok']}   не пустят {c['no']}   не проверено {c['unknown']}",
              ACCENT_SUCCESS if c["ok"] else (ACCENT_ERROR if c["no"] else TEXT_MUTED))
             for label, c in (summary.get("fitness") or {}).items()])

        by_type = summary.get("by_type") or {}
        type_names = {"residential": "Жилые (лучшая репутация)",
                      "datacenter": "Датацентровые (режут чаще всего)",
                      "mobile": "Мобильные", "unknown": "Тип не определён"}
        self._proxy_section(
            "Тип выходных адресов",
            "Фильтры смотрят именно на это: датацентровый IP блокируется заметно чаще жилого.",
            [(type_names.get(kind, kind), f"{count} адресов",
              ACCENT_WARNING if kind == "datacenter" else TEXT_MAIN)
             for kind, count in sorted(by_type.items(), key=lambda kv: -kv[1])])

        countries = summary.get("countries") or {}
        if countries:
            top = sorted(countries.items(), key=lambda kv: -kv[1])[:12]
            self._proxy_section(
                "География выходных адресов",
                "Прокси из страны домена получателя выбирается первым — это снижает долю отказов.",
                [(code, f"{count} адресов", TEXT_MAIN) for code, count in top])

        self._proxy_section(
            "Гигиена адресов",
            "PTR нужен Yahoo и AOL; чёрные списки и «грязное» имя закрывают Outlook, iCloud и GMX.",
            [("С обратным DNS (PTR)", f"{summary.get('with_ptr', 0)} прокси", ACCENT_SUCCESS),
             ("PTR проверить не удалось", f"{summary.get('ptr_unknown', 0)} прокси", TEXT_MUTED),
             ("В чёрных списках", f"{summary.get('in_dnsbl', 0)} прокси",
              ACCENT_ERROR if summary.get('in_dnsbl') else TEXT_MAIN),
             ("Имя в PTR выдаёт прокси/VPN", f"{summary.get('rdns_dirty', 0)} прокси",
              ACCENT_WARNING if summary.get('rdns_dirty') else TEXT_MAIN)])

    def _proxy_section(self, title, hint, rows):
        """Блок «заголовок + пояснение + строки». Пустой блок не рисуется."""
        if not rows:
            return
        block = ctk.CTkFrame(self.proxy_panel_body, fg_color=BG_CARD_1,
                             corner_radius=10, border_width=1, border_color=BORDER)
        block.pack(fill="x", pady=(0, 12))

        ctk.CTkLabel(block, text=title, text_color=TEXT_MAIN,
                     font=ctk.CTkFont(size=13, weight="bold")).pack(
            anchor="w", padx=14, pady=(12, 0))
        ctk.CTkLabel(block, text=hint, text_color=TEXT_DIM, justify="left",
                     font=ctk.CTkFont(size=10)).pack(anchor="w", padx=14, pady=(2, 8))

        for label, value, color in rows:
            line = ctk.CTkFrame(block, fg_color="transparent")
            line.pack(fill="x", padx=14, pady=1)
            ctk.CTkLabel(line, text=label, text_color=TEXT_MUTED,
                         font=ctk.CTkFont(size=12)).pack(side="left")
            ctk.CTkLabel(line, text=value, text_color=color,
                         font=ctk.CTkFont(size=12, weight="bold")).pack(side="right")
        ctk.CTkFrame(block, height=8, fg_color="transparent").pack()

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
