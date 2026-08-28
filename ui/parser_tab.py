# ui/parser_tab.py
"""Вкладка парсера: сбор адресов по дорк-запросам.

Отдельный от валидации режим со своей очередью, своим логом и своими
счётчиками. Вынесено из gui.py по той же причине, по которой вынесена
разметка: две несвязанные задачи в одном файле — это файл, в котором правка
одной задевает другую.
"""
import os
import threading

import customtkinter as ctk
from tkinter import filedialog, messagebox

from ui.colors import *



class ParserTabMixin:

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
        self._attach_sources(filepaths, self.dork_sources, self.dork_selector,
                             self.loaded_dorks_lbl, "Загружено: {count}",
                             getattr(self, "safe_parser_log", None))

    def on_dorks_pasted(self, text):
        self.dork_sources.append({"type": "text", "content": text})
        self._count_lines_async(self.dork_sources, self.loaded_dorks_lbl,
                                "Загружено: {count}")

    def load_parser_proxies(self):
        # Парсер умеет все три протокола: чекер работает в режиме HTTP
        # (socks4, socks5 и CONNECT), а ProxyManager сам дописывает схему.
        # Отсеивать socks4 и HTTP значило выбрасывать часть купленного пула.
        filepaths = filedialog.askopenfilenames(filetypes=[("Text Files", "*.txt")])
        self._attach_sources(filepaths, self.parser_proxy_sources,
                             self.parser_proxy_selector,
                             self.loaded_parser_proxies_lbl,
                             "Прокси (оценка): {count}",
                             getattr(self, "safe_parser_log", None))

    def on_parser_proxies_pasted(self, text):
        self.parser_proxy_sources.append({"type": "text", "content": text})
        self._count_lines_async(self.parser_proxy_sources, self.loaded_parser_proxies_lbl,
                                "Прокси (оценка): {count}")

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
        
        engine_name = self.engine_var.get()
        proxy_sources = list(self.parser_proxy_sources)
        dork_sources = list(self.dork_sources)

        def launch():
            """Читает прокси и запускает конвейер В ФОНЕ.

            Раньше эти две строки стояли прямо в обработчике кнопки: файл
            прокси прочитывался целиком в главном потоке Tk, и на большом
            пуле окно замирало ровно между нажатием «Старт» и началом работы.
            Схлопывание повторов идёт по разобранным частям, а не по строке —
            один прокси, записанный дважды, занимал два места в ротации.
            Протоколы берутся все: чекер умеет socks4, socks5 и HTTP CONNECT.
            """
            from core.network import dedupe_proxies_stream
            actual_proxies = list(dedupe_proxies_stream(
                StreamLoader(proxy_sources).stream_lines()))

            from core.parser_pipeline import ParserPipeline
            pipeline = ParserPipeline(
                dork_sources=dork_sources,
                proxies=actual_proxies,
                max_threads=threads,
                timeout=timeout,
                on_log=self.safe_parser_log,
                on_progress=self.safe_update_parser_progress,
                on_stats_update=self.safe_update_parser_stats,
                on_result_found=self.safe_add_parser_result,
                on_complete=self.on_parser_complete,
                engine_name=engine_name,
            )
            self.parser_pipeline = pipeline
            pipeline.start()

        threading.Thread(target=launch, daemon=True).start()

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
        self._ui_call(self._reset_ui_after_parser_complete)

    def _reset_ui_after_parser_complete(self):
        self._set_playback_state("stopped")
        self._set_sidebar_state("normal")
