"""Переделка внешнего вида не имеет права ломать окно и путать заново.

Два разных обещания, и оба проверяются здесь.

ПЕРВОЕ — контракт. Логика окна и полторы сотни тестов обращаются к виджетам
по именам: stat_1, terminal_box, db_selector, min_score_var и так далее.
Разметку можно перебирать сколько угодно, но если исчезнет хоть одно имя,
сломается не вид, а работа: перестанут обновляться счётчики, отвалится
экспорт, посыплются тесты, которые к дизайну отношения не имеют.

ВТОРОЕ — простота, ради которой всё и затевалось. Простоту легко объявить и
незаметно потерять: достаточно добавить в панель ещё один «очень нужный»
переключатель, потом ещё один — и через месяц там снова десять органов
управления. Поэтому она измеряется числом, а не описывается словами.
"""
import io
import os
import re
import sys
import unittest

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from tests.gui_fixture import shared_app


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

# Имена, на которые опирается всё остальное. Список собран не рукой: он
# получен пересечением «что создаёт разметка» и «что читает остальной код».
CONTRACT = [
    # chk_ai / chk_cache / chk_osint_val / chk_resume убраны из окна
    # 05.09.2026: пять настроек качества включены в ядре, щёлкать их
    # вручную больше не нужно. Фильтры результатов (chk_valid и
    # прочие) к ним отношения не имеют и остаются.
    "chk_invalid_var", "chk_spam_var",
    "chk_unknown_var", "chk_valid_var", "chunk_entry", "controls_frame",
    "country_mode_hint", "country_mode_seg", "country_mode_var", "db_selector",
    "dork_selector", "engine_frame", "engine_selector", "engine_var",
    "export_btn", "lbl_page", "loaded_lbl", "loaded_proxies_lbl",
    "log_note_lbl", "main_title_lbl", "min_score_var", "parser_proxy_frame",
    "parser_proxy_selector", "parser_sidebar_frame", "parser_threads_slider",
    "parser_timeout_slider", "parser_workspace", "pause_btn", "percent_lbl",
    "progress_bar", "progress_lbl", "proxy_cards", "proxy_selector",
    "proxy_view", "start_btn", "stat_0", "stat_1", "stat_2", "stat_3",
    "stat_4", "stat_names", "stop_btn", "sub_title_lbl", "suppress_btn",
    "table_view", "tab_seg", "terminal_box", "terminal_view", "threads_slider",
    "timeout_slider", "tree", "validator_sidebar_frame", "validator_workspace",
    "dashboard_frame", "filter_frame", "score_filter_frame", "actions_frame",
    "pagination_frame", "table_export_frame", "min_score_entry", "copy_btn",
    "copy_logs_btn", "btn_prev_page", "btn_next_page", "chk_valid",
    "chk_invalid", "chk_spam", "chk_unknown", "mode_switcher", "sidebar",
    "max_hw_threads",
]


class TestWidgetContractSurvives(unittest.TestCase):

    def setUp(self):
        try:
            self.app = shared_app()
        except RuntimeError as exc:
            self.skipTest(str(exc))

    def test_every_name_still_exists(self):
        missing = [name for name in CONTRACT if not hasattr(self.app, name)]
        self.assertEqual(missing, [],
                         f"переделка вида снесла виджеты: {missing}")

    def test_counters_are_widgets_that_can_show_text(self):
        for name in ("stat_0", "stat_1", "stat_2", "stat_3", "stat_4", "stat_names"):
            with self.subTest(card=name):
                widget = getattr(self.app, name)
                widget.configure(text="42")
                self.assertEqual(widget.cget("text"), "42")

    def test_run_buttons_are_wired_to_the_pipeline(self):
        """Кнопка, которая ничего не запускает, — худший вид красивой кнопки."""
        for name, handler in (("start_btn", "start_process"),
                              ("pause_btn", "pause_process"),
                              ("stop_btn", "stop_process")):
            with self.subTest(button=name):
                command = getattr(self.app, name).cget("command")
                self.assertTrue(callable(command), f"{name} без обработчика")

    def test_buttons_say_what_they_do(self):
        """Иконка без слова заставляет угадывать. Здесь нужны слова."""
        for name in ("start_btn", "pause_btn", "stop_btn"):
            with self.subTest(button=name):
                text = getattr(self.app, name).cget("text")
                self.assertTrue(any(ch.isalpha() for ch in text),
                                f"{name} подписан только значком: {text!r}")


class TestProgressiveDisclosure(unittest.TestCase):
    """Простота измеряется числом видимого, а не объявляется в описании."""

    # Считаются НАСТРОЙКИ — то, по чему от человека требуется решение:
    # переключатели, ползунки, списки. Кнопки сюда не входят: «Выбрать файл»
    # и «Начать проверку» решения не требуют, они и есть сам путь.
    #
    # До переделки таких решений было восемь, и все — сразу на виду: потоки,
    # ожидание, три тумблера, режим страны и два переключателя «файл/текст».
    # Осталось два, и оба про формат ввода, а не про работу алгоритма.
    MAX_VISIBLE_SETTINGS = 3

    def setUp(self):
        try:
            self.app = shared_app()
        except RuntimeError as exc:
            self.skipTest(str(exc))

    def _is_placed(self, widget, stop):
        """Размещён ли виджет и все его предки вплоть до stop.

        winfo_ismapped() здесь не годится: окно в тестах скрыто через
        withdraw(), и тогда НИ ОДИН виджет не считается отображённым — счётчик
        всегда даёт ноль и проверка становится пустой. Менеджер геометрии
        отвечает на нужный вопрос независимо от того, показано ли окно:
        pack_forget() очищает его, а вложенность учитывается подъёмом по
        родителям.
        """
        node = widget
        while node is not None and node is not stop:
            try:
                if not node.winfo_manager():
                    return False
                node = node.master
            except Exception:
                return False
        return True

    def _visible_controls(self, widget):
        """Настройки, размещённые прямо сейчас. Кнопки не считаются."""
        import customtkinter as ctk
        kinds = (ctk.CTkSwitch, ctk.CTkSlider, ctk.CTkOptionMenu,
                 ctk.CTkSegmentedButton, ctk.CTkCheckBox)
        found = 0
        stack = list(widget.winfo_children())
        while stack:
            child = stack.pop()
            if isinstance(child, kinds) and self._is_placed(child, widget):
                found += 1
            stack.extend(child.winfo_children())
        return found

    def test_expert_settings_are_hidden_until_asked(self):
        self.app.update()
        self.assertFalse(self.app.settings_open,
                         "блок настроек раскрыт при старте")
        self.assertFalse(self.app.settings_body.winfo_ismapped(),
                         "экспертные настройки видны сразу")

    def test_sidebar_does_not_overwhelm_at_start(self):
        self.app.update()
        visible = self._visible_controls(self.app.validator_sidebar_frame)
        self.assertLessEqual(
            visible, self.MAX_VISIBLE_SETTINGS,
            f"в панели сразу требуется {visible} решений — "
            "прогрессивное раскрытие потеряно")

    def test_settings_open_on_demand_and_close_back(self):
        self.app.update()
        before = self._visible_controls(self.app.validator_sidebar_frame)

        self.app._toggle_settings()
        self.app.update()
        opened = self._visible_controls(self.app.validator_sidebar_frame)
        self.assertGreater(opened, before,
                           "щелчок по «Настройки» ничего не показал")

        self.app._toggle_settings()
        self.app.update()
        closed = self._visible_controls(self.app.validator_sidebar_frame)
        self.assertEqual(closed, before, "настройки не свернулись обратно")

    def test_positive_control_counter_sees_hidden_controls(self):
        """Контроль: счётчик обязан РАЗЛИЧАТЬ скрытое и показанное.

        Иначе проверка выше зелёная просто потому, что счётчик не считает.
        """
        # Считаем ОТ ПАНЕЛИ, а не от самого блока настроек: цепочка проверки
        # родителей должна пройти через settings_body, иначе его собственная
        # скрытость в расчёт не попадёт и контроль ничего не проверит.
        panel = self.app.validator_sidebar_frame
        settings = {id(w) for w in self._all_children(self.app.settings_body)}

        self.app.update()
        hidden = self._count_in(panel, settings)
        self.app._toggle_settings()
        self.app.update()
        shown = self._count_in(panel, settings)
        self.app._toggle_settings()
        self.app.update()

        self.assertEqual(hidden, 0, "счётчик видит скрытое как видимое")
        self.assertGreater(shown, 0, "счётчик не видит показанное")

    def _all_children(self, widget):
        stack, out = list(widget.winfo_children()), []
        while stack:
            child = stack.pop()
            out.append(child)
            stack.extend(child.winfo_children())
        return out

    def _count_in(self, root, allowed_ids):
        """Сколько настроек из заданного набора размещено прямо сейчас."""
        import customtkinter as ctk
        kinds = (ctk.CTkSwitch, ctk.CTkSlider, ctk.CTkOptionMenu,
                 ctk.CTkSegmentedButton, ctk.CTkCheckBox)
        found = 0
        for child in self._all_children(root):
            if (id(child) in allowed_ids and isinstance(child, kinds)
                    and self._is_placed(child, root)):
                found += 1
        return found


class TestPaletteIsChecked(unittest.TestCase):
    """Палитра проверяется формулой, а не глазом."""

    def test_all_pairs_pass_wcag(self):
        sys.path.insert(0, ROOT)
        from tools.check_contrast import main as check
        self.assertEqual(check(), 0, "палитра не проходит WCAG AA")

    def test_no_raw_hex_left_in_layout(self):
        """Цвет, вписанный прямо в разметку, мимо палитры не проверяется."""
        source = io.open(os.path.join(ROOT, "ui", "panels.py"),
                         encoding="utf-8").read()
        # Отбрасываем строки комментариев: там hex встречается как пояснение.
        code = "\n".join(line.split("#", 1)[0] for line in source.splitlines())
        stray = re.findall(r'"#[0-9A-Fa-f]{3,8}"', code)
        self.assertEqual(stray, [],
                         f"цвета мимо палитры: {stray}")


class TestStartHintTellsTheTruth(unittest.TestCase):
    """Подсказка под кнопкой запуска обязана описывать текущее состояние.

    Статичная строка «сначала выберите файлы» врёт с того момента, как файлы
    выбраны, и человек, сделавший всё правильно, продолжает видеть упрёк.
    А кнопка запуска до выбора файлов молчит — без подсказки это читается как
    поломка, а не как «не хватает данных».
    """

    def setUp(self):
        try:
            self.app = shared_app()
        except RuntimeError as exc:
            self.skipTest(str(exc))
        self.app.email_sources = []
        self.app.proxy_sources = []

    def _hint(self):
        self.app._refresh_start_hint()
        return self.app.start_hint.cget("text")

    def test_names_what_is_missing(self):
        self.assertIn("адреса", self._hint())
        self.assertIn("прокси", self._hint())

    def test_names_only_what_is_still_missing(self):
        self.app.email_sources = [{"type": "text", "content": "a@b.com"}]
        text = self._hint()
        self.assertIn("прокси", text)
        self.assertNotIn("адреса", text,
                         "просит то, что уже загружено")

    def test_says_ready_when_everything_is_loaded(self):
        self.app.email_sources = [{"type": "text", "content": "a@b.com"}]
        self.app.proxy_sources = [{"type": "text", "content": "1.2.3.4:1080"}]
        self.assertIn("готово", self._hint().lower())

    def test_goes_back_to_asking_after_clearing(self):
        self.app.email_sources = [{"type": "text", "content": "a@b.com"}]
        self.app.proxy_sources = [{"type": "text", "content": "1.2.3.4:1080"}]
        self._hint()
        self.app.email_sources = []
        self.assertIn("адреса", self._hint(),
                      "после очистки подсказка осталась «всё готово»")


if __name__ == "__main__":
    unittest.main()
