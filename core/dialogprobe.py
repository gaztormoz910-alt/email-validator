# -*- coding: utf-8 -*-
import io
import os
import sys
import threading
import time
import traceback

ЖДАТЬ_ДИАЛОГ = 25.0

БЫСТРЕЕ_ЧЕЛОВЕКА = 2.0


def решение(выбор, прошло):
    if not выбор and прошло < БЫСТРЕЕ_ЧЕЛОВЕКА:
        return 1, "диалог не открылся: пустой ответ за %.2f с" % прошло
    if not выбор:
        return 0, "диалог открывался, человек отказался за %.1f с" % прошло
    return 0, "диалог вернул выбор: %d файл(ов)" % len(выбор)


def run(путь_лога):
    каталог = os.path.dirname(os.path.abspath(путь_лога))
    if каталог:
        os.makedirs(каталог, exist_ok=True)
    лог = io.open(путь_лога, "w", encoding="utf-8", newline="")

    def пиши(т):
        лог.write(str(т) + "\n")
        лог.flush()

    итог = {"код": 1, "почему": "проба не дошла до конца"}

    try:
        from core.paths import app_version, is_frozen
        from ui.webapp import ValidatorApi, apply_no_throttle, start_api_server
        from core.winnoise import quiet_chromium

        пиши("MailFact проба диалога")
        пиши("  версия: %s, собран: %s" % (app_version(), is_frozen()))
        пиши("  HOMEPATH: %r" % os.environ.get("HOMEPATH"))
        пиши("  HOMEDRIVE: %r" % os.environ.get("HOMEDRIVE"))
        for имя in ("stdout", "stderr"):
            поток = getattr(sys, имя, None)
            пиши("  sys.%s: %r (пишет: %s)"
                 % (имя, type(поток).__name__ if поток is not None else None,
                    hasattr(поток, "write")))
            try:
                (поток.write("") if поток is not None else None)
                пиши("     запись в %s: без ошибки" % имя)
            except Exception as беда:
                пиши("     ЗАПИСЬ В %s ПАДАЕТ: %s: %s"
                     % (имя, type(беда).__name__, беда))
                итог["код"] = 1
                итог["почему"] = ("вывод сломан: запись в sys.%s даёт %s"
                                  % (имя, type(беда).__name__))
        пиши("  исходные: __stdout__=%s __stderr__=%s"
             % (sys.__stdout__ is None, sys.__stderr__ is None))

        apply_no_throttle()
        quiet_chromium()
        import webview

        пиши("  FileDialog.OPEN: %r"
             % getattr(getattr(webview, "FileDialog", None), "OPEN", "НЕТ"))

        api = ValidatorApi()
        _server, порт, токен = start_api_server(api)
        окно = webview.create_window(
            "MailFact проба", "http://127.0.0.1:%s/?token=%s" % (порт, токен),
            width=800, height=520, background_color="#0A0E14")
        api.window = окно

        def сколько_ждать_диалога(начало, метка="ЗАДЕРЖКА ДИАЛОГА",
                                  закрывать=False):
            try:
                from core.winicon import _окна_процесса
            except Exception:
                return
            были = set(_окна_процесса(os.getpid()))
            было_окон = len(были)
            предел = начало + 30.0
            while time.time() < предел:
                time.sleep(0.02)
                try:
                    окна = _окна_процесса(os.getpid())
                except Exception:
                    continue
                if len(окна) > было_окон:
                    пиши("  %s: %.2f с" % (метка, time.time() - начало))
                    if закрывать:
                        time.sleep(0.1)
                        try:
                            import ctypes
                            for hwnd in set(окна) - были:
                                ctypes.windll.user32.PostMessageW(
                                    ctypes.c_void_p(hwnd), 0x0010, 0, 0)
                        except Exception:
                            pass
                    return
            пиши("  %s: окно диалога не появилось за 30 с" % метка)

        def проба():
            показалось = окно.events.shown.wait(30)
            пиши("  событие 'показано' пришло: %s" % показалось)
            пиши("  поток вызова: %s" % threading.current_thread().name)
            try:
                начало = time.time()
                threading.Thread(
                    target=сколько_ждать_диалога,
                    args=(начало, "ЗАДЕРЖКА ДИАЛОГА (первый)", True),
                    daemon=True, name="секундомер-1").start()
                api._pick_files("emails")

                начало = time.time()
                threading.Thread(
                    target=сколько_ждать_диалога,
                    args=(начало, "ЗАДЕРЖКА ДИАЛОГА (второй)", False),
                    daemon=True, name="секундомер-2").start()
                выбор = api._pick_files("emails")
                прошло = time.time() - начало
                пиши("  ДИАЛОГ ВЕРНУЛ: %r за %.1f с" % (выбор, прошло))
                итог["код"], итог["почему"] = решение(выбор, прошло)
            except Exception as беда:
                пиши("  ДИАЛОГ УПАЛ: %s: %s" % (type(беда).__name__, беда))
                пиши(traceback.format_exc())
                итог["код"] = 1
                итог["почему"] = "%s: %s" % (type(беда).__name__, беда)
            finally:
                try:
                    окно.destroy()
                except Exception:
                    pass

        threading.Thread(target=проба, daemon=True, name="проба").start()

        def сторож():
            time.sleep(ЖДАТЬ_ДИАЛОГ + 35)
            пиши("  СТОРОЖ: вызов не вернулся — значит диалог открыт и ждёт")
            пиши("DIALOG_OK (открыт и ждёт человека)")
            лог.close()
            os._exit(0)

        threading.Thread(target=сторож, daemon=True, name="сторож").start()
        webview.start(private_mode=False)
    except Exception:
        пиши("ИСКЛЮЧЕНИЕ ВНЕ ПРОБЫ:")
        пиши(traceback.format_exc())
        итог["код"] = 1
        итог["почему"] = "проба не поднялась"

    пиши("")
    if итог["код"] == 0:
        пиши("DIALOG_OK (%s)" % итог["почему"])
    else:
        пиши("DIALOG_BROKEN: %s" % итог["почему"])
    лог.close()
    return итог["код"]
