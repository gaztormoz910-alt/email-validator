"""Одно окно на весь прогон тестов — и почему иначе нельзя.

На этой сборке Python (Windows Store) в процессе поднимается РОВНО ОДИН
корень Tk. Второй падает с «Can't find a usable init.tcl», хотя первый
работал: интерпретатор теряет путь к Tcl после уничтожения корня. Поэтому
любой тест, который создаёт своё окно и убивает его в tearDown, ломает все
последующие — они получают исключение и уходят в skip.

Чем это плохо. Пропущенный тест выглядит как «нет проблем», а на деле это
непроверенное утверждение. Именно так проверка отзывчивости окна — та, что
ловит замирание на десять секунд, — молча выключалась в полном прогоне,
оставаясь зелёной по отдельности.

Здесь окно создаётся один раз и живёт до конца процесса. Между тестами оно
не уничтожается, а ПРИВОДИТСЯ В ПОРЯДОК: очереди опустошаются, хранилище
чистится, фильтры и страницы возвращаются к исходным. Тесты продолжают быть
независимыми, а окно — одно.
"""

_app = None
_broken = None


def shared_app():
    """Единственное окно программы. Второй вызов отдаёт то же самое.

    Бросает RuntimeError, если Tk недоступен вовсе (нет дисплея) — вызывающий
    тест должен превратить это в skip сам, чтобы в отчёте было видно, что
    именно не проверялось.
    """
    global _app, _broken
    if _broken is not None:
        raise RuntimeError(_broken)
    if _app is None:
        try:
            from ui.gui import ValidatorApp
            _app = ValidatorApp()
            _app.withdraw()
            _app.update()
        except Exception as exc:
            _broken = f"Tk недоступен: {type(exc).__name__}: {exc}"
            raise RuntimeError(_broken) from exc
    reset_app(_app)
    return _app


def reset_app(app):
    """Возвращает окно в состояние сразу после запуска.

    Чистится всё, что тест мог наследить: накопленные результаты, очереди
    между потоками, троттлеры показа, номер страницы и фильтры. Без этого
    тесты видели бы чужие строки и зависели от порядка запуска.
    """
    import queue

    try:
        app.result_store.clear()
    except Exception:
        pass

    for name in ("validator_result_queue", "result_queue", "log_queue",
                 "stats_queue", "progress_queue"):
        pipe = getattr(app, name, None)
        if pipe is None:
            continue
        while True:
            try:
                pipe.get_nowait()
            except queue.Empty:
                break
            except Exception:
                break

    log = getattr(app, "validator_log_queue", None)
    if log is not None:
        try:
            log.drain()
            log.dropped = 0
        except Exception:
            pass

    # Троттлеры хранят время последнего показа. Не сбросить их — значит
    # отдать следующему тесту чужое «уже показывали».
    for name in ("_stats_throttle", "_table_throttle"):
        throttle = getattr(app, name, None)
        if throttle is not None:
            try:
                throttle.last = 0.0
            except Exception:
                pass

    app._table_dirty = False
    app._stats_dirty = False
    app._shown_emails = None
    app.validator_page = 1
    app._export_busy = False
    app.email_sources = []
    app.proxy_sources = []
    try:
        app.min_score_var.set("0")
    except Exception:
        pass

    # Карточки счётчиков — это ВИДЖЕТЫ, и они хранят прошлый текст сами.
    # Пустое хранилище их не обнуляет: пока не случится показ, наверху так и
    # висит «6» от предыдущего теста, и положительный контроль соседнего
    # файла на этом падал.
    try:
        app._refresh_stat_cards()
    except Exception:
        pass
    try:
        app.refresh_validator_tree(force=True)
    except Exception:
        pass
    try:
        app.update()
    except Exception:
        pass
