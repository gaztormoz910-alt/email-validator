# -*- coding: utf-8 -*-
"""Обработчик Ctrl+C в cli.py: не берёт замков и всегда снимается.

ПОЧЕМУ СВОЙСТВО, А НЕ СЦЕНАРИЙ. Обработчик сигнала исполняется в главном
потоке МЕЖДУ его же байт-кодами. Если главный в этот миг держит внутренний
замок объекта, которого касается обработчик, обработчик ждёт сам себя вечно:
у threading.Event внутри Condition(Lock()), замок нереентерабельный. Так было
в 55632b7 — обработчик звал звонок.set(), а главный крутил звонок.wait() и
звонок.clear(); стресс-репро (сигналы без паузы) зависало и на 3.11, и на
3.13. Гонка узкая, сценарный тест её почти никогда не застанет, поэтому здесь
проверяется само свойство: внутри обработчика нет ни одного захвата замка и
ни одного вызова в threading.

Снятие обработчика проверяется отдельно: оставленный обработчик молча глотал
бы Ctrl+C до конца процесса — тесты, идущие следом, уже не смогли бы
прервать ничего.
"""
import os
import signal
import sys
import threading
import time

import pytest


def _прогон(monkeypatch, tmp_path, класс):
    import cli
    monkeypatch.setattr(cli, "ValidationPipeline", класс)
    база = tmp_path / "base.txt"
    база.write_text("a@example.com\n", encoding="utf-8")
    return cli.main(["validate", "--emails", str(база), "--allow-direct",
                     "-o", str(tmp_path / "out.csv"), "--no-ai", "--quiet"])


def _спокойный():
    from core.pipeline import ValidationPipeline

    class _Спокойный(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self._stage("check")
            self.callbacks["on_result"]("a@example.com", "Valid", "250 OK", "mx", {})
            self._finish_activity()
            self.callbacks["on_complete"]()
    return _Спокойный


def test_ctrl_c_handler_takes_no_locks(monkeypatch, tmp_path):
    поставлены = []
    настоящий = signal.signal

    def шпион(signum, handler):
        if signum == signal.SIGINT:
            поставлены.append(handler)
        return настоящий(signum, handler)
    monkeypatch.setattr(signal, "signal", шпион)

    assert _прогон(monkeypatch, tmp_path, _спокойный()) == 0
    # Первым ставится обработчик Ctrl+C; дальше идут его снятие и
    # _без_прерываний() на время записи.
    assert поставлены and callable(поставлены[0]), поставлены
    обработчик = поставлены[0]

    вызовы = []

    def профиль(frame, event, arg):
        if event == "call":
            вызовы.append(("py", os.path.basename(frame.f_code.co_filename),
                           frame.f_code.co_name))
        elif event == "c_call":
            владелец = getattr(arg, "__self__", None)
            вызовы.append(("c", type(владелец).__name__,
                           getattr(arg, "__name__", repr(arg))))

    sys.setprofile(профиль)
    try:
        обработчик(signal.SIGINT, None)
    finally:
        sys.setprofile(None)

    в_threading = [в for в in вызовы if в[0] == "py" and в[1] == "threading.py"]
    замки = [в for в in вызовы if в[0] == "c" and в[1] in ("lock", "RLock")]
    assert not в_threading and not замки, (
        "обработчик Ctrl+C берёт замок — сигнал посреди wait()/clear() "
        "главного потока повесит CLI навсегда: %r" % (вызовы,))


def test_ctrl_c_handler_is_restored_after_run(monkeypatch, tmp_path):
    до = signal.getsignal(signal.SIGINT)
    assert _прогон(monkeypatch, tmp_path, _спокойный()) == 0
    assert signal.getsignal(signal.SIGINT) is до


def test_ctrl_c_handler_is_restored_after_failure(monkeypatch, tmp_path, capsys):
    from core.pipeline import ValidationPipeline

    class _Падает(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self._stage("check")
            raise ValueError("сломалось в прогоне")

    до = signal.getsignal(signal.SIGINT)
    with pytest.raises(ValueError):
        _прогон(monkeypatch, tmp_path, _Падает)
    assert signal.getsignal(signal.SIGINT) is до


# ══════════════════════════ окна вокруг обработчика (проверка 23.10.2026)
#
# Каждый тест посылает Ctrl+C (_thread.interrupt_main) ровно в узкое окно.
# Вырвавшийся KeyboardInterrupt ловится и превращается в провал теста: иначе
# он оборвал бы всю сессию pytest, как это уже было на Python 3.11.

def _ctrl_c():
    import _thread
    _thread.interrupt_main(signal.SIGINT)
    time.sleep(0.05)             # дать обработчику сработать здесь же


def test_ctrl_c_right_after_the_run_does_not_lose_the_file(monkeypatch, tmp_path):
    """Прогон закончен, обработчик снят — до записи Ctrl+C не должен
    оборвать CLI: журнал сделанного уже на диске, и потерянные из файла
    адреса продолжение сочло бы проверенными."""
    import core.activity as активность
    исходный = активность.Pulse.stop

    def стоп(self):
        if threading.current_thread() is threading.main_thread():
            _ctrl_c()
        return исходный(self)
    monkeypatch.setattr(активность.Pulse, "stop", стоп)
    до = signal.getsignal(signal.SIGINT)
    try:
        код = _прогон(monkeypatch, tmp_path, _спокойный())
    except KeyboardInterrupt:
        pytest.fail("Ctrl+C сразу после прогона оборвал CLI до записи файла")
    assert код == 0
    assert "a@example.com" in (tmp_path / "out.csv").read_text(encoding="utf-8-sig")
    assert signal.getsignal(signal.SIGINT) is до


def test_ctrl_c_as_the_run_starts_is_a_stop_not_a_crash(monkeypatch, tmp_path):
    """Ctrl+C сразу после запуска потока прогона — это «Стоп», а не
    KeyboardInterrupt мимо всей обработки (обработчик ставится до запуска)."""
    from core.pipeline import ValidationPipeline
    исходный_старт = threading.Thread.start

    def старт(self):
        исходный_старт(self)
        if self.name == "cli-run":
            _ctrl_c()
    monkeypatch.setattr(threading.Thread, "start", старт)

    class _Долгий(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self.is_running = True
            self._stage("check")
            конец = time.monotonic() + 10
            while self.is_running and time.monotonic() < конец:
                time.sleep(0.05)
            self.callbacks["on_result"]("a@example.com", "Valid", "250 OK", "mx", {})
            self._finish_activity()
            self.callbacks["on_complete"]()

    до = signal.getsignal(signal.SIGINT)
    try:
        код = _прогон(monkeypatch, tmp_path, _Долгий)
    except KeyboardInterrupt:
        pytest.fail("Ctrl+C на старте прогона вырвался мимо обработки")
    assert код == 2
    assert "a@example.com" in (tmp_path / "out.csv").read_text(encoding="utf-8-sig")
    assert signal.getsignal(signal.SIGINT) is до


def test_failing_print_of_the_cause_still_exits_at_once(monkeypatch, tmp_path):
    """После второго Ctrl+C запись упала, и упала сама печать причины (stderr
    в файл на полном диске) — выход всё равно сразу, иначе удержанный замок
    результатов повесил бы процесс на потоках пула."""
    import traceback
    import cli
    from core.pipeline import ValidationPipeline
    выходы = []
    monkeypatch.setattr(cli, "_выйти_сразу", lambda код: выходы.append(код))

    def печать(*a, **kw):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(traceback, "print_exc", печать)
    отпусти = threading.Event()

    class _Зависший(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self.is_running = True
            self._stage("check")
            self.callbacks["on_result"]("a@example.com", "Valid", "250 OK", "mx", {})
            threading.Timer(0.3, _ctrl_c).start()
            threading.Timer(0.9, _ctrl_c).start()
            отпусти.wait(30)

    monkeypatch.setattr(cli, "ValidationPipeline", _Зависший)
    база = tmp_path / "base.txt"
    база.write_text("a@example.com\n", encoding="utf-8")
    try:
        with pytest.raises(OSError):
            cli.main(["validate", "--emails", str(база), "--allow-direct",
                      "-o", str(tmp_path / "нет" / "out.csv"), "--no-ai", "--quiet"])
    finally:
        отпусти.set()
    assert выходы == [1], выходы


def test_inherited_sig_ign_is_respected(monkeypatch, tmp_path):
    """Родитель велел Ctrl+C игнорировать («cmd &» в скрипте, «trap '' INT»)
    — CLI не ставит поверх свой обработчик: прогон доходит до конца, код 0,
    и после возврата снова SIG_IGN."""
    from core.pipeline import ValidationPipeline
    во_время = []

    class _Смотрит(ValidationPipeline):
        def setup(self, **kw):
            pass

        def run_pipeline(self, sources, **kw):
            self._stage("check")
            во_время.append(signal.getsignal(signal.SIGINT))
            self.callbacks["on_result"]("a@example.com", "Valid", "250 OK", "mx", {})
            self._finish_activity()
            self.callbacks["on_complete"]()

    до = signal.signal(signal.SIGINT, signal.SIG_IGN)
    try:
        код = _прогон(monkeypatch, tmp_path, _Смотрит)
        после = signal.getsignal(signal.SIGINT)
    finally:
        signal.signal(signal.SIGINT, до)
    assert во_время == [signal.SIG_IGN], "унаследованный SIG_IGN подменён на время прогона"
    assert после == signal.SIG_IGN
    assert код == 0
