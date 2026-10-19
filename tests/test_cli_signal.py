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
