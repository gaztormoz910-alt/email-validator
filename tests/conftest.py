# -*- coding: utf-8 -*-
import os
import shutil
import sys
import tempfile
import threading

import pytest

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, КОРЕНЬ)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _увести_данные_во_временную_папку():
    if os.environ.get("MAILFACT_DATA_DIR"):
        return
    временная = tempfile.mkdtemp(prefix="mailfact-tests-data-")
    исток = os.path.join(КОРЕНЬ, "data")
    ПИШУЩИЕСЯ = (".sqlite", ".sqlite-shm", ".sqlite-wal", ".log")
    if os.path.isdir(исток):
        for имя in os.listdir(исток):
            путь = os.path.join(исток, имя)
            if os.path.isdir(путь):
                shutil.copytree(путь, os.path.join(временная, имя),
                                dirs_exist_ok=True)
                continue
            if имя.endswith(ПИШУЩИЕСЯ) or имя.startswith("results_"):
                continue
            if имя == "settings.json":
                continue
            try:
                shutil.copyfile(путь, os.path.join(временная, имя))
            except OSError:
                pass
    os.environ["MAILFACT_DATA_DIR"] = временная


_увести_данные_во_временную_папку()


@pytest.fixture(autouse=True)
def _isolate_longterm_memory(tmp_path_factory, request):
    from core import longterm

    original = longterm.DEFAULT_PATH
    safe = "".join(ch if ch.isalnum() else "_" for ch in request.node.nodeid)[-60:]
    folder = tmp_path_factory.mktemp("longterm", numbered=True)
    longterm.DEFAULT_PATH = str(folder / ("%s.sqlite" % safe))
    yield
    longterm.DEFAULT_PATH = original


@pytest.fixture(scope="session", autouse=True)
def _закрыть_хранилища_результатов():
    import os
    import weakref

    from ui.result_store import ResultStore

    записи = []
    исходный = ResultStore.__init__

    def запомнить(self, *args, **kwargs):
        исходный(self, *args, **kwargs)
        if getattr(self, "_temporary", False):
            записи.append((weakref.ref(self), getattr(self, "_path", None)))

    ResultStore.__init__ = запомнить
    try:
        yield
    finally:
        ResultStore.__init__ = исходный
        for ссылка, путь in записи:
            хранилище = ссылка()
            if хранилище is not None:
                try:
                    хранилище.close()
                except Exception:
                    pass
            if not путь:
                continue
            for хвост in ("", "-wal", "-shm"):
                try:
                    os.remove(путь + хвост)
                except OSError:
                    pass


@pytest.fixture(autouse=True)
def _не_ходить_в_dns_за_выдуманными_mx(monkeypatch, request):
    if request.node.get_closest_marker("настоящий_mx_hosts_alive"):
        return
    try:
        from core.network import NetworkValidator
    except Exception:
        return
    monkeypatch.setattr(NetworkValidator, "mx_hosts_alive",
                        lambda self, mx_records: None, raising=False)


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "настоящий_mx_hosts_alive: тест мерит сам mx_hosts_alive и отказывается "
        "от общей подмены DNS")


@pytest.fixture(autouse=True)
def _изолировать_базу_одноразовых():
    from core import disposable

    было = set(disposable.DISPOSABLE_DOMAINS)
    try:
        yield
    finally:
        disposable.DISPOSABLE_DOMAINS.clear()
        disposable.DISPOSABLE_DOMAINS.update(было)


def _снять_эталон_списков():
    try:
        from core import disposable, provider
        return (disposable.DISPOSABLE_DOMAINS, set(disposable.DISPOSABLE_DOMAINS),
                provider._FREE_MAIL_EXTRA, set(provider._FREE_MAIL_EXTRA))
    except Exception:
        return None


_ЭТАЛОН_СПИСКОВ = _снять_эталон_списков()


@pytest.fixture(autouse=True)
def _изолировать_глобальные_списки():
    _вернуть_списки_к_эталону()
    yield
    _вернуть_списки_к_эталону()


_ЦЕЛЬ_ПОТОКА_КОНВЕЙЕРА = "ValidationPipeline.start.<locals>.worker"


@pytest.fixture(autouse=True)
def _дождаться_потоков_конвейера(_изолировать_глобальные_списки):
    до = set(threading.enumerate())
    yield
    for поток in threading.enumerate():
        if поток in до or not поток.is_alive():
            continue
        цель = getattr(поток, "_target", None)
        if getattr(цель, "__qualname__", "") != _ЦЕЛЬ_ПОТОКА_КОНВЕЙЕРА:
            continue
        поток.join(120)
        assert not поток.is_alive(), (
            "поток конвейера, запущенный тестом, не закончил за 120 с: %s" % поток.name)


def _вернуть_списки_к_эталону():
    if not _ЭТАЛОН_СПИСКОВ:
        return
    одноразовые, эталон_одноразовых, бесплатные, эталон_бесплатных = _ЭТАЛОН_СПИСКОВ
    if len(одноразовые) != len(эталон_одноразовых):
        одноразовые.clear()
        одноразовые.update(эталон_одноразовых)
    if len(бесплатные) != len(эталон_бесплатных):
        бесплатные.clear()
        бесплатные.update(эталон_бесплатных)
