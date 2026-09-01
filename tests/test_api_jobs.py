# -*- coding: utf-8 -*-
"""Задачи REST API: пачка адресов с настоящей SMTP-проверкой.

Раньше через API были доступны только досетевые проверки: синтаксис, правила
провайдера, одноразовые домены. Проверить пятьдесят тысяч адресов по SMTP
было нечем — а держать HTTP-соединение часами нельзя ни клиенту, ни серверу.

Здесь обычная схема «поставил задачу — спрашиваешь статус», и три правила,
которые в ней важнее устройства: без прокси задача не стартует молча,
результаты не живут вечно, задач одновременно немного.

Сеть не трогается: настоящий конвейер подменяется.
"""
import os
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture
def registry():
    """Свой реестр на каждый тест: общий REGISTRY — состояние процесса."""
    from api.jobs import JobRegistry

    return JobRegistry()


def instant_runner(results=None, fail=None, hold=None):
    """Подделка конвейера: кладёт готовые результаты и заканчивает."""
    from api import jobs

    def runner(job, emails, proxies, threads, timeout):
        if hold is not None:
            hold.wait(5)
        if fail:
            jobs._finish(job, "failed", fail)
            return
        with job.lock:
            job.results.extend(results if results is not None else [
                {"email": e, "status": "Valid", "reason": "250 OK"} for e in emails])
        jobs._finish(job, "done")

    return runner


# ═══════════════════════════════ постановка и опрос

def test_job_is_created_and_finishes(registry):
    code, body = registry.create(
        emails=["a@gmail.com", "b@gmail.com"], smtp=True,
        proxies=["1.2.3.4:8080"], runner=instant_runner())
    assert code == 202
    # Состояние в ответе на постановку — либо «идёт», либо уже «готово»:
    # подделка конвейера успевает закончить раньше, чем мы читаем снимок.
    # Требовать здесь именно «идёт» значило бы проверять расписание потоков,
    # а не поведение реестра.
    assert body["state"] in ("running", "done")
    assert body["total"] == 2
    assert "results" not in body, "постановка не должна тащить результаты"

    for _ in range(50):
        job = registry.get(body["job_id"])
        if job.snapshot()["state"] == "done":
            break
        time.sleep(0.02)

    done = registry.get(body["job_id"]).snapshot()
    assert done["state"] == "done"
    assert done["checked"] == 2
    assert {r["email"] for r in done["results"]} == {"a@gmail.com", "b@gmail.com"}


def test_status_of_unknown_job_is_not_an_empty_success(registry):
    """Несуществующая задача — это 404, а не пустой успешный ответ."""
    assert registry.get("нет-такой") is None


def test_status_can_be_asked_without_results(registry):
    """На большой задаче результаты весят много — их можно не тащить."""
    code, body = registry.create(emails=["a@gmail.com"], smtp=False,
                                 allow_direct=True, runner=instant_runner())
    job = registry.get(body["job_id"])
    assert "results" not in job.snapshot(with_results=False)
    assert "results" in job.snapshot(with_results=True)


# ═══════════════════════════════ прямое соединение — только по согласию

def test_smtp_without_proxies_is_refused(registry):
    """То же правило, что в окне: молча ходить напрямую нельзя.

    Через HTTP это опаснее, чем в окне: там владелец хотя бы видит, что
    нажимает, а здесь запрос может прийти откуда угодно.
    """
    code, body = registry.create(emails=["a@gmail.com"], smtp=True,
                                 runner=instant_runner())
    assert code == 400
    assert body["direct"] is True
    assert "allow_direct" in body["error"]


def test_smtp_without_proxies_runs_with_consent(registry):
    code, body = registry.create(emails=["a@gmail.com"], smtp=True,
                                 allow_direct=True, runner=instant_runner())
    assert code == 202


def test_no_smtp_needs_no_consent(registry):
    """Досетевая проверка никуда не ходит — согласия не требует."""
    code, _ = registry.create(emails=["a@gmail.com"], smtp=False,
                              runner=instant_runner())
    assert code == 202


# ═══════════════════════════════ пределы

def test_empty_list_is_refused(registry):
    code, body = registry.create(emails=[], runner=instant_runner())
    assert code == 400
    assert "emails" in body["error"]


def test_too_many_emails_are_refused(registry):
    from api.jobs import MAX_EMAILS_PER_JOB

    code, body = registry.create(
        emails=["a@gmail.com"] * (MAX_EMAILS_PER_JOB + 1),
        allow_direct=True, runner=instant_runner())
    assert code == 400
    assert str(MAX_EMAILS_PER_JOB) in body["error"]


def test_too_many_jobs_at_once_are_refused(registry):
    """Каждая задача — свой конвейер с сотней потоков.

    Пустить десяток параллельно значит уронить и сеть, и себя.
    """
    from api.jobs import MAX_ACTIVE_JOBS

    gate = threading.Event()
    try:
        for _ in range(MAX_ACTIVE_JOBS):
            code, _ = registry.create(emails=["a@gmail.com"], smtp=False,
                                      runner=instant_runner(hold=gate))
            assert code == 202
        code, body = registry.create(emails=["b@gmail.com"], smtp=False,
                                     runner=instant_runner())
        assert code == 429
        assert str(MAX_ACTIVE_JOBS) in body["error"]
    finally:
        gate.set()


# ═══════════════════════════════ отмена и уборка

def test_job_can_be_cancelled(registry):
    gate = threading.Event()
    try:
        _, body = registry.create(emails=["a@gmail.com"], smtp=False,
                                  runner=instant_runner(hold=gate))
        code, cancelled = registry.cancel(body["job_id"])
        assert code == 200
        assert cancelled["state"] == "cancelled"
    finally:
        gate.set()


def test_cancelling_an_unknown_job_says_so(registry):
    code, body = registry.cancel("нет-такой")
    assert code == 404
    assert "нет такой задачи" in body["error"]


def test_failed_job_reports_the_reason(registry):
    _, body = registry.create(emails=["a@gmail.com"], smtp=False,
                              runner=instant_runner(fail="прокси кончились"))
    for _ in range(50):
        state = registry.get(body["job_id"]).snapshot()
        if state["state"] != "running":
            break
        time.sleep(0.02)
    state = registry.get(body["job_id"]).snapshot()
    assert state["state"] == "failed"
    assert "прокси кончились" in state["error"]


def test_finished_jobs_are_purged(registry, monkeypatch):
    """API — ворота к движку, а не база данных.

    Долгоживущий сервер иначе превращается в свалку чужих вердиктов.
    """
    from api import jobs

    _, body = registry.create(emails=["a@gmail.com"], smtp=False,
                              runner=instant_runner())
    for _ in range(50):
        if registry.get(body["job_id"]).snapshot()["state"] == "done":
            break
        time.sleep(0.02)

    monkeypatch.setattr(jobs, "FINISHED_TTL_SECONDS", -1)
    assert registry.get(body["job_id"]) is None


def test_running_job_is_never_purged(registry, monkeypatch):
    """Обратная сторона: уборка не имеет права трогать работающую задачу."""
    from api import jobs

    gate = threading.Event()
    try:
        _, body = registry.create(emails=["a@gmail.com"], smtp=False,
                                  runner=instant_runner(hold=gate))
        monkeypatch.setattr(jobs, "FINISHED_TTL_SECONDS", -1)
        assert registry.get(body["job_id"]) is not None
    finally:
        gate.set()


# ═══════════════════════════════ через настоящий HTTP-обработчик

def test_endpoints_are_wired_into_the_api():
    from api.server import handle

    code, body = handle("/api/jobs/create", {"emails": ["a@gmail.com"], "smtp": True})
    assert code == 400 and body.get("direct") is True

    code, body = handle("/api/jobs/status", {"job_id": "нет"})
    assert code == 404

    code, body = handle("/api/jobs/cancel", {"job_id": "нет"})
    assert code == 404


def test_numbers_from_the_request_are_bounded():
    """100000 потоков валидатор принял бы и попробовал выполнить."""
    from api.server import _bounded

    assert _bounded(100000, 50, 1, 300) == 300
    assert _bounded(-5, 50, 1, 300) == 1
    assert _bounded("abc", 50, 1, 300) == 50
    assert _bounded(None, 50, 1, 300) == 50
    assert _bounded(120, 50, 1, 300) == 120


def test_real_runner_uses_the_same_pipeline():
    """Задача идёт тем же движком, что и окно, а не своей копией правил."""
    import inspect

    from api import jobs

    source = inspect.getsource(jobs._run_job)
    assert "from core.pipeline import ValidationPipeline" in source
    assert "deep_ping=job.smtp" in source
