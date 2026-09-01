# api/jobs.py
"""Задачи REST API: проверка пачки адресов, в том числе по SMTP.

Зачем отдельно от api/server.py. Досетевые проверки отвечают мгновенно, и им
хватает обычного запроса-ответа. SMTP — нет: одна проба занимает секунды,
пачка на пятьдесят тысяч адресов идёт часами. Держать HTTP-соединение всё это
время нельзя ни со стороны клиента, ни со стороны сервера, поэтому здесь
обычная схема «поставил задачу — спрашиваешь статус».

Три правила, которым тут всё подчинено.

**Прямое соединение — только по явному согласию.** Без прокси проверка идёт с
IP той машины, где запущен сервер, и почтовики его увидят. Через HTTP это ещё
опаснее, чем в окне: там владелец хотя бы видит, что нажимает. Поэтому без
прокси задача не стартует, пока в запросе нет `allow_direct`.

**Результаты живут в памяти и стареют.** API — это ворота к движку, а не база
данных. Готовая задача хранится ограниченное время, после чего убирается:
иначе долгоживущий сервер превращается в свалку чужих вердиктов.

**Задач одновременно немного.** Каждая поднимает свой конвейер с сотней
потоков; пустить их десяток параллельно значит уронить и сеть, и себя.
"""
import threading
import time
import uuid

# Сколько задач можно держать одновременно. Каждая — это свой конвейер с
# собственным пулом потоков и собственными соединениями к почтовикам.
MAX_ACTIVE_JOBS = 3

# Сколько живёт ЗАКОНЧЕННАЯ задача, прежде чем её уберут. Хватает, чтобы
# клиент забрал результат, и мало, чтобы память не росла без предела.
FINISHED_TTL_SECONDS = 3600

# Потолок на одну задачу. Тот же, что и у пакетной досетевой проверки.
MAX_EMAILS_PER_JOB = 50_000


class Job:
    """Одна задача. Состояния: running -> done | failed | cancelled."""

    __slots__ = ("id", "state", "created_at", "finished_at", "total",
                 "results", "error", "pipeline", "lock", "smtp")

    def __init__(self, job_id, total, smtp):
        self.id = job_id
        self.state = "running"
        self.created_at = time.time()
        self.finished_at = None
        self.total = total
        self.smtp = bool(smtp)
        self.results = []
        self.error = ""
        self.pipeline = None
        self.lock = threading.Lock()

    def snapshot(self, with_results=True):
        with self.lock:
            done = len(self.results)
            body = {
                "job_id": self.id,
                "state": self.state,
                "smtp": self.smtp,
                "total": self.total,
                "checked": done,
                "created_at": int(self.created_at),
            }
            if self.error:
                body["error"] = self.error
            if with_results:
                body["results"] = list(self.results)
            return body


class JobRegistry:
    """Реестр задач. Один на процесс сервера."""

    def __init__(self):
        self._jobs = {}
        self._lock = threading.Lock()

    def _purge_locked(self):
        """Убирает задачи, за результатом которых уже не придут."""
        cutoff = time.time() - FINISHED_TTL_SECONDS
        stale = [key for key, job in self._jobs.items()
                 if job.finished_at is not None and job.finished_at < cutoff]
        for key in stale:
            self._jobs.pop(key, None)

    def active_count(self):
        with self._lock:
            self._purge_locked()
            return sum(1 for job in self._jobs.values() if job.state == "running")

    def get(self, job_id):
        with self._lock:
            self._purge_locked()
            return self._jobs.get(str(job_id or ""))

    def create(self, emails, smtp=False, proxies=None, allow_direct=False,
               threads=50, timeout=10, runner=None):
        """Ставит задачу и запускает её в фоне. Возвращает (код, тело)."""
        if not isinstance(emails, list) or not emails:
            return 400, {"error": "нужен непустой список emails"}
        if len(emails) > MAX_EMAILS_PER_JOB:
            return 400, {"error": "за одну задачу принимается не больше %d адресов"
                                  % MAX_EMAILS_PER_JOB}
        proxies = [str(p) for p in proxies] if isinstance(proxies, list) else []
        if smtp and not proxies and not allow_direct:
            # То же правило, что и в окне: молча ходить напрямую нельзя.
            return 400, {
                "direct": True,
                "error": ("SMTP-проверка без прокси пойдёт с IP этой машины, и "
                          "почтовые серверы его увидят. Если это осознанно, "
                          "передайте allow_direct: true."),
            }
        if self.active_count() >= MAX_ACTIVE_JOBS:
            return 429, {"error": "уже выполняется %d задач — дождитесь их "
                                  "окончания" % MAX_ACTIVE_JOBS}

        job = Job(uuid.uuid4().hex, len(emails), smtp)
        with self._lock:
            self._jobs[job.id] = job

        work = runner or _run_job
        thread = threading.Thread(
            target=work,
            args=(job, [str(e) for e in emails], proxies, threads, timeout),
            daemon=True)
        thread.start()
        return 202, job.snapshot(with_results=False)

    def cancel(self, job_id):
        job = self.get(job_id)
        if job is None:
            return 404, {"error": "нет такой задачи"}
        with job.lock:
            if job.state != "running":
                return 200, job.snapshot(with_results=False)
            pipeline = job.pipeline
        if pipeline is not None:
            try:
                pipeline.stop()
            except Exception:
                pass
        with job.lock:
            job.state = "cancelled"
            job.finished_at = time.time()
        return 200, job.snapshot(with_results=False)


def _finish(job, state, error=""):
    with job.lock:
        if job.state == "running":
            job.state = state
            job.error = error
        job.finished_at = time.time()


def _run_job(job, emails, proxies, threads, timeout):
    """Выполняет задачу тем же конвейером, что и окно.

    Отдельная функция, а не метод: её подменяют в тестах, чтобы проверить
    реестр, не поднимая сеть.
    """
    try:
        from core.pipeline import ValidationPipeline

        done = threading.Event()

        def on_result(email, status, reason, mx, data=None):
            payload = data if isinstance(data, dict) else {}
            with job.lock:
                job.results.append({
                    "email": email,
                    "status": status,
                    "reason": reason,
                    "mx": mx,
                    "score": payload.get("engagement_score"),
                    "provider": payload.get("provider_name"),
                    "name": payload.get("name"),
                    "gender": payload.get("gender"),
                    "country": payload.get("country"),
                })

        pipeline = ValidationPipeline(callbacks={
            "on_log": lambda *a, **k: None,
            "on_progress": lambda *a, **k: None,
            "on_proxy_progress": lambda *a, **k: None,
            "on_result": on_result,
            "on_complete": lambda *a, **k: done.set(),
            "on_unique_count": lambda *a, **k: None,
            "on_proxies_tested": lambda *a, **k: None,
            "on_proxy_profile": lambda *a, **k: None,
        })
        with job.lock:
            job.pipeline = pipeline

        pipeline.start(
            email_sources=[{"type": "text", "content": "\n".join(emails)}],
            threads=threads, timeout=timeout,
            fix_typos=True, check_spam=True, deep_ping=job.smtp,
            enable_ai=False, proxies=proxies or None,
            enable_osint=False, use_cache=True, resume=False)
        done.wait()
        _finish(job, "done")
    except Exception as exc:                      # noqa: BLE001
        _finish(job, "failed", "%s: %s" % (type(exc).__name__, exc))


REGISTRY = JobRegistry()
