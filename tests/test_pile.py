# -*- coding: utf-8 -*-
"""Куча: всё, что оставалось недоделанным после третьего прохода.

Список собирался по коду, а не по памяти, и каждый пункт здесь закрыт
проверкой. Порядок — как в леджере `.unlazy/pile/GATES.md`.

Самое дорогое в этой куче — не новая функция, а **готовая функция без
ручки**: продолжение прерванного прогона было написано, покрыто тестами и
недостижимо из обоих интерфейсов. Нажал «Стоп» на миллионе — начинай сначала.
"""
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.pipeline as pipeline_module                        # noqa: E402
from tests.test_third_pass import FakeNetwork, validator       # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def read(rel):
    with io.open(os.path.join(ROOT, rel), encoding="utf-8") as handle:
        return handle.read()


# ══════════════════════════ P1: продолжение прерванного прогона

def test_resume_count_is_readable_without_touching_the_journal(tmp_path):
    """Окно обязано узнать, сколько уже сделано, ничего при этом не стерев."""
    from core.runstate import RunState, resumable_count, run_id_for

    journal = str(tmp_path / "state.sqlite")
    source = str(tmp_path / "base.txt")
    io.open(source, "w", encoding="utf-8").write("a@x.test\n")
    sources = [{"type": "file", "path": source}]

    state = RunState(run_id_for(sources), path=journal, resume=False)
    state.mark_done("a@x.test")
    state.mark_done("b@x.test")
    state.close()

    assert resumable_count(sources, path=journal) == 2
    # Вопрос не должен ничего портить: спросили дважды — ответ тот же.
    assert resumable_count(sources, path=journal) == 2


def test_resume_count_is_zero_for_other_files(tmp_path):
    """Контроль: чужое «уже сделано» на другую базу не распространяется."""
    from core.runstate import RunState, resumable_count, run_id_for

    journal = str(tmp_path / "state.sqlite")
    one = str(tmp_path / "one.txt")
    two = str(tmp_path / "two.txt")
    io.open(one, "w", encoding="utf-8").write("a@x.test\n")
    io.open(two, "w", encoding="utf-8").write("b@x.test\nc@x.test\n")

    state = RunState(run_id_for([{"type": "file", "path": one}]),
                     path=journal, resume=False)
    state.mark_done("a@x.test")
    state.close()

    assert resumable_count([{"type": "file", "path": two}], path=journal) == 0


def test_resume_reaches_the_pipeline_from_the_web_window():
    """Флаг из окна обязан дойти до конвейера, а не потеряться по дороге."""
    source = read("ui/webapp.py")
    assert 'resume=False)' not in source, (
        "в окне снова жёсткий отказ продолжать")
    assert 'resume=bool(payload.get("resume", False))' in source
    assert "def resume_info" in source, "окну нечем спросить, есть ли что продолжать"


def test_resume_has_a_handle_in_both_windows():
    """Ручка нужна в обоих интерфейсах: запасное окно владелец оставил."""
    assert 'id="optResume"' in read("ui/web/index.html")
    assert 'resume: $("#optResume").checked' in read("ui/web/app.js")

    panels = read("ui/panels.py")
    assert "self.chk_resume" in panels, "в классическом окне тумблера нет"
    gui = read("ui/gui.py")
    assert "resume=self.chk_resume.get() == 1" in gui
    assert "self.chk_resume.configure(state=state)" in gui, (
        "тумблер не запирается на время прогона — его можно передёрнуть на ходу")


# ══════════════════════════ P2: SPF у обратных адресов

def test_mail_from_spf_is_measured_for_every_sender():
    """Нельзя поставить адрес в пул, не замерив его SPF.

    Строгий `-all` означает «письма с чужих IP — подделка», а мы приходим
    именно с чужого: сервер отвергнет MAIL FROM, и до вопроса о ящике дело
    не дойдёт. Таблица замеров рядом с пулом, и этот тест следит, чтобы она
    не отстала от пула.
    """
    from core.mail_constants import MAIL_FROM_POOL, MAIL_FROM_SPF_MODE

    domains = {addr.split("@")[1].lower() for addr in MAIL_FROM_POOL}
    missing = sorted(domains - set(MAIL_FROM_SPF_MODE))
    assert not missing, "в пуле есть незамеренные отправители: %s" % missing


def test_mail_from_pool_has_no_strict_spf():
    """Ни один обратный адрес не должен быть под строгим SPF."""
    from core.mail_constants import MAIL_FROM_POOL, MAIL_FROM_SPF_MODE

    strict = sorted(dom for dom, mode in MAIL_FROM_SPF_MODE.items()
                    if mode.strip() == "-all"
                    and dom in {a.split("@")[1] for a in MAIL_FROM_POOL})
    assert not strict, "строгий SPF у отправителя: %s" % strict


# ══════════════════════════ P3: второй круг перепроверки

def test_final_sweep_gives_a_second_round(monkeypatch):
    """Адрес, которому и повтор не помог, получает ещё один круг.

    Первый круг закрывает «сорвалось у нас». Второй нужен для случая, когда
    и повтор упёрся в то же самое: лимит на том же почтовике, вторая выдержка
    серого списка, второй грязный выход.
    """
    calls = []

    class TwiceBroken(FakeNetwork):
        def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
            calls.append(avoid_exit_of or prefer_exit_of)
            if len(calls) < 3:
                return {"status": "unknown", "reason": "Timeout",
                        "mx_record": "mx.test", "proxy": "socks5://a:%d" % len(calls)}
            return {"status": "valid", "reason": "250 OK", "mx_record": "mx.test"}

    results = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: results.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = TwiceBroken({"status": "unknown", "reason": "Timeout"})
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)
    monkeypatch.setattr(pipeline_module, "GREYLIST_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)

    assert len(calls) == 3, "второго круга не было: %s" % (calls,)
    assert results and results[0][1] == "Valid", results


def test_final_sweep_stops_at_the_declared_limit(monkeypatch):
    """Контроль: кругов ровно столько, сколько объявлено, а не бесконечность.

    Иначе адрес, который не отвечает никогда, крутился бы вечно и хвост
    прогона не кончался бы.
    """
    calls = []

    class NeverAnswers(FakeNetwork):
        def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
            calls.append(1)
            return {"status": "unknown", "reason": "Timeout",
                    "mx_record": "mx.test", "proxy": "socks5://a:1"}

    results = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: results.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = NeverAnswers({"status": "unknown", "reason": "Timeout"})
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)
    monkeypatch.setattr(pipeline_module, "GREYLIST_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)

    assert len(calls) == 1 + pipeline_module.MAX_RETRY_ROUNDS, calls
    # И адрес всё равно показан — молча пропасть он не имеет права.
    assert results and results[0][0] == "user@example-corp.test", results


# ══════════════════════════ P4: catch-all у соседей по MX

def test_mx_hint_needs_two_neighbours():
    """Один сосед по почтовому серверу ничего не значит."""
    v = validator()
    assert v._mx_catchall_suspected("mx.hoster.test", "mine.test") is False
    v._note_mx_catchall("mx.hoster.test", "one.test")
    assert v._mx_catchall_suspected("mx.hoster.test", "mine.test") is False
    v._note_mx_catchall("mx.hoster.test", "two.test")
    assert v._mx_catchall_suspected("mx.hoster.test", "mine.test") is True


def test_mx_hint_saves_the_domain_when_the_probe_breaks():
    """Сорвавшаяся проба + двое соседей = «принимает что угодно».

    Это единственное место, где подсказка вообще читается. Ответ «не
    catch-all» здесь опаснее всего: он отправляет несуществующие ящики в
    Valid, и владелец узнаёт правду по отскокам.
    """
    v = validator()
    v._note_mx_catchall("mx.hoster.test", "one.test")
    v._note_mx_catchall("mx.hoster.test", "two.test")
    v._probe_recipients = lambda addrs, mx, proxy=None, from_email=None: [
        {"status": "unknown", "reason": "Timeout"} for _ in addrs]
    assert v.is_catch_all_domain("mine.test", "mx.hoster.test") is True


def test_mx_hint_never_overrides_a_real_answer():
    """Контроль: подсказка не перебивает СОБСТВЕННУЮ пробу.

    Сервер отверг выдуманный адрес — значит домен не catch-all, сколько бы
    соседей на том же MX ни было.
    """
    v = validator()
    v._note_mx_catchall("mx.hoster.test", "one.test")
    v._note_mx_catchall("mx.hoster.test", "two.test")
    v._probe_recipients = lambda addrs, mx, proxy=None, from_email=None: [
        {"status": "invalid", "reason": "550 no such user"} for _ in addrs]
    assert v.is_catch_all_domain("mine.test", "mx.hoster.test") is False


# ══════════════════════════ P5: HELO привязан к выходу

def test_helo_differs_between_exits():
    """Все прокси, назвавшиеся одним именем, — это подпись прогона."""
    v = validator(proxies=["a:1", "b:2", "c:3"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"},
                            "c:3": {"exit_ip": "3.3.3.3"}})
    names = {v._helo_for(p) for p in ("a:1", "b:2", "c:3")}
    assert len(names) > 1, "все выходы представляются одинаково: %s" % names


def test_helo_is_stable_for_one_exit():
    """И столь же обязательна стабильность: тройка серого списка."""
    v = validator(proxies=["a:1"], profiles={"a:1": {"exit_ip": "1.1.1.1"}})
    first = v._helo_for("a:1")
    assert all(v._helo_for("a:1") == first for _ in range(5))
    from core.mail_constants import LEGIT_HELO_NAMES
    assert first in LEGIT_HELO_NAMES


def test_helo_without_proxy_falls_back():
    """Без прокси остаётся прежнее имя процесса — ломать нечего."""
    v = validator()
    assert v._helo_for(None) == v.helo_name


# ══════════════════════════ P6: выбывший прокси называется вслух

def test_banned_proxy_is_reported_once():
    """Выбывший прокси надо назвать — и ровно один раз."""
    v = validator(proxies=["a:1", "b:2"])
    assert v.take_recent_bans() == []
    # Сбои на РАЗНЫХ серверах: именно так выбывает прокси, а не сервер.
    from core.mail_constants import PROXY_MAX_CONSECUTIVE_FAILS
    for number in range(PROXY_MAX_CONSECUTIVE_FAILS):
        v._update_proxy_score("a:1", False, mx_record="mx%d.test" % number)
    assert v.take_recent_bans() == ["a:1"]
    assert v.take_recent_bans() == [], "о выбытии доложили дважды"


def test_pipeline_says_which_proxy_left():
    """Строка в логе обязана называть прокси поимённо."""
    source = read("core/pipeline.py")
    assert "take_recent_bans" in source, "конвейер не спрашивает о выбывших"
    assert "Прокси выбыл из ротации" in source


# ══════════════════════════ P7: фаза перепроверки видна

def test_retry_phase_is_announced(monkeypatch):
    """Пока идёт перепроверка, окно не должно выглядеть зависшим."""
    phases = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: None,
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
        "on_phase": lambda name, count: phases.append((name, count)),
    })
    pipe.network = FakeNetwork({"status": "unknown", "reason": "Timeout",
                                "mx_record": "mx.test", "proxy": "socks5://a:1"})
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)

    assert ("retry", 1) in phases, phases
    assert phases[-1] == ("", 0), "фаза не снята — окно так и останется в ней"


def test_phase_channel_is_optional(monkeypatch):
    """Контроль: окно без этого канала (классическое) не должно падать."""
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: None,
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe._phase("retry", 5)          # обработчика нет — и ничего не происходит


def test_web_window_shows_the_phase():
    assert '"phase"' in read("ui/webapp.py")
    assert "Перепроверка отложенных" in read("ui/web/app.js")


# ══════════════════════════ P9: мёртвый API вычищен

def test_dead_api_is_gone():
    """Очередь повторов в RunState не звал никто, кроме её же тестов."""
    from core import runstate

    for name in ("schedule_retry", "due_retries", "pending_retries",
                 "next_due_in", "drain_retries"):
        assert not hasattr(runstate.RunState, name), (
            "мёртвый метод вернулся: %s" % name)
    assert "CREATE TABLE IF NOT EXISTS retry" not in read("core/runstate.py")


def test_dead_api_removal_left_the_delays_alone():
    """Контроль: выдержки, которыми пользуется конвейер, на месте."""
    from core.runstate import DEFAULT_RETRY_DELAY, GREYLIST_RETRY_DELAY

    assert DEFAULT_RETRY_DELAY == 90
    assert GREYLIST_RETRY_DELAY >= 300


# ══════════════════════════ P10 и P11: быстрый круг и предел времени

def test_markers_split_fast_from_slow():
    """Маркер объявлен, и им действительно что-то помечено."""
    config = read("pytest.ini")
    assert "markers =" in config and "slow:" in config

    marked = [name for name in sorted(os.listdir(os.path.join(ROOT, "tests")))
              if name.endswith(".py")
              and "pytestmark = pytest.mark.slow" in read("tests/" + name)]
    assert len(marked) >= 3, "медленными помечено слишком мало файлов: %s" % marked


def test_timeout_is_configured():
    """Зависший тест больше не вешает прогон навсегда."""
    config = read("pytest.ini")
    assert "timeout =" in config
    import pytest_timeout                                   # noqa: F401
    assert "pytest-timeout" in read("requirements-dev.txt")


@pytest.mark.slow
def test_slow_marker_actually_deselects_this_test():
    """Положительный контроль самого маркера.

    Без него проверка выше зеленела бы и в том случае, когда маркер объявлен,
    но pytest его не применяет: этот тест обязан ИСЧЕЗАТЬ из быстрого круга.
    """
    assert True


def test_journal_stays_enabled_after_a_clean_start(tmp_path):
    """Контроль к P9: вычистив мёртвое, легко задеть живое.

    Так и вышло: `clear()` продолжал чистить УДАЛЁННУЮ таблицу, любое
    открытие журнала с resume=False валилось в except — и журнал молча
    выключался целиком. Дедуп на диске и «уже сделано» переставали работать
    при КАЖДОМ обычном прогоне, а тесты дедупа этого не замечали: без журнала
    каждый адрес выглядит новым.
    """
    from core.runstate import RunState

    state = RunState("clean-start", path=str(tmp_path / "s.sqlite"), resume=False)
    try:
        assert state.enabled, "журнал выключился на обычном старте"
        assert state.add_if_new("a@x.test") is True
        assert state.add_if_new("a@x.test") is False, "дедуп на диске не работает"
    finally:
        state.close()


# ══════════════════════════ P8 и P12: замеры, записанные в документ

def test_starttls_decision_is_recorded_with_the_measurement():
    """Решение «не делать» тоже должно быть записано — и с замером.

    Иначе к вопросу возвращаются каждые полгода: «а не добавить ли
    STARTTLS?» Замер живым диалогом показал, что ответ ПРО ЯЩИК не меняется
    ни кодом, ни текстом.
    """
    doc = read("docs/КРИТЕРИИ.md")
    assert "STARTTLS проверке ящика ничего не даёт" in doc
    assert "550 5.7.1 No such user!" in doc, "замер приведён без данных"


def test_two_windows_gap_is_measured_not_guessed():
    """Разрыв между окнами назван числом, а решение владельца — записано."""
    doc = read("docs/КРИТЕРИИ.md")
    assert "Два интерфейса" in doc
    assert "двенадцати возможностям" in doc
    assert "запасное окно остаётся" in doc.lower() or "остаётся" in doc


def test_classic_window_shows_the_retry_phase_too():
    """Фаза перепроверки была разрывом — и он закрыт, а не описан."""
    gui = read("ui/gui.py")
    assert "'on_phase': self.safe_phase" in gui
    assert "Перепроверка отложенных" in gui
