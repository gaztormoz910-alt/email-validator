# -*- coding: utf-8 -*-
"""Лог не показывает одну и ту же строку дважды.

Владелец прислал лог прогона, где каждая строка результата напечатана по два
раза, и решил, что дубликаты адресов не удалились. Дедупликация базы при этом
работала: во входе 142 строки, схлопнуто 12, к проверке 78 — это видно в том
же логе, и счётчики окна показывают те же 78.

Удваивался ПОКАЗ. Страница берёт накопленный хвост лога и тут же заводит
опрос. Если опрос успевал первым, он забирал очередь, а пришедший следом
хвост отдавал те же строки снова. Воспроизведено до починки: из 290
показанных строк 129 были дублями.
"""
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.webapp import ValidatorApi  # noqa: E402


def drain(api, seen, since):
    """Один тик страницы: берём только то, что после последнего номера."""
    state = api.state({"logSince": since})
    for line in state["log"]:
        seen.append(line["text"])
    return max(since, state.get("logSeq", since))


# ────────────────────────────────────────────── хвост против опроса

def test_tail_and_poll_never_show_the_same_line_twice():
    """Тот самый случай: опрос успел раньше хвоста."""
    api = ValidatorApi()
    for i in range(50):
        api._on_log("[VALID] user%d@gmail.com -> 250 OK" % i, "valid")

    seen = []
    since = 0
    # Страница успела опросить состояние до того, как вернулся хвост.
    since = drain(api, seen, since)
    for i in range(50, 80):
        api._on_log("[VALID] user%d@gmail.com -> 250 OK" % i, "valid")
    since = drain(api, seen, since)

    # И только теперь пришёл ответ на запрос хвоста.
    tail = api.log_tail()
    for line in tail["log"]:
        if line["n"] > 0 and line["text"] not in seen:
            seen.append(line["text"])

    assert len(seen) == len(set(seen)), \
        "строк показано %d, уникальных %d" % (len(seen), len(set(seen)))


def test_tail_under_a_live_stream_stays_clean():
    """Строки льются потоком, пока страница просыпается, — как на прогоне."""
    api = ValidatorApi()
    stop = threading.Event()

    def flood():
        i = 0
        while not stop.is_set() and i < 300:
            api._on_log("[VALID] user%d@gmail.com -> 250 OK" % i, "valid")
            i += 1
            time.sleep(0.001)

    thread = threading.Thread(target=flood, daemon=True)
    thread.start()

    seen, since = [], 0
    for _ in range(5):
        since = drain(api, seen, since)
        time.sleep(0.03)
    # Хвост приходит позже всех тиков — и не должен ничего повторить.
    for line in api.log_tail()["log"]:
        if line["n"] > since:
            seen.append(line["text"])

    stop.set()
    thread.join(5)

    assert len(seen) == len(set(seen)), \
        "дублей: %d" % (len(seen) - len(set(seen)))


def test_tail_reports_where_it_ended():
    """Без номера окончания страница не смогла бы попросить «только новое»."""
    api = ValidatorApi()
    api._on_log("раз", "info")
    api._on_log("два", "info")
    tail = api.log_tail()
    assert tail["seq"] == 2
    assert [line["n"] for line in tail["log"]] == [1, 2]


def test_tail_still_restores_the_log_after_a_reload():
    """Положительный контроль: хвост не должен просто перестать работать.

    Иначе «нет дублей» достигалось бы тем, что после перезагрузки страницы
    терминал оставался пустым, — а это уже чинилось раньше.
    """
    api = ValidatorApi()
    for i in range(10):
        api._on_log("строка %d" % i, "info")
    api.state()                       # страница получила всё и «перезагрузилась»
    tail = api.log_tail()["log"]
    assert len(tail) == 10


def test_tail_since_zero_returns_everything():
    """Только что открытая страница просит всё с нуля."""
    api = ValidatorApi()
    for i in range(5):
        api._on_log("строка %d" % i, "info")
    lines = api.state({"logSince": 0})["log"]
    assert len(lines) == 5


def test_tail_since_the_last_number_returns_only_new_lines():
    api = ValidatorApi()
    for i in range(5):
        api._on_log("старое %d" % i, "info")
    seq = api.state()["logSeq"]
    for i in range(3):
        api._on_log("новое %d" % i, "info")

    lines = api.state({"logSince": seq})["log"]
    assert [line["text"] for line in lines] == ["новое 0", "новое 1", "новое 2"]


def test_tail_numbering_survives_the_history_cap():
    """Хвост ограничен по длине, но номера продолжают расти.

    Иначе после переполнения буфера номера пошли бы по второму кругу, и
    страница снова получила бы старые строки как новые.
    """
    api = ValidatorApi()
    for i in range(api._history_cap + 50):
        api._on_log("строка %d" % i, "info")
    tail = api.log_tail()
    assert tail["seq"] == api._history_cap + 50
    assert len(tail["log"]) == api._history_cap
    # Номера в хвосте — последние, а не первые.
    assert tail["log"][0]["n"] > 1


def test_tail_every_line_carries_a_number():
    api = ValidatorApi()
    api._on_log("раз", "info")
    for line in api.state()["log"]:
        assert isinstance(line.get("n"), int) and line["n"] > 0, line
