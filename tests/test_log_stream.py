# -*- coding: utf-8 -*-
import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.webapp import ValidatorApi


def drain(api, seen, since):
    state = api.state({"logSince": since})
    for line in state["log"]:
        seen.append(line["text"])
    return max(since, state.get("logSeq", since))


def test_tail_and_poll_never_show_the_same_line_twice():
    api = ValidatorApi()
    for i in range(50):
        api._on_log("[VALID] user%d@gmail.com -> 250 OK" % i, "valid")

    seen = []
    since = 0
    since = drain(api, seen, since)
    for i in range(50, 80):
        api._on_log("[VALID] user%d@gmail.com -> 250 OK" % i, "valid")
    since = drain(api, seen, since)

    tail = api.log_tail()
    for line in tail["log"]:
        if line["n"] > 0 and line["text"] not in seen:
            seen.append(line["text"])

    assert len(seen) == len(set(seen)), \
        "строк показано %d, уникальных %d" % (len(seen), len(set(seen)))


def test_tail_under_a_live_stream_stays_clean():
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
    for line in api.log_tail()["log"]:
        if line["n"] > since:
            seen.append(line["text"])

    stop.set()
    thread.join(5)

    assert len(seen) == len(set(seen)), \
        "дублей: %d" % (len(seen) - len(set(seen)))


def test_tail_reports_where_it_ended():
    api = ValidatorApi()
    api._on_log("раз", "info")
    api._on_log("два", "info")
    tail = api.log_tail()
    assert tail["seq"] == 2
    assert [line["n"] for line in tail["log"]] == [1, 2]


def test_tail_still_restores_the_log_after_a_reload():
    api = ValidatorApi()
    for i in range(10):
        api._on_log("строка %d" % i, "info")
    api.state()
    tail = api.log_tail()["log"]
    assert len(tail) == 10


def test_tail_since_zero_returns_everything():
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
    api = ValidatorApi()
    for i in range(api._history_cap + 50):
        api._on_log("строка %d" % i, "info")
    tail = api.log_tail()
    assert tail["seq"] == api._history_cap + 50
    assert len(tail["log"]) == api._history_cap
    assert tail["log"][0]["n"] > 1


def test_tail_every_line_carries_a_number():
    api = ValidatorApi()
    api._on_log("раз", "info")
    for line in api.state()["log"]:
        assert isinstance(line.get("n"), int) and line["n"] > 0, line
