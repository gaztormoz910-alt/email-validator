# -*- coding: utf-8 -*-
import csv
import io
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ui.base_store import BaseStore, PENDING

ВСЕ = ["valid", "invalid", "spam", "unknown", PENDING]


def дождаться(api_или_база, timeout=15.0):
    состояние = (api_или_база.state if isinstance(api_или_база, BaseStore)
                 else (lambda: api_или_база.state()["base"]))
    предел = time.monotonic() + timeout
    while time.monotonic() < предел:
        st = состояние()
        if not st["loading"]:
            return st
        time.sleep(0.02)
    raise AssertionError("база не дочиталась за %.0f с" % timeout)


def окно(текст):
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    api.paste({"kind": "emails", "text": текст})
    дождаться(api)
    return api


def отбор(группы, **ещё):
    фильтр = {"groups": tuple(группы), "min_score": 0, "country": [], "gender": [],
              "provider": [], "search": "", "hide_typo": False}
    фильтр.update(ещё)
    return фильтр


def test_loaded_base_is_in_the_table_before_any_check():
    api = окно("fedor.zimin@gmail.com;Фёдор;Мужской;Россия\n"
               "lida.k@mail.ru\n"
               "это не адрес\n")
    page = api.page({"groups": ["valid", PENDING]})
    assert page["total"] == 2 and page["checked"] == 0 and page["pending"] == 2, page
    first, second = page["rows"]
    assert first["email"] == "fedor.zimin@gmail.com"
    assert first["status"] == "Не проверен" and first["group"] == PENDING
    assert (first["name"], first["gender"], first["country"]) == ("Фёдор", "Мужской", "Россия")
    assert first["more"]["name_source"] == "файл" and first["more"]["pending"] is True
    assert first["provider"] == "Gmail" and second["provider"] == "Mail.ru"
    assert first["score"] == "" and first["reason"] == "" and first["when"] == ""


def test_default_page_without_pending_group_shows_only_verdicts():
    api = окно("fedor.zimin@gmail.com\n")
    assert api.page({"groups": ["valid"]})["total"] == 0


def test_state_reports_the_base():
    api = окно("a.one@gmail.com\nb.two@gmail.com\n")
    base = api.state()["base"]
    assert base == {"total": 2, "pending": 2, "loading": False, "error": ""}, base


def test_password_column_does_not_become_a_name():
    строки = "\n".join("user.n%d@gmail.com:Zq%dxk%dwp" % (i, i * 7, i * 3) for i in range(40))
    api = окно(строки)
    rows = api.page({"groups": [PENDING]})["rows"]
    assert len(rows) == 40
    assert all(row["name"] == "" for row in rows), rows[:3]


def test_verdict_moves_the_row_out_of_pending_together_with_its_twin():
    api = окно("fedor.zimin@gmail.com\nfedorzimin@gmail.com\nlida.k@mail.ru\n")
    api._on_result("fedor.zimin@gmail.com", "Valid", "250 OK", "mx", {})
    page = api.page({"groups": ВСЕ})
    assert [(r["email"], r["group"]) for r in page["rows"]] == [
        ("fedor.zimin@gmail.com", "valid"), ("lida.k@mail.ru", PENDING)], page["rows"]
    assert api.state()["base"]["pending"] == 1


def test_verdict_on_repaired_domain_marks_the_loaded_spelling():
    api = окно("olga.v@gmial.com\n")
    api._on_result("olga.v@gmail.com", "Valid", "250 OK", "mx",
                   {"original_email": "olga.v@gmial.com"})
    assert api.state()["base"]["pending"] == 0
    assert api.page({"groups": [PENDING]})["total"] == 0


def test_new_run_makes_the_whole_base_pending_again():
    api = окно("a.one@gmail.com\nb.two@gmail.com\n")
    api._on_result("a.one@gmail.com", "Invalid", "550", "mx", {})
    assert api.state()["base"]["pending"] == 1
    api._clear_results()
    assert api.state()["base"]["pending"] == 2
    assert api.page({"groups": ВСЕ})["pending"] == 2
    page = api.page({"groups": ВСЕ})
    assert [r["email"] for r in page["rows"]] == ["a.one@gmail.com", "b.two@gmail.com"]
    assert all(r["group"] == PENDING for r in page["rows"]), page["rows"]
    assert api.page({"groups": ВСЕ, "search": "gmail"})["pending"] == 2


def test_stop_forgets_the_base_in_the_table():
    api = окно("a.one@gmail.com\n")
    api.stop()
    дождаться(api)
    assert api.state()["base"]["total"] == 0
    assert api.page({"groups": ВСЕ})["total"] == 0


def test_clear_empties_the_table():
    api = окно("a.one@gmail.com\n")
    api.clear({"kind": "emails"})
    дождаться(api)
    assert api.page({"groups": ВСЕ})["total"] == 0


def test_copy_never_takes_pending_rows():
    api = окно("a.one@gmail.com\nb.two@gmail.com\n")
    api._on_result("a.one@gmail.com", "Valid", "250 OK", "mx", {})
    assert api.copy_rows({"groups": [PENDING]})["count"] == 0
    copied = api.copy_rows({"groups": ["valid", PENDING]})
    assert copied["text"] == "a.one@gmail.com" and copied["count"] == 1, copied


def test_export_never_takes_pending_rows(tmp_path):
    api = окно("a.one@gmail.com\nb.two@gmail.com\n")
    api._on_result("a.one@gmail.com", "Valid", "250 OK", "mx", {})
    path = str(tmp_path / "out.csv")
    api._export_worker(path, api._filters({"groups": ["valid", PENDING]}), 0)
    with io.open(path, encoding="utf-8-sig") as handle:
        rows = list(csv.reader(handle))
    emails = [row[0] for row in rows[1:]]
    assert emails == ["a.one@gmail.com"], rows
    said = " ".join(line["text"] for line in api.state()["log"])
    assert "Не проверенные в файл не входят" in said, said


def test_paging_continues_from_checked_into_pending():
    адреса = ["user.p%03d@gmail.com" % i for i in range(150)]
    api = окно("\n".join(адреса))
    for адрес in адреса[:120]:
        api._on_result(адрес, "Valid", "250 OK", "mx", {"engagement_score": 50})
    первая = api.page({"groups": ВСЕ, "page": 1})
    вторая = api.page({"groups": ВСЕ, "page": 2})
    assert первая["total"] == 150 and первая["pages"] == 2
    assert [r["group"] for r in первая["rows"]] == ["valid"] * 100
    assert [r["group"] for r in вторая["rows"]] == ["valid"] * 20 + [PENDING] * 30
    assert [r["email"] for r in вторая["rows"][20:]] == адреса[120:]


def test_filters_apply_to_pending_rows():
    api = окно("ivan.a@gmail.com;Иван;Мужской;Россия\n"
               "lida.b@mail.ru;Лида;Женский;США\n"
               "petr.c@gmail.com;Пётр;Мужской;США\n")

    def адреса(**ещё):
        return [r["email"] for r in api.page(dict({"groups": [PENDING]}, **ещё))["rows"]]

    assert адреса(country=["США"]) == ["lida.b@mail.ru", "petr.c@gmail.com"]
    assert адреса(gender=["Мужской"]) == ["ivan.a@gmail.com", "petr.c@gmail.com"]
    assert адреса(provider=["mail.ru"]) == ["lida.b@mail.ru"]
    assert адреса(search="PETR") == ["petr.c@gmail.com"]
    assert адреса(search="a_b") == []
    assert адреса(minScore=10) == []


def test_facets_count_pending_rows_too():
    api = окно("ivan.a@gmail.com;Иван;Мужской;Россия\n"
               "lida.b@mail.ru;Лида;Женский;США\n")
    api._on_result("ivan.a@gmail.com", "Valid", "250 OK", "mx", {"country": "Россия"})
    facets = api.facets({"groups": ["valid", PENDING]})
    countries = {item["value"]: item["count"] for item in facets["facets"]["country"]}
    assert countries == {"Россия": 1, "США": 1}, facets
    assert facets["total"] == 2


def test_verdict_that_arrives_before_the_row_is_still_counted():
    store = BaseStore()
    try:
        store.mark("late.one@gmail.com")
        store.flush()
        store.reload([{"type": "text", "content": "early@gmail.com\nlate.one@gmail.com\n"}])
        st = дождаться(store)
        assert st["total"] == 2 and st["pending"] == 1, st
        assert [r["email"] for r in store.page(отбор([PENDING]), 0, 10)] == ["early@gmail.com"]
    finally:
        store.close()


def test_marks_of_the_previous_run_do_not_leak_into_the_next():
    store = BaseStore()
    try:
        store.reload([{"type": "text", "content": "a.one@gmail.com\n"}])
        дождаться(store)
        store.mark("a.one@gmail.com")
        store.reset_checked()
        store.flush()
        assert store.state()["pending"] == 1
    finally:
        store.close()


class _ЗапираемыйПисатель:

    def __init__(self, настоящий):
        import threading

        self._настоящий = настоящий
        self.вошёл = threading.Event()
        self.отпустить = threading.Event()

    def executemany(self, sql, rows):
        if sql.lstrip().upper().startswith("UPDATE BASE SET RUN"):
            self.вошёл.set()
            assert self.отпустить.wait(10), "тест не отпустил запись"
        return self._настоящий.executemany(sql, rows)

    def __getattr__(self, имя):
        return getattr(self._настоящий, имя)


def test_reader_waits_for_marks_another_thread_is_writing():
    import threading

    store = BaseStore()
    try:
        store.reload([{"type": "text", "content": "a.one@gmail.com\nb.two@gmail.com\n"}])
        дождаться(store)
        писатель = _ЗапираемыйПисатель(store._writer)
        store._writer = писатель
        store.mark("a.one@gmail.com")
        первый = threading.Thread(target=store.flush)
        первый.start()
        assert писатель.вошёл.wait(10), "запись отметки не началась"
        увидел = []
        второй = threading.Thread(target=lambda: увидел.append(store.count(отбор([PENDING]))))
        второй.start()
        второй.join(0.3)
        assert увидел == [], "читатель ответил до записи отметки: %r" % увидел
        писатель.отпустить.set()
        первый.join(10)
        второй.join(10)
        assert увидел == [1], увидел
    finally:
        store._writer = getattr(store._writer, "_настоящий", store._writer)
        store.close()


def test_reload_abandons_the_previous_load():
    big = "\n".join("u.n%d@gmail.com" % i for i in range(30_000))
    store = BaseStore()
    try:
        store.reload([{"type": "text", "content": big}])
        store.reload([{"type": "text", "content": "only.one@gmail.com\n"}])
        st = дождаться(store)
        assert st["total"] == 1, st
        assert [r["email"] for r in store.page(отбор([PENDING]), 0, 10)] == ["only.one@gmail.com"]
    finally:
        store.close()


def test_table_reads_while_a_big_base_is_still_loading(tmp_path):
    path = tmp_path / "big.txt"
    path.write_text("\n".join("u.n%d@gmail.com" % i for i in range(60_000)), encoding="utf-8")
    store = BaseStore()
    try:
        store.reload([{"type": "file", "path": str(path)}])
        увидел_по_ходу = False
        предел = time.monotonic() + 30
        while store.state()["loading"] and time.monotonic() < предел:
            if store.page(отбор([PENDING]), 0, 5):
                увидел_по_ходу = True
            time.sleep(0.01)
        assert увидел_по_ходу, "до конца загрузки таблица была пустой"
        assert store.state()["total"] == 60_000
    finally:
        store.close()


def test_close_removes_the_temporary_file():
    store = BaseStore()
    path = store._path
    assert path and os.path.exists(path)
    store.close()
    assert not os.path.exists(path)


def _git_ignores(path):
    import subprocess
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return subprocess.run(["git", "check-ignore", "-q", path], cwd=root,
                          capture_output=True).returncode == 0


def test_base_file_never_goes_to_git():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    store = BaseStore()
    try:
        name = os.path.basename(store._path)
    finally:
        store.close()
    assert name.startswith("base_")
    for suffix in ("", "-wal", "-shm", "-journal"):
        target = os.path.join(root, "data", name + suffix)
        assert _git_ignores(target), "git готов закоммитить " + name + suffix


def test_git_control_source_file_is_not_ignored():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    assert not _git_ignores(os.path.join(root, "ui", "base_store.py"))


def test_big_list_is_not_pushed_into_the_paste_field():
    from ui.webapp import ValidatorApi

    api = ValidatorApi()
    строка = "maria.k%06d@gmail.com:Pw%06d\n"
    много = "".join(строка % (i, i) for i in range(5000))
    assert len(много) > ValidatorApi.FIELD_LIMIT
    api.paste({"kind": "emails", "text": много})
    info = api.sources()["emails"]
    assert info["editable"] is False and info["text"] == ""
    assert info["count"] == 1, "список не подключился"

    мало = ValidatorApi()
    мало.paste({"kind": "emails", "text": "ivan@gmail.com\nlida@mail.ru"})
    assert мало.sources()["emails"]["text"] == "ivan@gmail.com\nlida@mail.ru"


def _read(name):
    web = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "ui", "web")
    with io.open(os.path.join(web, name), encoding="utf-8") as handle:
        return handle.read()


def test_page_shows_pending_by_default():
    html, js = _read("index.html"), _read("app.js")
    assert '<input type="checkbox" value="pending" checked>' in html
    assert 'groups: ["valid", "pending"]' in js
    assert 'pending: "Не проверен"' in js


def test_table_refresh_is_throttled_and_lists_are_lazy():
    js = _read("app.js")
    assert 'if (ui.tab === "results" && s.log.length) await refreshRows(true);' not in js
    assert "scheduleTable(s);" in js
    body = js[js.index("async function refreshRows"):js.index("function scheduleTable")]
    assert "if (facetsDue())" in body and "rowsBusy" in body
