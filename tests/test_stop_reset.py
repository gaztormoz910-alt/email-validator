"""«Стоп» возвращает окно к первому открытию (просьба владельца 06.11.2026).

Владелец: «когда я нажимал на стоп, то у меня в интерфейсе реально
сбрасывалось вообще всё, как если бы я впервые открыл сам софт ... А то даже
после нажатия кнопки стоп у меня полоса с прогресс баром всё равно
мерцала/анимировалась как-то бесконечно».

Мост окна проверяется здесь напрямую: после «Стопа» он отдаёт то же, что
только что открытое окно; поздние события брошенного прогона в окно не
попадают; номер строки журнала не убывает (окно просит «строки после N»);
«Начать» во время доживания движка честно отказывает, а источники при этом
можно менять. Окно (app.js) после ответа перезагружает страницу — путь
первого открытия.
"""
import io
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def новое_окно():
    """Мост, как его создаёт run(): с двумя стартовыми строками журнала."""
    from ui.webapp import ValidatorApi
    api = ValidatorApi()
    for текст, тег in api.START_LINES:
        api._on_log(текст, тег)
    return api


def нагруженное_окно():
    """Окно посреди прогона: источники, результаты, журнал, прокси, сбор."""
    api = новое_окно()
    api.paste({"kind": "emails", "text": "anna@example.com\nboris@example.org"})
    api.paste({"kind": "proxies", "text": "1.2.3.4:1080\n5.6.7.8:1080"})
    api.paste({"kind": "dorks", "text": "site:example.com \"@example.com\""})
    api._on_result("anna@example.com", "Valid", "250 OK", "mx.example.com", {"name": "Anna"})
    api._on_result("boris@example.org", "Invalid/Bounce", "550", "mx.example.org", {})
    api._on_log("[INFO] Проверяю прокси", "info")
    api._on_progress(2, 10)
    api._on_proxy_progress(100, 2799)
    api._on_phase("retry", 3)
    api._on_proxy_profile({"rows": [1, 2, 3]})
    api._state = "running"
    api._parser_result_cb("found@example.com", "dork")
    api._parser_log("[Система] Сбор идёт.", "info")
    api._parser_state = "running"
    return api


def без_времени(строки):
    return [(с["text"], с["tag"]) for с in строки]


def снимок(api):
    """То, что видит окно: состояние, журнал с начала, источники, сбор."""
    s = api.state({"logSince": 0})
    src = api.sources()
    p = api.parser_state()
    return {
        "state": s["state"], "running": s["running"], "counts": s["counts"],
        "progress": s["progress"], "proxyRunning": s["proxyProgress"]["running"],
        "proxyCounts": (s["proxyProgress"]["checked"], s["proxyProgress"]["seen"]),
        "phase": s["phase"], "proxy": s["proxy"],
        "activity": (s["activity"]["level"], s["activity"]["title"]),
        "log": без_времени(api.log_tail()["log"]),
        "sources": {k: (src[k]["count"], src[k]["title"]) for k in ("emails", "proxies", "dorks", "pproxy")},
        "ready": src["ready"],
        "parser": (p["state"], p["stats"]["found"], без_времени(api.parser_log_tail()["log"])),
    }


def test_stop_returns_the_window_to_the_first_open():
    эталон = снимок(новое_окно())
    api = нагруженное_окно()
    assert снимок(api) != эталон          # контроль: окно действительно «грязное»
    ответ = api.stop()
    assert ответ["ok"] is True
    assert снимок(api) == эталон


def test_late_events_of_the_stopped_run_do_not_reach_the_window():
    эталон = снимок(новое_окно())
    api = нагруженное_окно()
    api.stop()
    cb = api.pipeline.callbacks
    cb["on_result"]("late@example.com", "Valid", "250 OK", "mx", {})
    cb["on_log"]("[ПУЛЬС] Останавливаю — в работе 227", "info")
    cb["on_progress"](7, 10)
    cb["on_proxy_progress"](5, 6)
    cb["on_phase"]("retry", 9)
    cb["on_proxy_profile"]({"rows": [9]})
    cb["on_revise"](["example.com"], "Unknown", "catch-all")
    cb["on_complete"]()
    api._parser_result_cb("late@example.net", "dork")
    api._parser_log("[Система] Сбор адресов остановлен.", "info")
    api._parser_stats_cb(5, 5, 5, 5, 5)
    api._parser_complete_cb(True)
    assert снимок(api) == эталон


def test_log_number_never_goes_back():
    api = нагруженное_окно()
    до = api.state()["logSeq"]
    ответ = api.stop()
    assert ответ["seq"] >= до + len(api.START_LINES)
    assert api.log_tail()["seq"] == ответ["seq"]
    # Окно, видевшее всё до старого номера, получает новые стартовые строки.
    assert без_времени(api.state({"logSince": до})["log"]) == list(api.START_LINES)


def test_start_while_the_engine_is_still_freeing_refuses_honestly():
    api = нагруженное_окно()
    api.stop()
    api._starting = True           # поток брошенного прогона ещё жив
    s = api.state()
    assert s["engineBusy"] is True and s["running"] is False
    assert "завершает" in s["activity"]["detail"]
    api.paste({"kind": "emails", "text": "new@example.com"})
    ответ = api.start({"allowDirect": True})
    assert ответ["ok"] is False and ответ["error"] == api._ENGINE_FREEING
    api._starting = False


def test_sources_can_change_while_the_stopped_run_drains():
    api = нагруженное_окно()
    api.stop()
    api._starting = True
    ответ = api.paste({"kind": "emails", "text": "next@example.com"})
    assert "error" not in ответ, ответ
    assert ответ["emails"]["count"] == 1
    api._starting = False


def test_stop_during_export_clears_the_table_after_it():
    api = нагруженное_окно()
    api._export_busy = True
    api.stop()
    assert api.store.counts()["total"] == 2, "таблицу очистили посреди выгрузки"
    api._export_done()
    assert api.store.counts()["total"] == 0
    assert api._clear_store_after_export is False


def _без_запуска(api):
    """start() доходит до запуска движка, но движок не запускается."""
    api._launch_pipeline = lambda payload: None


def test_start_waits_for_an_export_that_outlived_the_stop():
    """«Стоп» посреди выгрузки, потом «Начать»: старая выгрузка, кончившись,
    стирала таблицу НОВОГО прогона (рецензия 07.11.2026)."""
    api = нагруженное_окно()
    api._export_busy = True
    api.stop()
    _без_запуска(api)
    api.paste({"kind": "emails", "text": "new@example.com"})
    ответ = api.start({"allowDirect": True})
    assert ответ["ok"] is False and "выгрузка" in ответ["error"], ответ
    api._export_done()                         # выгрузка кончилась
    ответ = api.start({"allowDirect": True})
    assert ответ["ok"] is True, ответ
    api.pipeline.callbacks["on_result"]("new@example.com", "Valid", "250 OK", "mx", {})
    api._export_busy = True                    # следующая выгрузка — уже нового прогона
    api._export_done()
    assert api.store.counts()["total"] == 1, "конец выгрузки стёр таблицу нового прогона"
    api._starting = False


def test_stop_and_export_end_decide_under_one_lock():
    """«Стоп» и конец выгрузки решают про таблицу под одним замком.

    Гонка из рецензии 07.11.2026: «Стоп» прочитал «выгрузка идёт», выгрузка
    кончилась, «Стоп» отложил очистку — таблица не очищена, а отложенная
    очистка висит до СЛЕДУЮЩЕЙ выгрузки. Прежний тест гонял два потока 200
    раз без порядка и проходил и без замка (рецензия 08.11.2026). Здесь
    замок держит сам тест: оба обязаны ждать его, а не решать мимо.
    """
    api = нагруженное_окно()
    api._export_busy = True
    замок = api._export_gate()
    стоп = threading.Thread(target=api.stop, daemon=True)
    конец = threading.Thread(target=api._export_done, daemon=True)
    замок.acquire()
    try:
        стоп.start()
        конец.start()
        стоп.join(0.5)
        конец.join(0.5)
        assert стоп.is_alive() and конец.is_alive(), "решение принято мимо замка"
        assert api._export_busy is True and api._clear_store_after_export is False
        assert api.store.counts()["total"] == 2
    finally:
        замок.release()
    стоп.join(5)
    конец.join(5)
    assert not стоп.is_alive() and not конец.is_alive()
    assert api.store.counts()["total"] == 0
    assert api._clear_store_after_export is False
    assert api._export_busy is False


def test_double_click_on_start_launches_one_engine():
    """Второй «Начать», пришедший, пока первый чистит таблицу, не запускает
    второй движок (рецензия 08.11.2026: после прогона на миллион строк
    очистка длится 0,4 с, и двойной щелчок запускал два конвейера)."""
    api = нагруженное_окно()
    api.stop()
    api.paste({"kind": "emails", "text": "one@example.com"})
    запуски = []
    жив = threading.Event()

    def запуск(payload):
        запуски.append(1)
        поток = threading.Thread(target=жив.wait, args=(30,), daemon=True)
        поток.start()
        return поток                    # «движок» жив, пока тест не отпустит

    api._launch_pipeline = запуск
    внутри, отпустить = threading.Event(), threading.Event()
    настоящая = api.store.clear

    def медленная_очистка():
        внутри.set()
        отпустить.wait(10)
        настоящая()

    api.store.clear = медленная_очистка
    ответы = {}

    def щелчок(имя):
        ответы[имя] = api.start({"allowDirect": True})

    первый = threading.Thread(target=щелчок, args=("первый",), daemon=True)
    второй = threading.Thread(target=щелчок, args=("второй",), daemon=True)
    try:
        первый.start()
        assert внутри.wait(5), "первый запуск не дошёл до очистки таблицы"
        второй.start()
        второй.join(0.5)
        assert "второй" not in ответы or ответы["второй"]["ok"] is False
    finally:
        отпустить.set()
    первый.join(5)
    второй.join(5)
    try:
        assert not первый.is_alive() and not второй.is_alive()
        assert ответы["первый"]["ok"] is True, ответы
        assert ответы["второй"] == {"ok": False, "error": "Проверка уже идёт"}, ответы
        assert len(запуски) == 1, "движок запущен %d раз" % len(запуски)
    finally:
        жив.set()


def test_start_refused_for_missing_sources_does_not_lock_the_button():
    """Отказ «сначала выберите адреса» не оставляет флаг «запускаюсь»."""
    api = новое_окно()
    _без_запуска(api)
    ответ = api.start({"allowDirect": True})
    assert ответ == {"ok": False, "error": "Сначала выберите адреса"}
    assert api._starting is False
    api.paste({"kind": "emails", "text": "one@example.com"})
    ответ = api.start({})
    assert ответ["ok"] is False and ответ.get("direct") is True
    assert api._starting is False
    assert api.start({"allowDirect": True})["ok"] is True
    api._starting = False


def test_result_caught_mid_flight_by_stop_stays_out_of_the_clean_window():
    """Результат, который движок уже начал писать в окно, «Стоп» дожидается.

    Раньше поток, прошедший проверку «окно не сброшено» ДО «Стопа», дописывал
    строку в таблицу и журнал уже ПОСЛЕ сброса: окно после перезагрузки было
    не «как при первом открытии» (рецензия 08.11.2026).
    """
    эталон = снимок(новое_окно())
    api = нагруженное_окно()
    внутри, отпустить = threading.Event(), threading.Event()
    настоящая = api.store.append

    def медленная_запись(*args, **kwargs):
        внутри.set()
        отпустить.wait(10)
        return настоящая(*args, **kwargs)

    api.store.append = медленная_запись
    движок = threading.Thread(
        target=api.pipeline.callbacks["on_result"],
        args=("late@example.com", "Valid", "250 OK", "mx", {}), daemon=True)
    стоп = threading.Thread(target=api.stop, daemon=True)
    try:
        движок.start()
        assert внутри.wait(5), "результат не дошёл до записи в таблицу"
        стоп.start()
        стоп.join(0.5)
        assert стоп.is_alive(), "«Стоп» сбросил окно, не дождавшись идущей записи"
    finally:
        отпустить.set()
    движок.join(5)
    стоп.join(5)
    assert not движок.is_alive() and not стоп.is_alive()
    api.store.append = настоящая
    assert снимок(api) == эталон


def test_parser_stop_resets_the_window_but_spares_a_running_check():
    эталон = снимок(новое_окно())
    api = нагруженное_окно()
    api._state = "idle"
    ответ = api.parser_stop()
    assert ответ["ok"] is True
    assert снимок(api) == эталон

    # Идущую проверку «Стоп» сбора не трогает.
    api2 = нагруженное_окно()
    api2.pipeline.is_running = True
    api2.parser_stop()
    s = api2.state({"logSince": 0})
    assert s["counts"]["total"] == 2 and s["state"] == "running"
    api2.pipeline.is_running = False


class _ДоживающийСбор:
    """Поток сбора после «Стопа»: остановка запрошена, а он ещё закрывает
    соединения — жив, пока тест не скажет иначе."""
    failed_reason = ""

    def __init__(self):
        self._stop_event = threading.Event()
        self._pause_event = threading.Event()
        self.жив = True

    def is_alive(self):
        return self.жив

    def stop(self):
        self._stop_event.set()


def test_collector_draining_after_stop_is_not_shown_as_running():
    """После «Стопа» сбора окно чистое и не «идёт», хотя поток ещё доживает;
    «Начать сбор» отказывает честно, а не «уже идёт» (рецензия 08.11.2026:
    окно писало «не запущено», держало поля запертыми и отвечало «Сбор уже
    идёт»)."""
    api = нагруженное_окно()
    api._state = "idle"
    сбор = _ДоживающийСбор()
    api.parser = сбор
    api.parser_stop()
    assert сбор._stop_event.is_set()
    p = api.parser_state()
    assert p["state"] == "idle" and p["running"] is False and p["engineBusy"] is True
    assert "завершает" in p["activity"]["detail"]
    api.paste({"kind": "dorks", "text": 'site:example.org "@example.org"'})
    ответ = api.parser_start({})
    assert ответ == {"ok": False, "error": api._PARSER_FREEING}
    сбор.жив = False                      # поток сбора дожил
    p = api.parser_state()
    assert p["running"] is False and p["engineBusy"] is False
    assert "завершает" not in p["activity"]["detail"]


def test_running_collector_still_says_it_is_running():
    """Контроль к тесту выше: идущий сбор по-прежнему «идёт» и «уже идёт»."""
    api = новое_окно()
    api.paste({"kind": "dorks", "text": 'site:example.org "@example.org"'})
    сбор = _ДоживающийСбор()
    api.parser = сбор
    api._parser_state = "running"
    p = api.parser_state()
    assert p["running"] is True and p["engineBusy"] is False
    assert api.parser_start({}) == {"ok": False, "error": "Сбор уже идёт"}
    сбор.жив = False


def test_new_run_brings_the_events_back():
    """Через настоящий start(): тест, который сам снимал флаг, не заметил бы,
    что start() его не снимает (рецензия 07.11.2026)."""
    api = нагруженное_окно()
    api.stop()
    _без_запуска(api)
    api.paste({"kind": "emails", "text": "again@example.com"})
    assert api.start({"allowDirect": True})["ok"] is True
    api.pipeline.callbacks["on_result"]("again@example.com", "Valid", "250 OK", "mx", {})
    assert api.state()["counts"]["total"] == 1
    api._starting = False


def _app_js():
    текст = io.open(os.path.join(КОРЕНЬ, "ui", "web", "app.js"), encoding="utf-8").read()
    return текст.replace("\r\n", "\n")


def _функция(app, заголовок):
    """Текст функции app.js от заголовка до закрывающей скобки в начале строки."""
    начало = app.index(заголовок)
    return app[начало:app.index("\n}\n", начало) + 3]


def _в_node(tmp_path, код):
    """Выполняет JS в Node.js и возвращает разобранную последнюю строку вывода.

    Поведение страницы проверяется исполнением, а не поиском подстрок: тесты
    на подстроки проходили и на app.js с перевёрнутым условием перезагрузки
    (рецензия 08.11.2026). Без Node тест честно пропускается.
    """
    import json
    import shutil
    import subprocess

    import pytest
    node = shutil.which("node")
    if node is None:
        pytest.skip("нет Node.js — поведение app.js исполнить нечем")
    файл = tmp_path / "probe.js"
    файл.write_text(код, encoding="utf-8")
    итог = subprocess.run([node, str(файл)], capture_output=True, text=True,
                          encoding="utf-8", timeout=60)
    assert итог.returncode == 0, итог.stderr
    return json.loads(итог.stdout.strip().splitlines()[-1])


_ПРОБА_СТОПА = """
const calls = {reload: 0, toasts: [], methods: [], order: []};
const location = {reload() { calls.reload += 1; calls.order.push("reload"); }};
const toast = (text, kind) => calls.toasts.push([text, kind]);
const quench = (on) => calls.order.push("quench:" + on);
let answer = null;
const api = async (method) => {
  calls.methods.push(method);
  calls.order.push("api:" + method);
  if (answer instanceof Error) throw answer;
  return answer;
};
//ФУНКЦИЯ//
(async () => {
  const out = [];
  const answers = [{ok: true}, {ok: false, error: "Движок занят"}, null, new Error("мост упал")];
  for (const a of answers) {
    answer = a; calls.reload = 0; calls.toasts = []; calls.methods = []; calls.order = [];
    const button = {disabled: false};
    await stopAndReset(button, "stop");
    out.push({reload: calls.reload, disabled: button.disabled,
              toasts: calls.toasts, methods: calls.methods, order: calls.order});
  }
  console.log(JSON.stringify(out));
})();
"""


def test_window_reloads_after_the_bridge_answers(tmp_path):
    """Окно ждёт ответа моста и перезагружается — путь первого открытия.

    Раньше обработчик был `() => api("stop")`: ответ не читался, окно
    продолжало жить прошлым прогоном. При отказе или упавшем мосте окно НЕ
    перезагружается: причина осталась бы непоказанной, а кнопка — мёртвой.
    """
    app = _app_js()
    assert 'stopAndReset($("#btnStop"), "stop")' in app
    assert 'stopAndReset($("#pBtnStop"), "parser_stop")' in app
    assert '() => api("stop")' not in app
    код = _ПРОБА_СТОПА.replace("//ФУНКЦИЯ//", _функция(app, "async function stopAndReset"))
    успех, отказ, пусто, сбой = _в_node(tmp_path, код)
    # Окно гаснет ДО запроса к мосту и остаётся погашенным до перезагрузки;
    # при отказе гашение снимается — прогон идёт, и окно обязано его показывать.
    погас = ["quench:true", "api:stop"]
    assert успех == {"reload": 1, "disabled": True, "toasts": [], "methods": ["stop"],
                     "order": погас + ["reload"]}
    assert отказ == {"reload": 0, "disabled": False, "toasts": [["Движок занят", "bad"]],
                     "methods": ["stop"], "order": погас + ["quench:false"]}
    запас = [["Не удалось остановить — попробуйте ещё раз", "bad"]]
    assert пусто == {"reload": 0, "disabled": False, "toasts": запас, "methods": ["stop"],
                     "order": погас + ["quench:false"]}
    assert сбой == {"reload": 0, "disabled": False, "toasts": запас, "methods": ["stop"],
                    "order": погас + ["quench:false"]}


_ПРОБА_ОПРОСА = """
const calls = {api: 0, nolink: 0, classes: []};
let skip = 0, missed = 0, logSeen = 0, lastStateOk = 0;
let parserSkip = 0, parserMissed = 0, lastParserOk = 0;
const ui = {};
const document = {documentElement: {classList: {
  toggle(name, on) { calls.classes.push([name, on]); }}}};
const renderNoLink = () => { calls.nolink += 1; };
// Первое, что опрос рисует после ответа моста: до него доходить нельзя.
const drawn = () => { throw new Error("НАРИСОВАНО"); };
const syncRunState = drawn, renderLive = drawn;
let release = null, fail = false;
const api = () => {
  calls.api += 1;
  return new Promise((resolve, reject) => {
    release = () => (fail ? reject(new Error("мост упал"))
                          : resolve({running: true, state: "running", activity: {}}));
  });
};
//ГАШЕНИЕ//
//ОПРОС//
const poll = //ИМЯ//;
const settle = (p) => p.then(() => "тихо", (e) => e.message);
(async () => {
  const out = {};
  let p = poll(); release();
  out.control = await settle(p);                 // контроль: без «Стопа» ответ рисуется
  p = poll(); quench(true); release();           // щелчок, пока опрос в полёте
  out.lateAnswer = await settle(p);
  const before = calls.api;
  p = poll();                                    // погашенное окно мост не опрашивает
  out.polledWhileHalted = calls.api - before;
  if (out.polledWhileHalted) release();          // иначе проба повисла бы на запросе
  await settle(p);
  quench(false); fail = true;
  p = poll(); quench(true); release();           // опрос упал уже после щелчка
  await settle(p);
  out.noLinkWhileHalted = calls.nolink;
  quench(false);
  p = poll(); release(); await settle(p);        // контроль: без «Стопа» сбой виден
  out.noLinkControl = calls.nolink;
  fail = false; skip = 0; parserSkip = 0;
  p = poll(); release();
  out.afterRefusal = await settle(p);            // мост отказал — окно снова рисует
  out.classes = calls.classes;
  console.log(JSON.stringify(out));
})();
"""


def _проба_опроса(tmp_path, заголовок, имя):
    app = _app_js()
    начало = app.index("let halted = false;")
    гашение = app[начало:app.index("\n}\n", начало) + 3]
    код = (_ПРОБА_ОПРОСА.replace("//ГАШЕНИЕ//", гашение)
           .replace("//ОПРОС//", _функция(app, заголовок)).replace("//ИМЯ//", имя))
    return _в_node(tmp_path, код)


def test_poll_answer_that_outlived_the_click_is_not_drawn(tmp_path):
    """Опрос, ушедший до щелчка «Стоп» и вернувшийся после, в окно не рисуется.

    Жалоба владельца 13.11.2026: полоса после «Стопа» ещё мерцала. Мост
    отвечает на «Стоп» не мгновенно (ждёт обработчики, стирает таблицу), а
    ответ прежнего опроса с «идёт» приходил в этот промежуток и заново
    включал бегущую полосу. Оба экрана: проверка и сбор адресов.
    """
    # Проверяется тело опроса: у обоих экранов оно в *Once, а обёртка вокруг
    # держит «один опрос в полёте» (у сборщика — с 20.11.2026).
    for заголовок, имя in (("async function tickOnce()", "tickOnce"),
                           ("async function parserTickOnce()", "parserTickOnce")):
        итог = _проба_опроса(tmp_path, заголовок, имя)
        assert итог["control"] == "НАРИСОВАНО", имя      # проба действительно видит отрисовку
        assert итог["lateAnswer"] == "тихо", имя
        assert итог["polledWhileHalted"] == 0, имя
        assert итог["noLinkWhileHalted"] == 0, имя       # «нет связи» поверх погашенного окна
        assert итог["noLinkControl"] == 1, имя
        assert итог["afterRefusal"] == "НАРИСОВАНО", имя
        assert итог["classes"][0] == ["is-halted", True], имя
        assert итог["classes"][1] == ["is-halted", False], имя


def _правило(css, селектор):
    """Объявления правила style.css с точно таким селектором: {свойство: значение}."""
    начало = css.index("\n" + селектор + " {") + 1
    тело = css[css.index("{", начало) + 1:css.index("}", начало)]
    пары = (кусок.split(":", 1) for кусок in тело.split(";") if ":" in кусок)
    return начало, {к.strip(): " ".join(з.split()) for к, з in пары}


def test_halted_window_has_no_moving_progress_bar():
    """Стиль погашенного окна снимает с полосы всё, что движется, и перебивает «бегущую».

    Бегущая заливка задана с !important, поэтому гасящее правило обязано быть
    тоже с !important, стоять позже и весить не меньше — иначе «Стоп» полосу
    не погасит. Здесь сверяется текст стиля; что браузер считает его так же,
    проверено на живой странице (отчёт правки 13.11.2026).
    """
    css = io.open(os.path.join(КОРЕНЬ, "ui", "web", "style.css"),
                  encoding="utf-8").read().replace("\r\n", "\n")
    бежит_с, бежит = _правило(css, ".progress__track.is-running .progress__bar")
    assert "progress-sweep" in бежит["animation"]        # контроль: гасить есть что
    гаснет_с, гаснет = _правило(css, "html.is-halted .progress__track .progress__bar")
    assert гаснет_с > бежит_с
    for свойство in ("animation", "transition"):
        assert гаснет[свойство] == "none !important", свойство
    assert гаснет["width"] == "0 !important"
    for селектор in ("html.is-halted .run-state .dot", "html.is-halted .live__dot"):
        assert _правило(css, селектор)[1]["animation"] == "none !important", селектор


def test_run_writes_the_same_start_lines():
    """Эталон сброса — тот же, что пишет run() при первом открытии."""
    import inspect
    from ui import webapp
    код = inspect.getsource(webapp.run)
    assert "api.START_LINES" in код


def test_stop_of_an_idle_window_leaves_journals_alone(tmp_path):
    """Сам мост журналы на диске не трогает: журнал БРОШЕННОГО прогона стирает
    его доживающий поток (core/pipeline_control.py, tests/test_stop_abort.py),
    а «Стоп» в окне без идущего прогона не стирает ничей журнал — например,
    оставленный Ctrl+C в консоли для продолжения.

    База — файлом: у текстовых источников журнал общий («empty»), и запись
    отсюда попала бы в счёт чужих тестов.
    """
    from core.runstate import RunState, resumable_count, run_id_for
    путь = tmp_path / "база.txt"
    путь.write_text("anna@example.com\nboris@example.org", encoding="utf-8")
    источники = [{"type": "file", "path": str(путь)}]
    журнал = RunState(run_id_for(источники), resume=True)
    журнал.mark_done("anna@example.com")
    журнал.close()
    до = resumable_count(источники)
    assert до >= 1                       # контроль: запись в журнале есть
    api = нагруженное_окно()
    api.stop()
    assert resumable_count(источники) == до


def test_log_number_does_not_run_ahead_of_its_lines():
    """Номер в ответе не опережает строки этого же ответа.

    Номер читался после замка: строка, дописанная в этот миг, в ответ не
    попадала, а номер её уже покрывал, и окно больше её не спрашивало.
    Здесь запись случается ровно в этот миг — на выходе из замка.
    """
    api = новое_окно()
    настоящий = api._lock

    class ЗаписьНаВыходе:
        def __enter__(self):
            настоящий.acquire()
            return self

        def __exit__(self, *exc):
            настоящий.release()
            api._lock = настоящий
            api._on_log("[INFO] дописано сразу после выборки", "info")
            return False

    api._lock = ЗаписьНаВыходе()
    ответ = api.state({"logSince": 0})
    api._lock = настоящий
    покрыто = max(строка["n"] for строка in ответ["log"])
    assert ответ["logSeq"] == покрыто
    # Пропущенная строка приходит следующим опросом.
    следующий = api.state({"logSince": ответ["logSeq"]})
    assert [с["text"] for с in следующий["log"]] == ["[INFO] дописано сразу после выборки"]


_ПРОБА_ЖУРНАЛА = """
let logShownTop = 0;
const MAX_LOG_NODES = 1000;
const document = {createDocumentFragment: () => ({items: [], appendChild(x) { this.items.push(x); }})};
const logBox = {
  scrollTop: 0, clientHeight: 0, scrollHeight: 0, childNodes: [],
  appendChild(frag) { for (const x of frag.items) this.childNodes.push(x); },
  removeChild(x) { this.childNodes.splice(this.childNodes.indexOf(x), 1); },
  get firstChild() { return this.childNodes[0]; },
};
const logSpan = (line) => line.text;
//ФУНКЦИЯ//
appendLog([{n: 1, text: "a"}, {n: 2, text: "b"}]);
appendLog([{n: 2, text: "b"}, {n: 3, text: "c"}]);   // опросы перекрылись
appendLog([{n: 1, text: "a"}]);                       // старая строка пришла снова
appendLog([{text: "без номера"}]);
appendLog(null);
console.log(JSON.stringify(logBox.childNodes));
"""


def test_window_does_not_show_a_log_line_twice(tmp_path):
    """Окно отбрасывает строку с уже показанным номером и не шлёт опрос поверх опроса."""
    app = _app_js()
    код = _ПРОБА_ЖУРНАЛА.replace("//ФУНКЦИЯ//", _функция(app, "function appendLog"))
    assert _в_node(tmp_path, код) == ["a", "b", "c", "без номера"]
    опрос = app[app.index("async function tick()"):app.index("async function tickOnce()")]
    assert "if (tickBusy) return;" in опрос
