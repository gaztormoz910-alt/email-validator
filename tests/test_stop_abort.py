import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_activity_bridge import _Net, _конвейер, _ждать


class _ВисящаяСеть(_Net):

    def __init__(self, быстрых=3):
        self.abort_event = threading.Event()
        self.быстрых = быстрых
        self.начато = 0
        self.lock = threading.Lock()

    def check_email(self, email, **_kw):
        with self.lock:
            self.начато += 1
            номер = self.начато
        if номер > self.быстрых:
            if self.abort_event.wait(30):
                return {"status": "unknown", "reason": "Проверка остановлена", "aborted": True,
                        "mx_record": "N/A"}
        return super().check_email(email)


class _Кэш:
    def __init__(self):
        self.записано = []

    def get(self, *a, **k):
        return None

    def put(self, email, *a, **k):
        self.записано.append(email)

    def close(self):
        pass

    def forget_domain(self, *a, **k):
        return 0


def _прогон(сеть, адресов=12, потоков=4, папка=None):
    p, строки, результаты = _конвейер()
    p.network = сеть
    p.cache = _Кэш()
    база = "\n".join("u%d@example.com" % i for i in range(адресов))
    источники = [{"type": "text", "content": база}]
    if папка is not None:
        путь = os.path.join(str(папка), "база.txt")
        with open(путь, "w", encoding="utf-8") as f:
            f.write(база)
        источники = [{"type": "file", "path": путь}]
    поток = threading.Thread(target=p.run_pipeline, args=(источники,),
                             kwargs=dict(threads=потоков, fix_typos=False, check_spam=False,
                                         deep_ping=True, enable_ai=False), daemon=True)
    поток.start()
    return p, поток, результаты, источники, p.cache


def test_abort_ends_the_run_in_seconds_and_drops_unfinished_addresses(tmp_path):
    from core.runstate import resumable_count
    сеть = _ВисящаяСеть(быстрых=3)
    p, поток, результаты, источники, кэш = _прогон(сеть, папка=tmp_path)
    assert _ждать(lambda: len(результаты) >= 3 and сеть.начато >= 6, 60), (
        "не дождались начатых проверок")
    выдано_до = len(результаты)
    в_кэше_до = len(кэш.записано)
    начало = time.monotonic()
    p.stop(abort=True)
    поток.join(15)
    прошло = time.monotonic() - начало
    assert not поток.is_alive(), "прогон не кончился после «Стопа»"
    assert прошло < 8, "после «Стопа» прогон шёл %.1f с" % прошло
    assert len(результаты) == выдано_до, результаты[выдано_до:]
    assert len(кэш.записано) == в_кэше_до, кэш.записано[в_кэше_до:]
    assert resumable_count(источники) == 0


def test_next_run_after_window_stop_shows_everything(tmp_path):
    сеть = _ВисящаяСеть(быстрых=3)
    p, поток, результаты, источники, _к = _прогон(сеть, папка=tmp_path)
    assert _ждать(lambda: len(результаты) >= 3 and сеть.начато >= 6, 60)
    p.stop(abort=True)
    поток.join(15)
    assert not поток.is_alive()
    p2, _строки2, результаты2 = _конвейер()
    p2.network = _Net()
    поток2 = threading.Thread(target=p2.run_pipeline, args=(источники,),
                              kwargs=dict(threads=4, fix_typos=False, check_spam=False,
                                          deep_ping=True, enable_ai=False), daemon=True)
    поток2.start()
    поток2.join(60)
    assert not поток2.is_alive()
    assert len(результаты2) == 12, результаты2


class _ГлухаяСеть(_Net):

    def __init__(self, быстрых=3):
        self.abort_event = threading.Event()
        self.отпустить = threading.Event()
        self.быстрых = быстрых
        self.начато = 0
        self.lock = threading.Lock()

    def check_email(self, email, **_kw):
        with self.lock:
            self.начато += 1
            номер = self.начато
        if номер > self.быстрых:
            self.отпустить.wait(30)
            return {"status": "unknown", "reason": "Проверка остановлена", "aborted": True,
                    "mx_record": "N/A"}
        return super().check_email(email)


def test_window_stop_wipes_done_marks_before_the_run_dies(tmp_path):
    from core.runstate import resumable_count
    сеть = _ГлухаяСеть(быстрых=3)
    p, поток, результаты, источники, _к = _прогон(сеть, папка=tmp_path)
    try:
        assert _ждать(lambda: len(результаты) >= 3 and сеть.начато >= 6, 60)
        p.state.flush()
        assert resumable_count(источники) >= 3
        p.stop(abort=True)
        assert поток.is_alive(), "контроль: брошенный прогон ещё доживает"
        assert resumable_count(источники) == 0, "журнал пережил бы закрытие окна"
        p.state.mark_done("late@example.com")
        p.state.flush()
        assert resumable_count(источники) == 0
    finally:
        сеть.отпустить.set()
    поток.join(15)
    assert not поток.is_alive()
    assert resumable_count(источники) == 0


def test_aborted_check_skips_the_rest_of_the_ladder(tmp_path):
    сеть = _ВисящаяСеть(быстрых=3)
    p, поток, результаты, _и, _к = _прогон(сеть, папка=tmp_path)
    лестница = []
    настоящая = p._settle

    def считать(email, *a, **k):
        лестница.append(email)
        return настоящая(email, *a, **k)
    p._settle = считать
    assert _ждать(lambda: len(результаты) >= 3 and сеть.начато >= 6, 60)
    до = len(лестница)
    p.stop(abort=True)
    поток.join(15)
    assert not поток.is_alive()
    assert len(лестница) == до, лестница[до:]


def test_aborted_ping_ends_check_email_before_dns():
    from core.network import NetworkValidator
    сеть = NetworkValidator(timeout=1)
    вызовы = []
    сеть.get_mx_records = lambda domain: ["mx.example.com"]

    def проба(*a, **k):
        сеть.abort_event.set()
        return dict(сеть.ABORTED)
    сеть.stealth_smtp_ping = проба

    def записать(имя):
        return lambda *a, **k: вызовы.append(имя)
    for имя in ("_confirm_acceptance", "mx_hosts_alive", "check_dns_health",
                "postmaster_is_honored"):
        setattr(сеть, имя, записать(имя))
    ответ = сеть.check_email("someone@example.com")
    assert ответ.get("aborted") is True and ответ["status"] == "unknown"
    assert вызовы == []


def test_network_made_in_setup_shares_the_stop_event():
    from core.network import NetworkValidator
    p, _с, _р = _конвейер()
    p.network = NetworkValidator(timeout=1)
    p._share_abort_event()
    assert p.network.abort_event is p._abort_event
    p.stop(abort=True)
    assert p.network.aborted() is True


def test_old_profile_refresher_dies_with_its_own_run():
    p, _с, _р = _конвейер()
    p.is_running = True
    внутри, отпустить = threading.Event(), threading.Event()

    class _Сеть:
        def refresh_proxy_profiles(self, **_kw):
            внутри.set()
            отпустить.wait(5)
            return {"checked": 0}
    p.network = _Сеть()
    p._start_profile_refresher(timeout=1, workers=1, interval=0.02)
    старый, его_стоп = p._refresh_thread, p._refresh_stop
    assert внутри.wait(5), "обновление не началось"
    его_стоп.set()
    p._refresh_stop = threading.Event()
    отпустить.set()
    старый.join(2)
    жив = старый.is_alive()
    p._refresh_stop.set()
    p.is_running = False
    старый.join(2)
    assert not жив, "обновлятель прошлого прогона жил на событии нового"


def test_plain_stop_still_finishes_the_started_checks():

    class _Медленная(_Net):
        def __init__(self):
            self.начато = 0
            self.lock = threading.Lock()

        def check_email(self, email, **_kw):
            with self.lock:
                self.начато += 1
            time.sleep(0.5)
            return super().check_email(email)

    сеть = _Медленная()
    p, поток, результаты, _и, _к = _прогон(сеть, адресов=12, потоков=3)
    assert _ждать(lambda: сеть.начато >= 3, 60)
    p.stop()
    поток.join(30)
    assert not поток.is_alive()
    assert len(результаты) >= 3
    assert len(результаты) == сеть.начато


def test_network_pause_and_queue_wait_end_on_stop():
    from core.network import NetworkValidator
    сеть = NetworkValidator(timeout=1)
    threading.Timer(0.2, сеть.abort_event.set).start()
    начало = time.monotonic()
    assert сеть._pause(10) is True
    assert time.monotonic() - начало < 3
    сеть.abort_event.clear()
    занят = threading.Semaphore(0)
    threading.Timer(0.2, сеть.abort_event.set).start()
    начало = time.monotonic()
    assert сеть._take(занят) is False
    assert time.monotonic() - начало < 3
    сеть.abort_event.clear()
    свободен = threading.Semaphore(1)
    assert сеть._take(свободен) is True


def test_aborted_network_answers_without_touching_proxies():
    from core.network import NetworkValidator
    сеть = NetworkValidator(timeout=1, proxies=["127.0.0.1:1"])
    штрафы = []
    сеть._update_proxy_score = lambda *a, **k: штрафы.append(a)
    сеть.abort_event.set()
    начало = time.monotonic()
    ответ = сеть.check_email("someone@example.com")
    assert ответ.get("aborted") is True and ответ["status"] == "unknown"
    ответ = сеть._do_single_ping("someone@example.com", "mx.example.com", proxy="127.0.0.1:1")
    assert ответ.get("aborted") is True
    assert time.monotonic() - начало < 2
    assert штрафы == []


def test_window_stop_uses_abort():
    import inspect
    from ui.webapp import ValidatorApi
    assert "stop(abort=True)" in inspect.getsource(ValidatorApi.stop)
