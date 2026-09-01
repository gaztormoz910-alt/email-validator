# -*- coding: utf-8 -*-
"""Третий проход по точности: три места, где вердикт брался не у сервера.

**Повтор шёл тем же выходом.** Адрес, отложенный из-за серого списка или
временного отказа, перепроверялся обычным выбором прокси — то есть мог уйти
через тот же выходной IP, который только что не смог. У greylisting запись
ведётся по тройке (IP, отправитель, получатель): тот же IP получает тот же
серый ответ. Отказ по репутации с того же адреса повторяется дословно. В
комментарии у места откладывания при этом было написано «повтор другим прокси
часто даёт однозначный ответ» — обещание, которое код не выполнял.

**Проверка обязательного адреса срывалась молча.** `postmaster_is_honored`
спрашивал один адрес и на таймаут, мёртвый прокси или отказ по репутации
возвращал None — «не выяснили». Вызывающий после этого верил тому самому
`550`, ради проверки которого сюда и пришёл. Обязательных адреса два
(RFC 5321 §4.5.1 и RFC 2142 §4), и второй RCPT в уже открытой сессии стоит
один пакет.

**Длина имени хоронила без сервера.** `check_local_part` возвращал
`impossible` за имя длиннее предела провайдера, и адрес уезжал в Invalid без
единого сетевого запроса. Предел при этом взят с нынешней страницы помощи
провайдера, а не получен от сервера. У Gmail это ошибалось измеримо: точки в
имени Gmail не значат ничего, поэтому доставляемый адрес легко перерастает
тридцать символов, оставаясь именем из четырнадцати.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.pipeline as pipeline_module                      # noqa: E402
from core.local_rules import IMPOSSIBLE, OK, UNLIKELY, check_local_part  # noqa: E402


def validator(proxies=None, profiles=None):
    from core.network import NetworkValidator

    made = NetworkValidator(timeout=2, proxies=proxies or [])
    if profiles:
        made.set_proxy_profiles(profiles)
    # Страна получателя выясняется по зоне и по имени MX — то есть реальным
    # запросом в сеть. К предмету проверок ниже она отношения не имеет, а на
    # выдуманном домене упирается в таймаут: четырнадцать секунд на тест.
    made.country_for_domain = lambda domain, mx_host="": ""
    return made


class FakeNetwork:
    """Сеть, которая первый раз срывается, а второй отвечает.

    Ровно то, ради чего очередь перепроверки и существует: первый ответ —
    не вердикт о ящике, а сбой нашей стороны.
    """

    def __init__(self, first, second=None):
        self.first = first
        self.second = second or {"status": "valid", "reason": "250 OK",
                                 "mx_record": "mx.test"}
        self.calls = []

    def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
        # Записываем НАМЕРЕНИЕ, а не только имя прокси: для серого списка и
        # для сбоя оно противоположно, и тест обязан их различать.
        if prefer_exit_of:
            self.calls.append((email, ("prefer", prefer_exit_of)))
        else:
            self.calls.append((email, avoid_exit_of))
        return dict(self.first) if len(self.calls) == 1 else dict(self.second)

    def get_live_proxy_count(self):
        return 2

    def has_proxies_configured(self):
        return True

    def all_proxies_dead(self):
        return False

    def get_mx_records(self, domain):
        return ["mx.test"]


def run_one(first, second=None, monkeypatch=None):
    """Прогоняет один адрес через настоящий пайплайн с подменённой сетью."""
    net = FakeNetwork(first, second)
    results = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: results.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = net
    pipe.cache = None
    # Обогащение и модели к вопросу не относятся, а грузятся долго.
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None

    # Выдержка перепроверки — в ноль: проверяем МАРШРУТ повтора, а не часы.
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)
    monkeypatch.setattr(pipeline_module, "GREYLIST_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=2, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)
    return net, results


# ══════════════════════════ G1: повтор идёт другим выходом

def test_retry_avoids_the_exit_that_just_failed(monkeypatch):
    """Отложенный адрес перепроверяется НЕ тем прокси, что сорвался."""
    net, results = run_one({"status": "unknown", "reason": "Timeout",
                            "mx_record": "mx.test", "proxy": "socks5://a:1"},
                           monkeypatch=monkeypatch)
    assert len(net.calls) == 2, "повтора не было вовсе: %s" % (net.calls,)
    assert net.calls[0][1] is None, "первый заход не должен ничего избегать"
    assert net.calls[1][1] == "socks5://a:1", (
        "повтор не знает, какой выход только что не смог: %s" % (net.calls,))
    assert results and results[0][1] == "Valid", (
        "вердикт повтора не дошёл до выдачи: %s" % (results,))


def test_retry_after_greylisting_keeps_the_same_exit(monkeypatch):
    """Серый список ведётся по тройке (наш IP, наш отправитель, получатель).

    Здесь требование ОБРАТНОЕ соседнему: сервер намеренно ответил «позже» и
    ждёт, что вернётся ТА ЖЕ тройка. Прийти с другого выхода — значит завести
    новую запись в серый список и начать выдержку заново, сколько ни повторяй.
    Разница между «сбой у нас» и «сервер попросил подождать» здесь решает всё:
    первому нужен другой адрес, второму — тот же самый.
    """
    net, _ = run_one({"status": "greylisted", "reason": "451 greylisted",
                      "mx_record": "mx.test", "proxy": "socks5://b:2"},
                     monkeypatch=monkeypatch)
    assert len(net.calls) == 2
    # Повтор пришёл С ТЕМ ЖЕ выходом, а не «в обход» него.
    assert net.calls[1][1] == ("prefer", "socks5://b:2"), net.calls


def test_retry_without_a_known_proxy_asks_as_before(monkeypatch):
    """Контроль: если прокси не был известен, повтор идёт обычным порядком.

    Иначе проверка выше зеленела бы и в том случае, когда в поле «избегать»
    что-нибудь подставляется всегда.
    """
    net, _ = run_one({"status": "unknown", "reason": "Timeout",
                      "mx_record": "mx.test"},          # прокси в ответе нет
                     monkeypatch=monkeypatch)
    assert len(net.calls) == 2
    assert net.calls[1][1] is None


# ══════════════════════════ G2: чей это был ответ — видно

def test_ping_reports_which_proxy_answered():
    """Без этого поля повтору неоткуда узнать, какой выход не смог."""
    v = validator(proxies=["a:1"], profiles={"a:1": {"exit_ip": "1.1.1.1"}})
    v._do_single_ping = lambda *a, **k: {"status": "unknown", "reason": "Timeout"}
    result = v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"])
    assert result.get("proxy") == "a:1", result


def test_ping_without_proxies_reports_no_proxy():
    """Контроль: когда прокси не задан, поля быть не должно.

    Иначе повтор стал бы избегать выдуманной строки и мог остаться без
    выбора вовсе.
    """
    v = validator()
    v._do_single_ping = lambda *a, **k: {"status": "unknown", "reason": "Timeout"}
    result = v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"])
    assert "proxy" not in result


# ══════════════════════════ G3: единственный выход — не повод не проверять

def test_single_exit_still_gets_checked():
    """В пуле один выходной адрес, и его же просят избегать.

    Ответить «прокси кончились» здесь значило бы соврать: они живы. Живой
    адрес остался бы непроверенным из-за нашей же осторожности.
    """
    v = validator(proxies=["a:1"], profiles={"a:1": {"exit_ip": "1.1.1.1"}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    result = v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"],
                                 avoid_exit_of="a:1")
    assert seen == ["a:1"], "проверка не состоялась вовсе: %s" % (seen,)
    assert result["status"] == "valid"
    assert "Proxies Dead" not in result.get("reason", "")


def test_two_exits_do_honour_the_ban():
    """Контроль: когда выбор есть, запрет соблюдается."""
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"], avoid_exit_of="a:1")
    assert seen == ["b:2"], seen


# ══════════════════════════ G4/G5: второй обязательный адрес

def probe_recorder(v, answers):
    """Подменяет сессию проверки получателей и записывает, о чём спросили."""
    calls = []

    def fake_probe(addresses, mx_record, proxy=None, from_email=None):
        calls.append(list(addresses))
        return [dict(a) for a in answers][:len(addresses)]

    v._probe_recipients = fake_probe
    return calls


def test_abuse_answers_when_postmaster_probe_fails():
    """Сорвавшаяся проба postmaster@ больше не оставляет домен без ответа."""
    v = validator()
    calls = probe_recorder(v, [{"status": "unknown", "reason": "Timeout"},
                               {"status": "invalid", "reason": "550 no such user"}])
    assert v.postmaster_is_honored("wall.test", "mx.wall.test") is False
    assert calls == [["postmaster@wall.test", "abuse@wall.test"]], calls


def test_abuse_can_also_clear_the_server():
    """И наоборот: принятый abuse@ возвращает серверу право на приговор."""
    v = validator()
    probe_recorder(v, [{"status": "unknown", "reason": "Proxy Dead"},
                       {"status": "valid", "reason": "250 OK"}])
    assert v.postmaster_is_honored("ok.test", "mx.ok.test") is True


def test_postmaster_still_decides_first():
    """Контроль: когда postmaster ответил, второй адрес ничего не меняет.

    Обязательность abuse@ слабее: он нужен как запасной источник, а не как
    голос против уже полученного ответа.
    """
    v = validator()
    probe_recorder(v, [{"status": "invalid", "reason": "550"},
                       {"status": "valid", "reason": "250 OK"}])
    assert v.postmaster_is_honored("first.test", "mx.first.test") is False

    other = validator()
    probe_recorder(other, [{"status": "valid", "reason": "250 OK"},
                           {"status": "invalid", "reason": "550"}])
    assert other.postmaster_is_honored("second.test", "mx.second.test") is True


def test_both_mandatory_addresses_cost_one_session():
    """Экономия: два RCPT в одной сессии, а не две сессии на домен."""
    v = validator()
    calls = probe_recorder(v, [{"status": "unknown"}, {"status": "unknown"}])
    assert v.postmaster_is_honored("quiet.test", "mx.quiet.test") is None
    assert len(calls) == 1, "домен опрошен дважды: %s" % (calls,)


def test_failed_probe_is_not_remembered():
    """Сорвавшаяся проба не кэшируется — иначе один сбой лишал бы домен проверки."""
    v = validator()
    probe_recorder(v, [{"status": "unknown"}, {"status": "unknown"}])
    assert v.postmaster_is_honored("later.test", "mx.later.test") is None
    probe_recorder(v, [{"status": "valid"}, {"status": "valid"}])
    assert v.postmaster_is_honored("later.test", "mx.later.test") is True


# ══════════════════════════ G6/G7: без сервера хороним только факты

@pytest.mark.parametrize("email,why", [
    ("a" * 35 + "@gmail.com", "предел Gmail взят со страницы помощи, не с сервера"),
    ("a" * 40 + "@aol.com", "то же самое у AOL"),
    ("a" * 25 + "@icloud.com", "и у iCloud"),
    (".".join("johndoesmithjunior") + "@gmail.com",
     "точки Gmail не значат ничего: это имя из восемнадцати знаков"),
])
def test_length_no_longer_buries_without_a_server(email, why):
    assert check_local_part(email)[0] != IMPOSSIBLE, why


def test_empty_name_is_the_only_thing_impossible():
    """Единственный приговор без сети — адресовать нечего."""
    assert check_local_part("@gmail.com")[0] == IMPOSSIBLE
    assert check_local_part("x" * 31 + "@gmail.com")[0] == UNLIKELY
    assert check_local_part("john.smith@gmail.com")[0] == OK


def test_long_gmail_name_reaches_the_server_and_survives_silence():
    """Длинное имя идёт в сеть, и молчание сервера его не хоронит.

    Раньше сюда дело не доходило вовсе: вердикт выносился до DNS.
    """
    v = validator()
    v.get_mx_records = lambda domain: ["mx.gmail.test"]
    v.is_catch_all_domain = lambda domain, mx: False
    v.check_dns_health = lambda domain: {"score": 0, "has_spf": False,
                                         "has_dmarc": False, "has_dkim": False}
    asked = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        asked.append(email)
        return {"status": "unknown", "reason": "Timeout"}

    v._do_single_ping = fake_ping
    result = v.check_email("a" * 35 + "@gmail.com")
    assert asked, "адрес по-прежнему хоронится без единого запроса"
    assert result["status"] != "invalid", result
    assert "длиннее" in result["reason"], (
        "подозрение потерялось — оно должно понижать доверие: %s" % result)


def test_the_server_still_decides_the_long_name():
    """А ответивший сервер решает всё: 250 значит живой ящик из старых."""
    v = validator()
    v.get_mx_records = lambda domain: ["mx.gmail.test"]
    v.is_catch_all_domain = lambda domain, mx: False
    v._do_single_ping = lambda *a, **k: {"status": "valid", "reason": "250 OK"}
    result = v.check_email("a" * 35 + "@gmail.com")
    assert result["status"] == "valid", result


def test_facts_without_a_server_are_still_invalid():
    """Контроль: то, что доказывается БЕЗ сервера, хоронится как прежде."""
    v = validator()
    v.get_mx_records = lambda domain: []
    assert v.check_email("user@no-mx.test")["status"] == "invalid"
    assert v.check_email("a b@gmail.com")["status"] == "invalid"


# ══════════════════════════ G9: отказ по репутации — самый восстановимый

REPUTATION = ("5.7.1 550 Отказ по политике/репутации IP "
              "(ящик может существовать)")


def test_reputation_refusal_is_retried(monkeypatch):
    """Сервер отказал НАМ, а не ящику — такой ответ обязан быть перепроверен.

    Формулировки классификатора русские, а список причин для повтора был
    английским: самые восстановимые отказы не повторялись никогда.
    """
    net, results = run_one({"status": "unknown", "reason": REPUTATION,
                            "mx_record": "mx.test", "proxy": "socks5://dirty:1"},
                           monkeypatch=monkeypatch)
    assert len(net.calls) == 2, "отказ по репутации остался без повтора"
    assert net.calls[1][1] == "socks5://dirty:1"
    assert results[0][1] == "Valid"


def test_reputation_refusal_upgraded_to_risky_is_retried_too(monkeypatch):
    """У домена с SPF/DMARC тот же отказ приезжает уже как risky.

    Повышение делает шаг «DNS-здоровье», и говорит оно про ДОМЕН. Про ящик
    по-прежнему не сказано ничего — значит и повтор нужен тот же.
    """
    net, _ = run_one({"status": "risky",
                      "reason": REPUTATION + " [DNS: SPF=✓, DMARC=✓, DKIM=✗]",
                      "mx_record": "mx.test", "proxy": "socks5://dirty:1"},
                     monkeypatch=monkeypatch)
    assert len(net.calls) == 2, "risky по нашей же вине остался без повтора"


def test_a_real_verdict_is_never_retried(monkeypatch):
    """Контроль: ответ сервера про ящик повторять нечего.

    Иначе «повторяем восстановимое» превратилось бы в «повторяем всё», и
    прогон удвоился бы впустую.
    """
    net, results = run_one({"status": "invalid", "reason": "550 5.1.1 нет ящика",
                            "mx_record": "mx.test", "proxy": "socks5://a:1"},
                           monkeypatch=monkeypatch)
    assert len(net.calls) == 1, "вердикт сервера ушёл на повтор: %s" % (net.calls,)
    assert results[0][1] == "Invalid/Bounce"


def test_retry_prefers_a_clean_exit():
    """Повтор берёт по возможности ЧИСТЫЙ выход, а не просто другой.

    Самая частая причина попасть на повтор — репутация. Менять грязный адрес
    на такой же грязный значит получить тот же ответ вторым заходом.
    """
    v = validator(proxies=["dirty:1", "dirty:2", "clean:3"],
                  profiles={"dirty:1": {"exit_ip": "1.1.1.1", "in_dnsbl": True},
                            "dirty:2": {"exit_ip": "2.2.2.2", "in_dnsbl": True},
                            "clean:3": {"exit_ip": "3.3.3.3", "in_dnsbl": False}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"],
                        avoid_exit_of="dirty:1")
    assert seen == ["clean:3"], seen


def test_clean_preference_is_soft_not_a_refusal():
    """Контроль: чистых не осталось — идём грязным, а не отказываемся.

    Требование «только чистый» превратило бы отсутствие чистого прокси в
    непроверенный адрес, то есть лечило бы одну потерю другой.
    """
    v = validator(proxies=["dirty:1", "dirty:2"],
                  profiles={"dirty:1": {"exit_ip": "1.1.1.1", "in_dnsbl": True},
                            "dirty:2": {"exit_ip": "2.2.2.2", "in_dnsbl": True}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    result = v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"],
                                 avoid_exit_of="dirty:1")
    assert seen == ["dirty:2"], seen
    assert result["status"] == "valid"


# ══════════════════════════ G10: старый приговор не переживает отмену правила

def test_cache_forgets_verdicts_the_rule_no_longer_makes(tmp_path):
    """Кэш держит Invalid девяносто дней — и отдавал бы отменённый приговор.

    Замерено на базе владельца: `entertainmentkatikatientertainment@gmail.com`
    лежал там как Invalid/Bounce с причиной «имя длиннее 30 символов» и mx
    «N/A» — то есть похоронен без единого запроса к серверу. Без чистки
    исправление до него бы просто не дошло.
    """
    import sqlite3

    from core.cache import ResultCache

    path = str(tmp_path / "cache.sqlite")
    cache = ResultCache(path=path)
    assert cache.enabled
    cache.put("long@gmail.com", "Invalid/Bounce",
              "Имя не может существовать — Gmail: имя длиннее 30 символов.", "N/A")
    cache.put("dead@nowhere.test", "Invalid/Bounce",
              "No MX/A records (Dead Domain)", "N/A")
    cache.put("live@gmail.com", "Valid", "250 OK", "mx.gmail.test")
    cache.close()

    reopened = ResultCache(path=path)
    try:
        assert reopened.get("long@gmail.com") is None, (
            "отменённый приговор всё ещё выдаётся из кэша")
        # А факты остаются: мёртвый домен доказывается без сервера и сегодня.
        assert reopened.get("dead@nowhere.test") is not None
        assert reopened.get("live@gmail.com") is not None
    finally:
        reopened.close()

    with sqlite3.connect(path) as con:
        left = con.execute("SELECT COUNT(*) FROM results").fetchone()[0]
    assert left == 2, left


# ══════════════════════════ G11: страховка называет НАСТОЯЩУЮ причину

def test_leftover_keeps_the_real_reason(monkeypatch):
    """Нажали «Стоп» — адрес отдаётся с той причиной, по которой отложен.

    Раньше страховка писала всем подряд «Greylisted (перепроверка не
    выполнена)», а в очередь попадают ещё таймауты, мёртвые прокси и отказы
    по репутации нашего IP. Владелец читает эту строку, чтобы понять, что
    чинить: серый список ждут, а грязный прокси меняют.
    """
    results = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: results.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })

    class StopsAfterFirst(FakeNetwork):
        def check_email(self, email, avoid_exit_of=None):
            answer = FakeNetwork.check_email(self, email, avoid_exit_of)
            pipe.is_running = False          # как будто нажали «Стоп»
            return answer

    pipe.network = StopsAfterFirst({"status": "unknown", "reason": REPUTATION,
                                    "mx_record": "mx.test",
                                    "proxy": "socks5://dirty:1"})
    pipe.cache = None
    pipe.name_extractor = object()
    pipe.ml_predictor = object()
    pipe._enrich_and_score = lambda *a, **kw: None
    monkeypatch.setattr(pipeline_module, "DEFAULT_RETRY_DELAY", 0.0)

    pipe.run_pipeline([{"type": "text", "content": "user@example-corp.test"}],
                      threads=1, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)

    assert results, "адрес пропал вовсе"
    email, status, reason = results[0][0], results[0][1], results[0][2]
    assert email == "user@example-corp.test"
    assert status == "Unknown"
    assert "репутации" in reason, reason
    assert "перепроверка не выполнена" in reason.lower(), reason
    assert "greylisted" not in reason.lower(), reason


# ══════════════════════════ G12: тройка серого списка не разваливается

def test_sender_is_stable_for_a_domain():
    """Отправитель для домена один и тот же — иначе тройка не совпадёт.

    Раньше здесь стоял random.choice на КАЖДУЮ попытку. Серый список ведётся
    по тройке (наш IP, наш отправитель, получатель): со случайным
    отправителем сервер видел при повторе новую тройку и отвечал «позже»
    снова, сколько бы мы ни ждали. Выдержка не работала вовсе.
    """
    from core.mail_constants import MAIL_FROM_POOL, mail_from_for

    for domain in ("gmail.com", "corp.example", "почта.рф", "web.de"):
        first = mail_from_for(domain)
        assert first in MAIL_FROM_POOL
        assert all(mail_from_for(domain) == first for _ in range(5)), domain


def test_sender_still_rotates_across_domains():
    """Контроль: стабильность не превратилась в один адрес на всю базу.

    Ротация нужна затем, чтобы один почтовик не видел всю проверку за одним
    отправителем. Стабильность — внутри домена, разброс — между доменами.
    """
    from core.mail_constants import MAIL_FROM_POOL, mail_from_for

    domains = ["d%02d.example" % n for n in range(60)]
    used = {mail_from_for(d) for d in domains}
    assert len(used) == len(MAIL_FROM_POOL), used


def test_sender_survives_junk_input():
    """Мусор на входе не роняет проверку: зовут из рабочих потоков."""
    from core.mail_constants import MAIL_FROM_POOL, mail_from_for

    for junk in (None, "", 42, [], {}, "@", "\x00"):
        assert mail_from_for(junk) in MAIL_FROM_POOL


def test_ping_honours_the_requested_exit():
    """prefer_exit_of берётся как есть — это и есть возврат той же тройкой."""
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"], prefer_exit_of="a:1")
    assert seen == ["a:1"], seen


def test_requested_exit_that_died_falls_back():
    """Контроль: выбывший прокси не превращает повтор в отказ от проверки."""
    v = validator(proxies=["a:1", "b:2"],
                  profiles={"a:1": {"exit_ip": "1.1.1.1"},
                            "b:2": {"exit_ip": "2.2.2.2"}})
    v._proxy_banned.add("a:1")          # выбыл по ходу прогона
    seen = []

    def fake_ping(email, mx, proxy=None, **kwargs):
        seen.append(proxy)
        return {"status": "valid", "reason": "250 OK"}

    v._do_single_ping = fake_ping
    v.stealth_smtp_ping("user@corp.test", ["mx.corp.test"], prefer_exit_of="a:1")
    assert seen == ["b:2"], seen
