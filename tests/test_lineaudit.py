# -*- coding: utf-8 -*-
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import core.pipeline as pipeline_module
from core.cleaner import EmailCleaner, normalize_for_dedup
from core.disposable import (DISPOSABLE_DOMAINS,
                             extend_disposable_domains, is_disposable)
from core.heuristics import is_parked_domain
from core.network import (NetworkValidator,
                          _generate_random_local,
                          control_probe_address)
from core.runstate import RunState
from ui.result_store import group_of


class _СетьСЛовушкой:

    def __init__(self):
        self.calls = 0

    def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
        self.calls += 1
        return {"status": "trap", "reason": "AV Vendor (Dangerous)",
                "mx_record": "mx.emailsecurity.trendmicro.com"}

    def get_live_proxy_count(self):
        return 2

    def has_proxies_configured(self):
        return True

    def all_proxies_dead(self):
        return False

    def get_mx_records(self, domain):
        return ["mx.emailsecurity.trendmicro.com"]


class _ЗаписнойКэш:

    def __init__(self):
        self.puts = []

    def get(self, email):
        return None

    def put(self, email, status, reason, mx, data=None):
        self.puts.append((email, status))
        return True

    def close(self):
        pass


def _прогнать(сеть, кэш=None):
    итоги = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: итоги.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = сеть
    pipe.cache = кэш
    pipe.run_pipeline(
        [{"type": "text", "content": "ivan@corp-behind-gateway.test"}],
        threads=2, fix_typos=False, check_spam=False,
        deep_ping=True, enable_ai=False, enable_osint=False)
    return итоги


def test_d01_ловушка_вендора_не_показывается_как_отскок():
    итоги = _прогнать(_СетьСЛовушкой())
    assert итоги, "адрес пропал из выдачи целиком"
    статус = итоги[0][1]
    assert статус != "Invalid/Bounce", (
        "MX ведёт на honeypot вендора, сервера не спрашивали — а вердикт "
        "«Invalid/Bounce», то есть «ящика нет». Получено: %r" % (статус,))
    assert group_of(статус) != "invalid", (
        "статус %r попадает в группу «слать нельзя никогда», хотя "
        "доказательства отсутствия ящика нет" % (статус,))


def test_d01_ловушка_вендора_не_уезжает_в_кэш_как_отскок():
    кэш = _ЗаписнойКэш()
    _прогнать(_СетьСЛовушкой(), кэш)
    отскоки = [п for п in кэш.puts if п[1] == "Invalid/Bounce"]
    assert not отскоки, (
        "в кэш положен отскок, которого сервер не подтверждал: %s" % (отскоки,))


@pytest.mark.parametrize("адрес", [
    "ramiza@live.comb",
    "m.savic8@hotmail.cam",
    "thanda@yahoo.conm",
    "chovan@ymail.colm",
    "e@none.comf",
    "a@happydaysfreedom.como",
    "j@hotmail.ccom",
    "jane.roe@agriculture.arkansas",
    "h@naftalina.concept",
    "x@openid.user",
    "k@mars.all.around",
    "ivan@mail.home.company.co.uk",
    "a@mail.web.demo.corp.ru",
])
def test_d02_очистка_не_подменяет_домен(адрес):
    было = адрес.rsplit("@", 1)[1].lower()
    стало = (EmailCleaner().clean_email(адрес) or "").rsplit("@", 1)[-1]
    assert стало == было, (
        "домен подменён: загрузили %r, проверять будем %r — "
        "это вердикт о чужом ящике" % (было, стало))


def test_d02_обрезанная_метка_больше_не_подменяет_домен():
    очистка = EmailCleaner()
    спрошено = []

    def домен_принимает_почту(домен):
        спрошено.append(домен)
        return False

    очистка.установить_проверку_домена(домен_принимает_почту)
    стало = (очистка.clean_email("207144@honda.carpoi") or "").rsplit("@", 1)[-1]
    assert стало == "honda.carpoi", (
        "домен подменён на %r — это вердикт о чужом ящике" % (стало,))
    assert спрошено == ["honda.car"], (
        "очистка обязана спросить именно про то, во что собралась резать; "
        "спрошено: %r" % (спрошено,))


def test_d02_настоящая_склейка_чинится_когда_домен_отвечает():
    очистка = EmailCleaner()
    очистка.установить_проверку_домена(lambda домен: домен == "mail.ru")
    стало = (очистка.clean_email("y@mail.ruxxx") or "").rsplit("@", 1)[-1]
    assert стало == "mail.ru", "настоящая склейка не починена: %r" % (стало,)


def test_d02_молчание_dns_не_даёт_подменить_домен():
    очистка = EmailCleaner()
    очистка.установить_проверку_домена(lambda домен: None)
    стало = (очистка.clean_email("207144@honda.carpoi") or "").rsplit("@", 1)[-1]
    assert стало == "honda.carpoi", "подмена при молчащем DNS: %r" % (стало,)


@pytest.mark.parametrize("адрес,ждём", [
    ("x@gmail.comtelefoon", "gmail.com"),
    ("y@lee.neteditorryan", "lee.net"),
    ("z@theprairiestar.comlivestock", "theprairiestar.com"),
    ("w@woh.rr.comjwm", "woh.rr.com"),
    ("v@mobiustrio.orgfor", "mobiustrio.org"),
    ("u@gmail.comi", "gmail.com"),
])
def test_d02_настоящие_склейки_по_прежнему_чинятся(адрес, ждём):
    стало = (EmailCleaner().clean_email(адрес) or "").rsplit("@", 1)[-1]
    assert стало == ждём, "склейка не починена: %r -> %r" % (адрес, стало)


def _движок_с_ответом(ответ):
    v = NetworkValidator(timeout=1, proxies=[])
    v._probe_recipients = lambda addresses, mx, proxy=None, from_email=None: [
        dict(ответ) for _ in addresses]
    v._probe_proxy_for = lambda domain: "socks5://proxy:1"
    v.memory = None
    return v


def test_d03_серый_список_не_доказывает_что_домен_не_catchall():
    v = _движок_с_ответом({"status": "greylisted",
                           "reason": "450 Greylisted (Retry Later)"})
    вывод = v.is_catch_all_domain("corp.test", "mx.corp.test")
    assert вывод is False, "без ответа вывод один: считаем домен не catch-all"
    assert "corp.test" not in v.catchall_cache, (
        "ответ «приходите позже» записан в память как доказанное "
        "«домен не catch-all» — следующий 250 станет ложным Valid")


def test_d03_отказ_выдуманному_адресу_по_прежнему_доказывает():
    v = _движок_с_ответом({"status": "invalid",
                           "reason": "550 Получателя не существует"})
    assert v.is_catch_all_domain("corp.test", "mx.corp.test") is False
    assert v.catchall_cache.get("corp.test") is False, (
        "доказанный ответ обязан запоминаться")


def test_d04_корпоративный_google_не_схлопывается_с_gmail():
    assert (normalize_for_dedup("sundar@google.com")
            != normalize_for_dedup("sundar@gmail.com")), (
        "ключ дедупа совпал: один из двух адресов молча выпадет из прогона")


def test_d04_настоящие_синонимы_gmail_по_прежнему_схлопываются():
    один = normalize_for_dedup("john.doe@gmail.com")
    assert normalize_for_dedup("johndoe@googlemail.com") == один
    assert normalize_for_dedup("john.doe+news@gmail.com") == один


def test_d05_публичный_суффикс_в_списке_не_хоронит_всю_зону():
    было = set(DISPOSABLE_DOMAINS)
    try:
        extend_disposable_domains({"msk.ru", "info.pl", "co.uk", "edu.pl"})
        assert not is_disposable("a@echo.msk.ru"), (
            "весь домен объявлен одноразовым из-за зоны msk.ru "
            "в скачанном списке")
        assert not is_disposable("b@firma.info.pl"), (
            "зона info.pl — ровно тот случай, который прежний признак "
            "пропускал: первое слово длинное")
        assert not is_disposable("c@shop.co.uk")
    finally:
        DISPOSABLE_DOMAINS.clear()
        DISPOSABLE_DOMAINS.update(было)


def test_d05_поддомен_настоящего_сервиса_по_прежнему_ловится():
    было = set(DISPOSABLE_DOMAINS)
    try:
        extend_disposable_domains({"gaggle.net", "33mail.com",
                                   "mail-tester.com"})
        assert is_disposable("a@asd5.gaggle.net")
        assert is_disposable("b@srv1.mail-tester.com")
        assert not is_disposable("c@bearcat.33mail.com")
    finally:
        DISPOSABLE_DOMAINS.clear()
        DISPOSABLE_DOMAINS.update(было)


def test_d06_возобновление_не_считает_дублем_адрес_без_вердикта(tmp_path):
    путь = str(tmp_path / "state.sqlite")

    первый = RunState("run-1", path=путь, resume=False)
    assert первый.add_if_new("a@x.com") is True
    assert первый.add_if_new("b@x.com") is True
    первый.mark_done("b@x.com")
    первый.flush()
    первый.close()

    второй = RunState("run-1", path=путь, resume=True)
    try:
        assert второй.is_done("b@x.com") is True, "журнал сделанного потерян"
        второй.reset_seen()
        assert второй.add_if_new("a@x.com") is True, (
            "адрес без вердикта пропущен как ДУБЛЬ: проверен он не будет "
            "никогда, и в выдаче его не окажется")
        assert второй.is_done("a@x.com") is False, (
            "журнал сделанного не должен пополняться сбросом дедупа")
    finally:
        второй.close()


class _СетьВсегдаГоден:
    def check_email(self, email, avoid_exit_of=None, prefer_exit_of=None):
        return {"status": "valid", "reason": "250 OK", "mx_record": "mx.test"}

    def get_live_proxy_count(self):
        return 2

    def has_proxies_configured(self):
        return True

    def all_proxies_dead(self):
        return False

    def get_mx_records(self, domain):
        return ["mx.test"]


def test_d06_продолженный_прогон_доводит_непроверенный_адрес_до_выдачи(
        tmp_path, monkeypatch):
    путь_состояния = str(tmp_path / "runstate.sqlite")
    файл = tmp_path / "база.txt"
    файл.write_text("a@x.test\nb@x.test\n", encoding="utf-8")
    источники = [{"type": "file", "path": str(файл)}]

    настоящий = pipeline_module.RunState
    monkeypatch.setattr(
        pipeline_module, "RunState",
        lambda run_id, resume=True: настоящий(run_id, path=путь_состояния,
                                              resume=resume))

    run_id = pipeline_module.run_id_for(источники)
    было = настоящий(run_id, path=путь_состояния, resume=False)
    было.add_if_new("a@x.test")
    было.add_if_new("b@x.test")
    было.mark_done("b@x.test")
    было.flush()
    было.close()

    итоги = []
    pipe = pipeline_module.ValidationPipeline(callbacks={
        "on_log": lambda *a, **kw: None,
        "on_result": lambda *a: итоги.append(a),
        "on_progress": lambda *a: None,
        "on_complete": lambda: None,
    })
    pipe.network = _СетьВсегдаГоден()
    pipe.cache = None
    pipe.run_pipeline(источники, threads=2, fix_typos=False, check_spam=False,
                      deep_ping=True, enable_ai=False, enable_osint=False)

    показаны = {строка[0] for строка in итоги}
    assert "a@x.test" in показаны, (
        "адрес без вердикта не проверен и при продолжении — он выброшен "
        "из работы навсегда. Показаны: %s" % (sorted(показаны),))
    assert "b@x.test" not in показаны, (
        "адрес с готовым вердиктом проверен заново — журнал не работает")


def test_d06_дедуп_внутри_одного_прогона_работает(tmp_path):
    путь = str(tmp_path / "state2.sqlite")
    s = RunState("run-2", path=путь, resume=False)
    try:
        assert s.add_if_new("dup@x.com") is True
        assert s.add_if_new("dup@x.com") is False
    finally:
        s.close()


@pytest.mark.parametrize("домен", [
    "givaudan.com", "brownjordan.com", "sheridan.com", "psav.com",
    "wsav.com", "nationalescrow.com", "feistyfrugalandfabulous.com",
])
def test_d07_живой_домен_не_считается_припаркованным(домен):
    assert not is_parked_domain(домен), (
        "домен %r помечен припаркованным по совпадению подстроки — "
        "скор занижен у настоящей компании" % (домен,))


@pytest.mark.parametrize("хост", [
    "ns1.sedoparking.com", "mx.bodis.com", "park1.hugedomains.com",
    "dan.com", "mx.dan.com",
])
def test_d07_настоящая_парковка_по_прежнему_ловится(хост):
    assert is_parked_domain(хост)


ГЛАСНЫЕ = set("aeiouy")


def test_d08_контрольная_проба_похожа_на_настоящее_имя():
    адрес = control_probe_address("corp.test")
    имя, _, домен = адрес.rpartition("@")
    assert домен == "corp.test", "проба ушла не на тот домен: %r" % (адрес,)

    буквы = "".join(ч for ч in имя if ч.isalpha())
    assert имя.count(".") == 1, "имя ящика без разделителя: %r" % (имя,)
    assert буквы and буквы.islower(), "в имени не только строчные буквы: %r" % (имя,)
    доля = sum(1 for ч in буквы if ч in ГЛАСНЫЕ) / float(len(буквы))
    assert 0.35 <= доля <= 0.65, (
        "доля гласных %.2f — так выглядит машинная строка, а не имя: %r"
        % (доля, имя,))
    for i in range(len(буквы) - 2):
        assert not (буквы[i] not in ГЛАСНЫЕ and буквы[i + 1] not in ГЛАСНЫЕ
                    and буквы[i + 2] not in ГЛАСНЫЕ), (
            "три согласных подряд — имя так не пишется: %r" % (имя,))
    assert len(адрес.encode("utf-8")) <= 64 + 1 + len(домен), (
        "имя ящика длиннее предела RFC 5321 §4.5.3.1: %r" % (имя,))


def test_d08_контрольная_проба_не_может_совпасть_с_живым_ящиком():
    набор = {control_probe_address("corp.test") for _ in range(3000)}
    assert len(набор) == 3000, (
        "на трёх тысячах проб уже %d совпадений — случайности мало"
        % (3000 - len(набор),))


def test_d08_старые_формы_пробы_остались_доступны():
    короткая = _generate_random_local("short")
    уидовая = _generate_random_local("uuid")
    assert короткая.isalnum() and len(короткая) == 16
    assert уидовая.isalnum() and len(уидовая) == 24


def _похоже_на_имя(локальная):
    буквы = "".join(ч for ч in локальная if ч.isalpha())
    if not буквы or not буквы.islower() or локальная.count(".") != 1:
        return False
    доля = sum(1 for ч in буквы if ч in ГЛАСНЫЕ) / float(len(буквы))
    if not 0.35 <= доля <= 0.65:
        return False
    return not any(буквы[i] not in ГЛАСНЫЕ and буквы[i + 1] not in ГЛАСНЫЕ
                   and буквы[i + 2] not in ГЛАСНЫЕ
                   for i in range(len(буквы) - 2))


def test_d08_прежняя_форма_пробы_договору_не_отвечает():
    провалов = sum(0 if _похоже_на_имя(_generate_random_local("uuid")) else 1
                   for _ in range(50))
    assert провалов == 50, (
        "договор «похоже на имя» пропускает старую форму пробы %d раз из 50 — "
        "значит он ничего не отделяет" % (50 - провалов,))
    провалов = sum(0 if _похоже_на_имя(_generate_random_local("short")) else 1
                   for _ in range(50))
    assert провалов == 50, (
        "договор пропускает короткую форму %d раз из 50" % (50 - провалов,))


def test_н1_компания_берёт_зону_из_списка_mozilla():
    from core.org_role import company_from_domain

    assert company_from_domain("company.msk.ru", "Corporate") == "Company"
    assert company_from_domain("bbc.co.uk", "Corporate") == "Bbc"
    assert company_from_domain("veltrano.com", "Corporate") == "Veltrano"
    assert company_from_domain("mail.company.com", "Corporate") == "Company"
    assert company_from_domain("gmail.com", "Personal") == ""


def test_н2_проверка_аватарки_не_роняет_рабочий_поток():
    from core.gravatar import GravatarChecker

    чекер = GravatarChecker(timeout=1)
    for мусор in (None, 123, [], {}, b"bytes", object()):
        assert чекер.has_gravatar(мусор) is False, мусор


def test_н3_списки_ящиков_с_ptr_не_расходятся():
    from core.mail_constants import AOL_DOMAINS, YAHOO_DOMAINS
    from core.provider import _PROVIDER_DOMAINS, VERIFIABILITY

    for провайдер, маршрут in (("AOL", AOL_DOMAINS), ("Yahoo", YAHOO_DOMAINS)):
        assert VERIFIABILITY.get(провайдер) == "needs_ptr", провайдер
        потеряны = sorted(_PROVIDER_DOMAINS[провайдер] - маршрут)
        assert потеряны == [], (
            "%s: домены известны классификации, но не маршрутизации — их "
            "проверят прокси без PTR и ответа о ящике не получат: %s"
            % (провайдер, потеряны))


def test_н4_адрес_в_настоящей_idn_зоне_опознаётся_адресом():
    from core.input_guard import detect_kind, looks_like_email

    for зона in ("рф", "ελ", "中国", "срб", "ישראל", "укр"):
        assert looks_like_email("ivan@почта.%s" % зона), зона

    assert detect_kind("ивфт@пьфшд.сщь") == "unknown"
    assert not looks_like_email("x@abc.несуществующаязона")


_РАЗМЕР_ДО = {}


def test_н5_а_тест_пачкает_глобальный_список():
    from core.disposable import (DISPOSABLE_DOMAINS, extend_disposable_domains,
                                 is_disposable)

    _РАЗМЕР_ДО["одноразовые"] = len(DISPOSABLE_DOMAINS)
    добавлено = extend_disposable_domains(["проба-негерметичности.example"])
    assert добавлено == 1
    assert is_disposable("x@проба-негерметичности.example")


def test_н5_б_список_вернулся_к_эталону():
    from core.disposable import DISPOSABLE_DOMAINS, is_disposable

    assert not is_disposable("x@проба-негерметичности.example"), (
        "домен из соседнего теста остался в глобальном списке — "
        "набор не герметичен")
    assert len(DISPOSABLE_DOMAINS) == _РАЗМЕР_ДО.get("одноразовые"), (
        "размер списка не вернулся: было %s, стало %d"
        % (_РАЗМЕР_ДО.get("одноразовые"), len(DISPOSABLE_DOMAINS)))
