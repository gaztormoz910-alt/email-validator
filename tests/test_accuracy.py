# -*- coding: utf-8 -*-
"""Восемь доказанных источников ложного вердикта — и защита от их возврата.

Все восемь нашёл аудит каталога проверок. Тогда владелец просил только оценку,
и они остались в коде; воспроизводились до последнего дня
(`.unlazy/shots91/verify.py`, блок G2).

Четыре из них дают ровно тот исход, которого владелец боится больше всего:
Valid на ящике, которого не существует. Он рассылает по колонке «Статус», и
ложный Valid — это письмо в никуда, отскок и удар по репутации отправителя.
Ещё три — обратная ошибка: живые адреса теряются молча.

    Б1  подмена домена       вердикт про ЧУЖОЙ ящик          ложный VALID
    Б3  catch-all не стопит  разоблачение перекрыто повтором ложный VALID
    Б6  код 252 -> valid     «не берусь проверить» = «есть»  ложный VALID
    Б2  кэш не забывает      разоблачённый домен 30 суток    ложный VALID
    Б4  тарпит в память      gmail.com месяц как catch-all   потеря базы
    Б5  предохранитель PTR   ложное «прокси мертвы»          потеря лидов
    Б7  регистр имени ящика  наружу уходит не тот адрес      порча данных
    Б8  administrator@       ролевой ящик не опознан         скоринг

У каждого дефекта здесь есть отрицательный контроль: проверка «баг ушёл»
ничего не стоит, если вместе с багом ушла и польза. Поэтому рядом с каждым
«теперь не чинит» стоит «а вот это по-прежнему чинит».
"""
import io
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cache import ResultCache                                # noqa: E402
from core.cleaner import EmailCleaner, strip_wrapping_junk        # noqa: E402
from core.email_syntax import _lower_domain_only                  # noqa: E402
from core.heuristics import is_role_based                         # noqa: E402
from core.network import NetworkValidator                         # noqa: E402
from core.smtp_codes import classify_smtp_response                # noqa: E402
from core.streamer import StreamLoader                            # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _validator(profiles):
    """Валидатор с настоящей логикой, но без выхода в сеть.

    Заглушены ровно три вещи, и ни одна из них к проверяемым дефектам
    отношения не имеет: пауза перед запросом, определение страны получателя
    (оно резолвит MX и ходит за ASN) и здоровье домена по DNS. Разбор ответа,
    выбор прокси и цикл повторов остаются настоящими — иначе тест мерил бы
    собственную заглушку.
    """
    nv = NetworkValidator(proxies=list(profiles))
    nv.set_proxy_profiles(profiles)
    nv._mx_delay = lambda mx: 0.0
    nv.country_for_domain = lambda domain, mx_host="": ""
    nv.check_dns_health = lambda d, mx_record="": {
        "score": 0, "has_spf": False, "has_dmarc": False, "has_dkim": False}
    return nv


def _tmp_cache():
    return ResultCache(path=os.path.join(tempfile.mkdtemp(), "acc.sqlite"))


# ══════════════════════════ Б1: очистка не подменяет домен ══════════════

# Домены законные. Каждый из них раньше подменялся, и вердикт выносился про
# другой ящик — «Годен» про чужого человека либо «нет такого» про настоящий
# адрес, который никто не спрашивал.
B1_ЗАКОННЫЕ = [
    "user@sky.company.co.uk",     # начинается с sky.com
    "b@aol.company.com",          # начинается с aol.com
    "a@web.de.hosting.net",       # начинается с web.de
    "d@list.ru-company.com",      # хвост после .ru
]

# Строк такого вида как домена не бывает — это артефакт копирования, и
# восстанавливать их надо по-прежнему.
B1_СКЛЕЙКИ = {
    "user@gmail.comtelefoon": "user@gmail.com",
    "y@mail.ruxxx": "y@mail.ru",
    "z@corp.com-jobs": "z@corp.com",
    "w@yandex.rublahblah": "w@yandex.ru",
    "q@gmail.com.br.spam.xyz": "q@gmail.com",
}


def test_b1_legit_domains_are_never_rewritten():
    """Законный домен доходит до проверки нетронутым."""
    cleaner = EmailCleaner()
    подменено = []
    for адрес in B1_ЗАКОННЫЕ:
        вышло = cleaner.correct_and_normalize(адрес)
        if вышло != адрес:
            подменено.append("%s -> %s" % (адрес, вышло))
    assert not подменено, "домен подменён, вердикт будет про чужой ящик: %s" % подменено


def test_b1_control_real_glue_is_still_repaired():
    """Контроль: настоящая склейка мусора по-прежнему чинится.

    Без него «исправление» свелось бы к отключению очистки, и живые адреса
    уехали бы в «мёртвый домен».
    """
    cleaner = EmailCleaner()
    для_отчёта = []
    for адрес, ждём in B1_СКЛЕЙКИ.items():
        вышло = cleaner.correct_and_normalize(адрес)
        if вышло != ждём:
            для_отчёта.append("%s -> %s (ждали %s)" % (адрес, вышло, ждём))
    assert not для_отчёта, "склейка перестала чиниться: %s" % для_отчёта


def test_b1_rule_is_about_the_dot_not_a_list_of_exceptions():
    """Правило ловит КЛАСС ошибки, а не четыре известных примера.

    Признак — точка в остатке: она порождает новую метку домена, то есть
    строка законна. Список исключений устарел бы на первом же новом домене.
    """
    cleaner = EmailCleaner()
    assert cleaner._junk_tail("telefoon") is True
    assert cleaner._junk_tail("-jobs") is True
    assert cleaner._junk_tail("pany.co.uk") is False
    assert cleaner._junk_tail(".hosting.net") is False
    assert cleaner._junk_tail("") is False
    # Домен, которого нет ни в одном списке, но устроен так же.
    assert cleaner.correct_and_normalize("k@bbc.company.co.uk") == "k@bbc.company.co.uk"


# ══════════════════════════ Б2: кэш умеет забыть домен ══════════════════

def test_b2_cache_can_forget_a_domain():
    """Разоблачённый домен стирается из кэша целиком."""
    cache = _tmp_cache()
    try:
        cache.put("a@catchall.test", "Valid", "250 OK", "mx.catchall.test", {})
        cache.put("b@catchall.test", "Valid", "250 OK", "mx.catchall.test", {})
        assert cache.get("a@catchall.test") is not None
        убрано = cache.forget_domain("catchall.test")
        assert убрано == 2, "убрано %s" % убрано
        assert cache.get("a@catchall.test") is None
        assert cache.get("b@catchall.test") is None
    finally:
        cache.close()


def test_b2_control_other_domains_survive():
    """Контроль: чужие домены не задеты.

    Забывчивость, которая стирает лишнее, — это не исправление, а потеря
    работы всего прогона.
    """
    cache = _tmp_cache()
    try:
        cache.put("a@catchall.test", "Valid", "250 OK", "mx1", {})
        cache.put("a@honest.test", "Valid", "250 OK", "mx2", {})
        cache.forget_domain("catchall.test")
        assert cache.get("a@honest.test") is not None, "стёрт посторонний домен"
    finally:
        cache.close()


def test_b2_control_partial_domain_name_does_not_match():
    """Контроль: `catchall.test` не стирает `notcatchall.test`.

    Стирание идёт по SQL LIKE, и без якоря `@` под удаление попал бы любой
    домен, чьё имя оканчивается на то же.
    """
    cache = _tmp_cache()
    try:
        cache.put("a@notcatchall.test", "Valid", "250 OK", "mx", {})
        cache.forget_domain("catchall.test")
        assert cache.get("a@notcatchall.test") is not None
    finally:
        cache.close()


def test_b2_control_like_wildcards_in_the_domain_are_escaped():
    """Контроль: `%` и `_` в домене не превращаются в подстановочные знаки.

    Стирание идёт через SQL LIKE, где `_` означает «любой один символ». Без
    экранирования домен `my_corp.test` стёр бы заодно `myXcorp.test` — то
    есть забывчивость съела бы чужую работу. В именах хостов подчёркивание
    незаконно, но в кэш попадает то, что подали на вход, а не то, что законно.
    """
    cache = _tmp_cache()
    try:
        cache.put("a@myxcorp.test", "Valid", "250 OK", "mx", {})
        cache.put("a@my_corp.test", "Valid", "250 OK", "mx", {})
        убрано = cache.forget_domain("my_corp.test")
        assert убрано == 1, "убрано %s — задет чужой домен" % убрано
        assert cache.get("a@myxcorp.test") is not None
        assert cache.get("a@my_corp.test") is None
    finally:
        cache.close()


def test_b4_the_giant_list_lives_in_one_place():
    """Список гигантов — ОДИН на модуль, а не две копии.

    Две копии одного знания расходятся молча, и Б4 появился именно так:
    ветка проверки набирала список у себя, а долгая память о нём не знала.
    """
    источник = io.open(os.path.join(ROOT, "core", "network.py"),
                       encoding="utf-8").read()
    assert "skip_catchall = self._is_never_catchall(domain)" in источник, (
        "ветка проверки снова набирает список гигантов сама")
    # И mail.ru в него по-прежнему НЕ входит: он настоящий catch-all.
    nv = _validator({})
    for домен in ("mail.ru", "bk.ru", "inbox.ru", "list.ru"):
        assert nv._is_never_catchall(домен) is False, домен


def test_b2_pipeline_forgets_after_unmasking():
    """Конвейер зовёт забывание там же, где пересматривает строки.

    Пересмотр чинит текущий прогон — таблицу и выгрузку. Кэш живёт тридцать
    суток, и без этого вызова ложный «Годен» вернулся бы в следующем запуске.
    """
    источник = io.open(os.path.join(ROOT, "core", "pipeline.py"),
                       encoding="utf-8").read()
    assert "_forget_cached" in источник
    # Зовётся для ОБОИХ разоблачений: catch-all и тарпитинга.
    assert источник.count("self._forget_cached(") >= 2, (
        "забывание подключено не ко всем разоблачениям")


# ══════════════════════════ Б3: catch-all прекращает повторы ════════════

def _catchall_harness():
    """Домен, который принимает и настоящий адрес, и выдуманный."""
    nv = _validator({"socks5://1.2.3.4:1080": {"exit_ip": "1.2.3.4"}})
    nv.get_mx_records = lambda d: ["mx.example.test"]
    попытки = []

    def ping(email, mx, proxy=None, control_probe=False, **kw):
        попытки.append(email)
        if control_probe:
            return {"status": "catchall",
                    "reason": "Catch-All: сервер принял и выдуманный адрес"}
        return {"status": "valid", "reason": "250 OK"}

    nv._do_single_ping = ping
    nv.is_catch_all_domain = lambda d, mx: False
    return nv, попытки


def test_b3_catchall_stops_the_retry_loop():
    """Уличённый домен не переспрашивается: одна попытка, статус сохранён."""
    nv, попытки = _catchall_harness()
    итог = nv.stealth_smtp_ping("someone@example.test", ["mx.example.test"],
                                control_probe=True)
    assert итог["status"] == "catchall", итог
    assert len(попытки) == 1, "повторов после разоблачения: %d" % len(попытки)


def test_b3_control_valid_still_returns_at_once():
    """Контроль: подтверждённый ящик по-прежнему возвращается с первой попытки."""
    nv, попытки = _catchall_harness()
    итог = nv.stealth_smtp_ping("someone@example.test", ["mx.example.test"],
                                control_probe=False)
    assert итог["status"] == "valid", итог
    assert len(попытки) == 1


def test_b3_control_unknown_still_retries():
    """Контроль: временный сбой по-прежнему уходит в повтор.

    Если бы «исправление» останавливало цикл на любом статусе, живые адреса
    получали бы Unknown с первой неудачи прокси.
    """
    nv = _validator({"socks5://1.2.3.4:1080": {"exit_ip": "1.2.3.4"},
                     "socks5://5.6.7.8:1080": {"exit_ip": "5.6.7.8"}})
    nv.get_mx_records = lambda d: ["mx.example.test"]
    попытки = []

    def ping(email, mx, proxy=None, control_probe=False, **kw):
        попытки.append(email)
        return {"status": "unknown", "reason": "Timeout"}

    nv._do_single_ping = ping
    nv.is_catch_all_domain = lambda d, mx: False
    nv.stealth_smtp_ping("someone@example.test", ["mx.example.test"])
    assert len(попытки) > 1, "повторов не было вовсе: %d" % len(попытки)


# ══════════════════════════ Б4: тарпит не оседает в памяти ══════════════

class _Память(object):
    """Долгая память, которая только записывает — чтобы было что проверить."""

    def __init__(self):
        self.записи = []

    def catchall_put(self, domain, is_catchall):
        self.записи.append((domain, is_catchall))

    def catchall_get(self, domain):
        return None


def test_b4_tarpit_is_not_remembered_as_catchall():
    """Гигант, принявший выдуманный адрес, в память как catch-all не идёт.

    Это тарпитинг: почтовик перестал отвечать честно, потому что с нашего
    выхода идёт перебор. Записав его как catch-all на тридцать суток, мы
    отправили бы ВСЮ почту gmail в Unknown в каждом следующем запуске, не
    доходя до сервера.
    """
    nv = _validator({"socks5://9.9.9.9:1080": {"exit_ip": "9.9.9.9"}})
    nv.memory = _Память()
    for домен in ("gmail.com", "yandex.ru", "icloud.com",
                  "yahoo.com", "outlook.com", "aol.com"):
        nv._remember_catchall(домен, True)
    assert nv.memory.записи == [], (
        "тарпитинг записан как catch-all: %s" % nv.memory.записи)


def test_b4_control_ordinary_domain_is_still_remembered():
    """Контроль: обычный домен по-прежнему запоминается.

    Иначе тройная проба переспрашивала бы одно и то же при каждом запуске —
    лишние сессии и лишний повод попасться почтовику на глаза.
    """
    nv = _validator({"socks5://9.9.9.9:1080": {"exit_ip": "9.9.9.9"}})
    nv.memory = _Память()
    nv._remember_catchall("corp-example.test", True)
    assert nv.memory.записи == [("corp-example.test", True)]


def test_b4_control_negative_answer_is_remembered_for_giants_too():
    """Контроль: «НЕ catch-all» у гиганта запоминать можно и нужно.

    Запрет касается только положительного ответа: он у гигантов невозможен.
    Отрицательный — обычный полезный факт.
    """
    nv = _validator({"socks5://9.9.9.9:1080": {"exit_ip": "9.9.9.9"}})
    nv.memory = _Память()
    nv._remember_catchall("gmail.com", False)
    assert nv.memory.записи == [("gmail.com", False)]


def test_b4_call_site_is_guarded_too():
    """Гвардия стоит и в месте вызова, а не только внутри записи.

    Сам вызов означает «мы считаем это catch-all», и смотрит на него не одна
    только память.
    """
    источник = io.open(os.path.join(ROOT, "core", "network.py"),
                       encoding="utf-8").read()
    assert "if not self._is_never_catchall(domain):" in источник
    nv = _validator({})
    assert nv._is_never_catchall("gmail.com") is True
    assert nv._is_never_catchall("yahoo.com") is True
    assert nv._is_never_catchall("corp-example.test") is False


# ══════════════════════════ Б5: предохранитель PTR ══════════════════════

def test_b5_guard_fires_when_profiling_found_no_ptr():
    """Профилирование прошло, PTR нет ни у кого — честный отказ без попыток.

    Условие смотрит на ФАКТ профилирования. Пока оно смотрело на непустоту
    списка PTR-прокси, случай «PTR нет ни у кого» выключал сам предохранитель:
    множество пусто, значит условие ложно.
    """
    nv = _validator({"socks5://1.2.3.4:1080": {"exit_ip": "1.2.3.4",
                                               "has_ptr": False}})
    nv.get_mx_records = lambda d: ["mx.yahoo.test"]
    попытки = []
    nv._do_single_ping = lambda *a, **k: (попытки.append(1) or
                                          {"status": "valid", "reason": "250"})
    итог = nv.stealth_smtp_ping("someone@yahoo.com", ["mx.yahoo.test"])
    assert итог["status"] == "unknown", итог
    assert "PTR" in итог["reason"], итог["reason"]
    assert попытки == [], "потрачено холостых попыток: %d" % len(попытки)


def test_b5_control_diagnosis_names_the_real_cause():
    """Контроль: причина названа своим именем, а не «все прокси мертвы».

    Ложный диагноз отправлял владельца чинить живой пул прокси вместо того,
    чтобы достать адрес с обратным DNS.
    """
    nv = _validator({"socks5://1.2.3.4:1080": {"exit_ip": "1.2.3.4",
                                               "has_ptr": False}})
    nv.get_mx_records = lambda d: ["mx.yahoo.test"]
    nv._do_single_ping = lambda *a, **k: {"status": "valid", "reason": "250"}
    причина = nv.stealth_smtp_ping("s@yahoo.com", ["mx.yahoo.test"])["reason"]
    assert "мертв" not in причина.lower(), причина
    assert "прокси" in причина.lower()


def test_b5_control_unprofiled_pool_is_not_blocked():
    """Контроль: без профилирования ограничений нет.

    «Не профилировали» и «профилировали, PTR ни у кого нет» — разные случаи.
    Спутав их, мы запретили бы Yahoo всем, кто просто не гонял профилирование.
    """
    nv = NetworkValidator(proxies=["socks5://1.2.3.4:1080"])
    nv._mx_delay = lambda mx: 0.0
    nv.country_for_domain = lambda domain, mx_host="": ""
    nv.check_dns_health = lambda d, mx_record="": {"score": 0}
    nv.get_mx_records = lambda d: ["mx.yahoo.test"]
    nv._do_single_ping = lambda *a, **k: {"status": "valid", "reason": "250 OK"}
    итог = nv.stealth_smtp_ping("someone@yahoo.com", ["mx.yahoo.test"])
    assert итог["status"] == "valid", итог


# ══════════════════════════ Б6: код 252 не вердикт ══════════════════════

def test_b6_code_252_is_not_a_verdict():
    """252 — прямой отказ отвечать о ящике, а не подтверждение.

    RFC 5321 §3.5.3: «не берусь проверить получателя, но письмо приму и
    попробую доставить». Засчитав это как Valid, мы отправляем письмо и
    узнаём правду по отскоку — когда база уже разослана.
    """
    итог = classify_smtp_response(252, b"2.0.0 cannot VRFY user")
    assert итог["status"] == "unknown", итог
    assert "252" in итог["reason"]


def test_b6_control_250_and_251_remain_valid():
    """Контроль: настоящие подтверждения не задеты."""
    assert classify_smtp_response(250, b"OK")["status"] == "valid"
    assert classify_smtp_response(251, b"will forward")["status"] == "valid"


def test_b6_control_mailbox_full_still_proves_existence():
    """Контроль: переполненный ящик — по-прежнему доказательство существования.

    Самый сильный положительный сигнал после 250: ящик не только есть, им
    пользуются.
    """
    итог = classify_smtp_response(452, b"4.2.2 mailbox full, over quota")
    assert итог["status"] == "valid", итог


# ══════════════════════════ Б7: регистр имени ящика ═════════════════════

def test_b7_mailbox_case_survives_loading():
    """Загрузчик базы больше не переписывает имя ящика."""
    загружено = [e for e, _ in StreamLoader(
        [{"type": "text", "content": "Jeronimo.Cuthbert@Corp-Example.com\n"}]
    ).stream_emails()]
    assert загружено == ["Jeronimo.Cuthbert@corp-example.com"], загружено


def test_b7_mailbox_case_survives_cleaning():
    """И очистка тоже: второе место, где регистр терялся."""
    assert strip_wrapping_junk("  John.Smith@Corp.COM ") == "John.Smith@corp.com"
    assert strip_wrapping_junk("Ivan P <IvanP@Example.RU>") == "IvanP@example.ru"


def test_b7_control_domain_is_still_lowercased():
    """Контроль: домен по-прежнему приводится к нижнему регистру.

    DNS регистр не различает, и без приведения `Gmail.com` разошёлся бы с
    `gmail.com` во всех словарях провайдеров.
    """
    assert _lower_domain_only("A@B.COM") == "A@b.com"
    assert strip_wrapping_junk("x@GMAIL.COM").endswith("@gmail.com")


def test_b7_control_dedup_key_is_still_case_insensitive():
    """Контроль: ключ сравнения по-прежнему в нижнем регистре.

    Регистр сохраняется в ДАННЫХ, но не в ключе: иначе `John@x.com` и
    `john@x.com` разъехались бы в дедупе и в сверке отписок, и человек,
    попросивший его не трогать, получил бы письмо снова.
    """
    from core.cleaner import normalize_for_dedup
    assert normalize_for_dedup("John.Smith@Corp.COM") == \
        normalize_for_dedup("john.smith@corp.com")


def test_b7_control_no_at_sign_is_survivable():
    """Контроль: строка без «собаки» не роняет помощник."""
    assert _lower_domain_only("MUSOR") == "musor"
    assert _lower_domain_only(None) == ""


# ══════════════════════════ Б8: ролевые ящики ═══════════════════════════

def test_b8_full_forms_are_recognised():
    """Полная форма опознаётся наравне с сокращением."""
    непойманные = [имя for имя in
                   ("administrator", "administration", "webadmin", "helpdesk",
                    "moderator", "operator", "newsletter", "careers",
                    "recruitment", "notifications", "autoreply", "donotreply",
                    "mailerdaemon", "invoices", "enquiries")
                   if not is_role_based("%s@corp-example.test" % имя)]
    assert not непойманные, "не опознаны как ролевые: %s" % непойманные


def test_b8_control_short_forms_still_work():
    """Контроль: то, что ловилось раньше, ловится и теперь."""
    for имя in ("admin", "info", "support", "postmaster", "abuse", "noreply"):
        assert is_role_based("%s@corp-example.test" % имя), имя


def test_b8_control_personal_mailboxes_are_not_swept_up():
    """Контроль: личные ящики ролевыми НЕ становятся.

    Лишний «Role-based» отнимает живой лид ровно так же, как ложный Invalid,
    поэтому имена, которые бывают и личными, в список не вносились.
    """
    личные = [имя for имя in
              ("ivan", "j.smith", "maria2005", "alex.petrov", "mail", "it",
               "dev", "order", "account", "ceo", "manager", "anna")
              if is_role_based("%s@corp-example.test" % имя)]
    assert not личные, "личный ящик помечен ролевым: %s" % личные


# ══════════════════════════ документ не расходится с кодом ══════════════

def test_docs_describe_the_fixed_behaviour():
    """Критерии описывают то, что в коде.

    Документ — обещание владельцу; расхождение с кодом хуже его отсутствия,
    потому что читают именно документ.
    """
    док = io.open(os.path.join(ROOT, "docs", "КРИТЕРИИ.md"),
                  encoding="utf-8").read()
    отсутствует = [кусок for кусок in
                   ("252", "точк", "регистр", "тарпит")
                   if кусок.lower() not in док.lower()]
    assert not отсутствует, "в критериях не описано: %s" % отсутствует
