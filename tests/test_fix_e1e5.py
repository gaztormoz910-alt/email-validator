# -*- coding: utf-8 -*-
"""Аудит 03.11.2026 (.unlazy/rivals/ОТЧЁТ.md): ложные «Не слать» и отказ во входе.

E1 — пересылки реальных людей получали Trap/Disposable;
E2 — живой почтовик из таблиц программы хоронился встроенным списком;
E3 — бесплатный почтовик хоронился одной строкой широкого сборника;
E4 — ящик за MX охранного вендора получал Trap/Disposable без единого RCPT;
E5 — окно отвергало CSV в кавычках и «"Имя" <адрес>» как поисковые запросы.

У каждого правила рядом стоит контроль, на котором оно срабатывать НЕ должно:
иначе исправление могло бы оказаться простым отключением проверки.
"""
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.disposable import (DISPOSABLE_DOMAINS, NEVER_DISPOSABLE,   # noqa: E402
                             extend_disposable_domains, is_disposable)
from core.filters import BLACKLIST_SENTINELS, SpamFilter            # noqa: E402
from core.input_guard import (KIND_DORK, KIND_EMAIL, check_text,     # noqa: E402
                              detect_kind)

# Поддельный почтовый сервер и настоящий валидатор — тот же стенд, что в
# аудите 27.09.2026: подменены только адрес соединения и ответ DNS. Берутся
# классы стенда, а фикстура заводится здесь: импортированная фикстура,
# использованная как имя параметра, для pyflakes — переопределение имени
# (tests/test_cleanup.py это ловит).
from test_audit6_fixes import (Принимает, _Обработчик, _Сервер,      # noqa: E402
                               валидатор, прогон)


@pytest.fixture
def поднять():
    """Фабрика поддельных серверов; все закрываются после теста."""
    серверы = []

    def сделать(сценарий):
        сервер = _Сервер(("127.0.0.1", 0), _Обработчик)
        сервер.сценарий = сценарий
        threading.Thread(target=сервер.serve_forever, daemon=True).start()
        серверы.append(сервер)
        return сервер.server_address[1]

    yield сделать
    for сервер in серверы:
        сервер.shutdown()
        сервер.server_close()


def _список(папка, имя, домены):
    with open(os.path.join(str(папка), имя), "w", encoding="utf-8") as f:
        f.write("\n".join(домены) + "\n")


# ═════════════════════════════════════ E1: пересылка — не одноразовый ящик

@pytest.mark.parametrize("домен", sorted(NEVER_DISPOSABLE))
def test_e1_relay_and_its_subdomain_survive_any_list(домен):
    """Ни строка в скачанном списке, ни поддомен пользователя не хоронят пересылку."""
    extend_disposable_domains([домен, "user." + домен])
    assert is_disposable("alias@" + домен) is False
    assert is_disposable("alias@user." + домен) is False


def test_e1_owner_list_cannot_bury_a_relay_but_still_works(tmp_path):
    """Свой список владельца пересылку не хоронит — а свои одноразовые ловит.

    В список кладутся и сами пересылки, и их ПОДДОМЕНЫ отдельными строками:
    голый домен вычищает из чёрного списка последний рубеж загрузки, а
    поддомен — только проверка цепочки в is_spam_or_disposable. Без неё
    `alias@user.anonaddy.com` совпал бы со строкой точно (рецензия, tests-2).
    """
    # Добивка выдуманными доменами: иначе живые почтовики среди пересылок
    # составили бы больше 5% файла, и он был бы отвергнут целиком.
    добивка = ["owner-temp-%03d.example" % i for i in range(300)]
    поддомены = ["user." + д for д in sorted(NEVER_DISPOSABLE)]
    _список(tmp_path, "my_list.txt", sorted(NEVER_DISPOSABLE) + поддомены + добивка)
    фильтр = SpamFilter(data_dir=str(tmp_path))
    assert "user.anonaddy.com" in фильтр.blacklist_domains, "проверка стала холостой"
    # Голые домены пересылок вычищены из самого чёрного списка, а не только
    # спасены проверкой цепочки: без вычета вердикты те же, но список и его
    # размер врут (рецензия №1, мутация M_filters_minus_never не ловилась).
    assert not (NEVER_DISPOSABLE & фильтр.blacklist_domains)
    for домен in NEVER_DISPOSABLE:
        assert not фильтр.is_spam_or_disposable("alias@" + домен), домен
        assert not фильтр.is_spam_or_disposable("alias@user." + домен), домен
    assert фильтр.is_spam_or_disposable("x@owner-temp-007.example")


def test_e1_relay_subdomain_is_not_a_machine_address():
    """Признак «машинное имя» прощает и поддомен пересылки, как фильтр одноразовых."""
    from core.heuristics import looks_machine_generated

    assert looks_machine_generated("k8jf3nzqwt9x@user.anonaddy.com") is False
    assert looks_machine_generated("k8jf3nzqwt9x@gmail.com") is True     # контроль


def test_e1_relay_is_not_buried_by_its_mail_server_either():
    """Шаг по почтовому серверу тоже не хоронит пересылку.

    У масок opayq.com MX чужой — junkemailfilter.com, — и строка с ним в любом
    списке похоронила бы их все: шаг сверял только имя сервера, а не домен
    адреса (рецензия правки E1, 06.11.2026).
    """
    import types
    from core.settle import SettleMixin

    extend_disposable_domains(["junkemailfilter.com"])
    шаг = SettleMixin()
    шаг.network = types.SimpleNamespace(get_mx_records=lambda домен: ["plato.junkemailfilter.com"])
    шаг._emit_trap = lambda *a, **k: None
    assert шаг._disposable_by_mx("mask@opayq.com", {}, False) is False
    assert шаг._disposable_by_mx("x@new-temp-e1.example", {}, False) is True     # контроль


def test_e1_real_disposables_are_still_caught():
    """Контроль: временные ящики и их поддомены по-прежнему ловятся.

    spamgourmet.com — граница правила: его адреса сами умирают после заданного
    числа писем, это одноразовый ящик, а не постоянная пересылка.
    """
    for адрес in ("a@mailinator.com", "a@sub.mailinator.com", "a@yopmail.com",
                  "a@10minutemail.com", "a@spamgourmet.com"):
        assert is_disposable(адрес) is True, адрес


# ════════════════════ E2: живой почтовик одноразовым не бывает нигде

def test_e2_live_provider_in_the_builtin_list_is_not_disposable():
    """Страж чистил только скачанные списки; встроенный набор — нет."""
    живые = sorted(BLACKLIST_SENTINELS)[:40]
    DISPOSABLE_DOMAINS.update(живые)
    for домен in живые:
        assert is_disposable("user@" + домен) is False, домен


def test_e2_mail_infrastructure_from_a_list_is_not_disposable(tmp_path):
    """Почтовую инфраструктуру крупных служб список тоже не хоронит.

    Программа сама числит её «никогда не одноразовой» (_MX_NEVER_DISPOSABLE),
    а широкий сборник называл forwardemail.net — там живут support@ и abuse@
    самого сервиса — и yandex.net (вторая проверка полноты, 06.11.2026).
    """
    from core.disposable import _MX_NEVER_DISPOSABLE

    добивка = ["infra-temp-%03d.example" % i for i in range(300)]
    _список(tmp_path, "my_list.txt", ["forwardemail.net", "yandex.net"] + добивка)
    фильтр = SpamFilter(data_dir=str(tmp_path))
    extend_disposable_domains(фильтр.blacklist_domains)
    assert not (_MX_NEVER_DISPOSABLE & фильтр.blacklist_domains)
    for домен in ("forwardemail.net", "yandex.net"):
        assert not фильтр.is_spam_or_disposable("support@" + домен), домен
        assert is_disposable("support@" + домен) is False, домен
    assert фильтр.is_spam_or_disposable("x@infra-temp-007.example")     # контроль


def test_e2_mail_infrastructure_in_the_base_itself_is_not_disposable():
    """В обход SpamFilter: строка, попавшая в базу напрямую, тоже не хоронит.

    Это держит страж в is_disposable, а не вычет в фильтре: без этого теста
    откат стража был незаметен (рецензия 3–4-го кругов, 06.11.2026).
    """
    extend_disposable_domains(["forwardemail.net", "yandex.net"])
    assert is_disposable("support@forwardemail.net") is False
    assert is_disposable("support@yandex.net") is False


def test_e2_ordinary_builtin_entry_still_works():
    """Контроль: обычная запись встроенного набора по-прежнему действует."""
    DISPOSABLE_DOMAINS.add("not-a-live-provider-e2.example")
    assert is_disposable("user@not-a-live-provider-e2.example") is True


# ══════════ E3: широкий сборник не хоронит бесплатного почтовика одной строкой

@pytest.fixture
def списки(tmp_path):
    _список(tmp_path, "free_providers.txt",
            ["freebox-e3.example", "curated-free-e3.example", "owner-free-e3.example",
             "x.parent-temp-e3.example"])
    _список(tmp_path, "disposable.txt", ["curated-free-e3.example", "curated-only-e3.example"])
    _список(tmp_path, "disposable_more.txt",
            ["freebox-e3.example", "curated-free-e3.example", "temp-only-e3.example",
             "parent-temp-e3.example"])
    _список(tmp_path, "disposable_extra.txt", ["freebox-e3.example"])
    _список(tmp_path, "my_list.txt", ["owner-free-e3.example"])
    return str(tmp_path)


def test_e3_free_provider_named_only_by_a_broad_list_is_kept(списки):
    фильтр = SpamFilter(data_dir=списки)
    assert not фильтр.is_spam_or_disposable("a@freebox-e3.example")
    # Спор записан, а не проглочен: видно, откуда и что выброшено.
    assert "freebox-e3.example" in фильтр.free_conflicts["disposable_more.txt"]
    assert "freebox-e3.example" in фильтр.free_conflicts["disposable_extra.txt"]


def test_e3_curated_and_owner_lists_still_win(списки):
    """Контроль: курируемый список и свой файл владельца по-прежнему хоронят."""
    фильтр = SpamFilter(data_dir=списки)
    assert фильтр.is_spam_or_disposable("a@curated-free-e3.example")
    assert фильтр.is_spam_or_disposable("a@owner-free-e3.example")
    assert фильтр.is_spam_or_disposable("a@temp-only-e3.example")
    assert фильтр.is_spam_or_disposable("a@curated-only-e3.example")


def test_e3_parent_service_still_counts(списки):
    """Контроль: `parent-temp-e3.example` — свидетельство о сервисе, и его поддомен ловится."""
    фильтр = SpamFilter(data_dir=списки)
    extend_disposable_domains(фильтр.blacklist_domains)
    assert is_disposable("a@x.parent-temp-e3.example") is True
    assert is_disposable("a@freebox-e3.example") is False


# ═══════════ E4: MX охранного вендора — «не проверяли», а не «писать нельзя»

# Регистр и точка на конце — как DNS отдаёт имя на деле (core/dns_checks.py
# снимает только точку, регистр остаётся исходным).
VENDOR_MX = ("mx1.emailsecurity.trendmicro.com", "mx.fireeye.com", "mail.agari.com",
             "MX2.FireEye.COM.")


@pytest.mark.parametrize("mx", VENDOR_MX)
def test_e4_vendor_mx_is_unknown_and_never_probed(monkeypatch, поднять, mx):
    from core.pipeline import _is_transient_failure
    from core.verdict import verdict_confidence

    сценарий = Принимает("anna.ivanova")
    v = валидатор(monkeypatch, поднять(сценарий), mx=mx)
    итог = v.check_email("anna.ivanova@vendor-e4.ru")
    assert итог["status"] == "unknown"
    assert итог["security_vendor_mx"] in mx.lower()
    # Защита осталась: к серверу вендора не ушло ни одного RCPT.
    assert not [строка for строка in сценарий.журнал if строка.startswith("RCPT")]
    # Повтора нет, и держит это постоянная пометка «не проверяется», а не
    # случайное отсутствие временных слов: с дописанным «timeout» причина всё
    # равно не повторяется, хотя сам «timeout» повтор даёт. Прежняя проверка
    # оставалась зелёной и без пометки (рецензия №2, verdicts2-1).
    assert _is_transient_failure("unknown", итог["reason"]) is False
    assert _is_transient_failure("unknown", "timeout") is True
    assert _is_transient_failure("unknown", итог["reason"] + "; timeout") is False
    # Основание в выгрузке — «не проверялся», а не «сорвалось на нашей
    # стороне: таймаут, прокси» (рецензия, verdicts-1).
    assert verdict_confidence("unknown", итог["reason"]) == (0, "адрес не проверялся по сети")


def test_e4_vendor_mx_ends_as_unknown_in_the_pipeline(monkeypatch, поднять):
    v = валидатор(monkeypatch, поднять(Принимает("anna.ivanova")), mx=VENDOR_MX[0])
    итог = прогон(monkeypatch, v, ["anna.ivanova@vendor-e4.ru"])
    assert итог["anna.ivanova@vendor-e4.ru"][0] == "Unknown"


@pytest.mark.parametrize("mx", [None, "mx.sagari.com", "mail.notfireeye.com.br"])
def test_e4_ordinary_mx_is_still_checked(monkeypatch, поднять, mx):
    """Контроль: на обычном MX тот же сервер отвечает честно — и это видно.

    Похожее имя чужого сервера (`mx.sagari.com`) вендором не считается: вендор
    узнаётся по границе метки, а не подстрокой (рецензия, verdicts-5).
    """
    if mx is None:
        v = валидатор(monkeypatch, поднять(Принимает("anna.ivanova")))
    else:
        v = валидатор(monkeypatch, поднять(Принимает("anna.ivanova")), mx=mx)
    assert v.check_email("anna.ivanova@ordinary-e4.ru")["status"] == "valid"
    assert v.check_email("ghost.person1@ordinary-e4.ru")["status"] == "invalid"


# ════════════ E5: строка базы с кавычками — не поисковый запрос

СТРОКИ_БАЗЫ = [
    '"user0@gmail.com","Ivan Petrov","US"',
    '"Ivan Petrov" <user0@gmail.com>',
    '"Петров Иван" <ivan.petrov@mail.ru>',
    '"user1@yahoo.com";"Anna Maria Lopez";"ES"',
    # Заметка в поле: `ext:` внутри «Next:» — не оператор поиска (рецензия, input-2).
    '"user2@gmail.com","Next: call on Monday","US"',
    # Выгрузка с разделителем «|» пишет поля впритык.
    '"user3@gmail.com"|"Ivan Petrov"|"US"',
    # Настоящий CSV, который строгий разбор обязан принять: разделитель внутри
    # кавычек, пробел перед разделителем, удвоенная кавычка внутри поля.
    '"Petrov, Ivan","user4@gmail.com"',
    '"user5@gmail.com" , "Ivan Petrov"',
    '"Ivan ""The Boss"" Petrov","user6@gmail.com"',
    # Ячейка адреса с пробелами внутри кавычек (CHAR(n) из базы данных):
    # detect_kind давал «непонятно» (рецензия 3–4-го кругов, 06.11.2026).
    '"user7@gmail.com   ","Ivan Petrov","US"',
    '" user8@gmail.com","Ivan Petrov"',
]
ЗАПРОСЫ = [
    '"@gmail.com" контакты',
    'site:linkedin.com "@gmail.com"',
    'site:linkedin.com "ivan@gmail.com"',
    '"john smith" "@gmail.com"',
    'intext:"@aol.com" marketing manager',
    '-site:vk.com "@mail.ru" директор',
    # Шаблон с подстановкой и запрос с целым адресом — тоже запросы: строку
    # базы отличает строение, а не наличие адреса (рецензия, input-1/tests-1).
    '"*@gmail.com" marketing manager',
    '"%@yahoo.com" director',
    '"ivan@gmail.com" телефон',
    # Подстановка в поле через разделитель — тоже шаблон, а не адрес: без
    # защиты от `*` и `%` эти строки ушли бы в базу (рецензия 2, input2-3).
    '"*@gmail.com", marketing manager',
    '"%@yahoo.com"; director',
    # «|» с пробелами — «ИЛИ» поисковика, а не разделитель полей (input2-1).
    '"user0@gmail.com" | "user1@yahoo.com" phone',
    # Оператор сразу после разделителя без пробела (input2-2).
    '"@gmail.com"|site:linkedin.com',
    '"@gmail.com",site:linkedin.com',
    # Текст сразу за закрывающей кавычкой — запрос, а не поле выгрузки: на
    # b68b9a8 это были запросы, а первая правка E5 делала их строками базы
    # (остаток input2-1, найден проверкой полноты 04.11.2026).
    '"ivan@gmail.com"|"anna@gmail.com" marketing',
    '"ivan@gmail.com","anna@gmail.com" marketing',
]


@pytest.mark.parametrize("строка", СТРОКИ_БАЗЫ)
def test_e5_quoted_base_line_is_an_address(строка):
    assert detect_kind(строка) == KIND_EMAIL


@pytest.mark.parametrize("строка", ЗАПРОСЫ)
def test_e5_real_queries_are_still_queries(строка):
    """Контроль: запрос в кавычках и запрос с оператором остаются запросами."""
    assert detect_kind(строка) == KIND_DORK


def test_e5_quoted_csv_export_is_accepted_by_the_window():
    выгрузка = '"email","name","country"\n' + "\n".join(
        '"user%d@gmail.com","Ivan Petrov%d","US"' % (i, i) for i in range(10))
    assert check_text(выгрузка, KIND_EMAIL)["ok"] is True
    assert check_text("\n".join(ЗАПРОСЫ), KIND_EMAIL)["ok"] is False


def test_e5_queries_with_whole_addresses_are_accepted_as_queries():
    """Обратная сторона в поле запросов: такой список принимался на b68b9a8.

    После первой правки E5 он отвергался целиком словами «Это список адресов,
    а не поисковые запросы» (проверка полноты, 04.11.2026).
    """
    запросы = "\n".join('"a%d@x.com"|"b%d@y.com" marketing' % (i, i) for i in range(3))
    assert check_text(запросы, KIND_DORK)["ok"] is True


ДВУСМЫСЛЕННЫЕ = [
    '"a%d@x.com", телефон директора',
    '"a%d@x.com"; телефон директора',
    '"a%d@x.com"\tтелефон директора',
    '"a%d@x.com"|"Oleg Petrov"',
    '"a%d@x.com"| телефон директора',
    '" a%d@x.com", телефон директора',
]


@pytest.mark.parametrize("шаблон", ДВУСМЫСЛЕННЫЕ)
def test_e5_ambiguous_line_belongs_to_the_field_it_was_pasted_into(шаблон):
    """Строка, верная и как CSV, и как запрос, — то, во что её вставили.

    Поле запросов принимает такой список как запросы (так было на b68b9a8),
    поле адресов — как строки базы (E5). Строение их не различает
    (вторая проверка полноты, 06.11.2026: поле запросов их отвергало).
    """
    текст = "\n".join(шаблон % i for i in range(3))
    assert check_text(текст, KIND_DORK)["ok"] is True
    assert check_text(текст, KIND_EMAIL)["ok"] is True


def test_e5_unquoted_base_in_the_query_field_is_still_rejected():
    """Контроль: база без кавычек в поле запросов по-прежнему отвергается."""
    база = "\n".join("user%d@gmail.com;Ivan;Petrov" % i for i in range(5))
    итог = check_text(база, KIND_DORK)
    assert итог["ok"] is False
    assert "список адресов" in итог["reason"]


def test_e5_query_field_keeps_the_old_operator_rule():
    """В поле запросов оператор узнаётся и внутри слова, как на b68b9a8.

    Сужение до начала слова нужно полю адресов — заметка «Next: call» не
    делает строку базы запросом. В поле запросов `website:` и `text:` остаются
    запросами (рецензия правки E5, 06.11.2026: поле их отвергало).
    """
    запросы = "contact website: @gmail.com\n@gmail.com text:resume\nmarketing @gmail.com context:usa"
    assert check_text(запросы, KIND_DORK)["ok"] is True


@pytest.mark.parametrize("мусор", ["website:@gmail.com", "«@mail.ru»site:vk.com", "email:@gmail.com"])
def test_e5_colon_is_never_part_of_an_address(мусор):
    """Двоеточия нет ни в имени ящика без кавычек, ни в домене."""
    assert check_text("\n".join([мусор] * 3), KIND_EMAIL)["ok"] is False


@pytest.mark.parametrize("шаблон", [
    "mailto:user%d@gmail.com,Ivan Petrov",
    "Ivan;mailto:user%d@gmail.com;US",
    "Email:user%d@gmail.com;Phone:123",
    '{"email":"user%d@gmail.com","name":"Ivan"}',
    "login%d:user%d@gmail.com|Ivan",
])
def test_e5_address_after_a_key_prefix_is_still_an_address(шаблон):
    """Положительный контроль правила «:»: поле «ключ:значение» с адресом — строка базы.

    Правило отвергало такие списки вместе с мусором, а b68b9a8 их принимал
    (рецензия 5-го круга, 06.11.2026).
    """
    текст = "\n".join(шаблон.replace("%d", str(i)) for i in range(5))
    assert check_text(текст, KIND_EMAIL)["ok"] is True


def test_e5_lone_surrogate_does_not_crash_the_check():
    """Одиночный суррогат приходит из вставки через JSON — ответ, а не падение."""
    строка = '"\ud800ivan@gmail.com", Ivan Petrov'
    assert check_text(строка, KIND_EMAIL)["ok"] in (True, False)
    assert check_text(строка, KIND_DORK)["ok"] in (True, False)


@pytest.mark.parametrize("разделитель", ['"', "\n", "\r", None, "", ",;"])
def test_e5_csv_fields_refuses_foreign_separators(разделитель):
    """Чужой разделитель — «не CSV»: с Python 3.13 csv сам бросает ValueError."""
    from core.input_guard import _csv_fields

    assert _csv_fields('"a@x.com","b"', разделитель) is None
