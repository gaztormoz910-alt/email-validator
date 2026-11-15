# -*- coding: utf-8 -*-
"""Что показал живой прогон 15.11.2026 через грязные прокси.

300 адресов с прежними ответами серверов, 14 живых прокси (11 в чёрных
списках, обратный DNS у двух). Противоречий с эталоном не было ни одного: где
программа дала определённый ответ, он совпал. Но вскрылись две вещи, обе — о
том, как грязный выход отравляет вывод:

1. yandex.com, принявший выдуманный адрес с такого выхода, лёг в долгую
   память как «принимает любой адрес» на месяц, хотя это тот же почтовик, что
   yandex.ru (сервер mx.yandex.ru), и в базе владельца он честно отвечал
   «нет такого ящика».
2. 82 адреса gmail в конце прогона получили причину «домен принимает любой
   адрес (catch-all)», хотя у gmail это тарпитинг нашего выхода, а не
   свойство домена: владелец пошёл бы чистить базу вместо смены прокси.

Сеть не нужна: проверяется решение, а не диалог с сервером.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network import NetworkValidator  # noqa: E402
from core.verdict_revision import VerdictRevisionMixin  # noqa: E402


class _Память:
    def __init__(self):
        self.записи = []

    def catchall_put(self, domain, is_catchall):
        self.записи.append((domain, is_catchall))

    def catchall_get(self, domain):
        return None


def validator():
    return NetworkValidator(timeout=2, proxy_dns=False)


def test_yandex_family_is_never_remembered_as_catch_all():
    nv = validator()
    nv.memory = _Память()
    for домен in ("yandex.com", "yandex.by", "yandex.kz", "yandex.com.tr"):
        assert nv._is_never_catchall(домен), домен
        nv._remember_catchall(домен, True)
    assert nv.memory.записи == []


def test_real_catch_all_providers_are_not_added_by_mistake():
    """Обратный контроль: mail.ru и его домены ПРИНИМАЮТ любой адрес (проверено
    вживую раньше) — им нужна тройная проба, иначе несуществующие ящики уйдут
    в «Годен». protonmail.com вне списка, пока противоречие не разрешено."""
    nv = validator()
    for домен in ("mail.ru", "bk.ru", "inbox.ru", "list.ru", "protonmail.com",
                  "yandex.ua", "narod.ru", "corp-example.test"):
        assert not nv._is_never_catchall(домен), домен


def test_ordinary_domain_is_still_remembered_as_catch_all():
    nv = validator()
    nv.memory = _Память()
    nv._remember_catchall("corp-example.test", True)
    assert nv.memory.записи == [("corp-example.test", True)]


class _Конвейер(VerdictRevisionMixin):
    def __init__(self):
        self.network = validator()


def test_giant_that_accepted_a_fake_is_reported_as_tarpit_not_catch_all():
    proven, trapped = _Конвейер()._split_catchall_from_tarpit(
        ["corp-example.test", "gmail.com", "yandex.com"], [])
    assert proven == ["corp-example.test"]
    assert trapped == ["gmail.com", "yandex.com"]


def test_split_keeps_existing_tarpit_and_plain_catch_all():
    """Контроль: без гигантов ничего не перекладывается и не теряется."""
    proven, trapped = _Конвейер()._split_catchall_from_tarpit(
        ["corp-example.test", "shop-example.test"], ["outlook.com"])
    assert proven == ["corp-example.test", "shop-example.test"]
    assert trapped == ["outlook.com"]
    assert _Конвейер()._split_catchall_from_tarpit([], []) == ([], [])


def test_pipeline_uses_the_split_before_revising():
    """Пересмотр в конце прогона идёт через деление, а не напрямую."""
    import io
    src = io.open(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                               "core", "pipeline.py"), encoding="utf-8").read()
    i = src.index("proven_catchall_domains()")
    assert "_split_catchall_from_tarpit(proven, trapped)" in src[i:i + 600]
