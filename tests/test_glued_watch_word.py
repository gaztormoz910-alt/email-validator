# -*- coding: utf-8 -*-
"""Почтовик с приклеенным словом: `gmail.com.watch`, `gmail.com.regarde`.

Базы, собранные со страниц видео, несут после адреса начало следующей фразы
(«…@gmail.com. Watch…»), и пробел теряется. Замерено 15.11.2026 на двух
базах владельца: 3,4% и 3,9% строк такого вида. Это живые ящики, а программа
хоронила их как «домена нет», а без сети `regarde` и вовсе резался до зоны
`re` — чужого домена `gmail.com.re`.

Решает DNS, а не вид строки: `yahoo.com.vn` выглядит так же, но это
настоящий домен. Сеть здесь не нужна — проверка домена подменяется заглушкой
с известными ответами. Адреса выдуманы.
"""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cleaner import EmailCleaner  # noqa: E402


def cleaner_with_dns(answers):
    """Очистка с проверкой домена: answers[домен] -> True/False/None."""
    c = EmailCleaner()
    c.установить_проверку_домена(lambda d: answers.get(d, False))
    return c


@pytest.mark.parametrize("word", ["watch", "regarde", "mira", "assista", "xem", "schau"])
def test_glued_word_is_cut_when_dns_proves_it(word):
    """Загруженный домен почту не принимает, почтовик — принимает: чиним."""
    c = cleaner_with_dns({"gmail.com": True})
    assert c.clean_email("qa.tester@gmail.com.%s" % word) == "qa.tester@gmail.com"


def test_real_country_domain_of_a_provider_is_kept():
    """Отрицательный контроль: домен вида почтовик+метка, который почту ПРИНИМАЕТ,
    законный (как yahoo.com.vn), и трогать его нельзя."""
    c = cleaner_with_dns({"yahoo.com": True, "yahoo.com.vn": True})
    assert c.clean_email("qa.tester@yahoo.com.vn") == "qa.tester@yahoo.com.vn"


def test_unknown_dns_answer_leaves_the_address_as_loaded():
    """«Спросить не удалось» — не доказательство: адрес остаётся загруженным."""
    c = EmailCleaner()
    c.установить_проверку_домена(lambda d: None)
    assert c.clean_email("qa.tester@gmail.com.watch") == "qa.tester@gmail.com.watch"


def test_dead_provider_too_leaves_the_address_as_loaded():
    """Если и почтовик не отвечает, подменять не на что — оставляем как есть."""
    c = cleaner_with_dns({})
    assert c.clean_email("qa.tester@gmail.com.watch") == "qa.tester@gmail.com.watch"


def test_without_network_no_foreign_zone_is_made_up():
    """Без сети `regarde` больше не режется до чужой зоны `re`.

    Прежде очистка без конвейера выдавала `gmail.com.re` — чужой домен в зоне
    Реюньона. Теперь адрес остаётся загруженным: решит DNS, когда он будет.
    """
    c = EmailCleaner()
    for addr in ("qa.tester@gmail.com.regarde", "qa.tester@yahoo.com.regarde",
                 "qa.tester@mail.ru.regarde"):
        assert c.clean_email(addr) == addr


def test_dns_is_asked_only_about_the_two_candidates():
    """Спрашиваем ровно про загруженный домен и про почтовик — без перебора."""
    asked = []
    c = EmailCleaner()

    def check(d):
        asked.append(d)
        return {"gmail.com": True}.get(d, False)
    c.установить_проверку_домена(check)
    assert c.clean_email("qa.tester@gmail.com.watch") == "qa.tester@gmail.com"
    assert asked == ["gmail.com.watch", "gmail.com"]


@pytest.mark.parametrize("raw, expected", [
    # Прежние починки и защиты не задеты новым правилом.
    ("qa.tester@gmail.comtelefoon", "qa.tester@gmail.com"),
    ("qa.tester@sky.company.co.uk", "qa.tester@sky.company.co.uk"),
    ("qa.tester@list.ru-company.com", "qa.tester@list.ru-company.com"),
    ("qa.tester@gmail.com", "qa.tester@gmail.com"),
    ("qa.tester@corp-example.test", "qa.tester@corp-example.test"),
])
def test_old_repairs_and_guards_are_untouched(raw, expected):
    assert EmailCleaner().clean_email(raw) == expected
