# -*- coding: utf-8 -*-
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.cleaner import EmailCleaner


def cleaner_with_dns(answers):
    c = EmailCleaner()
    c.установить_проверку_домена(lambda d: answers.get(d, False))
    return c


@pytest.mark.parametrize("word", ["watch", "regarde", "mira", "assista", "xem", "schau"])
def test_glued_word_is_cut_when_dns_proves_it(word):
    c = cleaner_with_dns({"gmail.com": True})
    assert c.clean_email("qa.tester@gmail.com.%s" % word) == "qa.tester@gmail.com"


def test_real_country_domain_of_a_provider_is_kept():
    c = cleaner_with_dns({"yahoo.com": True, "yahoo.com.vn": True})
    assert c.clean_email("qa.tester@yahoo.com.vn") == "qa.tester@yahoo.com.vn"


def test_unknown_dns_answer_leaves_the_address_as_loaded():
    c = EmailCleaner()
    c.установить_проверку_домена(lambda d: None)
    assert c.clean_email("qa.tester@gmail.com.watch") == "qa.tester@gmail.com.watch"


def test_dead_provider_too_leaves_the_address_as_loaded():
    c = cleaner_with_dns({})
    assert c.clean_email("qa.tester@gmail.com.watch") == "qa.tester@gmail.com.watch"


def test_without_network_no_foreign_zone_is_made_up():
    c = EmailCleaner()
    for addr in ("qa.tester@gmail.com.regarde", "qa.tester@yahoo.com.regarde",
                 "qa.tester@mail.ru.regarde"):
        assert c.clean_email(addr) == addr


def test_dns_is_asked_only_about_the_two_candidates():
    asked = []
    c = EmailCleaner()

    def check(d):
        asked.append(d)
        return {"gmail.com": True}.get(d, False)
    c.установить_проверку_домена(check)
    assert c.clean_email("qa.tester@gmail.com.watch") == "qa.tester@gmail.com"
    assert asked == ["gmail.com.watch", "gmail.com"]


@pytest.mark.parametrize("raw, expected", [
    ("qa.tester@gmail.comtelefoon", "qa.tester@gmail.com"),
    ("qa.tester@sky.company.co.uk", "qa.tester@sky.company.co.uk"),
    ("qa.tester@list.ru-company.com", "qa.tester@list.ru-company.com"),
    ("qa.tester@gmail.com", "qa.tester@gmail.com"),
    ("qa.tester@corp-example.test", "qa.tester@corp-example.test"),
])
def test_old_repairs_and_guards_are_untouched(raw, expected):
    assert EmailCleaner().clean_email(raw) == expected
