# -*- coding: utf-8 -*-
"""Проверки распознавания того, что положили в поле ввода.

Требование владельца: «чтобы в блок куда надо загружать почты чтобы я
случайно прокси туда не загрузил», и отдельно — чтобы путаница из-за
раскладки клавиатуры тоже ловилась.

Главная опасность этой задачи — перестараться. Строгая проверка, написанная
без оглядки, начинает резать кириллические адреса, а они законны. Поэтому
почти каждый тест здесь идёт парой: что должно отвергаться и что рядом с ним
обязано пройти.
"""
import io
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NEWLINE = "\n"

from core.encoding import SAMPLE_BYTES  # noqa: E402
from core.input_guard import (  # noqa: E402
    KIND_DORK, KIND_EMAIL, KIND_PROXY, KIND_UNKNOWN,
    check, check_file, check_text, classify, detect_kind, fix_layout,
    layout_suggestion, looks_like_email, looks_like_proxy,
)


# ─────────────────────────────────────────────── detect: адреса

@pytest.mark.parametrize("line", [
    "ivan@gmail.com",
    "IVAN.PETROV@Yahoo.COM",
    "ivan+news@googlemail.com",
    "ivan@gmail.com;Иван;Петров;США",
    "ivan@gmail.com,Ivan Petrov,US",
    "ivan@gmail.com|Ivan|30",
    "ivan@gmail.com\tIvan\tPetrov",
    "ivan@mail.example.co.uk",
    "иван@почта.рф",
    "müller@bücher.de",
    "ivan@gmail.com:Ivan:Petrov",
])
def test_detect_reads_every_email_format(line):
    assert detect_kind(line) == KIND_EMAIL, line


# ─────────────────────────────────────────────── detect: прокси

@pytest.mark.parametrize("line", [
    "1.2.3.4:8080",
    "1.2.3.4:8080:user:pass",
    "socks5://1.2.3.4:1080",
    "socks4://1.2.3.4:1080",
    "http://1.2.3.4:3128",
    "https://proxy.example.com:3128",
    "user:pass@1.2.3.4:8080",
    "http://user:pass@1.2.3.4:3128",
    "socks5://user:pass@proxy.example.com:1080",
    "proxy.example.com:8080",
])
def test_detect_reads_every_proxy_format(line):
    assert detect_kind(line) == KIND_PROXY, line


def test_detect_proxy_with_credentials_is_not_mistaken_for_an_email():
    """user:pass@host:port содержит собаку, но адресом не является."""
    assert not looks_like_email("user:pass@1.2.3.4:8080")
    assert detect_kind("user:pass@1.2.3.4:8080") == KIND_PROXY


def test_detect_rejects_impossible_port():
    assert detect_kind("1.2.3.4:99999") != KIND_PROXY


# ─────────────────────────────────────────────── detect: запросы

@pytest.mark.parametrize("line", [
    'site:linkedin.com "@gmail.com"',
    'intext:"@yahoo.com" marketing',
    'inurl:contact "@aol.com"',
    'filetype:pdf "@gmail.com" резюме',
    '"@aol.com" контакты компании',
    "marketing manager contacts",
])
def test_detect_reads_every_dork_format(line):
    assert detect_kind(line) == KIND_DORK, line


def test_detect_dork_wins_over_the_email_inside_it():
    """В дорке почти всегда есть собака — и это не делает его адресом."""
    line = 'site:linkedin.com "@gmail.com"'
    assert detect_kind(line) == KIND_DORK
    assert detect_kind("ivan@gmail.com") == KIND_EMAIL


# ─────────────────────────────────────────────── mismatch: не туда положили

def test_mismatch_proxies_pasted_into_the_address_field():
    text = "\n".join(["1.2.3.4:8080", "5.6.7.8:3128", "socks5://9.9.9.9:1080"])
    result = check_text(text, KIND_EMAIL)
    assert result["ok"] is False
    assert "прокси" in result["reason"]
    # Отказ обязан сказать, КУДА это нести, иначе он бесполезен.
    assert "«Прокси»" in result["reason"]


def test_mismatch_addresses_pasted_into_the_proxy_field():
    text = "\n".join(["ivan@gmail.com", "anna@yahoo.com", "petr@mail.ru"])
    result = check_text(text, KIND_PROXY)
    assert result["ok"] is False
    assert "адрес" in result["reason"]
    assert "«Адреса для проверки»" in result["reason"]


def test_mismatch_dorks_pasted_into_the_address_field():
    text = 'site:linkedin.com "@gmail.com"\nintext:"@yahoo.com" sales'
    result = check_text(text, KIND_EMAIL)
    assert result["ok"] is False
    assert "Поисковые запросы" in result["reason"]


def test_mismatch_accepts_the_right_list_in_the_right_field():
    """Положительный контроль: без него проверка могла бы просто всё отвергать."""
    assert check_text("ivan@gmail.com\nanna@yahoo.com", KIND_EMAIL)["ok"] is True
    assert check_text("1.2.3.4:8080\n5.6.7.8:3128", KIND_PROXY)["ok"] is True
    assert check_text('site:vk.com "@mail.ru"', KIND_DORK)["ok"] is True


def test_mismatch_tolerates_a_header_and_blank_lines():
    """В живом файле есть заголовок CSV и пустые строки — это не повод отказать."""
    text = "email;name;country\nivan@gmail.com;Ivan;US\n\n   \nanna@yahoo.com;Anna;UK\n"
    assert check_text(text, KIND_EMAIL)["ok"] is True


def test_mismatch_rejects_an_empty_list():
    result = check_text("   \n\n#комментарий\n", KIND_EMAIL)
    assert result["ok"] is False
    assert "пуст" in result["reason"]


# ─────────────────────────────────────────────── раскладка

def test_layout_translates_by_physical_keys():
    # «ivan», набранное в русской раскладке: i=ш, v=м, a=ф, n=т.
    assert fix_layout("шмфт") == "ivan"
    assert fix_layout("пьфшд") == "gmail"
    assert fix_layout("шмфт@пьфшд.сщь") == "ivan@gmail.com"


def test_layout_is_offered_for_a_wrong_keyboard_layout():
    assert layout_suggestion("шмфт@пьфшд.сщь") == "ivan@gmail.com"


def test_layout_real_cyrillic_address_is_left_alone():
    """Граница задачи. Кириллический адрес законен, и трогать его нельзя.

    Скилл валидации прямо запрещает считать не-ASCII признаком ошибки:
    иван@почта.рф — работающий адрес, и ложный отказ здесь стоит владельцу
    живого контакта.
    """
    assert detect_kind("иван@почта.рф") == KIND_EMAIL
    assert layout_suggestion("иван@почта.рф") is None
    assert check_text("иван@почта.рф\nмария@почта.рус", KIND_EMAIL)["ok"] is True


def test_layout_is_reported_to_the_owner_with_the_fix():
    result = check_text("шмфт@пьфшд.сщь\nфттф@нфрщщ.сщь", KIND_EMAIL)
    assert result["ok"] is False
    assert "раскладка" in result["reason"].lower()
    assert "ivan@gmail.com" in result["reason"]


def test_layout_suggestion_is_silent_on_plain_gibberish():
    """Не всякая непонятная строка — раскладка; выдумывать исправление нельзя."""
    assert layout_suggestion("!!!!") is None
    assert layout_suggestion("...") is None


# ─────────────────────────────────────────────── файлы

@pytest.fixture
def tmp_lists(tmp_path):
    emails = tmp_path / "base.txt"
    emails.write_text("\n".join("user%d@gmail.com" % i for i in range(50)),
                      encoding="utf-8")
    proxies = tmp_path / "proxy.txt"
    proxies.write_text("\n".join("1.2.3.%d:8080" % i for i in range(1, 50)),
                       encoding="utf-8")
    return emails, proxies


def test_file_rejects_a_proxy_list_chosen_as_the_base(tmp_lists):
    emails, proxies = tmp_lists
    result = check_file(str(proxies), KIND_EMAIL)
    assert result["ok"] is False
    assert "прокси" in result["reason"]
    # Имя файла в отказе: у владельца открыто несколько, надо знать который.
    assert "proxy.txt" in result["reason"]


def test_file_accepts_the_right_list(tmp_lists):
    emails, proxies = tmp_lists
    assert check_file(str(emails), KIND_EMAIL)["ok"] is True
    assert check_file(str(proxies), KIND_PROXY)["ok"] is True


def test_file_reads_only_a_sample_not_the_whole_base(tmp_path):
    """Гигантская база не должна читаться целиком ради опознания типа.

    Проверяется не время, а факт: файл открывается лениво и до конца не
    дочитывается. Замер по позиции в файле честнее секундомера — он не
    зависит от того, чем занята машина.
    """
    big = tmp_path / "huge.txt"
    with io.open(big, "w", encoding="utf-8") as handle:
        for i in range(200_000):
            handle.write("user%d@gmail.com\n" % i)

    total_lines = 200_000
    served = []
    sniffed = []
    real_open = io.open

    class Counting:
        """Отдаёт строки и считает, сколько их успели забрать."""

        def __init__(self, handle):
            self._handle = handle
            self.lines = 0

        def __iter__(self):
            for line in self._handle:
                self.lines += 1
                yield line

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            served.append(self.lines)
            return self._handle.__exit__(*exc)

    class Sniffing:
        """Двоичное чтение для опознания кодировки: считает БАЙТЫ.

        Определение кодировки — второй читатель того же файла, и на нём то же
        требование: заглянуть в начало, а не прочитать базу целиком.
        """

        def __init__(self, handle):
            self._handle = handle

        def read(self, size=-1):
            data = self._handle.read(size)
            sniffed.append(len(data))
            return data

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return self._handle.__exit__(*exc)

    def spy(path, *args, **kwargs):
        handle = real_open(path, *args, **kwargs)
        if str(path) != str(big):
            return handle
        mode = kwargs.get("mode") or (args[0] if args else "r")
        return Sniffing(handle) if "b" in mode else Counting(handle)

    io.open = spy
    try:
        result = check_file(str(big), KIND_EMAIL)
    finally:
        io.open = real_open

    assert result["ok"] is True
    assert served, "файл вообще не открывался"
    # Прочитано меньше сотой доли строк: выборка, а не весь файл.
    assert served[0] < total_lines / 100, (served[0], total_lines)
    # И опознание кодировки тоже читает выборку, а не всю базу.
    assert sniffed, "кодировка не определялась — файл читался вслепую"
    assert max(sniffed) <= SAMPLE_BYTES, max(sniffed)


def test_file_missing_is_reported_not_crashed(tmp_path):
    result = check_file(str(tmp_path / "нет-такого.txt"), KIND_EMAIL)
    assert result["ok"] is False
    assert "не удалось прочитать" in result["reason"].lower()


# ─────────────────────────────────────────────── общее

def test_classify_counts_every_kind():
    summary = classify([
        "ivan@gmail.com", "anna@yahoo.com",
        "1.2.3.4:8080",
        'site:vk.com "@mail.ru"',
        "!!!",
    ])
    assert summary["counts"][KIND_EMAIL] == 2
    assert summary["counts"][KIND_PROXY] == 1
    assert summary["counts"][KIND_DORK] == 1
    assert summary["counts"][KIND_UNKNOWN] == 1
    assert summary["dominant"] == KIND_EMAIL


def test_check_never_raises_on_junk():
    """Проверка ввода не имеет права уронить окно на чужих данных."""
    for junk in ([None], [123], [b"\xff\xfe"], ["\x00" * 100], [" " * 10_000]):
        result = check(junk, KIND_EMAIL)
        assert isinstance(result["ok"], bool)


def test_proxy_and_email_never_both_true():
    """Строка не может быть и адресом, и прокси — иначе поля не различить."""
    for line in ("ivan@gmail.com", "1.2.3.4:8080", "user:pass@1.2.3.4:8080",
                 "иван@почта.рф", "socks5://9.9.9.9:1080"):
        assert not (looks_like_email(line) and looks_like_proxy(line)), line

def test_file_suppression_list_is_checked_too(tmp_path, monkeypatch):
    """Список отписок проверяется строже прочих.

    По нему решают, кому НЕ слать. Подсунутый вместо него список прокси не
    вычтет никого, и письмо уйдёт тому, кто прямо попросил его не трогать.
    """
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from ui.webapp import ValidatorApi

    proxies = tmp_path / "proxy.txt"
    proxies.write_text(NEWLINE.join("1.2.3.%d:8080" % i for i in range(1, 40)),
                       encoding="utf-8")
    unsubs = tmp_path / "unsubs.txt"
    unsubs.write_text(NEWLINE.join("user%d@gmail.com" % i for i in range(40)),
                      encoding="utf-8")

    api = ValidatorApi()

    api._pick_files = lambda kind: [str(proxies)]
    refused = api.choose_suppression()
    assert refused.get("error"), "список прокси принят как отписки"
    assert api.suppress_path is None

    api._pick_files = lambda kind: [str(unsubs)]
    accepted = api.choose_suppression()
    assert not accepted.get("error")
    assert api.suppress_path == str(unsubs)
