"""Корпус НАСТОЯЩИХ ответов почтовых серверов и вердикт, который им положен.

Зачем отдельный файл. Точечные тесты проверяют то, на что смотрели, когда их
писали. Ответы серверов — область, где ошибиться можно ровно на одной подстроке
из полусотни, и увидеть это можно только на широкой выборке живых формулировок.
Здесь собраны ответы Gmail, Outlook, Yahoo, Mail.ru, Yandex, Zoho, QQ, Naver,
Proton, GMX, а также Postfix, Exim, Exchange, qmail и шлюзов безопасности —
в том виде, в каком они приходят на `RCPT TO`.

Каждая строка помечена одним из трёх классов:

* ``DEAD``   — сервер ДОКАЗАЛ, что ящика нет. Обязан быть `invalid`.
* ``ALIVE``  — ответ доказывает, что ящик есть. Обязан быть `valid`.
* ``NOTOLD`` — сервер о ящике не сказал ничего (репутация, политика,
  отправитель, лимит, протокол). `invalid` и `valid` здесь ОДИНАКОВО
  запрещены: первый хоронит живой контакт, второй ведёт к отскоку.

Именно третий класс — главный. Ложный `invalid` навсегда теряет живой адрес,
ложный `valid` портит репутацию отправителя отскоком.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.smtp_codes import classify_smtp_response, enhanced_status

DEAD, ALIVE, NOTOLD = "DEAD", "ALIVE", "NOTOLD"

# (код, ответ сервера, класс, откуда взято)
CORPUS = [
    # ------------------------------------------------------------- Gmail --
    (550, b"5.1.1 The email account that you tried to reach does not exist. "
          b"Please try double-checking the recipient's email address for typos "
          b"or unnecessary spaces. https://support.google.com/mail/?p=NoSuchUser",
     DEAD, "Gmail, несуществующий ящик"),
    (550, b"5.2.1 The email account that you tried to reach is disabled. "
          b"https://support.google.com/mail/?p=DisabledUser",
     NOTOLD, "Gmail, отключённый ящик — человек есть, письмо не дойдёт"),
    (550, b"5.7.1 [1.2.3.4] Our system has detected that this message is likely "
          b"unsolicited mail. To reduce the amount of spam sent to Gmail, this "
          b"message has been blocked.",
     NOTOLD, "Gmail, блок по репутации нашего IP"),
    (452, b"4.2.2 The email account that you tried to reach is over quota. "
          b"https://support.google.com/mail/?p=OverQuotaTemp",
     ALIVE, "Gmail, переполненный ящик"),
    (421, b"4.7.0 Try again later, closing connection.", NOTOLD, "Gmail, лимит скорости"),
    (250, b"2.1.5 OK  s12-20020a0561 - gsmtp", ALIVE, "Gmail, ящик принят"),

    # ------------------------------------------- Outlook / Microsoft 365 --
    (550, b"5.1.1 Requested action not taken: mailbox unavailable",
     DEAD, "Outlook.com, нет ящика"),
    (550, b"5.1.10 RESOLVER.ADR.RecipientNotFound; Recipient not found by SMTP "
          b"address lookup", DEAD, "Exchange Online, адрес не найден"),
    (550, b"5.7.1 Service unavailable, Client host [1.2.3.4] blocked using "
          b"Spamhaus. To request removal from this list see "
          b"https://www.spamhaus.org/query/ip/1.2.3.4",
     NOTOLD, "Outlook, наш IP в Spamhaus"),
    (550, b"5.7.606 Access denied, banned sending IP [1.2.3.4]",
     NOTOLD, "Exchange Online, забаненный отправляющий IP"),
    (550, b"5.7.1 Recipient address rejected: Access denied",
     NOTOLD, "O365, отказ по политике — про ящик не сказано"),
    (452, b"4.5.3 Too many recipients", NOTOLD, "Exchange, лимит получателей"),

    # ------------------------------------------------------------- Yahoo --
    (554, b"delivery error: dd This user doesn't have a yahoo.com account "
          b"(nosuchuser@yahoo.com) [0] - mta4123.mail.gq1.yahoo.com",
     DEAD, "Yahoo, нет аккаунта"),
    (550, b"5.7.25 [1.2.3.4] The IP address sending this message does not have "
          b"a PTR record setup, or the corresponding forward DNS entry does not "
          b"point to the sending IP.",
     NOTOLD, "Yahoo, у нашего IP нет PTR"),
    (421, b"4.7.0 [TSS04] Messages from 1.2.3.4 temporarily deferred due to user "
          b"complaints", NOTOLD, "Yahoo, временная отсрочка по жалобам"),

    # ------------------------------------------------------------ Mail.ru --
    (550, b"Message was not accepted -- invalid mailbox.  Local mailbox "
          b"nosuchuser@mail.ru is unavailable: user not found",
     DEAD, "Mail.ru, ящика нет"),
    (550, b"5.7.1 Spam message rejected. Please visit "
          b"https://help.mail.ru/notspam-support/id?c=...", NOTOLD, "Mail.ru, спам-фильтр"),
    (250, b"OK", ALIVE, "Mail.ru принимает ЛЮБОЙ адрес — это catch-all уровнем выше"),

    # ------------------------------------------------------------ Yandex --
    (550, b"5.7.1 No such user!", DEAD, "Yandex, нет пользователя"),
    (550, b"5.7.1 Message rejected under suspicion of SPAM",
     NOTOLD, "Yandex, подозрение на спам"),

    # -------------------------------------------------- Proton / Zoho / GMX --
    (550, b"5.1.1 Recipient not found", DEAD, "Proton, нет получателя"),
    (550, b"5.1.1 <x@zoho.com>: Recipient address rejected: User unknown in "
          b"virtual mailbox table", DEAD, "Zoho на postfix, нет ящика"),
    (550, b"5.7.1 Requested action not taken: mailbox unavailable (in reply to "
          b"RCPT TO command)", NOTOLD, "GMX, отказ по политике с тем же текстом"),

    # ------------------------------------------------------- QQ / 163 / Naver --
    (550, b"Mailbox not found. https://service.mail.qq.com/detail/122/168",
     DEAD, "QQ, ящик не найден"),
    (550, b"MI:DMC http://mail.163.com/help/help_spam_16.htm?ip=1.2.3.4",
     NOTOLD, "163.com, отказ по нашему IP без слов о ящике"),
    (550, b"5.1.1 Invalid recipient", DEAD, "Naver, неверный получатель"),

    # ------------------------------------------------------------- Postfix --
    (550, b"5.1.1 <x@example.com>: Recipient address rejected: User unknown in "
          b"local recipient table", DEAD, "Postfix, локальная таблица"),
    (550, b"5.1.1 <x@example.com>: Recipient address rejected: User unknown in "
          b"relay recipient table", DEAD, "Postfix, релейная таблица"),
    (554, b"5.7.1 <x@example.com>: Relay access denied",
     NOTOLD, "Postfix, релей запрещён — про ящик молчит"),
    (553, b"5.7.1 <spoofed@example.com>: Sender address rejected: not owned by "
          b"user", NOTOLD, "Postfix, отвергнут ОТПРАВИТЕЛЬ"),
    (450, b"4.7.1 <x@example.com>: Recipient address rejected: Greylisted, see "
          b"http://postgrey.schweikert.ch/help/example.com.html",
     NOTOLD, "Postfix greylisting"),
    (450, b"4.2.0 <x@example.com>: Recipient address rejected: Temporary lookup "
          b"failure", NOTOLD, "Postfix, временный сбой поиска"),

    # ---------------------------------------------------------------- Exim --
    (550, b"Unrouteable address", DEAD, "Exim, адрес не маршрутизируется"),
    (550, b"Unknown user", DEAD, "Exim, неизвестный пользователь"),
    (451, b"Temporary local problem - please try later",
     NOTOLD, "Exim, временная локальная проблема"),
    (550, b"Administrative prohibition", NOTOLD, "Exim, запрет администратора"),

    # ------------------------------------------------------------ Exchange --
    (550, b"5.1.1 RESOLVER.ADR.ExRecipNotFound; not found",
     DEAD, "Exchange локальный, получатель не найден"),
    (550, b"5.2.1 RESOLVER.RST.NotAuthorized; not authorized",
     NOTOLD, "Exchange, не авторизован"),
    (552, b"5.2.2 <x@example.com> ... Mailbox full", ALIVE, "Exchange, ящик полон"),

    # ------------------------------------------------------------- qmail ---
    (550, b"sorry, no mailbox here by that name (#5.1.1)",
     DEAD, "qmail, нет такого ящика"),
    (451, b"qq temporary problem (#4.3.0)", NOTOLD, "qmail, временная проблема"),

    # --------------------------------------------- шлюзы и прочие ловушки --
    (550, b"5.7.1 Message rejected due to content restrictions",
     NOTOLD, "Proofpoint, отказ по содержимому"),
    (452, b"4.3.1 Insufficient system storage",
     NOTOLD, "На СЕРВЕРЕ кончилось место — про ящик не сказано"),
    (452, b"4.5.3 local error in processing, server overloaded",
     NOTOLD, "Перегруженный сервер: слово over не делает ящик живым"),
    (552, b"5.3.4 Message size exceeds fixed maximum message size",
     NOTOLD, "Ограничение на размер письма, не на ящик"),
    (551, b"User not local; please try <x@other.example.com>",
     NOTOLD, "Ящик существует, но на другом сервере"),
    (251, b"User not local; will forward to <x@other.example.com>",
     ALIVE, "Письмо будет переслано — адрес доставляем"),
    (550, b"5.2.1 The user's mailbox is temporarily unavailable, try again later",
     NOTOLD, "Постоянный код с временным текстом"),
    (500, b"5.5.1 Command unrecognized: \"RCPT TO:<x@example.com>\"",
     NOTOLD, "Сервер не понял команду"),
    (521, b"5.2.1 example.com does not accept mail",
     NOTOLD, "Домен вообще не принимает почту"),
    (530, b"5.7.0 Authentication required", NOTOLD, "Нужна авторизация"),
    (571, b"5.7.1 Delivery not authorized, message refused",
     NOTOLD, "Доставка не разрешена — блок по IP"),
    (550, b"Rejected", NOTOLD, "Голый отказ без объяснения"),
    (550, b"", NOTOLD, "Пустой ответ"),
    (554, b"5.7.1 Your access to this mail system has been rejected due to the "
          b"sending MTA's poor reputation", NOTOLD, "Отказ по репутации MTA"),
]


class TestSMTPCorpus(unittest.TestCase):
    """Ни одна строка корпуса не имеет права получить запрещённый ей вердикт."""

    def test_dead_addresses_are_buried(self):
        """Настоящие отскоки обязаны становиться invalid.

        Пропущенный invalid не теряет контакт, но и не защищает: письмо
        уйдёт в мёртвый ящик, вернётся отскоком и испортит репутацию.
        """
        for code, message, kind, source in CORPUS:
            if kind != DEAD:
                continue
            with self.subTest(source=source):
                verdict = classify_smtp_response(code, message)
                self.assertEqual(
                    verdict["status"], "invalid",
                    f"{source}: {code} {message[:70]!r} -> {verdict}")

    def test_alive_addresses_are_kept(self):
        for code, message, kind, source in CORPUS:
            if kind != ALIVE:
                continue
            with self.subTest(source=source):
                verdict = classify_smtp_response(code, message)
                self.assertEqual(
                    verdict["status"], "valid",
                    f"{source}: {code} {message[:70]!r} -> {verdict}")

    def test_silence_is_never_a_verdict(self):
        """Главный инвариант: молчание сервера о ящике — не приговор и не помилование."""
        for code, message, kind, source in CORPUS:
            if kind != NOTOLD:
                continue
            with self.subTest(source=source):
                verdict = classify_smtp_response(code, message)
                self.assertNotIn(
                    verdict["status"], ("invalid", "valid"),
                    f"{source}: {code} {message[:70]!r} -> {verdict}")

    def test_every_line_gets_a_known_status(self):
        allowed = {"valid", "invalid", "risky", "unknown", "greylisted"}
        for code, message, _kind, source in CORPUS:
            with self.subTest(source=source):
                self.assertIn(classify_smtp_response(code, message)["status"], allowed)


class TestEnhancedStatusParsing(unittest.TestCase):
    """Расширенный код читается как доказательство, значит его разбор обязан быть точным."""

    def test_reads_the_status_not_the_version(self):
        # Версия软 в баннере не должна читаться как статус состояния
        self.assertIsNone(enhanced_status("esmtp sendmail 8.14.7/8.14.7"))

    def test_reads_multi_digit_detail(self):
        self.assertEqual(enhanced_status("5.1.10 recipient not found"), (5, 1, 10))

    def test_reads_after_the_numeric_code(self):
        self.assertEqual(enhanced_status("550 5.1.1 user unknown"), (5, 1, 1))

    def test_reads_multiline_continuation(self):
        self.assertEqual(enhanced_status("550-5.7.1 blocked\n550 5.7.1 see docs"), (5, 7, 1))

    def test_ignores_impossible_class(self):
        self.assertIsNone(enhanced_status("9.9.9 nonsense"))

    def test_none_for_absent_status(self):
        self.assertIsNone(enhanced_status("mailbox unavailable"))


class TestNoFalseValidFromSubstrings(unittest.TestCase):
    """Подстрока не имеет права делать ящик живым.

    Это отрицательная проверка, поэтому рядом стоит положительный контроль:
    настоящая формулировка про переполнение обязана по-прежнему давать valid.
    Без контроля «ничего не совпало» неотличимо от «проверка сломана».
    """

    TRAPS = [
        (452, b"4.5.3 server overloaded, try later"),
        (452, b"4.7.1 you have sent over the allowed number of messages"),
        (552, b"5.7.0 content rejected: message contains a discovery link"),
        (450, b"4.3.2 system not accepting network messages, handover in progress"),
        (552, b"5.3.4 message too large"),
    ]

    POSITIVE_CONTROL = [
        (452, b"4.2.2 mailbox is full"),
        (552, b"5.2.2 over quota"),
        (452, b"4.2.2 The email account that you tried to reach is over quota"),
    ]

    def test_traps_do_not_produce_valid(self):
        for code, message in self.TRAPS:
            with self.subTest(message=message):
                self.assertNotEqual(
                    classify_smtp_response(code, message)["status"], "valid")

    def test_positive_control_still_produces_valid(self):
        for code, message in self.POSITIVE_CONTROL:
            with self.subTest(message=message):
                self.assertEqual(
                    classify_smtp_response(code, message)["status"], "valid")


class TestMalformedInput(unittest.TestCase):
    """Мусор на входе не должен ни падать, ни превращаться в вердикт."""

    def test_garbage_codes(self):
        for code in (None, "", "abc", -1, 0, 999, 3.7, [], {}):
            with self.subTest(code=code):
                verdict = classify_smtp_response(code, b"whatever")
                self.assertIn(verdict["status"], {"valid", "invalid", "risky",
                                                  "unknown", "greylisted"})
                self.assertNotEqual(verdict["status"], "invalid")

    def test_garbage_messages(self):
        for message in (None, b"", "", b"\xff\xfe\x00binary", 12345, [], {"a": 1}):
            with self.subTest(message=message):
                verdict = classify_smtp_response(550, message)
                self.assertIn(verdict["status"], {"valid", "invalid", "risky",
                                                  "unknown", "greylisted"})


if __name__ == "__main__":
    unittest.main()
