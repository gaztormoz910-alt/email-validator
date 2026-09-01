"""Три источника ложных вердиктов, закрытые в leaf-1.1.

Проверяется ПОВЕДЕНИЕ на подставном SMTP-сервере, а не наличие строк в коде.
Каждый тест начинается с негативного контроля: сначала показываем, что при
«честном» сервере вердикт прежний, и только потом — что при лгущем он меняется.
Без этого зелёный тест не отличить от теста, который проходит всегда.
"""

import sys
import os
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network import NetworkValidator


class FakeSMTP:
    """Подставной SMTP-сервер: отвечает по сценарию, считает команды.

    Сценарий RCPT задаётся списком (код, текст) по порядку обращений, чтобы
    можно было отличить ответ реальному адресу от ответа контрольному.
    """

    def __init__(self, rcpt_script, mail_code=250, banner=b"220 fake ESMTP"):
        self.rcpt_script = list(rcpt_script)
        self.mail_code = mail_code
        self.banner = banner
        self.rcpt_calls = []
        self.connects = 0
        self.quits = 0

    def connect(self, host, port):
        self.connects += 1
        return (220, self.banner)

    def ehlo(self, name=None):
        return (250, b"fake hello")

    def helo(self, name=None):
        return (250, b"fake hello")

    def has_extn(self, name):
        return False

    def mail(self, addr, options=None):
        # Подпись как у smtplib.SMTP.mail: options нужен для SMTPUTF8.
        self.mail_options = list(options or [])
        return (self.mail_code, b"250 sender ok")

    def rcpt(self, addr):
        self.rcpt_calls.append(addr)
        if self.rcpt_script:
            return self.rcpt_script.pop(0)
        return (250, b"250 OK")

    def quit(self):
        self.quits += 1


def validator_with(server):
    """Валидатор, у которого каждое SMTP-соединение — это переданный сервер."""
    v = NetworkValidator(timeout=1)
    v._make_smtp_connection = lambda proxy=None: server
    v._mx_delay = lambda mx: 0        # тесты не должны ждать реальных пауз
    return v


class TestControlRcpt(unittest.TestCase):
    """S1: контрольный RCPT в той же сессии ловит скрытый catch-all."""

    def test_control_rcpt_marks_catchall_when_fake_address_also_accepted(self):
        # Сервер принимает ВСЁ: и реальный адрес, и выдуманный
        server = FakeSMTP([(250, b"250 OK"), (250, b"250 OK")])
        v = validator_with(server)

        res = v._do_single_ping("real@corp-x.com", "mx.corp-x.com",
                                control_probe=True)

        self.assertEqual(res["status"], "catchall",
                         "сервер принял выдуманный адрес, но домен не помечен catch-all")
        self.assertEqual(len(server.rcpt_calls), 2,
                         "контрольный RCPT не отправлен")
        self.assertEqual(server.connects, 1,
                         "контрольная проба стоила лишнего подключения — она обязана "
                         "идти в той же сессии")
        self.assertTrue(v.catchall_cache.get("corp-x.com"),
                        "вывод о catch-all не сохранён для домена")

    def test_control_rcpt_confirms_real_mailbox_when_fake_rejected(self):
        # Негативный контроль: честный сервер отвергает выдуманный адрес
        server = FakeSMTP([(250, b"250 OK"), (550, b"550 no such user")])
        v = validator_with(server)

        res = v._do_single_ping("real@corp-x.com", "mx.corp-x.com",
                                control_probe=True)

        self.assertEqual(res["status"], "valid",
                         "честный сервер — вердикт обязан остаться Valid")
        self.assertEqual(res.get("control_rcpt"), "rejected")
        self.assertIs(v.catchall_cache.get("corp-x.com"), False)

    def test_control_rcpt_is_off_by_default(self):
        # Без флага лишних команд быть не должно — иначе вырастет нагрузка
        server = FakeSMTP([(250, b"250 OK")])
        v = validator_with(server)

        res = v._do_single_ping("real@corp-x.com", "mx.corp-x.com")

        self.assertEqual(res["status"], "valid")
        self.assertEqual(len(server.rcpt_calls), 1,
                         "контрольный RCPT отправлен без запроса")

    def test_control_rcpt_skipped_when_real_address_rejected(self):
        # Реальный адрес отвергнут — спрашивать выдуманный незачем
        server = FakeSMTP([(550, b"550 no such user")])
        v = validator_with(server)

        res = v._do_single_ping("dead@corp-x.com", "mx.corp-x.com",
                                control_probe=True)

        self.assertEqual(res["status"], "invalid")
        self.assertEqual(len(server.rcpt_calls), 1,
                         "контрольный RCPT потрачен на заведомо мёртвый адрес")


class TestNarrowInvalid(unittest.TestCase):
    """S2: временный отказ больше не читается как отсутствующий ящик."""

    def setUp(self):
        self.v = NetworkValidator(timeout=1)
        self.parse = self.v._parse_smtp_response

    def test_narrow_invalid_keeps_burying_real_bounces(self):
        # Негативный контроль: настоящие отказы обязаны остаться invalid
        decisive = [
            b"5.1.1 User unknown",
            b"550 No such user here",
            b"550 5.1.1 The email account that you tried to reach does not exist",
            b"550 Requested action not taken: mailbox unavailable",
            b"550 invalid recipient",
            b"550 recipient rejected",
        ]
        for msg in decisive:
            with self.subTest(msg=msg):
                res = self.parse(550, msg, "a@b.com", "b.com")
                self.assertEqual(res["status"], "invalid",
                                 f"настоящий отскок перестал быть invalid: {msg!r}")

    def test_narrow_invalid_spares_temporary_wording(self):
        # 550 с временной формулировкой противоречит сам себе — не хороним
        transient = [
            b"550 5.2.1 The mailbox is temporarily unavailable",
            b"550 mailbox busy, try again later",
            b"550 4.2.1 recipient deferred, retry later",
            b"550 user account is not available at this time",
            b"550 too busy to accept mail for this recipient",
        ]
        for msg in transient:
            with self.subTest(msg=msg):
                res = self.parse(550, msg, "a@b.com", "b.com")
                self.assertNotEqual(
                    res["status"], "invalid",
                    f"временный отказ похоронен как мёртвый ящик: {msg!r}")

    def test_narrow_invalid_spares_recipient_word_without_negation(self):
        # Слово о получателе без отрицания ничего не доказывает
        vague = [
            b"550 recipient",
            b"550 mailbox",
            b"550 address policy",
        ]
        for msg in vague:
            with self.subTest(msg=msg):
                res = self.parse(550, msg, "a@b.com", "b.com")
                self.assertNotEqual(res["status"], "invalid",
                                    f"упоминание получателя без отрицания "
                                    f"похоронило адрес: {msg!r}")

    def test_narrow_invalid_does_not_touch_other_codes(self):
        # Соседние ветки разбора не должны поехать
        self.assertEqual(self.parse(250, b"OK", "a@b.com", "b.com")["status"], "valid")
        self.assertEqual(self.parse(452, b"mailbox full", "a@b.com", "b.com")["status"],
                         "valid")
        self.assertEqual(self.parse(452, b"insufficient system storage",
                                    "a@b.com", "b.com")["status"], "unknown")
        # 551 — «User not local; please try <forward-path>». Сервер говорит
        # «этот ящик не у меня», а не «этого ящика нет»: RFC 5321 §3.4 ровно
        # для того и завёл код, чтобы указать НА ДРУГОЙ сервер. Раньше здесь
        # стоял приговор, и он хоронил живые адреса на доменах с раздельной
        # маршрутизацией (почта уехала к другому провайдеру, старый MX ещё
        # отвечает). Доказательства отсутствия ящика в 551 нет, поэтому risky.
        self.assertEqual(self.parse(551, b"user not local", "a@b.com", "b.com")["status"],
                         "risky")


class TestPostmasterTrust(unittest.TestCase):
    """S3: сервер, отвергающий postmaster@, теряет право хоронить адрес."""

    def test_postmaster_honored_returns_true_when_accepted(self):
        v = NetworkValidator(timeout=1)
        v._probe_recipients = lambda addrs, mx, proxy=None, from_email=None: [
            {"status": "valid", "reason": "250 OK"}]
        self.assertIs(v.postmaster_is_honored("corp-x.com", "mx.corp-x.com"), True)

    def test_postmaster_honored_returns_false_when_rejected(self):
        v = NetworkValidator(timeout=1)
        v._probe_recipients = lambda addrs, mx, proxy=None, from_email=None: [
            {"status": "invalid", "reason": "550 no such user"}]
        self.assertIs(v.postmaster_is_honored("corp-x.com", "mx.corp-x.com"), False)

    def test_postmaster_unknown_is_not_cached(self):
        """Сбой не должен навсегда лишить домен проверки."""
        calls = []

        def probe(addrs, mx, proxy=None, from_email=None):
            calls.append(addrs)
            return [{"status": "unknown", "reason": "Timeout"}]

        v = NetworkValidator(timeout=1)
        v._probe_recipients = probe
        self.assertIsNone(v.postmaster_is_honored("corp-x.com", "mx.corp-x.com"))
        self.assertIsNone(v.postmaster_is_honored("corp-x.com", "mx.corp-x.com"))
        self.assertEqual(len(calls), 2, "неудачная проба закэширована")

    def test_postmaster_result_is_cached_once_decided(self):
        calls = []

        def probe(addrs, mx, proxy=None, from_email=None):
            calls.append(addrs)
            return [{"status": "invalid", "reason": "550"}]

        v = NetworkValidator(timeout=1)
        v._probe_recipients = probe
        v.postmaster_is_honored("corp-x.com", "mx.corp-x.com")
        v.postmaster_is_honored("corp-x.com", "mx.corp-x.com")
        self.assertEqual(len(calls), 1, "решённый вердикт спрашивается повторно")

    def test_postmaster_downgrades_invalid_to_risky_in_check_email(self):
        """Сквозная проверка: лгущий сервер больше не хоронит адрес."""
        v = NetworkValidator(timeout=1)
        v.get_mx_records = lambda d: ["mx.corp-x.com"]
        v.is_catch_all_domain = lambda d, mx: False
        v.stealth_smtp_ping = lambda e, mx, control_probe=False, **kwargs: {
            "status": "invalid", "reason": "550 User Does Not Exist"}

        # Негативный контроль: честный сервер — вердикт остаётся invalid
        v.postmaster_is_honored = lambda d, mx: True
        honest = v.check_email("ghost@corp-x.com")
        self.assertEqual(honest["status"], "invalid",
                         "у честного сервера вердикт invalid обязан сохраниться")

        # Лгущий сервер — вердикт обесценивается
        v2 = NetworkValidator(timeout=1)
        v2.get_mx_records = lambda d: ["mx.corp-x.com"]
        v2.is_catch_all_domain = lambda d, mx: False
        v2.stealth_smtp_ping = lambda e, mx, control_probe=False, **kwargs: {
            "status": "invalid", "reason": "550 User Does Not Exist"}
        v2.postmaster_is_honored = lambda d, mx: False
        lying = v2.check_email("ghost@corp-x.com")
        self.assertEqual(lying["status"], "risky",
                         "сервер, отвергающий postmaster@, всё ещё хоронит адрес")
        self.assertIs(lying.get("postmaster_honored"), False)

    def test_postmaster_not_probed_for_live_addresses(self):
        """Лишняя сессия на домен не тратится там, где вердикт и так не invalid."""
        probed = []
        v = NetworkValidator(timeout=1)
        v.get_mx_records = lambda d: ["mx.corp-x.com"]
        v.is_catch_all_domain = lambda d, mx: False
        v.stealth_smtp_ping = lambda e, mx, control_probe=False, **kwargs: {
            "status": "valid", "reason": "250 OK"}
        v.check_dns_health = lambda d, mx_record="": {"score": 0}
        v.postmaster_is_honored = lambda d, mx: probed.append(d) or True

        v.check_email("live@corp-x.com")
        self.assertEqual(probed, [], "postmaster спрошен там, где никого не хоронят")


class TestCheckEmailAsksForTheControlProbe(unittest.TestCase):
    """check_email обязан ЗАКАЗЫВАТЬ контрольную пробу там, где она нужна.

    Дыра, которую это закрывает, тихая. Тройная проба на catch-all при сбое
    (мёртвый прокси, таймаут) возвращает False — «не catch-all», — потому что
    другого способа сказать «не знаю» у неё нет. Дальше обычный пинг получает
    250 на настоящий адрес, и без контрольной пробы это уехало бы в Valid на
    домене, который принимает вообще всё. Ровно тот ложный Valid, ради
    которого потом приходит отскок.

    Контрольная проба стоит одной команды RCPT в уже открытой сессии, но
    заказывается она НЕ везде: гиганты вроде gmail.com catch-all быть не
    могут, и тратить её там незачем. Проверяется и то, и другое.
    """

    def _validator(self, seen):
        from core.network import NetworkValidator

        validator = NetworkValidator(proxies=[])
        validator.get_mx_records = lambda domain: ["mx.example.com"]
        validator.is_catch_all_domain = lambda domain, mx: False
        validator.check_dns_health = lambda domain, mx_record="": {"score": 0}

        def ping(email, mx_records, control_probe=False, **kwargs):
            seen.append(control_probe)
            return {"status": "valid", "reason": "250 OK"}

        validator.stealth_smtp_ping = ping
        return validator

    def test_ordinary_domain_gets_the_control_probe(self):
        seen = []
        self._validator(seen).check_email("someone@corp-example.com")
        self.assertEqual(seen, [True],
                         "контрольная проба не заказана: сорвавшаяся проверка "
                         "catch-all выдаст ложный Valid")

    def test_giants_pay_for_it_rarely_but_do_pay(self):
        """У гигантов контроль идёт изредка — и это сознательная смена решения.

        Раньше здесь стояло «гиганты не платят»: Gmail и Яндекс catch-all не
        бывают. Соображение верно ровно до тех пор, пока наш исходящий адрес
        чист. Столкнувшись с перебором адресов с подозрительного IP, крупные
        почтовики перестают отвечать честно и принимают ЛЮБОГО получателя —
        так они не дают выяснить, какие ящики существуют. Тогда вся база
        уезжает в «Годен», и узнаётся это по отскокам после рассылки.

        Поэтому контроль включён и у них, но не на каждом адресе: первый —
        обязательно, дальше изредка.
        """
        for domain in ("gmail.com", "yandex.ru", "icloud.com"):
            with self.subTest(domain=domain):
                validator = self._validator([])
                seen = []

                def ping(email, mx_records, control_probe=False, **kwargs):
                    seen.append(control_probe)
                    return {"status": "valid", "reason": "250 OK"}

                validator.stealth_smtp_ping = ping
                for _ in range(30):
                    validator.check_email(f"someone@{domain}")

                self.assertTrue(seen[0],
                                "первая проверка домена обязана быть "
                                "контрольной: сервер мог тарпитить уже сейчас")
                paid = sum(1 for value in seen if value)
                self.assertLessEqual(paid, 3,
                                     "контроль у гиганта не должен идти на "
                                     "каждом адресе — это лишние RCPT")
                self.assertGreaterEqual(paid, 1)


if __name__ == "__main__":
    unittest.main()


class TestSecondMx(unittest.TestCase):
    """P17: приговор «ящика нет» сверяется со вторым сервером домена.

    Почему это важно именно для invalid. У домена бывает несколько MX, и они
    не всегда знают одно и то же: запасной узел часто отвечает 550 на всё
    подряд, потому что списка ящиков у него нет. Приговор такого сервера
    выбрасывает живой контакт навсегда, а это самая дорогая ошибка валидатора.
    """

    def _validator(self, answers):
        """answers: {mx_host: status} — что «ответит» каждый сервер."""
        v = NetworkValidator(timeout=1)
        asked = []

        def fake_ping(email, mx_record, proxy=None, from_email=None,
                      control_probe=False):
            asked.append(mx_record)
            return {"status": answers.get(mx_record, "unknown"), "reason": "тест"}

        v._do_single_ping = fake_ping
        v._pick_best_proxy = lambda **kw: None
        return v, asked

    def test_second_mx_confirms_the_bounce(self):
        """Оба сервера отвергли — приговор в силе."""
        v, asked = self._validator({"mx1": "invalid", "mx2": "invalid"})
        result = v.stealth_smtp_ping("a@b.com", ["mx1", "mx2"])
        self.assertEqual(result["status"], "invalid")
        self.assertIn("mx2", asked, "второй сервер вообще не спрашивали")

    def test_second_mx_disagreement_saves_the_address(self):
        """Второй сервер принял адрес — хоронить нельзя."""
        v, asked = self._validator({"mx1": "invalid", "mx2": "valid"})
        result = v.stealth_smtp_ping("a@b.com", ["mx1", "mx2"])
        self.assertEqual(result["status"], "risky",
                         "серверы разошлись, а адрес всё равно похоронен")
        # Формулировка переписана вместе с расширением проверки: второе
        # мнение теперь спрашивается не только у другого MX, но и с другого
        # выходного IP, и «серверы домена ответили по-разному» перестало быть
        # правдой для домена с единственным MX. Требование то же: причина
        # должна называть РАСХОЖДЕНИЕ, а не прятать его за словом «risky».
        self.assertIn("противоречит", result["reason"])
        self.assertIn("может существовать", result["reason"])

    def test_second_mx_silence_leaves_the_verdict(self):
        """Молчание второго сервера — не несогласие."""
        v, _ = self._validator({"mx1": "invalid", "mx2": "unknown"})
        result = v.stealth_smtp_ping("a@b.com", ["mx1", "mx2"])
        self.assertEqual(result["status"], "invalid",
                         "молчание второго сервера принято за оправдание")

    def test_second_mx_single_server_domain_is_unchanged(self):
        """Негативный контроль: сверять не с чем — поведение прежнее."""
        v, asked = self._validator({"mx1": "invalid"})
        result = v.stealth_smtp_ping("a@b.com", ["mx1"])
        self.assertEqual(result["status"], "invalid")
        self.assertEqual(asked.count("mx1"), 1,
                         "на домене с одним MX сделан лишний запрос")

    def test_second_mx_costs_nothing_for_live_mailboxes(self):
        """На valid лишний запрос не тратится вовсе."""
        v, asked = self._validator({"mx1": "valid", "mx2": "valid"})
        result = v.stealth_smtp_ping("a@b.com", ["mx1", "mx2"])
        self.assertEqual(result["status"], "valid")
        self.assertNotIn("mx2", asked,
                         "подтверждённый живой ящик потянул за собой лишнее "
                         "подключение ко второму серверу")
