# -*- coding: utf-8 -*-
"""DNS через прокси: вторая дорожка (вариант В, 29.09.2026).

Раньше все шесть попыток вопроса (две DoH и четыре обычные справочные) шли
через один прокси. Умер он — каждая ждала полный таймаут: 30 с на вопрос при
таймауте 5 с, 90 с при 15 с (замер 29.09.2026). Теперь прежняя дорожка
остаётся как была и где была (в потоке вызывающего), а после ожидания
впустую параллельно открывается вторая — через другие прокси. Что сторожат
эти тесты:

  1. Мёртвый первый прокси стоит два ожидания (следующие вопросы — одно), а
     не шесть.
  2. Ответ, который находила прежняя дорожка, не теряется: разовая заминка
     первого прокси, молчащий у него DoH при живом TCP, единственный прокси.
  3. Быстрый отказ прокси вторую дорожку не открывает; прокси, отказавший и
     по DoH, и по обычному DNS, — открывает.
  4. При целиком мёртвом пуле вопрос не дольше прежнего потолка, а прежняя
     дорожка делает ровно свои шесть попыток.
  5. Ни одного соединения не на 127.0.0.1: вопрос через прокси не уходит
     напрямую ни при каком ответе провайдера, ни при нераспознанной строке
     прокси, ни при заданной переменной HTTPS_PROXY.
  6. Память о молчании открывает вторую дорожку сразу, держит две минуты и
     НЕ уводит первый выбор с лучшего прокси.
  7. Ответ второй дорожки не перебивает ответ прежней: берутся только
     положительные ответы и заверенное DoH «нет такой записи»; подменённое
     «домена нет» по обычному DNS через чужой прокси и SERVFAIL — нет.
  8. Под нагрузкой (300 вызывающих, как по умолчанию в окне) прежняя
     дорожка не встаёт в очередь и не опаздывает.

Прокси поддельные, на 127.0.0.1: сеть наружу не нужна, и каждый вид сбоя
задан точно, а не зависит от того, какие бесплатные прокси живы сегодня.
Три независимых рецензента нашли в первой редакции (просто «перейти на
другой прокси») потерю ответа в сценариях из п. 2 — они здесь закреплены.
"""
import gc
import os
import socket
import struct
import sys
import threading
import time
import unittest
import weakref
from unittest import mock

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import dns.exception
import dns.message
import dns.rcode
import dns.resolver
import dns.rrset
import requests
import socks
import urllib3

from core import dns_resolver
from core.dns_resolver import (DNS_SILENCE_COOLDOWN_SEC, DNSUnavailable,
                               ProxiedResolver, _waited_in_vain)
from core.network import NetworkValidator

ОТВЕТ = "192.0.2.7"
СПРАВОЧНЫЕ = ["8.8.8.8", "1.1.1.1", "8.8.4.4", "1.0.0.1"]
# Две DoH + четыре обычные справочные: столько попыток у прежней дорожки.
ПОПЫТОК = 2 + len(СПРАВОЧНЫЕ)
# Таймаут 1 с, а не 0.5: пороги времени здесь различают «было лишнее
# ожидание» и «не было», а ожидание стоит таймаут целиком. Кроме ожиданий,
# каждая попытка стоит и постоянную цену машины: здесь ~15 мс, на Windows в
# GitHub Actions 30.09.2026 — ~0.15 с (три попытки без единого ожидания
# шли 0.45 с). При 0.5 с эта цена съедала запас порогов, и тесты падали на
# медленной машине, не найдя ни одного лишнего ожидания.
ТАЙМАУТ = 1.0
КОРОТКИЙ = 0.2


def _прочесть(conn, n):
    данные = b""
    while len(данные) < n:
        кусок = conn.recv(n - len(данные))
        if not кусок:
            raise EOFError
        данные += кусок
    return данные


class ПоддельныйПрокси:
    """SOCKS5-прокси на 127.0.0.1 с заданным поведением.

    режим "молчит"     — принимает соединение и не отвечает ни байта:
                          так выглядит умерший прокси с ещё открытым портом.
    режим "справочная" — соединяет. На порт 53 — по на_53: "ответ" (сам
                          отвечает как DNS-сервер A-записью ОТВЕТ), "отказ"
                          (SOCKS 0x05), "молчать" (туннель есть, ответа нет).
                          На прочие порты (DoH идёт на 443) — по на_443:
                          "закрыть" (быстрый обрыв), "отказ", "молчать".
    первые_молчат=k    — первые k соединений молчат при любом режиме:
                          разовая заминка живого прокси.
    """

    def __init__(self, режим, на_443="закрыть", на_53="ответ", первые_молчат=0):
        self.режим = режим
        self.на_443 = на_443
        self.на_53 = на_53
        self.первые_молчат = первые_молчат
        self.соединений = 0
        self.порты = []
        self._замок = threading.Lock()
        self._стоп = threading.Event()
        self._сокет = socket.socket()
        self._сокет.bind(("127.0.0.1", 0))
        self._сокет.listen(64)
        # accept с таймаутом: на Linux close() из другого потока не будит
        # блокирующий accept, и поток висел бы до конца процесса.
        self._сокет.settimeout(0.2)
        self.адрес = "socks5://127.0.0.1:%d" % self._сокет.getsockname()[1]
        threading.Thread(target=self._принимать, daemon=True).start()

    def закрыть(self):
        self._стоп.set()
        try:
            self._сокет.close()
        except OSError:
            pass

    def _принимать(self):
        while not self._стоп.is_set():
            try:
                conn, _ = self._сокет.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with self._замок:
                self.соединений += 1
                номер = self.соединений
            threading.Thread(target=self._обслужить, args=(conn, номер), daemon=True).start()

    def _обслужить(self, conn, номер):
        try:
            conn.settimeout(10)
            if self.режим == "молчит" or номер <= self.первые_молчат:
                self._стоп.wait(10)
                return
            порт = self._рукопожатие(conn)
            with self._замок:
                self.порты.append(порт)
            поведение = self.на_53 if порт == 53 else self.на_443
            if поведение == "отказ":
                conn.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
                return
            conn.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
            if поведение == "молчать":
                self._стоп.wait(10)
                return
            if порт != 53 or поведение != "ответ":
                return
            длина = struct.unpack(">H", _прочесть(conn, 2))[0]
            вопрос = dns.message.from_wire(_прочесть(conn, длина))
            ответ = dns.message.make_response(вопрос)
            ответ.answer.append(dns.rrset.from_text(
                вопрос.question[0].name, 60, "IN", "A", ОТВЕТ))
            wire = ответ.to_wire()
            conn.sendall(struct.pack(">H", len(wire)) + wire)
        except (OSError, EOFError, ValueError, dns.exception.DNSException):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _рукопожатие(conn):
        """Приветствие и CONNECT по RFC 1928; возвращает запрошенный порт."""
        _, методов = _прочесть(conn, 2)
        _прочесть(conn, методов)
        conn.sendall(b"\x05\x00")
        _, _, _, тип = _прочесть(conn, 4)
        if тип == 1:
            _прочесть(conn, 4)
        elif тип == 3:
            _прочесть(conn, _прочесть(conn, 1)[0])
        elif тип == 4:
            _прочесть(conn, 16)
        return struct.unpack(">H", _прочесть(conn, 2))[0]


class Пул:
    """Провайдер прокси с детерминированным порядком: первый не исключённый."""

    def __init__(self, *адреса):
        self.порядок = list(адреса)
        self.вызовы = []

    def __call__(self, exclude=()):
        self.вызовы.append(frozenset(exclude))
        for адрес in self.порядок:
            if адрес not in exclude:
                return адрес
        return ""


_НАСТОЯЩИЙ_CONNECT = socket.socket.connect
_НАСТОЯЩИЙ_CONNECT_EX = socket.socket.connect_ex


class Основа(unittest.TestCase):
    """Поддельные прокси и запрет соединений куда-либо, кроме 127.0.0.1.

    Запрет — главный сторож утечки: подмена одного лишь _plain.resolve не
    видит вопрос, ушедший напрямую через DoH-сессию без прокси.
    """

    def setUp(self):
        self._прокси = []
        self.нарушения = []
        нарушения = self.нарушения

        def проверить(адрес):
            хост = адрес[0] if isinstance(адрес, tuple) else адрес
            if хост not in ("127.0.0.1", "localhost"):
                нарушения.append(адрес)
                raise OSError("тест: соединение не на 127.0.0.1 запрещено: %r" % (адрес,))

        def connect(sock, адрес):
            проверить(адрес)
            return _НАСТОЯЩИЙ_CONNECT(sock, адрес)

        def connect_ex(sock, адрес):
            проверить(адрес)
            return _НАСТОЯЩИЙ_CONNECT_EX(sock, адрес)

        заплатки = [mock.patch.object(socket.socket, "connect", connect),
                    mock.patch.object(socket.socket, "connect_ex", connect_ex)]
        for заплатка in заплатки:
            заплатка.start()
            self.addCleanup(заплатка.stop)

    def tearDown(self):
        for прокси in self._прокси:
            прокси.закрыть()
        self.assertEqual(self.нарушения, [], "соединение мимо прокси")

    def прокси(self, режим, **поведение):
        прокси = ПоддельныйПрокси(режим, **поведение)
        self._прокси.append(прокси)
        return прокси

    @staticmethod
    def резолвер(провайдер, таймаут=ТАЙМАУТ):
        return ProxiedResolver(СПРАВОЧНЫЕ, timeout=таймаут, proxy_provider=провайдер)

    @staticmethod
    def спросить(резолвер):
        начало = time.monotonic()
        ответ = резолвер.resolve("example.com", "A")
        return [запись.to_text() for запись in ответ], time.monotonic() - начало

    @staticmethod
    def дать_дожить():
        # Счётчики соединений ведут потоки поддельного прокси: даём им
        # дочитать очередь, иначе последнее соединение ещё не посчитано.
        time.sleep(0.3)


class TestВтораяДорожка(Основа):

    def test_мёртвый_первый_стоит_два_ожидания_а_не_шесть(self):
        # Главное, ради чего правка: раньше этот вопрос шесть раз ждал
        # мёртвый прокси и кончался отказом, хотя рядом был живой. Теперь:
        # первая попытка прождала — открылась вторая дорожка; вторая попытка
        # прежней (в том же потоке) досиживает свой таймаут, и на стыке
        # берётся ответ второй дорожки.
        мёртвый, живой = self.прокси("молчит"), self.прокси("справочная")
        ответ, прошло = self.спросить(self.резолвер(Пул(мёртвый.адрес, живой.адрес)))
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertLess(прошло, 2.6 * ТАЙМАУТ)

    def test_разовая_заминка_первого_не_теряет_ответ(self):
        # Первый прокси промолчал один раз, запасной мёртв. Первая редакция
        # уходила с первого навсегда и теряла ответ (рецензия, F1).
        заминка = self.прокси("справочная", первые_молчат=1)
        мёртвый = self.прокси("молчит")
        ответ, прошло = self.спросить(self.резолвер(Пул(заминка.адрес, мёртвый.адрес)))
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertLess(прошло, 2 * ТАЙМАУТ)

    def test_у_первого_молчит_doh_а_tcp_работает(self):
        # DoH через первый прокси молчит, обычный DNS отвечает, запасной
        # мёртв. Прежний код отвечал на третьей попытке — должен и новый.
        первый = self.прокси("справочная", на_443="молчать")
        мёртвый = self.прокси("молчит")
        # Мерка — тот же первый прокси в одиночку: запасного нет, вторая
        # дорожка не открывается, это ровно прежний путь. Абсолютный порог
        # (два таймаута + 0.3 с) заодно мерил скорость машины и упал на
        # Windows в GitHub Actions (1.44 с при пороге 1.3, 30.09.2026), хотя
        # лишнего ожидания не было: оно одно стоило бы 0.5 с сверх двух.
        _, как_раньше = self.спросить(self.резолвер(Пул(первый.адрес)))
        del первый.порты[:]
        ответ, прошло = self.спросить(self.резолвер(Пул(первый.адрес, мёртвый.адрес)))
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertEqual(первый.порты, [443, 443, 53], "прежняя дорожка изменилась")
        self.assertLess(прошло - как_раньше, ТАЙМАУТ / 2, "вторая дорожка задержала прежнюю")

    def test_единственный_прокси_как_раньше(self):
        один = self.прокси("справочная", на_443="молчать")
        ответ, прошло = self.спросить(self.резолвер(Пул(один.адрес)))
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertGreaterEqual(прошло, 1.5 * ТАЙМАУТ, "обе DoH-попытки должны были прождать")

    def test_быстрый_отказ_не_открывает_вторую(self):
        # Прокси ответил «не могу соединить» на DoH — значит, он жив.
        # Следующую справочную спрашиваем через него же, запасной не трогаем.
        отказывает = self.прокси("справочная", на_443="отказ")
        запасной = self.прокси("справочная")
        ответ, прошло = self.спросить(self.резолвер(Пул(отказывает.адрес, запасной.адрес)))
        self.assertEqual(ответ, [ОТВЕТ])
        self.дать_дожить()
        self.assertEqual(запасной.соединений, 0)
        self.assertLess(прошло, ТАЙМАУТ, "быстрый отказ не должен стоить таймаута")

    def test_отказавший_на_всё_во_второй_дорожке_меняется(self):
        # Живой замер 29.09.2026: после мёртвого прокси вопрос ушёл в прокси,
        # мгновенно отказывавший на всё, и потерял ответ, хотя рабочие были.
        мёртвый = self.прокси("молчит")
        сломанный = self.прокси("справочная", на_443="отказ", на_53="отказ")
        живой = self.прокси("справочная")
        ответ, прошло = self.спросить(self.резолвер(Пул(мёртвый.адрес, сломанный.адрес, живой.адрес)))
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertLess(прошло, 2.6 * ТАЙМАУТ)
        self.дать_дожить()
        self.assertEqual(сломанный.соединений, 2, "одна DoH и одна TCP — и хватит")

    def test_первый_отказал_на_всё_открывает_вторую(self):
        # Прежний код в этом случае ответа не получал вовсе.
        # Все отказы мгновенные, ждать нечего — таймаут 3 с тесту ничего не
        # стоит, а порог в полтаймаута отделяет «ни одного ожидания» от «было
        # ожидание» с запасом и на медленной машине (4–5 попыток по 0.25 с).
        т = 3.0
        сломанный = self.прокси("справочная", на_443="отказ", на_53="отказ")
        живой = self.прокси("справочная")
        ответ, прошло = self.спросить(self.резолвер(Пул(сломанный.адрес, живой.адрес), таймаут=т))
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertLess(прошло, т / 2, "было ожидание, хотя прокси отказывали сразу")

    def test_закрытый_порт_первого(self):
        # Прокси недостижим: на Linux отказ мгновенный, на Windows повторы SYN
        # обрезает таймаут. В обоих случаях — вторая дорожка и ответ.
        закрыт = socket.socket()
        закрыт.bind(("127.0.0.1", 0))
        порт = закрыт.getsockname()[1]
        закрыт.close()
        живой = self.прокси("справочная")
        р = self.резолвер(Пул("socks5://127.0.0.1:%d" % порт, живой.адрес), таймаут=КОРОТКИЙ)
        ответ, _ = self.спросить(р)
        self.assertEqual(ответ, [ОТВЕТ])

    def test_все_мертвы_не_дольше_потолка(self):
        # Весь пул мёртв. Прежняя дорожка делает свои шесть попыток через
        # первый прокси, вторая — не больше шести через другие; вопрос
        # кончается к прежнему потолку (6×таймаут), а не позже.
        мёртвые = [self.прокси("молчит") for _ in range(ПОПЫТОК + 2)]
        р = self.резолвер(Пул(*[м.адрес for м in мёртвые]), таймаут=КОРОТКИЙ)
        начало = time.monotonic()
        with self.assertRaises(DNSUnavailable):
            р.resolve("example.com", "A")
        прошло = time.monotonic() - начало
        self.дать_дожить()
        self.assertEqual(мёртвые[0].соединений, ПОПЫТОК, "прежняя дорожка изменилась")
        self.assertTrue(all(м.соединений <= 1 for м in мёртвые[1:]))
        self.assertLessEqual(sum(м.соединений for м in мёртвые[1:]), ПОПЫТОК)
        self.assertLess(прошло, ПОПЫТОК * КОРОТКИЙ + 1.0)


class TestНикогдаНапрямую(Основа):

    def test_провайдер_без_замены_не_отпускает_вопрос_мимо_прокси(self):
        # Провайдер на просьбу «кроме этих» отвечает None или "". Ни то ни
        # другое не разрешение идти напрямую: это раскрыло бы IP.
        for ответ_на_замену in (None, ""):
            with self.subTest(ответ_на_замену=ответ_на_замену):
                мёртвый = self.прокси("молчит")

                def провайдер(exclude=(), адрес=мёртвый.адрес, замена=ответ_на_замену):
                    return замена if exclude else адрес

                # Ответа здесь не ждём — таймаут минимальный, считаются попытки.
                р = self.резолвер(провайдер, таймаут=0.1)
                р._plain.resolve = lambda *a, **k: self.fail("ушли напрямую в обход прокси")
                for _ in range(2):   # второй вопрос открывает вторую дорожку сразу
                    with self.assertRaises(DNSUnavailable):
                        р.resolve("example.com", "A")
                self.дать_дожить()
                self.assertEqual(мёртвый.соединений, 2 * ПОПЫТОК)

    def test_провайдер_без_exclude_работает_по_старому(self):
        # Старый контракт провайдера (без параметра) не ломается: одна
        # дорожка, один прокси на весь вопрос, без TypeError.
        живой = self.прокси("справочная")
        ответ, _ = self.спросить(self.резолвер(lambda: живой.адрес))
        self.assertEqual(ответ, [ОТВЕТ])
        мёртвый = self.прокси("молчит")
        р = self.резолвер(lambda: мёртвый.адрес, таймаут=КОРОТКИЙ)
        with self.assertRaises(DNSUnavailable):
            р.resolve("example.com", "A")
        self.дать_дожить()
        self.assertEqual(мёртвый.соединений, ПОПЫТОК)

    def test_нераспознанная_строка_прокси_не_уходит_напрямую(self):
        # build_proxy_dict не разбирает строку — сессия DoH осталась бы без
        # прокси, и вопрос ушёл бы с домашнего IP (рецензия, F4).
        р = self.резолвер(lambda: "socks5h://198.51.100.9:1080")
        with self.assertRaises(DNSUnavailable):
            р.resolve("example.com", "A")

    def test_переменная_https_proxy_не_перехватывает_вопрос(self):
        # У requests переменная окружения главнее proxies сессии: DoH ушёл бы
        # не через прокси пула, а через чужой (рецензия, F5).
        чужой, живой = self.прокси("молчит"), self.прокси("справочная")
        адрес = чужой.адрес.replace("socks5://", "http://")
        среда = {k: v for k, v in os.environ.items() if k.lower() != "no_proxy"}
        среда.update({"HTTPS_PROXY": адрес, "https_proxy": адрес})
        with mock.patch.dict(os.environ, среда, clear=True):
            ответ, _ = self.спросить(self.резолвер(Пул(живой.адрес)))
        self.assertEqual(ответ, [ОТВЕТ])
        self.дать_дожить()
        self.assertEqual(чужой.соединений, 0)


class TestПамятьОМолчании(Основа):

    def test_после_молчания_следующий_вопрос_платит_одно_ожидание(self):
        # Второй вопрос того же домена (SPF после MX): вторая дорожка
        # открывается сразу, и ответ берётся на первом же стыке — одно
        # ожидание вместо двух. Таймаут 1 с: между «одно» и «два» запас 0.5 с.
        мёртвый, живой = self.прокси("молчит"), self.прокси("справочная")
        р = self.резолвер(Пул(мёртвый.адрес, живой.адрес), таймаут=1.0)
        self.спросить(р)
        ответ, прошло = self.спросить(р)
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertLess(прошло, 1.5)

    def test_память_держит_две_минуты(self):
        мёртвый, живой = self.прокси("молчит"), self.прокси("справочная")
        р = self.резолвер(Пул(мёртвый.адрес, живой.адрес))
        self.спросить(р)
        with р._silent_lock:
            осталось = р._silent[мёртвый.адрес] - time.monotonic()
        self.assertGreater(осталось, DNS_SILENCE_COOLDOWN_SEC - 10)
        self.assertGreaterEqual(DNS_SILENCE_COOLDOWN_SEC, 60)
        self.assertLessEqual(DNS_SILENCE_COOLDOWN_SEC, 600)

    def test_память_истекает(self):
        мёртвый, живой = self.прокси("молчит"), self.прокси("справочная")
        р = self.резолвер(Пул(мёртвый.адрес, живой.адрес), таймаут=1.0)
        self.спросить(р)
        with р._silent_lock:
            р._silent[мёртвый.адрес] = time.monotonic() - 1
        _, прошло = self.спросить(р)
        self.assertGreaterEqual(прошло, 1.5, "после выдержки вторая дорожка снова не сразу")

    def test_память_не_уводит_первый_выбор_с_лучшего(self):
        # Лучший прокси недавно промолчал, остальные мертвы. Первая редакция
        # на следующем вопросе начинала с «не молчавших» — то есть с мёртвых —
        # и теряла ответ (рецензия, F2). Первым должен остаться лучший:
        # память только открывает вторую дорожку сразу.
        #
        # Метка ставится руками. Живым путём её тут не получить: ответ через
        # лучший прокси метку снимает, а мёртвые ответа не дают. Прежняя
        # версия теста (метка от разовой заминки в первом вопросе) поэтому не
        # сторожила ничего — к второму вопросу метки уже не было, и возврат
        # F2 (мутация M25) проходил весь файл зелёным (проверено 30.09.2026).
        #
        # Таймаут 2 с: верный путь не ждёт ни разу (на Windows в GitHub
        # Actions три такие попытки шли 0.45 с), а уход на мёртвый стоил бы
        # ожидание целиком — между ними порог в секунду с запасом в обе
        # стороны. Самому тесту таймаут ничего не стоит: его никто не ждёт.
        т = 2.0
        лучший = self.прокси("справочная")
        мёртвые = [self.прокси("молчит") for _ in range(3)]
        р = self.резолвер(Пул(лучший.адрес, *[м.адрес for м in мёртвые]), таймаут=т)
        р._remember_silence(лучший.адрес)
        ответ, прошло = self.спросить(р)
        self.assertEqual(ответ, [ОТВЕТ])
        # Прежняя дорожка шла через лучший: две DoH (сразу оборваны) и TCP.
        self.assertEqual(лучший.порты, [443, 443, 53], "первым выбран не лучший")
        self.assertLess(прошло, т / 2, "было ожидание — значит, начали не с лучшего")

    def test_вторая_дорожка_обходит_недавно_молчавших(self):
        первый, помеченный, живой = (self.прокси("молчит"), self.прокси("молчит"),
                                     self.прокси("справочная"))
        р = self.резолвер(Пул(первый.адрес, помеченный.адрес, живой.адрес))
        р._remember_silence(помеченный.адрес)
        ответ, _ = self.спросить(р)
        self.assertEqual(ответ, [ОТВЕТ])
        self.дать_дожить()
        self.assertEqual(помеченный.соединений, 0)

    def test_ответ_снимает_метку_молчания(self):
        живой = self.прокси("справочная")
        р = self.резолвер(Пул(живой.адрес))
        р._remember_silence(живой.адрес)
        ответ, _ = self.спросить(р)
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertEqual(р._recently_silent(), frozenset())


class TestПотоки(Основа):

    def test_много_потоков_делят_мёртвый_прокси(self):
        мёртвый, живой = self.прокси("молчит"), self.прокси("справочная")
        р = self.резолвер(Пул(мёртвый.адрес, живой.адрес))
        ответы = []

        def спросить():
            ответы.append(self.спросить(р)[0])

        потоки = [threading.Thread(target=спросить) for _ in range(8)]
        начало = time.monotonic()
        for п in потоки:
            п.start()
        for п in потоки:
            п.join(10)
        self.assertEqual(ответы, [[ОТВЕТ]] * 8)
        self.assertLess(time.monotonic() - начало, 3 * ТАЙМАУТ)

    def test_две_задачи_разом_не_садятся_на_один_поток(self):
        # Иначе попытка второй дорожки ждала бы, пока прежняя досидит таймаут.
        полосы = dns_resolver._Lanes(8)
        начало = time.monotonic()
        задачи = [полосы.submit(time.sleep, 0.4) for _ in range(2)]
        for з in задачи:
            з.result(5)
        self.assertLess(time.monotonic() - начало, 0.75)


class TestПулПрокси(Основа):
    """Пул умеет «любой, кроме этих», и сеть валидатора этим пользуется."""

    A, B = "socks5://198.51.100.1:1080", "socks5://198.51.100.2:1080"

    def test_исключённый_не_выдаётся(self):
        v = NetworkValidator(timeout=2, proxies=[self.A, self.B])
        for _ in range(30):
            self.assertEqual(v._dns_proxy(exclude=frozenset({self.A})), self.B)

    def test_все_исключены_значит_пустая_строка_а_не_напрямую(self):
        v = NetworkValidator(timeout=2, proxies=[self.A, self.B])
        self.assertEqual(v._dns_proxy(exclude=frozenset({self.A, self.B})), "")

    def test_без_прокси_по_прежнему_напрямую(self):
        self.assertIsNone(NetworkValidator(timeout=2)._dns_proxy(exclude=frozenset({self.A})))
        v = NetworkValidator(timeout=2, proxies=[self.A], proxy_dns=False)
        self.assertIsNone(v._dns_proxy(exclude=frozenset({self.B})))

    def test_выбывший_не_возвращается_через_исключения(self):
        v = NetworkValidator(timeout=2, proxies=[self.A, self.B])
        v._proxy_banned.add(self.B)
        self.assertEqual(v._dns_proxy(exclude=frozenset({self.A})), "")

    def test_сквозной_с_настоящим_пулом_валидатора(self):
        # Не заглушка провайдера, а NetworkValidator._dns_proxy: мёртвый
        # прокси с высоким счётом (умер посреди прогона) первым.
        мёртвый, живой = self.прокси("молчит"), self.прокси("справочная")
        v = NetworkValidator(timeout=ТАЙМАУТ, proxies=[мёртвый.адрес, живой.адрес])
        v._proxy_scores[мёртвый.адрес] = 100
        self.assertTrue(v.resolver._provider_excludes)
        ответ, прошло = self.спросить(v.resolver)
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertLess(прошло, 2.6 * ТАЙМАУТ)


class TestЧтоСчитатьОжиданием(unittest.TestCase):
    """Вторая дорожка открывается сразу только после сбоя, стоившего таймаута."""

    def test_таймауты_и_недоступный_прокси(self):
        for ошибка in (TimeoutError(), dns.exception.Timeout(),
                       requests.exceptions.ReadTimeout(),
                       socks.ProxyConnectionError("нет связи", ConnectionRefusedError())):
            with self.subTest(ошибка=type(ошибка).__name__):
                self.assertTrue(_waited_in_vain(ошибка))

    def test_таймаут_в_глубине_цепочки(self):
        try:
            try:
                raise TimeoutError()
            except TimeoutError as причина:
                raise requests.exceptions.ConnectionError("обёртка") from причина
        except requests.exceptions.ConnectionError as обёртка:
            self.assertTrue(_waited_in_vain(обёртка))

    def test_быстрые_отказы_не_ожидание(self):
        for ошибка in (socks.GeneralProxyError("Socket error",
                                               socks.SOCKS5Error("0x05: Connection refused")),
                       ConnectionAbortedError(), ValueError("битый ответ"),
                       requests.exceptions.ConnectionError("обрыв")):
            with self.subTest(ошибка=type(ошибка).__name__):
                self.assertFalse(_waited_in_vain(ошибка))

    def test_отказ_соединения_urllib3_не_таймаут(self):
        # NewConnectionError в urllib3 2.x унаследован от ConnectTimeoutError,
        # хотя означает мгновенный отказ. Принять его за ожидание — открывать
        # вторую дорожку после каждого «не могу соединить».
        отказ = urllib3.exceptions.NewConnectionError(None, "Connection refused")
        self.assertFalse(_waited_in_vain(отказ))
        self.assertTrue(_waited_in_vain(urllib3.exceptions.ReadTimeoutError(None, "/", "таймаут")))

    def test_недостижимый_http_прокси_как_недостижимый_socks(self):
        # Рецензия, F2: для HTTP-прокси requests даёт ProxyError, внутри
        # которого не удалось само соединение. Это то же «не достучались».
        недостижим = requests.exceptions.ProxyError(urllib3.exceptions.MaxRetryError(
            None, "/", urllib3.exceptions.ProxyError(
                "Unable to connect to proxy",
                urllib3.exceptions.NewConnectionError(None, "Connection refused"))))
        self.assertTrue(_waited_in_vain(недостижим))
        # А ответ живого прокси (407 и т. п.) — это быстрый отказ.
        ответил = requests.exceptions.ProxyError(urllib3.exceptions.MaxRetryError(
            None, "/", urllib3.exceptions.ProxyError(
                "Unable to connect to proxy", OSError("Tunnel connection failed: 407"))))
        self.assertFalse(_waited_in_vain(ответил))

    def test_закрытый_порт_http_прокси_вживую(self):
        закрыт = socket.socket()
        закрыт.bind(("127.0.0.1", 0))
        порт = закрыт.getsockname()[1]
        закрыт.close()
        р = ProxiedResolver(СПРАВОЧНЫЕ, timeout=КОРОТКИЙ)
        вопрос = dns.message.make_query("example.com", "A")
        with self.assertRaises(Exception) as пойман:
            р._ask_doh(dns_resolver.DOH_ENDPOINTS[0], вопрос, "http://127.0.0.1:%d" % порт)
        self.assertTrue(_waited_in_vain(пойман.exception))


class Заглушки:
    """Подменённые попытки: поведение задаётся по (прокси, справочная).

    Для сценариев, которые на поддельном SOCKS-прокси не собрать: DoH с
    ответом (там TLS), подменённый ответ, SERVFAIL, сотни вызывающих.
    Правило — функция (прокси, где) -> действие:
      ("молчит",)             — ждёт таймаут и бросает TimeoutError;
      ("отказ",)              — мгновенный отказ (прокси жив);
      ("ответ", адрес, сек)   — положительный ответ через сек;
      ("код", rcode, сек)     — ответ с кодом (NXDOMAIN, SERVFAIL, пустой NOERROR).
    """

    def __init__(self, таймаут, правило):
        self.таймаут = таймаут
        self.правило = правило
        self.журнал = []
        self._замок = threading.Lock()

    def doh(self, _резолвер, url, вопрос, прокси):
        return self._сделать(прокси, "doh:" + url.split("/")[2], вопрос)

    def tcp(self, _резолвер, справочная, вопрос, прокси):
        return self._сделать(прокси, "tcp:" + справочная, вопрос)

    def _сделать(self, прокси, где, вопрос):
        with self._замок:
            self.журнал.append((прокси, где))
        действие = self.правило(прокси, где)
        if действие[0] == "молчит":
            time.sleep(self.таймаут)
            raise TimeoutError("молчит")
        if действие[0] == "отказ":
            raise ConnectionAbortedError("отказ")
        time.sleep(действие[2])
        ответ = dns.message.make_response(вопрос)
        if действие[0] == "ответ":
            ответ.answer.append(dns.rrset.from_text(
                вопрос.question[0].name, 60, "IN", "A", действие[1]))
        else:
            ответ.set_rcode(действие[1])
        return ответ

    def включить(self, тест):
        for имя, метод in (("_ask_doh", self.doh), ("_ask_tcp", self.tcp)):
            заплатка = mock.patch.object(ProxiedResolver, имя, autospec=True, side_effect=метод)
            заплатка.start()
            тест.addCleanup(заплатка.stop)


class TestОтветВторойНеПеребиваетПрежнюю(unittest.TestCase):
    """Вторая рецензия, DOM-1/F3: «кто первым ответил» отдавал подмену и SERVFAIL."""

    T = 0.2

    def спросить(self, *пул):
        р = ProxiedResolver(СПРАВОЧНЫЕ, timeout=self.T, proxy_provider=Пул(*пул))
        начало = time.monotonic()
        try:
            return [x.to_text() for x in р.resolve("example.com", "A")], time.monotonic() - начало
        except dns.exception.DNSException as e:
            return type(e).__name__, time.monotonic() - начало

    def test_подменённое_домена_нет_через_чужой_прокси_не_принимается(self):
        # У A DoH молчит, обычный DNS отвечает; B по обычному DNS мгновенно
        # отвечает «домена нет» — так выглядит перехват DNS самим прокси.
        def правило(прокси, где):
            if прокси == "A":
                return ("молчит",) if где.startswith("doh") else ("ответ", ОТВЕТ, 0.01)
            return ("отказ",) if где.startswith("doh") else ("код", dns.rcode.NXDOMAIN, 0)
        Заглушки(self.T, правило).включить(self)
        итог, _ = self.спросить("A", "B")
        self.assertEqual(итог, [ОТВЕТ])

    def test_servfail_второй_дорожки_не_ответ(self):
        def правило(прокси, где):
            if прокси == "A":
                return ("молчит",) if где.startswith("doh") else ("ответ", ОТВЕТ, 0.01)
            return ("код", dns.rcode.SERVFAIL, 0) if где.startswith("doh") else ("отказ",)
        Заглушки(self.T, правило).включить(self)
        итог, _ = self.спросить("A", "B")
        self.assertEqual(итог, [ОТВЕТ])

    def test_ответ_прежней_в_той_же_попытке_главнее(self):
        # У A первая DoH молчит, вторая отвечает через половину таймаута. B
        # мгновенно отвечает чужим адресом. Старый код отдал бы ответ A —
        # и новый обязан.
        def правило(прокси, где):
            if прокси == "A":
                if где == "doh:cloudflare-dns.com":
                    return ("молчит",)
                return ("ответ", ОТВЕТ, self.T / 2)
            return ("отказ",) if где.startswith("doh") else ("ответ", "6.6.6.6", 0)
        Заглушки(self.T, правило).включить(self)
        итог, _ = self.спросить("A", "B")
        self.assertEqual(итог, [ОТВЕТ])

    def test_заверенное_doh_домена_нет_принимается(self):
        # Первый прокси мёртв; через второй DoH говорит «домена нет». Это тот
        # же ответ Cloudflare, что старый код получил бы первой попыткой, будь
        # его прокси жив, — берём на стыке, не дожидаясь шести таймаутов.
        def правило(прокси, где):
            if прокси == "A":
                return ("молчит",)
            return ("код", dns.rcode.NXDOMAIN, 0) if где.startswith("doh") else ("отказ",)
        Заглушки(self.T, правило).включить(self)
        итог, прошло = self.спросить("A", "B")
        self.assertEqual(итог, "NXDOMAIN")
        self.assertLess(прошло, 2.6 * self.T)

    def test_два_одинаковых_нет_через_разные_прокси_принимаются(self):
        # Живой замер 29.09: DoH через бесплатные прокси работает редко, и
        # настоящее «записи нет» (DKIM-селектора нет) терялось. Два одинаковых
        # «нет» через разные прокси — уже не подмена одного прокси.
        def правило(прокси, где):
            if прокси == "A":
                return ("молчит",)
            return ("отказ",) if где.startswith("doh") else ("код", dns.rcode.NXDOMAIN, 0)
        Заглушки(self.T, правило).включить(self)
        итог, прошло = self.спросить("A", "B", "C")
        self.assertEqual(итог, "NXDOMAIN")
        self.assertLess(прошло, 2.6 * self.T)

    def test_разные_нет_не_подтверждают_друг_друга(self):
        def правило(прокси, где):
            if прокси == "A":
                return ("молчит",)
            if где.startswith("doh"):
                return ("отказ",)
            return ("код", dns.rcode.NXDOMAIN if прокси == "B" else dns.rcode.NOERROR, 0)
        Заглушки(self.T, правило).включить(self)
        итог, _ = self.спросить("A", "B", "C")
        self.assertEqual(итог, "DNSUnavailable")

    def test_домена_нет_по_обычному_dns_второй_дорожки_не_ответ(self):
        def правило(прокси, где):
            if прокси == "A":
                return ("молчит",)
            return ("отказ",) if где.startswith("doh") else ("код", dns.rcode.NXDOMAIN, 0)
        Заглушки(self.T, правило).включить(self)
        итог, _ = self.спросить("A", "B")
        self.assertEqual(итог, "DNSUnavailable")

    def test_первый_отказал_мгновенно_ждём_вторую_недолго(self):
        # DOM-6: первый прокси отказал на всё мгновенно, запасные мертвы.
        # Старый код сдавался сразу; ждать вторую дорожку полные 6×таймаут
        # за это нельзя — не дольше двух таймаутов.
        def правило(прокси, где):
            return ("отказ",) if прокси == "A" else ("молчит",)
        Заглушки(self.T, правило).включить(self)
        итог, прошло = self.спросить("A", "B", "C", "D")
        self.assertEqual(итог, "DNSUnavailable")
        self.assertLess(прошло, 2 * self.T + 0.25)


class TestПодНагрузкой(unittest.TestCase):
    """Вторая рецензия, F1/DOM-2: при 300 потоках прежняя дорожка опаздывала."""

    T = 0.2
    ВЫЗЫВАЮЩИХ = 300

    def прогнать(self, правило, пул):
        Заглушки(self.T, правило).включить(self)
        р = ProxiedResolver(СПРАВОЧНЫЕ, timeout=self.T, proxy_provider=Пул(*пул))
        времена, итоги = [], []
        замок = threading.Lock()
        старт = threading.Barrier(self.ВЫЗЫВАЮЩИХ)

        def спросить():
            старт.wait()
            начало = time.monotonic()
            try:
                итог = [x.to_text() for x in р.resolve("example.com", "A")]
            except dns.exception.DNSException as e:
                итог = type(e).__name__
            with замок:
                времена.append(time.monotonic() - начало)
                итоги.append(итог)

        потоки = [threading.Thread(target=спросить) for _ in range(self.ВЫЗЫВАЮЩИХ)]
        for п in потоки:
            п.start()
        for п in потоки:
            п.join(30)
        return времена, итоги

    def test_ответ_прежней_дорожки_не_опаздывает(self):
        # У лучшего прокси DoH молчит, обычный DNS отвечает — старый код
        # отвечал за два таймаута; запасные мертвы.
        def правило(прокси, где):
            if прокси == "A":
                return ("молчит",) if где.startswith("doh") else ("ответ", ОТВЕТ, 0.01)
            return ("молчит",)
        времена, итоги = self.прогнать(правило, ["A", "B", "C", "D", "E"])
        self.assertEqual(итоги, [[ОТВЕТ]] * self.ВЫЗЫВАЮЩИХ)
        self.assertLess(max(времена), 2 * self.T + 0.4)

    def test_мёртвый_пул_не_дольше_потолка(self):
        времена, итоги = self.прогнать(lambda прокси, где: ("молчит",), ["A", "B", "C", "D"])
        self.assertEqual(set(map(str, итоги)), {"DNSUnavailable"})
        self.assertLess(max(времена), ПОПЫТОК * self.T + 0.6)


class TestSpamhausТолькоСвоиСправочные(unittest.TestCase):

    def test_резолвер_без_публичных_doh(self):
        р = ProxiedResolver(["10.0.0.53"], timeout=1, public_doh=False)
        self.assertEqual([вид for вид, _, _ in р._attempts()], ["tcp"])
        self.assertEqual([вид for вид, _, _ in ProxiedResolver(["8.8.8.8"], timeout=1)._attempts()],
                         ["doh", "doh", "tcp"])

    def test_сеть_валидатора_строит_spamhaus_без_doh(self):
        # DOM-4: публичные DoH Spamhaus не обслуживает (отказ 127.255.255.254),
        # и его отказ читался как «IP чист».
        v = NetworkValidator(timeout=1, proxies=["socks5://198.51.100.1:1080"])
        заглушка = mock.MagicMock()
        заглушка.return_value.resolve.side_effect = dns.resolver.NXDOMAIN
        with mock.patch("core.dns_checks.ProxiedResolver", заглушка):
            v.set_spamhaus_resolver(["10.0.0.53"])
        self.assertIs(заглушка.call_args.kwargs.get("public_doh"), False)


class TestЧастныеСправочныеЧерезПрокси(Основа):
    """Частный адрес справочной через чужой прокси — это чужая локальная сеть.

    Среди системных резолверов, которые перебирает поиск Spamhaus, бывают
    адреса домашней сети (на машине владельца — два из пяти). Через
    бесплатный прокси такой вопрос ушёл бы в локальную сеть его хозяина.
    """

    def test_частные_не_спрашиваются(self):
        живой = self.прокси("справочная")
        р = ProxiedResolver(["192.168.1.1", "10.0.0.53", "127.0.0.1", "169.254.1.1"],
                            timeout=КОРОТКИЙ, proxy_provider=lambda: живой.адрес,
                            public_doh=False)
        with self.assertRaises(DNSUnavailable):
            р.resolve("example.com", "A")
        self.дать_дожить()
        self.assertEqual(живой.соединений, 0)

    def test_публичные_спрашиваются_как_раньше(self):
        живой = self.прокси("справочная")
        р = ProxiedResolver(["9.9.9.9"], timeout=ТАЙМАУТ, proxy_provider=lambda: живой.адрес,
                            public_doh=False)
        ответ, _ = self.спросить(р)
        self.assertEqual(ответ, [ОТВЕТ])
        self.assertIn(53, живой.порты)


class TestПулПотоковВторойДорожки(unittest.TestCase):

    def test_неудачный_старт_потока_не_ломает_счёт(self):
        полосы = dns_resolver._Lanes(4)
        настоящий = threading.Thread.start

        def падает(поток):
            if поток.name == "dns-lane":
                raise RuntimeError("can't start new thread")
            return настоящий(поток)

        with mock.patch.object(threading.Thread, "start", падает):
            задача = полосы.submit(lambda: 1)
        self.assertIsInstance(задача.exception(timeout=1), RuntimeError)
        self.assertEqual((полосы._threads, полосы._pending), (0, 0))
        self.assertEqual(полосы.submit(lambda: 7).result(timeout=2), 7)

    def test_простаивающий_поток_не_держит_последнюю_задачу(self):
        # Иначе через задачу держался бы резолвер, а через его провайдера —
        # весь NetworkValidator прошлого прогона (вторая рецензия, F4).
        class Груз:
            pass

        полосы = dns_resolver._Lanes(2)
        груз = Груз()
        ссылка = weakref.ref(груз)
        полосы.submit(lambda _: None, груз).result(timeout=2)
        del груз
        for _ in range(20):
            gc.collect()
            if ссылка() is None:
                break
            time.sleep(0.05)
        self.assertIsNone(ссылка())

if __name__ == "__main__":
    unittest.main()
