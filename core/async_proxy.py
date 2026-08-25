"""Асинхронная проверка живости прокси.

Отдельно от профилирования: здесь выясняется только «отвечает ли», а каким
почтовикам прокси пригоден — в core/network.py и core/proxy_profile.py.

Главное изменение против прежней версии: раньше любая неудача давала один
диагноз «мёртв». Из-за этого пользователь с полностью рабочим списком видел
«ни один прокси не работает» и шёл покупать новый — хотя проблема была в том,
что провайдер закрыл 25 порт. Теперь при неудаче тот же прокси проверяется по
443, и диагнозов становится три: live, port25_blocked, dead.

Рукопожатие и проверка цели разделены (_open_*_tunnel против _check_*): без
этого контрольную пробу пришлось бы дублировать протокол за протоколом.
"""

import asyncio
import socket
import struct


class AsyncProxyChecker:
    def __init__(self, proxies: list, workers: int = 500, timeout: float = 5.0,
                 mode: str = "http", progress_callback=None):
        """mode: "http" (для парсера) или "smtp" (для валидатора)."""
        self.proxies = proxies
        self.workers = workers
        self.timeout = timeout
        self.mode = mode
        self.progress_callback = progress_callback

        self.queue = asyncio.Queue()
        self.live_proxies = []

        self.checked_count = 0
        self.total = len(proxies)

        # Диагноз по каждому прокси: "live" | "port25_blocked" | "dead"
        self.diagnosis = {}
        self.port25_blocked = []

        # Контрольная цель. Проверяется только когда основная проба не прошла:
        # ответ по 443 при отказе по 25 означает, что прокси жив, а закрыт порт.
        self.control_host = "www.google.com"
        self.control_port = 443

        if self.mode == "http":
            self.target_host = "gstatic.com"
            self.target_ip = "142.250.186.99"
            self.target_port = 80
            self.http_get_payload = (b"GET http://gstatic.com/generate_204 HTTP/1.1\r\n"
                                     b"Host: gstatic.com\r\nConnection: close\r\n\r\n")
            self.expected_response = b"204 No Content"
        elif self.mode == "smtp":
            self.target_host = "gmail-smtp-in.l.google.com"
            self.target_ip = "142.250.114.26"  # google mx ip
            self.target_port = 25

    # --- транспорт ---------------------------------------------------------

    async def _tcp_ping(self, ip: str, port: int):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port), timeout=self.timeout)
        return reader, writer

    async def _check_http(self, reader, writer):
        writer.write(self.http_get_payload)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
        return self.expected_response in response

    async def _check_smtp(self, reader, writer):
        # Читаем приветственный баннер, например "220 mx.google.com ESMTP"
        response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
        return b"220 " in response

    async def _check_target(self, reader, writer):
        """Проверка самой цели за уже открытым туннелем."""
        if self.mode == "http":
            return await self._check_http(reader, writer)
        return await self._check_smtp(reader, writer)

    # --- SOCKS4 ------------------------------------------------------------

    async def _open_socks4_tunnel(self, reader, writer, host=None, port=None):
        """Только рукопожатие SOCKS4. True — туннель до цели открыт."""
        target_ip = self.target_ip if host is None else None
        if target_ip is None:
            try:
                target_ip = socket.gethostbyname(host)
            except Exception:
                return False
        ip_bytes = socket.inet_aton(target_ip)
        port_bytes = struct.pack(">H", self.target_port if port is None else port)
        request = b"\x04\x01" + port_bytes + ip_bytes + b"\x00"

        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)

        try:
            response = await asyncio.wait_for(reader.readexactly(8), timeout=self.timeout)
        except asyncio.IncompleteReadError:
            return False

        return len(response) >= 2 and response[1] == 0x5a

    async def _check_socks4(self, reader, writer):
        if not await self._open_socks4_tunnel(reader, writer):
            return False
        return await self._check_target(reader, writer)

    # --- SOCKS5 ------------------------------------------------------------

    async def _socks5_authenticate(self, reader, writer, user, password):
        """Авторизация логином/паролем по RFC 1929."""
        user_bytes = user.encode("utf-8")
        password_bytes = password.encode("utf-8")
        if len(user_bytes) > 255 or len(password_bytes) > 255:
            return False
        writer.write(b"\x01" + bytes([len(user_bytes)]) + user_bytes
                     + bytes([len(password_bytes)]) + password_bytes)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        try:
            response = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
        except asyncio.IncompleteReadError:
            return False
        return response[1] == 0x00

    async def _open_socks5_tunnel(self, reader, writer, user=None, password=None,
                                  host=None, port=None):
        """Только рукопожатие SOCKS5. True — туннель до цели открыт.

        Раньше предлагался единственный метод 0x00 («без авторизации»), поэтому
        платные прокси с логином и паролем всегда объявлялись мёртвыми.
        """
        if user and password:
            writer.write(b"\x05\x02\x00\x02")
        else:
            writer.write(b"\x05\x01\x00")
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)

        try:
            response = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
        except asyncio.IncompleteReadError:
            return False

        if response[0] != 0x05:
            return False

        chosen = response[1]
        if chosen == 0x02:
            if not (user and password):
                return False  # Сервер требует авторизацию, а учётных данных нет
            if not await self._socks5_authenticate(reader, writer, user, password):
                return False
        elif chosen != 0x00:
            return False

        target_host = self.target_host if host is None else host
        target_port = self.target_port if port is None else port
        domain_bytes = target_host.encode("utf-8")
        request = (b"\x05\x01\x00\x03" + bytes([len(domain_bytes)]) + domain_bytes
                   + struct.pack(">H", target_port))

        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)

        try:
            response = await asyncio.wait_for(reader.readexactly(4), timeout=self.timeout)
        except asyncio.IncompleteReadError:
            return False

        if response[0] != 0x05 or response[1] != 0x00:
            return False

        # Дочитываем адрес привязки, иначе он останется в буфере и попадёт
        # в ответ вместо баннера SMTP
        atyp = response[3]
        try:
            if atyp == 0x01:
                await asyncio.wait_for(reader.readexactly(6), timeout=self.timeout)
            elif atyp == 0x03:
                length = await asyncio.wait_for(reader.readexactly(1), timeout=self.timeout)
                await asyncio.wait_for(reader.readexactly(length[0] + 2), timeout=self.timeout)
            elif atyp == 0x04:
                await asyncio.wait_for(reader.readexactly(18), timeout=self.timeout)
            else:
                return False
        except asyncio.IncompleteReadError:
            return False

        return True

    async def _check_socks5(self, reader, writer, user=None, password=None):
        if not await self._open_socks5_tunnel(reader, writer, user, password):
            return False
        return await self._check_target(reader, writer)

    # --- HTTP CONNECT ------------------------------------------------------

    async def _open_http_tunnel(self, reader, writer, host=None, port=None):
        target_host = self.target_host if host is None else host
        target_port = self.target_port if port is None else port
        request = (f"CONNECT {target_host}:{target_port} HTTP/1.1\r\n"
                   f"Host: {target_host}:{target_port}\r\n\r\n").encode()
        writer.write(request)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
        return b"200" in response and b"establish" in response.lower()

    # --- контрольная проба -------------------------------------------------

    async def _control_reachable(self, protocol, ip, port, user, password):
        """Отвечает ли прокси на соединение до 443 порта.

        Проверяется ТОЛЬКО факт установления туннеля: ни байта данных не шлём
        и TLS не поднимаем. Вопрос ровно один — жив ли сам прокси.
        """
        writer = None
        try:
            reader, writer = await self._tcp_ping(ip, port)
            if protocol == "socks4":
                return await self._open_socks4_tunnel(
                    reader, writer, host=self.control_host, port=self.control_port)
            if protocol == "socks5":
                return await self._open_socks5_tunnel(
                    reader, writer, user, password,
                    host=self.control_host, port=self.control_port)
            return await self._open_http_tunnel(
                reader, writer, host=self.control_host, port=self.control_port)
        except Exception:
            return False
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    def diagnosis_report(self):
        """Сколько прокси живы, у скольких закрыт 25 порт, сколько мертвы."""
        counts = {"live": 0, "port25_blocked": 0, "dead": 0}
        for verdict in self.diagnosis.values():
            if verdict in counts:
                counts[verdict] += 1
        return counts

    # --- рабочий цикл ------------------------------------------------------

    async def _worker(self):
        while not self.queue.empty():
            proxy = await self.queue.get()
            protocol = "socks5"
            ip = ""
            port = 0
            user = None
            password = None

            try:
                if "://" in proxy:
                    # .lower() только для схемы: логин и пароль регистрозависимы
                    protocol = proxy.split("://", 1)[0].lower()

                from core.network import _parse_proxy
                parsed = _parse_proxy(proxy)
                if not parsed:
                    raise ValueError("bad proxy format")
                ip, port, user, password = parsed
            except Exception:
                self.diagnosis[proxy] = "dead"
                self.checked_count += 1
                if self.progress_callback:
                    self.progress_callback(self.checked_count, self.total,
                                           len(self.live_proxies))
                self.queue.task_done()
                continue

            writer = None
            try:
                reader, writer = await self._tcp_ping(ip, port)

                if protocol == "socks4":
                    is_live = await self._check_socks4(reader, writer)
                elif protocol == "socks5":
                    is_live = await self._check_socks5(reader, writer, user, password)
                elif self.mode == "http":
                    is_live = await self._check_http(reader, writer)
                else:
                    is_live = (await self._open_http_tunnel(reader, writer)
                               and await self._check_smtp(reader, writer))

                if is_live:
                    self.live_proxies.append(proxy)
                    self.diagnosis[proxy] = "live"
                else:
                    self.diagnosis[proxy] = await self._diagnose_failure(
                        protocol, ip, port, user, password)
            except Exception:
                try:
                    self.diagnosis[proxy] = await self._diagnose_failure(
                        protocol, ip, port, user, password)
                except Exception:
                    self.diagnosis[proxy] = "dead"
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass

            self.checked_count += 1
            if self.progress_callback:
                self.progress_callback(self.checked_count, self.total,
                                       len(self.live_proxies))
            self.queue.task_done()

    async def _diagnose_failure(self, protocol, ip, port, user, password):
        """Мёртв прокси или у него просто закрыт 25 порт.

        Контрольная проба делается только в режиме smtp: в режиме http порт и
        так открыт у всех, и тратить на это второе соединение незачем.
        """
        if self.mode != "smtp":
            return "dead"
        if await self._control_reachable(protocol, ip, port, user, password):
            proxy_key = f"{ip}:{port}"
            self.port25_blocked.append(proxy_key)
            return "port25_blocked"
        return "dead"

    async def run(self):
        for proxy in self.proxies:
            self.queue.put_nowait(proxy)

        # Потолок воркеров — защита сетевого стека и роутера, а не оптимизация.
        # Плюс разнос старта: открывать все сокеты в одну миллисекунду значит
        # выглядеть для антивируса ровно как сканер портов.
        safe_workers = min(self.workers, len(self.proxies), 500)

        tasks = []
        for index in range(safe_workers):
            tasks.append(asyncio.create_task(self._worker()))
            if index % 50 == 0:
                await asyncio.sleep(0.02)

        await self.queue.join()
        for task in tasks:
            task.cancel()

        return self.live_proxies


def run_async_checker(proxies, workers=500, timeout=5.0, mode="http",
                      progress_callback=None, return_checker=False):
    """Синхронная обёртка. return_checker=True отдаёт и сам чекер с диагнозами."""
    checker = AsyncProxyChecker(proxies, workers, timeout, mode, progress_callback)

    def finish(result):
        return (result, checker) if return_checker else result

    # get_running_loop вместо get_event_loop: второй в Python 3.12+ выдаёт
    # DeprecationWarning при вызове вне цикла, а вне цикла мы здесь как раз
    # и находимся в подавляющем большинстве случаев.
    try:
        running = asyncio.get_running_loop()
    except RuntimeError:
        running = None
    if running is not None:
        # Внутри уже работающего цикла синхронный вызов невозможен;
        # пул потоков в GUI своего цикла не держит, поэтому сюда не попадаем.
        running.set_exception_handler(lambda loop, context: None)
        return finish(running.run_until_complete(checker.run()))

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # Гасим внутренние ошибки транспорта asyncio (например WinError 10054)
    loop.set_exception_handler(lambda loop, context: None)
    try:
        return finish(loop.run_until_complete(checker.run()))
    finally:
        try:
            loop.close()
        except Exception:
            pass
