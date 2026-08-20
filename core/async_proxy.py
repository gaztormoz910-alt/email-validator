import asyncio
import socket
import struct

class AsyncProxyChecker:
    def __init__(self, proxies: list, workers: int = 500, timeout: float = 5.0, mode: str = "http", progress_callback=None):
        """
        mode: "http" (for parser) or "smtp" (for validator)
        """
        self.proxies = proxies
        self.workers = workers
        self.timeout = timeout
        self.mode = mode
        self.progress_callback = progress_callback
        
        self.queue = asyncio.Queue()
        self.live_proxies = []
        
        self.checked_count = 0
        self.total = len(proxies)
        
        if self.mode == "http":
            self.target_host = "gstatic.com"
            self.target_ip = "142.250.186.99"
            self.target_port = 80
            self.http_get_payload = b"GET http://gstatic.com/generate_204 HTTP/1.1\r\nHost: gstatic.com\r\nConnection: close\r\n\r\n"
            self.expected_response = b"204 No Content"
        elif self.mode == "smtp":
            self.target_host = "gmail-smtp-in.l.google.com"
            self.target_ip = "142.250.114.26" # google mx ip
            self.target_port = 25

    async def _tcp_ping(self, ip: str, port: int):
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self.timeout)
        return reader, writer

    async def _check_http(self, reader, writer):
        writer.write(self.http_get_payload)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
        return self.expected_response in response

    async def _check_smtp(self, reader, writer):
        # Read the SMTP greeting banner, e.g. "220 mx.google.com ESMTP"
        response = await asyncio.wait_for(reader.read(1024), timeout=self.timeout)
        return b"220 " in response

    async def _check_socks4(self, reader, writer):
        ip_bytes = socket.inet_aton(self.target_ip)
        port_bytes = struct.pack(">H", self.target_port)
        req = b"\x04\x01" + port_bytes + ip_bytes + b"\x00"
        
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        
        try:
            resp = await asyncio.wait_for(reader.readexactly(8), timeout=self.timeout)
        except asyncio.IncompleteReadError:
            return False
            
        if len(resp) < 2 or resp[1] != 0x5a:
            return False
            
        if self.mode == "http":
            return await self._check_http(reader, writer)
        else:
            return await self._check_smtp(reader, writer)

    async def _socks5_authenticate(self, reader, writer, user, password):
        """Авторизация логином/паролем по RFC 1929."""
        u = user.encode("utf-8")
        pw = password.encode("utf-8")
        if len(u) > 255 or len(pw) > 255:
            return False
        writer.write(b"\x01" + bytes([len(u)]) + u + bytes([len(pw)]) + pw)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        try:
            resp = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
        except asyncio.IncompleteReadError:
            return False
        return resp[1] == 0x00

    async def _check_socks5(self, reader, writer, user=None, password=None):
        # Раньше предлагался только метод 0x00 ("без авторизации"), поэтому платные
        # прокси с логином/паролем всегда объявлялись мёртвыми. Теперь предлагаем оба
        # метода и проходим авторизацию, если сервер её требует.
        if user and password:
            writer.write(b"\x05\x02\x00\x02")
        else:
            writer.write(b"\x05\x01\x00")
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)

        try:
            resp = await asyncio.wait_for(reader.readexactly(2), timeout=self.timeout)
        except asyncio.IncompleteReadError:
            return False

        if resp[0] != 0x05:
            return False

        chosen = resp[1]
        if chosen == 0x02:
            if not (user and password):
                return False  # Сервер требует авторизацию, а учётных данных нет
            if not await self._socks5_authenticate(reader, writer, user, password):
                return False
        elif chosen != 0x00:
            return False
        domain_bytes = self.target_host.encode('utf-8')
        req = b"\x05\x01\x00\x03" + bytes([len(domain_bytes)]) + domain_bytes + struct.pack(">H", self.target_port)
        
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        
        try:
            resp = await asyncio.wait_for(reader.readexactly(4), timeout=self.timeout)
        except asyncio.IncompleteReadError:
            return False
            
        if resp[0] != 0x05 or resp[1] != 0x00:
            return False
            
        atyp = resp[3]
        try:
            if atyp == 0x01:
                await asyncio.wait_for(reader.readexactly(6), timeout=self.timeout)
            elif atyp == 0x03:
                domain_len_b = await asyncio.wait_for(reader.readexactly(1), timeout=self.timeout)
                await asyncio.wait_for(reader.readexactly(domain_len_b[0] + 2), timeout=self.timeout)
            elif atyp == 0x04:
                await asyncio.wait_for(reader.readexactly(18), timeout=self.timeout)
            else:
                return False
        except asyncio.IncompleteReadError:
            return False

        if self.mode == "http":
            return await self._check_http(reader, writer)
        else:
            return await self._check_smtp(reader, writer)

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
                    # .lower() applies to the scheme only: credentials are case-sensitive
                    protocol = proxy.split("://", 1)[0].lower()

                from core.network import _parse_proxy
                parsed = _parse_proxy(proxy)
                if not parsed:
                    raise ValueError("bad proxy format")
                ip, port, user, password = parsed
            except Exception:
                self.checked_count += 1
                if self.progress_callback:
                    self.progress_callback(self.checked_count, self.total, len(self.live_proxies))
                self.queue.task_done()
                continue
                
            reader = None
            writer = None
            
            try:
                reader, writer = await self._tcp_ping(ip, port)
                
                is_live = False
                if protocol == "socks4":
                    is_live = await self._check_socks4(reader, writer)
                elif protocol == "socks5":
                    is_live = await self._check_socks5(reader, writer, user, password)
                else:
                    if self.mode == "http":
                        is_live = await self._check_http(reader, writer)
                    else:
                        connect_req = f"CONNECT {self.target_host}:{self.target_port} HTTP/1.1\r\nHost: {self.target_host}:{self.target_port}\r\n\r\n".encode()
                        writer.write(connect_req)
                        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
                        resp = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
                        if b"200 Connection established" in resp:
                            is_live = await self._check_smtp(reader, writer)

                if is_live:
                    self.live_proxies.append(proxy)
                    
            except Exception:
                pass
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                        
            self.checked_count += 1
            if self.progress_callback:
                self.progress_callback(self.checked_count, self.total, len(self.live_proxies))
                
            self.queue.task_done()

    async def run(self):
        for proxy in self.proxies:
            self.queue.put_nowait(proxy)
            
        # AV Evation & Network Stack Optimization:
        # 1. Cap workers to a safe OS limit (500 max to avoid router/WiFi overload)
        # 2. Stagger worker startup so we don't open all sockets in the exact same millisecond.
        safe_workers = min(self.workers, len(self.proxies), 500)
        
        tasks = []
        for i in range(safe_workers):
            tasks.append(asyncio.create_task(self._worker()))
            if i % 50 == 0:
                await asyncio.sleep(0.02)  # Small jitter to prevent heuristics triggering
            
        await self.queue.join()
        for task in tasks:
            task.cancel()
            
        return self.live_proxies

def run_async_checker(proxies, workers=500, timeout=5.0, mode="http", progress_callback=None):
    checker = AsyncProxyChecker(proxies, workers, timeout, mode, progress_callback)
    
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If we are in a running loop, this function is meant to be synchronous, 
            # so we shouldn't use it directly if loop is running, but standard ThreadPool 
            # used by GUI isn't running an event loop.
            loop.set_exception_handler(lambda loop, context: None)
            return loop.run_until_complete(checker.run())
    except RuntimeError:
        pass
        
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # Mute all internal asyncio transport errors (like WinError 10054)
    loop.set_exception_handler(lambda loop, context: None)
    return loop.run_until_complete(checker.run())
