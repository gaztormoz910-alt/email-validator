import asyncio
import socket
import struct

class AsyncProxyChecker:
    def __init__(self, proxies: list, workers: int = 500, timeout: float = 5.0):
        """
        proxies: list of str, e.g. ["http://127.0.0.1:8080", "socks5://10.0.0.1:1080"]
        workers: number of concurrent async workers
        timeout: global timeout for network operations
        """
        self.proxies = proxies
        self.workers = workers
        self.timeout = timeout
        
        self.queue = asyncio.Queue()
        self.live_proxies = []
        
        # Predefined target for tests
        self.target_host = "gstatic.com"
        self.target_ip = "142.250.186.99"
        self.target_port = 80
        self.http_get_payload = b"GET http://gstatic.com/generate_204 HTTP/1.1\r\nHost: gstatic.com\r\nConnection: close\r\n\r\n"
        self.expected_response = b"204 No Content"

    async def _tcp_ping(self, ip: str, port: int):
        """Quick TCP ping to check if the proxy port is open."""
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=self.timeout)
        return reader, writer

    async def _check_http(self, reader, writer):
        writer.write(self.http_get_payload)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        
        response = await asyncio.wait_for(reader.read(4096), timeout=self.timeout)
        return self.expected_response in response

    async def _check_socks4(self, reader, writer):
        # SOCKS4 connect request to 142.250.186.99:80
        # VN(1) + CD(1) + DSTPORT(2) + DSTIP(4) + USERID(variable) + NULL(1)
        # VN=4, CD=1 (CONNECT)
        ip_bytes = socket.inet_aton(self.target_ip)
        port_bytes = struct.pack(">H", self.target_port)
        req = b"\x04\x01" + port_bytes + ip_bytes + b"\x00"
        
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        
        resp = await asyncio.wait_for(reader.read(8), timeout=self.timeout)
        if len(resp) < 2 or resp[1] != 0x5a:  # 0x5a = 90 (Request granted)
            return False
            
        return await self._check_http(reader, writer)

    async def _check_socks5(self, reader, writer):
        # SOCKS5 Greeting: VER(5) + NMETHODS(1) + METHODS(0 = NO AUTH)
        writer.write(b"\x05\x01\x00")
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        
        resp = await asyncio.wait_for(reader.read(2), timeout=self.timeout)
        if len(resp) != 2 or resp[0] != 0x05 or resp[1] != 0x00:
            return False
            
        # SOCKS5 Connect: VER(5) + CMD(1) + RSV(0) + ATYP(3 = DOMAIN) + DOMAIN_LEN(1) + DOMAIN + DSTPORT(2)
        domain_bytes = self.target_host.encode('utf-8')
        req = b"\x05\x01\x00\x03" + bytes([len(domain_bytes)]) + domain_bytes + struct.pack(">H", self.target_port)
        
        writer.write(req)
        await asyncio.wait_for(writer.drain(), timeout=self.timeout)
        
        # Read SOCKS5 reply
        # VER(1) + REP(1) + RSV(1) + ATYP(1) + BND.ADDR(var) + BND.PORT(2)
        resp = await asyncio.wait_for(reader.read(4), timeout=self.timeout)
        if len(resp) < 4 or resp[0] != 0x05 or resp[1] != 0x00:  # REP=0x00 (Succeeded)
            return False
            
        atyp = resp[3]
        if atyp == 0x01:  # IPv4
            await asyncio.wait_for(reader.read(4 + 2), timeout=self.timeout)
        elif atyp == 0x03:  # Domain
            domain_len_b = await asyncio.wait_for(reader.read(1), timeout=self.timeout)
            if not domain_len_b:
                return False
            d_len = domain_len_b[0]
            await asyncio.wait_for(reader.read(d_len + 2), timeout=self.timeout)
        elif atyp == 0x04:  # IPv6
            await asyncio.wait_for(reader.read(16 + 2), timeout=self.timeout)
        else:
            return False

        return await self._check_http(reader, writer)

    async def _worker(self):
        while not self.queue.empty():
            proxy = await self.queue.get()
            protocol = "http"
            ip = ""
            port = 0
            
            # Basic parsing of proxy string
            try:
                if "://" in proxy:
                    protocol, addr = proxy.lower().split("://", 1)
                else:
                    addr = proxy
                ip, port_str = addr.split(":")
                port = int(port_str)
            except Exception:
                self.queue.task_done()
                continue
                
            reader = None
            writer = None
            
            try:
                # 1. TCP Fast Ping
                reader, writer = await self._tcp_ping(ip, port)
                
                # 2. Protocol Check
                is_live = False
                if protocol == "socks4":
                    is_live = await self._check_socks4(reader, writer)
                elif protocol == "socks5":
                    is_live = await self._check_socks5(reader, writer)
                else:
                    is_live = await self._check_http(reader, writer)
                    
                if is_live:
                    self.live_proxies.append(proxy)
                    
            except (asyncio.TimeoutError, ConnectionRefusedError, ConnectionResetError, socket.gaierror, OSError):
                pass
            finally:
                if writer is not None:
                    try:
                        writer.close()
                        await writer.wait_closed()
                    except Exception:
                        pass
                
            self.queue.task_done()

    async def run(self):
        # Fill the queue
        for proxy in self.proxies:
            self.queue.put_nowait(proxy)
            
        # Create workers
        tasks = []
        for _ in range(min(self.workers, len(self.proxies))):
            task = asyncio.create_task(self._worker())
            tasks.append(task)
            
        # Wait for all queue items to be processed
        await self.queue.join()
        
        # Cancel any hanging workers
        for task in tasks:
            task.cancel()
            
        return self.live_proxies

# Пример использования
if __name__ == "__main__":
    # Замени на свой список
    test_proxies = [
        "socks5://127.0.0.1:9050",
        "http://8.8.8.8:8080"
    ]
    
    checker = AsyncProxyChecker(proxies=test_proxies, workers=100, timeout=5.0)
    
    print(f"Запущена асинхронная проверка {len(test_proxies)} прокси...")
    live = asyncio.run(checker.run())
    
    print(f"Живых прокси найдено: {len(live)}")
    for p in live:
        print(f"  - {p}")
