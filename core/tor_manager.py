import os
import sys
import time
import zipfile
import urllib.request
import subprocess
import threading
from pathlib import Path
from stem.control import Controller
from stem import Signal

class TorManager:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls, *args, **kwargs):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(TorManager, cls).__new__(cls)
                cls._instance._initialized = False
        return cls._instance

    def __init__(self, log_callback=None):
        if self._initialized:
            return
            
        self.log_callback = log_callback or print
        
        # Determine paths
        if getattr(sys, 'frozen', False):
            self.base_dir = Path(sys.executable).parent
        else:
            self.base_dir = Path(__file__).parent.parent
            
        self.tor_dir = self.base_dir / "tor_bin"
        self.tor_exe = self.tor_dir / "Tor" / "tor.exe"
        self.data_dir = self.tor_dir / "Data" / "Tor"
        
        self.process = None
        self.tor_port = 9050
        self.control_port = 9051
        self.password = "parser_secret" # Simple password for local control port
        self.hashed_password = "16:21B3EB15BB696A62DB5DC05060A56EEDBEA79AD576403D3BB232AE0020" # Hash for "parser_secret" generated via tor --hash-password
        
        self._initialized = True

    def _log(self, msg, level="info"):
        try:
            self.log_callback(msg)
        except Exception as e:
            print(f"TorManager log error: {e}")

    def check_and_download(self):
        if self.tor_exe.exists() or (self.tor_dir / "tor" / "tor.exe").exists():
            if (self.tor_dir / "tor" / "tor.exe").exists():
                self.tor_exe = self.tor_dir / "tor" / "tor.exe"
            return True
            
        self._log("[Система] Исполняемый файл Tor не найден. Получение последней версии...", "info")
        
        try:
            import json
            req_version = urllib.request.Request("https://aus1.torproject.org/torbrowser/update_3/release/downloads.json", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req_version) as response:
                version = json.loads(response.read())['version']
            
            url = f"https://dist.torproject.org/torbrowser/{version}/tor-expert-bundle-windows-x86_64-{version}.tar.gz"
            self._log(f"[Система] Начинаю автоматическую загрузку Tor v{version} (около 15 МБ)...", "info")
        except Exception as e:
            self._log(f"[Система] Не удалось получить последнюю версию, используем резервную 15.0.16. Ошибка: {e}", "info")
            url = "https://dist.torproject.org/torbrowser/15.0.16/tor-expert-bundle-windows-x86_64-15.0.16.tar.gz"
        import tarfile
        
        tar_path = self.base_dir / "tor_bundle.tar.gz"
        
        try:
            self.tor_dir.mkdir(parents=True, exist_ok=True)
            
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req) as response, open(tar_path, 'wb') as out_file:
                total_length = response.getheader('content-length')
                if total_length is None:
                    out_file.write(response.read())
                else:
                    dl = 0
                    total_length = int(total_length)
                    for data in iter(lambda: response.read(4096), b""):
                        dl += len(data)
                        out_file.write(data)
                        
            self._log("[Система] Загрузка завершена. Распаковка архива...", "info")
            
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=self.tor_dir)
            
            if (self.tor_dir / "tor" / "tor.exe").exists():
                self.tor_exe = self.tor_dir / "tor" / "tor.exe"
            
            if tar_path.exists():
                tar_path.unlink()
                
            self._log("[Система] Установка встроенного Tor успешно завершена!", "success")
            return True
            
        except Exception as e:
            self._log(f"[DEAD] Ошибка при загрузке Tor: {e}", "dead")
            if tar_path.exists():
                try: tar_path.unlink()
                except: pass
            return False

    def start(self):
        if self.process and self.process.poll() is None:
            self._log("[Система] Процесс Tor уже запущен в фоне.", "info")
            return True
            
        if not self.check_and_download():
            return False
            
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        torrc_path = self.tor_dir / "torrc"
        
        data_dir_str = str(self.data_dir).replace("\\", "/")
        
        with open(torrc_path, "w", encoding="utf-8") as f:
            f.write(f"SocksPort {self.tor_port}\n")
            f.write(f"ControlPort {self.control_port}\n")
            f.write(f"HashedControlPassword {self.hashed_password}\n")
            f.write(f'DataDirectory "{data_dir_str}"\n')
            f.write("Log notice stdout\n")
            f.write("UseBridges 1\n")
            f.write("ClientTransportPlugin snowflake exec pluggable_transports/lyrebird.exe\n")
            f.write("Bridge snowflake 192.0.2.3:80 2B280B23E1107BB62ABFC40DDCC8824814F80A72 fingerprint=2B280B23E1107BB62ABFC40DDCC8824814F80A72 url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn\n")
            f.write("Bridge snowflake 192.0.2.4:80 8838024498816A039FCBBAB14E6F40A0843051FA fingerprint=8838024498816A039FCBBAB14E6F40A0843051FA url=https://1098762253.rsc.cdn77.org/ fronts=app.datapacket.com,www.datapacket.com ice=stun:stun.epygi.com:3478,stun:stun.uls.co.za:3478,stun:stun.voipgate.com:3478,stun:stun.mixvoip.com:3478,stun:stun.telnyx.com:3478,stun:stun.hot-chilli.net:3478,stun:stun.fitauto.ru:3478,stun:stun.m-online.net:3478 utls-imitate=hellorandomizedalpn\n")
            
        self._log("[Система] Очистка старых процессов Tor...", "info")
        if os.name == 'nt':
            os.system("taskkill /F /IM tor.exe >nul 2>&1")
            
        self._log("[Система] Запуск локального движка Tor (через мосты Snowflake)...", "info")
        
        creation_flags = 0
        if os.name == 'nt':
            creation_flags = subprocess.CREATE_NO_WINDOW
            
        self.process = subprocess.Popen(
            [str(self.tor_exe), "-f", str(torrc_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=creation_flags,
            text=True,
            cwd=str(self.tor_dir / "tor")
        )
        
        start_time = time.time()
        bootstrapped = False
        while time.time() - start_time < 300:
            line = self.process.stdout.readline()
            if not line:
                break
            if "Bootstrapped 100%" in line:
                bootstrapped = True
                break
            if "Bootstrapped" in line:
                try:
                    pct = line.split("Bootstrapped ")[1].split("%")[0]
                    self._log(f"[Система] Подключение к анонимной сети: {pct}%", "info")
                except: pass
                
        if bootstrapped:
            self._log(f"[Система] Tor успешно запущен и готов к работе!", "success")
            return True
        else:
            self._log("[DEAD] Ошибка: Не удалось подключиться к сети Tor (Таймаут).", "dead")
            self.stop()
            return False

    def renew_ip(self):
        if not self.process or self.process.poll() is not None:
            return False
            
        try:
            self._log("[Система] Запрашиваю смену IP адреса у Tor...", "warning")
            with Controller.from_port(port=self.control_port) as controller:
                controller.authenticate(password=self.password)
                controller.signal(Signal.NEWNYM)
            time.sleep(2.5) # Ждем пока построится новая цепочка
            self._log("[Система] IP адрес успешно изменен! Продолжаю парсинг.", "success")
            return True
        except Exception as e:
            self._log(f"[DEAD] Ошибка при смене IP адреса: {e}", "dead")
            return False

    def stop(self):
        if self.process:
            self._log("[Система] Остановка процесса Tor...", "info")
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill()
            self.process = None

    def get_proxy_url(self):
        return f"socks5h://127.0.0.1:{self.tor_port}"
