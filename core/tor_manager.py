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

class TorInstance:
    def __init__(self, index, base_dir, tor_exe, log_callback, password, hashed_password):
        self.index = index
        self.base_dir = base_dir
        self.tor_exe = tor_exe
        self.log_callback = log_callback
        self.tor_port = 9050 + (index * 2)
        self.control_port = 9051 + (index * 2)
        self.password = password
        self.hashed_password = hashed_password
        self.data_dir = base_dir / "tor_bin" / "Data" / f"Tor_{index}"
        self.tor_dir = base_dir / "tor_bin"
        self.process = None
        self._renew_lock = threading.Lock()
        self._last_renew_time = 0

    def _log(self, msg, level="info"):
        try:
            self.log_callback(msg)
        except Exception as e:
            print(f"TorInstance log error: {e}")

    def start(self):
        self.data_dir.mkdir(parents=True, exist_ok=True)
        torrc_path = self.tor_dir / f"torrc_{self.index}"
        data_dir_str = str(self.data_dir).replace("\\", "/")
        
        with open(torrc_path, "w", encoding="utf-8") as f:
            f.write(f"SocksPort {self.tor_port}\n")
            f.write(f"ControlPort {self.control_port}\n")
            f.write(f"HashedControlPassword {self.hashed_password}\n")
            f.write(f'DataDirectory "{data_dir_str}"\n')
            f.write("Log notice stdout\n")
            f.write("UseBridges 0\n")
            # Bridges removed for direct connection
            
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            
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
        last_progress = ""
        while time.time() - start_time < 90:
            line = self.process.stdout.readline()
            if not line: break
            if "Bootstrapped" in line:
                if "100%" in line:
                    bootstrapped = True
                    break
                else:
                    try:
                        percent = line.split("Bootstrapped ")[1].split("%")[0]
                        if percent != last_progress:
                            self._log(f"[Tor #{self.index}] Bootstrap: {percent}%", "info")
                            last_progress = percent
                    except: pass
                
        if bootstrapped:
            self._log(f"[Система] Tor #{self.index} успешно запущен (Порт {self.tor_port})", "success")
            return True
        else:
            self._log(f"[DEAD] Ошибка: Tor #{self.index} не смог подключиться (Таймаут).", "dead")
            self.stop()
            return False

    def renew_ip(self):
        if not self.process or self.process.poll() is not None:
            return False
            
        with self._renew_lock:
            current_time = time.time()
            # Rate-limit: IP was recently changed, skip without blocking
            if current_time - self._last_renew_time < 10.0:
                return True
                
            try:
                import socket
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5.0)
                    s.connect(('127.0.0.1', self.control_port))
                    s.sendall(f'AUTHENTICATE "{self.password}"\r\n'.encode('utf-8'))
                    resp = s.recv(1024).decode('utf-8')
                    if not resp.startswith('250'): raise Exception("Auth Error")
                    
                    s.sendall(b'SIGNAL NEWNYM\r\n')
                    resp = s.recv(1024).decode('utf-8')
                    if not resp.startswith('250'): raise Exception("NEWNYM Error")
                
                self._last_renew_time = time.time()
                return True
            except Exception:
                return False
            finally:
                self._last_renew_time = time.time()

    def stop(self):
        if self.process:
            try:
                # Use taskkill to cleanly kill Tor and its lyrebird child processes
                subprocess.call(['taskkill', '/F', '/T', '/PID', str(self.process.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except:
                pass
            self.process = None
            
            try:
                import psutil
                parent = psutil.Process(self.process.pid)
                for child in parent.children(recursive=True):
                    child.kill()
                parent.kill()
            except:
                pass
                
            self.process = None

    def is_alive(self):
        return self.process is not None and self.process.poll() is None

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
        if log_callback:
            self.log_callback = log_callback
        else:
            if not hasattr(self, 'log_callback'):
                self.log_callback = print
                
        if getattr(self, '_initialized', False):
            return
        
        if getattr(sys, 'frozen', False):
            self.base_dir = Path(sys.executable).parent
        else:
            self.base_dir = Path(__file__).parent.parent
            
        self.tor_dir = self.base_dir / "tor_bin"
        self.tor_exe = self.tor_dir / "Tor" / "tor.exe"
        
        self.password = "parser_secret"
        self.hashed_password = "16:0276BB60159E2A43607648F746CFC086CE78F225E20C1E526107CDD6E0"
        
        self.instances = []
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
            # Причина названа вслух: «используем резервную» без объяснения не
            # даёт отличить отсутствие сети от изменившегося формата ответа,
            # а лечатся эти два случая по-разному.
            self._log("[Система] Не удалось узнать последнюю версию Tor "
                      "(%s: %s), берём резервную 15.0.16." % (type(e).__name__, e),
                      "info")
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
                    for data in iter(lambda: response.read(4096), b""):
                        out_file.write(data)
                        
            self._log("[Система] Загрузка завершена. Распаковка архива...", "info")
            with tarfile.open(tar_path, "r:gz") as tar:
                tar.extractall(path=self.tor_dir)
            
            if (self.tor_dir / "tor" / "tor.exe").exists():
                self.tor_exe = self.tor_dir / "tor" / "tor.exe"
            
            if tar_path.exists(): tar_path.unlink()
            self._log("[Система] Установка встроенного Tor успешно завершена!", "success")
            return True
        except Exception as e:
            self._log(f"[DEAD] Ошибка при загрузке Tor: {e}", "dead")
            if tar_path.exists():
                try: tar_path.unlink()
                except: pass
            return False

    def start(self, num_instances=1):
        if not self.check_and_download():
            return False
            
        self.stop() # Clean up old instances if any
        self.instances = []
        
        self._log("[Система] Очистка старых процессов Tor...", "info")
        if os.name == 'nt':
            os.system("taskkill /F /IM tor.exe >nul 2>&1")
            
        self._log(f"[Система] Запуск {num_instances} процессов Tor (через Snowflake)...", "info")
        
        def start_instance(idx):
            # Stagger startup to avoid hammering the Snowflake broker simultaneously
            time.sleep(idx * 6.0)
            
            for attempt in range(2): # 2 attempts per instance
                inst = TorInstance(idx, self.base_dir, self.tor_exe, self.log_callback, self.password, self.hashed_password)
                if inst.start():
                    with self._lock:
                        self.instances.append(inst)
                    return
                # If failed, wait a bit before retrying
                if attempt == 0:
                    self._log(f"[Система] Повторная попытка запуска Tor #{idx}...", "warning")
                    time.sleep(10.0)
                
        threads = []
        for i in range(num_instances):
            t = threading.Thread(target=start_instance, args=(i,))
            t.start()
            threads.append(t)
            
        for t in threads:
            t.join()
            
        if len(self.instances) > 0:
            self._log(f"[Система] {len(self.instances)}/{num_instances} Tor-узлов успешно запущены!", "success")
            return True
        else:
            self._log("[DEAD] Не удалось запустить ни одного процесса Tor.", "dead")
            return False

    def renew_ip(self, proxy_url=None):
        alive = [inst for inst in self.instances if inst.is_alive()]
        if not alive: return False
        
        if proxy_url:
            try:
                port = int(proxy_url.split(":")[-1])
                for inst in alive:
                    if inst.tor_port == port:
                        return inst.renew_ip()
            except: pass
            
        # Renew a random alive instance
        import random
        return random.choice(alive).renew_ip()

    def stop(self):
        if self.instances:
            self._log(f"[Система] Остановка {len(self.instances)} процессов Tor...", "info")
            for inst in self.instances:
                inst.stop()
            self.instances.clear()

    def get_proxy_url(self):
        import random
        alive = [inst for inst in self.instances if inst.is_alive()]
        if not alive:
            return None
        inst = random.choice(alive)
        return f"socks5h://127.0.0.1:{inst.tor_port}"

    def get_alive_count(self):
        return len([inst for inst in self.instances if inst.is_alive()])
