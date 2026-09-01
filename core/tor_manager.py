import binascii
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request
from pathlib import Path

# stem отсюда убран намеренно: он числился в зависимостях и импортировался,
# но управляющий порт открывается обычным сокетом — за библиотеку платили
# установкой, а пользовались ей ноль раз. zipfile убран по той же причине.

class TorInstance:
    def __init__(self, index, base_dir, tor_exe, log_callback):
        self.index = index
        self.base_dir = base_dir
        self.tor_exe = tor_exe
        self.log_callback = log_callback
        self.tor_port = 9050 + (index * 2)
        self.control_port = 9051 + (index * 2)
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
            f.write("CookieAuthentication 1\n")
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
                    except Exception: pass
                
        if bootstrapped:
            self._log(f"[Система] Tor #{self.index} успешно запущен (Порт {self.tor_port})", "success")
            return True
        else:
            self._log(f"[DEAD] Ошибка: Tor #{self.index} не смог подключиться (Таймаут).", "dead")
            self.stop()
            return False

    def _auth_cookie(self):
        """Cookie управляющего порта в шестнадцатеричном виде.

        Файл tor кладёт в свой каталог данных при CookieAuthentication 1.
        Пустой ответ означает «не прочитали» — тогда AUTHENTICATE не пройдёт,
        и смена цепочки честно вернёт False вместо тихого продолжения.
        """
        try:
            raw = (self.data_dir / "control_auth_cookie").read_bytes()
        except Exception:
            return b""
        return binascii.hexlify(raw)

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
                    s.sendall(b"AUTHENTICATE " + self._auth_cookie() + b"\r\n")
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
        if not self.process:
            return

        # PID запоминается ДО обнуления. Раньше self.process обнулялся между
        # двумя способами убийства, и второй падал на AttributeError внутри
        # голого except — то есть не выполнялся никогда. Молча: дочерние
        # процессы (lyrebird, snowflake) переживали остановку, держали порт и
        # мешали следующему запуску.
        pid = self.process.pid

        try:
            subprocess.call(["taskkill", "/F", "/T", "/PID", str(pid)],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass

        # Второй заход — на случай, если taskkill недоступен (не Windows) или
        # не справился с деревом.
        try:
            import psutil

            parent = psutil.Process(pid)
            for child in parent.children(recursive=True):
                try:
                    child.kill()
                except Exception:
                    pass
            parent.kill()
        except Exception:
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
        
        # Управляющий порт больше НЕ защищён общим паролем.
        #
        # Поля password и hashed_password убраны совсем: держать пустые строки
        # «на всякий случай» значит оставить дорогу назад к общему секрету.
        #
        # Раньше здесь лежала пара «parser_secret» и её готовый хэш —
        # одинаковая у всех установок. Порт слушает только 127.0.0.1, но
        # общеизвестный пароль означает, что любой процесс на этой машине мог
        # сменить нам цепочку или прочитать её состояние.
        #
        # Вместо этого — штатный CookieAuthentication: tor кладёт случайный
        # файл в СВОЙ каталог данных, и знает его только тот, кто может этот
        # каталог читать. Секрета в исходниках не остаётся вовсе.

        
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
                except Exception: pass
            return False

    def start(self, num_instances=1):
        if not self.check_and_download():
            return False
            
        self.stop() # Clean up old instances if any
        self.instances = []
        
        # Чистим ТОЛЬКО своё.
        #
        # Раньше здесь стоял `taskkill /F /IM tor.exe` — то есть глушился
        # каждый tor.exe на машине, включая Tor Browser владельца и чужие
        # программы. Свои процессы уже остановлены вызовом self.stop() строкой
        # выше; здесь добиваем осиротевшие от прошлого запуска — по номерам,
        # которые сами же и записали.
        self._kill_orphans()
            
        self._log(f"[Система] Запуск {num_instances} процессов Tor (через Snowflake)...", "info")
        
        def start_instance(idx):
            # Stagger startup to avoid hammering the Snowflake broker simultaneously
            time.sleep(idx * 6.0)
            
            for attempt in range(2): # 2 attempts per instance
                inst = TorInstance(idx, self.base_dir, self.tor_exe,
                                   self.log_callback)
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
            t = threading.Thread(target=start_instance, args=(i,), daemon=True)
            t.start()
            threads.append(t)
            
        for t in threads:
            t.join()
            
        if len(self.instances) > 0:
            self._remember_pids()
            self._log(f"[Система] {len(self.instances)}/{num_instances} Tor-узлов успешно запущены!", "success")
            return True
        else:
            self._log("[DEAD] Не удалось запустить ни одного процесса Tor.", "dead")
            return False

    def _pid_file(self):
        return self.tor_dir / "our_tor_pids.json"

    def _remember_pids(self):
        """Записывает номера ЗАПУЩЕННЫХ НАМИ процессов рядом с ними.

        Нужно ровно для одного: следующий запуск должен уметь добить то, что
        осталось от прошлого после падения, и при этом не тронуть чужое.
        """
        pids = [inst.process.pid for inst in self.instances
                if getattr(inst, "process", None) is not None]
        try:
            self._pid_file().parent.mkdir(parents=True, exist_ok=True)
            self._pid_file().write_text(json.dumps(pids), encoding="utf-8")
        except Exception:
            pass

    def _kill_orphans(self):
        """Добивает наши же процессы, пережившие прошлый запуск."""
        try:
            pids = json.loads(self._pid_file().read_text(encoding="utf-8"))
        except Exception:
            return
        if not isinstance(pids, list):
            return
        killed = 0
        for pid in pids:
            if not isinstance(pid, int):
                continue
            try:
                import psutil

                proc = psutil.Process(pid)
                # Имя проверяем обязательно: номер мог достаться чужой
                # программе после перезагрузки, и убить её было бы хуже, чем
                # оставить осиротевший tor.
                if "tor" not in (proc.name() or "").lower():
                    continue
                for child in proc.children(recursive=True):
                    try:
                        child.kill()
                    except Exception:
                        pass
                proc.kill()
                killed += 1
            except Exception:
                continue
        if killed:
            self._log(f"[Система] Добито осиротевших процессов Tor: {killed}", "info")

    def renew_ip(self, proxy_url=None):
        alive = [inst for inst in self.instances if inst.is_alive()]
        if not alive: return False
        
        if proxy_url:
            try:
                port = int(proxy_url.split(":")[-1])
                for inst in alive:
                    if inst.tor_port == port:
                        return inst.renew_ip()
            except Exception: pass
            
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
