# -*- coding: utf-8 -*-
import logging
import os
import sys

__all__ = [
    "install_webview_noise_filter",
    "WebViewReaper",
    "CHROMIUM_QUIET_FLAGS",
    "WEBVIEW_BUSY_HINT",
]

CHROMIUM_QUIET_FLAGS = "--log-level=3"

WEBVIEW_BUSY_HINT = (
    "Движок окна (WebView2) не смог занять свою папку профиля: её держит "
    "процесс от прошлого запуска. Окно откроется, но если оно ведёт себя "
    "странно — закройте программу и запустите заново. (HRESULT 0x800700AA)"
)

_ЗАЧИН = "webview2 initialization failed"

_ПРЕРВАНО = "0x80004004"
ЗАКРЫТО_ДО_ЗАПУСКА = ("Окно закрыто раньше, чем движок окна (WebView2) закончил "
                      "запуск. Это не ошибка. (HRESULT 0x80004004)")
_закрывается = False


def отметить_закрытие(*_):
    global _закрывается
    _закрывается = True


class _WebViewNoise(logging.Filter):

    def __init__(self, on_hint=None):
        logging.Filter.__init__(self)
        self.on_hint = on_hint
        self.перехвачено = 0

    def filter(self, record):
        try:
            текст = str(record.getMessage() or "")
        except Exception:
            return True
        if _ЗАЧИН not in текст.lower():
            return True
        self.перехвачено += 1
        if _закрывается and _ПРЕРВАНО in текст.lower():
            record.msg = ЗАКРЫТО_ДО_ЗАПУСКА
            record.args = ()
            record.levelno = logging.INFO
            record.levelname = "INFO"
            return True
        if "0x800700aa" in текст.lower() or "занят" in текст.lower():
            подсказка = WEBVIEW_BUSY_HINT
        else:
            первая = текст.split("\n")[1].strip() if "\n" in текст else текст
            подсказка = ("Движок окна (WebView2) сообщил об ошибке "
                         "инициализации: %s" % первая[:200])
        record.msg = подсказка
        record.args = ()
        record.levelno = logging.WARNING
        record.levelname = "WARNING"
        if callable(self.on_hint):
            try:
                self.on_hint(подсказка)
            except Exception:
                pass
        return True


def install_webview_noise_filter(on_hint=None, logger_name="pywebview"):
    logger = logging.getLogger(logger_name)
    for уже in logger.filters:
        if isinstance(уже, _WebViewNoise):
            уже.on_hint = on_hint or уже.on_hint
            return уже
    фильтр = _WebViewNoise(on_hint=on_hint)
    logger.addFilter(фильтр)
    return фильтр


class WebViewReaper(object):

    ИМЯ = "msedgewebview2"

    def __init__(self):
        self.до = set()
        self.снято = 0

    @staticmethod
    def _все_процессы():
        if sys.platform != "win32":
            return WebViewReaper._все_процессы_через_psutil()
        try:
            import ctypes
            from ctypes import wintypes

            class ЗАПИСЬ(ctypes.Structure):
                _fields_ = [
                    ("dwSize", wintypes.DWORD),
                    ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD),
                    ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long),
                    ("dwFlags", wintypes.DWORD),
                    ("szExeFile", wintypes.WCHAR * 260),
                ]

            k32 = ctypes.WinDLL("kernel32", use_last_error=True)
            k32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
            k32.Process32FirstW.argtypes = [wintypes.HANDLE,
                                            ctypes.POINTER(ЗАПИСЬ)]
            k32.Process32NextW.argtypes = [wintypes.HANDLE,
                                           ctypes.POINTER(ЗАПИСЬ)]

            TH32CS_SNAPPROCESS = 0x00000002
            INVALID = ctypes.c_void_p(-1).value
            снимок = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
            if not снимок or снимок == INVALID:
                return WebViewReaper._все_процессы_через_psutil()
            try:
                запись = ЗАПИСЬ()
                запись.dwSize = ctypes.sizeof(ЗАПИСЬ)
                найдено = {}
                ок = k32.Process32FirstW(снимок, ctypes.byref(запись))
                while ок:
                    найдено[int(запись.th32ProcessID)] = запись.szExeFile.lower()
                    ок = k32.Process32NextW(снимок, ctypes.byref(запись))
                return найдено
            finally:
                k32.CloseHandle(снимок)
        except Exception:
            return WebViewReaper._все_процессы_через_psutil()

    @staticmethod
    def _все_процессы_через_psutil():
        try:
            import psutil
        except Exception:
            return {}
        найдено = {}
        try:
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    найдено[int(proc.info["pid"])] = (proc.info.get("name") or "").lower()
                except Exception:
                    continue
        except Exception:
            return {}
        return найдено

    @staticmethod
    def _живые():
        return {pid for pid, имя in WebViewReaper._все_процессы().items()
                if WebViewReaper.ИМЯ in (имя or "")}

    def snapshot(self):
        self.до = self._живые()
        return len(self.до)

    def reap(self, grace=1.5):
        try:
            import psutil
        except Exception:
            return 0
        наши = self._живые() - self.до
        if not наши:
            return 0
        процессы = []
        for pid in наши:
            try:
                процессы.append(psutil.Process(pid))
            except Exception:
                continue
        for proc in процессы:
            try:
                proc.terminate()
            except Exception:
                pass
        живы = []
        try:
            _ушли, живы = psutil.wait_procs(процессы, timeout=grace)
        except Exception:
            живы = процессы
        for proc in живы:
            try:
                proc.kill()
            except Exception:
                pass
        self.снято = len(процессы)
        return self.снято


def quiet_chromium(environ=None):
    environ = os.environ if environ is None else environ
    key = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"
    current = environ.get(key, "")
    if CHROMIUM_QUIET_FLAGS in current:
        return current
    environ[key] = (current + " " + CHROMIUM_QUIET_FLAGS).strip()
    return environ[key]
