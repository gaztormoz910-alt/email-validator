# -*- coding: utf-8 -*-
import ctypes
import os
import sys
import threading
import time

_ХЕНДЛЫ = []

LR_LOADFROMFILE = 0x0010
IMAGE_ICON = 1
WM_SETICON = 0x0080
WM_GETICON = 0x007F
ICON_SMALL = 0
ICON_BIG = 1
SM_CXSMICON = 49
SM_CXICON = 11


def is_windows():
    return sys.platform == "win32"


def set_app_user_model_id(app_id):
    if not is_windows():
        return False
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
        return True
    except Exception:
        return False


def _окна_процесса(pid):
    u = ctypes.windll.user32
    найдено = []
    ТИП = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

    def обход(hwnd, _):
        свой = ctypes.c_ulong()
        u.GetWindowThreadProcessId(ctypes.c_void_p(hwnd),
                                   ctypes.byref(свой))
        if свой.value == pid and u.IsWindowVisible(ctypes.c_void_p(hwnd)):
            длина = u.GetWindowTextLengthW(ctypes.c_void_p(hwnd))
            if длина > 0:
                найдено.append(hwnd)
        return True

    u.EnumWindows(ТИП(обход), 0)
    return найдено


def apply_window_icons(ico_path, hwnd=None):
    if not is_windows() or not ico_path or not os.path.exists(ico_path):
        return {}
    u = ctypes.windll.user32
    u.LoadImageW.restype = ctypes.c_void_p
    u.SendMessageW.restype = ctypes.c_void_p
    u.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                               ctypes.c_void_p, ctypes.c_void_p]
    if hwnd is None:
        окна = _окна_процесса(os.getpid())
        if not окна:
            return {}
        hwnd = окна[0]

    поставлено = {}
    for слот, метрика in ((ICON_SMALL, SM_CXSMICON), (ICON_BIG, SM_CXICON)):
        px = u.GetSystemMetrics(метрика)
        h = u.LoadImageW(None, str(ico_path), IMAGE_ICON, px, px,
                         LR_LOADFROMFILE)
        if not h:
            continue
        _ХЕНДЛЫ.append(h)
        u.SendMessageW(ctypes.c_void_p(hwnd), WM_SETICON,
                       ctypes.c_void_p(слот), ctypes.c_void_p(h))
        поставлено[слот] = px
    return поставлено


def apply_when_shown(ico_path, timeout=20.0, interval=0.25):
    if not is_windows():
        return None

    def ждать():
        предел = time.time() + timeout
        while time.time() < предел:
            окна = _окна_процесса(os.getpid())
            if окна and apply_window_icons(ico_path, окна[0]):
                return
            time.sleep(interval)

    поток = threading.Thread(target=ждать, daemon=True, name="icon-setter")
    поток.start()
    return поток


def window_icon_sizes(hwnd):
    if not is_windows():
        return {}
    u = ctypes.windll.user32
    g = ctypes.windll.gdi32
    u.SendMessageW.restype = ctypes.c_void_p
    u.SendMessageW.argtypes = [ctypes.c_void_p, ctypes.c_uint,
                               ctypes.c_void_p, ctypes.c_void_p]

    class ICONINFO(ctypes.Structure):
        _fields_ = [("fIcon", ctypes.c_int), ("xHotspot", ctypes.c_uint32),
                    ("yHotspot", ctypes.c_uint32),
                    ("hbmMask", ctypes.c_void_p),
                    ("hbmColor", ctypes.c_void_p)]

    class BITMAP(ctypes.Structure):
        _fields_ = [("bmType", ctypes.c_long), ("bmWidth", ctypes.c_long),
                    ("bmHeight", ctypes.c_long),
                    ("bmWidthBytes", ctypes.c_long),
                    ("bmPlanes", ctypes.c_ushort),
                    ("bmBitsPixel", ctypes.c_ushort),
                    ("bmBits", ctypes.c_void_p)]

    итог = {}
    for слот in (ICON_SMALL, ICON_BIG):
        h = u.SendMessageW(ctypes.c_void_p(hwnd), WM_GETICON,
                           ctypes.c_void_p(слот), ctypes.c_void_p(0))
        if not h:
            итог[слот] = None
            continue
        info = ICONINFO()
        if not u.GetIconInfo(ctypes.c_void_p(h), ctypes.byref(info)):
            итог[слот] = None
            continue
        bm = BITMAP()
        источник = info.hbmColor or info.hbmMask
        g.GetObjectW(ctypes.c_void_p(источник), ctypes.sizeof(BITMAP),
                     ctypes.byref(bm))
        высота = bm.bmHeight if info.hbmColor else bm.bmHeight // 2
        итог[слот] = (int(bm.bmWidth), int(высота))
        for b in (info.hbmMask, info.hbmColor):
            if b:
                g.DeleteObject(ctypes.c_void_p(b))
    return итог


def expected_icon_sizes():
    if not is_windows():
        return {}
    u = ctypes.windll.user32
    return {ICON_SMALL: u.GetSystemMetrics(SM_CXSMICON),
            ICON_BIG: u.GetSystemMetrics(SM_CXICON)}
