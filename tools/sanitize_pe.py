# -*- coding: utf-8 -*-
import os
import struct
import sys
import pefile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SYNTHETIC_TIMESTAMP = 0x12cea600

EPOCH_MTIME = 315532800  # 1980-01-01 00:00:00 UTC


def sanitize_pe(path, timestamp=SYNTHETIC_TIMESTAMP):
    if not os.path.exists(path):
        print(f"File not found: {path}", file=sys.stderr)
        return False

    with open(path, "rb") as f:
        data = bytearray(f.read())

    initial_len = len(data)
    pe = pefile.PE(data=data, fast_load=False)

    changed = 0

    fh_off = pe.FILE_HEADER.get_file_offset()
    tds_off = fh_off + 4
    old_tds = struct.unpack_from("<I", data, tds_off)[0]
    if old_tds != timestamp:
        struct.pack_into("<I", data, tds_off, timestamp)
        changed += 1

    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        try:
            d_off = d.struct.get_file_offset()
            struct.pack_into("<I", data, d_off + 4, timestamp)
            changed += 1
        except Exception:
            pass

    export = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export and hasattr(export, "struct"):
        try:
            exp_off = export.struct.get_file_offset()
            struct.pack_into("<I", data, exp_off + 4, timestamp)
            changed += 1
        except Exception:
            pass

    resource = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if resource and hasattr(resource, "struct"):
        try:
            res_off = resource.struct.get_file_offset()
            struct.pack_into("<I", data, res_off + 4, timestamp)
            changed += 1
        except Exception:
            pass

    opt_off = pe.OPTIONAL_HEADER.get_file_offset()
    cs_off = opt_off + 64
    struct.pack_into("<I", data, cs_off, 0)

    pe_recalc = pefile.PE(data=data, fast_load=True)
    new_checksum = pe_recalc.generate_checksum()
    struct.pack_into("<I", data, cs_off, new_checksum)

    assert len(data) == initial_len, "Длина файла изменилась, оверлей поврежден!"

    with open(path, "wb") as f:
        f.write(data)

    print(f"[OK] {path}: обновлено {changed} таймстемпов -> {hex(timestamp)}, CheckSum -> {hex(new_checksum)}")
    return True


def sanitize_dir_times(directory, epoch=EPOCH_MTIME):
    """Рекурсивно ставит mtime и atime всех файлов и папок на epoch.

    На Windows также правит CreationTime через SetFileTime (ctypes).
    Идемпотентна: повторный вызов ничего не меняет.
    """
    if not os.path.isdir(directory):
        print(f"Папка не найдена: {directory}", file=sys.stderr)
        return False

    if sys.platform == "win32":
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        FILE_WRITE_ATTRIBUTES = 0x0100
        FILE_SHARE_ALL = 0x07
        FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
        OPEN_EXISTING = 3
        INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

        class FILETIME(ctypes.Structure):
            _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]

        kernel32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        kernel32.CreateFileW.restype = wintypes.HANDLE
        kernel32.SetFileTime.argtypes = [
            wintypes.HANDLE, ctypes.POINTER(FILETIME),
            ctypes.POINTER(FILETIME), ctypes.POINTER(FILETIME),
        ]
        kernel32.SetFileTime.restype = wintypes.BOOL
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL

        _EPOCH_FILETIME = 11644473600
        ticks = (epoch + _EPOCH_FILETIME) * 10 ** 7
        ft = FILETIME(ticks & 0xFFFFFFFF, ticks >> 32)

        def _set_creation(path):
            handle = kernel32.CreateFileW(
                path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_ALL, None,
                OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, None)
            if handle is None or handle == INVALID_HANDLE_VALUE:
                return
            try:
                kernel32.SetFileTime(handle,
                                     ctypes.byref(ft),
                                     ctypes.byref(ft),
                                     ctypes.byref(ft))
            finally:
                kernel32.CloseHandle(handle)
    else:
        def _set_creation(_path):
            return None

    count = 0
    # Файлы и подпапки: обходим снизу вверх, чтобы mtime папки не менялся
    # после правки её детей
    for root, dirs, files in os.walk(directory, topdown=False):
        for name in files:
            path = os.path.join(root, name)
            os.utime(path, (epoch, epoch))
            if _set_creation:
                _set_creation(path)
            count += 1
        for name in dirs:
            path = os.path.join(root, name)
            os.utime(path, (epoch, epoch))
            if _set_creation:
                _set_creation(path)
            count += 1
    # Сама корневая папка
    os.utime(directory, (epoch, epoch))
    if _set_creation:
        _set_creation(directory)
    count += 1

    print(f"[OK] {directory}: {count} объектов -> mtime/atime/ctime = {epoch} ({hex(epoch)})")
    return True


def verify_dir_times(directory, epoch=EPOCH_MTIME):
    """Проверяет, что mtime (и CreationTime на Windows) всех файлов в дереве равны epoch."""
    bad = []
    for root, dirs, files in os.walk(directory):
        for name in files + dirs:
            path = os.path.join(root, name)
            try:
                st = os.stat(path)
                mt = int(st.st_mtime)
            except OSError:
                continue
            if mt != epoch:
                bad.append((os.path.relpath(path, directory), f"mtime={mt}"))
                continue
            bt = getattr(st, "st_birthtime", None)
            if bt is not None and int(bt) != epoch:
                bad.append((os.path.relpath(path, directory), f"ctime={int(bt)}"))
    if bad:
        print(f"[FAIL] {len(bad)} объектов с неверным временем:")
        for path, why in bad[:20]:
            print(f"  {path}: {why} (ожидалось {epoch})")
        return False
    print(f"[OK] все файлы и папки в {directory} имеют время = {epoch}")
    return True


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="Sanitize PE timestamps / directory file times")
    p.add_argument("target", nargs="?", default=r"dist/MailFact/MailFact.exe",
                   help="PE file or directory (with --dir-times)")
    p.add_argument("--dir-times", action="store_true",
                   help="Рекурсивно обнулить mtime/atime/ctime всех файлов")
    p.add_argument("--verify-times", action="store_true",
                   help="Проверить, что все mtime равны epoch")
    p.add_argument("--epoch", type=int, default=EPOCH_MTIME,
                   help=f"Unix epoch для файловых времён (default: {EPOCH_MTIME})")
    a = p.parse_args()

    if a.verify_times:
        ok = verify_dir_times(a.target, a.epoch)
    elif a.dir_times:
        ok = sanitize_dir_times(a.target, a.epoch)
    else:
        ok = sanitize_pe(a.target)
    sys.exit(0 if ok else 1)
