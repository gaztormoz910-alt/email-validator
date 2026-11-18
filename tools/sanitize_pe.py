# tools/sanitize_pe.py
# -*- coding: utf-8 -*-
"""Нормализует PE-таймстемпы и контрольную сумму PE-заголовка IN-PLACE.

Безопасен для PyInstaller: не пересобирает секции и не двигает оверлей
(хвостовой архив PyInstaller), а точечно правит 4-байтовые поля в заголовках:
1. FILE_HEADER.TimeDateStamp -> 0x12cea600 (1980-01-01 00:00:00 UTC)
2. DIRECTORY_ENTRY_DEBUG[*].TimeDateStamp -> 0x12cea600
3. DIRECTORY_ENTRY_EXPORT.TimeDateStamp -> 0x12cea600
4. DIRECTORY_ENTRY_RESOURCE TimeDateStamp -> 0x12cea600
5. OPTIONAL_HEADER.CheckSum -> пересчитанная сумма по алгоритму PE.
"""
import os
import struct
import sys
import pefile

SYNTHETIC_TIMESTAMP = 0x12cea600  # 1980-01-01 00:00:00 UTC


def sanitize_pe(path, timestamp=SYNTHETIC_TIMESTAMP):
    if not os.path.exists(path):
        print(f"File not found: {path}", file=sys.stderr)
        return False

    with open(path, "rb") as f:
        data = bytearray(f.read())

    initial_len = len(data)
    pe = pefile.PE(data=data, fast_load=False)

    changed = 0

    # 1. FILE_HEADER.TimeDateStamp (offset +4 от начала FileHeader)
    fh_off = pe.FILE_HEADER.get_file_offset()
    tds_off = fh_off + 4
    old_tds = struct.unpack_from("<I", data, tds_off)[0]
    if old_tds != timestamp:
        struct.pack_into("<I", data, tds_off, timestamp)
        changed += 1

    # 2. DEBUG entries
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        try:
            d_off = d.struct.get_file_offset()
            # TimeDateStamp is at offset +4 in IMAGE_DEBUG_DIRECTORY
            struct.pack_into("<I", data, d_off + 4, timestamp)
            changed += 1
        except Exception:
            pass

    # 3. EXPORT entry
    export = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export and hasattr(export, "struct"):
        try:
            exp_off = export.struct.get_file_offset()
            # TimeDateStamp is at offset +4 in IMAGE_EXPORT_DIRECTORY
            struct.pack_into("<I", data, exp_off + 4, timestamp)
            changed += 1
        except Exception:
            pass

    # 4. RESOURCE directory
    resource = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if resource and hasattr(resource, "struct"):
        try:
            res_off = resource.struct.get_file_offset()
            # TimeDateStamp is at offset +4 in IMAGE_RESOURCE_DIRECTORY
            struct.pack_into("<I", data, res_off + 4, timestamp)
            changed += 1
        except Exception:
            pass

    # 5. CheckSum in OPTIONAL_HEADER
    # Offset of CheckSum is at +64 in both PE32 (offset 64) and PE32+ (offset 64).
    opt_off = pe.OPTIONAL_HEADER.get_file_offset()
    cs_off = opt_off + 64
    # Обнуляем контрольную сумму перед расчетом
    struct.pack_into("<I", data, cs_off, 0)

    # Пересчитываем контрольную сумму
    pe_recalc = pefile.PE(data=data, fast_load=True)
    new_checksum = pe_recalc.generate_checksum()
    struct.pack_into("<I", data, cs_off, new_checksum)

    assert len(data) == initial_len, "Длина файла изменилась, оверлей поврежден!"

    with open(path, "wb") as f:
        f.write(data)

    print(f"[OK] {path}: обновлено {changed} таймстемпов -> {hex(timestamp)}, CheckSum -> {hex(new_checksum)}")
    return True


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else r"dist/MailFact/MailFact.exe"
    sanitize_pe(target)
