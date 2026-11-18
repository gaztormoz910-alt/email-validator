# tools/sanitize_pe.py
"""Нормализует PE-таймстемпы к единой синтетической константе (1980-01-01 UTC).

Раздел 6 «Промпт-очистки-метаданных»:
- FILE_HEADER.TimeDateStamp
- DIRECTORY_ENTRY_DEBUG[*].struct.TimeDateStamp
- DIRECTORY_ENTRY_EXPORT.struct.TimeDateStamp
- DIRECTORY_ENTRY_RESOURCE TimeDateStamp
- Пересчёт OPTIONAL_HEADER.CheckSum
"""
import sys
import os
import pefile

SYNTHETIC_TIMESTAMP = 0x12cea600  # 1980-01-01 00:00:00 UTC


def sanitize_pe(path, timestamp=SYNTHETIC_TIMESTAMP):
    if not os.path.exists(path):
        print(f"File not found: {path}", file=sys.stderr)
        return False

    with open(path, "rb") as f:
        data = bytearray(f.read())

    pe = pefile.PE(data=data, fast_load=False)

    changed = 0

    # 1. FILE_HEADER
    if pe.FILE_HEADER.TimeDateStamp != timestamp:
        pe.FILE_HEADER.TimeDateStamp = timestamp
        changed += 1

    # 2. DEBUG
    for d in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []):
        if d.struct.TimeDateStamp != timestamp:
            d.struct.TimeDateStamp = timestamp
            changed += 1

    # 3. EXPORT
    export = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if export and export.struct.TimeDateStamp != timestamp:
        export.struct.TimeDateStamp = timestamp
        changed += 1

    # 4. RESOURCE
    resource = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
    if resource and resource.struct.TimeDateStamp != timestamp:
        resource.struct.TimeDateStamp = timestamp
        changed += 1

    # 5. Пересчёт контрольной суммы
    pe.OPTIONAL_HEADER.CheckSum = pe.generate_checksum()

    # Запись обратно
    new_data = pe.write()
    with open(path, "wb") as f:
        f.write(new_data)

    print(f"[OK] {path}: обновлено {changed} таймстемпов -> {hex(timestamp)}, CheckSum пересчитан ({hex(pe.OPTIONAL_HEADER.CheckSum)})")
    return True


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else r"dist/MailFact/MailFact.exe"
    sanitize_pe(target)
