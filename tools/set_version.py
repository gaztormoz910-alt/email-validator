# -*- coding: utf-8 -*-
import os
import re
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ИМЯ = "MailFact"
ФАЙЛ_ВЕРСИИ = os.path.join(КОРЕНЬ, "VERSION")
ФАЙЛ_РЕСУРСА = os.path.join(КОРЕНЬ, "version_info.txt")

ШАБЛОН = """# Сгенерировано tools/set_version.py — руками не править.
# Windows требует РОВНО четыре числа: 1.0.0 превращается в (1, 0, 0, 0).
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={четвёрка},
    prodvers={четвёрка},
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo([
      StringTable(
        '040904B0',
        [StringStruct('CompanyName', '{имя}'),
         StringStruct('FileDescription', 'MailFact — проверка существования почтовых ящиков'),
         StringStruct('FileVersion', '{версия}'),
         StringStruct('InternalName', '{имя}'),
         StringStruct('OriginalFilename', '{имя}.exe'),
         StringStruct('ProductName', '{имя}'),
         StringStruct('ProductVersion', '{версия}')])
    ]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
"""


def нормализовать(версия):
    версия = версия.strip().lstrip("vV").strip()
    if not re.fullmatch(r"\d+(\.\d+){0,3}", версия):
        raise SystemExit("непонятный номер версии: %r (ждём 1.0 или 1.0.0)"
                         % версия)
    части = [int(x) for x in версия.split(".")]
    while len(части) < 4:
        части.append(0)
    return версия, tuple(части[:4])


def main():
    if len(sys.argv) > 1:
        сырая = sys.argv[1]
    else:
        if not os.path.exists(ФАЙЛ_ВЕРСИИ):
            raise SystemExit("нет файла VERSION и номер не передан")
        with open(ФАЙЛ_ВЕРСИИ, encoding="utf-8") as f:
            сырая = f.read()

    версия, четвёрка = нормализовать(сырая)

    with open(ФАЙЛ_ВЕРСИИ, "w", encoding="utf-8", newline="") as f:
        f.write(версия)

    with open(ФАЙЛ_РЕСУРСА, "w", encoding="utf-8", newline="\n") as f:
        f.write(ШАБЛОН.format(четвёрка=четвёрка, версия=версия, имя=ИМЯ))

    print("VERSION        -> %s" % версия)
    print("version_info   -> %s" % (четвёрка,))
    print("файлы: %s, %s" % (ФАЙЛ_ВЕРСИИ, ФАЙЛ_РЕСУРСА))
    print("SET_VERSION_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
