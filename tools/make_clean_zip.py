# -*- coding: utf-8 -*-
import os
import sys
import zipfile

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

SYNTHETIC_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def make_clean_zip(src_dir, out_zip):
    src_dir = os.path.abspath(src_dir)
    if not os.path.isdir(src_dir):
        print(f"Directory not found: {src_dir}", file=sys.stderr)
        return False

    all_files = []
    for root, dirs, files in os.walk(src_dir):
        for f in files:
            full = os.path.join(root, f)
            rel = os.path.relpath(full, src_dir)
            all_files.append((rel, full))

    all_files.sort(key=lambda x: x[0].replace("\\", "/"))

    out_dir = os.path.dirname(os.path.abspath(out_zip))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        zf.comment = b""
        for rel_path, full_path in all_files:
            arcname = rel_path.replace("\\", "/")
            with open(full_path, "rb") as fh:
                data = fh.read()

            zinfo = zipfile.ZipInfo(filename=f"MailFact/{arcname}", date_time=SYNTHETIC_ZIP_TIME)
            zinfo.external_attr = 0o644 << 16
            if full_path.endswith(".exe") or full_path.endswith(".dll") or full_path.endswith(".pyd"):
                zinfo.external_attr = 0o755 << 16
            zinfo.extra = b""
            zinfo.comment = b""
            zf.writestr(zinfo, data)

    print(f"[OK] Создан чистый архив: {out_zip} ({len(all_files)} файлов)")
    return True


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else r"dist/MailFact"
    _ver_file = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "VERSION")
    _ver = open(_ver_file, encoding="utf-8").read().strip() if os.path.exists(_ver_file) else "0.0.0"
    out = sys.argv[2] if len(sys.argv) > 2 else f"dist/MailFact-v{_ver}-portable.zip"
    ok = make_clean_zip(src, out)
    sys.exit(0 if ok else 1)
