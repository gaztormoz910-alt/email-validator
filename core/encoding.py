import io
import os

__all__ = ["detect_encoding", "open_text", "read_sample"]

SAMPLE_BYTES = 65536

FALLBACK_ENCODING = "cp1251"

_BOMS = (
    (b"\xef\xbb\xbf", "utf-8-sig"),
    (b"\xff\xfe\x00\x00", "utf-32"),
    (b"\x00\x00\xfe\xff", "utf-32"),
    (b"\xff\xfe", "utf-16"),
    (b"\xfe\xff", "utf-16"),
)


def _is_path(path):
    return isinstance(path, (str, bytes, os.PathLike)) and not isinstance(path, bool)


def read_sample(path, size=SAMPLE_BYTES):
    if not _is_path(path):
        return b""
    try:
        with io.open(path, "rb") as handle:
            return handle.read(size)
    except (OSError, ValueError):
        return b""


def detect_encoding(path):
    sample = read_sample(path)
    if not sample:
        return "utf-8"

    for bom, name in _BOMS:
        if sample.startswith(bom):
            return name

    zeros_even = sample[0::2].count(0)
    zeros_odd = sample[1::2].count(0)
    half = max(1, len(sample) // 2)
    if zeros_odd > half * 0.3 and zeros_even < half * 0.05:
        return "utf-16-le"
    if zeros_even > half * 0.3 and zeros_odd < half * 0.05:
        return "utf-16-be"

    for cut in (0, 1, 2, 3):
        chunk = sample[:len(sample) - cut] if cut else sample
        try:
            chunk.decode("utf-8")
            return "utf-8"
        except UnicodeDecodeError:
            continue

    return FALLBACK_ENCODING


def open_text(path, encoding=None):
    if not _is_path(path):
        raise TypeError("нужен путь к файлу, получено %s" % type(path).__name__)
    return io.open(path, "r", encoding=encoding or detect_encoding(path),
                   errors="replace")
