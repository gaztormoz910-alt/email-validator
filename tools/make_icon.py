# -*- coding: utf-8 -*-
import argparse
import os
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

import numpy as np
from PIL import Image

КОРЕНЬ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ИМЯ = "MailFact"

РАЗМЕРЫ = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]

РАЗМЕРЫ_MAC = [32, 64, 128, 256, 512, 1024]

РЕЗКОСТЬ = {16: (0.5, 0.45), 20: (0.5, 0.45), 24: (0.55, 0.40),
            32: (0.6, 0.35), 40: (0.6, 0.30), 48: (0.7, 0.25)}

ПОРОГ_АЛЬФЫ = 16


def _srgb_to_linear(a):
    return np.where(a <= 0.04045, a / 12.92, ((a + 0.055) / 1.055) ** 2.4)


def _linear_to_srgb(a):
    a = np.clip(a, 0.0, 1.0)
    return np.where(a <= 0.0031308, a * 12.92,
                    1.055 * np.power(a, 1 / 2.4) - 0.055)


def _гаусс_1d(радиус):
    сигма = max(float(радиус), 1e-6)
    предел = max(1, int(np.ceil(сигма * 3)))
    x = np.arange(-предел, предел + 1, dtype=np.float64)
    ядро = np.exp(-(x ** 2) / (2 * сигма ** 2))
    return ядро / ядро.sum()


def _размыть(поле, радиус):
    ядро = _гаусс_1d(радиус)
    поле_ = поле
    for ось in (1, 0):
        ширина = [(0, 0), (0, 0)]
        ширина[ось] = (len(ядро) // 2, len(ядро) // 2)
        добито = np.pad(поле_, ширина, mode="edge")
        поле_ = np.apply_along_axis(
            lambda м: np.convolve(м, ядро, mode="valid"), ось, добито)
    return поле_


def resize_linear(img, size):
    arr = np.asarray(img.convert("RGBA"), dtype=np.float64) / 255.0
    rgb, alpha = arr[..., :3], arr[..., 3]
    lin = _srgb_to_linear(rgb) * alpha[..., None]

    planes = []
    for ch in (lin[..., 0], lin[..., 1], lin[..., 2], alpha):
        f = Image.fromarray(ch.astype(np.float32), mode="F")
        planes.append(np.asarray(f.resize((size, size), Image.LANCZOS),
                                 dtype=np.float64))

    out_a = np.clip(planes[3], 0.0, 1.0)
    safe = np.where(out_a > 1e-6, out_a, 1.0)
    out_rgb = np.stack(planes[:3], axis=-1) / safe[..., None]
    out_rgb = np.where(out_a[..., None] > 1e-6, out_rgb, 0.0)

    параметры = РЕЗКОСТЬ.get(size)
    if параметры:
        радиус, сила = параметры
        размыто = np.stack([_размыть(out_rgb[..., i], радиус)
                            for i in range(3)], axis=-1)
        резко = out_rgb + сила * (out_rgb - размыто)
        w = out_a[..., None]
        было = float((out_rgb * w).sum())
        стало = float((np.clip(резко, 0.0, 1.0) * w).sum())
        if стало > 1e-9:
            резко = резко * (было / стало)
        out_rgb = np.clip(резко, 0.0, 1.0)

    data = np.concatenate([_linear_to_srgb(out_rgb), out_a[..., None]], axis=-1)
    return Image.fromarray(np.round(data * 255).astype(np.uint8), mode="RGBA")


def найти_мастер():
    свой = os.path.join(КОРЕНЬ, "assets", ИМЯ + ".png")
    if os.path.exists(свой):
        return свой
    raise SystemExit("исходник не найден: положите его в assets/%s.png" % ИМЯ)


def квадрат_по_альфе(img):
    img = img.convert("RGBA")
    альфа = np.asarray(img.split()[3], dtype=np.int32)
    видно = альфа > ПОРОГ_АЛЬФЫ
    if not видно.any():
        raise SystemExit("в картинке нет ни одного видимого пикселя")
    строки = np.where(видно.any(axis=1))[0]
    столбцы = np.where(видно.any(axis=0))[0]
    x0, x1 = int(столбцы[0]), int(столбцы[-1]) + 1
    y0, y1 = int(строки[0]), int(строки[-1]) + 1
    сторона = max(x1 - x0, y1 - y0)
    цx, цy = (x0 + x1) / 2.0, (y0 + y1) / 2.0
    лx, лy = int(round(цx - сторона / 2.0)), int(round(цy - сторона / 2.0))

    холст = Image.new("RGBA", (сторона, сторона), (0, 0, 0, 0))
    холст.paste(img, (-лx, -лy))
    print("  границы рисунка по альфе: x %d..%d, y %d..%d" % (x0, x1, y0, y1))
    print("  квадрат: сторона %d, левый верх (%d, %d)" % (сторона, лx, лy))
    return холст


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--src", default=None)
    args = p.parse_args()

    исходник = args.src or найти_мастер()
    print("исходник:", исходник)
    сырой = Image.open(исходник)
    print("  размер исходника: %dx%d, режим %s" % (сырой.width, сырой.height,
                                                   сырой.mode))

    мастер = квадрат_по_альфе(сырой)
    активы = os.path.join(КОРЕНЬ, "assets")
    os.makedirs(активы, exist_ok=True)
    путь_png = os.path.join(активы, ИМЯ + ".png")

    мастер.save(путь_png, format="PNG")
    print("мастер:", путь_png, "%dx%d" % (мастер.width, мастер.height))

    кадры = [resize_linear(мастер, s) for s in РАЗМЕРЫ]
    путь_ico = os.path.join(активы, ИМЯ + ".ico")
    кадры[-1].save(путь_ico, format="ICO",
                   sizes=[(s, s) for s in РАЗМЕРЫ],
                   append_images=кадры[:-1])

    внутри = sorted(Image.open(путь_ico).info.get("sizes", []))
    print("ico:", путь_ico)
    print("  размеров внутри: %d -> %s" % (len(внутри),
                                           [s[0] for s in внутри]))
    if [s[0] for s in внутри] != sorted(РАЗМЕРЫ):
        print("РАЗМЕРЫ НЕ СОШЛИСЬ")
        raise SystemExit(1)

    кадры_mac = {s: resize_linear(мастер, s) for s in РАЗМЕРЫ_MAC}
    путь_icns = os.path.join(активы, ИМЯ + ".icns")
    кадры_mac[1024].save(путь_icns, format="ICNS",
                         append_images=[кадры_mac[s] for s in РАЗМЕРЫ_MAC])
    проверка = Image.open(путь_icns)
    print("icns:", путь_icns)
    print("  размер верхнего кадра: %s, размеров отдано: %d"
          % (проверка.size, len(РАЗМЕРЫ_MAC)))
    if проверка.size[0] < 512:
        print("ICNS СОБРАН НЕ ТОГО РАЗМЕРА")
        raise SystemExit(1)

    print("MAKE_ICON_OK")


if __name__ == "__main__":
    main()
