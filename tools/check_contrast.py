#!/usr/bin/env python
"""Проверка контраста палитры по WCAG 2.1.

Зачем это в проекте, а не «на глаз». Тёмная тема легко выглядит стильной и
при этом не читается: серый текст на почти чёрном фоне кажется аккуратным
дизайнеру со свежими глазами на хорошем мониторе — и пропадает у того, кто
сидит перед окном восемь часов или смотрит на дешёвую матрицу.

WCAG задаёт порог, который можно ПОСЧИТАТЬ:

    4.5:1 — обычный текст (AA)
    3.0:1 — крупный текст от 18pt / 14pt жирного, а также границы и иконки
    7.0:1 — повышенный уровень (AAA)

Считается по относительной яркости sRGB (WCAG 2.1, определение
relative luminance). Формула не приблизительная — это ровно то, чем меряют
соответствие.

Запуск:
    python tools/check_contrast.py          палитра окна на CustomTkinter
    python tools/check_contrast.py --web    палитра окна на веб-стеке
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

AA_NORMAL = 4.5
AA_LARGE = 3.0


def _srgb_channel(value):
    """Линеаризация канала sRGB по WCAG 2.1."""
    c = value / 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def luminance(hex_color):
    """Относительная яркость цвета (0 — чёрный, 1 — белый)."""
    value = hex_color.lstrip("#")
    if len(value) == 3:
        value = "".join(ch * 2 for ch in value)
    r, g, b = (int(value[i:i + 2], 16) for i in (0, 2, 4))
    return (0.2126 * _srgb_channel(r)
            + 0.7152 * _srgb_channel(g)
            + 0.0722 * _srgb_channel(b))


def contrast(fg, bg):
    """Коэффициент контраста двух цветов: от 1:1 до 21:1."""
    a, b = luminance(fg), luminance(bg)
    lighter, darker = max(a, b), min(a, b)
    return (lighter + 0.05) / (darker + 0.05)


def web_palette():
    """Переменные палитры читаются прямо из style.css.

    Не копия в этом файле: копия расходится с оформлением молча, и проверка
    начинает подтверждать цвета, которых на экране уже нет.
    """
    import re

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                        "ui", "web", "style.css")
    with io.open(path, encoding="utf-8") as handle:
        css = handle.read()
    root = re.search(r":root\s*\{(.*?)\}", css, re.S)
    if not root:
        raise SystemExit("в style.css нет блока :root — палитру негде взять")
    found = dict(re.findall(r"(--[\w-]+)\s*:\s*(#[0-9A-Fa-f]{3,6})\s*;", root.group(1)))
    if not found:
        raise SystemExit("в :root не нашлось ни одного цвета")
    return found


def web_pairs():
    """Пары «что на чём лежит» — сняты с настоящей разметки страницы."""
    v = web_palette()

    def c(name):
        try:
            return v[name]
        except KeyError:
            raise SystemExit("в палитре нет переменной %s" % name)

    return [
        ("Основной текст на фоне окна", c("--text"), c("--bg"), AA_NORMAL),
        ("Основной текст на панели", c("--text"), c("--bg-elev"), AA_NORMAL),
        ("Основной текст на карточке", c("--text"), c("--surface"), AA_NORMAL),
        ("Основной текст в поле", c("--text"), c("--surface-2"), AA_NORMAL),
        ("Основной текст на наведённой строке", c("--text"), c("--hover"), AA_NORMAL),
        ("Вторичный текст на фоне окна", c("--text-2"), c("--bg"), AA_NORMAL),
        ("Вторичный текст на панели", c("--text-2"), c("--bg-elev"), AA_NORMAL),
        ("Вторичный текст на карточке", c("--text-2"), c("--surface"), AA_NORMAL),
        ("Приглушённый текст на фоне окна", c("--text-3"), c("--bg"), AA_NORMAL),
        ("Приглушённый текст на карточке", c("--text-3"), c("--surface"), AA_NORMAL),
        ("Приглушённый текст на панели", c("--text-3"), c("--bg-elev"), AA_NORMAL),
        ("Текст на кнопке запуска", c("--on-accent"), c("--accent"), AA_NORMAL),
        ("Текст на светлом акценте", c("--on-accent"), c("--accent-2"), AA_NORMAL),
        ("Текст на зелёной заливке", c("--on-ok"), c("--ok"), AA_NORMAL),
        ("Текст на жёлтой заливке", c("--on-warn"), c("--warn"), AA_NORMAL),
        ("Акцент на фоне окна", c("--accent"), c("--bg"), AA_LARGE),
        ("Акцент на карточке", c("--accent"), c("--surface"), AA_LARGE),
        ("Зелёный вердикт на карточке", c("--ok"), c("--surface"), AA_LARGE),
        ("Красный вердикт на карточке", c("--bad"), c("--surface"), AA_LARGE),
        ("Жёлтый вердикт на карточке", c("--warn"), c("--surface"), AA_LARGE),
        ("Фиолетовый вердикт на карточке", c("--violet"), c("--surface"), AA_LARGE),
        ("Зелёный в терминале", c("--ok"), c("--bg"), AA_LARGE),
        ("Красный в терминале", c("--bad"), c("--bg"), AA_LARGE),
        ("Жёлтый в терминале", c("--warn"), c("--bg"), AA_LARGE),
        ("Заметная граница на карточке", c("--border-str"), c("--surface"), 1.2),
        ("Граница на панели", c("--border"), c("--bg-elev"), 1.1),
    ]


def desktop_pairs():
    from ui import colors as C


    # Пары «что на чём лежит» — взяты из настоящей разметки, а не выдуманы.
    # Третий элемент — требуемый порог: у крупного текста и границ он ниже.
    PAIRS = [
        ("Основной текст на фоне окна", C.TEXT_MAIN, C.BG_MAIN, AA_NORMAL),
        ("Основной текст на панели", C.TEXT_MAIN, C.BG_SIDEBAR, AA_NORMAL),
        ("Основной текст на карточке", C.TEXT_MAIN, C.BG_CARD_1, AA_NORMAL),
        ("Основной текст в поле ввода", C.TEXT_MAIN, C.BG_CARD_2, AA_NORMAL),
        ("Приглушённый текст на фоне окна", C.TEXT_MUTED, C.BG_MAIN, AA_NORMAL),
        ("Приглушённый текст на панели", C.TEXT_MUTED, C.BG_SIDEBAR, AA_NORMAL),
        ("Приглушённый текст на карточке", C.TEXT_MUTED, C.BG_CARD_1, AA_NORMAL),
        ("Подсказка на панели", C.TEXT_DIM, C.BG_SIDEBAR, AA_NORMAL),
        ("Подсказка на карточке", C.TEXT_DIM, C.BG_CARD_1, AA_NORMAL),
        ("Текст на кнопке действия", C.TEXT_ON_ACCENT, C.ACCENT_PRIMARY, AA_NORMAL),
        ("Текст на жёлтой кнопке", C.TEXT_ON_WARNING, C.ACCENT_WARNING, AA_NORMAL),
        ("Зелёный статус на карточке", C.ACCENT_SUCCESS, C.BG_CARD_1, AA_LARGE),
        ("Красный статус на карточке", C.ACCENT_ERROR, C.BG_CARD_1, AA_LARGE),
        ("Жёлтый статус на карточке", C.ACCENT_WARNING, C.BG_CARD_1, AA_LARGE),
        ("Зелёный в терминале", C.ACCENT_SUCCESS, C.BG_CARD_2, AA_LARGE),
        ("Красный в терминале", C.ACCENT_ERROR, C.BG_CARD_2, AA_LARGE),
        ("Жёлтый в терминале", C.ACCENT_WARNING, C.BG_CARD_2, AA_LARGE),
        ("Акцент на фоне окна", C.ACCENT_PRIMARY, C.BG_MAIN, AA_LARGE),
        ("Граница на панели", C.BORDER_STRONG, C.BG_SIDEBAR, 1.2),
        ("Заголовок таблицы", C.TEXT_MUTED, C.BG_TABLE_HEADER, AA_NORMAL),
        ("Текст выделенной строки", C.TEXT_MAIN, C.BG_SELECTED, AA_NORMAL),
    ]

    return PAIRS


def report(title, pairs):
    failed = []
    print(title)
    print(f"{'пара':44s} {'контраст':>9s}  {'порог':>6s}")
    print("-" * 70)
    for name, fg, bg, need in pairs:
        ratio = contrast(fg, bg)
        ok = ratio >= need
        mark = "" if ok else "   <-- НИЖЕ ПОРОГА"
        if not ok:
            failed.append((name, ratio, need))
        print(f"{name:44s} {ratio:8.2f}:1  {need:5.1f}:1{mark}")

    print()
    if failed:
        print(f"Не проходят WCAG: {len(failed)} из {len(pairs)}")
        for name, ratio, need in failed:
            print(f"  {name}: {ratio:.2f}:1 при требуемых {need}:1")
        print("CONTRAST-FAIL")
        return 1
    print(f"Все {len(pairs)} пар проходят WCAG AA.")
    print("CONTRAST-OK")
    return 0


def main():
    if "--web" in sys.argv:
        return report("Палитра окна на веб-стеке (ui/web/style.css)", web_pairs())
    return report("Палитра окна на CustomTkinter (ui/colors.py)", desktop_pairs())


if __name__ == "__main__":
    sys.exit(main())
