# -*- mode: python ; coding: utf-8 -*-
"""Сборка MailFact в папку (onedir). Одна спека на Windows, macOS и Linux.

ПОЧЕМУ onedir, А НЕ onefile. onefile при КАЖДОМ запуске распаковывает всю
сборку во временную папку: это секунды ожидания перед появлением окна и
частая ложная тревога у антивирусов, которым не нравится программа,
пишущая исполняемый код в %TEMP%. Установщик всё равно прячет структуру
папок от человека, поэтому выигрыша у onefile нет никакого.

ПОЧЕМУ spaCy ВНУТРИ, ХОТЯ ОН ТЯЖЁЛЫЙ. Он участвует в ОСНОВНОМ пути проверки:
`core/pipeline.py:457` спрашивает `is_person(name)` и по ответу отбрасывает
адрес. Выбросить spaCy ради размера значило бы молча изменить вердикты в
собранной программе по сравнению с запуском из исходников — то есть выдать
пользователю не ту программу, которую проверяли.

ПРО ТРИ ПЛАТФОРМЫ. PyInstaller НЕ УМЕЕТ кросс-сборку: под каждую ОС собирает
она сама. Поэтому здесь одна спека с ветвлениями, а три сборки делают три
раннера в .github/workflows/release.yml.

Что различается по платформам и почему:

  * Windows — движок окна WebView2 через pythonnet (`clr`). На macOS и Linux
    такого модуля нет вовсе, и просить его в hiddenimports значит уронить
    сборку на ровном месте.
  * macOS — иконка формата .icns и обёртка .app (BUNDLE). WKWebView встроен
    в саму ОС, доставлять нечего.
  * Linux — движка окна в системе может не быть ни одного. Бэкенд Qt берётся
    внутрь сборки, чтобы программа не требовала системных пакетов.
"""
import sys

from PyInstaller.utils.hooks import collect_all

ИМЯ = "MailFact"
ОКНА = sys.platform == "win32"
ЯБЛОКО = sys.platform == "darwin"
ПИНГВИН = sys.platform.startswith("linux")

datas = [
    ("assets", "assets"),
    ("VERSION", "."),
    # Разметка окна. Читается через core.paths.resource_path.
    ("ui/web", "ui/web"),
    # Поставляемые списки. Кладутся в сборку, а при первом запуске копируются
    # в пишущуюся data/ рядом с .exe (core.paths.seed_data): в самой сборке
    # им жить нельзя, BlacklistDownloader их перезаписывает.
    ("data/free_providers.txt", "data"),
    ("data/disposable.txt", "data"),
    ("data/disposable_extra.txt", "data"),
    ("data/disposable_more.txt", "data"),
    # Данные, лежащие внутри пакетов рядом с кодом.
    ("core/english_words.txt", "core"),
    ("core/parser/names_by_country.txt", "core/parser"),
    # Список публичных суффиксов Mozilla. Читается core/public_suffix.py и
    # решает, где кончается чужая зона и начинается чей-то домен. Без него
    # очистка перестанет узнавать настоящие зоны и снова начнёт резать
    # `mycompany.deloitte` до `mycompany.de` — см. core/public_suffix.py.
    ("core/public_suffix_list.dat", "core"),
]
binaries = []

# Импорты, которых PyInstaller не видит статическим анализом: они делаются
# лениво внутри функций либо подбираются по имени в рантайме.
hiddenimports = [
    # SOCKS-прокси для SMTP: импортируется как `socks` внутри функций.
    "socks",
    # dnspython подбирает обработчики типов записей по имени.
    "dns.rdtypes",
    "dns.rdtypes.ANY",
    "dns.rdtypes.IN",
    "dns.asyncresolver",
    # Определение числа потоков по железу — импортируется лениво.
    "psutil",
    # Возраст домена, когда прокси не заданы.
    "whois",
    # Поиск адресов: новое и старое имя одного пакета.
    "ddgs",
    "duckduckgo_search",
]

# Бэкенд окна — свой на каждой платформе.
if ОКНА:
    hiddenimports += ["webview.platforms.winforms",
                      "webview.platforms.edgechromium",
                      "clr"]
elif ЯБЛОКО:
    hiddenimports += ["webview.platforms.cocoa"]
elif ПИНГВИН:
    # Порядок важен: сначала Qt, потом GTK. Qt берётся внутрь сборки и
    # работает без системных пакетов, GTK — запасной путь для тех, у кого
    # WebKitGTK в системе уже есть.
    hiddenimports += ["webview.platforms.qt", "webview.platforms.gtk"]

# Пакеты, которые возят с собой данные (модели, словари, .json): без
# collect_all собранная программа падает на старте, не найдя своих файлов.
ПАКЕТЫ = ["webview", "names_dataset", "gender_guesser", "wordsegment",
          "spacy", "thinc", "en_core_web_sm", "srsly", "catalogue",
          "cymem", "preshed", "murmurhash", "blis", "wasabi", "weasel",
          "confection", "langcodes"]

# Пакеты, без которых программа НЕ ЗАПУСТИТСЯ на этой системе. Их отсутствие
# обязано ронять сборку, а не проходить мимо.
#
# ЗАМЕРЕНО на прогоне 1.1.5: раньше здесь стоял `except Exception: continue`
# на все пакеты подряд. PyQt6 в сборку не попал, PyInstaller не сказал ни
# слова, а Linux-сборка умерла у пользователя с «You must have either QT or
# GTK». Молчаливый пропуск тяжелее любого падения: падение видно сразу.
ОБЯЗАТЕЛЬНЫЕ = set()
if ПИНГВИН:
    # Движок окна для Linux целиком внутрь: иначе программа потребует
    # системный WebKitGTK, а «полноценно установить на любой ПК» означает
    # именно что ничего доставлять руками не надо.
    ПАКЕТЫ += ["PyQt6", "qtpy"]
    ОБЯЗАТЕЛЬНЫЕ |= {"PyQt6", "qtpy"}

for pkg in ПАКЕТЫ:
    try:
        d, b, h = collect_all(pkg)
    except Exception as беда:
        if pkg in ОБЯЗАТЕЛЬНЫЕ:
            raise SystemExit(
                "СБОРКА ОСТАНОВЛЕНА: пакет %s обязателен на этой системе, "
                "но собрать его не вышло: %s" % (pkg, беда))
        print("spec: необязательный пакет %s пропущен (%s)" % (pkg, беда))
        continue
    if pkg in ОБЯЗАТЕЛЬНЫЕ and not (d or b):
        raise SystemExit(
            "СБОРКА ОСТАНОВЛЕНА: пакет %s обязателен, но collect_all не дал "
            "ни одного файла — значит его нет в окружении" % pkg)
    datas += d
    binaries += b
    hiddenimports += h

a = Analysis(
    ["main.py"],
    pathex=["."],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    # Тяжёлое и ненужное, что тянется транзитивно. numpy НЕ исключаем: без
    # него не работает spaCy, а он в основном пути проверки.
    # ЗАМЕРЕНО на первой сборке: без этого списка dist весит 901.5 МБ, из них
    # torch 306 МБ, playwright 100.2 МБ, transformers 44 МБ, sklearn 18.2 МБ,
    # botocore 17.3 МБ. Ничего из этого программа не использует: thinc и spacy
    # объявляют torch/tensorflow/transformers НЕОБЯЗАТЕЛЬНЫМИ extras и грузят
    # их через try/except, а модели en_core_web_sm нужен только numpy+blis.
    # pycountry (20 МБ) НЕ исключаем: это настоящая зависимость names_dataset.
    excludes=["matplotlib", "scipy", "pandas", "pytest", "IPython", "jedi",
              "zmq", "tornado", "notebook", "jupyter", "PyQt5",
              "PySide2", "PySide6", "tkinter", "test", "unittest",
              "torch", "torchvision", "torchaudio", "tensorflow",
              "transformers", "spacy_transformers", "sklearn",
              "scikit_learn", "boto3", "botocore", "playwright",
              "huggingface_hub", "tokenizers", "safetensors", "datasets",
              "sentencepiece", "jax", "cupy", "PIL", "cv2"]
    # PyQt6 исключаем везде, КРОМЕ Linux: там он и есть движок окна.
    + ([] if ПИНГВИН else ["PyQt6"]),
    noarchive=False,
)
pyz = PYZ(a.pure)

# Иконка своя на каждой платформе. Linux иконку в исполняемый файл не
# вшивает вовсе — она берётся из .desktop-файла.
if ОКНА:
    иконка = "assets/MailFact.ico"
elif ЯБЛОКО:
    иконка = "assets/MailFact.icns"
else:
    иконка = None

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name=ИМЯ,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    # console=False: у окна на веб-стеке своего терминала быть не должно.
    console=False,
    disable_windowed_traceback=False,
    icon=иконка,
    # Ресурс версии — понятие Windows. На других платформах его нет.
    version="version_info.txt" if ОКНА else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name=ИМЯ,
)

if ЯБЛОКО:
    # .app — единственная форма, которую macOS считает программой: без неё
    # не будет ни иконки в Dock, ни запуска двойным кликом.
    app = BUNDLE(
        coll,
        name=ИМЯ + ".app",
        icon="assets/MailFact.icns",
        bundle_identifier="com.mailfact.app",
        info_plist={
            "CFBundleName": ИМЯ,
            "CFBundleDisplayName": ИМЯ,
            "CFBundleShortVersionString": open("VERSION").read().strip(),
            "CFBundleVersion": open("VERSION").read().strip(),
            # Окно рисуется, а не просто считает: без этого macOS запустит
            # программу как фоновую службу и окна не покажет.
            "LSBackgroundOnly": False,
            "NSHighResolutionCapable": True,
        },
    )
