# -*- mode: python ; coding: utf-8 -*-
"""Сборка MailFact в папку (onedir).

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
"""
from PyInstaller.utils.hooks import collect_all

ИМЯ = "MailFact"

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
]
binaries = []

# Импорты, которых PyInstaller не видит статическим анализом: они делаются
# лениво внутри функций либо подбираются по имени в рантайме.
hiddenimports = [
    # Движок окна. Бэкенд выбирается по платформе уже на старте.
    "webview.platforms.winforms",
    "webview.platforms.edgechromium",
    "clr",
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

# Пакеты, которые возят с собой данные (модели, словари, .json): без
# collect_all собранная программа падает на старте, не найдя своих файлов.
for pkg in ("webview", "names_dataset", "gender_guesser", "wordsegment",
            "spacy", "thinc", "en_core_web_sm", "srsly", "catalogue",
            "cymem", "preshed", "murmurhash", "blis", "wasabi", "weasel",
            "confection", "langcodes"):
    try:
        d, b, h = collect_all(pkg)
    except Exception:
        # Необязательный пакет мог не встать. Пропускаем молча здесь, но
        # tools/check_deps.py потом сверит фактические импорты со сборкой и
        # скажет вслух, если чего-то не хватает.
        continue
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
              "zmq", "tornado", "notebook", "jupyter", "PyQt5", "PyQt6",
              "PySide2", "PySide6", "tkinter", "test", "unittest",
              "torch", "torchvision", "torchaudio", "tensorflow",
              "transformers", "spacy_transformers", "sklearn",
              "scikit_learn", "boto3", "botocore", "playwright",
              "huggingface_hub", "tokenizers", "safetensors", "datasets",
              "sentencepiece", "jax", "cupy", "PIL", "cv2"],
    noarchive=False,
)
pyz = PYZ(a.pure)

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
    # console=False: у окна на WebView2 своего терминала быть не должно.
    console=False,
    disable_windowed_traceback=False,
    icon="assets/MailFact.ico",
    version="version_info.txt",
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
