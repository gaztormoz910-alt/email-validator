# -*- mode: python ; coding: utf-8 -*-
import sys

from PyInstaller.utils.hooks import collect_all

ИМЯ = "MailFact"
ОКНА = sys.platform == "win32"
ЯБЛОКО = sys.platform == "darwin"
ПИНГВИН = sys.platform.startswith("linux")

datas = [
    ("assets", "assets"),
    ("VERSION", "."),
    ("ui/web", "ui/web"),
    ("data/free_providers.txt", "data"),
    ("data/disposable.txt", "data"),
    ("data/disposable_extra.txt", "data"),
    ("data/disposable_more.txt", "data"),
    ("core/english_words.txt", "core"),
    ("core/parser/names_by_country.txt", "core/parser"),
    ("core/parser/name_trigrams.txt", "core/parser"),
    ("core/parser/name_clusters.txt", "core/parser"),
    ("core/public_suffix_list.dat", "core"),
]
binaries = []

hiddenimports = [
    "socks",
    "dns.rdtypes",
    "dns.rdtypes.ANY",
    "dns.rdtypes.IN",
    "dns.asyncresolver",
    "psutil",
    "whois",
    "ddgs",
    "duckduckgo_search",
]

if ОКНА:
    hiddenimports += ["webview.platforms.winforms",
                      "webview.platforms.edgechromium",
                      "clr"]
elif ЯБЛОКО:
    hiddenimports += ["webview.platforms.cocoa"]
elif ПИНГВИН:
    hiddenimports += ["webview.platforms.qt", "webview.platforms.gtk"]

ПАКЕТЫ = ["webview", "names_dataset", "gender_guesser", "wordsegment",
          "spacy", "thinc", "en_core_web_sm", "srsly", "catalogue",
          "cymem", "preshed", "murmurhash", "blis", "wasabi", "weasel",
          "confection", "langcodes"]

ОБЯЗАТЕЛЬНЫЕ = set()
if ПИНГВИН:
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
    excludes=["matplotlib", "scipy", "pandas", "pytest", "IPython", "jedi",
              "zmq", "tornado", "notebook", "jupyter", "PyQt5",
              "PySide2", "PySide6", "tkinter", "test", "unittest",
              "torch", "torchvision", "torchaudio", "tensorflow",
              "transformers", "spacy_transformers", "sklearn",
              "scikit_learn", "boto3", "botocore", "playwright",
              "huggingface_hub", "tokenizers", "safetensors", "datasets",
              "sentencepiece", "jax", "cupy", "PIL", "cv2"]
    + ([] if ПИНГВИН else ["PyQt6"]),
    noarchive=False,
)
pyz = PYZ(a.pure)

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
    console=False,
    disable_windowed_traceback=False,
    icon=иконка,
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

if ОКНА:
    exe_standalone = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name=ИМЯ + "-standalone",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,
        disable_windowed_traceback=False,
        icon=иконка,
        version="version_info.txt",
    )

if ЯБЛОКО:
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
            "LSBackgroundOnly": False,
            "NSHighResolutionCapable": True,
        },
    )
