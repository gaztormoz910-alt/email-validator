# -*- coding: utf-8 -*-
import io
import lzma
import os
import struct
import zipfile
import zlib

import pytest

from tools import check_privacy as cp

ВЫДУМАННЫЙ = "Zx9-canary-SLED"


def _иглы(*строки):
    return cp.иглы({"свой маркер": set(строки)})


def _папка(tmp_path, файлы):
    корень = tmp_path / "dist"
    for имя, данные in файлы.items():
        путь = корень / имя
        путь.parent.mkdir(parents=True, exist_ok=True)
        путь.write_bytes(данные)
    return str(корень)


@pytest.fixture(autouse=True)
def _не_на_сервере_github(monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("MAILFACT_PRIVATE_MARKERS", raising=False)


def test_домашняя_папка_попадает_в_маркеры_во_всех_написаниях():
    м = cp.маркеры_машины()
    дом = os.path.normpath(os.path.expanduser("~"))
    формы = м["домашняя папка того, кто собирал"]
    assert дом in формы
    assert дом.replace("\\", "/") in формы


def test_короткий_маркер_не_берётся():
    м = cp.маркеры_машины(свои=["PC", ВЫДУМАННЫЙ])
    assert "PC" not in м.get("свой маркер", set())
    assert ВЫДУМАННЫЙ in м["свой маркер"]


def test_маркер_из_окружения(monkeypatch):
    monkeypatch.setenv("MAILFACT_PRIVATE_MARKERS", "первый-маркер;второй-маркер")
    м = cp.маркеры_машины()
    assert {"первый-маркер", "второй-маркер"} <= м["свой маркер"]


def test_на_сервере_github_домашняя_папка_не_маркер(monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    м = cp.маркеры_машины()
    assert "домашняя папка того, кто собирал" not in м
    assert os.path.normpath(cp.КОРЕНЬ) in м["папка проекта на машине сборки"]


def test_свой_маркер_не_печатается_никогда(tmp_path, capsys):
    секрет = "Fam1lia-Sekret"
    папка = _папка(tmp_path, {"MailFact.exe": b"MZ path " + секрет.encode() + b" tail"})
    assert cp.main(["--dist", папка, "--marker", секрет]) == 1
    вывод = capsys.readouterr().out
    assert секрет.lower() not in вывод.lower()
    assert "значение скрыто" in вывод and "где: MailFact.exe" in вывод


def test_на_сервере_github_свои_маркеры_скрываются_до_вывода(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("MAILFACT_PRIVATE_MARKERS", "alpha-one;beta-two")
    папка = _папка(tmp_path, {"a.txt": b"clean"})
    cp.main(["--dist", папка])
    строки = capsys.readouterr().out.splitlines()
    assert строки[:2] == ["::add-mask::alpha-one", "::add-mask::beta-two"]


@pytest.mark.parametrize("данные", [
    ("путь: C:\\Users\\%s\\x" % ВЫДУМАННЫЙ).encode("utf-8"),
    ("путь: C:/Users/%s/x" % ВЫДУМАННЫЙ).encode("utf-8"),
    ("\x00\x00%s\x00" % ВЫДУМАННЫЙ).encode("utf-16-le"),
    ("РЕГИСТР: %s" % ВЫДУМАННЫЙ.upper()).encode("utf-8"),
], ids=["обратные", "прямые", "utf16", "регистр"])
def test_находит_маркер_в_любой_форме(tmp_path, данные):
    папка = _папка(tmp_path, {"_internal/lib.dll": b"MZ\x90\x00" + данные})
    отчёт = cp.Отчёт()
    cp.проверить_папку(папка, _иглы(ВЫДУМАННЫЙ), отчёт)
    assert [н[2] for н in отчёт.находки] == ["_internal/lib.dll"]


def test_находит_кириллический_маркер_в_cp1251(tmp_path):
    маркер = "Пользователь-Сборщик"
    папка = _папка(tmp_path, {"a.bin": ("C:\\Users\\" + маркер).encode("cp1251")})
    отчёт = cp.Отчёт()
    cp.проверить_папку(папка, _иглы(маркер), отчёт)
    assert len(отчёт.находки) == 1


def test_находит_маркер_внутри_сжатого_zip(tmp_path):
    буфер = io.BytesIO()
    with zipfile.ZipFile(буфер, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("pkg/mod.pyc", b"\x00" * 100 + ВЫДУМАННЫЙ.encode() + b"\x00" * 100)
    папка = _папка(tmp_path, {"_internal/base_library.zip": буфер.getvalue()})
    отчёт = cp.Отчёт()
    cp.проверить_папку(папка, _иглы(ВЫДУМАННЫЙ), отчёт)
    assert [н[2] for н in отчёт.находки] == ["_internal/base_library.zip!pkg/mod.pyc"]


def test_чистая_папка_чиста(tmp_path):
    папка = _папка(tmp_path, {"a.txt": b"nothing here", "b/c.bin": b"\x00\x01\x02"})
    отчёт = cp.Отчёт()
    cp.проверить_папку(папка, _иглы(ВЫДУМАННЫЙ), отчёт)
    assert отчёт.находки == [] and отчёт.не_разобрано == []
    assert отчёт.счётчики["файлов"] == 2


def test_битый_zip_не_чистый_а_неразобранный(tmp_path):
    папка = _папка(tmp_path, {"x.zip": b"PK\x03\x04" + b"\xff" * 50})
    отчёт = cp.Отчёт()
    cp.проверить_папку(папка, _иглы(ВЫДУМАННЫЙ), отчёт)
    assert отчёт.не_разобрано


def test_без_исполняемого_файла_ответ_не_чисто(tmp_path, capsys):
    папка = _папка(tmp_path, {"a.txt": b"clean"})
    assert cp.main(["--dist", папка]) == 2
    assert "PRIVACY-CLEAN" not in capsys.readouterr().out


def test_находка_даёт_код_1(tmp_path, capsys):
    папка = _папка(tmp_path, {"MailFact.exe": b"MZ" + ВЫДУМАННЫЙ.encode()})
    assert cp.main(["--dist", папка, "--marker", ВЫДУМАННЫЙ]) == 1
    вывод = capsys.readouterr().out
    assert "НАЙДЕНЫ СЛЕДЫ" in вывод and "PRIVACY-CLEAN" not in вывод


def test_не_установщик_не_объявляется_чистым(tmp_path, capsys):
    мусор = tmp_path / "setup.exe"
    мусор.write_bytes(b"MZ" + os.urandom(4096))
    assert cp.main(["--installer", str(мусор)]) == 2
    assert "PRIVACY-CLEAN" not in capsys.readouterr().out


def _блок_inno(полезное):
    lc, lp, pb, словарь = 3, 0, 2, 1 << 16
    сжатое = lzma.compress(полезное, format=lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA1, "lc": lc, "lp": lp, "pb": pb, "dict_size": словарь}])
    сырое = bytes([(pb * 5 + lp) * 9 + lc]) + struct.pack("<I", словарь) + сжатое
    куски = b""
    for i in range(0, len(сырое), 4096):
        кусок = сырое[i:i + 4096]
        куски += struct.pack("<I", zlib.crc32(кусок)) + кусок
    шапка = struct.pack("<IB", len(куски), 1)
    return struct.pack("<I", zlib.crc32(шапка)) + шапка + куски


def _поток_файлов(полезное):
    сжатое = lzma.compress(полезное, format=lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
    return b"zlb\x1a" + bytes([16]) + сжатое


def _установщик(заголовок, файлы, раскладка="старая"):
    подпись = b"Inno Setup Setup Data (6.7.0)".ljust(64, b"\x00")
    if раскладка == "старая":
        return (b"MZ" + b"\x00" * 200 + подпись + _блок_inno(заголовок)
                + b"\x00" * 16 + _поток_файлов(файлы))
    запись = b"\x00" * 49
    шифрование = struct.pack("<I", zlib.crc32(запись)) + запись
    return (b"MZ" + b"\x00" * 200 + _поток_файлов(файлы) + b"\x00" * 16
            + подпись + шифрование + _блок_inno(заголовок))


@pytest.mark.parametrize("раскладка", ["старая", "6.7"])
def test_маркер_в_заголовке_inno_найден(tmp_path, раскладка):
    путь = tmp_path / "setup.exe"
    путь.write_bytes(_установщик(b"AppName=X " + ВЫДУМАННЫЙ.encode(), b"files", раскладка))
    отчёт = cp.Отчёт()
    итог = cp.проверить_установщик(str(путь), _иглы(ВЫДУМАННЫЙ), отчёт, программа=False)
    assert итог["заголовок Inno, блоков"] >= 1
    assert итог["сжатые файлы, байт"] == len(b"files")
    assert any("заголовок Inno" in н[2] for н in отчёт.находки)
    assert not отчёт.не_разобрано


def test_маркер_в_сжатых_файлах_найден_даже_на_стыке_порций(tmp_path, monkeypatch):
    monkeypatch.setattr(cp, "ПОРЦИЯ", 7)
    файлы = b"lorem ipsum " * 500 + ВЫДУМАННЫЙ.encode() + b" dolor" * 500
    путь = tmp_path / "setup.exe"
    путь.write_bytes(_установщик(b"AppName=X", файлы))
    отчёт = cp.Отчёт()
    итог = cp.проверить_установщик(str(путь), _иглы(ВЫДУМАННЫЙ), отчёт, программа=False)
    assert итог["сжатые файлы, байт"] == len(файлы)
    assert [н[2] for н in отчёт.находки] == ["setup.exe (сжатые файлы)"]


def test_чистый_установщик_чист(tmp_path):
    путь = tmp_path / "setup.exe"
    путь.write_bytes(_установщик(b"AppName=X", b"clean files" * 100))
    отчёт = cp.Отчёт()
    cp.проверить_установщик(str(путь), _иглы(ВЫДУМАННЫЙ), отчёт, программа=False)
    assert отчёт.находки == [] and отчёт.не_разобрано == []


МОМЕНТ = 1790000000
ПОЯС = 3 * 3600


def _сборка_с_временем(tmp_path):
    папка = _папка(tmp_path, {"MailFact.exe": b"MZ", "_internal/a.dll": b"MZ"})
    for корень, _, файлы in os.walk(папка):
        for имя in файлы:
            os.utime(os.path.join(корень, имя), (МОМЕНТ, МОМЕНТ))
    return папка


@pytest.mark.parametrize("запись, ждём_находку", [
    (МОМЕНТ, False),
    (МОМЕНТ + ПОЯС, True),
], ids=["utc", "местное"])
def test_местное_время_в_установщике_выдаёт_пояс(tmp_path, запись, ждём_находку):
    папка = _сборка_с_временем(tmp_path)
    отметка = cp._filetime(запись)
    заголовок = b"AppName=X" + (b"\x00" * 7 + отметка) * 2
    путь = tmp_path / "setup.exe"
    путь.write_bytes(_установщик(заголовок, b"files"))
    отчёт = cp.Отчёт()
    итог = cp.проверить_установщик(str(путь), _иглы(ВЫДУМАННЫЙ), отчёт,
                                   папка=папка, смещение=ПОЯС, программа=False)
    пояс = [н for н in отчёт.находки if н[0] == "часовой пояс машины сборки"]
    assert bool(пояс) is ждём_находку
    if ждём_находку:
        assert пояс[0][1] == "UTC+3"
        assert итог["время файлов: местное"] == "2 из 2"
    else:
        assert итог["время файлов: по UTC"] == "2 из 2"


def test_в_iss_время_файлов_по_utc():
    корень = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    текст = open(os.path.join(корень, "MailFact.iss"), encoding="utf-8-sig").read()
    строки = [с.split(";")[0].strip().lower().replace(" ", "") for с in текст.splitlines()]
    assert "timestampsinutc=yes" in строки


def test_испорченный_crc_не_принимается_за_разобранный(tmp_path):
    данные = bytearray(_установщик(b"AppName=X", b"f"))
    i = данные.find(b"Inno Setup Setup Data (") + 64
    данные[i] ^= 0xFF
    путь = tmp_path / "setup.exe"
    путь.write_bytes(bytes(данные))
    отчёт = cp.Отчёт()
    cp.проверить_установщик(str(путь), _иглы(ВЫДУМАННЫЙ), отчёт)
    assert отчёт.не_разобрано


@pytest.mark.parametrize("смещение, закодировано, исходно", [
    (1030, "e8380a0100", "e82d060100"),
    (2590, "e810070000", "e8edfcffff"),
], ids=["вперёд", "назад"])
def test_снятие_фильтра_вызовов_на_настоящих_векторах(смещение, закодировано, исходно):
    буфер = bytearray(смещение + 16)
    буфер[смещение:смещение + 5] = bytes.fromhex(закодировано)
    итог = cp.снять_фильтр_вызовов(bytes(буфер))
    assert итог[смещение:смещение + 5] == bytes.fromhex(исходно)
    assert итог[:смещение] == bytes(смещение)


def test_байты_без_e8_e9_не_меняются():
    данные = bytes(range(0xE8)) * 50
    assert cp.снять_фильтр_вызовов(данные) == данные


def test_установщик_без_программы_внутри_не_чистый(tmp_path):
    путь = tmp_path / "setup.exe"
    путь.write_bytes(_установщик(b"AppName=X", b"no program here"))
    отчёт = cp.Отчёт()
    cp.проверить_установщик(str(путь), _иглы(ВЫДУМАННЫЙ), отчёт)
    assert any("PyInstaller" in почему for _, почему in отчёт.не_разобрано)


def test_маркер_в_сжатом_pyz_модуле_найден(tmp_path, monkeypatch):
    """Маркер в co_filename (в т.ч. во вложенной функции) внутри zlib-сжатого PYZ находится.

    Регрессионный тест: без zlib.decompress() и обхода marshal/co_filename
    сжатый байткод скрывает пути сборки от сырого поиска по байтам.
    """
    import marshal

    утечка = "C:/Users/TestUser42/" + ВЫДУМАННЫЙ + "/mod.py"
    код = compile("def inner():\n    return 'secret-" + ВЫДУМАННЫЙ + "'\n", утечка, "exec")
    сжатое = zlib.compress(marshal.dumps(код))
    чистый_код = compile("def ok():\n    return 'ok'\n", "clean.py", "exec")
    чистое_сжатое = zlib.compress(marshal.dumps(чистый_код))

    несжатый_маркер = ВЫДУМАННЫЙ.encode()
    assert несжатый_маркер.lower() not in сжатое.lower()
    assert несжатый_маркер.lower() in zlib.decompress(сжатое).lower()

    class FakePYZ:
        toc = ["mod", "clean"]

        def extract(self, name, raw=True):
            return сжатое if name == "mod" else чистое_сжатое

    class FakeCArchive:
        toc = ["PYZ-00.pyz"]

        def open_embedded_archive(self, name):
            return FakePYZ()

        def extract(self, name):
            return b""

    import PyInstaller.archive.readers as readers
    monkeypatch.setattr(readers, "CArchiveReader", lambda path: FakeCArchive())

    отчёт = cp.Отчёт()
    cp.проверить_архив_exe("fake.exe", _иглы(ВЫДУМАННЫЙ), отчёт)
    assert отчёт.счётчики["модулей PYZ"] == 2
    assert any(ВЫДУМАННЫЙ in н[1] or ВЫДУМАННЫЙ in н[3] for н in отчёт.находки), (
        "маркер в zlib-сжатом PYZ-модуле не найден"
    )
    assert "TestUser42" in отчёт.чужие_пути

    # Чистый сжатый PYZ не даёт находок и ошибок разбора
    class CleanPYZ:
        toc = ["clean"]

        def extract(self, name, raw=True):
            return чистое_сжатое

    class CleanCArchive:
        toc = ["PYZ-00.pyz"]

        def open_embedded_archive(self, name):
            return CleanPYZ()

        def extract(self, name):
            return b""

    monkeypatch.setattr(readers, "CArchiveReader", lambda path: CleanCArchive())
    чистый_отчёт = cp.Отчёт()
    cp.проверить_архив_exe("clean.exe", _иглы(ВЫДУМАННЫЙ), чистый_отчёт)
    assert чистый_отчёт.находки == []
    assert чистый_отчёт.не_разобрано == []
    assert чистый_отчёт.счётчики["модулей PYZ"] == 1
