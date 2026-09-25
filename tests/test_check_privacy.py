# -*- coding: utf-8 -*-
"""tools/check_privacy.py — проверка, что в сборке нет следов машины сборки.

Самое опасное у такой проверки — ложное «чисто». Проверка, которая ничего не
находит, выглядит ровно так же, как проверка, которая не умеет искать. Поэтому
большая часть тестов — положительные: подложить след и убедиться, что он
найден. На каждой форме, в которой путь реально встречается в файлах.

Маркеры в тестах — выдуманные либо вычисленные на машине прогона. Настоящих
данных владельца здесь нет и быть не должно: файл лежит в открытом репозитории.
"""
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


# ─────────────────────────────── маркеры ────────────────────────────────

@pytest.fixture(autouse=True)
def _не_на_сервере_github(monkeypatch):
    # Набор гоняется и в CI, где GITHUB_ACTIONS=true меняет поведение
    # проверки. Каждый тест сам решает, где он «запущен».
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.delenv("MAILFACT_PRIVATE_MARKERS", raising=False)


def test_домашняя_папка_попадает_в_маркеры_во_всех_написаниях():
    м = cp.маркеры_машины()
    дом = os.path.normpath(os.path.expanduser("~"))
    формы = м["домашняя папка того, кто собирал"]
    assert дом in формы
    assert дом.replace("\\", "/") in формы


def test_короткий_маркер_не_берётся():
    # «PC» нашёлся бы в любом двоичном файле: утопил бы настоящие находки.
    м = cp.маркеры_машины(свои=["PC", ВЫДУМАННЫЙ])
    assert "PC" not in м.get("свой маркер", set())
    assert ВЫДУМАННЫЙ in м["свой маркер"]


def test_маркер_из_окружения(monkeypatch):
    monkeypatch.setenv("MAILFACT_PRIVATE_MARKERS", "первый-маркер;второй-маркер")
    м = cp.маркеры_машины()
    assert {"первый-маркер", "второй-маркер"} <= м["свой маркер"]


def test_на_сервере_github_домашняя_папка_не_маркер(monkeypatch):
    # Там это общий аккаунт образа, на котором собраны и чужие библиотеки:
    # его пути в сборке есть всегда (6998 вхождений на замере), и искать их
    # значило бы ронять каждый релиз, ничего не узнав.
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    м = cp.маркеры_машины()
    assert "домашняя папка того, кто собирал" not in м
    # Путь проекта при этом остаётся: он уникален и ловит сам механизм утечки.
    assert os.path.normpath(cp.КОРЕНЬ) in м["папка проекта на машине сборки"]


def test_свой_маркер_не_печатается_никогда(tmp_path, capsys):
    секрет = "Fam1lia-Sekret"
    папка = _папка(tmp_path, {"MailFact.exe": b"MZ path " + секрет.encode() + b" tail"})
    assert cp.main(["--dist", папка, "--marker", секрет]) == 1
    вывод = capsys.readouterr().out
    assert секрет.lower() not in вывод.lower()
    assert "значение скрыто" in вывод and "где: MailFact.exe" in вывод


def test_на_сервере_github_свои_маркеры_скрываются_до_вывода(tmp_path, capsys, monkeypatch):
    # GitHub прячет в журнале только секрет целиком, а маркеры в нём через «;».
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("MAILFACT_PRIVATE_MARKERS", "alpha-one;beta-two")
    папка = _папка(tmp_path, {"a.txt": b"clean"})
    cp.main(["--dist", папка])
    строки = capsys.readouterr().out.splitlines()
    assert строки[:2] == ["::add-mask::alpha-one", "::add-mask::beta-two"]


# ───────────────────────── папка сборки: находит ────────────────────────

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
    # Старые программы под русской Windows пишут пути в cp1251, а не в UTF-8.
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
    # В сыром виде zip сжат, и маркер виден ТОЛЬКО в развёрнутом члене.
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


# ───────────────────── итоговый ответ: не врать «чисто» ──────────────────

def test_без_исполняемого_файла_ответ_не_чисто(tmp_path, capsys):
    # Сборка без .exe — значит, архив PyInstaller не просмотрен вовсе.
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


# ───────────────────────── установщик Inno Setup ────────────────────────

def _блок_inno(полезное):
    """Сжатый блок setup-0 так, как его пишет Inno: LZMA1 + CRC по кускам."""
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
    # Свойство 16 означает словарь в 1 МиБ: (2 | 0) << (16 // 2 + 11).
    сжатое = lzma.compress(полезное, format=lzma.FORMAT_RAW, filters=[{
        "id": lzma.FILTER_LZMA2, "dict_size": 1 << 20}])
    return b"zlb\x1a" + bytes([16]) + сжатое


def _установщик(заголовок, файлы, раскладка="старая"):
    """Два порядка частей, оба встречаются в жизни.

    Старая раскладка: загрузчик, заголовок, затем файлы. Inno Setup 6.7:
    загрузчик, файлы, в самом конце заголовок — и перед его блоками запись о
    шифровании со своей CRC (замерено на установщике, собранном 6.7.3).
    """
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
    # Порция в семь байт: поток распаковывается мелкими кусками, и маркер
    # почти наверняка разрезан их границей. Без перекрытия окон он бы потерялся.
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


# ─────────────── часовой пояс в отметках времени установщика ─────────────

МОМЕНТ = 1790000000          # чётная секунда: округление Inno её не сдвигает
ПОЯС = 6 * 3600


def _сборка_с_временем(tmp_path):
    папка = _папка(tmp_path, {"MailFact.exe": b"MZ", "_internal/a.dll": b"MZ"})
    for корень, _, файлы in os.walk(папка):
        for имя in файлы:
            os.utime(os.path.join(корень, имя), (МОМЕНТ, МОМЕНТ))
    return папка


@pytest.mark.parametrize("запись, ждём_находку", [
    (МОМЕНТ, False),              # TimeStampsInUTC=yes: время как есть
    (МОМЕНТ + ПОЯС, True),        # по умолчанию Inno: местное время сборщика
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
        assert пояс[0][1] == "UTC+6"
        assert итог["время файлов: местное"] == "2 из 2"
    else:
        assert итог["время файлов: по UTC"] == "2 из 2"


def test_в_iss_время_файлов_по_utc():
    # Без этой строки установщик, собранный на машине с поясом, выдаёт его:
    # замерено на 3456 файлах, все со сдвигом +6 часов.
    корень = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    текст = open(os.path.join(корень, "MailFact.iss"), encoding="utf-8-sig").read()
    строки = [с.split(";")[0].strip().lower().replace(" ", "") for с in текст.splitlines()]
    assert "timestampsinutc=yes" in строки


def test_испорченный_crc_не_принимается_за_разобранный(tmp_path):
    # Блок, не сошедшийся по контрольной сумме, — не «пустой заголовок», а
    # неразобранная часть: иначе мусор сошёл бы за чистоту.
    данные = bytearray(_установщик(b"AppName=X", b"f"))
    i = данные.find(b"Inno Setup Setup Data (") + 64
    данные[i] ^= 0xFF
    путь = tmp_path / "setup.exe"
    путь.write_bytes(bytes(данные))
    отчёт = cp.Отчёт()
    cp.проверить_установщик(str(путь), _иглы(ВЫДУМАННЫЙ), отчёт)
    assert отчёт.не_разобрано


# ──────────────── программа внутри установщика: фильтр Inno ─────────────

# Векторы сняты с настоящего установщика (Inno 6.7.3): закодированные байты
# из потока против исходных из папки сборки, на тех же смещениях в .exe.
@pytest.mark.parametrize("смещение, закодировано, исходно", [
    (1030, "e8380a0100", "e82d060100"),     # обычный вызов вперёд
    (2590, "e810070000", "e8edfcffff"),     # вызов назад: старший байт перевёрнут
], ids=["вперёд", "назад"])
def test_снятие_фильтра_вызовов_на_настоящих_векторах(смещение, закодировано, исходно):
    буфер = bytearray(смещение + 16)
    буфер[смещение:смещение + 5] = bytes.fromhex(закодировано)
    итог = cp.снять_фильтр_вызовов(bytes(буфер))
    assert итог[смещение:смещение + 5] == bytes.fromhex(исходно)
    # Остальное не тронуто.
    assert итог[:смещение] == bytes(смещение)


def test_байты_без_e8_e9_не_меняются():
    данные = bytes(range(0xE8)) * 50
    assert cp.снять_фильтр_вызовов(данные) == данные


def test_установщик_без_программы_внутри_не_чистый(tmp_path):
    # Настоящий установщик MailFact обязан нести программу. Если её в потоке
    # не нашлось, байткод не просмотрен — и это не «чисто», а «не разобрано».
    путь = tmp_path / "setup.exe"
    путь.write_bytes(_установщик(b"AppName=X", b"no program here"))
    отчёт = cp.Отчёт()
    cp.проверить_установщик(str(путь), _иглы(ВЫДУМАННЫЙ), отчёт)
    assert any("PyInstaller" in почему for _, почему in отчёт.не_разобрано)
