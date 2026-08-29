#!/usr/bin/env python
"""Запуск pytest с честным признаком успеха.

Зачем отдельный запускальщик. Гейт считается взятым, когда в выводе нашлась
строка EXPECT. У `pytest -q` слово «passed» печатается и при провале —
`1 failed, 23 passed` содержит его целиком. Гейт с таким EXPECT не способен
упасть, то есть он не проверка, а украшение.

Здесь токен `GATE-TESTS-CLEAN` печатается только когда:

  * pytest вернул ноль;
  * ни одного failed, error, xpassed;
  * ни одного ПРОПУЩЕННОГО теста.

Последнее — не придирка. В этом проекте четыре теста интерфейса однажды
молча уехали в skip (на процесс можно создать только один корень Tk), полный
прогон остался зелёным, и пропажа проверок была видна только в счётчике.
Пропущенный тест ничего не доказывает, поэтому здесь он считается провалом.
Осознанный пропуск объявляется явно флагом --allow-skips.

Запуск:
    python tools/run_gate_tests.py tests/test_web_ui.py -k icons
"""
import os
import re
import subprocess
import sys

# Консоль Windows по умолчанию не в UTF-8, а пояснения к провалу здесь
# по-русски: без этого раннер падает на собственном сообщении об ошибке.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = "GATE-TESTS-CLEAN"

# Слова из итоговой строки pytest, при которых прогон не чист.
BAD = ("failed", "error", "xpassed", "xfailed")


def main(argv):
    allow_skips = "--allow-skips" in argv
    args = [a for a in argv if a != "--allow-skips"]

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    # Свой корень в путь: тесты импортируют ui/ и core/ без установки пакета.
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")

    process = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"] + args,
        cwd=ROOT, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace")

    output = (process.stdout or "") + (process.returncode and (process.stderr or "") or "")
    sys.stdout.write(process.stdout or "")
    sys.stdout.write(process.stderr or "")

    if process.returncode != 0:
        print("%s НЕ печатается: pytest вернул %d" % (TOKEN, process.returncode))
        return 1

    summary = ""
    for line in reversed((process.stdout or "").splitlines()):
        if re.search(r"\b\d+\s+(passed|failed|error|skipped|deselected)", line):
            summary = line
            break
    if not summary:
        print("%s НЕ печатается: в выводе pytest нет итоговой строки" % TOKEN)
        return 1

    lowered = summary.lower()
    for word in BAD:
        if word in lowered:
            print("%s НЕ печатается: в итоге есть «%s» — %s" % (TOKEN, word, summary.strip()))
            return 1

    skipped = re.search(r"(\d+)\s+skipped", lowered)
    if skipped and not allow_skips:
        print("%s НЕ печатается: пропущено тестов — %s. "
              "Пропущенный тест ничего не доказывает; если пропуск осознанный, "
              "запускайте с --allow-skips." % (TOKEN, skipped.group(1)))
        return 1

    passed = re.search(r"(\d+)\s+passed", lowered)
    if not passed or int(passed.group(1)) == 0:
        print("%s НЕ печатается: не выполнено ни одного теста — %s"
              % (TOKEN, summary.strip()))
        return 1

    print("%s (%s тестов)" % (TOKEN, passed.group(1)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
