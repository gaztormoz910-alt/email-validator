#!/usr/bin/env python
import os
import re
import subprocess
import sys

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKEN = "GATE-TESTS-CLEAN"

BAD = ("failed", "error", "xpassed", "xfailed")


def main(argv):
    allow_skips = "--allow-skips" in argv
    args = [a for a in argv if a != "--allow-skips"]

    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONPATH"] = ROOT + os.pathsep + env.get("PYTHONPATH", "")

    process = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"] + args,
        cwd=ROOT, env=env, capture_output=True, text=True,
        encoding="utf-8", errors="replace")

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
