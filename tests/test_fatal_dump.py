import os
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _crash(tmp_path, how):
    env = dict(os.environ, MAILFACT_DATA_DIR=str(tmp_path), PYTHONIOENCODING="utf-8")
    code = ("import sys; sys.path.insert(0, %r)\n"
            "from core.crashlog import install_hooks\n"
            "install_hooks()\n"
            "def deep_frame():\n"
            "    %s\n"
            "deep_frame()\n") % (ROOT, how)
    done = subprocess.run([sys.executable, "-B", "-c", code], cwd=ROOT, env=env,
                          capture_output=True, timeout=120)
    path = tmp_path / "fatal.log"
    return done.returncode, path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""


@pytest.mark.skipif(sys.platform != "win32", reason="код аварии 0xC00000FD — только Windows")
def test_stack_overflow_leaves_a_stack_in_fatal_log(tmp_path):
    code, text = _crash(tmp_path, "import faulthandler; faulthandler._raise_exception("
                                  "faulthandler._EXCEPTION_STACK_OVERFLOW)")
    assert code != 0
    assert "stack overflow" in text.lower()
    assert "deep_frame" in text


def test_segfault_leaves_a_stack_in_fatal_log(tmp_path):
    code, text = _crash(tmp_path, "import faulthandler; faulthandler._sigsegv()")
    assert code != 0
    assert "deep_frame" in text


def test_control_clean_exit_writes_no_crash(tmp_path):
    code, text = _crash(tmp_path, "pass")
    assert code == 0
    assert "Fatal Python error" not in text and "fatal exception" not in text.lower()


def test_cli_installs_the_hooks(tmp_path):
    env = dict(os.environ, MAILFACT_DATA_DIR=str(tmp_path), PYTHONIOENCODING="utf-8")
    done = subprocess.run([sys.executable, "-B", "cli.py", "--help"], cwd=ROOT, env=env,
                          capture_output=True, timeout=120)
    assert done.returncode == 0
    assert (tmp_path / "fatal.log").exists()


def test_proxy_readiness_lines_do_not_lie():
    src = open(os.path.join(ROOT, "core", "pipeline_setup.py"), encoding="utf-8").read()
    assert "прокси с PTR.\"" not in src
    pipe = open(os.path.join(ROOT, "core", "pipeline.py"), encoding="utf-8").read()
    warn = pipe[pipe.index("[DEAD] ВНИМАНИЕ:"):][:400]
    assert "\", \".join(подставные)" in warn
