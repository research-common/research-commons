"""Shared test helpers: a fake ``commons`` binary and a throwaway environment."""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPO = ROOT.parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

# A fake binary: replays FAKE_STDOUT / FAKE_EXIT, records its argv and stdin to FAKE_LOG.
FAKE = """#!{python}
import os, sys
log = os.environ.get("FAKE_LOG")
if log:
    with open(log, "w") as f:
        f.write("\\n".join(sys.argv[1:]))
    with open(log + ".stdin", "wb") as f:
        f.write(b"" if sys.stdin.isatty() else sys.stdin.buffer.read())
sys.stdout.write(os.environ.get("FAKE_STDOUT", ""))
sys.stderr.write(os.environ.get("FAKE_STDERR", ""))
sys.exit(int(os.environ.get("FAKE_EXIT", "0")))
"""


def write_fake(directory: Path, name: str = "commons") -> Path:
    p = directory / name
    p.write_text(FAKE.format(python=sys.executable))
    p.chmod(p.stat().st_mode | stat.S_IXUSR)
    return p


class FakeCase(unittest.TestCase):
    """Points ``$COMMONS_BIN`` at a fake binary for the duration of each test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.tmp = Path(self._tmp.name)
        self.fake = write_fake(self.tmp)
        self.log = self.tmp / "log"
        self._saved = {k: os.environ.get(k) for k in
                       ("COMMONS_BIN", "FAKE_EXIT", "FAKE_STDOUT", "FAKE_STDERR", "FAKE_LOG", "PATH")}
        os.environ["COMMONS_BIN"] = str(self.fake)
        os.environ["FAKE_LOG"] = str(self.log)
        for k in ("FAKE_EXIT", "FAKE_STDOUT", "FAKE_STDERR"):
            os.environ.pop(k, None)
        self.addCleanup(self._restore)

    def _restore(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def fake_says(self, exit: int, stdout: str = "", stderr: str = "") -> None:
        os.environ["FAKE_EXIT"] = str(exit)
        os.environ["FAKE_STDOUT"] = stdout
        os.environ["FAKE_STDERR"] = stderr

    def argv(self) -> list:
        return self.log.read_text().split("\n") if self.log.read_text() else []


def build_real(dest: Path) -> str:
    """A real ``commons``: ``$COMMONS_TEST_BINARY``, else built from this tree (skips when it cannot be)."""
    pre = os.environ.get("COMMONS_TEST_BINARY")
    if pre:
        return pre
    if not shutil.which("go") or not (REPO / "cmd" / "commons").is_dir():
        raise unittest.SkipTest("no Go toolchain or source tree to build commons from")
    out = dest / "commons"
    subprocess.run(["go", "build", "-o", str(out), "./cmd/commons"], cwd=REPO, check=True)
    return str(out)
