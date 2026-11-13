import hashlib
import importlib.util
import io
import os
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.helpers import ROOT, SRC

spec = importlib.util.spec_from_file_location("build_wheels", ROOT / "scripts" / "build_wheels.py")
bw = importlib.util.module_from_spec(spec)
sys.modules["build_wheels"] = bw
spec.loader.exec_module(bw)

REPO = ROOT.parent
TOOL_VERSION = (REPO / "VERSION").read_text().strip()
PY_VERSION = bw.pep440(TOOL_VERSION)


def elf(machine, marker=b"x"):
    h = bytearray(b"\x7fELF" + bytes([2, 1, 1, 0]) + bytes(8))
    h += struct.pack("<HHI", 2, machine, 1)
    return bytes(h) + b"\0" * 40 + marker


def macho(cputype, minos=(11, 0), marker=b"x", filetype=2, build_version=True):
    cmd = b""
    if build_version:
        cmd = struct.pack("<IIIIII", 0x32, 24, 1, (minos[0] << 16) | (minos[1] << 8), 0, 0)
    hdr = struct.pack("<IiiIIIII", 0xFEEDFACF, cputype, 0, filetype, 1 if cmd else 0, len(cmd), 0, 0)
    return hdr + cmd + marker


MACHINES = {
    ("darwin", "amd64"): macho(0x01000007, (10, 12)),
    ("darwin", "arm64"): macho(0x0100000C, (11, 0)),
    ("linux", "amd64"): elf(62),
    ("linux", "arm64"): elf(183),
}


def archive(version, goos, goarch, binary, *, top=None, extra=None):
    top = top or "commons-%s-%s-%s" % (version, goos, goarch)
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        files = {"commons": binary, "LICENSE": b"licence\n", "NOTICE": b"notice\n", "README.md": b"readme\n"}
        files.update(extra or {})
        for n, d in files.items():
            ti = tarfile.TarInfo("%s/%s" % (top, n))
            ti.size, ti.mode, ti.mtime = len(d), 0o755 if n == "commons" else 0o644, 0
            tf.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


def make_release(d: Path, version=TOOL_VERSION, machines=None, sums=True):
    machines = machines or MACHINES
    lines = []
    for (o, a), b in sorted(machines.items()):
        name = "commons-%s-%s-%s.tar.gz" % (version, o, a)
        data = archive(version, o, a, b)
        (d / name).write_bytes(data)
        lines.append("%s  %s" % (hashlib.sha256(data).hexdigest(), name))
    if sums:
        (d / "SHA256SUMS").write_text("\n".join(lines) + "\n")
    return d


class Base(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.addCleanup(self._t.cleanup)
        self.tmp = Path(self._t.name)
        self.rel = self.tmp / "rel"
        self.rel.mkdir()
        self.out = self.tmp / "out"
        self.vf = REPO / "VERSION"

    def build(self, out=None, vf=None):
        return bw.build_all(self.rel, out or self.out, vf or self.vf)


class VersionTests(unittest.TestCase):
    def test_pep440(self):
        for tool, py in [("0.5.0-alpha.3", "0.5.0a3"), ("0.5.0-alpha.10", "0.5.0a10"), ("0.6.0-beta.1", "0.6.0b1"),
                         ("1.0.0-rc.2", "1.0.0rc2"), ("0.5.1", "0.5.1")]:
            self.assertEqual(bw.pep440(tool), py)
        for bad in ["0.5", "0.5.0-alpha", "0.5.0-alpha-3", "v0.5.0", "0.5.0-dev.1", "0.5.0+x", ""]:
            with self.assertRaises(bw.BuildError):
                bw.pep440(bad)

    def test_package_declares_the_tool_version(self):
        # fails when VERSION is bumped without python/pyproject.toml and __init__.__version__
        bw._declared_versions(PY_VERSION)
        import research_commons
        self.assertEqual(research_commons.__version__, PY_VERSION)

    def test_declared_version_mismatch_refused(self):
        with self.assertRaises(bw.BuildError) as cm:
            bw._declared_versions("9.9.9")
        self.assertIn("bump python/", str(cm.exception))


class ChecksumTests(Base):
    def test_good_release_builds_four_tagged_wheels(self):
        make_release(self.rel)
        paths = self.build()
        self.assertEqual(sorted(p.name for p in paths), sorted([
            "research_commons-%s-py3-none-macosx_10_12_x86_64.whl" % PY_VERSION,
            "research_commons-%s-py3-none-macosx_11_0_arm64.whl" % PY_VERSION,
            "research_commons-%s-py3-none-manylinux_2_17_aarch64.whl" % PY_VERSION,
            "research_commons-%s-py3-none-manylinux_2_17_x86_64.whl" % PY_VERSION,
        ]))

    def test_checksum_mismatch_refused_before_opening(self):
        make_release(self.rel)
        name = "commons-%s-linux-amd64.tar.gz" % TOOL_VERSION
        p = self.rel / name
        p.write_bytes(p.read_bytes() + b"tamper")  # no longer a clean gzip either: must fail on the sum first
        with self.assertRaises(bw.BuildError) as cm:
            self.build()
        self.assertIn("does not match SHA256SUMS", str(cm.exception))
        self.assertFalse(self.out.exists(), "nothing is written when any archive is refused")

    def test_mutation_reaches_the_boundary(self):
        # a valid archive with a different binary but the old sum is refused for the sum, not for the content
        make_release(self.rel)
        name = "commons-%s-linux-amd64.tar.gz" % TOOL_VERSION
        (self.rel / name).write_bytes(archive(TOOL_VERSION, "linux", "amd64", elf(62, b"evil")))
        with self.assertRaises(bw.BuildError) as cm:
            self.build()
        self.assertIn("does not match SHA256SUMS", str(cm.exception))

    def test_missing_sums_file_and_missing_entry(self):
        make_release(self.rel, sums=False)
        with self.assertRaises(bw.BuildError):
            self.build()
        make_release(self.rel)
        lines = (self.rel / "SHA256SUMS").read_text().splitlines()
        (self.rel / "SHA256SUMS").write_text("\n".join(lines[1:]) + "\n")
        with self.assertRaises(bw.BuildError) as cm:
            self.build()
        self.assertIn("no entry", str(cm.exception))

    def test_malformed_and_conflicting_sums(self):
        with self.assertRaises(bw.BuildError):
            bw.parse_sha256sums("nothex  file\n")
        with self.assertRaises(bw.BuildError):
            bw.parse_sha256sums("%s  ../x\n" % ("a" * 64))
        with self.assertRaises(bw.BuildError):
            bw.parse_sha256sums("%s  f\n%s  f\n" % ("a" * 64, "b" * 64))
        self.assertEqual(bw.parse_sha256sums("%s *f\n\n" % ("A" * 64)), {"f": "a" * 64})

    def test_missing_archive_refused(self):
        make_release(self.rel)
        (self.rel / ("commons-%s-darwin-arm64.tar.gz" % TOOL_VERSION)).unlink()
        with self.assertRaises(bw.BuildError) as cm:
            self.build()
        self.assertIn("missing release archive", str(cm.exception))


class VersionMismatchTests(Base):
    def test_archives_of_another_version_refused(self):
        make_release(self.rel, version="0.4.9")
        with self.assertRaises(bw.BuildError) as cm:
            self.build()
        self.assertIn("does not belong to VERSION", str(cm.exception))

    def test_extra_archive_of_another_version_refused(self):
        make_release(self.rel)
        (self.rel / "commons-0.4.9-linux-amd64.tar.gz").write_bytes(b"x")
        with self.assertRaises(bw.BuildError):
            self.build()

    def test_version_file_that_is_not_pep440_mappable(self):
        make_release(self.rel)
        vf = self.tmp / "VERSION"
        vf.write_text("0.5.0-alpha-3\n")
        with self.assertRaises(bw.BuildError):
            self.build(vf=vf)

    def test_package_not_bumped_with_VERSION(self):
        make_release(self.rel, version="0.5.0")
        vf = self.tmp / "VERSION"
        vf.write_text("0.5.0\n")
        with self.assertRaises(bw.BuildError) as cm:
            self.build(vf=vf)
        self.assertIn("bump python/", str(cm.exception))

    def test_archive_top_directory_must_name_the_version(self):
        make_release(self.rel)
        name = "commons-%s-linux-amd64.tar.gz" % TOOL_VERSION
        data = archive("0.4.9", "linux", "amd64", MACHINES[("linux", "amd64")])
        (self.rel / name).write_bytes(data)
        lines = [l for l in (self.rel / "SHA256SUMS").read_text().splitlines() if not l.endswith(name)]
        lines.append("%s  %s" % (hashlib.sha256(data).hexdigest(), name))
        (self.rel / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        with self.assertRaises(bw.BuildError) as cm:
            self.build()
        self.assertIn("has no commons-%s-linux-amd64/commons" % TOOL_VERSION, str(cm.exception))


class BinaryTests(Base):
    def _swap(self, goos, goarch, binary):
        make_release(self.rel, machines={**MACHINES, (goos, goarch): binary})

    def test_wrong_architecture_refused(self):
        self._swap("linux", "arm64", elf(62))
        with self.assertRaises(bw.BuildError) as cm:
            self.build()
        self.assertIn("not the linux/arm64", str(cm.exception))

    def test_wrong_os_format_refused(self):
        self._swap("darwin", "arm64", elf(183))
        with self.assertRaises(bw.BuildError):
            self.build()

    def test_not_an_executable_refused(self):
        self._swap("linux", "amd64", b"#!/bin/sh\necho hi\n")
        with self.assertRaises(bw.BuildError) as cm:
            self.build()
        self.assertIn("neither an ELF nor", str(cm.exception))
        self._swap("darwin", "arm64", macho(0x0100000C, filetype=1))
        with self.assertRaises(bw.BuildError):
            self.build()

    def test_macos_tag_raised_to_the_binary_minimum(self):
        make_release(self.rel, machines={**MACHINES, ("darwin", "arm64"): macho(0x0100000C, (14, 2)),
                                         ("darwin", "amd64"): macho(0x01000007, (10, 15))})
        names = sorted(p.name for p in self.build())
        self.assertIn("research_commons-%s-py3-none-macosx_14_0_arm64.whl" % PY_VERSION, names)
        self.assertIn("research_commons-%s-py3-none-macosx_10_15_x86_64.whl" % PY_VERSION, names)

    def test_macos_without_version_load_command_keeps_the_floor(self):
        make_release(self.rel, machines={**MACHINES, ("darwin", "arm64"): macho(0x0100000C, build_version=False)})
        self.assertIn("research_commons-%s-py3-none-macosx_11_0_arm64.whl" % PY_VERSION,
                      [p.name for p in self.build()])

    def test_archive_without_licence_refused(self):
        make_release(self.rel)
        name = "commons-%s-linux-amd64.tar.gz" % TOOL_VERSION
        buf = io.BytesIO()
        top = "commons-%s-linux-amd64" % TOOL_VERSION
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            d = MACHINES[("linux", "amd64")]
            ti = tarfile.TarInfo(top + "/commons")
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
        data = buf.getvalue()
        (self.rel / name).write_bytes(data)
        lines = [l for l in (self.rel / "SHA256SUMS").read_text().splitlines() if not l.endswith(name)]
        lines.append("%s  %s" % (hashlib.sha256(data).hexdigest(), name))
        (self.rel / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        with self.assertRaises(bw.BuildError):
            self.build()


class WheelTests(Base):
    def setUp(self):
        super().setUp()
        make_release(self.rel)
        self.paths = {p.name.split("-py3-none-")[1][:-4]: p for p in self.build()}

    def test_reproducible_bytes(self):
        again = bw.build_all(self.rel, self.tmp / "out2", self.vf)
        self.assertEqual(sorted(p.name for p in again), sorted(p.name for p in self.paths.values()))
        for p in again:
            self.assertEqual(p.read_bytes(), self.paths[p.name.split("-py3-none-")[1][:-4]].read_bytes(), p.name)

    def test_reproducible_across_source_mtimes_and_cwd(self):
        # a changed source mtime or working directory must not change the bytes
        src = ROOT / "src" / "research_commons" / "__init__.py"
        st = src.stat()
        self.addCleanup(os.utime, src, (st.st_atime, st.st_mtime))
        os.utime(src, (1_000_000_000, 1_000_000_000))
        cwd = os.getcwd()
        os.chdir(self.tmp)
        self.addCleanup(os.chdir, cwd)
        again = bw.build_all(self.rel, self.tmp / "out3", self.vf)
        for p in again:
            self.assertEqual(p.read_bytes(), self.paths[p.name.split("-py3-none-")[1][:-4]].read_bytes())

    def test_wheel_contents_and_metadata(self):
        w = self.paths["manylinux_2_17_x86_64"]
        with zipfile.ZipFile(w) as z:
            self.assertIsNone(z.testzip())
            names = z.namelist()
            di = "research_commons-%s.dist-info" % PY_VERSION
            self.assertEqual(names[-1], di + "/RECORD")
            for need in ["research_commons/__init__.py", "research_commons/_run.py", "research_commons/_cli.py",
                         "research_commons/py.typed", "research_commons/_bin/commons", di + "/METADATA", di + "/WHEEL",
                         di + "/entry_points.txt", di + "/licenses/LICENSE", di + "/licenses/NOTICE"]:
                self.assertIn(need, names)
            self.assertFalse([n for n in names if "__pycache__" in n or n.startswith("tests/")])
            for zi in z.infolist():
                self.assertEqual(zi.date_time, (1980, 1, 1, 0, 0, 0))
            self.assertEqual((z.getinfo("research_commons/_bin/commons").external_attr >> 16) & 0o777, 0o755)
            self.assertEqual((z.getinfo("research_commons/_run.py").external_attr >> 16) & 0o777, 0o644)
            wheel = z.read(di + "/WHEEL").decode()
            self.assertIn("Root-Is-Purelib: false", wheel)
            self.assertIn("Tag: py3-none-manylinux_2_17_x86_64", wheel)
            meta = z.read(di + "/METADATA").decode()
            self.assertIn("Version: " + PY_VERSION, meta)
            self.assertIn("Requires-Python: >=3.9", meta)
            self.assertNotIn("Requires-Dist", meta)  # stdlib only
            self.assertIn("commons = research_commons._cli:main", z.read(di + "/entry_points.txt").decode())
            self.assertEqual(z.read("research_commons/_bin/commons"), MACHINES[("linux", "amd64")])

    def test_record_is_exact(self):
        import base64
        for tag, w in self.paths.items():
            with zipfile.ZipFile(w) as z:
                di = "research_commons-%s.dist-info" % PY_VERSION
                rows = [r.split(",") for r in z.read(di + "/RECORD").decode().splitlines()]
                self.assertEqual(sorted(r[0] for r in rows), sorted(z.namelist()), tag)
                for name, h, size in rows:
                    if name.endswith("RECORD"):
                        self.assertEqual((h, size), ("", ""))
                        continue
                    d = z.read(name)
                    want = "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(d).digest()).rstrip(b"=").decode()
                    self.assertEqual((h, int(size)), (want, len(d)), name)

    def test_each_wheel_carries_its_own_binary(self):
        for (o, a), b in MACHINES.items():
            tag = {("darwin", "amd64"): "macosx_10_12_x86_64", ("darwin", "arm64"): "macosx_11_0_arm64",
                   ("linux", "amd64"): "manylinux_2_17_x86_64", ("linux", "arm64"): "manylinux_2_17_aarch64"}[(o, a)]
            with zipfile.ZipFile(self.paths[tag]) as z:
                self.assertEqual(z.read("research_commons/_bin/commons"), b, tag)

    def test_installed_wheel_uses_the_bundled_binary(self):
        # an extracted wheel on PYTHONPATH finds _bin/commons before $COMMONS_BIN and PATH
        script = b"#!/bin/sh\necho BUNDLED \"$@\"\n"
        # extract the wheel and swap in a runnable stand-in for the bundled binary
        w = self.paths["manylinux_2_17_x86_64"]
        site = self.tmp / "site"
        with zipfile.ZipFile(w) as z:
            for zi in z.infolist():
                z.extract(zi, site)
                if zi.filename == "research_commons/_bin/commons":
                    (site / zi.filename).write_bytes(script)
                    (site / zi.filename).chmod(0o755)
        env = dict(os.environ, PYTHONPATH=str(site), COMMONS_BIN="/nonexistent")
        p = subprocess.run([sys.executable, "-c",
                            "import research_commons as r; print(r.bundled_binary()); print(r.find_binary())"],
                           env=env, capture_output=True, text=True, cwd=self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertTrue(p.stdout.split()[0].endswith("research_commons/_bin/commons"))
        p = subprocess.run([sys.executable, "-m", "research_commons._cli", "a", "b"], env=env, capture_output=True,
                           text=True, cwd=self.tmp)
        self.assertEqual(p.stdout.strip(), "BUNDLED a b")

    def test_no_source_files_outside_the_package(self):
        with zipfile.ZipFile(self.paths["manylinux_2_17_x86_64"]) as z:
            top = {n.split("/")[0] for n in z.namelist()}
        self.assertEqual(top, {"research_commons", "research_commons-%s.dist-info" % PY_VERSION})

    def test_cli_refuses_with_status_1_and_writes_nothing(self):
        bad = self.tmp / "bad_dir"
        bad.mkdir()
        make_release(bad, version="0.4.9")
        out = self.tmp / "cli_out"
        script = str(ROOT / "scripts" / "build_wheels.py")
        r = subprocess.run([sys.executable, script, str(bad), "--out", str(out)], capture_output=True, text=True)
        self.assertEqual(r.returncode, 1)
        self.assertIn("refused", r.stderr)
        self.assertFalse(out.exists())
        r = subprocess.run([sys.executable, script, str(self.rel), "--out", str(self.tmp / "cli_ok")],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len(r.stdout.strip().splitlines()), 4)


if __name__ == "__main__":
    unittest.main()
