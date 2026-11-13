#!/usr/bin/env python3
"""Build the platform wheels of ``research-commons`` from a release directory.

Input: a directory holding the four release archives ``commons-<version>-<os>-<arch>.tar.gz`` and the
``SHA256SUMS`` file the release workflow wrote. Output: one wheel per archive, in ``--out`` (default
``dist/`` next to ``python/``).

Rules, in order:

1. The tool version comes from the ``VERSION`` file and is mapped to PEP 440 (``0.5.0-alpha.3`` -> ``0.5.0a3``).
   The ``version`` in ``pyproject.toml`` and ``research_commons.__version__`` must already equal it, and every
   release archive must name the same version: a mismatch is refused.
2. Every archive is checked against ``SHA256SUMS`` *before it is opened*. A missing entry, a mismatch, or a
   stray ``commons-*.tar.gz`` of another name is refused.
3. The binary is read from the archive in memory (nothing is extracted to disk) and must be an executable
   of the platform the archive name claims (ELF or Mach-O header, machine type). A macOS wheel's platform tag
   is never lower than the minimum OS version recorded in the binary.
4. The wheels are written with the standard library only, byte-for-byte reproducible: sorted entries, fixed
   timestamps and modes, fixed compression level. Building twice gives identical files (given the same zlib).

Publishing is not done here.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
import re
import struct
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Dict, List, NamedTuple, Optional, Tuple

HERE = Path(__file__).resolve().parent
PKG_ROOT = HERE.parent  # python/
REPO_ROOT = PKG_ROOT.parent
DIST_NAME = "research_commons"
ZIP_TIME = (1980, 1, 1, 0, 0, 0)  # the earliest a zip can record
MAX_BINARY = 256 * 1024 * 1024
MAX_SMALL = 1024 * 1024


class BuildError(Exception):
    """A refusal: nothing is written for the target in question."""


class Target(NamedTuple):
    os: str  # as in the archive name
    arch: str
    machine: Tuple[str, int]  # ("elf"|"macho", machine code)
    tag: str  # default platform tag (macOS: floor, raised to the binary's minimum OS)


TARGETS: List[Target] = [
    Target("darwin", "amd64", ("macho", 0x01000007), "macosx_10_12_x86_64"),
    Target("darwin", "arm64", ("macho", 0x0100000C), "macosx_11_0_arm64"),
    Target("linux", "amd64", ("elf", 62), "manylinux_2_17_x86_64"),
    Target("linux", "arm64", ("elf", 183), "manylinux_2_17_aarch64"),
]


# --- version -----------------------------------------------------------------------------------------------

_VERSION = re.compile(r"^(\d+)\.(\d+)\.(\d+)(?:-(alpha|beta|rc)\.(\d+))?$")
_PRE = {"alpha": "a", "beta": "b", "rc": "rc"}


def pep440(tool_version: str) -> str:
    """``0.5.0-alpha.3`` -> ``0.5.0a3``; ``0.5.0`` -> ``0.5.0``. Anything else is refused."""
    m = _VERSION.match(tool_version)
    if not m:
        raise BuildError("VERSION %r is not MAJOR.MINOR.PATCH[-alpha|beta|rc.N]; refusing to guess a PEP 440 form" % tool_version)
    base = "%s.%s.%s" % m.group(1, 2, 3)
    return base + (_PRE[m.group(4)] + str(int(m.group(5))) if m.group(4) else "")


def _declared_versions(py_version: str) -> None:
    """The package's own two version declarations must equal the release's."""
    pyproject = (PKG_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', pyproject)
    init = (PKG_ROOT / "src" / DIST_NAME / "__init__.py").read_text(encoding="utf-8")
    n = re.search(r'(?m)^__version__\s*=\s*"([^"]+)"', init)
    for what, got in (("pyproject.toml version", m and m.group(1)), ("__version__", n and n.group(1))):
        if got != py_version:
            raise BuildError("%s is %r but VERSION maps to %r: bump python/ with VERSION" % (what, got, py_version))


# --- checksums ---------------------------------------------------------------------------------------------

def parse_sha256sums(text: str) -> Dict[str, str]:
    """``sha256sum`` output: ``<64 hex>  <name>`` (or ``<hex> *<name>``). Conflicting duplicates are refused."""
    out: Dict[str, str] = {}
    for n, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        m = re.match(r"^([0-9a-fA-F]{64}) [ *](.+)$", line)
        if not m:
            raise BuildError("SHA256SUMS line %d is not '<sha256>  <name>'" % n)
        digest, name = m.group(1).lower(), m.group(2)
        if "/" in name or name in (".", ".."):
            raise BuildError("SHA256SUMS line %d names a path, not a file: %r" % (n, name))
        if out.get(name, digest) != digest:
            raise BuildError("SHA256SUMS lists %s twice with different digests" % name)
        out[name] = digest
    return out


def read_verified(release: Path, name: str, sums: Dict[str, str]) -> bytes:
    """The archive's bytes, after checking them against SHA256SUMS."""
    want = sums.get(name)
    if want is None:
        raise BuildError("SHA256SUMS has no entry for %s" % name)
    data = (release / name).read_bytes()
    got = hashlib.sha256(data).hexdigest()
    if got != want:
        raise BuildError("%s does not match SHA256SUMS (got %s, listed %s)" % (name, got, want))
    return data


# --- the binary --------------------------------------------------------------------------------------------

def inspect_binary(data: bytes) -> Tuple[str, int, Optional[Tuple[int, int]]]:
    """(``elf``|``macho``, machine code, macOS minimum version or None). Raises BuildError on anything else."""
    if data[:4] == b"\x7fELF":
        if len(data) < 20 or data[4] != 2:  # 64-bit only
            raise BuildError("the binary is not a 64-bit ELF file")
        endian = "<" if data[5] == 1 else ">"
        return "elf", struct.unpack_from(endian + "H", data, 18)[0], None
    if data[:4] == b"\xcf\xfa\xed\xfe":  # 64-bit little-endian Mach-O (every supported Mac)
        cputype, _sub, filetype, ncmds, _size = struct.unpack_from("<iiIII", data, 4)
        if filetype != 2:
            raise BuildError("the Mach-O file is not an executable")
        minos: Optional[Tuple[int, int]] = None
        off = 32
        for _ in range(ncmds):
            if off + 8 > len(data):
                raise BuildError("the Mach-O load commands run past the end of the file")
            cmd, size = struct.unpack_from("<II", data, off)
            if size < 8:
                raise BuildError("the Mach-O load commands are malformed")
            if cmd == 0x32 and size >= 16:  # LC_BUILD_VERSION: platform, minos, sdk
                v = struct.unpack_from("<I", data, off + 12)[0]
                minos = (v >> 16, (v >> 8) & 0xFF)
            elif cmd == 0x24 and size >= 12:  # LC_VERSION_MIN_MACOSX
                v = struct.unpack_from("<I", data, off + 8)[0]
                minos = (v >> 16, (v >> 8) & 0xFF)
            off += size
        return "macho", cputype & 0xFFFFFFFF, minos
    raise BuildError("the binary is neither an ELF nor a 64-bit Mach-O executable")


def platform_tag(t: Target, minos: Optional[Tuple[int, int]]) -> str:
    """The target's tag; a macOS tag is raised to the binary's own minimum OS when that is higher."""
    if t.os != "darwin" or minos is None:
        return t.tag
    m = re.match(r"^macosx_(\d+)_(\d+)_(.+)$", t.tag)
    assert m
    floor = (int(m.group(1)), int(m.group(2)))
    if minos <= floor:
        return t.tag
    if minos[0] >= 11:
        minos = (minos[0], 0)  # since macOS 11 the minor version is not part of the tag
    return "macosx_%d_%d_%s" % (minos[0], minos[1], m.group(3))


def binary_from_archive(archive: bytes, version: str, t: Target) -> Tuple[bytes, Dict[str, bytes]]:
    """(binary, {LICENSE, NOTICE}) read in memory from ``commons-<v>-<os>-<arch>/`` in the archive."""
    top = "commons-%s-%s-%s" % (version, t.os, t.arch)
    wanted = {top + "/commons": MAX_BINARY, top + "/LICENSE": MAX_SMALL, top + "/NOTICE": MAX_SMALL}
    found: Dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
            for m in tf:  # a streaming pass; nothing is extracted
                if m.name in wanted:
                    if not m.isreg() or m.size > wanted[m.name]:
                        raise BuildError("%s in the archive is not a regular file of reasonable size" % m.name)
                    f = tf.extractfile(m)
                    assert f is not None
                    found[m.name] = f.read()
    except (tarfile.TarError, EOFError, OSError) as e:
        raise BuildError("cannot read the archive: %s" % e)
    for n in wanted:
        if n not in found:
            raise BuildError("the archive has no %s" % n)
    return found[top + "/commons"], {"LICENSE": found[top + "/LICENSE"], "NOTICE": found[top + "/NOTICE"]}


# --- the wheel ---------------------------------------------------------------------------------------------

def _record_hash(data: bytes) -> str:
    return "sha256=" + base64.urlsafe_b64encode(hashlib.sha256(data).digest()).rstrip(b"=").decode("ascii")


def _metadata(py_version: str) -> bytes:
    pyproject = (PKG_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    readme = (PKG_ROOT / "README.md").read_text(encoding="utf-8")
    requires = re.search(r'(?m)^requires-python\s*=\s*"([^"]+)"', pyproject)
    summary = re.search(r'(?m)^description\s*=\s*"([^"]+)"', pyproject)
    if not requires or not summary:
        raise BuildError("pyproject.toml lacks requires-python or description")
    lines = [
        "Metadata-Version: 2.4",
        "Name: research-commons",
        "Version: " + py_version,
        "Summary: " + summary.group(1),
        "Project-URL: Source, https://github.com/research-common/research-commons",
        "Project-URL: Issues, https://github.com/research-common/research-commons/issues",
        "Author: The Research Commons Authors",
        "License-Expression: Apache-2.0",
        "License-File: LICENSE",
        "License-File: NOTICE",
        "Classifier: Development Status :: 3 - Alpha",
        "Classifier: Operating System :: MacOS",
        "Classifier: Operating System :: POSIX :: Linux",
        "Classifier: Programming Language :: Python :: 3",
        "Classifier: Typing :: Typed",
        "Requires-Python: " + requires.group(1),
        "Description-Content-Type: text/markdown",
    ]
    return ("\n".join(lines) + "\n\n" + readme).encode("utf-8")


def _info(name: str, data: bytes, mode: int) -> Tuple[zipfile.ZipInfo, bytes]:
    zi = zipfile.ZipInfo(name, ZIP_TIME)
    zi.compress_type = zipfile.ZIP_DEFLATED
    zi.create_system = 3  # Unix, so external_attr carries the mode
    zi.external_attr = (0o100000 | mode) << 16
    return zi, data


def build_wheel(py_version: str, tag: str, binary: bytes, licences: Dict[str, bytes]) -> bytes:
    """One platform wheel, as bytes."""
    dist_info = "%s-%s.dist-info" % (DIST_NAME, py_version)
    files: Dict[str, Tuple[bytes, int]] = {}
    src = PKG_ROOT / "src" / DIST_NAME
    for p in sorted(src.iterdir()):
        if p.is_file() and (p.suffix == ".py" or p.name == "py.typed"):
            files["%s/%s" % (DIST_NAME, p.name)] = (p.read_bytes(), 0o644)
    if "%s/__init__.py" % DIST_NAME not in files:
        raise BuildError("python/src/research_commons/__init__.py is missing")
    files["%s/_bin/commons" % DIST_NAME] = (binary, 0o755)
    meta: Dict[str, bytes] = {
        "METADATA": _metadata(py_version),
        "WHEEL": ("Wheel-Version: 1.0\nGenerator: research-commons build_wheels.py\nRoot-Is-Purelib: false\n"
                  "Tag: py3-none-%s\n" % tag).encode("ascii"),
        "entry_points.txt": b"[console_scripts]\ncommons = research_commons._cli:main\n",
        "licenses/LICENSE": licences["LICENSE"],
        "licenses/NOTICE": licences["NOTICE"],
    }
    for n, d in meta.items():
        files["%s/%s" % (dist_info, n)] = (d, 0o644)
    record = []
    for name in sorted(files, key=lambda n: (n.startswith(dist_info + "/"), n)):  # package first, dist-info after
        d, _ = files[name]
        record.append("%s,%s,%d" % (name, _record_hash(d), len(d)))
    record.append("%s/RECORD,," % dist_info)
    files[dist_info + "/RECORD"] = (("\n".join(record) + "\n").encode("utf-8"), 0o644)
    order = sorted(files, key=lambda n: (n == dist_info + "/RECORD", n.startswith(dist_info + "/"), n))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name in order:
            d, mode = files[name]
            zi, data = _info(name, d, mode)
            z.writestr(zi, data, zipfile.ZIP_DEFLATED, 9)
    return buf.getvalue()


def wheel_filename(py_version: str, tag: str) -> str:
    return "%s-%s-py3-none-%s.whl" % (DIST_NAME, py_version, tag)


# --- driver ------------------------------------------------------------------------------------------------

def build_all(release: Path, out: Path, version_file: Path) -> List[Path]:
    """Build every wheel or refuse; nothing is written to ``out`` unless all four pass."""
    tool_version = version_file.read_text(encoding="utf-8").strip()
    py_version = pep440(tool_version)
    _declared_versions(py_version)
    sums_path = release / "SHA256SUMS"
    if not sums_path.is_file():
        raise BuildError("%s has no SHA256SUMS" % release)
    sums = parse_sha256sums(sums_path.read_text(encoding="utf-8"))

    expected = {"commons-%s-%s-%s.tar.gz" % (tool_version, t.os, t.arch): t for t in TARGETS}
    for p in sorted(release.glob("commons-*.tar.gz")):
        if p.name not in expected:
            raise BuildError("%s does not belong to VERSION %s (expected %s)" % (p.name, tool_version, ", ".join(sorted(expected))))
    for name in expected:
        if not (release / name).is_file():
            raise BuildError("missing release archive %s" % name)

    built: List[Tuple[str, bytes]] = []
    for name, t in sorted(expected.items()):
        data = read_verified(release, name, sums)  # before anything is opened
        binary, licences = binary_from_archive(data, tool_version, t)
        kind, machine, minos = inspect_binary(binary)
        if (kind, machine) != t.machine:
            raise BuildError("%s: the binary is %s machine %#x, not the %s/%s executable the name says" % (name, kind, machine, t.os, t.arch))
        tag = platform_tag(t, minos)
        built.append((wheel_filename(py_version, tag), build_wheel(py_version, tag, binary, licences)))

    out.mkdir(parents=True, exist_ok=True)
    paths = []
    for fname, blob in built:
        p = out / fname
        tmp = out / (fname + ".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, p)
        paths.append(p)
    return paths


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("release_dir", type=Path, help="directory with the four release archives and SHA256SUMS")
    ap.add_argument("--out", type=Path, default=REPO_ROOT / "dist", help="where to write the wheels (default: dist/)")
    ap.add_argument("--version-file", type=Path, default=REPO_ROOT / "VERSION")
    a = ap.parse_args(argv)
    try:
        paths = build_all(a.release_dir, a.out, a.version_file)
    except BuildError as e:
        print("build_wheels: refused: %s" % e, file=sys.stderr)
        return 1
    for p in paths:
        print("%s  %s" % (hashlib.sha256(p.read_bytes()).hexdigest(), p))
    return 0


if __name__ == "__main__":
    sys.exit(main())
