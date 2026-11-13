"""Finding the ``commons`` executable.

Order: the binary bundled in a platform wheel, then ``$COMMONS_BIN``, then ``PATH``.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from .errors import BinaryNotFound

ENV_VAR = "COMMONS_BIN"
_BUNDLED = Path(__file__).resolve().parent / "_bin" / "commons"


def _usable(path: "str | os.PathLike[str]") -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def bundled_binary() -> Optional[str]:
    """The binary inside this installation (platform wheels only), or ``None``."""
    return str(_BUNDLED) if _usable(_BUNDLED) else None


def _which(skip: Optional[str]) -> Optional[str]:
    """First ``commons`` on ``PATH`` that is not ``skip`` (compared by real path)."""
    skip_real = os.path.realpath(skip) if skip else None
    for d in os.environ.get("PATH", "").split(os.pathsep):
        if not d:
            continue
        cand = os.path.join(d, "commons")
        if _usable(cand) and (skip_real is None or os.path.realpath(cand) != skip_real):
            return cand
    return None


def find_binary(*, skip: Optional[str] = None) -> str:
    """Return the path of the ``commons`` binary to run.

    ``skip`` names a file to pass over while searching ``PATH`` (the console script uses it to avoid
    finding itself). A ``$COMMONS_BIN`` that is set but not an executable file is an error, never a silent
    fall-through to ``PATH``: the caller asked for that file.
    """
    b = bundled_binary()
    if b:
        return b
    env = os.environ.get(ENV_VAR, "")
    if env:
        if _usable(env):
            return env
        raise BinaryNotFound(f"${ENV_VAR} is set but is not an executable file")
    p = _which(skip)
    if p:
        return p
    raise BinaryNotFound(
        "no commons binary found: none bundled in this installation, $%s is not set, and there is "
        "none on PATH (install a platform wheel, or build it with `go build ./cmd/commons`)" % ENV_VAR
    )


__all__ = ["find_binary", "bundled_binary", "ENV_VAR"]
