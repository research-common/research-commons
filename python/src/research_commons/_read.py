"""Conveniences for the read commands most scripts need. Each passes its arguments straight to the binary
and returns the :class:`~research_commons._run.Result`; none interprets an answer."""

from __future__ import annotations

import os
from typing import Optional, Union

from ._run import Result, run

Path = Union[str, "os.PathLike[str]"]


def _common(store: Optional[Path], policy: Optional[Path]) -> list:
    a: list = []
    if store is not None:
        a += ["--store", store]
    if policy is not None:
        a += ["--policy", policy]
    return a


def show(ref: str, *, store: Optional[Path] = None, policy: Optional[Path] = None, check: bool = True) -> Result:
    """``commons show <digest|id> --json``."""
    return run("show", *_common(store, policy), ref, check=check)


def verify(ref: str, *, store: Optional[Path] = None, policy: Optional[Path] = None, check: bool = True) -> Result:
    """``commons verify <digest|id> --json``.

    ``verify`` answers with exit 0 (checked and passed), 1 (a completed comparison disagreed) or 3 (could
    not check); with ``check=False`` those come back as a ``Result`` whose ``json`` is the verdict, never
    as an exception. With the default ``check=True`` they raise ``CheckedAndWrong`` / ``CouldNotCheck`` and
    the verdict is on ``exc.result.json``.
    """
    return run("verify", *_common(store, policy), ref, check=check)


def list_(*, store: Optional[Path] = None, policy: Optional[Path] = None, check: bool = True) -> Result:
    """``commons list --json``."""
    return run("list", *_common(store, policy), check=check)


def status(
    *, store: Optional[Path] = None, policy: Optional[Path] = None, limits: bool = False, check: bool = True
) -> Result:
    """``commons status [--limits] --json``."""
    extra = ["--limits"] if limits else []
    return run("status", *extra, *_common(store, policy), check=check)


def version() -> Result:
    """``commons --version --json``: ``json`` has ``version``, ``commit`` and ``go``."""
    return run("--version")
