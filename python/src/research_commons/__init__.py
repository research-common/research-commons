"""A thin wrapper around the Research Commons command-line tool.

It runs the ``commons`` binary with ``--json`` and returns what it printed. It never reimplements any
logic of the tool: every answer, token and exit code is the binary's own. An RFC 9457 problem object the
binary prints becomes an exception, chosen by exit code.

    >>> import research_commons as rc
    >>> rc.run("--version").json["version"]            # doctest: +SKIP
    '0.5.0-alpha.3'
    >>> rc.verify("sha256:…", check=False).exit         # doctest: +SKIP
    3
"""

from __future__ import annotations

from ._binary import bundled_binary, find_binary
from ._read import list_, show, status, verify, version
from ._run import Result, run
from .errors import (
    BinaryNotFound,
    CheckedAndWrong,
    CommonsError,
    CouldNotCheck,
    DidNotStart,
    EnvironmentMismatch,
    NothingToRerun,
    UnparseableOutput,
)

__version__ = "0.5.0a3"

__all__ = [
    "run",
    "Result",
    "show",
    "verify",
    "list_",
    "status",
    "version",
    "find_binary",
    "bundled_binary",
    "CommonsError",
    "CheckedAndWrong",
    "DidNotStart",
    "CouldNotCheck",
    "NothingToRerun",
    "EnvironmentMismatch",
    "BinaryNotFound",
    "UnparseableOutput",
    "__version__",
]
