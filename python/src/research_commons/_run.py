"""Run the ``commons`` binary with ``--json`` and map its outcome to a :class:`Result` or an exception."""

from __future__ import annotations

import json
import os
import subprocess
from dataclasses import dataclass
from typing import Any, List, Mapping, Optional, Sequence, Union

from ._binary import find_binary
from .errors import (
    EXIT_ERRORS,
    CommonsError,
    UnparseableOutput,
    is_problem,
)

#: The tool's exit table (``commons help exits``), for messages only; the class is chosen by the code.
EXIT_NAMES = {
    0: "ok",
    1: "checked and wrong",
    2: "did not start",
    3: "could not check",
    4: "nothing to re-run",
    5: "environment mismatch",
}

Arg = Union[str, "os.PathLike[str]"]


@dataclass(frozen=True)
class Result:
    """What one invocation produced.

    ``exit`` is the process exit code. ``json`` is the parsed stdout (one JSON value; ``None`` when stdout
    was empty or is not JSON). With a non-zero exit it is either a *verdict* (``verify``'s "could not
    check") or a problem object; ``problem`` is ``json`` when it is a problem and ``None`` otherwise.
    ``stdout`` and ``stderr`` are the decoded text, kept for debugging.
    """

    exit: int
    json: Any
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.exit == 0

    @property
    def problem(self) -> Optional[dict]:
        """The RFC 9457 problem object the tool printed, or ``None``."""
        return self.json if is_problem(self.json) else None


def _arg(a: Any) -> str:
    if isinstance(a, (str, os.PathLike)):
        s = os.fspath(a)
        if isinstance(s, str):
            return s
    raise TypeError("commons arguments must be str or path-like, got %s" % type(a).__name__)


def with_json_flag(args: Sequence[str]) -> List[str]:
    """``args`` with ``--json`` present before any ``--`` (which ends options), added once."""
    out = list(args)
    end = out.index("--") if "--" in out else len(out)
    if "--json" not in out[:end]:
        out.insert(end, "--json")
    return out


def _parse(raw: bytes) -> Any:
    if not raw.strip():
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def error_for(result: Result) -> CommonsError:
    """The exception for a non-zero ``result``: chosen by exit code, carrying the problem object if any."""
    cls = EXIT_ERRORS.get(result.exit, CommonsError)
    problem = result.problem
    if problem is not None and isinstance(problem.get("title"), str):
        # the tool's own words only; peer-supplied text is in problem["peer_text"]
        msg = problem["title"]
        if isinstance(problem.get("detail"), str) and problem["detail"]:
            msg += ": " + problem["detail"]
    elif result.exit < 0:
        msg = "commons was killed by signal %d" % -result.exit
    else:
        msg = "commons exited %d (%s)" % (result.exit, EXIT_NAMES.get(result.exit, "unknown exit code"))
    return cls(msg, exit=result.exit, problem=problem, result=result)


def run(
    *args: Arg,
    input: Union[str, bytes, None] = None,
    check: bool = True,
    cwd: Optional[Arg] = None,
    env: Optional[Mapping[str, str]] = None,
    timeout: Optional[float] = None,
) -> Result:
    """Run ``commons <args> --json`` and return its :class:`Result`.

    ``--json`` is added unless already given. With ``check=True`` (the default) a non-zero exit raises the
    :class:`~research_commons.errors.CommonsError` subclass for that exit code; a problem object on stdout
    is carried on it, a verdict (``verify`` exiting 1 or 3) is on ``exc.result``. With ``check=False`` every
    exit code returns a ``Result`` and the caller reads ``exit``. A missing binary raises
    :class:`~research_commons.errors.BinaryNotFound` either way. ``subprocess.TimeoutExpired`` propagates
    (the tool commits through a journal that the next open replays).
    """
    argv = with_json_flag([_arg(a) for a in args])
    binary = find_binary()
    data = input.encode("utf-8") if isinstance(input, str) else input
    try:
        proc = subprocess.run(
            [binary, *argv],
            input=data,
            stdin=None if data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=None if cwd is None else _arg(cwd),
            env=None if env is None else dict(env),
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as e:  # raced away between lookup and exec
        from .errors import BinaryNotFound

        raise BinaryNotFound("the commons binary disappeared before it could run") from e
    parsed = _parse(proc.stdout)
    result = Result(
        exit=proc.returncode,
        json=parsed,
        stdout=proc.stdout.decode("utf-8", "replace"),
        stderr=proc.stderr.decode("utf-8", "replace"),
    )
    if proc.returncode != 0:
        if check:
            raise error_for(result)
    elif parsed is None and proc.stdout.strip():
        if check:
            raise UnparseableOutput("commons exited 0 but its --json output is not JSON", exit=0, result=result)
    return result
