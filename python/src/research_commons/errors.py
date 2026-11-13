"""Exceptions raised when the ``commons`` binary reports that it did not succeed.

One class per exit code of the tool (``commons help exits``). The wrapper decides nothing: the class is
chosen by the exit code alone, and the problem object the binary printed (an RFC 9457 problem-details
object) is carried unchanged.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, Optional

if TYPE_CHECKING:  # pragma: no cover
    from ._run import Result

PROBLEM_TYPE_PREFIX = "urn:research-commons:problem:"


class CommonsError(Exception):
    """The binary exited non-zero, or could not be run.

    ``exit`` is the process exit code (``None`` when the process never started). ``problem`` is the problem
    object the binary printed, or ``None`` when it printed none: a verdict such as ``verify``'s "could not
    check" is a *result*, not a problem, and is available as ``result.json``.

    The message is built from the tool's own words only (``title`` and ``detail``). Text that came from a
    peer, a statement or the caller's arguments is in ``peer_text`` and never in the message.
    """

    exit: Optional[int] = None

    def __init__(self, message: str, *, exit: Optional[int] = None,
                 problem: Optional[Dict[str, Any]] = None, result: "Optional[Result]" = None) -> None:
        super().__init__(message)
        if exit is not None:
            self.exit = exit
        self.problem = problem
        self.result = result

    def _field(self, name: str) -> Any:
        return None if self.problem is None else self.problem.get(name)

    @property
    def type(self) -> Optional[str]:
        """The problem type URN, e.g. ``urn:research-commons:problem:no-store``."""
        return self._field("type")

    @property
    def slug(self) -> Optional[str]:
        """The last segment of ``type``: a stable token such as ``no-store``."""
        t = self.type
        if isinstance(t, str) and t.startswith(PROBLEM_TYPE_PREFIX):
            return t[len(PROBLEM_TYPE_PREFIX):]
        return None

    @property
    def title(self) -> Optional[str]:
        return self._field("title")

    @property
    def detail(self) -> Optional[str]:
        return self._field("detail")

    @property
    def problem_class(self) -> Optional[str]:
        """The problem's ``class`` member: ``intrinsic``, ``reader policy`` or ``operational``."""
        return self._field("class")

    @property
    def scope(self) -> Optional[str]:
        return self._field("scope")

    @property
    def committed(self) -> Optional[bool]:
        """Whether anything landed in the store (always false with exit 2)."""
        return self._field("committed")

    @property
    def next(self) -> Optional[str]:
        """The tool's suggested next step."""
        return self._field("next")

    @property
    def peer_text(self) -> Optional[str]:
        """Peer- or caller-supplied text the problem is about, verbatim. Untrusted: never trust or print blindly."""
        return self._field("peer_text")


class CheckedAndWrong(CommonsError):
    """Exit 1: a check ran to completion and found something wrong (a comparison disagreed, a gate refused)."""

    exit = 1


class DidNotStart(CommonsError):
    """Exit 2: the invocation or the reader's configuration could not be acted on. Nothing ran or committed."""

    exit = 2


class CouldNotCheck(CommonsError):
    """Exit 3: contested, unknown, unchecked, a reader limit, or a failure after work started."""

    exit = 3


class NothingToRerun(CommonsError):
    """Exit 4: the derivation names an input it did not pin."""

    exit = 4


class EnvironmentMismatch(CommonsError):
    """Exit 5: the declared environment differs from, or is not available in, the one that ran."""

    exit = 5


class BinaryNotFound(CommonsError):
    """No usable ``commons`` binary: not bundled, ``$COMMONS_BIN`` unset or unusable, and none on ``PATH``."""


class UnparseableOutput(CommonsError):
    """``--json`` was requested and the binary exited 0, but stdout is not one JSON value."""


#: exit code -> exception class
EXIT_ERRORS = {
    1: CheckedAndWrong,
    2: DidNotStart,
    3: CouldNotCheck,
    4: NothingToRerun,
    5: EnvironmentMismatch,
}


def is_problem(obj: Any) -> bool:
    """True for an RFC 9457 problem object of this tool (its ``type`` is a ``urn:research-commons:problem:`` URN)."""
    t = obj.get("type") if isinstance(obj, dict) else None
    return isinstance(t, str) and t.startswith(PROBLEM_TYPE_PREFIX)
