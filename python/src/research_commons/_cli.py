"""The ``commons`` console script: hands the process to the binary, so ``pip install research-commons``
gives the CLI with the binary's own exit codes and streams."""

from __future__ import annotations

import os
import shutil
import sys
from typing import NoReturn

from ._binary import find_binary
from .errors import BinaryNotFound


def _self_path() -> str:
    """This launcher's own path, so a ``PATH`` search never finds it again and loops."""
    a = sys.argv[0]
    if os.sep not in a:
        a = shutil.which(a) or a
    return a


def main() -> NoReturn:
    try:
        binary = find_binary(skip=_self_path())
    except BinaryNotFound as e:
        sys.stderr.write("commons: %s\n" % e)
        sys.exit(2)
    sys.stdout.flush()
    sys.stderr.flush()
    os.execv(binary, [binary, *sys.argv[1:]])


if __name__ == "__main__":  # pragma: no cover
    main()
