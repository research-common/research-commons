# research-commons (Python)

A thin Python wrapper around the [Research Commons](https://github.com/research-common/research-commons)
command-line tool, `commons`. It runs the binary with `--json` and returns what it printed. It never
reimplements any logic of the tool: every answer, token and exit code is the binary's own.

Alpha: the tool's `--json` output may change between alpha releases, and so may this package's surface.
Python 3.9 or newer, standard library only. Linux and macOS (the tool does not build for Windows).

## Install

```bash
pip install research-commons
commons --version
```

A platform wheel (Linux x86-64 and arm64, macOS x86-64 and arm64) carries the `commons` binary and installs a
`commons` command that runs it. Without a wheel for your platform, the package still imports; it finds the
binary in this order: the one bundled in the wheel, `$COMMONS_BIN`, then `PATH`. A `$COMMONS_BIN` that is set
but is not an executable file is an error (it never falls through to `PATH`).

## Use

```python
import research_commons as rc

r = rc.run("list", "--store", "/path/to/store")   # Result(exit, json, stdout, stderr)
r.json["count"]

rc.show(digest, store=...)                        # thin conveniences: show, verify, list_, status, version
r = rc.verify(digest, store=..., check=False)     # exit 0, 1 and 3 are verdicts, not exceptions
r.exit, r.json["grade"]
```

`run(*args, input=None, check=True, cwd=None, env=None, timeout=None)` adds `--json` unless you gave it.

### Errors

With `check=True` (the default) a non-zero exit raises a `CommonsError` subclass chosen by the **exit code**
alone (`commons help exits`):

| exit | exception |
|---|---|
| 1 | `CheckedAndWrong` |
| 2 | `DidNotStart` |
| 3 | `CouldNotCheck` |
| 4 | `NothingToRerun` |
| 5 | `EnvironmentMismatch` |

When the binary printed an RFC 9457 problem object, it is on the exception: `e.problem` (the whole object),
`e.slug`, `e.type`, `e.title`, `e.detail`, `e.problem_class`, `e.scope`, `e.committed`, `e.next`, `e.peer_text`.
The message holds only the tool's own words; text that came from a peer or from your arguments is in
`peer_text` and is untrusted. A *verdict* (`verify` exiting 1 or 3 prints a result, not a problem) has no
problem: read `e.result.json`, or call with `check=False`.

`BinaryNotFound` means there is no binary to run; `UnparseableOutput` means exit 0 with non-JSON stdout.

## Develop

```bash
cd python
python3 -m unittest -v        # builds ./cmd/commons for the real-binary tests when Go is installed
python3 scripts/build_wheels.py --help
```
