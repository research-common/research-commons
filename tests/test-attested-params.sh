#!/usr/bin/env bash
# Attested params cannot drift through --force; real signatures and CLI writes.
set -euo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
env -u COMMONS_SIGNING_KEY -u COMMONS_ROOT -u COMMONS_AGENT \
    PYTHONDONTWRITEBYTECODE=1 python3 - "$REPO" <<'PY'
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile

repo = Path(sys.argv[1])
tool = Path(os.environ.get("COMMONS_PARAMS_TEST_TOOL", repo / "bin/commons"))
passed = failed = 0

def check(label, result):
    global passed, failed
    if result:
        passed += 1
        print("  ok  " + label, flush=True)
    else:
        failed += 1
        print("  FAIL  " + label, flush=True)

with tempfile.TemporaryDirectory(prefix="commons-attested-params-") as temp:
    lab = Path(temp)
    key = lab / "identity.key"
    key.write_text("0x" + format(7, "064x") + "\n")
    key.chmod(0o600)
    root = lab / "data"
    env = dict(os.environ, COMMONS_ROOT=str(root), COMMONS_SIGNING_KEY=str(key))
    def cli(*args):
        return subprocess.run([str(tool), *map(str, args)], env=env, text=True,
                              capture_output=True, timeout=60)
    data = lab / "capture.json"
    data.write_text('{"observation":1}\n')
    r = cli("publish", "dataset", data, "capture", "--criteria", "capture protocol",
            "--param", "status=200", "--param", "empty=")
    if r.returncode: raise AssertionError(r.stderr)
    aid = r.stdout.strip().splitlines()[-1]
    path = root / "registry/artifacts" / (aid + ".json")
    r = cli("attest", aid)
    check("fixture attestation is created by CLI", r.returncode == 0)
    def ledger_bytes():
        return {p.name: p.read_bytes() for p in (root / "registry/ledger").glob("*.jsonl")}
    r = cli("publish", "dataset", data, "unchanged", "--force",
            "--param", "empty=", "--param", "status=200")
    check("same params in a different flag order republish", r.returncode == 0)
    m = json.loads(path.read_text())
    check("same params preserve empty member", m["verification"]["params"]["empty"] == "")
    attestation = m["verification"]["attested_by"]
    r = cli("publish", "dataset", data, "editorial", "--force", "--tier", "T3",
            "--criteria", "capture protocol")
    check("omitted params survive verification rebuild during editorial republish",
          r.returncode == 0 and json.loads(path.read_text())["verification"].get("params") ==
          {"status": "200", "empty": ""})
    check("editorial republish preserves the attestation statement",
          json.loads(path.read_text())["verification"]["attested_by"] == attestation)
    for params, label in ((["status=500", "empty="], "changed value"),
                          (["status=200"], "removed empty member"),
                          (["status=200", "empty=", "extra=x"], "added member")):
        before, logs = path.read_bytes(), ledger_bytes()
        r = cli("publish", "dataset", data, "changed", "--force",
                *[arg for value in params for arg in ("--param", value)])
        check("attested republish refuses " + label,
              r.returncode != 0 and "Changing --param" in r.stderr)
        check(label + " refusal leaves manifest and all logs unchanged",
              path.read_bytes() == before and ledger_bytes() == logs)
    # A v1 attestation still protects the manifest's recorded params from writers.
    m = json.loads(path.read_text())
    statement = dict(m["verification"]["attested_by"]["statement"])
    statement.pop("rc", None)
    statement.pop("params", None)
    signed = subprocess.run(["node", str(repo / "lib/sign-message.mjs"), "--stdin"],
                            input=json.dumps(statement, sort_keys=True, separators=(",", ":")),
                            env=env, text=True, capture_output=True, check=True)
    signature = json.loads(signed.stdout)
    m["verification"]["attested_by"] = {
        "statement": statement, "addr": signature["address"], "sig": signature["signature"]}
    path.write_text(json.dumps(m))
    before, logs = path.read_bytes(), ledger_bytes()
    r = cli("publish", "dataset", data, "v1 drift", "--force", "--param", "status=500")
    check("legacy v1 attestation also refuses changed params",
          r.returncode != 0 and "Changing --param" in r.stderr)
    check("legacy refusal leaves signed manifest and logs unchanged",
          before == path.read_bytes() and logs == ledger_bytes())
    # Opaque JSON values on a held legacy claim must survive editorial changes
    # and be emitted exactly by attestation/2, without truthiness coercion.
    typed_data = lab / "typed-capture.txt"
    typed_data.write_text("typed capture fixture\n")
    fixture = subprocess.run(
        [sys.executable, str(repo / "tests/legacy-writer-fixture.py"), str(tool),
         "publish", "dataset", str(typed_data), "typed capture",
         "--criteria", "typed protocol", "--license", "CC0-1.0"],
        env=env, text=True, capture_output=True, check=True)
    typed_id = fixture.stdout.strip().splitlines()[-1]
    typed_path = root / "registry/artifacts" / (typed_id + ".json")
    typed = json.loads(typed_path.read_text())
    exact = {"false": False, "int": 0, "float": 0.0, "empty": "",
             "null": None, "list": [], "object": {}}
    typed["verification"]["params"] = exact
    typed_path.write_text(json.dumps(typed))
    r = cli("attest", typed_id)
    current = json.loads(typed_path.read_text())["verification"]
    check("attestation/2 emits opaque bool, int, float and empty members exactly",
          r.returncode == 0 and current["attested_by"]["statement"].get("rc") ==
          "attestation/2" and json.dumps(
              current["attested_by"]["statement"].get("params"), sort_keys=True) ==
          json.dumps(exact, sort_keys=True))
    r = cli("publish", "dataset", typed_data, "typed editorial", "--force", "--tier", "T3")
    check("editorial rebuild carries opaque params without changing JSON types",
          r.returncode == 0 and json.dumps(
              json.loads(typed_path.read_text())["verification"].get("params"), sort_keys=True) ==
          json.dumps(exact, sort_keys=True))
    # Security contract: Python object equality would wrongly equate these values.
    os.environ.update(env)
    canonical = runpy.run_path(str(tool)).get("canonical_verification_params")
    for left, right, label in ((False, 0, "false differs from zero"),
                               (0, 0.0, "integer differs from float"),
                               ("", None, "empty value differs from null"),
                               ("", [], "empty value differs from empty list")):
        check(label, canonical is not None and
              canonical({"params": {"p": left}}) != canonical({"params": {"p": right}}))
    check("absent params and empty object are equivalent", canonical is not None and
          canonical({}) == canonical({"params": {}}))
    check("null params and empty object are equivalent", canonical is not None and
          canonical({"params": None}) == canonical({"params": {}}))
print("attested-params: %d passed, %d failed" % (passed, failed))
raise SystemExit(bool(failed))
PY
