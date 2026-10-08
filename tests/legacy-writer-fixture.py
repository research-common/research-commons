# SPDX-License-Identifier: Apache-2.0
"""Construct genuine pre-view writer output for legacy transport regressions.

This is fixture construction, never a production switch. The current CLI still
supplies content/spec validation; signatures are real and independently emitted.
Phase 2 writers themselves are exercised in test-view-writers.
"""
import hashlib
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys

tool, command, *args = sys.argv[1:]
ns = runpy.run_path(tool)
root = Path(ns["ROOT"])
key_env = dict(os.environ)
if command == "publish":
    unsigned_log = root / "registry/ledger/local-unsigned.jsonl"
    old = unsigned_log.read_bytes() if unsigned_log.exists() else b""
    env = dict(key_env)
    env.pop("COMMONS_SIGNING_KEY", None)
    result = subprocess.run([tool, command, *args], env=env, text=True, capture_output=True)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)
    current = unsigned_log.read_bytes() if unsigned_log.exists() else old
    events = [json.loads(line) for line in current[len(old):].splitlines() if line.strip()]
    if old:
        unsigned_log.write_bytes(old)
    elif unsigned_log.exists():
        unsigned_log.unlink()
    for event in events:
        for field in ("addr", "sig", "sig2", "prev", "ts"):
            event.pop(field, None)
        ns["ledger_append"](event)
elif command == "unview":
    # Strip the view from a just-created fixture, then independently sign and
    # re-chain its ledger. Used for run output whose production writer is viewed.
    aid = args[0]
    manifest = ns["load_manifest"](aid)
    manifest.pop("publisher_sig", None)
    ns["write_manifest"](aid, manifest)
    for path in (root / "registry/ledger").glob("*.jsonl"):
        events = [json.loads(line) for line in path.read_text().splitlines() if line]
        if not any(e.get("id") == aid and e.get("view") for e in events):
            continue
        prev = None
        lines = []
        for event in events:
            if event.get("id") == aid and event.get("view"):
                event.pop("view")
                for field in ("addr", "sig", "sig2"):
                    event.pop(field, None)
                addr, sig, sig2 = ns["sign_entry"](event, dual=True)
                event.update(addr=addr, sig=sig, sig2=sig2)
            event["prev"] = prev
            line = json.dumps(event, sort_keys=True)
            lines.append(line)
            prev = hashlib.sha256(line.encode()).hexdigest()
        path.write_text("".join(line + "\n" for line in lines))
elif command == "attest":
    aid, *options = args
    manifest = ns["load_manifest"](aid)
    verification = manifest.setdefault("verification", {})
    force = "--force" in options
    if verification.get("attested_by") and not force:
        raise SystemExit("fixture: already attested")
    if "--criteria" in options:
        verification["criteria"] = options[options.index("--criteria") + 1]
    observed = options[options.index("--observed") + 1] if "--observed" in options else None
    statement = {"attests": aid, "sha256": manifest["content"]["sha256"],
                 "criteria": verification.get("criteria") or ns["DEFAULT_T3_CRITERIA"],
                 "observed": ns["validate_observed"](observed)}
    signed = subprocess.run(
        ["node", str(Path(tool).resolve().parents[1] / "lib/sign-message.mjs"), "--stdin"],
        input=json.dumps(statement, sort_keys=True, separators=(",", ":")),
        text=True, capture_output=True, env=key_env, check=True)
    signature = json.loads(signed.stdout)
    verification["attested_by"] = {"addr": signature["address"],
                                  "sig": signature["signature"], "statement": statement}
    ns["write_manifest"](aid, manifest)
    ns["ledger_append"]({"agent": os.environ.get("COMMONS_AGENT", "fixture"),
                         "action": "attest", "id": aid,
                         "sha256": manifest["content"]["sha256"], "tier": "T3"})
    print("legacy fixture attested " + aid)
elif command in ("submit", "accept"):
    result = subprocess.run([tool, command, *args], text=True, capture_output=True)
    sys.stdout.write(result.stdout)
    sys.stderr.write(result.stderr)
    if result.returncode:
        raise SystemExit(result.returncode)
    task, result_id = args[:2]
    aid, relation, target = (result_id, "fulfills", task) if command == "submit" \
        else (task, "accepted", result_id)
    manifest = ns["load_manifest"](aid)
    link = {"rel": relation, "id": target}
    if link not in manifest.setdefault("links", []):
        manifest["links"].append(link)
        ns["write_manifest"](aid, manifest)
else:
    raise SystemExit("unsupported legacy fixture command: " + command)
