# SPDX-License-Identifier: Apache-2.0
"""Exercise phase 2 through subprocesses; COMMONS_WRITER_TEST_TOOL selects a baseline."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

REPO = Path(__file__).resolve().parents[1]
TOOL = Path(os.environ.get("COMMONS_WRITER_TEST_TOOL", REPO / "bin/commons"))
passed = failed = 0


def check(label, yes):
    global passed, failed
    if yes:
        passed += 1
        print("  ok  " + label, flush=True)
    else:
        failed += 1
        print("  FAIL  " + label, flush=True)


with tempfile.TemporaryDirectory(prefix="commons-view-writers-") as temp:
    lab = Path(temp)
    root = lab / "hub"
    root.mkdir()
    keys = []
    for number in (1, 2, 3):
        key = lab / ("key%d" % number)
        key.write_text("0x" + ("%064x" % number) + "\n")
        key.chmod(0o600)
        keys.append(key)
    env = dict(os.environ, COMMONS_ROOT=str(root), COMMONS_AGENT="writer",
               COMMONS_SIGNING_KEY=str(keys[0]), COMMONS_EXEC="native")
    env.update(GIT_AUTHOR_NAME="test", GIT_AUTHOR_EMAIL="test@example.org",
               GIT_COMMITTER_NAME="test", GIT_COMMITTER_EMAIL="test@example.org")

    def cli(*args, key=0, unsigned=False, root_at=None):
        e = dict(env)
        if unsigned:
            e.pop("COMMONS_SIGNING_KEY", None)
        else:
            e["COMMONS_SIGNING_KEY"] = str(keys[key])
        if root_at is not None:
            e["COMMONS_ROOT"] = str(root_at)
        return subprocess.run([str(TOOL), *map(str, args)], env=e, cwd=lab,
                              text=True, capture_output=True, timeout=60)

    def publish(kind, content, title, *args, **kwargs):
        file = lab / (title.replace(" ", "-") + ".json")
        file.write_text(content)
        r = cli("publish", kind, file, title, *args, **kwargs)
        if r.returncode:
            raise AssertionError("fixture publish: " + r.stdout + r.stderr)
        return kind, file, r.stdout.strip().splitlines()[-1]

    def manifest(aid, root_at=root):
        return json.loads((root_at / "registry/artifacts" / (aid + ".json")).read_text())

    def events(root_at=root):
        return [json.loads(line) for p in sorted((root_at / "registry/ledger").glob("*.jsonl"))
                for line in p.read_text().splitlines()]

    def view_bound(aid):
        m = manifest(aid)
        sig = m.get("publisher_sig", {})
        stmt = sig.get("statement", {})
        return (stmt.get("rc") == "manifest/1" and
                stmt.get("sha256") == m["content"]["sha256"] and
                any(e.get("id") == aid and e.get("view") == stmt.get("view")
                    and e.get("addr") == sig.get("addr") and e.get("sig") and e.get("sig2")
                    for e in events()))

    addresses = [cli("peer", "whoami", key=i).stdout.splitlines()[0] for i in range(3)]
    for i, address in enumerate(addresses):
        cli("peer", "add", address, "--agent-id", "writer%d" % i, "--trust", "full")
    ds = publish("dataset", '{"capture":1}\n', "capture", "--criteria", "captured",
                 "--param", "status=200", "--param", "empty=",
                 "--license", "CC0-1.0", "--obtainability", "open")
    aid = ds[2]
    check("keyed publish emits view bound to dual-signed event", view_bound(aid))
    before = (root / "registry/artifacts" / (aid + ".json")).read_bytes()
    r = cli("publish", ds[0], ds[1], "foreign", "--force", key=1)
    check("foreign key cannot replace held view", r.returncode != 0)
    check("refused replacement leaves manifest unchanged",
          (root / "registry/artifacts" / (aid + ".json")).read_bytes() == before)
    r = cli("publish", ds[0], ds[1], "revised", "--force")
    check("own republish succeeds and binds new view", r.returncode == 0 and view_bound(aid))
    check("republish authenticates exact new title", manifest(aid)["title"] == "revised")
    r = cli("attest", aid, "--observed", "2026-09-01T00:00:00Z")
    att = manifest(aid).get("verification", {}).get("attested_by", {})
    check("attest emits attestation/2", r.returncode == 0 and
          att.get("statement", {}).get("rc") == "attestation/2")
    check("attestation signs params including an empty member",
          att.get("statement", {}).get("params") == {"status": "200", "empty": ""})
    check("attestation preserves publisher signature", view_bound(aid))
    r = cli("fsck", "--views", "--ledger")
    check("emitted view and dual signatures pass real cryptographic audits", r.returncode == 0)
    capture_path = root / "registry/artifacts" / (aid + ".json")
    saved_capture = capture_path.read_bytes()
    m = manifest(aid)
    m["verification"]["params"]["status"] = "500"
    capture_path.write_text(json.dumps(m))
    r = cli("verify", aid)
    check("the #10 params forgery fails verification as altered metadata",
          r.returncode == 1 and "METADATA ALTERED" in r.stdout + r.stderr)
    probe = subprocess.run(
        ["python3", "-c",
         "import runpy,sys; n=runpy.run_path(sys.argv[1]); "
         "print(n['check_attestation'](n['load_manifest'](sys.argv[2]))[0])",
         str(TOOL), aid], env=env, text=True, capture_output=True)
    check("the #10 params forgery also leaves attestation stale", probe.stdout.strip() == "stale")
    capture_path.write_bytes(saved_capture)
    r = cli("attest", aid, "--force", key=1)
    check("force cannot displace a different attester", r.returncode != 0)
    r = cli("attest", aid, "--force", "--criteria", "new observation")
    check("owner changing criteria emits a matching republish view",
          r.returncode == 0 and view_bound(aid))

    # A genuine signed legacy publish, produced independently of the current writer.
    def legacy(title, owners=(0,), collection=False):
        typ = "collection" if collection else "dataset"
        content = (json.dumps({"scope": title, "members": [],
                              "maintainers": [{"addr": addresses[1]}]}) if collection
                   else json.dumps({"legacy": title}))
        item = publish(typ, content, title, unsigned=True)
        m = manifest(item[2])
        for i in owners:
            event = {"action": "publish", "agent": "legacy%d" % i, "id": item[2],
                     "sha256": m["content"]["sha256"], "ts": "2026-09-01T00:00:00Z",
                     "schema": "rc.v1"}
            msg = json.dumps({k: event[k] for k in ("action", "agent", "id", "sha256", "ts")},
                             sort_keys=True, separators=(",", ":"))
            out = subprocess.run(["node", str(REPO / "lib/sign-message.mjs"), "--stdin"],
                                 input=msg, env=dict(env, COMMONS_SIGNING_KEY=str(keys[i])),
                                 text=True, capture_output=True, check=True)
            s = json.loads(out.stdout)
            event.update(addr=s["address"], sig=s["signature"])
            # Legacy records live in their own flat log, before the v2 floor.
            with (root / "registry/ledger.jsonl").open("a") as f:
                f.write(json.dumps(event) + "\n")
        return item[2]

    own = legacy("own legacy")
    orphan = legacy("orphan", ())
    ambiguous = legacy("ambiguous", (0, 1))
    foreign = legacy("foreign legacy", (1,))
    maintained = legacy("maintained", (), collection=True)
    r = cli("manifest", "sign", own)
    check("sole legacy publisher backfills current view", r.returncode == 0 and view_bound(own))
    check("backfill prints the normalized view", '"manifest-view/1"' in r.stdout)
    check("backfill event is a dual-signed republish",
          any(e.get("id") == own and e.get("action") == "republish" and
              e.get("backfill") is True and e.get("view") and e.get("sig2") for e in events()))
    before = (root / "registry/artifacts" / (own + ".json")).read_bytes()
    count = len(events())
    r = cli("manifest", "sign", own)
    check("explicit sign of a valid view is idempotent",
          r.returncode == 0 and len(events()) == count and
          (root / "registry/artifacts" / (own + ".json")).read_bytes() == before)
    for target, label in ((orphan, "orphan"), (ambiguous, "ambiguous"), (foreign, "foreign")):
        r = cli("manifest", "sign", target)
        check("manifest sign refuses " + label + " adoption", r.returncode != 0 and
              "publisher_sig" not in manifest(target))
    r = cli("manifest", "sign", maintained, key=1)
    check("collection maintainer can sign legacy view", r.returncode == 0 and view_bound(maintained))
    mine = legacy("mine")
    r = cli("manifest", "sign", "--mine")
    check("mine signs eligible own legacy manifests", r.returncode == 0 and view_bound(mine))
    check("mine never adopts ambiguous or orphan manifests",
          "publisher_sig" not in manifest(orphan) and "publisher_sig" not in manifest(ambiguous))

    workflow = {"interpreter": "bash", "steps": ["printf 'output\\n' > \"$OUT_DIR/out.txt\""],
                "outputs": {"result": "out.txt"}, "verification": {"tier": "T0"}}
    wf = publish("workflow", json.dumps(workflow), "workflow")[2]
    r = cli("run", wf, "--publish", "--exec", "native")
    rid = "ds-" + hashlib.sha256(b"output\n").hexdigest()[:8]
    check("run --publish writes signed view", r.returncode == 0 and view_bound(rid))
    task = {"objective": "derive output", "beneficiary": {"addr": addresses[0]},
            "expires": "2099-01-01T00:00:00Z",
            "verification": {"tier": "T0", "criteria": "same bytes"},
            "execution": {"workflow": wf}}
    tk = publish("task", json.dumps(task), "task")[2]
    r = cli("run-task", tk, "--publish", "--exec", "native")
    srid = "sy-" + hashlib.sha256(b"output\n").hexdigest()[:8]
    check("run-task --publish writes signed view", r.returncode == 0 and
          (root / "registry/artifacts" / (srid + ".json")).exists() and view_bound(srid))
    # Lifecycle follows the published dataset so the test can continue on phase 1.
    paths = [root / "registry/artifacts" / (i + ".json") for i in (rid, tk)]
    saved = [p.read_bytes() for p in paths]
    r = cli("submit", tk, rid, "--force")
    check("submit leaves result manifest byte-identical", r.returncode == 0 and
          paths[0].read_bytes() == saved[0])
    r = cli("accept", tk, rid)
    check("accept leaves task manifest byte-identical", r.returncode == 0 and
          paths[1].read_bytes() == saved[1])
    check("links synthesizes fulfills without a cache",
          ("fulfills" in cli("links", rid).stdout))
    check("links synthesizes beneficiary acceptance without a cache",
          ("accepted" in cli("links", tk).stdout))
    r = cli("reject", tk, rid, "--reason", "withdrawn", "--force")
    check("latest rejection clears event-derived acceptance",
          r.returncode == 0 and "accepted" not in cli("links", tk).stdout and
          paths[1].read_bytes() == saved[1])
    m = manifest(tk)
    m.setdefault("links", []).append({"rel": "accepted", "id": rid})
    paths[1].write_text(json.dumps(m))
    check("historical accepted cache is ignored after rejection",
          "accepted" not in cli("links", tk).stdout and
          "UNBACKED CACHED LINK: " + tk in cli("fsck").stdout)
    paths[1].write_bytes(saved[1])
    r = cli("settle", tk, "--force")
    check("quorum settle records acceptance without changing manifest",
          r.returncode == 0 and paths[1].read_bytes() == saved[1] and
          "accepted" in cli("links", tk).stdout)
    replacement = publish("synthesis", "replacement output\n", "replacement",
                          "--tier", "T0", "--criteria", "same bytes")[2]
    cli("submit", tk, replacement, "--force")
    r = cli("accept", tk, replacement, "--force")
    accepted_lines = [line for line in cli("links", tk).stdout.splitlines()
                      if "accepted" in line]
    check("latest authenticated settlement replaces historical accepted result",
          r.returncode == 0 and len(accepted_lines) == 1 and
          replacement in accepted_lines[0] and rid not in accepted_lines[0] and
          paths[1].read_bytes() == saved[1])
    m = manifest(rid)
    m.setdefault("links", []).append({"rel": "fulfills", "id": "tk-deadbeef"})
    paths[0].write_text(json.dumps(m))
    check("unbacked cached fulfills ignored by links", "tk-deadbeef" not in cli("links", rid).stdout)
    r = cli("fsck")
    check("fsck reports unbacked cached link", r.returncode != 0 and
          "UNBACKED" in r.stdout and "tk-deadbeef" in r.stdout)
    # Embedded remote/local claims of ingest cannot conceal missing local data.
    lost = publish("dataset", '{"lost":1}', "lost")[2]
    m = manifest(lost)
    digest = m["content"]["sha256"]
    (root / "store/sha256" / digest[:2] / digest).unlink()
    m["ingest"] = {"from": "foreign", "received_at": "2026-09-01T00:00:00Z"}
    (root / "registry/artifacts" / (lost + ".json")).write_text(json.dumps(m))
    r = cli("fsck")
    check("embedded ingest stamp has no missing-blob authority",
          "MISSING BLOB: " + lost in r.stdout)

    # A fake container executes the actual workflow script in its mounted scratch
    # directory. This validates CLI rebaseline paths without claiming Docker isolation.
    runtime = lab / "runtime"
    runtime.mkdir()
    (runtime / "docker").write_text("""#!/usr/bin/env python3
import json, os, pathlib, subprocess, sys
a = sys.argv[1:]
if a[:2] == ["image", "inspect"]:
    print(json.dumps([{"Id": "sha256:" + "ab" * 32, "RepoDigests": []}]))
elif a and a[0] == "run":
    scratch = a[a.index("-v") + 1].split(":/work:")[0]
    e = dict(os.environ)
    for i, arg in enumerate(a):
        if arg == "-e":
            k, v = a[i+1].split("=", 1)
            e[k] = v.replace("/work", scratch)
    script = a[-1]
    if os.environ.get("MOCK_DIVERGE") == "1":
        pathlib.Path(e["OUT_DIR"], "out.txt").write_text("sandbox output\\\\n")
    else:
        r = subprocess.run([a[-3], "-c", script], env=e, cwd=scratch)
        sys.exit(r.returncode)
""")
    (runtime / "docker").chmod(0o755)
    env["PATH"] = str(runtime) + os.pathsep + os.environ["PATH"]
    m = manifest(rid)
    m["links"] = [l for l in m.get("links", []) if l.get("id") != "tk-deadbeef"]
    paths[0].write_text(json.dumps(m))
    before = paths[0].read_bytes()
    r = cli("rebaseline", rid)
    check("rebaseline match succeeds through actual workflow execution", r.returncode == 0)
    check("match leaves publisher manifest byte-identical", paths[0].read_bytes() == before)
    check("show displays authenticated sandbox reproduction",
          "reproduced under sandbox @sha256:" + "ab" * 32 in cli("show", rid).stdout)
    check("match event signs the exact execution digest", any(
        e.get("action") == "rebaseline" and e.get("id") == rid and
        e.get("result") == "match" and e.get("sig2") and
        e.get("image_digest") == "sha256:" + "ab" * 32 for e in events()))
    cli("peer", "add", addresses[0], "--agent-id", "writer0", "--trust", "none", "--force")
    check("untrusted reproduction cannot establish a displayed stamp",
          "reproduced under" not in cli("show", rid).stdout)
    cli("peer", "add", addresses[0], "--agent-id", "writer0", "--trust", "full", "--force")
    # Run by a signer without standing: event is real, but cannot vouch for the stamp.
    r = cli("rebaseline", rid, key=1)
    check("foreign rebaseline never changes publisher bytes",
          paths[0].read_bytes() == before)
    check("reader retains only the reproduction signer with standing",
          "by " + addresses[0].lower() in cli("show", rid).stdout and
          "by " + addresses[1].lower() not in cli("show", rid).stdout)
    env["MOCK_DIVERGE"] = "1"
    r = cli("rebaseline", rid, "--publish-superseding")
    superseding = "ds-" + hashlib.sha256(b"sandbox output\\n").hexdigest()[:8]
    check("rebaseline superseding publish writes a view-bound event",
          r.returncode == 0 and
          (root / "registry/artifacts" / (superseding + ".json")).exists()
          and view_bound(superseding))
    check("superseding path preserves original manifest", paths[0].read_bytes() == before)
    env.pop("MOCK_DIVERGE")

    # Prepare an authenticated delegation fixture before adoption, then run the
    # real rebaseline CLI as the reproducer rather than the publisher.
    r = cli("run", wf, "--publish", "--publish-type", "report", "--exec", "native",
            unsigned=True)
    delegated_run = "rp-" + hashlib.sha256(b"output\n").hexdigest()[:8]
    run_path = root / "registry/artifacts" / (delegated_run + ".json")
    if r.returncode:
        raise AssertionError(r.stdout + r.stderr)
    append_code = (
        "import json,runpy,sys; n=runpy.run_path(sys.argv[1]); "
        "n['ledger_append'](json.loads(sys.argv[2]))")
    subprocess.run(
        ["python3", "-c", append_code, str(TOOL), json.dumps({
            "agent": "writer", "action": "publish", "id": delegated_run,
            "sha256": manifest(delegated_run)["content"]["sha256"]})],
        env=env, check=True, text=True, capture_output=True)
    m = manifest(delegated_run)
    m["reproducers"] = [addresses[2]]
    run_path.write_text(json.dumps(m))
    cli("manifest", "sign", delegated_run)
    saved_run = run_path.read_bytes()
    r = cli("rebaseline", delegated_run, key=2)
    check("signed reproducer delegation grants reproduction standing",
          r.returncode == 0 and "by " + addresses[2].lower() in
          cli("show", delegated_run).stdout and run_path.read_bytes() == saved_run)
    m = manifest(delegated_run)
    m["reproducers"].append(addresses[1])
    run_path.write_text(json.dumps(m))
    check("altered held delegation cannot establish a reproduction stamp",
          "reproduced under" not in cli("show", delegated_run).stdout)
    r = cli("rebaseline", delegated_run, key=1)
    check("rebaseline refuses altered metadata before executing", r.returncode != 0 and
          "METADATA ALTERED" in r.stdout + r.stderr)
    run_path.write_bytes(saved_run)
    m = manifest(delegated_run)
    m["provenance"]["workflow"]["sha256"] = "0" * 64
    # Legacy copy permits checking pinned provenance independently of view validation.
    m.pop("publisher_sig", None)
    pin_probe = legacy("pinned provenance")
    pin_path = root / "registry/artifacts" / (pin_probe + ".json")
    pm = manifest(pin_probe)
    pm["verification"] = {"tier": "T0"}
    pm["provenance"] = m["provenance"]
    pin_path.write_text(json.dumps(pm))
    r = cli("rebaseline", pin_probe)
    check("rebaseline refuses a workflow digest different from pinned provenance",
          r.returncode != 0 and "provenance record" in r.stdout + r.stderr)

    delegated = legacy("delegation")
    p = root / "registry/artifacts" / (delegated + ".json")
    m = manifest(delegated)
    m["authority"] = [addresses[1]]
    m["reproducers"] = [addresses[2]]
    p.write_text(json.dumps(m))
    cli("manifest", "sign", delegated)
    r = cli("publish", "dataset", lab / "delegation.json", "delegate",
            "--force", key=1)
    check("held view delegate may sign the next view", r.returncode == 0 and view_bound(delegated))
    r = cli("publish", "dataset", lab / "delegation.json", "reproducer",
            "--force", key=2)
    check("reproducer delegation does not grant publisher authority", r.returncode != 0)
    r = cli("publish", "dataset", lab / "delegation.json", "delegated republish",
            "--force", key=1)
    check("republish carries held delegation fields forward",
          r.returncode == 0 and manifest(delegated).get("authority") == [addresses[1]] and
          manifest(delegated).get("reproducers") == [addresses[2]])

    # Real local Git pull: arrival metadata lives locally and does not dirty manifests.
    source, receiver = lab / "source", lab / "receiver"
    r = cli("hub", "init", source, "--name", "ingest")
    if r.returncode:
        raise AssertionError(r.stderr)
    def git(where, *args):
        r = subprocess.run(["git", "-c", "commit.gpgsign=false", *args], cwd=where,
                           env=env, text=True, capture_output=True)
        if r.returncode:
            raise AssertionError(r.stdout + r.stderr)
        return r.stdout.strip()
    git(source, "commit", "--allow-empty", "-qm", "base")
    git(lab, "clone", "-q", str(source), str(receiver))
    for address in addresses:
        cli("peer", "add", address, "--agent-id", "writer", "--trust", "full", root_at=receiver)
    new = publish("dataset", '{"pulled":true}', "pulled", "--license", "CC0-1.0",
                  "--obtainability", "open", root_at=source)[2]
    remote_bytes = (source / "registry/artifacts" / (new + ".json")).read_bytes()
    git(source, "add", "registry", "store")
    git(source, "commit", "-qm", "published")
    r = cli("pull", "origin", root_at=receiver)
    check("real pull accepts a keyed signed view", r.returncode == 0)
    arrivals = receiver / "registry/ingest.json"
    check("pull stores arrival only in local ingest registry",
          arrivals.exists() and
          json.loads(arrivals.read_text()).get("artifacts", {}).get(new, {}).get("from") == "origin")
    check("pull leaves signed remote manifest byte-identical",
          (receiver / "registry/artifacts" / (new + ".json")).read_bytes() == remote_bytes)
    check("ingest registry is ignored and untracked",
          "registry/ingest.json" in (receiver / ".gitignore").read_text() and
          not git(receiver, "ls-files", "registry/ingest.json"))
    md = manifest(new, receiver)["content"]["sha256"]
    (receiver / "store/sha256" / md[:2] / md).unlink()
    r = cli("fsck", root_at=receiver)
    check("local arrival record distinguishes not replicated from corruption",
          r.returncode == 0 and "NOT REPLICATED: " + new in r.stdout)
    # No incoming sender can choose this host's local arrival authority.
    (source / "registry/ingest.json").write_text(json.dumps({
        "schema": "rc.v1", "artifacts": {new: {"from": "attacker"}}}))
    git(source, "add", "-f", "registry/ingest.json")
    git(source, "commit", "-qm", "smuggled arrival state")
    prior_arrival = arrivals.read_bytes() if arrivals.exists() else b""
    r = cli("pull", "origin", root_at=receiver)
    check("pull refuses incoming local ingest registry and preserves held record",
          r.returncode != 0 and "registry/ingest.json" in r.stdout + r.stderr and
          arrivals.exists() and arrivals.read_bytes() == prior_arrival)

print("view-writers: %d passed, %d failed" % (passed, failed))
raise SystemExit(bool(failed))
