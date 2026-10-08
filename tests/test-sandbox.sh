#!/usr/bin/env bash
# P3 gate — sandboxed execution, exec-record provenance, ENV-MISMATCH, rebaseline.
# Throwaway COMMONS_ROOT. Requires docker + the default image, built from the repo:
#   docker build -t research-commons-sandbox:base environments/base/
set -uo pipefail

# Hermeticity: never inherit the operator's registry/key/exec settings. A suite that
# behaves differently depending on the invoking shell is measuring the shell.
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG


HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"

PASS=0; FAIL=0; SKIP=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
skip() { printf '  \033[33mskip\033[0m %s\n' "$1"; SKIP=$((SKIP+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

IMAGE=research-commons-sandbox:base
if ! command -v docker >/dev/null 2>&1 || ! timeout 30 docker info >/dev/null 2>&1; then
  echo "test-sandbox: docker unavailable — P3 cannot be validated on this host"; exit 1
fi
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  echo "test-sandbox: image $IMAGE missing — P3 cannot be validated."
  echo "  build it: docker build -t $IMAGE environments/base/"; exit 1
fi

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-test-sbx-XXXXXX)"
export COMMONS_AGENT=test-p3
trap 'rm -rf "$COMMONS_ROOT"' EXIT
mkdir -p "$COMMONS_ROOT/registry"
cp "$REPO/registry/exec-policy.example.json" "$COMMONS_ROOT/registry/exec-policy.json"
W="$COMMONS_ROOT/work"; mkdir -p "$W"

c() { "$COMMONS" "$@"; }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
export COMMONS_SIGNING_KEY="$W/publisher.key"
python3 - "$COMMONS_SIGNING_KEY" <<'PYKEY'
import os, secrets, sys
with open(sys.argv[1], "w") as f:
    f.write("0x" + secrets.token_hex(32))
os.chmod(sys.argv[1], 0o600)
PYKEY
PUBLISHER=$(c peer whoami | head -1)
c peer add "$PUBLISHER" --agent-id test-p3 --trust full >/dev/null || exit 1
jget() { python3 -c 'import json,sys
d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = d.get(k) if isinstance(d, dict) else None
    if d is None: break
print(d if d not in (None, "") else "MISSING")' "$1"; }
# Guard: a blank id would turn `chmod 644 $STORE/$X` into a chmod of the store
# directory itself. Fail loudly instead of corrupting the fixture registry.
need() { [ -n "$1" ] && [ "$1" != MISSING ] || { bad "$2 (empty id)"; return 1; }; }

head_ "fixtures"
cat > "$W/rewards.csv" <<'EOF'
avs,promised_usd,claimed_usd
alpha,1000,900
beta,500,500
EOF
DS=$(c publish dataset "$W/rewards.csv" "Rewards" -t demo)
# mkspec_py <outfile> <body-file> [extra-json] — python body staged as an attachment,
# so fixtures need no shell-quoting gymnastics (an earlier sed-based version silently
# produced empty ids and sent the suite chasing phantom implementation bugs).
mkspec_py() {
  python3 - "$1" "$DS" "$2" "${3:-null}" <<'PY'
import json, sys
out, ds, bodyfile, extra = sys.argv[1], sys.argv[2], sys.argv[3], json.loads(sys.argv[4])
spec = {"interpreter": "bash", "inputs": {"REWARDS": ds},
        "attachments": {"step.py": open(bodyfile).read()},
        "steps": ["python3 step.py"], "outputs": {"r": "r.json"},
        "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 120}
if extra: spec.update(extra)
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
}
# mkspec_sh <outfile> <steps-json> [extra-json] — literal shell steps
mkspec_sh() {
  python3 - "$1" "$DS" "$2" "${3:-null}" <<'PY'
import json, sys
out, ds, steps, extra = sys.argv[1], sys.argv[2], json.loads(sys.argv[3]), json.loads(sys.argv[4])
spec = {"interpreter": "bash", "inputs": {"REWARDS": ds}, "steps": steps,
        "outputs": {"r": "r.json"},
        "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 120}
if extra: spec.update(extra)
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
}

cat > "$W/body-pure.py" <<'PY'
import csv, json, os
rows = list(csv.DictReader(open(os.environ["IN_REWARDS"])))
json.dump({r["avs"]: int(r["claimed_usd"]) for r in rows},
          open(os.environ["OUT_DIR"] + "/r.json", "w"), indent=2, sort_keys=True)
PY
mkspec_py "$W/wf-pure.json" "$W/body-pure.py"
WFP=$(c publish workflow "$W/wf-pure.json" "pure stdlib agg" -t demo)

head_ "sandbox execution"
OUTS=$(c run "$WFP" --publish --publish-type synthesis --exec sandbox --title "sandboxed" | awk '{print $1}')
check "run --exec sandbox publishes" "$(echo "$OUTS" | grep -c '^sy-')" "1"
check "records exec mode" "$(c get "$OUTS" | jget provenance.run.exec.mode)" "sandbox"
check "records image tag" "$(c get "$OUTS" | jget provenance.run.exec.image)" "$IMAGE"
DIG=$(c get "$OUTS" | jget provenance.run.exec.image_digest)
check "records image DIGEST not just tag" "$(echo "$DIG" | grep -c '^sha256:')" "1"
check "ledger records exec_mode" "$(c log -n 5 | grep -c '\"exec_mode\": \"sandbox\"')" "1"
check "verify PASSes in same env" "$(rc c verify "$OUTS" --exec sandbox)" "0"
check "PASS prints environment" "$(grep -c 'environment: sandbox' "$W/out.txt")" "1"

head_ "network egress is blocked (the safety gate)"
mkspec_sh "$W/wf-net.json" '["curl -sS --max-time 5 http://example.com > \"$OUT_DIR/r.json\""]'
WFN=$(c publish workflow "$W/wf-net.json" "network egress" -t demo)
check "egress workflow FAILS in sandbox" "$(rc c run "$WFN" --exec sandbox -o "$W")" "1"
check "failure is reported as workflow failure" "$(grep -c 'failed' "$W/err.txt")" "1"

head_ "resource caps"
# Keep this probe small and force physical page allocation: a large zero-filled
# bytearray can depend on allocator/overcommit behaviour and available swap.
# Docker defaults to another memory limit's worth of swap, so 512 MiB of touched
# anonymous pages exceeds both the 128 MiB RAM cap and its 128 MiB swap allowance.
cp "$COMMONS_ROOT/registry/exec-policy.json" "$W/exec-policy.memory-backup.json" || exit 1
python3 - "$COMMONS_ROOT/registry/exec-policy.json" <<'PYMEM'
import json, sys
path = sys.argv[1]
policy = json.load(open(path))
policy["limits"]["memory"] = "128m"
json.dump(policy, open(path, "w"), indent=2, sort_keys=True)
PYMEM
[ "$?" -eq 0 ] || exit 1
cat > "$W/body-bomb.py" <<'PY'
import json, mmap, os

size = 512 * 1024 * 1024
pages = mmap.mmap(-1, size, flags=mmap.MAP_PRIVATE | mmap.MAP_ANONYMOUS)
for offset in range(0, size, mmap.PAGESIZE):
    pages[offset] = 1
json.dump({"touched_bytes": size}, open(os.environ["OUT_DIR"] + "/r.json", "w"))
PY
mkspec_py "$W/wf-bomb.json" "$W/body-bomb.py"
WFB=$(c publish workflow "$W/wf-bomb.json" "memory bomb" -t demo)
BOMB_RC=$(rc c run "$WFB" --exec sandbox -o "$W")
cp "$W/exec-policy.memory-backup.json" "$COMMONS_ROOT/registry/exec-policy.json" || exit 1
# A generic failure (syntax, missing output, timeout, etc.) must not pass this gate.
check "memory bomb killed by cap" \
  "$BOMB_RC:$(grep -cF 'failed (exit 137, sandbox mode)' "$W/err.txt")" "1:1"
mkspec_sh "$W/wf-slow.json" '["sleep 30"]' '{"timeout": 3}'
WFS=$(c publish workflow "$W/wf-slow.json" "slow" -t demo)
check "timeout enforced outside container" "$(rc c run "$WFS" --exec sandbox -o "$W")" "1"
check "timeout message names the limit" "$(grep -c 'timeout' "$W/err.txt")" "1"

head_ "image allowlist"
mkspec_sh "$W/wf-badimg.json" '["true"]' '{"image": "alpine:latest"}'
WFI=$(c publish workflow "$W/wf-badimg.json" "unlisted image" -t demo)
check "unlisted image refused" "$(rc c run "$WFI" --exec sandbox -o "$W")" "1"
check "refusal names the allowlist" "$(grep -c 'allowlist' "$W/err.txt")" "1"
check "spec image + native mode refused" "$(rc c run "$WFI" --exec native -o "$W")" "1"
cat > "$W/body-ok.py" <<'PY'
import json, os
json.dump({"ok": True}, open(os.environ["OUT_DIR"] + "/r.json", "w"), sort_keys=True)
PY
mkspec_py "$W/wf-okimg.json" "$W/body-ok.py" '{"image": "research-commons-sandbox:base"}'
WFOK=$(c publish workflow "$W/wf-okimg.json" "listed image" -t demo)
check "allowlisted image accepted" "$(rc c run "$WFOK" --exec sandbox -o "$W")" "0"

# A real registry digest exists only for pulled/tagged registry images. Locally built
# fixtures legitimately have an image ID but no RepoDigests; that cannot prove a pin,
# so mark these integration assertions skipped rather than weakening fail-closed logic.
if REPO_DIGEST=$(PYTHONDONTWRITEBYTECODE=1 python3 - "$COMMONS" "$IMAGE" 2>/dev/null <<'PYDIGEST'
import importlib.machinery, importlib.util, sys
loader = importlib.machinery.SourceFileLoader("commons_digest_integration", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
commons = importlib.util.module_from_spec(spec)
loader.exec_module(commons)
print(commons.image_digest(sys.argv[2], require_repository=True))
PYDIGEST
); then
  cp "$COMMONS_ROOT/registry/exec-policy.json" "$W/exec-policy.backup.json"
  python3 - "$COMMONS_ROOT/registry/exec-policy.json" "$IMAGE" "$REPO_DIGEST" <<'PYPIN'
import json, sys
path, image, digest = sys.argv[1:]
policy = json.load(open(path))
policy["images"] = [image + "@" + digest]
json.dump(policy, open(path, "w"), indent=2, sort_keys=True)
PYPIN
  check "digest-pinned image accepted at equal repository digest"     "$(rc c run "$WFOK" --exec sandbox -o "$W")" "0"

  MISMATCH_DIGEST="sha256:$(printf '0%.0s' {1..64})"
  python3 - "$COMMONS_ROOT/registry/exec-policy.json" "$IMAGE" "$MISMATCH_DIGEST" <<'PYPIN'
import json, sys
path, image, digest = sys.argv[1:]
policy = json.load(open(path))
policy["images"] = [image + "@" + digest]
json.dump(policy, open(path, "w"), indent=2, sort_keys=True)
PYPIN
  check "digest-pinned image refused at mismatched repository digest"     "$(rc c run "$WFOK" --exec sandbox -o "$W")" "1"
  check "digest mismatch refusal is explicit"     "$(grep -c 'does not match.*exec-policy pin' "$W/err.txt")" "1"
  cp "$W/exec-policy.backup.json" "$COMMONS_ROOT/registry/exec-policy.json"
else
  skip "digest-pin integration match (image has no repository digest)"
  skip "digest-pin integration mismatch (image has no repository digest)"
  skip "digest-pin mismatch reason (image has no repository digest)"
fi

head_ "cross-mode determinism (pure stdlib)"
# a native-only artifact from a distinct workflow, to observe the native exec record
cat > "$W/body-nat.py" <<'PY'
import csv, json, os
rows = list(csv.DictReader(open(os.environ["IN_REWARDS"])))
json.dump({"n": len(rows), "marker": "native-only"},
          open(os.environ["OUT_DIR"] + "/r.json", "w"), indent=2, sort_keys=True)
PY
mkspec_py "$W/wf-nat.json" "$W/body-nat.py"
WFNAT=$(c publish workflow "$W/wf-nat.json" "native-only agg" -t demo)
NATV_PRE=$(c run "$WFNAT" --publish --publish-type synthesis --exec native --title "native only" | awk '{print $1}')
OUTN=$(c run "$WFP" --publish --publish-type synthesis --exec native --title "native" | awk '{print $1}')
# Same id means the sandbox run reproduced the native bytes exactly. Because ids are
# content-derived, the second publish is a no-op: the manifest (and its exec record)
# stays as first written, which for this fixture was the sandbox run.
check "native and sandbox produce the SAME id" "$OUTN" "$OUTS"
check "first exec record is preserved, not clobbered" \
  "$(c get "$OUTN" | jget provenance.run.exec.mode)" "sandbox"
check "cross-env reproduction is logged as stronger evidence" \
  "$(c log -n 5 | grep -c 'reproduced-cross-env')" "1"
check "a fresh native-only artifact records native" \
  "$(c get "$NATV_PRE" | jget provenance.run.exec.mode)" "native"

head_ "ENV-MISMATCH — the migration signal"
# Build a genuinely userland-sensitive artifact: embed the python version.
cat > "$W/body-ver.py" <<'PY'
import json, os, sys
json.dump({"py": "%d.%d" % sys.version_info[:2]},
          open(os.environ["OUT_DIR"] + "/r.json", "w"), sort_keys=True)
PY
mkspec_py "$W/wf-ver.json" "$W/body-ver.py"
WFV=$(c publish workflow "$W/wf-ver.json" "version-sensitive" -t demo)
NATV=$(c run "$WFV" --publish --publish-type synthesis --exec native --title "native version" | awk '{print $1}')
HOSTPY=$(python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])')
SBXPY=$(docker run --rm "$IMAGE" python3 -c 'import sys;print("%d.%d"%sys.version_info[:2])' 2>/dev/null)
if [ "$HOSTPY" = "$SBXPY" ]; then
  skip "host and sandbox python match ($HOSTPY) — cannot exercise divergence"
else
  ok "host python $HOSTPY vs sandbox $SBXPY (divergence available)"
  check "native artifact verifies natively" "$(rc c verify "$NATV" --exec native)" "0"
  check "cross-env verify = ENV-MISMATCH (5) not FAIL (1)" "$(rc c verify "$NATV" --exec sandbox)" "5"
  check "ENV-MISMATCH names both environments" "$(grep -cE 'recorded :|attempted:' "$W/out.txt")" "2"
  check "ENV-MISMATCH says it is not a failure" "$(grep -c 'not a reproducibility failure' "$W/out.txt")" "1"
  check "ENV-MISMATCH suggests rebaseline" "$(grep -c 'commons rebaseline' "$W/out.txt")" "1"
  check "ledger distinguishes env-mismatch from fail" "$(c log -n 5 | grep -c 'verify-env-mismatch')" "1"
  check "no verify-fail event emitted" "$(c log -n 5 | grep -c '\"verify-fail\"')" "0"
fi

head_ "genuine FAIL stays loud (same env, wrong bytes)"
BL=$(c get "$OUTS" | jget content.sha256)
if need "$BL" "tamper fixture"; then
  # Sharded store (store/sha256/ab/<hash>); tamper the path the code PREFERS or the
  # fixture is inert and the tamper guard looks broken.
  BLP="$COMMONS_ROOT/store/sha256/${BL:0:2}/$BL"
  cp "$BLP" "$W/blob.bak"
  chmod 644 "$BLP"; echo '{"tampered":1}' > "$BLP"
  check "tampered blob in SAME env = FAIL (1)" "$(rc c verify "$OUTS" --exec sandbox)" "1"
  check "FAIL is not disguised as env-mismatch" "$(grep -c 'ENV-MISMATCH' "$W/out.txt")" "0"
  cp -f "$W/blob.bak" "$BLP"; chmod 444 "$BLP"
fi

head_ "rebaseline — converge, don't reverse"
# $NATV_PRE is native-recorded and userland-insensitive: the canonical clean-converge case.
cp "$COMMONS_ROOT/registry/artifacts/$NATV_PRE.json" "$W/pre-rebaseline.json"
check "rebaseline of matching artifact records reproduction" "$(rc c rebaseline "$NATV_PRE")" "0"
check "stamp reported as MATCH" "$(grep -c '^MATCH' "$W/out.txt")" "1"
check "publisher exec record stays native" "$(c get "$NATV_PRE" | jget provenance.run.exec.mode)" "native"
check "publisher manifest stays byte-identical after reproduction" \
  "$(cmp -s "$W/pre-rebaseline.json" "$COMMONS_ROOT/registry/artifacts/$NATV_PRE.json" && echo yes)" "yes"
check "authenticated reproduction displays the sandbox image digest" \
  "$(c show "$NATV_PRE" | grep -c "reproduced under sandbox @$DIG by")" "1"
check "rebaseline event carries a signed timestamp" \
  "$(c log -n 5 | python3 -c 'import json,sys
events=[json.loads(line) for line in sys.stdin]
print(any(e.get("id")==sys.argv[1] and e.get("action")=="rebaseline"
          and e.get("result")=="match" and e.get("ts") and e.get("sig2")
          for e in events))' "$NATV_PRE")" "True"
check "rebaseline logged" "$(c log -n 5 | grep -c '\"rebaseline\"')" "1"
check "second rebaseline reproduces the immutable native baseline" \
  "$(c rebaseline "$NATV_PRE" | grep -c '^MATCH')" "1"
check "rebaselined artifact verifies in sandbox" "$(rc c verify "$NATV_PRE" --exec sandbox)" "0"
# Reproduction never changes the publisher's native verification baseline.
check "original native environment still PASSes" "$(rc c verify "$NATV_PRE" --exec native)" "0"
check "native PASS has no environment-difference claim" \
  "$(grep -c 'environment-independent' "$W/out.txt")" "0"
if [ "$HOSTPY" != "$SBXPY" ]; then
  check "diverging artifact needs explicit supersede" "$(rc c rebaseline "$NATV")" "5"
  check "reports DIVERGED" "$(grep -c '^DIVERGED' "$W/out.txt")" "1"
  check "nothing published without the flag" "$(grep -c 'Nothing written' "$W/out.txt")" "1"
  check "supersede publishes new artifact" "$(rc c rebaseline "$NATV" --publish-superseding)" "0"
  # take the id from the "published X [supersedes Y]" line, not the header line
  NEW=$(sed -n 's/^ *published \(sy-[0-9a-f]*\) .*/\1/p' "$W/out.txt" | head -1)
  need "$NEW" "supersede id extraction" || NEW=__none__
  check "new artifact supersedes the old" \
    "$(c get "$NEW" | python3 -c 'import json,sys;print(sum(1 for l in json.load(sys.stdin)["links"] if l["rel"]=="supersedes" and l["id"]==sys.argv[1]))' "$NATV")" "1"
  check "new artifact is sandbox-baselined" "$(c get "$NEW" | jget provenance.run.exec.mode)" "sandbox"
  check "legacy artifact still present" "$(rc c get "$NATV")" "0"
  check "supersession logged" "$(c log -n 10 | grep -c 'superseded_by')" "1"
  check "superseding artifact verifies in sandbox" "$(rc c verify "$NEW" --exec sandbox)" "0"
fi

head_ "nondeterminism is surfaced, not hidden"
cat > "$W/body-rand.py" <<'PY'
import json, os, random
json.dump({"x": random.random()}, open(os.environ["OUT_DIR"] + "/r.json", "w"))
PY
mkspec_py "$W/wf-rand.json" "$W/body-rand.py"
WFR=$(c publish workflow "$W/wf-rand.json" "nondeterministic" -t demo)
RND=$(c run "$WFR" --publish --publish-type synthesis --exec native --title "random" | awk '{print $1}')
check "nondeterministic artifact fails rebaseline" "$(rc c rebaseline "$RND")" "1"
check "diagnosed as workflow defect" "$(grep -c 'NONDETERMINISTIC' "$W/out.txt")" "1"
check "blames the workflow, not the userland" "$(grep -c 'genuine workflow defect' "$W/out.txt")" "1"

head_ "run-skill — fetched code is always sandboxed"
cat > "$W/probe.py" <<'PY'
#!/usr/bin/env python3
import os, socket, sys
print("args:", " ".join(sys.argv[1:]))
print("cwd:", os.getcwd())
try:
    socket.create_connection(("1.1.1.1", 53), timeout=3); print("NETWORK: reachable")
except Exception: print("NETWORK: blocked")
try:
    open("/etc/probe-escape", "w").write("x"); print("ROOTFS: writable")
except Exception: print("ROOTFS: read-only")
PY
SK=$(c publish skill "$W/probe.py" "probe skill" -t probe)
check "run-skill executes" "$(rc c run-skill "$SK" hello world)" "0"
check "args passed through" "$(grep -c 'args: hello world' "$W/out.txt")" "1"
check "no network inside run-skill" "$(grep -c 'NETWORK: blocked' "$W/out.txt")" "1"
check "rootfs read-only inside run-skill" "$(grep -c 'ROOTFS: read-only' "$W/out.txt")" "1"
COMMONS_EXEC=native c run-skill "$SK" >"$W/out.txt" 2>"$W/err.txt"
check "run-skill ignores COMMONS_EXEC=native" "$(grep -c 'NETWORK: blocked' "$W/out.txt")" "1"
check "run-skill logged with image digest" \
  "$(c log -n 5 | python3 -c 'import json,sys; ls=[json.loads(l) for l in sys.stdin]; print(sum(1 for e in ls if e["action"]=="run-skill" and e.get("image_digest","").startswith("sha256:")))')" "2"
check "run-skill refuses non-skill artifacts" "$(rc c run-skill "$DS")" "1"

head_ "status annotation (must NOT change grades)"
# $RND is native-published and never rebaselined -> annotated as a pre-sandbox baseline.
# (Its own tier is T0; the T3 dataset input is what sets the chain grade.)
check "legacy T0 annotated" \
  "$([ "$(c status "$RND" 2>&1 | grep -c 'pre-sandbox baseline')" -ge 1 ] && echo yes)" "yes"
check "annotation does not change the grade" "$(rc c status "$RND")" "3"
check "sandbox-baselined artifact grades normally" "$(rc c status "$OUTS")" "3"
check "annotation absent once rebaselined" "$(c status "$OUTN" 2>&1 | grep -c 'pre-sandbox baseline')" "0"

head_ "policy + housekeeping"
check "fsck clean" "$(rc c fsck)" "0"
check "reindex clean" "$(rc c reindex)" "0"
check "tiers documents ENV-MISMATCH" "$([ "$(c tiers | grep -c 'ENV-MISMATCH')" -ge 1 ] && echo yes)" "yes"
check "tiers explains exec parameterisation" "$(c tiers | grep -c 'provenance.run.exec')" "1"
check "exec-policy allowlist is readable" "$(python3 -c 'import json;print(len(json.load(open("'"$COMMONS_ROOT"'/registry/exec-policy.json"))["images"]))')" "1"
check "seeded default image is the in-repo reference build" \
  "$(python3 -c 'import json;print(json.load(open("'"$COMMONS_ROOT"'/registry/exec-policy.json"))["default_image"])')" "$IMAGE"

printf '\n\033[1mtest-sandbox: %d passed, %d failed, %d skipped\033[0m\n' "$PASS" "$FAIL" "$SKIP"
[ "$FAIL" -eq 0 ]
