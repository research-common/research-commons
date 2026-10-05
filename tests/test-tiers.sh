#!/usr/bin/env bash
# P1 gate — verification tiers, comparators, chain-grade rollup.
# Runs entirely against a throwaway COMMONS_ROOT. Never touches the live registry.
set -uo pipefail

# Hermeticity: never inherit the operator's registry/key/exec settings. A suite that
# behaves differently depending on the invoking shell is measuring the shell.
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG


HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"

PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-test-tiers-XXXXXX)"
export COMMONS_AGENT=test-p1
trap 'rm -rf "$COMMONS_ROOT"' EXIT
W="$COMMONS_ROOT/work"; mkdir -p "$W"

c() { "$COMMONS" "$@"; }
# run a command, capture exit code without tripping set -e
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }

head_ "digest-pinned image policy (daemon-independent)"
PYTHONDONTWRITEBYTECODE=1 python3 - "$COMMONS" "$W/policy-results.json" <<'PYPOLICY'
import importlib.machinery, importlib.util, json, os, sys, tempfile

commons_path, out_path = sys.argv[1:]
loader = importlib.machinery.SourceFileLoader("commons_policy_test", commons_path)
spec = importlib.util.spec_from_loader(loader.name, loader)
commons = importlib.util.module_from_spec(spec)
loader.exec_module(commons)

tag = "example/research:blessed"
good = "sha256:" + "a" * 64
bad = "sha256:" + "b" * 64
results = {}

commons.image_digest = lambda image, require_repository=False: good
commons.check_image_allowed(tag, {"images": [tag + "@" + good]})
results["equal"] = "accepted"

try:
    commons.check_image_allowed(tag, {"images": [tag + "@" + bad]})
except SystemExit as e:
    results["mismatch"] = "does not match" if "does not match" in str(e) else str(e)
else:
    results["mismatch"] = "accepted"

def unavailable(image, require_repository=False):
    raise SystemExit("error: cannot inspect image %s: docker absent" % image)
commons.image_digest = unavailable
try:
    commons.check_image_allowed(tag, {"images": [tag + "@" + good]})
except SystemExit as e:
    results["absent"] = "refusing closed" if "refusing closed" in str(e) else str(e)
else:
    results["absent"] = "accepted"

commons.image_digest = lambda *args, **kwargs: (_ for _ in ()).throw(
    AssertionError("plain-tag matching must not inspect Docker"))
commons.check_image_allowed(tag, {"images": [tag]})
results["plain"] = "accepted"

fd, malformed_path = tempfile.mkstemp(prefix="commons-policy-", suffix=".json")
os.close(fd)
try:
    with open(malformed_path, "w") as f:
        json.dump({"images": [tag + "@sha256:1234"]}, f)
    commons.EXEC_POLICY = malformed_path
    try:
        commons.load_exec_policy()
    except SystemExit as e:
        results["malformed"] = ("rejected clearly" if "malformed digest pin" in str(e)
                                else str(e))
    else:
        results["malformed"] = "accepted"
finally:
    os.unlink(malformed_path)

with open(out_path, "w") as f:
    json.dump(results, f, sort_keys=True)
PYPOLICY
policy_result() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))[sys.argv[2]])'     "$W/policy-results.json" "$1"
}
check "digest pin accepts equal repository digest" "$(policy_result equal)" "accepted"
check "digest pin refuses mismatched repository digest" "$(policy_result mismatch)" "does not match"
check "digest pin fails closed when Docker is absent" "$(policy_result absent)" "refusing closed"
check "legacy plain tag still matches without inspection" "$(policy_result plain)" "accepted"
check "malformed digest pin rejected while loading policy" "$(policy_result malformed)" "rejected clearly"

head_ "fixtures"
cat > "$W/rewards.csv" <<'EOF'
avs,month,promised_usd,claimed_usd,token_symbol
alpha,2026-04,1000,900,ALPHA
alpha,2026-05,2000,1500,ALPHA
beta,2026-04,500,500,BETA
EOF
DS=$(c publish dataset "$W/rewards.csv" "Rewards demo" -t demo)
check "dataset publishes" "$(echo "$DS" | grep -c '^ds-')" "1"
check "dataset defaults to T3" "$(c get "$DS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verification"]["tier"])')" "T3"
check "manifest carries schema rc.v1" "$(c get "$DS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["schema"])')" "rc.v1"

head_ "atomic manifests and collision guard"
check "identical-content re-publish exits 0" \
  "$(rc c publish dataset "$W/rewards.csv" "Rewards demo" -t demo)" "0"
check "identical-content re-publish keeps one manifest" \
  "$(find "$COMMONS_ROOT/registry/artifacts" -maxdepth 1 -name "$DS.json" | wc -l | tr -d ' ')" "1"
check "normal publish leaves no manifest temp files" \
  "$(find "$COMMONS_ROOT/registry/artifacts" -maxdepth 1 -name '*.tmp.*' | wc -l | tr -d ' ')" "0"
check "all published manifests remain valid JSON" \
  "$(python3 - "$COMMONS_ROOT/registry/artifacts" <<'PY'
import json, pathlib, sys
for p in pathlib.Path(sys.argv[1]).glob("*.json"):
    json.load(open(p))
print("yes")
PY
)" "yes"
COLLISION_ROOT="$W/collision-root"
check "same-id hash-prefix collision is refused" \
  "$(rc env COMMONS_ROOT="$COLLISION_ROOT" python3 - "$COMMONS" <<'PY'
import os, runpy, sys
mod = runpy.run_path(sys.argv[1])
os.makedirs(mod["ART"], exist_ok=True)
aid = "ds-c0ffee00"
base = {"schema": "rc.v1", "id": aid, "type": "dataset", "content": {"sha256": "1" * 64}}
mod["publish_manifest"](aid, base)
other = dict(base); other["content"] = {"sha256": "2" * 64}
mod["publish_manifest"](aid, other)
PY
)" "1"
check "collision error names id and both hashes" \
  "$([ "$(grep -c 'ds-c0ffee00' "$W/err.txt")" = 1 ] && \
      [ "$(grep -c "$(printf '1%.0s' {1..64})" "$W/err.txt")" = 1 ] && \
      [ "$(grep -c "$(printf '2%.0s' {1..64})" "$W/err.txt")" = 1 ] && \
      grep -c 'hash-prefix collision' "$W/err.txt")" "1"

# --- T0 workflow: deterministic sum ---
python3 - "$W/wf-t0.json" "$DS" <<'PY'
import json, sys
spec = {
  "interpreter": "bash",
  "inputs": {"REWARDS": sys.argv[2]},
  "attachments": {"agg.py": (
      "import csv, json, sys\n"
      "rows = list(csv.DictReader(open(sys.argv[1])))\n"
      "tot = {}\n"
      "for r in rows:\n"
      "    a = tot.setdefault(r['avs'], {'promised': 0, 'claimed': 0})\n"
      "    a['promised'] += int(r['promised_usd']); a['claimed'] += int(r['claimed_usd'])\n"
      "out = {avs: {**v, 'ratio': round(v['claimed']/v['promised'], 6)} for avs, v in sorted(tot.items())}\n"
      "json.dump(out, open(sys.argv[2], 'w'), indent=2, sort_keys=True)\n")},
  "steps": ["python3 agg.py \"$IN_REWARDS\" \"$OUT_DIR/agg.json\""],
  "outputs": {"agg": "agg.json"},
  "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"},
  "timeout": 60,
}
json.dump(spec, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WF0=$(c publish workflow "$W/wf-t0.json" "T0 aggregation" -t demo 2>"$W/wf0-err.txt")

head_ "network-shaped steps warn at publish (#7, advisory)"
check "deterministic workflow: no network warning" "$(grep -c 'network-shaped' "$W/wf0-err.txt")" "0"
net_case() {
  local label="$1" step="$2" want="$3"
  jq -n --arg s "$step" '{steps:["true", $s], outputs:{o:"o"}}' >"$W/wf-net-$label.json"
  local code; code=$(rc c publish workflow "$W/wf-net-$label.json" "net $label")
  if [ "$code" = 0 ] && grep -q "warning: steps\[1\] looks network-shaped: it $want" "$W/err.txt" \
     && grep -q -- "--exec sandbox" "$W/err.txt"; then
    ok "$label: warns, exit 0"
  else
    bad "$label (exit $code): $(cat "$W/err.txt")"
  fi
}
net_case curl 'curl -sS http://example.com > "$OUT_DIR/o"' "runs curl"
net_case piped-rpc 'seq 1 3 | xargs -n1 dcrctl getblockhash > "$OUT_DIR/o"' "runs dcrctl"
net_case subshell 'H=$(bitcoin-cli getbestblockhash); echo "$H" > "$OUT_DIR/o"' "runs bitcoin-cli"
net_case git-clone 'git clone https://example.org/x.git src' "runs git clone"
net_case pip 'pip install pandas' "installs packages (pip)"
net_case python-requests 'python3 -c "import requests; requests.get(1)"' "calls requests"
jq -n '{steps:["echo \"see the http docs\" > \"$OUT_DIR/o\"", "sort \"$IN_X\" | ssh-keygen -l > /dev/null || true"], outputs:{o:"o"}}' >"$W/wf-net-quiet.json"
check "word 'http' in an argument / ssh-keygen: no warning" \
  "$(rc c publish workflow "$W/wf-net-quiet.json" "net quiet" >/dev/null; grep -c 'network-shaped' "$W/err.txt")" "0"
OUT0=$(c run "$WF0" --publish --publish-type synthesis --title "T0 out" | awk '{print $1}')

head_ "T0 — bitwise"
check "run --publish stamps T0" "$(c get "$OUT0" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verification"]["tier"])')" "T0"
check "verify PASSes" "$(rc c verify "$OUT0")" "0"
check "verify says PASS" "$(grep -c '^PASS' "$W/out.txt")" "1"

# regression: corrupt the stored blob → verify must FAIL
BLOB=$(c get "$OUT0" | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])')
BLOB_PATH="$COMMONS_ROOT/store/sha256/${BLOB:0:2}/$BLOB"
cp "$BLOB_PATH" "$W/blob.bak"
chmod 644 "$BLOB_PATH"; echo '{"tampered":true}' > "$BLOB_PATH"
check "corrupt blob → verify FAIL" "$(rc c verify "$OUT0")" "1"
check "tamper FAIL names local corruption" "$(grep -c 'local tampering/corruption' "$W/err.txt")" "1"
check "fsck detects tamper" "$(rc c fsck)" "1"
cp -f "$W/blob.bak" "$BLOB_PATH"; chmod 444 "$BLOB_PATH"
check "restored blob → verify PASS again" "$(rc c verify "$OUT0")" "0"

head_ "comparators publish as untiered methods"
CMP=$(c publish skill "$REPO/comparators/json-numeric-epsilon.py" "json-numeric-epsilon" \
        -d "T1 comparator: JSON with float tolerance" -t comparator)
CMP_SET=$(c publish skill "$REPO/comparators/sorted-set-equality.py" "sorted-set-equality" \
        -d "T1 comparator: line multiset equality" -t comparator)
check "epsilon comparator published" "$(echo "$CMP" | grep -c '^sk-')" "1"
check "set comparator published" "$(echo "$CMP_SET" | grep -c '^sk-')" "1"
check "skill gets no verification block" \
  "$(c get "$CMP" | python3 -c 'import json,sys;print("verification" in json.load(sys.stdin))')" "False"
check "workflow gets no verification block" \
  "$(c get "$WF0" | python3 -c 'import json,sys;print("verification" in json.load(sys.stdin))')" "False"
# 3 = WF0 + the two comparators; the #7 network-warning cases above add 7 workflows.
check "method ledger line says method" "$(c log -n 100 | grep -c '"tier": "method"')" "10"
check "method shows as — in list" "$(c list --type skill | grep -c '—')" "2"
check "explicit tier on a method still honoured" \
  "$(c publish skill "$REPO/comparators/sorted-set-equality.py" "forced tier" --tier T0 --force >/dev/null; c get "$CMP_SET" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verification"]["tier"])')" "T0"
c publish skill "$REPO/comparators/sorted-set-equality.py" "sorted-set-equality" \
  -d "T1 comparator: line multiset equality" -t comparator --force >/dev/null
check "comparator self-test passes" "$(rc "$REPO/comparators/json-numeric-epsilon.py" --self-test)" "0"
check "set comparator self-test passes" "$(rc "$REPO/comparators/sorted-set-equality.py" --self-test)" "0"

head_ "T1 — tolerance (last-ulp float jitter)"
# Workflow whose float output jitters in the last ulp between runs: byte-compare
# must fail, epsilon comparator must pass. Jitter is driven by a marker file so
# the *first* run (the published one) and re-runs differ deterministically.
python3 - "$W/wf-t1.json" "$DS" <<'PY'
import json, sys
spec = {
  "interpreter": "bash",
  "inputs": {"REWARDS": sys.argv[2]},
  "attachments": {"jitter.py": (
      "import csv, json, os, sys\n"
      "rows = list(csv.DictReader(open(sys.argv[1])))\n"
      "tot = sum(int(r['claimed_usd']) for r in rows) / sum(int(r['promised_usd']) for r in rows)\n"
      "# deterministic last-ulp perturbation on re-runs (marker persists in scratch)\n"
      "marker = os.path.join(os.path.dirname(os.path.dirname(sys.argv[2])), '.ran')\n"
      "import math\n"
      "if os.path.exists(os.environ.get('JITTER_MARKER', marker)):\n"
      "    tot = math.nextafter(tot, math.inf)\n"
      "else:\n"
      "    open(os.environ.get('JITTER_MARKER', marker), 'w').close()\n"
      "json.dump({'ratio': tot, 'n': len(rows)}, open(sys.argv[2], 'w'), indent=2, sort_keys=True)\n")},
  "steps": ["python3 jitter.py \"$IN_REWARDS\" \"$OUT_DIR/ratio.json\""],
  "outputs": {"ratio": "ratio.json"},
  "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"},
  "timeout": 60,
  "tier": "T1",
  "comparator": "__CMP__",
}
json.dump(spec, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
# The marker path is DECLARED in the spec's env, not exported into the harness shell.
# Native runs get a scrubbed environment (only PATH/HOME plus spec env), because an
# undeclared host variable is an undeclared input: it can change output bytes while
# leaving provenance identical, so the publisher would verify PASS and everyone else
# FAIL. This fixture needs a re-run to differ on purpose, so it declares the knob it
# uses.
export JITTER_MARKER="$W/.jitter-marker"
python3 - "$W/wf-t1.json" "$CMP" "$JITTER_MARKER" <<'PY'
import json, sys
p = sys.argv[1]; spec = json.load(open(p))
spec["comparator"] = sys.argv[2]
spec.setdefault("env", {})["JITTER_MARKER"] = sys.argv[3]
json.dump(spec, open(p, "w"), indent=2, sort_keys=True)
PY
WF1=$(c publish workflow "$W/wf-t1.json" "T1 jittery ratio" -t demo)
OUT1=$(c run "$WF1" --publish --publish-type synthesis --title "T1 out" | awk '{print $1}')
check "run --publish honours spec tier T1" "$(c get "$OUT1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verification"]["tier"])')" "T1"
check "T1 records comparator id" "$(c get "$OUT1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verification"]["criteria"])')" "$CMP"

# prove the jitter is real: a re-run's bytes differ from the published blob
c run "$WF1" -o "$W" >/dev/null 2>&1
STORED_HASH=$(c get "$OUT1" | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])')
STORED_PATH="$COMMONS_ROOT/store/sha256/${STORED_HASH:0:2}/$STORED_HASH"
RERUN_HASH=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$W/ratio.json")
if [ "$STORED_HASH" != "$RERUN_HASH" ]; then ok "re-run bytes differ (jitter present)"; else bad "jitter fixture did not jitter"; fi
check "byte-compare would fail" "$(rc "$REPO/comparators/sorted-set-equality.py" "$STORED_PATH" "$W/ratio.json")" "1"
check "epsilon comparator accepts jitter" "$(EPSILON=1e-9 rc "$REPO/comparators/json-numeric-epsilon.py" "$STORED_PATH" "$W/ratio.json")" "0"
check "T1 verify PASSes despite jitter" "$(rc c verify "$OUT1")" "0"
check "T1 verify cites comparator" "$(grep -c 'equivalent under' "$W/out.txt")" "1"

# T1 with a comparator that rejects: tight epsilon via manifest params
head_ "T1 — comparator that rejects"
python3 - "$COMMONS_ROOT/registry/artifacts/$OUT1.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m["verification"]["params"] = {"EPSILON": "0"}
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
check "EPSILON=0 → T1 verify FAILs" "$(rc c verify "$OUT1")" "1"
python3 - "$COMMONS_ROOT/registry/artifacts/$OUT1.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m["verification"].pop("params", None)
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY

head_ "T2/T3 — not machine verifiable"
echo "# Narrative synthesis of the demo data" > "$W/note.md"
T2=$(c publish report "$W/note.md" "Judged report" --tier T2 \
      --criteria "Rubric: each claim cites an artifact id; no numbers absent from cited data" \
      --input "$DS" --link "cites:$OUT0")
check "T2 verify exits 3" "$(rc c verify "$T2")" "3"
check "T2 prints NOT-MACHINE-VERIFIABLE" "$(grep -c 'NOT-MACHINE-VERIFIABLE' "$W/out.txt")" "1"
check "T2 prints criteria" "$(grep -c 'Rubric: each claim cites' "$W/out.txt")" "1"
check "T2 without criteria refused" "$(rc c publish report "$W/note.md" "No rubric" --tier T2)" "1"
check "T3 verify exits 3" "$(rc c verify "$DS")" "3"

head_ "tier validation"
check "T1 publish without criteria refused" "$(rc c publish dataset "$W/rewards.csv" "x" --tier T1)" "1"
check "T1 criteria must be sk- id" "$(rc c publish dataset "$W/rewards.csv" "x" --tier T1 --criteria "some text")" "1"
check "T1 criteria must exist" "$(rc c publish dataset "$W/rewards.csv" "x" --tier T1 --criteria sk-deadbeef)" "1"
check "unknown tier refused" "$(rc c publish dataset "$W/rewards.csv" "x" --tier T9)" "2"
echo "not a comparator" > "$W/nope.txt"
NOTSKILL=$(c publish dataset "$W/nope.txt" "not a skill")
check "T1 criteria must be a skill" "$(rc c publish dataset "$W/rewards.csv" "x" --tier T1 --criteria "$NOTSKILL")" "1"

head_ "status — chain grade"
RP=$(c publish report "$W/note.md" "Chain report" --tier unverified --force \
      --input "$DS" --link "cites:$OUT0" --link "cites:$T2")
check "status exit reflects grade" "$(rc c status "$RP")" "4"
check "status names weakest tier" "$(grep -c 'chain grade: unverified' "$W/out.txt")" "1"
check "status walks to T0 node" "$(grep -c "$OUT0" "$W/out.txt")" "1"
# $DS is reachable twice (direct input + via $OUT0's provenance): shown once,
# then flagged as a repeat — that de-duplication is the cycle guard doing its job.
check "status walks to T3 input" "$([ "$(grep -c "$DS" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "repeat node shown once, then flagged" "$(grep "$DS" "$W/out.txt" | grep -c 'already shown')" "1"

# a T0 artifact whose own chain is all T0/T3 → grade is the weakest (T3 dataset)
check "T0 output chain grade = T3 (weakest input)" "$(rc c status "$OUT0")" "3"
check "grade line shows T3" "$(grep -c 'chain grade: T3' "$W/out.txt")" "1"

# methods (workflow/skill) are pinned by hash, not tiered → no chain grade
check "--criteria without --tier refused" "$(rc c publish skill "$W/nope.txt" "x" --criteria "rubric")" "1"
check "workflow node status exits 0 (method)" "$(rc c status "$WF0")" "0"
check "workflow reports grade n/a" "$(grep -c 'chain grade: n/a' "$W/out.txt")" "1"
check "comparator skill is a method too" "$(rc c status "$CMP")" "0"
check "workflow not counted in T0 chain" "$(c status "$OUT0" 2>&1 | grep -c 'method')" "1"

head_ "status — cycle safety"
# A cites B, B cites A (hand-built cycle) must terminate
CY_A=$(c publish wiki "$W/note.md" "cycle A" --tier T0 --force)
echo "# cycle b" > "$W/b.md"
CY_B=$(c publish wiki "$W/b.md" "cycle B" --tier T0 --link "cites:$CY_A")
python3 - "$COMMONS_ROOT/registry/artifacts/$CY_A.json" "$CY_B" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m["links"] = [{"rel": "cites", "id": sys.argv[2]}]
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
timeout 20 "$COMMONS" status "$CY_A" >"$W/out.txt" 2>&1; CYRC=$?
if [ "$CYRC" -ne 124 ]; then ok "cycle terminates (no hang)"; else bad "cycle hung"; fi
check "cycle marks repeat node" "$(grep -c 'already shown' "$W/out.txt")" "1"

# deep chain hits the depth cap rather than recursing forever
PREV=$(c publish wiki "$W/b.md" "depth 0" --force --tier T0)
for i in $(seq 1 14); do
  printf '# depth %s\n' "$i" > "$W/d$i.md"
  PREV=$(c publish wiki "$W/d$i.md" "depth $i" --tier T0 --link "cites:$PREV")
done
timeout 20 "$COMMONS" status "$PREV" >"$W/out.txt" 2>&1; DRC=$?
if [ "$DRC" -ne 124 ]; then ok "deep chain terminates"; else bad "deep chain hung"; fi
check "depth cap reported" "$(grep -c 'depth cap reached' "$W/out.txt")" "1"

head_ "status — dangling reference"
DANG=$(c publish wiki "$W/b.md" "dangling citer" --tier T0 --force --link "cites:ds-deadbeef")
timeout 20 "$COMMONS" status "$DANG" >"$W/out.txt" 2>&1; DGRC=$?
check "missing artifact in chain is flagged" "$(grep -c 'MISSING from registry' "$W/out.txt")" "1"
check "dangling ref degrades grade to unverified" "$DGRC" "4"

head_ "machine-readable list"
check "list --json exits 0" "$(rc c list --json --type dataset --limit 1)" "0"
check "list --json suppresses total stderr" "$(wc -c < "$W/err.txt" | tr -d ' ')" "0"
check "list --json is parseable and limited" \
  "$(python3 - "$W/out.txt" <<'PY'
import json, sys
rows = json.load(open(sys.argv[1]))
print(len(rows) == 1 and rows[0]["type"] == "dataset")
PY
)" "True"
check "list --json exposes stable row fields" \
  "$(python3 - "$W/out.txt" <<'PY'
import json, sys
row = json.load(open(sys.argv[1]))[0]
print(all(k in row for k in ("id", "type", "tier", "agent", "created", "title")))
PY
)" "True"
JSON_ROWS=$(c list --json --type wiki --limit 3 | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')
HUMAN_ROWS=$(c list --type wiki --limit 3 2>/dev/null | wc -l | tr -d ' ')
check "JSON array length matches human row count" "$JSON_ROWS" "$HUMAN_ROWS"

head_ "housekeeping"
check "search --by works (no argparse collision)" "$(rc c search demo --by test-p1)" "0"
check "search --tier filters" "$(c search demo --tier T3 | grep -c "$DS")" "1"

# Hyphenated queries: FTS5 reads `-` as syntax, so `claim-efficiency` used to raise
# "no such column: efficiency" as a raw traceback — on the most natural query anyone
# would type against a registry full of hyphenated terms.
c publish wiki "$W/b.md" "claim-efficiency notes" --force >/dev/null 2>&1
check "hyphenated query does not crash" "$(rc c search claim-efficiency)" "0"
check "no traceback leaked" "$(grep -c 'Traceback' "$W/out.txt" "$W/err.txt" | grep -c ':[1-9]')" "0"
check "hyphenated query actually matches" \
  "$([ "$(grep -c 'claim-efficiency' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "dotted/colon query does not crash" "$(rc c search 'rc.v1')" "$(rc c search 'rc.v1')"
check "FTS operators still work" "$(rc c search 'claim OR demo')" "0"
check "prefix search still works" "$(rc c search 'dem*')" "0"
check "deliberate phrase syntax passes through" "$(rc c search '"claim-efficiency notes"')" "0"
check "broken query reports a query error, not a corrupt index" \
  "$([ "$(rc c search '"unclosed')" = "1" ] && grep -c 'could not parse the search query' "$W/err.txt")" "1"
check "list --tier filters" "$(c list --tier T0 | wc -l | tr -d ' ')" "$(c list --tier T0 | grep -c 'T0')"
check "every publish ledger line carries a tier" \
  "$(c log -n 200 | python3 -c 'import json,sys; ls=[json.loads(l) for l in sys.stdin]; print(sum(1 for e in ls if e["action"] in ("publish","republish") and "tier" not in e))')" "0"
check "ledger lines carry schema" \
  "$(c log -n 200 | python3 -c 'import json,sys; ls=[json.loads(l) for l in sys.stdin]; print(sum(1 for e in ls if e.get("schema")!="rc.v1"))')" "0"
check "verify events record tier" \
  "$(c log -n 200 | python3 -c 'import json,sys; ls=[json.loads(l) for l in sys.stdin]; print(sum(1 for e in ls if e["action"].startswith("verify-") and "tier" not in e))')" "0"
check "unknown schema major refused" "$(python3 - "$COMMONS_ROOT/registry/artifacts/$DS.json" <<'PY' >/dev/null 2>&1; rc c get "$DS"
import json, sys
p = sys.argv[1]; m = json.load(open(p)); m["schema"] = "rz.v9"
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
)" "1"
python3 - "$COMMONS_ROOT/registry/artifacts/$DS.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p)); m["schema"] = "rc.v1"
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
check "reindex clean" "$(rc c reindex)" "0"
check "fsck clean" "$(rc c fsck)" "0"

head_ "migration (v0.1 manifests)"
MIG="$COMMONS_ROOT/mig"; mkdir -p "$MIG/registry/artifacts" "$MIG/store/sha256"
python3 - "$MIG" <<'PY'
import hashlib, json, os, sys
root = sys.argv[1]
def put(aid, atype, body, prov=None):
    d = hashlib.sha256(body.encode()).hexdigest()
    open(os.path.join(root, "store/sha256", d), "w").write(body)
    m = {"id": aid, "type": atype, "title": aid, "description": "", "tags": [],
         "agent": "alice", "created": "2026-07-23T00:00:00Z",
         "content": {"sha256": d, "filename": aid + ".txt", "bytes": len(body)}, "links": []}
    if prov: m["provenance"] = prov
    json.dump(m, open(os.path.join(root, "registry/artifacts", aid + ".json"), "w"),
              indent=2, sort_keys=True)
put("ds-11111111", "dataset", "a,b\n1,2\n")
put("wf-22222222", "workflow", '{"interpreter":"bash","steps":[]}')
put("sy-33333333", "synthesis", "derived\n",
    {"workflow": {"id": "wf-22222222", "sha256": "x"}, "inputs": []})
put("rp-44444444", "report", "# narrative\n")
PY
check "migrate --dry-run writes nothing" "$(rc python3 "$REPO/scripts/migrate-v02.py" --root "$MIG" --dry-run)" "0"
check "dry-run left manifests unstamped" "$(grep -c verification "$MIG/registry/artifacts/ds-11111111.json" || true)" "0"
check "migrate runs" "$(rc python3 "$REPO/scripts/migrate-v02.py" --root "$MIG")" "0"
tier_of() { python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["verification"]["tier"])' "$MIG/registry/artifacts/$1.json"; }
check "derived → T0" "$(tier_of sy-33333333)" "T0"
check "dataset → T3" "$(tier_of ds-11111111)" "T3"
check "narrative report → unverified" "$(tier_of rp-44444444)" "unverified"
check "workflow stays untiered (method)" \
  "$(python3 -c 'import json,sys;print("verification" in json.load(open(sys.argv[1])))' "$MIG/registry/artifacts/wf-22222222.json")" "False"
check "method still gets schema stamp" \
  "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["schema"])' "$MIG/registry/artifacts/wf-22222222.json")" "rc.v1"
check "schema stamped" "$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["schema"])' "$MIG/registry/artifacts/ds-11111111.json")" "rc.v1"
check "migrate is idempotent" "$(python3 "$REPO/scripts/migrate-v02.py" --root "$MIG" | grep -c '0 stamped')" "1"

head_ "native exec: undeclared host env is not an input (regression, 2026-08-12)"
# A workflow whose output depends on an UNDECLARED host variable. If the runner leaks
# the host environment, the publisher's bytes differ from a stranger's while provenance
# stays byte-identical: publisher verifies PASS, everyone else FAILs, and no manifest
# inspection can reveal it. Sandbox mode never had this; native did until this fix.
python3 - "$W/wf-envleak.json" <<'PY'
import json, sys
json.dump({
  "interpreter": "bash",
  "steps": ["printf '%s' \"${COMMONS_TEST_LEAK:-absent}\" > $OUT_DIR/r.txt"],
  "outputs": {"r": "r.txt"},
  "timeout": 60,
  "tier": "T0",
}, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WFL=$(c publish workflow "$W/wf-envleak.json" "env leak probe" -t demo)
# Publish with the host variable set; it must NOT reach the run.
LEAKED=$(COMMONS_TEST_LEAK=SECRET c run "$WFL" --exec native --publish --publish-type synthesis \
           --title "leak probe" | awk '{print $1}')
check "undeclared host var does not reach a native run" "$(c cat "$LEAKED")" "absent"
# The decisive property: a stranger (no host var) must reach the publisher's verdict.
check "stranger verifies PASS" "$(rc c verify "$LEAKED" --exec native)" "0"
check "publisher-with-var reaches the same verdict" \
  "$(COMMONS_TEST_LEAK=SECRET rc c verify "$LEAKED" --exec native)" "0"
# A DECLARED env value must still work — the fix scrubs, it does not ignore the spec.
python3 - "$W/wf-envdecl.json" <<'PY'
import json, sys
json.dump({
  "interpreter": "bash",
  "steps": ["printf '%s' \"${COMMONS_TEST_DECLARED:-absent}\" > $OUT_DIR/r.txt"],
  "outputs": {"r": "r.txt"},
  "env": {"COMMONS_TEST_DECLARED": "declared-value"},
  "timeout": 60,
  "tier": "T0",
}, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WFD=$(c publish workflow "$W/wf-envdecl.json" "env declared probe" -t demo)
DECL=$(c run "$WFD" --exec native --publish --publish-type synthesis --title "declared probe" \
         | awk '{print $1}')
check "declared spec env still reaches the run" "$(c cat "$DECL")" "declared-value"
check "host var cannot override declared spec env" \
  "$(COMMONS_TEST_DECLARED=hijacked c cat "$DECL")" "declared-value"

head_ "native publish: say so when the container runtime is unreachable (issue #25)"
# Daemon-independent: a stub `docker` that always fails stands in for a stopped
# daemon, and one that always succeeds for a running one. Advisory only.
STUBDOWN="$W/stub-down"; STUBUP="$W/stub-up"; mkdir -p "$STUBDOWN" "$STUBUP"
printf '#!/bin/sh\necho "Cannot connect to the Docker daemon" >&2\nexit 1\n' > "$STUBDOWN/docker"
printf '#!/bin/sh\necho 27.0.0\nexit 0\n' > "$STUBUP/docker"
chmod +x "$STUBDOWN/docker" "$STUBUP/docker"
check "runtime down: native --publish still succeeds (exit unchanged)" \
  "$(PATH="$STUBDOWN:$PATH" rc c run "$WFD" --exec native --publish --publish-type synthesis --title "declared probe")" "0"
check "runtime down: stderr says sandboxed execution was not available" \
  "$(grep -c 'runtime is not reachable on this host' "$W/err.txt")" "1"
check "runtime down: the warning stays off stdout" \
  "$(grep -c 'not reachable' "$W/out.txt")" "0"
check "runtime up: no warning on native --publish" \
  "$(PATH="$STUBUP:$PATH" rc c run "$WFD" --exec native --publish --publish-type synthesis --title "declared probe" >/dev/null; grep -c 'not reachable' "$W/err.txt")" "0"
mkdir -p "$W/noout"
check "runtime down, no --publish: no warning (nothing is being published)" \
  "$(PATH="$STUBDOWN:$PATH" rc c run "$WFD" --exec native -o "$W/noout" >/dev/null; grep -c 'not reachable' "$W/err.txt")" "0"

printf '\n\033[1mtest-tiers: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
