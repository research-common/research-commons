#!/usr/bin/env bash
# P5 gate — capacity exchange lifecycle: task lint, claim/submit/accept, TTLs,
# beneficiary-only settlement, and the non-negotiable foreign-task sandbox rule.
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

# Probe with a throwaway key: this checks viem is installed, not that the host has a key.
_PROBEKEY="$(mktemp -t commons-probe-XXXXXX)"
python3 -c "import secrets,sys;open(sys.argv[1],'w').write('0x'+secrets.token_hex(32))" "$_PROBEKEY"
if ! MESSAGE=probe COMMONS_SIGNING_KEY="$_PROBEKEY" node "$REPO/lib/sign-message.mjs" >/dev/null 2>&1; then
  rm -f "$_PROBEKEY"
  echo "test-exchange: signer not functional — cannot validate P5"; exit 1
fi
rm -f "$_PROBEKEY"
if ! command -v docker >/dev/null 2>&1 || ! timeout 30 docker info >/dev/null 2>&1; then
  echo "test-exchange: docker unavailable — the sandbox gate cannot be proven"; exit 1
fi
if ! docker image inspect research-commons-sandbox:base >/dev/null 2>&1; then
  echo "test-exchange: default image research-commons-sandbox:base missing — the sandbox gate cannot be proven."
  echo "  build it: docker build -t research-commons-sandbox:base environments/base/"; exit 1
fi

LAB="$(mktemp -d -t commons-exch-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export COMMONS_ROOT="$LAB/reg"; export COMMONS_AGENT=test-p5
mkdir -p "$COMMONS_ROOT/registry" "$LAB/w"
cp "$REPO/registry/exec-policy.example.json" "$COMMONS_ROOT/registry/exec-policy.json"
W="$LAB/w"

# Two identities: the beneficiary (us) and a worker (them).
BKEY="$LAB/ben.key"; WKEY="$LAB/wrk.key"
python3 -c "import secrets;open('$BKEY','w').write('0x'+secrets.token_hex(32))"
python3 -c "import secrets;open('$WKEY','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$BKEY" "$WKEY"
ben() { COMMONS_SIGNING_KEY="$BKEY" "$COMMONS" "$@"; }
wrk() { COMMONS_SIGNING_KEY="$WKEY" COMMONS_AGENT=worker "$COMMONS" "$@"; }
rc()  { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
# Generation has no public publish flag. Fixture authors amend their own held
# view through the real signing/commit path instead of editing signed claims.
set_generation() {
  COMMONS_SIGNING_KEY="$1" python3 - "$COMMONS" "$2" "$3" <<'PYGEN'
import json, runpy, sys
ns = runpy.run_path(sys.argv[1])
m = ns["load_manifest"](sys.argv[2])
m["generation"] = json.loads(sys.argv[3])
ns["commit_signed_publish"](m["id"], m, {
    "agent": "generation-fixture", "action": "republish", "id": m["id"],
    "sha256": m["content"]["sha256"]}, True)
PYGEN
}

BEN=$(ben peer whoami | head -1)
WRK=$(wrk peer whoami | head -1)
ben peer add "$BEN" --agent-id test-p5 --trust full >/dev/null
ben peer add "$WRK" --agent-id worker --trust full >/dev/null

head_ "fixtures"
printf 'avs,claimed\nalpha,900\nbeta,500\n' > "$W/d.csv"
DS=$(ben publish dataset "$W/d.csv" "task input" --license MIT 2>/dev/null)
cat > "$W/body.py" <<'PY'
import csv, json, os
rows = list(csv.DictReader(open(os.environ["IN_D"])))
json.dump({"total": sum(int(r["claimed"]) for r in rows), "n": len(rows)},
          open(os.environ["OUT_DIR"] + "/r.json", "w"), indent=2, sort_keys=True)
PY
python3 - "$W/wf.json" "$DS" "$W/body.py" <<'PY'
import json, sys
json.dump({"interpreter": "bash", "inputs": {"D": sys.argv[2]},
           "attachments": {"step.py": open(sys.argv[3]).read()},
           "steps": ["python3 step.py"], "outputs": {"r": "r.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60},
          open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WF=$(ben publish workflow "$W/wf.json" "task workflow" 2>/dev/null)
check "fixtures published" "$([ -n "$DS" ] && [ -n "$WF" ] && echo yes)" "yes"

# mkwf <outfile> <salt> — a deterministic workflow whose output is unique per salt,
# so each task in this suite gets a distinct result artifact. (Content-addressing means
# identical work collapses to ONE artifact fulfilling many tasks: correct, and exactly
# why fixtures must differ when a test wants to inspect one task's result in isolation.)
mkwf() {
  local out="$1" salt="$2"
  cat > "$W/body-$salt.py" <<PY
import csv, json, os
rows = list(csv.DictReader(open(os.environ["IN_D"])))
json.dump({"total": sum(int(r["claimed"]) for r in rows), "n": len(rows),
           "salt": "$salt"},
          open(os.environ["OUT_DIR"] + "/r.json", "w"), indent=2, sort_keys=True)
PY
  python3 - "$out" "$DS" "$W/body-$salt.py" <<'PY'
import json, sys
json.dump({"interpreter": "bash", "inputs": {"D": sys.argv[2]},
           "attachments": {"step.py": open(sys.argv[3]).read()},
           "steps": ["python3 step.py"], "outputs": {"r": "r.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60},
          open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
}

mktask() {  # mktask <outfile> <python-dict-overrides>
  python3 - "$1" "$DS" "$WF" "$BEN" "$2" <<'PY'
import json, sys
out, ds, wf, ben, over = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
spec = {"objective": "Total the claimed column", "priority": 2,
        "expires": "2099-01-01T00:00:00Z",
        "inputs": [{"id": ds}],
        "execution": {"workflow": wf},
        "verification": {"tier": "T0", "criteria": "byte-identical re-derivation"},
        "beneficiary": {"agent": "test-p5", "addr": ben}}
spec.update(json.loads(over))
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
}

head_ "publish lint — terms bind before anyone can claim"
mktask "$W/t-ok.json" '{}'
TK=$(ben publish task "$W/t-ok.json" "Total claimed" 2>/dev/null)
check "valid task publishes" "$(echo "$TK" | grep -c '^tk-')" "1"

mktask "$W/t-norubric.json" '{"verification": {"tier": "T2"}}'
check "T2 without criteria refused" "$(rc ben publish task "$W/t-norubric.json" "x")" "1"
check "refusal cites rubric-before-claim" "$(grep -c 'rubric-before-claim' "$W/err.txt")" "1"

mktask "$W/t-noexp.json" '{"expires": null}'
check "task without expiry refused" "$(rc ben publish task "$W/t-noexp.json" "x")" "1"
check "refusal explains why" "$(grep -c 'never leaves the queue' "$W/err.txt")" "1"

mktask "$W/t-nowf.json" '{"execution": {"brief": "do it by hand"}}'
check "T0 without a workflow refused" "$(rc ben publish task "$W/t-nowf.json" "x")" "1"
check "refusal explains machine-verifiable needs a machine" \
  "$(grep -c 'needs a machine to run' "$W/err.txt")" "1"

mktask "$W/t-pedigree.json" '{"verification": {"tier": "T2", "criteria": "Must be written by Claude Opus, well argued"}, "execution": {"brief": "write an analysis"}}'
check "T2 rubric naming a model refused" "$(rc ben publish task "$W/t-pedigree.json" "x")" "1"
check "refusal explains masquerade economics" \
  "$(grep -c 'masquerading pays' "$W/err.txt")" "1"
mktask "$W/t-t2ok.json" '{"verification": {"tier": "T2", "criteria": "Every claim cites an artifact id; no figure appears that is absent from cited data"}, "execution": {"brief": "write an analysis"}}'
T2TASK=$(ben publish task "$W/t-t2ok.json" "Judged analysis" 2>/dev/null)
check "output-only T2 rubric accepted" "$(echo "$T2TASK" | grep -c '^tk-')" "1"

mktask "$W/t-noben.json" '{"beneficiary": {}}'
check "task without beneficiary refused" "$(rc ben publish task "$W/t-noben.json" "x")" "1"
mktask "$W/t-badquorum.json" '{"max_claims": 2, "diversity_quorum": {"k": 3, "distinct_families": 2}}'
check "unfillable diversity quorum refused" "$(rc ben publish task "$W/t-badquorum.json" "x")" "1"
check "refusal notes it could never be filled" \
  "$(grep -c 'could never be filled' "$W/err.txt")" "1"
mktask "$W/t-badinput.json" '{"inputs": [{"id": "ds-deadbeef"}]}'
check "task citing an unpublished input refused" "$(rc ben publish task "$W/t-badinput.json" "x")" "1"

head_ "queue is a view over the ledger"
check "new task shows open" "$(ben queue | grep "$TK" | grep -c 'open')" "1"
check "queue filters by beneficiary" "$(ben queue --peer test-p5 | grep -c "$TK")" "1"
check "queue excludes other beneficiaries" "$(ben queue --peer nobody | grep -c "$TK")" "0"
check "status reports open" "$(ben status "$TK" | grep -c 'state      : open')" "1"

head_ "claim lifecycle"
check "unsigned claim refused" "$(COMMONS_SIGNING_KEY= rc "$COMMONS" claim "$TK")" "1"
check "refusal explains attribution" "$(grep -c 'indistinguishable from squatting' "$W/err.txt")" "1"
check "worker claims" "$(rc wrk claim "$TK" --ttl 24h)" "0"
check "claim announces the sandbox rule" "$(grep -c 'FOREIGN task' "$W/out.txt")" "1"
check "state now claimed" "$(ben status "$TK" | grep -c 'state      : claimed')" "1"
check "double-claim by same worker refused" "$(rc wrk claim "$TK")" "1"
check "second claimant refused (max_claims=1)" "$(rc ben claim "$TK")" "1"
check "refusal names the holder" "$(grep -c "$WRK" "$W/err.txt")" "1"
check "queue shows slot usage" "$(ben queue | grep "$TK" | grep -c '1/1')" "1"

head_ "🔒 THE GATE: foreign task execution is sandboxed in code"
# A workflow that records whether it can see the host filesystem. Under the sandbox
# it cannot; natively it can. The marker is how we prove which path actually ran.
MARKER="$W/escaped-to-host"
rm -f "$MARKER"
cat > "$W/body-escape.py" <<PY
import json, os
escaped = os.path.isdir("$W")
if escaped:
    open("$MARKER", "w").write("native execution reached the host filesystem")
json.dump({"escaped": escaped}, open(os.environ["OUT_DIR"] + "/r.json", "w"), sort_keys=True)
PY
python3 - "$W/wf-escape.json" "$DS" "$W/body-escape.py" <<'PY'
import json, sys
json.dump({"interpreter": "bash", "inputs": {"D": sys.argv[2]},
           "attachments": {"step.py": open(sys.argv[3]).read()},
           "steps": ["python3 step.py"], "outputs": {"r": "r.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 120},
          open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WFE=$(ben publish workflow "$W/wf-escape.json" "escape probe" 2>/dev/null)
mktask "$W/t-escape.json" "{\"execution\": {\"workflow\": \"$WFE\"}, \"objective\": \"escape probe\"}"
TKE=$(ben publish task "$W/t-escape.json" "Escape probe" 2>/dev/null)
wrk claim "$TKE" >/dev/null 2>&1

# The assertion that matters: an explicit env override must NOT weaken execution.
COMMONS_EXEC=native wrk run-task "$TKE" >"$W/out.txt" 2>"$W/err.txt"; ESC_RC=$?
check "run-task succeeds under COMMONS_EXEC=native" "$ESC_RC" "0"
check "override was explicitly ignored" "$(grep -c 'ignored' "$W/err.txt")" "1"
check "🔒 host filesystem NOT reached (marker absent)" "$([ -f "$MARKER" ] && echo LEAKED || echo yes)" "yes"
RES_ESC=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
check "result records sandbox execution" \
  "$(ben get "$RES_ESC" | python3 -c 'import json,sys;print(json.load(sys.stdin)["provenance"]["run"]["exec"]["mode"])')" "sandbox"
check "result proves isolation held" \
  "$(ben cat "$RES_ESC" | python3 -c 'import json,sys;print(json.load(sys.stdin)["escaped"])')" "False"
check "own task still honours --exec native" \
  "$(rc ben run-task "$TK" --exec native)" "0"
check "own-task result recorded native" \
  "$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1 | xargs -I{} sh -c "$COMMONS get {} | python3 -c 'import json,sys;print(json.load(sys.stdin)[\"provenance\"][\"run\"][\"exec\"][\"mode\"])'")" "native"

head_ "submit"
wrk run-task "$TK" >"$W/out.txt" 2>&1
RES=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
check "worker produced a result" "$([ -n "$RES" ] && echo yes)" "yes"
check "submitting an unpublished result refused" "$(rc wrk submit "$TK" sy-deadbeef)" "1"
check "refusal insists on published content" "$(grep -c 'publish it first' "$W/err.txt")" "1"
check "submit succeeds" "$(rc wrk submit "$TK" "$RES")" "0"
check "result derives fulfills->task from the authenticated submit" \
  "$(ben links "$RES" | grep -- '->' | grep -Fc "$TK [fulfills]")" "1"
check "state now submitted" "$(ben status "$TK" | grep -c 'state      : submitted')" "1"
check "status lists the submission" "$(ben status "$TK" | grep -c "$RES")" "1"
check "unclaimed submit refused" "$(rc ben submit "$T2TASK" "$RES")" "1"
check "refusal cites the concurrency limit" "$(grep -c 'bypass the concurrency limit' "$W/err.txt")" "1"

head_ "settlement is the beneficiary's alone"
check "worker cannot accept its own work" "$(rc wrk accept "$TK")" "1"
check "refusal names the beneficiary" "$(grep -ic "$BEN" "$W/err.txt")" "1"
check "refusal explains settlement authority" \
  "$(grep -c 'Settlement authority' "$W/err.txt")" "1"
check "reject without a reason refused" "$(rc ben reject "$TK")" "1"
check "refusal explains unappealable" "$(grep -c 'unappealable' "$W/err.txt")" "1"
check "beneficiary accepts" "$(rc ben accept "$TK")" "0"
check "state now accepted" "$(ben status "$TK" | grep -c 'state      : accepted')" "1"
check "status exits 0 once accepted" "$(rc ben status "$TK")" "0"
check "task derives accepted->result from the authenticated acceptance" \
  "$(ben links "$TK" | grep -- '->' | grep -Fc "$RES [accepted]")" "1"
check "settled task leaves the default queue" "$(ben queue | grep -c "$TK")" "0"
check "--all still shows it" "$(ben queue --all | grep -c "$TK")" "1"
check "claiming a settled task refused" "$(rc wrk claim "$TK")" "1"

head_ "rejection carries its reason into the ledger"
mktask "$W/t-rej.json" '{"objective": "will be rejected"}'
TKR=$(ben publish task "$W/t-rej.json" "Rejectable" 2>/dev/null)
wrk claim "$TKR" >/dev/null 2>&1
wrk run-task "$TKR" >"$W/out.txt" 2>&1
RESR=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$TKR" "$RESR" >/dev/null 2>&1
check "reject with reason succeeds" "$(rc ben reject "$TKR" --reason "totals disagree with the source data")" "0"
check "state now rejected" "$(ben status "$TKR" | grep -c 'state      : rejected')" "1"
check "reason visible in status" "$(ben status "$TKR" | grep -c 'totals disagree')" "1"
check "reason recorded in the ledger" "$(ben log -n 40 | grep -c 'totals disagree')" "1"

head_ "claim TTL expiry reopens the slot (no daemon)"
mktask "$W/t-ttl.json" '{"objective": "ttl test"}'
TKT=$(ben publish task "$W/t-ttl.json" "TTL test" 2>/dev/null)
# TTL headroom matters: the "still claimed" assertion runs a `status` that verifies
# signatures via a node subprocess, so a 1s TTL raced its own check under load and
# reported the task already reopened. Not a product bug — the claim really had expired.
# 4s is comfortably longer than a cold verify while keeping the suite fast.
wrk claim "$TKT" --ttl 4s >/dev/null 2>&1
check "claimed immediately after" "$(ben status "$TKT" | grep -c 'state      : claimed')" "1"
sleep 5
check "expired claim reopens the task" "$(ben status "$TKT" | grep -c 'state      : open')" "1"
check "expired claim is counted, not erased" "$(ben status "$TKT" | grep -c '1 expired')" "1"
check "another peer may now claim" "$(rc ben claim "$TKT")" "0"
check "release frees a slot immediately" \
  "$(ben release "$TKT" --reason "not needed" >/dev/null 2>&1; ben status "$TKT" | grep -c 'state      : open')" "1"

head_ "claim-time freshness advisories (federation lag, P3 2026-08-26)"
# Case 1: the task's declared input has since been superseded by a newer artifact.
printf 'avs,claimed\nnewer,111\n' > "$W/d2.csv"
DS2=$(ben publish dataset "$W/d2.csv" "newer input" --license MIT --link "supersedes:$DS" 2>/dev/null)
check "superseding dataset published" "$([ -n "$DS2" ] && echo yes)" "yes"
mktask "$W/t-fresh1.json" '{"objective": "freshness probe: superseded input"}'
TKF1=$(ben publish task "$W/t-fresh1.json" "Freshness 1" 2>/dev/null)
check "claim on superseded-input task still succeeds" "$(rc wrk claim "$TKF1")" "0"
check "warns about the superseded input" \
  "$(grep -c "input $DS has a newer artifact" "$W/err.txt")" "1"
check "names the superseding artifact" "$(grep -c "$DS2" "$W/err.txt")" "1"
wrk release "$TKF1" >/dev/null 2>&1

# Case 2: a result manifest already links fulfills->task locally, with no submit
# event yet recorded — the manifest replicated ahead of (or instead of) the ledger
# line that names it.
mktask "$W/t-fresh2.json" '{"objective": "freshness probe: orphaned result"}'
TKF2=$(ben publish task "$W/t-fresh2.json" "Freshness 2" 2>/dev/null)
printf 'orphan result bytes\n' > "$W/orphan.txt"
RESO=$(ben publish synthesis "$W/orphan.txt" "pre-linked result" --link "fulfills:$TKF2" 2>/dev/null)
check "orphaned result published" "$([ -n "$RESO" ] && echo yes)" "yes"
check "claim on task with an orphaned result still succeeds" "$(rc wrk claim "$TKF2")" "0"
check "warns about the pre-existing unrecorded result" \
  "$(grep -c "a result matching $TKF2 already exists locally" "$W/err.txt")" "1"
check "names the orphaned result" "$(grep -c "$RESO" "$W/err.txt")" "1"
wrk release "$TKF2" >/dev/null 2>&1
# The deliberately unbacked cached link has served its federation-lag probe.
# Remove it through the publisher's signing path so final fsck sees a clean view;
# publish --force without --link preserves existing links rather than removing them.
COMMONS_SIGNING_KEY="$BKEY" python3 - "$COMMONS" "$RESO" "$TKF2" <<'PYCLEAN'
import runpy, sys
ns = runpy.run_path(sys.argv[1])
m = ns["load_manifest"](sys.argv[2])
m["links"] = [link for link in m.get("links", [])
              if link != {"rel": "fulfills", "id": sys.argv[3]}]
ns["commit_signed_publish"](m["id"], m, {
    "agent": "freshness-fixture", "action": "republish", "id": m["id"],
    "sha256": m["content"]["sha256"]}, True)
PYCLEAN
check "unbacked freshness fixture cleaned through signed republish" "$?" "0"

# Control: a task with a fresh, never-superseded input and no pre-existing result
# manifest must not warn at all — the advisory must not fire on the common case.
# Deliberately points at $DS2, not $DS — $DS itself is now superseded (by the case-1
# fixture above), so reusing it here would make this a positive case, not a control.
mktask "$W/t-fresh-ctl.json" "{\"objective\": \"freshness probe: control (no staleness)\", \"inputs\": [{\"id\": \"$DS2\"}]}"
TKFC=$(ben publish task "$W/t-fresh-ctl.json" "Freshness control" 2>/dev/null)
check "control claim succeeds" "$(rc wrk claim "$TKFC")" "0"
check "control claim carries no freshness warning" \
  "$(grep -c 'newer artifact\|already exists locally' "$W/err.txt")" "0"
wrk release "$TKFC" >/dev/null 2>&1

head_ "heartbeat keeps long T2 work alive"
rc wrk claim "$T2TASK" --ttl 30s >/dev/null 2>&1
check "T2 claim announces the heartbeat requirement" \
  "$([ "$(cat "$W/out.txt" "$W/err.txt" | grep -c 'heartbeat')" -ge 1 ] && echo yes)" "yes"
check "holder can heartbeat" "$(rc wrk heartbeat "$T2TASK")" "0"
check "heartbeat recorded in the ledger" "$(ben log -n 10 | grep -c '"heartbeat"')" "1"
check "heartbeat by a non-holder refused" "$(rc ben heartbeat "$T2TASK")" "1"
check "refusal is explicit about the claim" "$(grep -c 'active claim' "$W/err.txt")" "1"

head_ "expired task cannot be claimed"
mktask "$W/t-past.json" '{"expires": "2020-01-01T00:00:00Z", "objective": "already over"}'
TKP=$(ben publish task "$W/t-past.json" "Past" 2>/dev/null)
check "expired task shows expired" "$(ben status "$TKP" | grep -c 'state      : expired')" "1"
check "claiming an expired task refused" "$(rc wrk claim "$TKP")" "1"
check "refusal names the expiry" "$(grep -c '2020-01-01' "$W/err.txt")" "1"

head_ "unauthenticated events cannot move state"
# Forge an accept from a key nobody registered: valid JSON, invalid authority.
python3 - "$COMMONS_ROOT/registry/ledger" "$TKR" <<'PY'
import glob, hashlib, json, os, sys
d, tid = sys.argv[1], sys.argv[2]
f = sorted(glob.glob(os.path.join(d, "*.jsonl")))[0]
lines = [l for l in open(f).read().splitlines() if l.strip()]
forged = {"action": "accept", "agent": "attacker", "id": tid, "task": tid,
          "sha256": "00"*32, "schema": "rc.v1", "ts": "2026-07-26T00:00:00Z",
          "addr": "0x" + "11"*20, "sig": "0x" + "22"*65,
          "prev": hashlib.sha256(lines[-1].encode()).hexdigest()}
open(f, "a").write(json.dumps(forged, sort_keys=True) + "\n")
PY
check "forged accept does not settle the task" "$(ben status "$TKR" | grep -c 'state      : rejected')" "1"
check "forged entry is flagged by log --verify" "$(rc ben log --verify)" "1"

head_ "settlement: replication by distinct signers (T0/T1)"
# A second independent worker, established up front so it exists before first use.
W2KEY="$LAB/w2.key"
python3 -c "import secrets;open('$W2KEY','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$W2KEY"
wrk2() { COMMONS_SIGNING_KEY="$W2KEY" COMMONS_AGENT=worker2 "$COMMONS" "$@"; }
W2=$(wrk2 peer whoami | head -1)
ben peer add "$W2" --agent-id worker2 --trust full >/dev/null

# max_claims=2 so two independent workers can both run the same deterministic task.
mkwf "$W/wf-q.json" quorum
WFQ=$(ben publish workflow "$W/wf-q.json" "quorum workflow" 2>/dev/null)
mktask "$W/t-quorum.json" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 0}, \"execution\": {\"workflow\": \"$WFQ\"}, \"objective\": \"quorum: total the claimed column\"}"
TKQ=$(ben publish task "$W/t-quorum.json" "Quorum task" 2>/dev/null)
check "settle refuses with nothing submitted" "$(rc ben settle "$TKQ")" "1"

# Both workers derive independently. Worker2 commits to the bytes BEFORE worker1
# publishes them — the only way a second party can prove it derived rather than copied,
# now that content-addressing makes the artifact id shared.
QSALT=aa11bb22cc33dd44
QHASH=$(python3 -c "
import csv, json, hashlib
rows = list(csv.DictReader(open('$W/d.csv')))
out = {'total': sum(int(r['claimed']) for r in rows), 'n': len(rows), 'salt': 'quorum'}
print(hashlib.sha256(json.dumps(out, indent=2, sort_keys=True).encode()).hexdigest())")
wrk2 claim "$TKQ" >/dev/null 2>&1
wrk2 commit-derivation "$TKQ" --result-hash "$QHASH" --salt "$QSALT" >/dev/null 2>&1

wrk claim "$TKQ" >/dev/null 2>&1
wrk run-task "$TKQ" >"$W/out.txt" 2>&1
RQ1=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$TKQ" "$RQ1" >/dev/null 2>&1
check "one derivation is not yet a quorum of two" "$(rc ben settle "$TKQ")" "3"
check "reports how far off it is" "$(grep -c '1/2 independent derivation' "$W/out.txt")" "1"

# The same worker2 identity established above re-derives the same bytes. Same content
# -> same id, so agreement is literally hash equality, not a similarity judgement.
# (Do NOT re-mint the key here: regenerating it mid-suite orphans worker2's earlier
# derivation-commit and looks exactly like a settlement bug.)
wrk2 run-task "$TKQ" >"$W/out.txt" 2>&1
RQ2=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
check "second worker re-derives identical bytes" "$RQ2" "$RQ1"
wrk2 submit "$TKQ" "$RQ2" --salt "$QSALT" >/dev/null 2>&1
check "two independent derivations are settleable" "$(rc ben settle "$TKQ" --dry-run)" "0"
check "dry-run reports the replication" \
  "$(grep -c 'independently derived by 2' "$W/out.txt")" "1"
check "dry-run did not settle" "$(ben status "$TKQ" | grep -c 'state      : submitted')" "1"
check "settle accepts by quorum" "$(rc ben settle "$TKQ")" "0"
check "state now accepted" "$(ben status "$TKQ" | grep -c 'state      : accepted')" "1"
check "ledger records quorum settlement" "$(ben log -n 20 | grep -c '"settlement": "quorum"')" "1"
check "ledger records the signer count" "$(ben log -n 20 | grep -c '"signers": 2')" "1"
check "congruence profile shows agreement" \
  "$(ben status "$TKQ" | grep -c 'congruence : 2 independent derivation(s) agree')" "1"
check "non-beneficiary cannot settle" "$(rc wrk settle "$TKQ" --force)" "1"

head_ "settlement: the same signer twice is not replication"
mkwf "$W/wf-sr.json" selfrep
WFSR=$(ben publish workflow "$W/wf-sr.json" "selfrep workflow" 2>/dev/null)
mktask "$W/t-selfrep.json" "{\"max_claims\": 2, \"execution\": {\"workflow\": \"$WFSR\"}, \"objective\": \"self-replication attempt\"}"
TKS=$(ben publish task "$W/t-selfrep.json" "Self-replication" 2>/dev/null)
wrk claim "$TKS" >/dev/null 2>&1
wrk run-task "$TKS" >"$W/out.txt" 2>&1
RS=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$TKS" "$RS" >/dev/null 2>&1
wrk submit "$TKS" "$RS" --force >/dev/null 2>&1
check "two submissions recorded" "$(ben status "$TKS" | grep -c 'submissions: 2')" "1"
# k defaults to 1 for a task with no diversity_quorum, so this DOES settle — but the
# point is that it counts ONE signer, not two.
check "counts derivations, not submissions" \
  "$(ben status "$TKS" | grep -c 'congruence : 1 independent derivation(s) agree')" "1"

head_ "settlement: divergence is a finding, never a silent drop"
# A deliberately nondeterministic workflow: two honest runs disagree.
cat > "$W/body-div.py" <<'PY'
import json, os, random
json.dump({"x": random.random()}, open(os.environ["OUT_DIR"] + "/r.json", "w"))
PY
python3 - "$W/wf-div.json" "$DS" "$W/body-div.py" <<'PY'
import json, sys
json.dump({"interpreter": "bash", "inputs": {"D": sys.argv[2]},
           "attachments": {"step.py": open(sys.argv[3]).read()},
           "steps": ["python3 step.py"], "outputs": {"r": "r.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60},
          open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WFD=$(ben publish workflow "$W/wf-div.json" "divergent workflow" 2>/dev/null)
mktask "$W/t-div.json" "{\"max_claims\": 2, \"execution\": {\"workflow\": \"$WFD\"}, \"objective\": \"divergence probe\"}"
TKD=$(ben publish task "$W/t-div.json" "Divergence" 2>/dev/null)
wrk claim "$TKD" >/dev/null 2>&1
wrk run-task "$TKD" >"$W/out.txt" 2>&1
RD1=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$TKD" "$RD1" >/dev/null 2>&1
wrk2 claim "$TKD" >/dev/null 2>&1
wrk2 run-task "$TKD" >"$W/out.txt" 2>&1
RD2=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk2 submit "$TKD" "$RD2" >/dev/null 2>&1
check "the two results actually differ" "$([ "$RD1" != "$RD2" ] && echo yes)" "yes"
check "settle refuses to auto-accept divergence" "$(rc ben settle "$TKD")" "1"
check "reported as DIVERGENT" "$(grep -c '^DIVERGENT' "$W/out.txt")" "1"
check "both results are listed, not dropped" \
  "$([ "$(grep -c "$RD1" "$W/out.txt")" -ge 1 ] && [ "$(grep -c "$RD2" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "names it a finding, not a tie" "$(grep -c 'not a tie to break' "$W/out.txt")" "1"
# The detector is ephemeral stdout; the convention doc is where the finding becomes an
# artifact. Without this pointer the two mechanisms live one command apart with no bridge.
check "points at the divergence-report convention" \
  "$(grep -c 'DESIGN-notes-divergence-reports.md' "$W/out.txt")" "1"
check "status shows the divergence" "$(ben status "$TKD" | grep -c 'congruence : DIVERGENT')" "1"
check "status explains what divergence localises" \
  "$(ben status "$TKD" | grep -c 'not deterministic')" "1"
# Machine-tier wording is tier-specific and must NOT leak onto a judged tier. Capture
# it BEFORE the manual accept below — once settled, `settle` short-circuits on the
# already-accepted guard and never reaches the divergence branch again.
MACHINE_OUT="$W/div-t0.txt"
rc ben settle "$TKD" >/dev/null 2>&1; cp "$W/out.txt" "$MACHINE_OUT"
check "T0 divergence says machine tier" \
  "$(grep -c 'machine-verifiable tier producing different answers' "$MACHINE_OUT")" "1"
check "T0 divergence does not mention reviewers" \
  "$(grep -c 'reviewers reached different judgements' "$MACHINE_OUT")" "0"
check "T0 status wording is the determinism one" \
  "$(ben status "$TKD" | grep -c 'not deterministic')" "1"
check "beneficiary can still settle by hand" "$(rc ben accept "$TKD" "$RD1")" "0"

head_ "settlement: divergence wording is tier-guarded (T2 is not a determinism bug)"
# Same detector, different meaning. A judged tier never promised identical bytes, so
# telling the operator to debug determinism sends them after a property the task did
# not assert. Needs a diversity_quorum or the "judged work is not counted" guard
# short-circuits before the divergence branch is ever reached.
cat > "$W/body-jdiv.py" <<'PY'
import json, os, random
json.dump({"judgement": random.random()}, open(os.environ["OUT_DIR"] + "/r.json", "w"))
PY
python3 - "$W/wf-jdiv.json" "$DS" "$W/body-jdiv.py" <<'PY'
import json, sys
json.dump({"interpreter": "bash", "inputs": {"D": sys.argv[2]},
           "attachments": {"step.py": open(sys.argv[3]).read()},
           "steps": ["python3 step.py"], "outputs": {"r": "r.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60},
          open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
# A third identity on purpose: the peer-stats section below asserts worker2's
# reference and derivation columns differ, so adding another worker2 derivation here
# would couple an unrelated assertion to this one.
W3KEY="$LAB/w3.key"
python3 -c "import secrets;open('$W3KEY','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$W3KEY"
wrk3() { COMMONS_SIGNING_KEY="$W3KEY" COMMONS_AGENT=worker3 "$COMMONS" "$@"; }
W3=$(wrk3 peer whoami | head -1)
ben peer add "$W3" --agent-id worker3 --trust full >/dev/null
WFJD=$(ben publish workflow "$W/wf-jdiv.json" "judged divergent workflow" 2>/dev/null)
# Prose-only T2 (no criteria_list): the quorum is k=1 because k>1 without an enumerated
# rubric is now refused at lint (2026-09-15) — it had no reachable success state. Two
# distinct prose results still trip the same DIVERGENT detector; that is what this probes.
mktask "$W/t-jdiv.json" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 1, \"distinct_families\": 0}, \"verification\": {\"tier\": \"T2\", \"criteria\": \"Every claim cites an artifact id\"}, \"execution\": {\"workflow\": \"$WFJD\"}, \"objective\": \"judged divergence probe\"}"
TKJD=$(ben publish task "$W/t-jdiv.json" "Judged divergence" 2>/dev/null)
wrk claim "$TKJD" >/dev/null 2>&1
wrk run-task "$TKJD" >"$W/out.txt" 2>&1
RJ1=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$TKJD" "$RJ1" >/dev/null 2>&1
wrk3 claim "$TKJD" >/dev/null 2>&1
wrk3 run-task "$TKJD" >"$W/out.txt" 2>&1
RJ2=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk3 submit "$TKJD" "$RJ2" >/dev/null 2>&1
check "the two judged results actually differ" "$([ "$RJ1" != "$RJ2" ] && echo yes)" "yes"
# The exit code is the contract; only the advisory prose is allowed to move.
check "T2 divergence exits exactly as T0 does" "$(rc ben settle "$TKJD")" "1"
JUDGED_OUT="$W/div-t2.txt"; cp "$W/out.txt" "$JUDGED_OUT"
check "still reported as DIVERGENT at T2" "$(grep -c '^DIVERGENT' "$JUDGED_OUT")" "1"
check "T2 wording names differing reviewer judgement" \
  "$(grep -c 'reviewers reached different judgements' "$JUDGED_OUT")" "1"
check "T2 does NOT tell the operator to debug determinism" \
  "$(grep -ci 'machine-verifiable tier producing different answers' "$JUDGED_OUT")" "0"
check "T2 wording differs from T0 wording" \
  "$(cmp -s "$MACHINE_OUT" "$JUDGED_OUT" && echo same || echo differ)" "differ"
check "T2 still points at the divergence-report convention" \
  "$(grep -c 'DESIGN-notes-divergence-reports.md' "$JUDGED_OUT")" "1"
check "T2 still lists both results, not dropped" \
  "$([ "$(grep -c "$RJ1" "$JUDGED_OUT")" -ge 1 ] && [ "$(grep -c "$RJ2" "$JUDGED_OUT")" -ge 1 ] && echo yes)" "yes"
check "T2 status shows the divergence" \
  "$(ben status "$TKJD" | grep -c 'congruence : DIVERGENT')" "1"
check "T2 status says judgement, not nondeterminism" \
  "$(ben status "$TKJD" | grep -c 'differing reviewer judgement')" "1"
check "T2 status omits the determinism line" \
  "$(ben status "$TKJD" | grep -c 'locates where the pipeline is not deterministic')" "0"
check "T2 status exit code unchanged" "$(rc ben status "$TKJD")" "3"
check "beneficiary can still settle the judged divergence by hand" \
  "$(rc ben accept "$TKJD" "$RJ1")" "0"

head_ "settlement: judged work is reviewed, not counted"
wrk claim "$T2TASK" >/dev/null 2>&1
# Needs a submission present, or the "nothing submitted" guard short-circuits first.
wrk run-task "$TK" >"$W/out.txt" 2>&1 || true
T2RES=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$T2TASK" "$T2RES" --force >/dev/null 2>&1
check "T2 without a quorum refuses auto-settle" "$(rc ben settle "$T2TASK")" "1"
check "refusal says judged work needs review" \
  "$(cat "$W/out.txt" "$W/err.txt" | grep -c 'accepted by review, not by counting')" "1"
check "and points at the manual path" \
  "$(cat "$W/out.txt" "$W/err.txt" | grep -c 'commons accept')" "1"

head_ "diversity quorum: self-reported family claims do not count"
mkwf "$W/wf-dq.json" divquorum
WFDQ=$(ben publish workflow "$W/wf-dq.json" "diversity workflow" 2>/dev/null)
mktask "$W/t-dq.json" "{\"max_claims\": 3, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 2}, \"execution\": {\"workflow\": \"$WFDQ\"}, \"objective\": \"cross-family replication\"}"
TKF=$(ben publish task "$W/t-dq.json" "Diversity quorum" 2>/dev/null)
wrk claim "$TKF" >/dev/null 2>&1
wrk run-task "$TKF" >"$W/out.txt" 2>&1
RF=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
# Self-reported family: advisory only, must NOT satisfy the quorum.
set_generation "$WKEY" "$RF" \
  '{"model":"some-model","model_family":"vendor-a/model","attestation":"self-reported"}'
wrk submit "$TKF" "$RF" >/dev/null 2>&1
check "self-reported family shown as advisory" \
  "$([ "$(ben status "$TKF" | grep -c 'advisory')" -ge 1 ] && echo yes)" "yes"
check "self-reported family does not satisfy the quorum" "$(rc ben settle "$TKF")" "3"
check "refusal explains attestation is required" \
  "$(grep -c 'needs attestation receipt|tee' "$W/out.txt")" "1"
check "refusal names the re-monetization risk" \
  "$(grep -c 're-monetizes the model claim' "$W/out.txt")" "1"
# Promote to an attested claim: now it counts.
set_generation "$WKEY" "$RF" \
  '{"model":"some-model","model_family":"vendor-a/model","attestation":"receipt"}'
check "attested family is counted" "$(ben status "$TKF" | grep -c 'families vendor-a/model')" "1"
check "quorum line reports progress" "$(ben status "$TKF" | grep -c 'quorum     : need k=2')" "1"
check "still short of 2 families" "$(rc ben settle "$TKF")" "3"

head_ "independence: a copy is not a derivation"
# The vector: submitting an artifact id proves nothing about having produced it. Without
# derivation-aware accounting, one derivation cited twice reads as k-way replication.
mkwf "$W/wf-copy.json" copyvector
WFC=$(ben publish workflow "$W/wf-copy.json" "copy-vector workflow" 2>/dev/null)
mktask "$W/t-copy.json" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 0}, \"execution\": {\"workflow\": \"$WFC\"}, \"objective\": \"copy-submission probe\"}"
TKC=$(ben publish task "$W/t-copy.json" "Copy probe" 2>/dev/null)

wrk claim "$TKC" >/dev/null 2>&1
wrk run-task "$TKC" >"$W/out.txt" 2>&1
RC1=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$TKC" "$RC1" >/dev/null 2>&1
check "original submitter counts as a derivation" \
  "$(ben status "$TKC" | grep -c '1 independent derivation(s) agree')" "1"

# worker2 submits the SAME id having done no work at all.
wrk2 claim "$TKC" >/dev/null 2>&1
check "copy-submission is accepted as a submission" "$(rc wrk2 submit "$TKC" "$RC1")" "0"
check "submitter is told it is a concurring reference" \
  "$(grep -c 'CONCURRING REFERENCE' "$W/out.txt")" "1"
check "told how to count next time" "$(grep -c 'commit-derivation' "$W/out.txt")" "1"
check "two submissions recorded" \
  "$([ "$(ben status "$TKC" | grep -cE 'submissions *: *2')" -ge 1 ] && echo yes)" "yes"
check "🔒 copy carries NO quorum weight" \
  "$(ben status "$TKC" | grep -c '1 independent derivation(s) agree')" "1"
check "copy reported as an uncounted reference" \
  "$([ "$(ben status "$TKC" | grep -c 'concurring reference')" -ge 1 ] && echo yes)" "yes"
check "🔒 k=2 quorum NOT satisfied by a copy" "$(rc ben settle "$TKC")" "3"
check "settle says how many real derivations it has" \
  "$(grep -c '1/2 independent derivation' "$W/out.txt")" "1"
check "settle names the copies explicitly" \
  "$(grep -c 'concurring references' "$W/out.txt")" "1"

head_ "independence: commit-reveal earns quorum weight"
mkwf "$W/wf-cr.json" commitreveal
WFCR=$(ben publish workflow "$W/wf-cr.json" "commit-reveal workflow" 2>/dev/null)
mktask "$W/t-cr.json" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 0}, \"execution\": {\"workflow\": \"$WFCR\"}, \"objective\": \"commit-reveal probe\"}"
TKR2=$(ben publish task "$W/t-cr.json" "Commit-reveal" 2>/dev/null)

# worker2 derives FIRST, privately, and commits to the bytes before publishing.
wrk2 claim "$TKR2" >/dev/null 2>&1
wrk2 run-task "$TKR2" -o "$W" >/dev/null 2>&1 || true
# Derive the result content independently to get its hash without publishing it.
SALT=deadbeefcafe1234
PRE=$(wrk2 commit-derivation "$TKR2" --result-hash "$(python3 -c "
import csv, json, os, hashlib
rows = list(csv.DictReader(open('$W/d.csv')))
out = {'total': sum(int(r['claimed']) for r in rows), 'n': len(rows), 'salt': 'commitreveal'}
print(hashlib.sha256((json.dumps(out, indent=2, sort_keys=True)).encode()).hexdigest())")" --salt "$SALT" 2>&1)
check "commit recorded" "$(echo "$PRE" | grep -c 'committed to a derivation')" "1"
check "commit is a signed ledger event" "$(ben log -n 5 | grep -c 'derivation-commit')" "1"

# Now the ORIGINAL worker publishes it first.
wrk claim "$TKR2" >/dev/null 2>&1
wrk run-task "$TKR2" >"$W/out.txt" 2>&1
RCR=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$TKR2" "$RCR" >/dev/null 2>&1
# worker2 reveals its pre-publication commitment: it knew the bytes before they existed
# publicly, so this is an independent derivation, not a copy.
check "commit-reveal submission accepted" \
  "$(rc wrk2 submit "$TKR2" "$RCR" --salt "$SALT" --force)" "0"
check "🔒 commit-reveal counts as independent derivation" \
  "$(grep -c 'counts as: independent derivation' "$W/out.txt")" "1"
check "quorum now satisfied by two real derivations" "$(rc ben settle "$TKR2" --dry-run)" "0"
check "settle reports two derivations" \
  "$(grep -c 'independently derived by 2' "$W/out.txt")" "1"

head_ "independence: a commit posted too late proves nothing"
mkwf "$W/wf-late.json" latecommit
WFL=$(ben publish workflow "$W/wf-late.json" "late-commit workflow" 2>/dev/null)
mktask "$W/t-late.json" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 0}, \"execution\": {\"workflow\": \"$WFL\"}, \"objective\": \"late commit probe\"}"
TKL=$(ben publish task "$W/t-late.json" "Late commit" 2>/dev/null)
wrk claim "$TKL" >/dev/null 2>&1
wrk run-task "$TKL" >"$W/out.txt" 2>&1
RL=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$TKL" "$RL" >/dev/null 2>&1
# worker2 commits AFTER the result is already public — committing to bytes you can read
# is free, so this must not count.
LSALT=feedface00112233
RLHASH=$(ben get "$RL" | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])')
wrk2 commit-derivation "$TKL" --result-hash "$RLHASH" --salt "$LSALT" >/dev/null 2>&1
wrk2 claim "$TKL" >/dev/null 2>&1
rc wrk2 submit "$TKL" "$RL" --salt "$LSALT" --force
check "🔒 late commit is still a reference" \
  "$(grep -c 'CONCURRING REFERENCE' "$W/out.txt")" "1"
check "reason names the ordering problem" \
  "$(grep -c 'commit posted after' "$W/out.txt")" "1"
check "quorum not satisfied by a late commit" "$(rc ben settle "$TKL")" "3"

head_ "independence: an UNSIGNED publish can't be ordered against (fail closed)"
# Regression: the ordering checks used to run only when a VERIFIED SIGNED first
# publisher existed. An artifact whose only publish was unsigned (legacy, or written
# with no key) had none, so a commit posted after it was public graded as
# commit-reveal and earned quorum weight. An unsigned publish's timestamp is nobody's
# signed word (and unsigned lines can arrive from a peer), so it can neither grant nor
# be trusted to deny priority: any commit against such an artifact is a reference.
anon() { env -u COMMONS_SIGNING_KEY COMMONS_AGENT=legacy "$COMMONS" "$@"; }
mktask "$W/t-unsig.json" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 0}, \"objective\": \"unsigned-publish ordering probe\"}"
TKU=$(ben publish task "$W/t-unsig.json" "Unsigned ordering" 2>/dev/null)
echo '{"unsigned": "already public"}' > "$W/r-unsig.json"
RU=$(anon publish synthesis "$W/r-unsig.json" "public, unsigned publish" 2>/dev/null | grep -oE 'sy-[0-9a-f]{8}' | head -1)
check "unsigned publish written" "$(grep -c "\"id\": \"$RU\"" "$COMMONS_ROOT/registry/ledger/local-unsigned.jsonl")" "1"
RUHASH=$(sha256sum "$W/r-unsig.json" | cut -d' ' -f1)
sleep 1   # second-resolution timestamps: the commit is strictly later
wrk2 commit-derivation "$TKU" --result-hash "$RUHASH" --salt "0a1b2c3d4e5f" >/dev/null 2>&1
wrk2 claim "$TKU" >/dev/null 2>&1
rc wrk2 submit "$TKU" "$RU" --salt "0a1b2c3d4e5f" --force >/dev/null
check "🔒 late commit vs unsigned publish is a reference" \
  "$(grep -c 'CONCURRING REFERENCE' "$W/out.txt")" "1"
check "reason names the unsigned publish" "$(grep -c 'has an unsigned publish event' "$W/out.txt")" "1"
check "status agrees: the submission is an uncounted reference" \
  "$(ben status "$TKU" | grep -ic "$W2.*concurring reference (no quorum weight)")" "1"
check "🔒 quorum not satisfied" "$(rc ben settle "$TKU")" "3"

# An unsigned-only artifact cannot be adopted through a keyed republish.
sleep 1
ADOPT_RC=$(rc ben publish synthesis "$W/r-unsig.json" "signed republish" --force)
rc wrk2 submit "$TKU" "$RU" --salt "0a1b2c3d4e5f" --force >/dev/null
check "🔒 unsigned-only adoption refuses and the submission remains a reference" \
  "$ADOPT_RC:$(grep -c 'CONCURRING REFERENCE' "$W/out.txt")" "1:1"

# A commit that truly precedes an unsigned publish also can't be credited: the
# publish time is unprovable, so ordering is unprovable. Fail closed costs credit
# here, by design; the fix for the publisher is to sign.
mktask "$W/t-unsig2.json" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 0}, \"objective\": \"unsigned-publish, commit first\"}"
TKU2=$(ben publish task "$W/t-unsig2.json" "Unsigned, commit first" 2>/dev/null)
echo '{"unsigned": "committed first"}' > "$W/r-unsig2.json"
RU2HASH=$(sha256sum "$W/r-unsig2.json" | cut -d' ' -f1)
wrk2 commit-derivation "$TKU2" --result-hash "$RU2HASH" --salt "f0e1d2c3b4a5" >/dev/null 2>&1
sleep 1
RU2=$(anon publish synthesis "$W/r-unsig2.json" "unsigned, published after the commit" 2>/dev/null | grep -oE 'sy-[0-9a-f]{8}' | head -1)
wrk2 claim "$TKU2" >/dev/null 2>&1
rc wrk2 submit "$TKU2" "$RU2" --salt "f0e1d2c3b4a5" --force >/dev/null
check "🔒 commit before an unsigned publish is still unprovable" \
  "$(grep -c 'CONCURRING REFERENCE' "$W/out.txt")" "1"

# Control: the same sequence against a SIGNED publish still earns commit-reveal, so
# the fix closes the gap without making commit-reveal impossible.
mktask "$W/t-sig.json" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 0}, \"objective\": \"signed control\"}"
TKS=$(ben publish task "$W/t-sig.json" "Signed control" 2>/dev/null)
echo '{"signed": "committed first"}' > "$W/r-sig.json"
RSHASH=$(sha256sum "$W/r-sig.json" | cut -d' ' -f1)
wrk2 commit-derivation "$TKS" --result-hash "$RSHASH" --salt "5a5a5a5a5a5a" >/dev/null 2>&1
sleep 1
RS=$(ben publish synthesis "$W/r-sig.json" "signed, published after the commit" 2>/dev/null | grep -oE 'sy-[0-9a-f]{8}' | head -1)
wrk2 claim "$TKS" >/dev/null 2>&1
rc wrk2 submit "$TKS" "$RS" --salt "5a5a5a5a5a5a" --force >/dev/null
check "control: commit before a signed publish is commit-reveal" \
  "$(grep -c 'counts as: independent derivation (committed before publication' "$W/out.txt")" "1"

# No publish event anywhere (a hand-copied manifest): nothing to order against.
mktask "$W/t-nopub.json" "{\"max_claims\": 2, \"objective\": \"no-publish probe\"}"
TKN=$(ben publish task "$W/t-nopub.json" "No publish event" 2>/dev/null)
echo '{"unsigned": "no ledger event"}' > "$W/r-nopub.json"
RNHASH=$(sha256sum "$W/r-nopub.json" | cut -d' ' -f1)
wrk2 commit-derivation "$TKN" --result-hash "$RNHASH" --salt "aa55aa55aa55" >/dev/null 2>&1
RN=$(anon publish synthesis "$W/r-nopub.json" "manifest only" 2>/dev/null | grep -oE 'sy-[0-9a-f]{8}' | head -1)
python3 - "$COMMONS_ROOT/registry/ledger/local-unsigned.jsonl" "$RN" <<'PY2'
import json, sys
p, rid = sys.argv[1], sys.argv[2]
keep = [l for l in open(p) if json.loads(l).get("id") != rid]
open(p, "w").writelines(keep)
PY2
check "publish event removed (fixture)" \
  "$(grep -c "\"id\": \"$RN\"" "$COMMONS_ROOT/registry/ledger/local-unsigned.jsonl")" "0"
wrk2 claim "$TKN" >/dev/null 2>&1
rc wrk2 submit "$TKN" "$RN" --salt "aa55aa55aa55" --force >/dev/null
check "🔒 no publish event: commit cannot be ordered, so a reference" \
  "$(grep -c 'CONCURRING REFERENCE' "$W/out.txt")" "1"
check "reason names the missing publish event" \
  "$(grep -c 'no publish event for' "$W/out.txt")" "1"

head_ "independence: a wrong salt proves nothing"
mkwf "$W/wf-badsalt.json" badsalt
WFB2=$(ben publish workflow "$W/wf-badsalt.json" "bad-salt workflow" 2>/dev/null)
mktask "$W/t-badsalt.json" "{\"max_claims\": 2, \"execution\": {\"workflow\": \"$WFB2\"}, \"objective\": \"bad salt probe\"}"
TKB=$(ben publish task "$W/t-badsalt.json" "Bad salt" 2>/dev/null)
wrk claim "$TKB" >/dev/null 2>&1
wrk run-task "$TKB" >"$W/out.txt" 2>&1
RB=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
wrk submit "$TKB" "$RB" >/dev/null 2>&1
wrk2 claim "$TKB" >/dev/null 2>&1
rc wrk2 submit "$TKB" "$RB" --salt "0000notarealsalt0000" --force
check "unmatched salt is a reference" "$(grep -c 'CONCURRING REFERENCE' "$W/out.txt")" "1"
check "reason names the missing commitment" \
  "$(grep -c 'matches no prior commitment' "$W/out.txt")" "1"

head_ "independence: copied family claims cannot fake cross-family replication"
mkwf "$W/wf-fam.json" famfake
WFF=$(ben publish workflow "$W/wf-fam.json" "family-fake workflow" 2>/dev/null)
mktask "$W/t-fam.json" "{\"max_claims\": 3, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 2}, \"execution\": {\"workflow\": \"$WFF\"}, \"objective\": \"cross-family fake probe\"}"
TKFF=$(ben publish task "$W/t-fam.json" "Family fake" 2>/dev/null)
wrk claim "$TKFF" >/dev/null 2>&1
wrk run-task "$TKFF" >"$W/out.txt" 2>&1
RFF=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
# Attested family on the original.
set_generation "$WKEY" "$RFF" \
  '{"model":"m-a","model_family":"vendor-a/model","attestation":"receipt"}'
wrk submit "$TKFF" "$RFF" >/dev/null 2>&1
# worker2 copies the id. Even if the manifest claimed a second family, a copy is one
# derivation — so distinct_families=2 must remain unsatisfied.
wrk2 claim "$TKFF" >/dev/null 2>&1
wrk2 submit "$TKFF" "$RFF" --force >/dev/null 2>&1
check "🔒 copy cannot manufacture a second family" "$(rc ben settle "$TKFF")" "3"
check "quorum line counts derivations, not submissions" \
  "$(ben status "$TKFF" | grep -c 'independent derivations across 2 attested')" "1"

head_ "status/settle parity: attested-family count must use the SAME predicate"
# Regression for a real divergence: cmd_settle counts a family toward the diversity
# quorum only when derived_attested>0 (an ATTESTED submission that is also an
# independent DERIVATION), but cmd_status's quorum line used to count any family
# with attested>0 regardless of derivation kind. A fourth party (the beneficiary, so
# no extra claim slot is spent) publishes an attested result; two judges each submit
# that SAME id as a copy (no derivation-commit, no salt) — neither is an origin or a
# commit-reveal, so settle correctly counts 0 attested families while the unpatched
# status line, driven by the looser predicate, reported 1. Same displayed quantity,
# two answers at the same instant — settle is authoritative.
mkwf "$W/wf-parity.json" statusparity
WFP=$(ben publish workflow "$W/wf-parity.json" "parity workflow" 2>/dev/null)
mktask "$W/t-parity.json" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 2}, \"execution\": {\"workflow\": \"$WFP\"}, \"objective\": \"status/settle parity probe\"}"
TKP=$(ben publish task "$W/t-parity.json" "Status parity" 2>/dev/null)
# The beneficiary (ben) is the fourth party: publishes the result directly, holding no
# claim slot, so both real claim slots stay free for the two copying judges below.
ben run-task "$TKP" >"$W/out.txt" 2>&1
RP=$(grep -oE '(sy|ds)-[0-9a-f]{8}' "$W/out.txt" | head -1)
set_generation "$BKEY" "$RP" \
  '{"model":"m-a","model_family":"vendor-a/model","attestation":"receipt"}'
# Both judges submit the SAME id as a plain copy — neither derived it.
wrk claim "$TKP" >/dev/null 2>&1
wrk submit "$TKP" "$RP" --force >/dev/null 2>&1
wrk2 claim "$TKP" >/dev/null 2>&1
wrk2 submit "$TKP" "$RP" --force >/dev/null 2>&1
check "copies confirmed uncounted (0 derivers)" \
  "$(ben status "$TKP" | grep -c '0 independent derivation(s) agree')" "1"
check "settle refuses: 0 attested families (correct predicate)" \
  "$(rc ben settle "$TKP")" "3"
check "settle names 0 attested families explicitly" \
  "$(grep -c '0/2 attested families' "$W/out.txt")" "1"
check "🔒 status agrees with settle: 0 attested families, not 1" \
  "$(ben status "$TKP" | grep -c 'attested famil.* — have 0 / 0')" "1"
check "status never reports the stale 1-attested-family reading" \
  "$(ben status "$TKP" | grep -c ' — have 0 / 1')" "0"

head_ "peer stats: credit follows events, not artifacts"
check "stats runs" "$(rc ben peer stats)" "0"
check "derivations and references are separate columns" \
  "$(grep -cE 'deriv.*ref' "$W/out.txt")" "1"
statcol() {  # statcol <addr> <deriv|ref>
  ben peer stats "$1" | awk -v want="$2" '
    NR==1 { for (i=1;i<=NF;i++) col[$i]=i; next }
    NR==2 { print $(col[want]) }'
}
# worker2 legitimately derives elsewhere in this suite (commit-reveal), so the claim
# under test is that copies land in the reference column — not that this peer never
# derives. Conflating the two would make the assertion depend on suite ordering.
check "copies accrue references" "$([ "$(statcol "$W2" ref)" -gt 0 ] && echo yes)" "yes"
check "references are counted separately from derivations" \
  "$([ "$(statcol "$W2" ref)" -ne "$(statcol "$W2" deriv)" ] && echo yes)" "yes"
check "the deriver accrued derivations" \
  "$([ "$(statcol "$WRK" deriv)" -gt 0 ] && echo yes)" "yes"
check "stats states that it counts signed events only" \
  "$(ben peer stats | grep -c 'signed ledger events')" "1"
check "unknown address is refused" "$(rc ben peer stats 0x0000000000000000000000000000000000000009)" "1"

head_ "observation captures: T3 results on a judged task (2026-09-25 interim pattern)"
# Design note 2026-09-25 observation tasks §2: a T2 task with a prose conformance rubric,
# contributors submit attested T3 captures. Captures of a live system are EXPECTED to
# differ, so status must not call them DIVERGENT, and submit must not demand a
# `generation` block that only describes model-produced work. Display only: the exit
# codes below are the same ones any T2 task produces.
mktask "$W/t-obs.json" '{"max_claims": 2, "inputs": [], "verification": {"tier": "T2", "criteria": "Capture follows protocol P: schema v1, n>=4 slots, observed inside the task window, attested"}, "execution": {"brief": "run protocol P on your node; publish + attest the capture; submit it"}, "objective": "observation capture probe"}'
TKO=$(ben publish task "$W/t-obs.json" "Observation captures" 2>/dev/null)
check "T3 task itself is still refused" \
  "$(python3 -c "import json;s=json.load(open('$W/t-obs.json'));s['verification']['tier']='T3';json.dump(s,open('$W/t-obs3.json','w'))"; rc ben publish task "$W/t-obs3.json" x)" "1"
printf 'slot,usd_per_h\n1,0.146\n2,0.065\n3,0.034\n4,0.096\n' > "$W/cap1.csv"
printf 'slot,usd_per_h\n1,0.146\n2,0.140\n3,0.006\n4,0.090\n' > "$W/cap2.csv"
CAP1=$(wrk publish dataset "$W/cap1.csv" "capture 1" --license CC0-1.0 --obtainability open --criteria "protocol P, node 1" 2>/dev/null)
CAP2=$(wrk3 publish dataset "$W/cap2.csv" "capture 2" --license CC0-1.0 --obtainability open --criteria "protocol P, node 2" 2>/dev/null)
wrk attest "$CAP1" --observed 2026-09-24T12:00:00Z >/dev/null 2>&1
wrk3 attest "$CAP2" --observed 2026-09-24T13:00:00Z >/dev/null 2>&1
check "captures are T3" "$(ben list --type dataset | grep -E "^($CAP1|$CAP2) " | grep -c ' T3 ')" "2"
wrk claim "$TKO" >/dev/null 2>&1
check "T3 capture submits to a T2 task" "$(rc wrk submit "$TKO" "$CAP1")" "0"
check "no generation warning for a T3 capture" "$(grep -c 'no `generation` block' "$W/err.txt")" "0"
check "submit says review is protocol conformance" "$(grep -c 'followed the task.s protocol' "$W/err.txt")" "1"
wrk3 claim "$TKO" >/dev/null 2>&1
wrk3 submit "$TKO" "$CAP2" >/dev/null 2>&1
ben status "$TKO" >"$W/obs-status.txt" 2>&1; OBS_RC=$?
check "status: no DIVERGENT for all-T3 submissions" "$(grep -c 'DIVERGENT' "$W/obs-status.txt")" "0"
check "status: no congruence line at all" "$(grep -c 'congruence :' "$W/obs-status.txt")" "0"
check "status: reports captures and distinct signers" \
  "$(grep -c 'observations: 2 T3 capture(s) from 2 distinct signer(s)' "$W/obs-status.txt")" "1"
check "status: says acceptance is conformance, not truth" \
  "$(grep -c 'followed the protocol, not that it is true' "$W/obs-status.txt")" "1"
check "status: both captures still listed" \
  "$(grep -cE "^    ($CAP1|$CAP2) by .*\[T3\]" "$W/obs-status.txt")" "2"
check "status exit code unchanged (unsettled = 3)" "$OBS_RC" "3"
check "settle still refuses judged work (exit unchanged)" "$(rc ben settle "$TKO")" "1"
check "accept still works" "$(rc ben accept "$TKO" "$CAP1")" "0"
# Mixed submissions keep the congruence profile: suppression needs EVERY result to be T3.
mktask "$W/t-mix.json" '{"max_claims": 2, "inputs": [], "verification": {"tier": "T2", "criteria": "Capture follows protocol P"}, "execution": {"brief": "capture"}, "objective": "mixed submission probe"}'
TKM=$(ben publish task "$W/t-mix.json" "Mixed" 2>/dev/null)
printf 'a judged prose note\n' > "$W/mix-note.md"
MIXR=$(wrk3 publish report "$W/mix-note.md" "judged note" --tier T2 --criteria "prose review" 2>/dev/null)
wrk claim "$TKM" >/dev/null 2>&1; wrk submit "$TKM" "$CAP1" >/dev/null 2>&1
wrk3 claim "$TKM" >/dev/null 2>&1
wrk3 submit "$TKM" "$MIXR" >"$W/mix-out.txt" 2>"$W/mix-err.txt"
check "non-T3 result still gets the generation warning" \
  "$(grep -c 'no `generation` block' "$W/mix-err.txt")" "1"
check "mixed submissions: congruence still reported" \
  "$(ben status "$TKM" | grep -c 'congruence : DIVERGENT')" "1"
check "mixed submissions: no observations line" \
  "$(ben status "$TKM" | grep -c 'observations:')" "0"

head_ "housekeeping"
check "fsck clean" "$(rc ben fsck)" "0"
check "reindex clean" "$(rc ben reindex)" "0"
check "task type searchable" \
  "$([ "$(ben list --type task | grep -c '^tk-')" -ge 6 ] && echo yes)" "yes"

printf '\n\033[1mtest-exchange: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
