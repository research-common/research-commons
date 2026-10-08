#!/usr/bin/env bash
# Ledger events bind what they mean (#45, #46, #48, #49, #14).
#
# What this pins:
#   1. #49  every new event is dual-signed: `sig` over the v1 fields (so tools that
#           predate `sig2` still verify it) and `sig2` over the whole entry; a changed
#           field breaks `sig2`, and a broken `sig2` is a forgery
#   2. #45  a relayed accept whose unsigned `task` was changed settles nothing: not the
#           task it now names, and (as a copy we don't hold) not the original either
#   3. #45  a submit whose `result` was changed (sig2 stripped) is dropped from the
#           fold, so a plain `accept` cannot settle on the substituted result
#   3b. #45 a v1 submit naming an id with no held manifest is not a submission; a v1
#           accept is judged against every submission, whatever the ts order
#   4. #46  a backdated foreign `republish` never becomes the first publisher, so a
#           submit of someone else's artifact counts as a reference
#   5. #46  `publish --force` of a legacy unsigned-only artifact refuses adoption
#           without minting publisher authority (recovery is deferred to #58)
#   6. #48  `pull` refuses a line signed by one key inside another key's log
#   7. #14  KNOWN GAP (pinned): `pull` accepts new incoming lines in the unsigned logs,
#           with a warning and a quarantine record (a bootstrap pull from a hub with
#           legacy unsigned history needs them; #14 stays open)
#   8. #48  `pull` from an unrelated history refuses tags only the incoming copy has
set -uo pipefail

unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"

PASS=0 FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

LAB="$(mktemp -d -t commons-test-ledger-binding-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
W="$LAB/work"; mkdir -p "$W"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
KL="$LAB/lead.key"; KC="$LAB/contrib.key"
for k in "$KL" "$KC"; do
  python3 -c "import secrets;print('0x'+secrets.token_hex(32))" > "$k"; chmod 600 "$k"
done
HL="$LAB/hub-lead"; HC="$LAB/hub-contrib"; BARE="$LAB/hub.git"

L()  { ( cd "$HL" && COMMONS_ROOT="$HL" COMMONS_AGENT=lead    COMMONS_SIGNING_KEY="$KL" "$COMMONS" "$@" ); }
C()  { ( cd "$HC" && COMMONS_ROOT="$HC" COMMONS_AGENT=contrib COMMONS_SIGNING_KEY="$KC" "$COMMONS" "$@" ); }
LC() { ( cd "$HC" && COMMONS_ROOT="$HC" COMMONS_AGENT=lead    COMMONS_SIGNING_KEY="$KL" "$COMMONS" "$@" ); }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
both() { cat "$W/out.txt" "$W/err.txt"; }
py() { ( cd "$1" && COMMONS_ROOT="$1" python3 - "$COMMONS" "${@:2}" ); }

branch() { ( cd "$HC" && git fetch -q origin && git checkout -q main && git reset -q --hard origin/main \
             && git checkout -q -B "$1" ); }
cpush()  { ( cd "$HC" && git add -A registry store && git commit -qm "$1" \
             && git push -q -f origin "HEAD:$(git rev-parse --abbrev-ref HEAD)" ); }
lpull()  { rc L pull origin --branch "$1" "${@:2}"; }
lreset() { ( cd "$HL" && git reset -q --hard "$1" ); }
hcheck() { ( cd "$HC" && COMMONS_ROOT="$HC" "$COMMONS" hub check --base origin/main ) \
             >"$W/out.txt" 2>&1; echo $?; }
# append a signed event under key $1 into root $2's ledger: <key> <root> <agent> <action> <id> <ts>
append_signed() {
  ( cd "$2" && COMMONS_ROOT="$2" COMMONS_SIGNING_KEY="$1" python3 - "$COMMONS" "$3" "$4" "$5" "$6" "$2" <<'PY'
import json, pathlib, runpy, sys
commons, agent, action, aid, ts, root = sys.argv[1:]
ns = runpy.run_path(commons)
m = json.loads((pathlib.Path(root) / "registry/artifacts" / (aid + ".json")).read_text())
e = {"agent": agent, "action": action, "id": aid, "sha256": m["content"]["sha256"],
     "schema": ns["SCHEMA"], "ts": ts}
addr, sig, sig2 = ns["sign_entry"](e, dual=True)
e["addr"], e["sig"], e["sig2"] = addr, sig, sig2
ns["ledger_commit"](e)
PY
  ); }

"$COMMONS" hub init "$HL" --name ledger-binding >/dev/null 2>&1
ADDR_L=$(L peer whoami 2>/dev/null | head -1)
ADDR_C=$( (cd "$HL" && COMMONS_ROOT="$HL" COMMONS_SIGNING_KEY="$KC" "$COMMONS" peer whoami) 2>/dev/null | head -1)
ADDR_Ll=$(echo "$ADDR_L" | tr 'A-Z' 'a-z'); ADDR_Cl=$(echo "$ADDR_C" | tr 'A-Z' 'a-z')
if [ -z "$ADDR_L" ] || [ -z "$ADDR_C" ]; then
  echo "cannot derive signing addresses (is node + viem available?)"; exit 1
fi
L peer add "$ADDR_L" --agent-id lead    --trust full >/dev/null 2>&1
L peer add "$ADDR_C" --agent-id contrib --trust full >/dev/null 2>&1

mktask() {  # mktask <outfile> <objective>
  python3 - "$1" "$ADDR_L" "$2" <<'PY'
import json, sys
json.dump({"objective": sys.argv[3], "priority": 2, "expires": "2099-01-01T00:00:00Z",
           "max_claims": 2, "execution": {"brief": "b"},
           "verification": {"tier": "T2", "criteria": "every row checked by hand"},
           "beneficiary": {"agent": "lead", "addr": sys.argv[2]}}, open(sys.argv[1], "w"))
PY
}
printf 'x\n1\n' > "$W/a.csv"; printf 'y\n2\n' > "$W/b.csv"; printf 'z\n3\n' > "$W/c.csv"
DS=$(L publish dataset "$W/a.csv" "lead data" --license CC0-1.0 --obtainability open 2>/dev/null | tail -1)
mktask "$W/t1.json" "first task"; mktask "$W/t2.json" "second task"
TK1=$(L publish task "$W/t1.json" "t1" 2>/dev/null | tail -1)
TK2=$(L publish task "$W/t2.json" "t2" 2>/dev/null | tail -1)
UL=$( (cd "$HL" && COMMONS_ROOT="$HL" COMMONS_AGENT=legacy "$COMMONS" publish dataset "$W/c.csv" \
        "legacy unsigned" --license CC0-1.0 --obtainability open) 2>/dev/null | tail -1)
check "fixtures published" "$(echo "$DS $TK1 $TK2 $UL" | grep -cE '^ds-[0-9a-f]{8} tk-[0-9a-f]{8} tk-[0-9a-f]{8} ds-[0-9a-f]{8}$')" "1"
( cd "$HL" && git add -A && git commit -qm base && git init -q --bare -b main "$BARE" \
  && git remote add origin "$BARE" && git push -q origin HEAD:main )
git clone -q "$BARE" "$HC"
C peer add "$ADDR_C" --agent-id contrib --trust full >/dev/null 2>&1
C peer add "$ADDR_L" --agent-id lead    --trust full >/dev/null 2>&1
BASE=$(git -C "$HL" rev-parse HEAD)

# ---------------------------------------------------------------- 1. dual signatures
head_ "1. every new event is dual-signed, and sig2 binds the fields sig leaves open (#49)"
check "the lead's publish carries sig and sig2" \
  "$(tail -1 "$HL/registry/ledger/$ADDR_Ll.jsonl" | python3 -c 'import json,sys;e=json.load(sys.stdin);print(bool(e.get("sig")) and bool(e.get("sig2")) and "sig_v" not in e)')" "True"
check "a dual-signed event verifies; sig over the v1 fields verifies alone; a changed field fails" \
  "$(py "$HL" <<'PY'
import json, runpy, sys
ns = runpy.run_path(sys.argv[1])
import glob
e = json.loads(open(glob.glob("registry/ledger/0x*.jsonl")[0]).read().splitlines()[-1])
v1 = ns["_verify_message"](ns["canonical"](ns["signing_payload"](e)), e["sig"], e["addr"])[0]
whole = ns["verify_entry"](e, e["sig"], e["addr"])[0]
changed = dict(e, tier="T0")
bad = ns["verify_entry"](changed, changed["sig"], changed["addr"])[0]
v1_of_changed = ns["_verify_message"](ns["canonical"](ns["signing_payload"](changed)),
                                      changed["sig"], changed["addr"])[0]
empty = dict(e, sig2="")
print(v1 and whole and not bad and v1_of_changed
      and not ns["verify_entry"](empty, empty["sig"], empty["addr"])[0])
PY
)" "True"

# ---------------------------------------------------------------- 2. accept task retarget
head_ "2. a relayed accept with its task changed settles nothing (#45)"
branch work
R=$(C publish dataset "$W/b.csv" "contrib result" --license CC0-1.0 --obtainability open 2>/dev/null | tail -1)
check "contributor claims and submits" "$(rc C claim "$TK1")$(rc C submit "$TK1" "$R")" "00"
cpush work
check "lead pulls the submission" "$(lpull work)" "0"
( cd "$HL" && git push -q origin HEAD:main )
BASE2=$(git -C "$HL" rev-parse HEAD)
check "lead accepts R for TK1 on its own machine" "$(rc L accept "$TK1" "$R")" "0"
branch relay
python3 - "$HL/registry/ledger/$ADDR_Ll.jsonl" "$HC/registry/ledger/$ADDR_Ll.jsonl" "$TK2" <<'PY'
import hashlib, json, sys
src, dst, tk2 = sys.argv[1:]
e = json.loads(open(src).read().splitlines()[-1]); assert e["action"] == "accept"
lines = open(dst).read().splitlines()
e = dict(e, task=tk2, prev=hashlib.sha256(lines[-1].encode()).hexdigest())
e.pop("sig2")          # downgraded to v1: `task` is then outside every signature
open(dst, "a").write(json.dumps(e, sort_keys=True) + "\n")
PY
cpush relay
TP="$LAB/third"; git clone -q "$BARE" "$TP"
( cd "$TP" && for a in "$ADDR_L:lead" "$ADDR_C:contrib"; do
    COMMONS_ROOT="$TP" "$COMMONS" peer add "${a%%:*}" --agent-id "${a##*:}" --trust full >/dev/null 2>&1; done
  COMMONS_ROOT="$TP" "$COMMONS" pull origin --branch relay >/dev/null 2>&1 )
check "third party: TK2 (never submitted to) stays open" \
  "$( cd "$TP" && COMMONS_ROOT="$TP" "$COMMONS" status "$TK2" 2>&1 | grep -c 'state      : open')" "1"
check "third party: TK1 is not settled by the retargeted copy" \
  "$( cd "$TP" && COMMONS_ROOT="$TP" "$COMMONS" status "$TK1" 2>&1 | grep -c 'state      : submitted')" "1"
branch relay2
python3 - "$HL/registry/ledger/$ADDR_Ll.jsonl" "$HC/registry/ledger/$ADDR_Ll.jsonl" <<'PY'
import hashlib, json, sys
src, dst = sys.argv[1:]
e = json.loads(open(src).read().splitlines()[-1]); assert e["action"] == "accept"
lines = open(dst).read().splitlines()
e = {k: v for k, v in e.items() if k not in ("sig2", "result")}
e["prev"] = hashlib.sha256(lines[-1].encode()).hexdigest()
open(dst, "a").write(json.dumps(e, sort_keys=True) + "\n")
PY
cpush relay2
TP2="$LAB/third2"; git clone -q "$BARE" "$TP2"
( cd "$TP2" && for a in "$ADDR_L:lead" "$ADDR_C:contrib"; do
    COMMONS_ROOT="$TP2" "$COMMONS" peer add "${a%%:*}" --agent-id "${a##*:}" --trust full >/dev/null 2>&1; done
  COMMONS_ROOT="$TP2" "$COMMONS" pull origin --branch relay2 >/dev/null 2>&1 )
check "third party: an accept with result AND sig2 stripped does not settle TK1" \
  "$( cd "$TP2" && COMMONS_ROOT="$TP2" "$COMMONS" status "$TK1" 2>&1 | grep -c 'state      : submitted')" "1"
check "the genuine accept, once pulled, settles TK1 (lead's own log)" \
  "$(L status "$TK1" 2>&1 | grep -c 'state      : accepted')" "1"

# ---------------------------------------------------------------- 3. submit result swap
head_ "3. a submit whose result was swapped is dropped from the fold (#45)"
lreset "$BASE2"
printf 'r1\n1\n' > "$W/r1.csv"; printf 'r2\n2\n' > "$W/r2.csv"
branch swap
R1=$(C publish dataset "$W/r1.csv" "contrib R1" --license CC0-1.0 --obtainability open 2>/dev/null | tail -1)
R2=$(C publish dataset "$W/r2.csv" "other R2" --license CC0-1.0 --obtainability open 2>/dev/null | tail -1)
check "contributor submits R1 for TK2" "$(rc C claim "$TK2")$(rc C submit "$TK2" "$R1" --force)" "00"
python3 - "$HC/registry/ledger/$ADDR_Cl.jsonl" "$R2" <<'PY'
import json, sys
p, r2 = sys.argv[1:]
lines = open(p).read().splitlines()
e = json.loads(lines[-1]); assert e["action"] == "submit"
e.pop("sig2"); e["result"] = r2
lines[-1] = json.dumps(e, sort_keys=True)
open(p, "w").write("\n".join(lines) + "\n")
PY
cpush swap
check "lead refuses the downgraded submit after the signer's v2 floor" "$(lpull swap)" "1"
check "the refusal names stripped sig2 / the v2 floor" \
  "$(both | grep -Ec 'v2 floor|stripped sig2')" "1"
check "the swapped submission is not listed" "$(L status "$TK2" 2>&1 | grep -c "$R2 by")" "0"
check "a plain accept has nothing to settle on" "$(rc L accept "$TK2")" "1"

# ---------------------------------------------------------------- 3b. phantom result + order
head_ "3b. a v1 submit binds a held result by its full hash; accepts ignore ts order (#45)"
# Unit-level, against the fold functions on the lead's root: build signed events in
# memory and judge them, so no fixture branch can mask the result.
check "phantom id (right 8-hex suffix, no manifest) is not a submission" \
  "$(py "$HL" "$TK1" "$R" <<'PY'
import json, runpy, sys
ns = runpy.run_path(sys.argv[1]); tid, real = sys.argv[2], sys.argv[3]
m = ns["load_manifest"](real)
e = {"action": "submit", "agent": "c", "id": tid, "task": tid, "result": real,
     "sha256": m["content"]["sha256"], "sig": "0x00", "addr": "0x00"}
phantom = dict(e, result="rp-" + real.rsplit("-", 1)[1])
print(ns["submission_result"](e) == real, ns["submission_result"](phantom))
PY
)" "True None"
check "an accept that sorts before its submit (clock skew) still settles" \
  "$(py "$HL" "$TK1" "$R" "$ADDR_L" "$KL" <<'PY'
import runpy, sys, os, json
commons, tid, real, ben, key = sys.argv[1:]
ns = runpy.run_path(commons)
m = ns["load_manifest"](real); tm = ns["load_manifest"](tid)
os.environ["COMMONS_SIGNING_KEY"] = key
def signed(e):
    a, s = ns["sign_entry"](e); return dict(e, addr=a, sig=s)   # v1 only, like an old tool
sub = {"action": "submit", "agent": "c", "id": tid, "task": tid, "result": real,
       "sha256": m["content"]["sha256"], "ts": "2026-10-04T12:00:00Z", "schema": ns["SCHEMA"]}
acc = {"action": "accept", "agent": "lead", "id": tid, "task": tid, "result": real,
       "sha256": tm["content"]["sha256"], "ts": "2025-10-04T12:00:00Z", "schema": ns["SCHEMA"]}
sub = dict(sub, addr="0x" + "c" * 40, sig="v1")   # submit verification is not under test
acc = signed(acc)
ns["task_events"] = lambda t: [acc, sub]
ns["task_state"].__globals__["task_events"] = ns["task_events"]
ns["task_state"].__globals__["verify_entry"] = lambda e, s, a: (True, e["addr"])
st = ns["task_state"](tm)
print(st["state"])
PY
)" "accepted"

# ---------------------------------------------------------------- 4. backdated republish
head_ "4. a backdated foreign republish is never the first publisher (#46)"
lreset "$BASE"
branch backdate
append_signed "$KC" "$HC" contrib republish "$DS" 2000-01-01T00:00:00Z
cpush backdate
check "the branch passes both gates (a republish is metadata)" "$(hcheck)$(lpull backdate)" "00"
check "first publisher is still the lead" \
  "$(py "$HL" "$DS" <<'PY'
import runpy, sys
ns = runpy.run_path(sys.argv[1]); print(ns["first_publisher"](sys.argv[2])[0])
PY
)" "$ADDR_Ll"
check "a foreign republish of an unsigned-only artifact claims nothing either" \
  "$(append_signed "$KC" "$HL" contrib republish "$UL" 2000-01-01T00:00:00Z; py "$HL" "$UL" <<'PY'
import runpy, sys
ns = runpy.run_path(sys.argv[1]); print(ns["first_publisher"](sys.argv[2]))
PY
)" "None"

# ---------------------------------------------------------------- 5. no authorship by republish
head_ "5. publish --force of an unsigned-only artifact refuses adoption (#46, #58)"
lreset "$BASE"
BEFORE=$(wc -l <"$HL/registry/ledger/$ADDR_Ll.jsonl")
check "the republish refuses unsigned-only adoption" \
  "$(rc L publish dataset "$W/c.csv" "legacy unsigned" --license CC0-1.0 --obtainability open --force)" "1"
check "  without adding an event" \
  "$(wc -l <"$HL/registry/ledger/$ADDR_Ll.jsonl")" "$BEFORE"
check "  so fsck still reports it unsigned-only (recovery is #58)" \
  "$(L fsck --attribution 2>&1 | grep -c "UNSIGNED-ONLY: $UL")" "1"

# ---------------------------------------------------------------- 6. own-log rule in pull
head_ "6. pull refuses a line written into another signer's log (#48)"
lreset "$BASE"
branch wronglog
append_signed "$KC" "$HC" contrib heartbeat "$TK1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
python3 - "$HC/registry/ledger" "$ADDR_Cl" "$ADDR_Ll" <<'PY'
import hashlib, json, pathlib, sys
d, c, l = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
line = (d / (c + ".jsonl")).read_text().splitlines()[-1]
rest = (d / (c + ".jsonl")).read_text().splitlines()[:-1]
(d / (c + ".jsonl")).write_text("".join(x + "\n" for x in rest))
if not rest: (d / (c + ".jsonl")).unlink()
ll = (d / (l + ".jsonl")).read_text().splitlines()
e = json.loads(line); e["prev"] = hashlib.sha256(ll[-1].encode()).hexdigest()
with (d / (l + ".jsonl")).open("a") as f: f.write(json.dumps(e, sort_keys=True) + "\n")
PY
cpush wronglog
check "hub check --base refuses it (unchanged behaviour)" "$(hcheck)" "1"
check "pull refuses it" "$(lpull wronglog --dry-run)" "1"
check "  naming the rule" "$(both | grep -c "written into someone else's log")" "1"
branch copyheld
python3 - "$HC/registry/ledger" "$ADDR_Cl" "$ADDR_Ll" <<'PY'
import pathlib, sys
d, c, l = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
held = (d / (c + ".jsonl")).read_text().splitlines()[0]   # a line every side holds
with (d / (l + ".jsonl")).open("a") as f: f.write(held + "\n")
PY
cpush copyheld
check "a byte-identical copy of a held line planted in another log is refused too" \
  "$(lpull copyheld --dry-run)" "1"
check "  naming the rule" "$(both | grep -c "written into someone else's log")" "1"

# ---------------------------------------------------------------- 7. unsigned logs in pull
head_ "7. KNOWN GAP (pinned): pull warns on, but accepts, new unsigned-log lines (#14)"
branch unsigned
python3 - "$HC/registry/ledger/local-unsigned.jsonl" "$DS" <<'PY'
import json, sys
p, aid = sys.argv[1:]
open(p, "a").write(json.dumps({"action": "publish", "agent": "x", "id": aid,
                               "sha256": "0" * 64, "ts": "2000-01-01T00:00:00Z",
                               "addr": None, "sig": None}, sort_keys=True) + "\n")
PY
cpush unsigned
check "pull accepts it" "$(lpull unsigned --dry-run)" "0"
check "  with a warning naming the unsigned log" "$(both | grep -c "incoming line(s) in an unsigned log.*local-unsigned.jsonl")" "1"
check "lines both sides already hold still pull cleanly" \
  "$(git -C "$HL" ls-files registry/ledger/local-unsigned.jsonl | wc -l | tr -d ' ')" "1"

# ---------------------------------------------------------------- 8. tags, unrelated history
head_ "8. an unrelated history cannot add tags to a manifest we hold (#48)"
U="$LAB/unrelated"; cp -r "$HL" "$U"; rm -rf "$U/.git"; git -C "$U" init -q -b main
python3 - "$U/registry/artifacts/$DS.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p)); m["tags"] = ["retracted"]
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
( cd "$U" && git add -A && git commit -qm boot )
( cd "$HL" && git remote add unrelated "$U" )
check "pull refuses the incoming tag" "$(rc L pull unrelated --branch main --dry-run)" "1"
check "  naming the altered view" "$(both | grep -c 'metadata altered')" "1"

printf '\n\033[1mtest-ledger-binding: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
