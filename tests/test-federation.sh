#!/usr/bin/env bash
# P4 gate — two registries + a bare repo between them: push gates, ingest gate,
# quarantine, lazy replication, per-peer ledgers, anchoring.
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

# Blob store is sharded (store/sha256/ab/<fullhash>) with a legacy flat-read fallback.
# Tests must target the path the CODE PREFERS — writing the flat path while the code
# reads the shard makes a tamper fixture silently inert (the tamper "passes" and the
# guard looks broken). bp <root> <digest> resolves the canonical write/tamper path.
bp() { printf '%s/store/sha256/%s/%s' "$1" "${2:0:2}" "$2"; }
# rel path inside a git working tree (same shard rule, no root prefix)
bprel() { printf 'store/sha256/%s/%s' "${1:0:2}" "$1"; }

# Probe with a throwaway key: this checks viem is installed, not that the host has a key.
_PROBEKEY="$(mktemp -t commons-probe-XXXXXX)"
python3 -c "import secrets,sys;open(sys.argv[1],'w').write('0x'+secrets.token_hex(32))" "$_PROBEKEY"
if ! MESSAGE=probe COMMONS_SIGNING_KEY="$_PROBEKEY" node "$REPO/lib/sign-message.mjs" >/dev/null 2>&1; then
  rm -f "$_PROBEKEY"
  echo "test-federation: signer not functional — cannot validate P4"; exit 1
fi
rm -f "$_PROBEKEY"

LAB="$(mktemp -d -t commons-fed-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@local
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@local

# --- two identities ---
KEY_A="$LAB/a.key"; KEY_B="$LAB/b.key"
python3 -c "import secrets;open('$KEY_A','w').write('0x'+secrets.token_hex(32))"
python3 -c "import secrets;open('$KEY_B','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$KEY_A" "$KEY_B"

# --- helpers: run commons as A or B ---
A="$LAB/A"; B="$LAB/B"; BARE="$LAB/bare.git"
a() { COMMONS_ROOT="$A" COMMONS_AGENT=peer-a COMMONS_SIGNING_KEY="$KEY_A" "$COMMONS" "$@"; }
b() { COMMONS_ROOT="$B" COMMONS_AGENT=peer-b COMMONS_SIGNING_KEY="$KEY_B" "$COMMONS" "$@"; }
rc() { "$@" >"$LAB/out.txt" 2>"$LAB/err.txt"; echo $?; }

head_ "lab setup"
git init -q --bare "$BARE"
mkdir -p "$A/registry" "$B/registry"
for R in "$A" "$B"; do
  git init -q "$R"
  ( cd "$R" && git remote add origin "$BARE" \
    && printf 'registry/index.sqlite\nregistry/peers.json\nregistry/quarantine.log\n__pycache__/\n' > .gitignore \
    && mkdir -p registry store/sha256 \
    && cp "$REPO/registry/exec-policy.example.json" registry/exec-policy.json \
    && git add -A && git commit -qm init )
done
ADDR_A=$(a peer whoami | head -1)
ADDR_B=$(b peer whoami | head -1)
check "A has an identity" "$(echo "$ADDR_A" | grep -c '^0x')" "1"
check "B has a different identity" "$([ "$ADDR_A" != "$ADDR_B" ] && echo yes)" "yes"
# each side registers the other
a peer add "$ADDR_A" --agent-id peer-a --trust full --note self >/dev/null
a peer add "$ADDR_B" --agent-id peer-b --trust full --note "the other side" >/dev/null
b peer add "$ADDR_B" --agent-id peer-b --trust full --note self >/dev/null
b peer add "$ADDR_A" --agent-id peer-a --trust full --note "the other side" >/dev/null
check "A knows both peers" "$(a peer list | grep -c '^0x')" "2"
check "peers.json is not tracked (local trust policy)" \
  "$(cd "$A" && git ls-files --error-unmatch registry/peers.json 2>/dev/null | wc -l | tr -d ' ')" "0"

head_ "A publishes and pushes"
printf 'avs,claimed\nalpha,900\nbeta,500\n' > "$LAB/d.csv"
DS=$(a publish dataset "$LAB/d.csv" "Federated dataset" --license CC0-1.0 \
      --obtainability open \
      --tier T3 --criteria "hand-authored demo capture" 2>/dev/null)
check "publish ok" "$(echo "$DS" | grep -c '^ds-')" "1"
a attest "$DS" >/dev/null 2>&1
check "attested before export" "$(a verify "$DS" 2>&1 | grep -c 'attester : VALID')" "1"
check "per-peer ledger written" "$(ls "$A/registry/ledger/" | grep -ci "${ADDR_A#0x}")" "1"
( cd "$A" && git add -A && git commit -qm "publish $DS" )
check "push gate passes" "$(rc a push origin)" "0"
check "push reported" "$(grep -c 'pushed' "$LAB/out.txt")" "1"

head_ "push gates refuse bad exports"
# These fixtures declare --obtainability deliberately: the licence gate and the
# obtainability gate are independent, and a fixture missing BOTH cannot tell you which
# one fired. Each gate gets tested with the other satisfied.
printf 'x\n1\n' > "$LAB/unlic.csv"
UNLIC=$(a publish dataset "$LAB/unlic.csv" "no license" --obtainability open 2>/dev/null)
( cd "$A" && git add -A && git commit -qm "unlicensed" )
check "unlicensed dataset blocks push" "$(rc a push origin)" "1"
check "refusal names the artifact" "$(grep -c "$UNLIC" "$LAB/err.txt")" "1"
check "refusal explains why it matters" "$(grep -c 'cannot be walked back' "$LAB/err.txt")" "1"
check "--allow-unlicensed overrides" "$(rc a push origin --allow-unlicensed)" "0"
# Give that artifact a license so it stops blocking every later push.
a publish dataset "$LAB/unlic.csv" "no license" --license MIT --obtainability open \
  --force >/dev/null 2>&1
( cd "$A" && git add -A && git commit -qm "license it" ) >/dev/null 2>&1

# The gate keys on artifact TYPE, not on whether an artifact carries data. Pin both
# directions of that, because the tempting "fix" (require a license on anything derived
# from a dataset) would be wrong: license terms attach to the data you are
# redistributing, and a synthesis is a new work, not a copy of its inputs. Inheriting
# them would make every downstream number a licensing decision and stall the exchange.
printf 'v\n42\n' > "$LAB/lic.csv"
LICDS=$(a publish dataset "$LAB/lic.csv" "licensed source" --license CC0-1.0 \
          --obtainability open 2>/dev/null)
printf '{"n":42}\n' > "$LAB/derived.json"
DERIV=$(a publish synthesis "$LAB/derived.json" "derived from licensed data" \
          --input "$LICDS" 2>/dev/null)
( cd "$A" && git add -A && git commit -qm "derived synthesis" ) >/dev/null 2>&1
check "synthesis from a licensed dataset needs no license of its own" \
  "$(rc a push origin)" "0"
check "the derived artifact really was exported" \
  "$([ -n "$DERIV" ] && a get "$DERIV" >/dev/null 2>&1 && echo yes)" "yes"
# ...and the converse still bites: a NEW unlicensed dataset blocks again, so the pass
# above is the type rule working, not the gate having been switched off.
printf 'y\n2\n' > "$LAB/unlic2.csv"
UNLIC2=$(a publish dataset "$LAB/unlic2.csv" "still no license" --obtainability open 2>/dev/null)
( cd "$A" && git add -A && git commit -qm "second unlicensed" ) >/dev/null 2>&1
check "an unlicensed dataset still blocks after a clean push" "$(rc a push origin)" "1"
check "refusal names the new artifact" "$(grep -c "$UNLIC2" "$LAB/err.txt")" "1"
a publish dataset "$LAB/unlic2.csv" "still no license" --license MIT --obtainability open \
  --force >/dev/null 2>&1
( cd "$A" && git add -A && git commit -qm "license the second" ) >/dev/null 2>&1

# The obtainability gate is the licence gate's twin, and must be independently provable:
# a fully LICENSED dataset that stays silent about whether anyone else could obtain it
# still blocks. Undeclared is not "open" — that silent-default is the whole bug.
printf 'z\n9\n' > "$LAB/undisclosed.csv"
UNDISC=$(a publish dataset "$LAB/undisclosed.csv" "licensed but undisclosed" \
           --license CC0-1.0 2>/dev/null)
( cd "$A" && git add -A && git commit -qm "undisclosed availability" ) >/dev/null 2>&1
check "licensed dataset with undeclared obtainability blocks push" "$(rc a push origin)" "1"
check "obtainability refusal names the artifact" "$(grep -c "$UNDISC" "$LAB/err.txt")" "1"
check "obtainability refusal is not the licence one" \
  "$(grep -c 'cannot be walked back' "$LAB/err.txt")" "0"
check "refusal states proprietary data is welcome" "$(grep -c 'welcome here' "$LAB/err.txt")" "1"
check "--allow-undisclosed overrides" "$(rc a push origin --allow-undisclosed)" "0"
# Declaring restricted is a full fix: the commons accepts unobtainable data, it just
# refuses silence about it.
a publish dataset "$LAB/undisclosed.csv" "licensed but undisclosed" --license CC0-1.0 \
  --obtainability restricted --force >/dev/null 2>&1
( cd "$A" && git add -A && git commit -qm "declare restricted" ) >/dev/null 2>&1
check "push clean once availability is declared restricted" "$(rc a push origin)" "0"

# COMMONS_REQUIRE_SIG: an unsigned entry must block export under that flag.
# Note where the unsigned entry lands: its own `local-unsigned` log. That segregation
# is the point — unsigned work is never mixed into a signed chain.
# NB: use a DIFFERENT file, so this doesn't republish (and re-stamp) the attested one.
printf 'unsigned,row\n1,1\n' > "$LAB/unsigned.csv"
COMMONS_SIGNING_KEY= COMMONS_ROOT="$A" COMMONS_AGENT=peer-a "$COMMONS" \
  publish dataset "$LAB/unsigned.csv" "unsigned entry" --license MIT \
  --obtainability open >/dev/null 2>&1
check "unsigned entry segregated into its own log" \
  "$([ -f "$A/registry/ledger/local-unsigned.jsonl" ] && echo yes)" "yes"
COMMONS_REQUIRE_SIG=1 a push origin >"$LAB/out.txt" 2>"$LAB/err.txt"; SIGRC=$?
check "COMMONS_REQUIRE_SIG=1 blocks unsigned ledger entries" "$SIGRC" "1"
check "refusal cites the flag" \
  "$([ "$(cat "$LAB/out.txt" "$LAB/err.txt" | grep -c 'COMMONS_REQUIRE_SIG')" -ge 1 ] && echo yes)" "yes"
# Drop the unsigned log so the rest of the suite exports cleanly.
rm -f "$A/registry/ledger/local-unsigned.jsonl"
( cd "$A" && git add -A && git commit -qm "drop unsigned log" ) >/dev/null 2>&1
check "push works once entries are signed" "$(rc a push origin)" "0"

head_ "B pulls through the ingest gate"
check "dry-run validates without merging" "$(rc b pull origin --dry-run)" "0"
check "dry-run says so" "$(grep -c 'dry run' "$LAB/out.txt")" "1"
check "dry-run left B empty" "$(b list 2>/dev/null | grep -c "$DS")" "0"
check "pull succeeds" "$(rc b pull origin)" "0"
check "artifact present on B" "$(b list | grep -c "$DS")" "1"
check "content usable on B" "$(b cat "$DS" | grep -c 'alpha,900')" "1"
check "received_at stamped in local arrival registry" \
  "$(python3 - "$B/registry/ingest.json" "$DS" <<'PY'
import json, sys
print("received_at" in json.load(open(sys.argv[1]))["artifacts"][sys.argv[2]])
PY
)" "True"
check "A's attestation verifies on B" "$(b verify "$DS" 2>&1 | grep -c 'attester : VALID')" "1"
check "B sees A's ledger as a separate log" \
  "$([ "$(ls "$B/registry/ledger" | wc -l)" -ge 1 ] && echo yes)" "yes"
check "B's log --verify clean (A registered)" "$(rc b log --verify)" "0"

head_ "T0 artifact survives the trip (verify PASS on B)"
cat > "$LAB/body.py" <<'PY'
import csv, json, os
rows = list(csv.DictReader(open(os.environ["IN_D"])))
json.dump({r["avs"]: int(r["claimed"]) for r in rows},
          open(os.environ["OUT_DIR"] + "/r.json", "w"), indent=2, sort_keys=True)
PY
python3 - "$LAB/wf.json" "$DS" "$LAB/body.py" <<'PY'
import json, sys
out, ds, body = sys.argv[1], sys.argv[2], sys.argv[3]
json.dump({"interpreter": "bash", "inputs": {"D": ds},
           "attachments": {"step.py": open(body).read()},
           "steps": ["python3 step.py"], "outputs": {"r": "r.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60},
          open(out, "w"), indent=2, sort_keys=True)
PY
WF=$(a publish workflow "$LAB/wf.json" "federated workflow" 2>/dev/null)
OUT=$(a run "$WF" --publish --publish-type synthesis --title "derived" | awk '{print $1}')
check "A derives a T0 artifact" "$(a verify "$OUT" | grep -c '^PASS')" "1"
( cd "$A" && git add -A && git commit -qm "workflow + output" )
a push origin >/dev/null 2>&1
check "B pulls the workflow + output" "$(rc b pull origin)" "0"
check "T0 output verifies on B (re-derived independently)" "$(rc b verify "$OUT")" "0"
check "B's PASS is its own re-derivation" "$(grep -c 'reproduced byte-identically' "$LAB/out.txt")" "1"

head_ "tampering is quarantined, registry stays clean"
# A malicious middle: rewrite a blob in the bare repo so the hash no longer matches.
EVIL="$LAB/evil"; git clone -q "$BARE" "$EVIL"
BLOB=$(cd "$EVIL" && python3 -c "
import json,glob
m=json.load(open(glob.glob('registry/artifacts/$DS.json')[0]))
print(m['content']['sha256'])")
( cd "$EVIL" && mkdir -p "$(dirname "$(bprel "$BLOB")")" \
  && chmod 644 "$(bprel "$BLOB")" 2>/dev/null; \
  cd "$EVIL" && echo 'tampered,content' > "$(bprel "$BLOB")" \
  && git add -A && git commit -qm "tamper" && git push -q origin HEAD:master 2>/dev/null \
  || ( cd "$EVIL" && git push -q origin HEAD:main 2>/dev/null ) )
# B already has the good copy; a fresh peer C is the one at risk
C="$LAB/C"; mkdir -p "$C/registry"
git init -q "$C" && ( cd "$C" && git remote add origin "$BARE" \
  && printf 'registry/index.sqlite\n' > .gitignore && mkdir -p registry store/sha256 \
  && git add -A && git commit -qm init )
c_() { COMMONS_ROOT="$C" COMMONS_AGENT=peer-c COMMONS_SIGNING_KEY="$KEY_B" "$COMMONS" "$@"; }
c_ peer add "$ADDR_A" --agent-id peer-a --trust full >/dev/null
check "C refuses the tampered pull" "$(rc c_ pull origin)" "1"
check "reported as blob hash mismatch" "$(grep -ci 'does not match its hash' "$LAB/out.txt")" "1"
check "quarantine log written" "$([ -s "$C/registry/quarantine.log" ] && echo yes)" "yes"
check "quarantine records the reason" "$(grep -c 'ingest-rejected' "$C/registry/quarantine.log")" "1"
check "C's registry left clean (nothing ingested)" "$(c_ list 2>/dev/null | grep -c '^ds-')" "0"
check "refusal explains the fetch is unmerged" "$(grep -c 'left unmerged' "$LAB/err.txt")" "1"
# B ALREADY holds the good copy of this artifact. A poisoned blob under an unchanged
# manifest must still be refused, or the merge would overwrite good bytes with bad.
check "already-held artifact protected from poisoned blob" "$(rc b pull origin)" "1"
check "reported against the held artifact" \
  "$([ "$(grep -c 'already-held artifact' "$LAB/out.txt")" -ge 1 ] && echo yes)" "yes"
check "B's good copy survives" "$(b cat "$DS" | grep -c 'alpha,900')" "1"
check "B's registry still passes fsck" "$(rc b fsck)" "0"
# Repair the shared repo: the poisoned blob would (correctly) block every later pull,
# which is the right behaviour but makes it a permanent tripwire for the rest of the suite.
# Restore the good bytes from A (the publisher, the only holder of record) and push.
# Repair via a FRESH clone: the tamper clone has a dirty tree and a stale branch, and
# a silent failure in this fixture would masquerade as a product bug (it did, twice).
# Gotchas encoded here: store blobs are mode 444 (in-place cp fails silently), and the
# branch has advanced since the tamper commit.
FIX="$LAB/fix"; rm -rf "$FIX"; git clone -q "$BARE" "$FIX"
FIXBRANCH=$(cd "$FIX" && git branch --show-current)
mkdir -p "$(dirname "$(bp "$FIX" "$BLOB")")"
chmod 644 "$(bp "$FIX" "$BLOB")" 2>/dev/null || true
rm -f "$(bp "$FIX" "$BLOB")"
cp "$(bp "$A" "$BLOB")" "$(bp "$FIX" "$BLOB")"
chmod 644 "$(bp "$FIX" "$BLOB")"
( cd "$FIX" && git add -A && git commit -qm "restore good blob" \
  && git push -q origin "HEAD:$FIXBRANCH" ) || bad "repair fixture failed to push"
check "bare repo now carries the good bytes" \
  "$(cd "$BARE" && git show "$FIXBRANCH:$(bprel "$BLOB")" | sha256sum | cut -d' ' -f1)" "$BLOB"
# B may still hold tampered bytes ingested before the guard existed; repair locally too.
mkdir -p "$(dirname "$(bp "$B" "$BLOB")")"
chmod 644 "$(bp "$B" "$BLOB")" 2>/dev/null || true
rm -f "$(bp "$B" "$BLOB")"
cp "$(bp "$A" "$BLOB")" "$(bp "$B" "$BLOB")"
chmod 444 "$(bp "$B" "$BLOB")"
check "shared repo repaired" "$(rc b pull origin)" "0"
# B may still hold the tampered bytes locally from before the guard existed; a pull
# never overwrites local blobs, so repair it the way a real operator would.
chmod 644 "$(bp "$B" "$BLOB")" 2>/dev/null || true
rm -f "$(bp "$B" "$BLOB")"
cp "$(bp "$A" "$BLOB")" "$(bp "$B" "$BLOB")"
chmod 444 "$(bp "$B" "$BLOB")"
check "repaired blob matches again" "$(rc b fsck)" "0"

head_ "trust policy cannot be smuggled in"
# Run this against a THROWAWAY peer: the point is what the receiver refuses, and a
# rejected pull must not be able to strand the rest of the network mid-merge.
S="$LAB/S"; mkdir -p "$S/registry"
git init -q "$S" && ( cd "$S" && git remote add origin "$BARE" \
  && printf 'registry/index.sqlite\nregistry/peers.json\nregistry/quarantine.log\n' > .gitignore \
  && mkdir -p registry store/sha256 && git add -A && git commit -qm init )
s_() { COMMONS_ROOT="$S" COMMONS_AGENT=peer-s COMMONS_SIGNING_KEY="$KEY_B" "$COMMONS" "$@"; }
s_ peer add "$ADDR_A" --agent-id peer-a --trust full >/dev/null

SMUG="$LAB/smug"; git clone -q "$BARE" "$SMUG"
SMUGBRANCH=$(cd "$SMUG" && git branch --show-current)
( cd "$SMUG" \
  && printf '{"schema":"rc.v1","peers":[{"addr":"0x%040d","agent":"attacker","trust":"full"}]}\n' 1 \
     > registry/peers.json \
  && git add -f registry/peers.json && git commit -qm "smuggle trust policy" \
  && git push -q origin "HEAD:$SMUGBRANCH" )

check "incoming trust policy refused" "$(rc s_ pull origin)" "1"
check "refusal explains the risk" "$(grep -c 'whom you trust' "$LAB/err.txt")" "1"
check "logged as smuggled state" "$(grep -c 'smuggled-local-state' "$S/registry/quarantine.log")" "1"
check "receiver's own trust policy intact" "$(s_ peer list | grep -c "$ADDR_A")" "1"
check "attacker not in receiver's registry" "$(s_ peer list | grep -ci 'attacker')" "0"
check "nothing ingested from the poisoned tree" "$(s_ list 2>/dev/null | grep -c '^ds-')" "0"
# Undo the smuggle in the shared repo so later sections see a clean remote.
( cd "$SMUG" && git rm -q --cached registry/peers.json \
  && rm -f registry/peers.json \
  && git commit -qm "remove smuggled policy" \
  && git push -q origin "HEAD:$SMUGBRANCH" )

head_ "execution policy cannot be smuggled in"
# Regression for 2026-08-02: registry/exec-policy.json used to be git-tracked, so an
# ordinary `pull` fast-forwarded a peer's copy straight over the receiver's. That let a
# remote peer add its own image to your allowlist, make it your DEFAULT, and lift your
# memory/cpu/pids caps — with the ingest gate reporting "0 rejected" the whole time,
# because artifact validation never looked at the policy file. Execution policy IS trust
# policy: it decides what may execute on this host. Same class as peers.json, same
# refusal. Verified before the fix that this attack succeeded.
# Reuse the populated shared remote: the ingest gate bails with "not a commons repo"
# before reaching the local-only check if the incoming tree has no registry/artifacts,
# which would make this test pass for entirely the wrong reason.
X="$LAB/X"; mkdir -p "$X/registry"
git init -q "$X" && ( cd "$X" && git remote add origin "$BARE" \
  && printf 'registry/index.sqlite\nregistry/peers.json\nregistry/quarantine.log\nregistry/exec-policy.json\n' > .gitignore \
  && mkdir -p registry store/sha256 && git add -A && git commit -qm init )
cp "$REPO/registry/exec-policy.example.json" "$X/registry/exec-policy.json"
x_() { COMMONS_ROOT="$X" COMMONS_AGENT=peer-x COMMONS_SIGNING_KEY="$KEY_B" "$COMMONS" "$@"; }
x_ peer add "$ADDR_A" --agent-id peer-a --trust full >/dev/null

# Snapshot the three things an attacker would want to change.
xpol() { python3 -c "
import json;d=json.load(open('$X/registry/exec-policy.json'))
print(sorted(d.get('images',[])), d.get('default_image'), sorted((d.get('limits') or {}).items()))"; }
POL_BEFORE="$(xpol)"

XSMUG="$LAB/xsmug"; git clone -q "$BARE" "$XSMUG"
XBRANCH=$(cd "$XSMUG" && git branch --show-current)
( cd "$XSMUG" && mkdir -p registry \
  && printf '%s\n' '{"schema":"rc.v1","default_image":"evil/attacker:latest","images":["evil/attacker:latest"],"limits":{"memory":"64g","cpus":"32","pids":100000}}' \
     > registry/exec-policy.json \
  && git add -f registry/exec-policy.json && git commit -qm "smuggle exec policy" \
  && git push -q origin "HEAD:$XBRANCH" )

check "incoming exec policy refused" "$(rc x_ pull origin)" "1"
check "refusal names exec-policy.json" \
  "$([ "$(grep -c 'exec-policy.json' "$LAB/err.txt")" -ge 1 ] && echo yes || echo no)" "yes"
check "refusal is the local-only refusal" \
  "$(grep -c 'local-only state' "$LAB/err.txt")" "1"
check "migration note distinguishes old code from attack" \
  "$(grep -c 'probably running older code' "$LAB/err.txt")" "1"
check "logged as smuggled state" \
  "$(grep -c 'smuggled-local-state' "$X/registry/quarantine.log")" "1"
# The whole point: the receiver's execution policy is byte-identical afterwards.
check "allowlist / default image / limits all intact" "$(xpol)" "$POL_BEFORE"
check "attacker image not on the allowlist" \
  "$(grep -c 'evil/attacker' "$X/registry/exec-policy.json")" "0"

# Honest path: the peer upgrades, untracks the file, and the pull then works. Without
# this the fix would be indistinguishable from "federation with older peers is broken".
# This also restores the shared remote for later sections — leaving the smuggled file
# in $BARE would make every subsequent pull in this suite fail on local-only state.
( cd "$XSMUG" && git rm -q --cached registry/exec-policy.json \
  && rm -f registry/exec-policy.json \
  && printf 'registry/exec-policy.json\n' >> .gitignore \
  && git add .gitignore && git commit -qm "untrack exec policy" \
  && git push -q origin "HEAD:$XBRANCH" )
check "pull succeeds once the peer untracks it" "$(rc x_ pull origin)" "0"
check "policy still intact after the honest pull" "$(xpol)" "$POL_BEFORE"

# A fresh clone has no exec-policy.json at all (it is local-only now), so the tracked
# example must materialize one — otherwise the fix trades a vulnerability for a repo
# that cannot execute anything.
rm -f "$X/registry/exec-policy.json"
# Must be a command that actually reaches load_exec_policy(). `list` never loads it, and
# `run` on a missing id exits at artifact resolution first — both would make this pass
# vacuously. $WF was ingested above, so a real sandboxed run gets there.
x_ run "$WF" --exec sandbox >/dev/null 2>&1
check "absent policy bootstraps from the tracked example" \
  "$([ -f "$X/registry/exec-policy.json" ] && echo yes || echo no)" "yes"
check "bootstrapped policy has no attacker image" \
  "$(grep -c 'evil/attacker' "$X/registry/exec-policy.json")" "0"

# HOST-ONLY / CLEANROOM-SKIP: this suite is guarded by its signer probe above.
# The same refusal also has an offline local-git regression in test-store.sh.
head_ "subscription policy cannot be smuggled in"
( cd "$XSMUG" && mkdir -p registry   && echo '{"schema":"rc.v1","subscriptions":[{"collection":"cl-1234abcd","remote":"origin","blobs":"all","executables":true,"follow_supersedes":"any","added":"2026-08-03T00:00:00Z"}]}'      > registry/subscriptions.json   && git add -f registry/subscriptions.json   && git commit -qm "smuggle subscription policy"   && git push -q origin "HEAD:$XBRANCH" )
check "incoming subscription policy refused" "$(rc x_ pull origin)" "1"
check "subscription refusal names local-only file"   "$([ "$(grep -c 'subscriptions.json' "$LAB/err.txt")" -ge 1 ] && echo yes || echo no)" "yes"
check "subscription migration note distinguishes older code"   "$(grep -c 'subscriptions.json became local-only on 2026-08-03' "$LAB/err.txt")" "1"
check "subscription smuggle logged in quarantine"   "$(grep 'smuggled-local-state' "$X/registry/quarantine.log" | grep -c 'subscriptions.json')" "1"
check "sender cannot choose receiver subscription intent"   "$(test -e "$X/registry/subscriptions.json"; echo $?)" "1"
( cd "$XSMUG" && git rm -q --cached registry/subscriptions.json   && rm -f registry/subscriptions.json   && echo 'registry/subscriptions.json' >> .gitignore   && git add .gitignore && git commit -qm "untrack subscription policy"   && git push -q origin "HEAD:$XBRANCH" )
check "pull succeeds once subscription policy is untracked" "$(rc x_ pull origin)" "0"

head_ "unknown signer / trust policy"
D="$LAB/D"; mkdir -p "$D/registry"
git init -q "$D" && ( cd "$D" && git remote add origin "$BARE" \
  && printf 'registry/index.sqlite\n' > .gitignore && mkdir -p registry store/sha256 \
  && git add -A && git commit -qm init )
d_() { COMMONS_ROOT="$D" COMMONS_AGENT=peer-d COMMONS_SIGNING_KEY="$KEY_B" "$COMMONS" "$@"; }
# empty peer registry: A's attested artifact must be refused as an unknown attester
# D trusts nobody yet, so A's attested artifact must be refused on attester grounds.
rc d_ pull origin >/dev/null 2>&1
d_ pull origin >"$LAB/out.txt" 2>"$LAB/err.txt"; DRC=$?
check "empty registry refuses attested artifacts" "$DRC" "1"
check "unknown attester was flagged" \
  "$([ "$(grep -c 'not in peer registry' "$LAB/out.txt")" -ge 1 ] && echo yes)" "yes"
check "nothing ingested" "$(d_ list 2>/dev/null | grep -c '^ds-')" "0"
# datasets-only trust must refuse executable methods (workflows and skills are code)
d_ peer add "$ADDR_A" --agent-id peer-a --trust datasets-only >/dev/null
d_ pull origin >"$LAB/out.txt" 2>"$LAB/err.txt" || true
check "datasets-only peer cannot ship executable methods" \
  "$([ "$(grep -c 'trust=full required for code' "$LAB/out.txt")" -ge 1 ] && echo yes)" "yes"
check "the refusal is about code, not data" \
  "$([ "$(grep -cE 'REJECT (wf|sk)-' "$LAB/out.txt")" -ge 1 ] && echo yes)" "yes"
# Raise to full trust: the same code becomes acceptable, so this is a policy decision
# rather than a blanket ban. (Asserted after the tamper repair below, since a poisoned
# blob in the shared repo legitimately blocks every pull until it is fixed.)
d_ peer add "$ADDR_A" --agent-id peer-a --trust full --force >/dev/null
check "trust upgrade recorded" "$(d_ peer list | grep -c 'full')" "1"
# The shared repo was repaired earlier in the run, so the code genuinely lands now.
check "full-trust peer may ship code" "$(rc d_ pull origin)" "0"
check "workflow ingested under full trust" "$(d_ list --type workflow | grep -c '^wf-')" "1"
check "received code re-derives its output on the receiver" "$(rc d_ verify "$OUT")" "0"

head_ "concurrent appends do not collide (per-peer logs)"
printf 'own,data\n7,8\n' > "$LAB/bown.csv"
b publish dataset "$LAB/bown.csv" "B's own artifact" --license MIT \
  --obtainability open >/dev/null 2>&1
( cd "$B" && git add -A && git commit -qm "B publishes" ) >/dev/null 2>&1
# B syncs with the remote first (ordinary git fast-forward requirement), then pushes.
( cd "$B" && git fetch -q origin && git merge -q --no-edit origin/"$(git branch --show-current)" ) >/dev/null 2>&1
check "B pushes without merge conflict" "$(rc b push origin)" "0"
check "A pulls B's work" "$(rc a pull origin)" "0"
check "A now has two ledger logs (one per writer)" \
  "$([ "$(ls "$A/registry/ledger" 2>/dev/null | wc -l)" -ge 2 ] && echo yes)" "yes"
check "each writer owns exactly one log file" \
  "$(ls "$A/registry/ledger" | sort -u | wc -l | tr -d ' ')" "$(ls "$A/registry/ledger" | wc -l | tr -d ' ')"
check "both chains verify independently" "$(rc a log --verify)" "0"
check "verify counts multiple logs" "$(grep -c 'across [2-9] log' "$LAB/out.txt")" "1"

head_ "lazy replication"
# Manifest present, blob absent: fsck must call it not-replicated, not corrupt.
# Pick a synthesis that carries a workflow: the last check here re-verifies after
# fetching, and a synthesis published with only --input has no provenance.workflow, so
# `verify` correctly returns UNVERIFIED(4) and the fixture would be testing the wrong
# thing. Selecting on the property the test depends on keeps it from breaking whenever
# another synthesis is published earlier in the suite.
LAZY=""
for cand in $(b list --type synthesis 2>/dev/null | awk 'NF{print $1}'); do
  if b get "$cand" 2>/dev/null \
     | python3 -c 'import json,sys; m=json.load(sys.stdin); sys.exit(0 if ((m.get("provenance") or {}).get("workflow")) else 1)'; then
    LAZY="$cand"; break
  fi
done
LB=$(b get "$LAZY" | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])')
if [ -n "$LB" ] && [ -f "$(bp "$B" "$LB")" ]; then
  chmod 644 "$(bp "$B" "$LB")"; rm -f "$(bp "$B" "$LB")"
  python3 - "$B/registry/artifacts/$LAZY.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m.setdefault("ingest", {})["received_at"] = "2026-07-25T00:00:00Z"
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
  check "fsck distinguishes not-replicated from corrupt" "$(rc b fsck)" "0"
  check "reported as NOT REPLICATED" "$(grep -c 'NOT REPLICATED' "$LAB/out.txt")" "1"
  check "fetch retrieves the blob" "$(rc b fetch "$LAZY" origin)" "0"
  check "blob now present" "$([ -f "$(bp "$B" "$LB")" ] && echo yes)" "yes"
  check "fsck clean again" "$(rc b fsck)" "0"
  check "verify works after fetch" "$(rc b verify "$LAZY")" "0"
  # And the converse: while a blob is missing, the registry must not be exportable.
  chmod 644 "$(bp "$B" "$LB")"; rm -f "$(bp "$B" "$LB")"
  python3 - "$B/registry/artifacts/$LAZY.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m.pop("ingest", None)          # look locally-produced, i.e. genuinely corrupt
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
  check "missing blob blocks push (incomplete registry)" "$(rc b push origin)" "1"
  check "push refusal names the blob problem" "$(grep -c 'MISSING BLOB' "$LAB/out.txt")" "1"
  b fetch "$LAZY" origin >/dev/null 2>&1
  check "fsck clean after restoring" "$(rc b fsck)" "0"
else
  bad "lazy-replication fixture could not be set up"
fi

head_ "anchoring"
check "anchor records a root" "$(rc a anchor --local-only)" "0"
check "root printed" "$(grep -c 'root ' "$LAB/out.txt")" "1"
check "honest about lacking OTS" "$(grep -c 'NOT' "$LAB/out.txt")" "1"
check "anchor-verify re-derives" "$(rc a anchor-verify)" "0"
check "reported consistent" "$(grep -c 'consistent' "$LAB/out.txt")" "1"
# tamper with a recorded head: the root must no longer re-derive
AF=$(ls "$A/registry/anchors"/*.json | head -1)
python3 - "$AF" <<'PY'
import json, sys
p = sys.argv[1]; rec = json.load(open(p))
k = sorted(rec["heads"])[0]
rec["heads"][k] = "00" * 32
json.dump(rec, open(p, "w"), indent=2, sort_keys=True)
PY
check "tampered anchor detected" "$(rc a anchor-verify)" "1"
check "reported as root mismatch" "$(grep -c 'ROOT MISMATCH' "$LAB/out.txt")" "1"

head_ "idempotence"
check "re-pull is a no-op" "$(rc b pull origin)" "0"
check "says nothing new" \
  "$([ "$(grep -c 'nothing new to merge\|already present' "$LAB/out.txt")" -ge 1 ] && echo yes)" "yes"
check "A fsck clean" "$(rc a fsck)" "0"
check "B fsck clean" "$(rc b fsck)" "0"

printf '\n\033[1mtest-federation: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
