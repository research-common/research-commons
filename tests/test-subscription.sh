#!/usr/bin/env bash
set -uo pipefail
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"; COMMONS="$REPO/bin/commons"
PASS=0; FAIL=0
ok(){ printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_(){ printf '\n\033[1m%s\033[0m\n' "$1"; }
bp(){ printf '%s/store/sha256/%s/%s' "$1" "${2:0:2}" "$2"; }
digest(){ COMMONS_ROOT="$1" "$COMMONS" get "$2" | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])'; }
rc(){ "$@" >"$LAB/out.txt" 2>"$LAB/err.txt"; echo $?; }

LAB="$(mktemp -d -t commons-subscription-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export GIT_AUTHOR_NAME=test GIT_AUTHOR_EMAIL=test@local
export GIT_COMMITTER_NAME=test GIT_COMMITTER_EMAIL=test@local
BARE="$LAB/bare.git"; PUB="$LAB/pub"
pub(){ COMMONS_ROOT="$PUB" COMMONS_AGENT=publisher "$COMMONS" "$@"; }

head_ "publisher and receiver fixture"
git init -q --bare "$BARE"; git init -q "$PUB"
(
  cd "$PUB" || exit
  git config user.name test; git config user.email test@local
  git remote add origin "$BARE"; printf '%s\n' registry/index.sqlite registry/peers.json registry/quarantine.log registry/exec-policy.json registry/subscriptions.json registry/ingest.json __pycache__/ > .gitignore  # a registry repo's own ignores (the tool repo's .gitignore excludes registry/* entirely)
  mkdir -p registry/artifacts store/sha256
  touch registry/artifacts/.keep store/sha256/.keep
  git add .gitignore registry/artifacts/.keep store/sha256/.keep
  git commit -qm seed; git push -q -u origin HEAD
)
for n in manifest members all self exec pending refused maint outsider none anysup; do
  git clone -q "$BARE" "$LAB/$n"
  git -C "$LAB/$n" config user.name test
  git -C "$LAB/$n" config user.email test@local
done
ADDR="0x$(printf 'a%.0s' $(seq 40))"
check "publisher fixture address is well formed" "$(printf '%s' "$ADDR" | grep -c '^0x')" "1"

printf 'curated bytes\n' >"$LAB/curated.txt"
CURATED=$(pub publish dataset "$LAB/curated.txt" curated --license MIT)
printf 'all-only bytes\n' >"$LAB/other.txt"
OTHER=$(pub publish report "$LAB/other.txt" other)
printf '#!/bin/sh\nprintf executable\n' >"$LAB/tool.sh"
EXEC=$(pub publish workflow "$LAB/tool.sh" executable)
for n in manifest members all self exec pending maint outsider none anysup; do
  cp "$PUB/registry/artifacts/$EXEC.json" "$LAB/$n/registry/artifacts/"
  python3 - "$LAB/$n/registry/ingest.json" "$EXEC" <<'PYARRIVAL'
import json, sys
json.dump({"schema": "rc.v1", "artifacts": {
    sys.argv[2]: {"received_at": "2026-08-03T00:00:00Z", "from": "origin"}}},
    open(sys.argv[1], "w"))
PYARRIVAL
  git -C "$LAB/$n" add "registry/artifacts/$EXEC.json"
  git -C "$LAB/$n" commit -qm "preaccepted executable manifest"
done
cat >"$LAB/collection.json" <<JSON
{"scope":"subscription policy test","maintainers":[{"addr":"$ADDR","agent":"publisher"}],"members":[{"id":"$CURATED","role":"source"},{"id":"$EXEC","role":"method"}]}
JSON
COLLECTION=$(pub publish collection "$LAB/collection.json" collection)
printf 'self-declared bytes\n' >"$LAB/self.txt"
SELF=$(pub publish report "$LAB/self.txt" claimant --link "part-of:$COLLECTION")

MADDR="0x$(printf 'b%.0s' $(seq 40))"
OADDR="0x$(printf 'c%.0s' $(seq 40))"
mkcollection(){  # mkcollection <out> <scope> <member> [supersedes-id]
  python3 - "$1" "$2" "$3" "$MADDR" "${4:-}" <<'PYCOLL'
import json, sys
spec = {"scope": sys.argv[2],
        "maintainers": [{"addr": sys.argv[4], "agent": "maintainer"}],
        "members": [{"id": sys.argv[3], "role": "source"}]}
if sys.argv[5]:
    spec["supersedes"] = [sys.argv[5]]   # the lineage lives in the spec (#39)
json.dump(spec, open(sys.argv[1], "w"), sort_keys=True)
PYCOLL
}
mkcollection "$LAB/c-old-maint.json" "maintainer old" "$CURATED"
OLD_M=$(pub publish collection "$LAB/c-old-maint.json" "maintainer old")
mkcollection "$LAB/c-new-maint.json" "maintainer new" "$OTHER" "$OLD_M"
NEW_M=$(pub publish collection "$LAB/c-new-maint.json" "maintainer new" --link "supersedes:$OLD_M")
mkcollection "$LAB/c-old-outsider.json" "outsider old" "$CURATED"
OLD_O=$(pub publish collection "$LAB/c-old-outsider.json" "outsider old")
mkcollection "$LAB/c-new-outsider.json" "outsider takeover" "$OTHER" "$OLD_O"
NEW_O=$(pub publish collection "$LAB/c-new-outsider.json" "outsider takeover" --link "supersedes:$OLD_O")
mkcollection "$LAB/c-old-none.json" "none old" "$CURATED"
OLD_N=$(pub publish collection "$LAB/c-old-none.json" "none old")
mkcollection "$LAB/c-new-none.json" "none new" "$OTHER" "$OLD_N"
NEW_N=$(pub publish collection "$LAB/c-new-none.json" "none new" --link "supersedes:$OLD_N")
mkcollection "$LAB/c-old-any.json" "any old" "$CURATED"
OLD_A=$(pub publish collection "$LAB/c-old-any.json" "any old")
mkcollection "$LAB/c-new-any.json" "any outsider" "$OTHER" "$OLD_A"
NEW_A=$(pub publish collection "$LAB/c-new-any.json" "any outsider" --link "supersedes:$OLD_A")
mkdir -p "$PUB/registry/ledger"
python3 - "$PUB/registry/ledger" "$MADDR" "$OADDR"   "$OLD_M" "$NEW_M" "$OLD_O" "$NEW_O" "$OLD_N" "$NEW_N" "$OLD_A" "$NEW_A" <<'PYLEDGERS'
import hashlib, json, os, sys
root, maint, outsider, *ids = sys.argv[1:]
groups = [(maint, "offline-maintainer", [ids[i] for i in (0,1,2,4,5,6)]),
          (outsider, "offline-outsider", [ids[i] for i in (3,7)])]
for addr, sig, aids in groups:
    path=os.path.join(root, addr.lower()+".jsonl")
    prev=None
    with open(path, "w") as f:
        for n, aid in enumerate(aids):
            e={"schema":"rc.v1","ts":"2026-08-03T00:00:%02dZ"%n,
               "agent":"fixture","action":"publish","id":aid,
               "addr":addr,"sig":sig,"prev":prev}
            line=json.dumps(e,sort_keys=True)
            f.write(line+chr(10))
            prev=hashlib.sha256(line.encode()).hexdigest()
PYLEDGERS

(cd "$PUB" && git add -A && git commit -qm artifacts && git push -q origin HEAD)
DC=$(digest "$PUB" "$CURATED"); DO=$(digest "$PUB" "$OTHER")
DE=$(digest "$PUB" "$EXEC"); DS=$(digest "$PUB" "$SELF")
DCL=$(digest "$PUB" "$COLLECTION")
for n in manifest members all self exec pending maint outsider none anysup; do
  COMMONS_ROOT="$LAB/$n" "$COMMONS" peer add "$ADDR" --agent-id publisher --trust full >/dev/null
  COMMONS_ROOT="$LAB/$n" "$COMMONS" peer add "$MADDR" --agent-id maintainer --trust full >/dev/null
  COMMONS_ROOT="$LAB/$n" "$COMMONS" peer add "$OADDR" --agent-id outsider --trust full >/dev/null
done

# The fixture ledgers carry placeholder signatures ("offline-maintainer" etc.), and
# `pull` verifies every incoming ledger line (#48), so plain syncs run through the
# same verify stub the supersede sections use.
sync_plain(){
  ( cd "$M" && COMMONS_ROOT="$M" COMMONS_TEST_MAINTAINER="$MADDR" COMMONS_TEST_OUTSIDER="$OADDR" python3 - "$COMMONS" "$@" <<'PY_PLAIN_SYNC'
import argparse, importlib.machinery, os, sys
mod=importlib.machinery.SourceFileLoader("commons_cli",sys.argv[1]).load_module()
m=os.environ["COMMONS_TEST_MAINTAINER"].lower()
o=os.environ["COMMONS_TEST_OUTSIDER"].lower()
real=mod.verify_entry
def verified(entry, sig, claimed):
    addr=(claimed or "").lower()
    if (sig=="offline-maintainer" and addr==m) or (sig=="offline-outsider" and addr==o):
        return True, claimed
    return real(entry, sig, claimed)
mod.verify_entry=verified
sub=sys.argv[3] if len(sys.argv) > 3 and sys.argv[2] == "--subscription" else None
try:
    mod.cmd_sync(argparse.Namespace(subscription=sub))
except SystemExit as e:
    if e.code not in (None, 0):
        if not isinstance(e.code, int): print(e.code, file=sys.stderr)
        sys.exit(e.code if isinstance(e.code, int) else 1)
PY_PLAIN_SYNC
  )
}

head_ "manifests-only"
M="$LAB/manifest"; COMMONS_ROOT="$M" "$COMMONS" subscribe "$COLLECTION" origin >/dev/null
check "manifests-only sync succeeds" "$(rc sync_plain)" "0"
check "full pull carries every manifest" "$(find "$M/registry/artifacts" -name '*.json' | wc -l | tr -d ' ')" "13"
check "manifests-only leaves curated blob absent" "$(test -e "$(bp "$M" "$DC")"; echo $?)" "1"
check "manifests-only leaves collection blob absent" "$(test -e "$(bp "$M" "$DCL")"; echo $?)" "1"
check "pull outcome reported" "$(grep -c 'pull: ok (full ingest gate, unfiltered)' "$LAB/out.txt")" "1"
check "zero-count report emitted" "$(grep -c 'result: fetched=0 skipped=0 already-present=0' "$LAB/out.txt")" "1"

head_ "curated members and executable deny"
M="$LAB/members"; COMMONS_ROOT="$M" "$COMMONS" subscribe "$COLLECTION" origin --blobs members >/dev/null
check "members sync succeeds" "$(rc sync_plain --subscription "$COLLECTION")" "0"
check "curated member fetched" "$(test -f "$(bp "$M" "$DC")"; echo $?)" "0"
check "self-declared excluded by default" "$(test -e "$(bp "$M" "$DS")"; echo $?)" "1"
check "unrelated artifact excluded" "$(test -e "$(bp "$M" "$DO")"; echo $?)" "1"
check "executable denied by default" "$(test -e "$(bp "$M" "$DE")"; echo $?)" "1"
check "executable skip is named" "$(grep -c "SKIPPED executable $EXEC" "$LAB/out.txt")" "1"
check "members counts fetched and skipped" "$(grep -c 'result: fetched=1 skipped=1 already-present=0' "$LAB/out.txt")" "1"
check "members resync succeeds" "$(rc sync_plain --subscription "$COLLECTION")" "0"
check "already-present member is counted" "$(grep -c 'result: fetched=0 skipped=1 already-present=1' "$LAB/out.txt")" "1"

head_ "fsck subscription completeness"
# Turn on an already-known self-declaration after sync: its manifest is local but its
# blob is not, giving fsck one pinned, one queued, and one policy-withheld member.
python3 - "$M/registry/subscriptions.json" <<'PYFSCKPOLICY'
import json, sys
p = sys.argv[1]
data = json.load(open(p))
data["subscriptions"][0]["include_self_declared"] = True
open(p, "w").write(json.dumps(data, indent=2, sort_keys=True) + chr(10))
PYFSCKPOLICY
python3 - "$M/registry/ingest.json" "$EXEC" <<'PYFSCKINGEST'
import json, sys
p = sys.argv[1]
arrivals = json.load(open(p))
arrivals["artifacts"][sys.argv[2]] = {"received_at": "2026-08-03T00:00:00Z", "from": "origin"}
open(p, "w").write(json.dumps(arrivals, indent=2, sort_keys=True) + chr(10))
PYFSCKINGEST
# An unattributed superseder is a pending-review candidate under the default
# maintainer-signed gate. Its dummy digest is computed, never embedded as a literal.
printf '%s' 'untrusted superseder bytes' >"$LAB/superseder.txt"
DNEW=$(sha256sum "$LAB/superseder.txt" | cut -d' ' -f1)
NEW="rp-${DNEW:0:8}"
mkdir -p "$M/store/sha256/${DNEW:0:2}"
cp "$LAB/superseder.txt" "$(bp "$M" "$DNEW")"
python3 - "$M/registry/artifacts/$NEW.json" "$NEW" "$DNEW" "$CURATED" <<'PYFSCKMANIFEST'
import json, sys
path, aid, digest, old_id = sys.argv[1:]
manifest = {
    "schema": "rc.v1", "id": aid, "type": "report", "title": "untrusted superseder",
    "content": {"sha256": digest, "bytes": len(b"untrusted superseder bytes"),
                "media_type": "text/plain"},
    "links": [{"rel": "supersedes", "id": old_id}],
}
open(path, "w").write(json.dumps(manifest, indent=2, sort_keys=True) + chr(10))
PYFSCKMANIFEST
check "fsck incomplete subscription remains nonfatal" "$(rc env COMMONS_ROOT="$M" "$COMMONS" fsck)" "0"
check "fsck completeness section is present" "$(grep -c '^--- subscription completeness ---$' "$LAB/out.txt")" "1"
check "fsck lists pinned member" "$(grep -c "^  pinned $CURATED$" "$LAB/out.txt")" "1"
check "fsck lists queued member" "$(grep -c "^  queued $SELF$" "$LAB/out.txt")" "1"
check "fsck names executable policy skip" "$(grep -c "^  skipped $EXEC " "$LAB/out.txt")" "1"
check "fsck counts are exact" "$(grep -c '^  counts: pinned=1 queued=1 skipped=1 pending-review=1$' "$LAB/out.txt")" "1"
check "fsck surfaces pending-review supersede" "$(grep -c "^  pending-review $NEW supersedes $CURATED" "$LAB/out.txt")" "1"
check "fsck integrity summary stays green" "$(grep -c '^fsck: OK;' "$LAB/out.txt")" "1"

head_ "empty subscription completeness"
EMPTY="$LAB/empty"; mkdir -p "$EMPTY"
check "empty-subscription fsck succeeds" "$(rc env COMMONS_ROOT="$EMPTY" "$COMMONS" fsck)" "0"
check "empty-subscription state renders cleanly" "$(grep -c '^no subscriptions$' "$LAB/out.txt")" "1"
check "empty-subscription counts are not invented" "$(grep -c '^  counts:' "$LAB/out.txt")" "0"

head_ "all policy"
M="$LAB/all"; COMMONS_ROOT="$M" "$COMMONS" subscribe "$COLLECTION" origin --blobs all >/dev/null
check "all sync succeeds" "$(rc sync_plain)" "0"
check "all fetches curated" "$(test -f "$(bp "$M" "$DC")"; echo $?)" "0"
check "all fetches unrelated" "$(test -f "$(bp "$M" "$DO")"; echo $?)" "0"
check "all fetches self-declared" "$(test -f "$(bp "$M" "$DS")"; echo $?)" "0"
check "all fetches collection metadata" "$(test -f "$(bp "$M" "$DCL")"; echo $?)" "0"
check "all still denies executable" "$(test -e "$(bp "$M" "$DE")"; echo $?)" "1"

head_ "self-declared opt-in"
M="$LAB/self"
COMMONS_ROOT="$M" "$COMMONS" subscribe "$COLLECTION" origin --blobs members --include-self-declared >/dev/null
check "self-declared opt-in sync succeeds" "$(rc sync_plain)" "0"
check "self-declared fetched with flag" "$(test -f "$(bp "$M" "$DS")"; echo $?)" "0"
check "self-declared intent persisted" "$(python3 - "$M/registry/subscriptions.json" <<'PY'
import json,sys
print(str(json.load(open(sys.argv[1]))["subscriptions"][0]["include_self_declared"]).lower())
PY
)" "true"

head_ "trusted executable opt-in"
M="$LAB/exec"; COMMONS_ROOT="$M" "$COMMONS" subscribe "$COLLECTION" origin --blobs members --executables >/dev/null
mkdir -p "$M/registry/ledger"
python3 - "$M/registry/ledger/offline-test.jsonl" "$EXEC" "$ADDR" <<'PYLEDGER'
import json, sys
entry = {"schema": "rc.v1", "ts": "2026-08-03T00:00:00Z", "action": "publish",
         "id": sys.argv[2], "addr": sys.argv[3], "sig": "offline-test-signature"}
open(sys.argv[1], "w").write(json.dumps(entry, sort_keys=True) + chr(10))
PYLEDGER
sync_exec_fixture(){
  COMMONS_ROOT="$M" COMMONS_TEST_VERIFIED_PUBLISHER="$ADDR" COMMONS_TEST_MAINTAINER="$MADDR" \
    COMMONS_TEST_OUTSIDER="$OADDR" python3 - "$COMMONS" <<'PYTRUST'
import argparse, importlib.machinery, os, sys
mod=importlib.machinery.SourceFileLoader("commons_cli",sys.argv[1]).load_module()
addr = os.environ["COMMONS_TEST_VERIFIED_PUBLISHER"].lower()
m = os.environ["COMMONS_TEST_MAINTAINER"].lower(); o = os.environ["COMMONS_TEST_OUTSIDER"].lower()
def _stub(entry, sig, claimed):
    c = (claimed or "").lower()
    return ((sig == "offline-test-signature" and c == addr)
            or (sig == "offline-maintainer" and c == m)
            or (sig == "offline-outsider" and c == o)), claimed
mod.verify_entry = _stub
mod.cmd_sync(argparse.Namespace(subscription=None))
PYTRUST
}
python3 - "$M/registry/peers.json" <<'PYTRUSTDOWN'
import json, sys
p = sys.argv[1]; data = json.load(open(p))
data["peers"][0]["trust"] = "datasets-only"
open(p, "w").write(json.dumps(data, indent=2, sort_keys=True) + chr(10))
PYTRUSTDOWN
check "executable opt-in with insufficient trust sync succeeds" "$(rc sync_exec_fixture)" "0"
check "insufficient-trust executable remains absent" "$(test -e "$(bp "$M" "$DE")"; echo $?)" "1"
check "insufficient publisher trust is logged" "$(grep -c 'publisher trust is not full' "$LAB/out.txt")" "1"
python3 - "$M/registry/peers.json" <<'PYTRUSTUP'
import json, sys
p = sys.argv[1]; data = json.load(open(p))
data["peers"][0]["trust"] = "full"
open(p, "w").write(json.dumps(data, indent=2, sort_keys=True) + chr(10))
PYTRUSTUP
check "trusted executable sync succeeds" "$(rc sync_exec_fixture)" "0"
check "trusted executable materialized" "$(test -f "$(bp "$M" "$DE")"; echo $?)" "0"
check "trusted executable counted fetched" "$(grep -c 'result: fetched=1 skipped=0 already-present=1' "$LAB/out.txt")" "1"

head_ "pending and pull refusal visibility"
M="$LAB/pending"; COMMONS_ROOT="$M" "$COMMONS" subscribe cl-1234abcd origin --blobs members >/dev/null
check "pending collection sync is nonfatal" "$(rc sync_plain)" "0"
check "pending collection is visible" "$(grep -c 'status: pending: collection not replicated' "$LAB/out.txt")" "1"
python3 - "$M/registry/ingest.json" "$EXEC" <<'PYPENDINGINGEST'
import json, sys
p = sys.argv[1]
arrivals = json.load(open(p))
arrivals["artifacts"][sys.argv[2]] = {"received_at": "2026-08-03T00:00:00Z", "from": "origin"}
open(p, "w").write(json.dumps(arrivals, indent=2, sort_keys=True) + chr(10))
PYPENDINGINGEST
check "unsynced subscription fsck is nonfatal" "$(rc env COMMONS_ROOT="$M" "$COMMONS" fsck)" "0"
check "unsynced subscription fsck stays pending" "$(grep -c '^  status: pending: collection not replicated$' "$LAB/out.txt")" "1"
check "unsynced subscription has zero derived counts" "$(grep -c '^  counts: pinned=0 queued=0 skipped=0 pending-review=0$' "$LAB/out.txt")" "1"
M="$LAB/refused"; COMMONS_ROOT="$M" "$COMMONS" subscribe cl-1234abcd missing --blobs all >/dev/null
check "pull refusal fails sync" "$(rc sync_plain)" "1"
check "pull refusal is reported" "$(grep -c 'pull: REFUSED' "$LAB/out.txt")" "1"

sync_supersede_fixture(){
  COMMONS_ROOT="$M" COMMONS_TEST_MAINTAINER="$MADDR" COMMONS_TEST_OUTSIDER="$OADDR"     python3 - "$COMMONS" <<'PY_SUPER_SYNC'
import argparse, importlib.machinery, os, sys
mod=importlib.machinery.SourceFileLoader("commons_cli",sys.argv[1]).load_module()
m=os.environ["COMMONS_TEST_MAINTAINER"].lower()
o=os.environ["COMMONS_TEST_OUTSIDER"].lower()
def verified(entry, sig, claimed):
    addr=(claimed or "").lower()
    ok=(sig=="offline-maintainer" and addr==m) or (sig=="offline-outsider" and addr==o)
    return ok, claimed
mod.verify_entry=verified
mod.cmd_sync(argparse.Namespace(subscription=None))
PY_SUPER_SYNC
}

head_ "supersedes trust gating and staleness"
M="$LAB/maint"; COMMONS_ROOT="$M" "$COMMONS" subscribe "$OLD_M" origin --blobs members >/dev/null
check "maintainer-signed supersede sync succeeds" "$(rc sync_supersede_fixture)" "0"
check "maintainer-signed hop is reported" "$(grep -c "followed $OLD_M -> $NEW_M (signer $MADDR)" "$LAB/out.txt")" "1"
check "maintainer-signed subscription advances" "$(python3 - "$M/registry/subscriptions.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))["subscriptions"][0]
print(r["collection"], r["superseded_from"], r["supersede_signer"])
PY
)" "$NEW_M $OLD_M $MADDR"
check "advanced subscription fetches new members" "$(test -f "$(bp "$M" "$DO")"; echo $?)" "0"
check "advanced subscription lists current" "$(COMMONS_ROOT="$M" "$COMMONS" subscriptions | grep -c "$NEW_M.*current")" "1"

M="$LAB/outsider"; COMMONS_ROOT="$M" "$COMMONS" subscribe "$OLD_O" origin --blobs members >/dev/null
check "different-key supersede sync succeeds" "$(rc sync_supersede_fixture)" "0"
check "curation takeover is pending review" "$(grep -c "pending review $OLD_O -> $NEW_O (signer $OADDR" "$LAB/out.txt")" "1"
check "different-key hop does not advance" "$(python3 - "$M/registry/subscriptions.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))["subscriptions"][0]
print(r["collection"], r["pending_supersedes"][0]["supersede_signer"])
PY
)" "$OLD_O $OADDR"
check "old collection keeps syncing after takeover" "$(test -f "$(bp "$M" "$DC")"; echo $?)" "0"
check "takeover collection member remains absent" "$(test -e "$(bp "$M" "$DO")"; echo $?)" "1"
check "subscriptions surfaces takeover review" "$(COMMONS_ROOT="$M" "$COMMONS" subscriptions | grep -c "$OLD_O.*supersedes available (pending review)")" "1"

M="$LAB/none"; COMMONS_ROOT="$M" "$COMMONS" subscribe "$OLD_N" origin --blobs members --follow-supersedes none >/dev/null
check "none supersede sync succeeds" "$(rc sync_supersede_fixture)" "0"
check "none reports pending supersede" "$(grep -c "pending review $OLD_N -> $NEW_N" "$LAB/out.txt")" "1"
check "none does not advance" "$(python3 - "$M/registry/subscriptions.json" <<'PY'
import json,sys
print(json.load(open(sys.argv[1]))["subscriptions"][0]["collection"])
PY
)" "$OLD_N"
check "none keeps old member syncing" "$(test -f "$(bp "$M" "$DC")"; echo $?)" "0"

M="$LAB/anysup"; COMMONS_ROOT="$M" "$COMMONS" subscribe "$OLD_A" origin --blobs members --follow-supersedes any >/dev/null
check "any supersede sync succeeds" "$(rc sync_supersede_fixture)" "0"
check "any follows different-key hop" "$(grep -c "followed $OLD_A -> $NEW_A (signer $OADDR)" "$LAB/out.txt")" "1"
check "any records signer" "$(python3 - "$M/registry/subscriptions.json" <<'PY'
import json,sys
r=json.load(open(sys.argv[1]))["subscriptions"][0]
print(r["collection"], r["supersede_signer"])
PY
)" "$NEW_A $OADDR"
check "any fetches new collection member" "$(test -f "$(bp "$M" "$DO")"; echo $?)" "0"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
