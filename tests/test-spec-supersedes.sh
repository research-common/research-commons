#!/usr/bin/env bash
# Issue #39: a collection's lineage is declared in its SPEC, not in its manifest.
#
# Before #39 the `supersedes` link that the ingest-policy walk (#11) follows lived only in
# the manifest, which no signature covers. Anyone holding the manifest could strip it, and
# the successor's policy stopped applying to claims against the old id, with every gate
# passing. The repro, reproduced here as the regression:
#   1. a contributor's `publish --force --link related:<old>` on the lead's successor, or a
#      PR that only edits the successor's manifest to `"links": []`, passes every gate;
#   2. after that, a leaky `part-of:<old>` dataset publishes and passes `hub check --base`.
#
# What this pins:
#   1. the spec's `supersedes` list is the authority: stripping the manifest link (by hand
#      or by `publish --force --link …`) does not drop the successor's policy, at the
#      publish gate or at `hub check --base`
#   2. a manifest link the spec does not declare does not count (no lineage by hint), and
#      the resolver says so when that successor carries a policy
#   3. `publish collection --link supersedes:X` is refused unless the spec declares X; the
#      manifest's supersedes links are derived from the spec, also on `--force`
#   4. `hub check` fails on a collection whose manifest hint disagrees with its spec, in
#      both directions, and passes when they agree
#   5. `collection add-member` writes the field, so the safe path needs no extra step
#   6. the spec's list is linted: shape, id form, duplicates, a non-collection target
#   7. browse surfaces (`collection show`, `list --tips-only`) and subscriptions read the
#      same definition: an undeclared hint retires nothing and is never followed
set -uo pipefail

unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"

PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

LAB="$(mktemp -d -t commons-test-spec-sup-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
W="$LAB/work"; mkdir -p "$W"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
KL="$LAB/lead.key"; KC="$LAB/contrib.key"
for k in "$KL" "$KC"; do
  python3 -c "import secrets;print('0x'+secrets.token_hex(32))" > "$k"; chmod 600 "$k"
done
HL="$LAB/hub-lead"; HC="$LAB/hub-contrib"; BARE="$LAB/hub.git"

L() { ( cd "$HL" && COMMONS_ROOT="$HL" COMMONS_AGENT=lead COMMONS_SIGNING_KEY="$KL" "$COMMONS" "$@" ); }
C() { ( cd "$HC" && COMMONS_ROOT="$HC" COMMONS_AGENT=contrib COMMONS_SIGNING_KEY="$KC" "$COMMONS" "$@" ); }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }

"$COMMONS" hub init "$HL" --name spec-sup >/dev/null 2>&1
ADDR_L=$(L peer whoami 2>/dev/null | head -1)
ADDR_C=$(C peer whoami 2>/dev/null | head -1 || true)
if [ -z "$ADDR_L" ]; then
  printf '\033[33mtest-spec-supersedes: signer not functional — skipping\033[0m\n'; exit 0
fi
L peer add "$ADDR_L" --agent-id lead --trust full >/dev/null 2>&1

mkcoll() {  # mkcoll <out> <scope> <ingest-json-or-empty> <supersedes-json-or-empty>
  python3 - "$1" "$2" "$3" "$4" "$ADDR_L" <<'PY'
import json, sys
out, scope, ing, sup, addr = sys.argv[1:6]
spec = {"scope": scope, "maintainers": [{"agent": "lead", "addr": addr}], "members": []}
if ing: spec["ingest"] = json.loads(ing)
if sup: spec["supersedes"] = json.loads(sup)
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
}
links_of() { python3 -c 'import json,sys;print(" ".join("%s:%s"%(l["rel"],l["id"]) for l in json.load(open(sys.argv[1])).get("links",[])))' "$1/registry/artifacts/$2.json"; }
strip_links() { python3 - "$1/registry/artifacts/$2.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p)); m["links"] = []
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
}
ACCT='{"forbidden_keys":["account_id"]}'
# Distinct bytes per call, from mktemp: leak is called as $(leak), in a subshell where a
# counter would not survive, and identical bytes would collapse onto one artifact id.
leak() { local f; f=$(mktemp "$W/leak-XXXXXX"); mv "$f" "$f.jsonl"
         printf '{"account_id":"%s","usd":1}\n' "${f##*-}" > "$f.jsonl"; echo "$f.jsonl"; }
pubds() {  # pubds <who> <file> <collection> [extra]
  local who="$1" f="$2" cl="$3"; shift 3
  rc "$who" publish dataset "$f" "ds $(basename "$f")" --license CC0-1.0 --obtainability open \
     --criteria fixture --link "part-of:$cl" "$@"
}

# ---------------------------------------------------------------- fixtures
head_ "fixtures: the lead's OLD (no policy) and NEW (policy, spec supersedes OLD)"
mkcoll "$W/old.json" "earnings per GB-hour" "" ""
OLD=$(L publish collection "$W/old.json" "old" --license CC-BY-4.0 2>/dev/null | tail -1)
mkcoll "$W/new.json" "earnings per GB-hour (v2)" "$ACCT" "[\"$OLD\"]"
check "a spec-declared supersede publishes WITHOUT --link" \
  "$(rc L publish collection "$W/new.json" "new" --license CC-BY-4.0)" "0"
NEW=$(tail -1 "$W/out.txt")
check "  and the manifest hint is derived from the spec" "$(links_of "$HL" "$NEW")" "supersedes:$OLD"
check "a matching --link is accepted too (idempotent republish)" \
  "$(rc L publish collection "$W/new.json" "new" --license CC-BY-4.0 --link "supersedes:$OLD")" "0"
check "  with the hint unchanged" "$(links_of "$HL" "$NEW")" "supersedes:$OLD"
( cd "$HL" && git add -A && git commit -qm base )
git init -q --bare -b main "$BARE"
( cd "$HL" && git remote add origin "$BARE" && git push -q origin HEAD:main )
git clone -q "$BARE" "$HC"
ADDR_C=$(C peer whoami 2>/dev/null | head -1)
C peer add "$ADDR_C" --agent-id contrib --trust full >/dev/null 2>&1
C peer add "$ADDR_L" --agent-id lead --trust full >/dev/null 2>&1
check "baseline: a contributor's leaky part-of OLD is refused" "$(pubds C "$(leak)" "$OLD")" "1"
check "  by NEW's policy" "$(grep -c "forbidden key 'account_id'.*(policy of $NEW)" "$W/err.txt")" "1"

# ---------------------------------------------------------------- the #39 repro, closed
head_ "repro step 1: a contributor's publish --force --link cannot strip the lineage"
( cd "$HC" && git checkout -qb strip-force )
check "--force with --link supersedes:<other> not in the spec is refused" \
  "$(rc C publish collection "$W/new.json" "new" --force --link "supersedes:cl-00000000")" "1"
check "  saying the spec must declare it" "$(grep -c 'is not declared in the spec' "$W/err.txt")" "1"
check "--force --link related:OLD (the original repro) publishes" \
  "$(rc C publish collection "$W/new.json" "new" --force --link "related:$OLD")" "0"
check "  but the supersede hint is re-derived from the spec, not dropped" \
  "$(links_of "$HC" "$NEW")" "related:$OLD supersedes:$OLD"
check "  and a leaky part-of OLD is still refused" "$(pubds C "$(leak)" "$OLD")" "1"
check "    by NEW's policy" "$(grep -c "(policy of $NEW)" "$W/err.txt")" "1"

head_ "repro step 2: a manifest-only edit stripping the hint changes nothing"
( cd "$HC" && git checkout -q main && git checkout -qb strip-edit )
strip_links "$HC" "$NEW"
check "fixture: NEW's manifest now has no links" "$(links_of "$HC" "$NEW")" ""
check "a leaky part-of OLD is still refused at the publish gate" "$(pubds C "$(leak)" "$OLD")" "1"
check "  by NEW's policy (the spec declares the hop)" "$(grep -c "(policy of $NEW)" "$W/err.txt")" "1"
( cd "$HC" && git add registry && git commit -qm strip-only )
check "hub check --base fails the manifest-only strip itself" \
  "$( ( cd "$HC" && COMMONS_ROOT="$HC" "$COMMONS" hub check --base origin/main ) >"$W/out.txt" 2>&1; echo $?)" "1"
check "  naming the stripped hint" \
  "$(grep -c "PROBLEM: $NEW: spec declares supersedes $OLD but the manifest does not link it" "$W/out.txt")" "1"

head_ "repro step 3: even past a merged strip, the leak is caught at hub check --base"
# Simulate the strip having merged (bypassing the check above): base now has no hint.
( cd "$HC" && git push -q origin strip-edit:main && git fetch -q origin )
( cd "$HC" && git checkout -q -b leak-after origin/main )
LK=$(leak)
check "a leaky part-of OLD is refused at the publish gate" "$(pubds C "$LK" "$OLD")" "1"
check "  forced through with --allow-unchecked-ingest? no: it is a policy hit, not unchecked" \
  "$(grep -c 'refusing to publish — 1 forbidden field name' "$W/err.txt")" "1"
# Hand-assemble the dataset, as a peer on older tooling would.
SNEAK=$(python3 - "$HC" "$OLD" "$LK" <<'PY'
import hashlib, json, os, shutil, sys
root, cid, src = sys.argv[1:4]
raw = open(src, "rb").read(); d = hashlib.sha256(raw).hexdigest(); aid = "ds-" + d[:8]
os.makedirs(os.path.join(root, "store", "sha256", d[:2]), exist_ok=True)
shutil.copy(src, os.path.join(root, "store", "sha256", d[:2], d))
json.dump({"id": aid, "type": "dataset", "schema": "rc.v1", "title": "sneaked",
           "agent": "contrib", "created": "2026-10-01T00:00:00Z", "description": "",
           "tags": [], "content": {"sha256": d, "filename": os.path.basename(src),
                                   "bytes": len(raw)},
           "links": [{"rel": "part-of", "id": cid}], "license": "CC0-1.0",
           "availability": {"obtainability": "open"},
           "verification": {"tier": "T3", "criteria": "x"}},
          open(os.path.join(root, "registry", "artifacts", aid + ".json"), "w"),
          indent=1, sort_keys=True)
print(aid)
PY
)
( cd "$HC" && git add registry store && git commit -qm leak )
( cd "$HC" && COMMONS_ROOT="$HC" "$COMMONS" hub check --base origin/main ) >"$W/out.txt" 2>&1
check "hub check --base refuses the leak against a base with the hint stripped" \
  "$(grep -c "PROBLEM: $SNEAK violates the ingest policy of $OLD: forbidden key 'account_id'.*(policy of $NEW)" "$W/out.txt")" "1"
( cd "$HC" && git checkout -q main && git reset -q --hard "$(git -C "$HL" rev-parse HEAD)" )
( cd "$HC" && git push -q -f origin main )

# ---------------------------------------------------------------- no lineage by hint
head_ "a manifest hint the spec does not declare does not count"
mkcoll "$W/old2.json" "hint-only target" "" ""
OLD2=$(L publish collection "$W/old2.json" "old2" --license CC-BY-4.0 2>/dev/null | tail -1)
mkcoll "$W/new2.json" "hint-only successor" "$ACCT" ""
NEW2=$(L publish collection "$W/new2.json" "new2" --license CC-BY-4.0 2>/dev/null | tail -1)
# A hand-added hint: what a pre-#39 manifest, or a tampered one, looks like.
python3 - "$HL/registry/artifacts/$NEW2.json" "$OLD2" <<'PY'
import json, sys
p, old = sys.argv[1:3]; m = json.load(open(p))
m["links"] = [{"rel": "supersedes", "id": old}]
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
check "a leak part-of OLD2 publishes: the hint is not a lineage" "$(pubds L "$(leak)" "$OLD2")" "0"
check "  OLD2 is not reported as superseded" "$(grep -c "$OLD2 has been superseded" "$W/err.txt")" "0"
check "  and a note names the ignored policy-bearing hint" \
  "$(grep -c "$NEW2: its manifest links supersedes:$OLD2 but its spec does not declare it" "$W/err.txt")" "1"
check "collection show does not mark OLD2 SUPERSEDED" \
  "$(L collection show "$OLD2" 2>/dev/null | grep -c 'SUPERSEDED')" "0"
check "list --tips-only keeps OLD2" \
  "$(L list --type collection --tips-only 2>/dev/null | grep -c "$OLD2")" "1"
( cd "$HL" && COMMONS_ROOT="$HL" "$COMMONS" hub check ) >"$W/out.txt" 2>&1
check "hub check fails the undeclared hint" \
  "$(grep -c "PROBLEM: $NEW2: manifest links supersedes:$OLD2 but the spec does not declare it" "$W/out.txt")" "1"
L publish collection "$W/new2.json" "new2" --force --link "related:$OLD2" >/dev/null 2>&1
check "a --force republish re-derives the hints, dropping the undeclared one" \
  "$(links_of "$HL" "$NEW2")" "related:$OLD2"
( cd "$HL" && COMMONS_ROOT="$HL" "$COMMONS" hub check ) >"$W/out.txt" 2>&1
check "  and hub check passes again" "$(grep -c PROBLEM "$W/out.txt")" "0"

# ---------------------------------------------------------------- publish consistency
head_ "publish collection: --link supersedes must be declared in the spec"
mkcoll "$W/nolist.json" "a successor that forgot the field" "" ""
check "--link supersedes:OLD without the spec field is refused" \
  "$(rc L publish collection "$W/nolist.json" "x" --link "supersedes:$OLD")" "1"
check "  and the message shows the field to add" \
  "$(grep -c "\"supersedes\": \[\"$OLD\"\]" "$W/err.txt")" "1"
check "  nothing was published" \
  "$(ls "$HL/registry/artifacts" | grep -c "^cl-$(sha256sum "$W/nolist.json" | cut -c1-8).json")" "0"
D1=$(L publish dataset "$(leak)" d1 --license CC0-1.0 --obtainability open --criteria x 2>/dev/null | tail -1)
check "datasets keep manifest-link supersedes (only collections changed)" \
  "$(rc L publish dataset "$(leak)" d2 --license CC0-1.0 --obtainability open --criteria x --link "supersedes:$D1")" "0"

head_ "lint: the spec's supersedes list"
for case in '"cl-1234"' '["not-an-id"]' '["cl-12345678","cl-12345678"]' '[7]'; do
  mkcoll "$W/lint.json" "lint $case" "" "$case"
  check "refused: supersedes = $case" "$(rc L publish collection "$W/lint.json" "lint")" "1"
done
DSX=$(L publish dataset "$(leak)" dsx --license CC0-1.0 --obtainability open --criteria x 2>/dev/null | tail -1)
mkcoll "$W/lint.json" "lint dataset target" "" "[\"$DSX\"]"
check "refused: supersedes names a dataset id" "$(rc L publish collection "$W/lint.json" "lint")" "1"
check "  saying it is not a collection id" "$(grep -c "supersedes\[0\] '$DSX' is not a collection id" "$W/err.txt")" "1"
mkcoll "$W/lint.json" "lint unheld target" "" '["cl-abcdef01"]'
check "accepted: an unheld collection id (lazy replication)" "$(rc L publish collection "$W/lint.json" "lint")" "0"

# ---------------------------------------------------------------- migrating a pre-#39 chain
head_ "migrating a pre-#39 chain: OLD3 (no policy) <- MID3 <- TIP3, lineage in hints only"
# The shape a hub has after superseding twice under 0.2.0: the policy was added on the first
# supersede, and both hops exist only as manifest links.
hint() { python3 - "$HL/registry/artifacts/$1.json" "$2" <<'PY'
import json, sys
p, old = sys.argv[1:3]; m = json.load(open(p))
m["links"] = [{"rel": "supersedes", "id": old}]
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
}
mkcoll "$W/old3.json" "migration root" "" ""
OLD3=$(L publish collection "$W/old3.json" "old3" --license CC-BY-4.0 2>/dev/null | tail -1)
mkcoll "$W/mid3.json" "migration middle" "$ACCT" ""
MID3=$(L publish collection "$W/mid3.json" "mid3" --license CC-BY-4.0 2>/dev/null | tail -1)
mkcoll "$W/tip3.json" "migration tip" "$ACCT" ""
TIP3=$(L publish collection "$W/tip3.json" "tip3" --license CC-BY-4.0 2>/dev/null | tail -1)
hint "$MID3" "$OLD3"; hint "$TIP3" "$MID3"
check "before migrating: a leak part-of OLD3 publishes (the root has no policy of its own)" \
  "$(pubds L "$(leak)" "$OLD3")" "0"
mkcoll "$W/m-direct.json" "migration tip v2, direct predecessor only" "$ACCT" "[\"$TIP3\"]"
L publish collection "$W/m-direct.json" "m-direct" --license CC-BY-4.0 >/dev/null 2>&1
check "a new tip declaring only TIP3 still lets a leak part-of OLD3 through" \
  "$(pubds L "$(leak)" "$OLD3")" "0"
mkcoll "$W/m-all.json" "migration tip v2, whole lineage" "$ACCT" "[\"$TIP3\",\"$MID3\",\"$OLD3\"]"
M3=$(L publish collection "$W/m-all.json" "m-all" --license CC-BY-4.0 2>/dev/null | tail -1)
check "a new tip declaring every ancestor refuses a leak part-of OLD3" "$(pubds L "$(leak)" "$OLD3")" "1"
check "  by the new tip's policy" "$(grep -c "(policy of $M3)" "$W/err.txt")" "1"
( cd "$HL" && COMMONS_ROOT="$HL" "$COMMONS" hub check ) >"$W/out.txt" 2>&1
check "hub check still fails the two stale hints" \
  "$(grep -cE "PROBLEM: ($MID3|$TIP3): manifest links supersedes:" "$W/out.txt")" "2"
L publish collection "$W/mid3.json" "mid3" --license CC-BY-4.0 --force >/dev/null 2>&1
L publish collection "$W/tip3.json" "tip3" --license CC-BY-4.0 --force >/dev/null 2>&1
check "a --force republish of each intermediate drops its hint, id unchanged" \
  "$(links_of "$HL" "$MID3")|$(links_of "$HL" "$TIP3")" "|"
( cd "$HL" && COMMONS_ROOT="$HL" "$COMMONS" hub check ) >"$W/out.txt" 2>&1
check "  and hub check passes" "$(grep -c PROBLEM "$W/out.txt")" "0"
check "the policy still holds against OLD3, MID3 and TIP3" \
  "$(for c in "$OLD3" "$MID3" "$TIP3"; do pubds L "$(leak)" "$c"; done | tr -d '\n')" "111"
check "collection show marks the root SUPERSEDED by the new tip" \
  "$(L collection show "$OLD3" 2>/dev/null | grep -c "SUPERSEDED by $M3")" "1"

# ---------------------------------------------------------------- add-member
head_ "collection add-member writes the field"
AM=$(L collection add-member "$NEW" "$DSX" 2>/dev/null | tail -1)
check "add-member publishes a new version" "$(echo "$AM" | grep -cE '^cl-[0-9a-f]{8}$')" "1"
check "  whose spec declares supersedes: [NEW]" \
  "$(L cat "$AM" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("supersedes"))')" "['$NEW']"
check "  and whose manifest hint matches" "$(links_of "$HL" "$AM")" "supersedes:$NEW"
check "a leak part-of OLD now gets NEW's policy two hops back, through AM" \
  "$(pubds L "$(leak)" "$OLD")" "1"
check "  naming AM as current" "$(grep -c "$OLD has been superseded (current: $AM)" "$W/err.txt")" "1"
AM2=$(L collection add-member "$AM" "$D1" 2>/dev/null | tail -1)
check "a second add-member replaces the field (immediate predecessor only)" \
  "$(L cat "$AM2" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("supersedes"))')" "['$AM']"

head_ "housekeeping"
( cd "$HL" && COMMONS_ROOT="$HL" "$COMMONS" fsck ) >"$W/out.txt" 2>&1
check "fsck clean" "$?" "0"

printf '\n\033[1mtest-spec-supersedes: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
