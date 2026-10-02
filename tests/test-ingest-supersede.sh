#!/usr/bin/env bash
# Issue #11: a `part-of` claim against a SUPERSEDED collection must not bypass the
# ingest policy that its maintainers added (or kept) in a later version.
#
# What this pins:
#   1. the policy that applies to part-of:<cid> is the UNION of <cid>'s own policy and
#      every version reachable by MAINTAINER-SIGNED supersedes, forks included, and the
#      output names which version contributed each key
#   2. following the chain only tightens: a later version that drops a key does not
#      relax the claim against an earlier one
#   3. a "successor" signed by someone who is not a maintainer of the collection it
#      supersedes is ignored, in both directions (it cannot relax, and cannot add keys)
#   4. every part-of at a superseded collection warns, policy or not, naming the tip
#   5. lazy replication fails CLOSED: a flagged successor whose spec is not held, or a
#      flagged version past an unheld intermediate, is `unchecked`
#   6. `hub check --base` applies the same union, with the lineage read from git at base
#   7. nothing stops silently: no length limit on the lineage or on the superseders past
#      an unheld spec, an UNVERIFIED successor carrying a policy is `unchecked` rather
#      than dropped, and malformed manifests or ledger lines cannot crash the gate
#
# The display half of the original report (`collection show <tip>` does not list claims
# made against its predecessors) is split out to #8 and is not tested here.
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

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-test-supersede-XXXXXX)"
export COMMONS_AGENT=lead
HUB="$(mktemp -d -t commons-test-supersede-hub-XXXXXX)"
trap 'rm -rf "$COMMONS_ROOT" "$HUB"' EXIT
W="$COMMONS_ROOT/work"; mkdir -p "$W"
KEY="$COMMONS_ROOT/signing.key"; OKEY="$COMMONS_ROOT/outsider.key"
for k in "$KEY" "$OKEY"; do
  python3 -c "import secrets;print('0x'+secrets.token_hex(32))" > "$k"; chmod 600 "$k"
done
export COMMONS_SIGNING_KEY="$KEY"

c() { "$COMMONS" "$@"; }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }

ADDR=$(c peer whoami 2>/dev/null | head -1)
OADDR=$(COMMONS_SIGNING_KEY="$OKEY" c peer whoami 2>/dev/null | head -1)
if [ -z "$ADDR" ] || [ -z "$OADDR" ]; then
  printf '\033[33mtest-ingest-supersede: signer not functional — skipping\033[0m\n'; exit 0
fi
c peer add "$ADDR" --agent-id lead --trust full --note me >/dev/null 2>&1
# The outsider is a FULLY trusted peer on purpose: peer trust is not what makes a supersede
# count. Only being a maintainer of the collection being superseded does.
c peer add "$OADDR" --agent-id outsider --trust full --note outsider >/dev/null 2>&1

mkcoll() {  # mkcoll <outfile> <scope> <maintainer-addr> <ingest-json-or-empty> [supersedes-id]
  python3 - "$@" <<'PY'
import json, sys
out, scope, addr, ing = sys.argv[1:5]
spec = {"scope": scope, "maintainers": [{"agent": "m", "addr": addr}], "members": []}
if ing:
    spec["ingest"] = json.loads(ing)
if len(sys.argv) > 5 and sys.argv[5]:
    spec["supersedes"] = [sys.argv[5]]   # the lineage lives in the spec (#39)
json.dump(spec, open(out, "w"), indent=2)
PY
}
# pubcoll <scope> <ingest-json-or-empty> [supersedes-id] — published by the maintainer.
# Each call gets a unique revision suffix on the scope: two versions with identical specs
# would otherwise be the same content-addressed collection, not a supersede. (mktemp, not a
# counter: this runs as $(pubcoll ...), in a subshell a counter would not survive.)
pubcoll() {
  local f; f=$(mktemp "$W/coll-XXXXXX")
  mkcoll "$f" "$1 (rev ${f##*-})" "$ADDR" "$2" "${3:-}"
  c publish collection "$f" "C: $1" --license CC-BY-4.0 ${3:+--link supersedes:$3} 2>/dev/null | tail -1
}
blob_of() { c get "$1" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])'; }
pubds() {  # pubds <file> <collection> [extra args...]
  local f="$1" cl="$2"; shift 2
  rc c publish dataset "$f" "ds $(basename "$f")" --license CC0-1.0 --obtainability open \
     --link "part-of:$cl" "$@"
}

# Distinct bytes per fixture: ids are content hashes, so a repeated fixture would collapse
# onto an existing artifact. Called as $(csv ...), i.e. in a subshell, so the uniqueness
# comes from mktemp rather than a counter that would not survive the subshell.
csv() {  # csv <header> -> path of a one-row CSV with that header
  local f; f=$(mktemp "$W/fixture-XXXXXX"); mv "$f" "$f.csv"
  printf '%s\n%s\n' "$1" "$(basename "$f")$(echo "$1" | tr -cd ',')" > "$f.csv"; echo "$f.csv"
}

ACCT='{"forbidden_keys":["account_id"]}'

# ---------------------------------------------------------------- the reported gap
head_ "publish gate: part-of a retired collection gets its successor's policy"

V1=$(pubcoll "repro lineage" "")
V2=$(pubcoll "repro lineage" "$ACCT" "$V1")
check "fixtures: v1 and v2 are distinct collections" "$([ -n "$V1" ] && [ "$V1" != "$V2" ] && echo y)" "y"
check "control: a leak part-of the CURRENT collection is refused" "$(pubds "$(csv ts,account_id,usd)" "$V2")" "1"
check "a leak part-of the RETIRED collection is refused too" "$(pubds "$(csv ts,account_id,usd)" "$V1")" "1"
check "  for the forbidden key, attributed to the successor's policy" \
  "$(grep -c "BLOCK $V1 line 1: forbidden key 'account_id'.*(policy of $V2)" "$W/err.txt")" "1"
check "  the refusal is a policy hit, not an unchecked policy" \
  "$(grep -c "refusing to publish — 1 forbidden field name(s) from the ingest policy of $V2 (via part-of $V1)" "$W/err.txt")" "1"
check "  it says the collection is superseded and names the tip" \
  "$(grep -c "warning: $V1 has been superseded (current: $V2)" "$W/err.txt")" "1"
check "  and lists which version contributed which keys" \
  "$(grep -cE "^    $V2: account_id$" "$W/err.txt")" "1"
check "clean data part-of the retired collection still publishes" "$(pubds "$(csv ts,usd)" "$V1")" "0"
check "  with the superseded warning" "$(grep -c "$V1 has been superseded (current: $V2)" "$W/err.txt")" "1"

head_ "two cited ids from one lineage report each key once"
check "a leak part-of BOTH the retired and the current collection is refused" \
  "$(pubds "$(csv ts,account_id,usd)" "$V1" --link "part-of:$V2")" "1"
check "  the key is counted once, not once per cited id" \
  "$(grep -c "refusing to publish — 1 forbidden field name(s)" "$W/err.txt")" "1"
check "  with one BLOCK line" "$(grep -c "^BLOCK .*forbidden key 'account_id'" "$W/err.txt")" "1"

head_ "warns on every part-of at a superseded collection, policy or not"
P1=$(pubcoll "no policy anywhere" "")
P2=$(pubcoll "no policy anywhere" "" "$P1")
check "a leak part-of a superseded policy-free collection publishes" \
  "$(pubds "$(csv ts,account_id)" "$P1")" "0"
check "  but warns that it is superseded, naming the tip" \
  "$(grep -c "warning: $P1 has been superseded (current: $P2)" "$W/err.txt")" "1"
check "part-of the current version publishes" "$(pubds "$(csv ts,account_id)" "$P2")" "0"
check "  with no superseded warning" "$(grep -c 'has been superseded' "$W/err.txt")" "0"

# ---------------------------------------------------------------- only tightens
head_ "a later version that drops a key does not relax an earlier one"
V3=$(pubcoll "repro lineage" "" "$V2")
check "v3 (no policy) supersedes v2" "$([ -n "$V3" ] && [ "$V3" != "$V1" ] && echo y)" "y"
check "a leak part-of v2 is still refused (v2's own keys)" "$(pubds "$(csv ts,account_id,a)" "$V2")" "1"
check "  and names v3 as the current version" \
  "$(grep -c "$V2 has been superseded (current: $V3)" "$W/err.txt")" "1"
check "a leak part-of v1 is still refused (v2's keys, two hops on)" "$(pubds "$(csv ts,account_id,b)" "$V1")" "1"
check "  attributed to v2" "$(grep -c "forbidden key 'account_id'.*(policy of $V2)" "$W/err.txt")" "1"
check "  and names v3, not v2, as current" \
  "$(grep -c "$V1 has been superseded (current: $V3)" "$W/err.txt")" "1"
check "part-of v3 itself enforces only v3's (empty) policy" "$(pubds "$(csv ts,account_id,c)" "$V3")" "0"

# ---------------------------------------------------------------- maintainer-signed only
head_ "a successor not signed by a maintainer is ignored, in both directions"
N1=$(pubcoll "outsider target" "$ACCT")
mkcoll "$W/outsider.json" "outsider target" "$OADDR" '{"forbidden_keys":["usd"]}' "$N1"
N2=$(COMMONS_SIGNING_KEY="$OKEY" COMMONS_AGENT=outsider \
     c publish collection "$W/outsider.json" "C: outsider" --license CC-BY-4.0 \
     --link "supersedes:$N1" 2>/dev/null | tail -1)
check "fixture: the outsider's laxer 'successor' exists" "$(echo "$N2" | grep -c '^cl-')" "1"
check "it cannot relax: a leak part-of the original is still refused" \
  "$(pubds "$(csv ts,account_id,d)" "$N1")" "1"
check "  on the original's own key" "$(grep -c "BLOCK $N1 line 1: forbidden key 'account_id'" "$W/err.txt")" "1"
check "  and the original is not reported as superseded" "$(grep -c 'has been superseded' "$W/err.txt")" "0"
check "it cannot tighten either: its own key is not applied" "$(pubds "$(csv ts,usd)" "$N1")" "0"
check "  nothing about usd is reported" "$(grep -c "forbidden key 'usd'" "$W/err.txt")" "0"
check "  but a note says a policy-bearing successor was ignored, and why" \
  "$(grep -c "$N2: supersedes $N1 and declares an ingest policy, but is not signed by a maintainer of $N1, so it is ignored" "$W/err.txt")" "1"

# ---------------------------------------------------------------- forks
head_ "a fork: the union across every maintainer-signed branch"
F0=$(pubcoll "fork base" "")
FA=$(pubcoll "fork branch a" '{"forbidden_keys":["account_id"]}' "$F0")
FB=$(pubcoll "fork branch b" '{"forbidden_keys":["provider_key"]}' "$F0")
check "a leak carrying both keys part-of the fork base is refused" \
  "$(pubds "$(csv ts,account_id,provider_key)" "$F0")" "1"
check "  branch a's key, attributed to branch a" \
  "$(grep -c "forbidden key 'account_id'.*(policy of $FA)" "$W/err.txt")" "1"
check "  branch b's key, attributed to branch b" \
  "$(grep -c "forbidden key 'provider_key'.*(policy of $FB)" "$W/err.txt")" "1"
check "  both tips are named as current" \
  "$(grep -cE "$F0 has been superseded \(current: ($FA, $FB|$FB, $FA)\)" "$W/err.txt")" "1"
check "only branch b's key is enough to refuse" "$(pubds "$(csv ts,provider_key)" "$F0")" "1"

# ---------------------------------------------------------------- lazy replication
head_ "a flagged successor whose spec is not held: unchecked"
S1=$(pubcoll "unheld successor" "")
S2=$(pubcoll "unheld successor" "$ACCT" "$S1")
SB=$(blob_of "$S2"); mv "$COMMONS_ROOT/store/sha256/${SB:0:2}/$SB" "$W/stash-s2"
check "clean data part-of the retired collection is refused" "$(pubds "$(csv ts,e)" "$S1")" "1"
check "  because the successor's policy cannot be read" \
  "$(grep -c "$S2: ingest_policy (spec is not held here)" "$W/err.txt")" "1"
check "  offering commons fetch of the successor" "$(grep -c "commons fetch $S2" "$W/err.txt")" "1"
check "  and the flag as the alternative" "$(grep -c '\-\-allow-unchecked-ingest' "$W/err.txt")" "1"
mv "$W/stash-s2" "$COMMONS_ROOT/store/sha256/${SB:0:2}/$SB"
check "with the spec back, the same lineage enforces it" "$(pubds "$(csv ts,account_id,f)" "$S1")" "1"

head_ "an unheld intermediate with a flagged later version: unchecked"
U1=$(pubcoll "unheld middle" "")
U2=$(pubcoll "unheld middle" "" "$U1")
U3=$(pubcoll "unheld middle" "$ACCT" "$U2")
UB=$(blob_of "$U2"); mv "$COMMONS_ROOT/store/sha256/${UB:0:2}/$UB" "$W/stash-u2"
check "clean data part-of the first version is refused" "$(pubds "$(csv ts,g)" "$U1")" "1"
check "  naming the flagged later version and why its hop cannot be checked" \
  "$(grep -c "$U3: ingest_policy (it supersedes $U2, whose spec is not held here" "$W/err.txt")" "1"
# The way out is the INTERMEDIATE's spec: U3's own blob is held, and fetching it again
# would not say whether U2's maintainers signed the U2 -> U3 hop.
check "  offering commons fetch of the intermediate, not of the later version" \
  "$(grep -c "commons fetch $U2 " "$W/err.txt")$(grep -c "commons fetch $U3" "$W/err.txt")" "10"
UNCH=$(c publish dataset "$(csv ts,h)" "ds unchecked" --license CC0-1.0 --obtainability open \
       --link "part-of:$U1" --allow-unchecked-ingest 2>"$W/err.txt" | tail -1)
check "--allow-unchecked-ingest publishes" "$(echo "$UNCH" | grep -c '^ds-')" "1"
check "  warning which version was not applied" \
  "$(grep -c "$U1: ingest policy NOT applied (--allow-unchecked-ingest) for $U3" "$W/err.txt")" "1"
check "  and the skip is recorded against the claimed collection" \
  "$(cat "$COMMONS_ROOT"/registry/ledger/*.jsonl | python3 -c '
import json,sys
print(sum(1 for l in sys.stdin if l.strip() and json.loads(l).get("id") == sys.argv[1]
          and json.loads(l).get("ingest_unchecked") == sys.argv[2]))' "$UNCH" "$U1")" "1"
mv "$W/stash-u2" "$COMMONS_ROOT/store/sha256/${UB:0:2}/$UB"
check "with the intermediate held, the later policy is enforced" "$(pubds "$(csv ts,account_id,i)" "$U1")" "1"
check "  attributed to the later version" "$(grep -c "(policy of $U3)" "$W/err.txt")" "1"

# The known hole, documented in resolve_ingest_policy: past an unheld spec, an UNFLAGGED
# later manifest gives nothing to refuse on. Pinned so that changing it is a decision.
Q1=$(pubcoll "unheld middle, no flag" "")
Q2=$(pubcoll "unheld middle, no flag" "" "$Q1")
Q3=$(pubcoll "unheld middle, no flag" "" "$Q2")
QB=$(blob_of "$Q2"); mv "$COMMONS_ROOT/store/sha256/${QB:0:2}/$QB" "$W/stash-q2"
check "an unheld intermediate with no flagged later version publishes" "$(pubds "$(csv ts,j)" "$Q1")" "0"
check "  with a note that the rest of the chain could not be checked" \
  "$(grep -c "$Q2: spec not held here, so 1 later version(s) ($Q3) cannot be checked" "$W/err.txt")" "1"
mv "$W/stash-q2" "$COMMONS_ROOT/store/sha256/${QB:0:2}/$QB"

# ---------------------------------------------------------------- no silent limits
# Review of the first cut: the walk stopped silently after 64 versions, and the walk past
# an unheld spec stopped after 64 superseders. Either way, what lay past the limit was
# never applied, and both limits are reachable: every add-member publishes a version, and
# anyone can publish superseders of anything.
head_ "a long honest lineage: the policy in version 66 still applies to version 1"
L1=$(pubcoll "long lineage" ""); LP="$L1"
for _ in $(seq 2 65); do LP=$(pubcoll "long lineage" "" "$LP"); done
L66=$(pubcoll "long lineage" "$ACCT" "$LP")
check "fixture: 66 distinct versions" \
  "$(cat "$COMMONS_ROOT"/registry/artifacts/cl-*.json | grep -c '"title": "C: long lineage')" "66"
check "a leak part-of version 1 is refused" "$(pubds "$(csv ts,account_id,long)" "$L1")" "1"
check "  attributed to version 66" "$(grep -c "forbidden key 'account_id'.*(policy of $L66)" "$W/err.txt")" "1"
check "  and version 66 is named as current" "$(grep -c "$L1 has been superseded (current: $L66)" "$W/err.txt")" "1"

head_ "a flood of junk superseders cannot hide a flagged version past an unheld spec"
X1=$(pubcoll "flood target" "")
X2=$(pubcoll "flood target" "$ACCT" "$X1")
# 64 junk collections superseding X1, with ids that SORT BEFORE X2: under the old limit
# they filled the walk and X2 was never looked at. Hand-assembled (no ledger entries)
# because who signed them does not matter past an unheld spec, and it keeps this fast.
python3 - "$COMMONS_ROOT" "$X1" "$X2" "$OADDR" <<'PY'
import hashlib, json, os, sys
root, x1, x2, oaddr = sys.argv[1:5]
made, i = [], 0
while len(made) < 64:
    i += 1
    raw = json.dumps({"scope": "junk %d" % i, "members": [],
                      "maintainers": [{"agent": "o", "addr": oaddr}]}).encode()
    d = hashlib.sha256(raw).hexdigest(); cid = "cl-" + d[:8]
    if cid >= x2:
        continue
    os.makedirs(os.path.join(root, "store", "sha256", d[:2]), exist_ok=True)
    open(os.path.join(root, "store", "sha256", d[:2], d), "wb").write(raw)
    json.dump({"id": cid, "type": "collection", "schema": "rc.v1", "title": "junk",
               "agent": "outsider", "created": "2026-09-30T00:00:00Z", "description": "",
               "tags": [], "content": {"sha256": d, "filename": "junk.json", "bytes": len(raw)},
               "links": [{"rel": "supersedes", "id": x1}], "license": "CC-BY-4.0"},
              open(os.path.join(root, "registry", "artifacts", cid + ".json"), "w"))
    made.append((cid, d))
open(os.path.join(root, "junk.list"), "w").write("\n".join("%s %s" % m for m in made) + "\n")
PY
check "fixture: 64 junk superseders, all sorting before the real successor" \
  "$(awk -v x="$X2" '$1 < x' "$COMMONS_ROOT/junk.list" | wc -l | tr -d ' ')" "64"
XB=$(blob_of "$X1"); mv "$COMMONS_ROOT/store/sha256/${XB:0:2}/$XB" "$W/stash-x1"
check "clean data part-of the unheld version is still refused" "$(pubds "$(csv ts,flood)" "$X1")" "1"
check "  naming the flagged real successor" \
  "$(grep -c "$X2: ingest_policy (it supersedes $X1, whose spec is not held here" "$W/err.txt")" "1"
check "  and no junk superseder as unchecked" \
  "$(grep -c "^         cl-[0-9a-f]*: ingest_policy" "$W/err.txt")" "1"
mv "$W/stash-x1" "$COMMONS_ROOT/store/sha256/${XB:0:2}/$XB"
while read -r jid jd; do
  rm -f "$COMMONS_ROOT/registry/artifacts/$jid.json" "$COMMONS_ROOT/store/sha256/${jd:0:2}/$jd"
done < "$COMMONS_ROOT/junk.list"

head_ "a maintainer's successor with no verified signature: unchecked, not dropped"
Y1=$(pubcoll "unsigned successor" "")
mkcoll "$W/y2.json" "unsigned successor (v2)" "$ADDR" "$ACCT" "$Y1"
# Published with no signing key: an unsigned entry, exactly what a maintainer without
# COMMONS_SIGNING_KEY set leaves behind. The policy must not be lost silently.
Y2=$(env -u COMMONS_SIGNING_KEY "$COMMONS" publish collection "$W/y2.json" "C: unsigned v2" \
     --license CC-BY-4.0 --link "supersedes:$Y1" 2>/dev/null | tail -1)
check "fixture: the unsigned successor exists" "$(echo "$Y2" | grep -c '^cl-')" "1"
check "a leak part-of the first version is refused" "$(pubds "$(csv ts,account_id,unsigned)" "$Y1")" "1"
check "  as unchecked, saying the successor has no verified signed publish" \
  "$(grep -c "$Y2: ingest_policy (it supersedes $Y1 but has no verified signed publish here" "$W/err.txt")" "1"
check "  offering a pull for the signed publish" \
  "$(grep -c "commons pull <remote>   # get a signed publish of $Y2" "$W/err.txt")" "1"
check "  and not a blob fetch, which would not help" "$(grep -c "commons fetch $Y2" "$W/err.txt")" "0"
check "--allow-unchecked-ingest publishes" "$(pubds "$(csv ts,unsigned2)" "$Y1" --allow-unchecked-ingest)" "0"
check "  warning which version was not applied" \
  "$(grep -c "$Y1: ingest policy NOT applied (--allow-unchecked-ingest) for $Y2" "$W/err.txt")" "1"
Z1=$(pubcoll "unsigned, no policy" "")
mkcoll "$W/z2.json" "unsigned, no policy (v2)" "$ADDR" "" "$Z1"
Z2=$(env -u COMMONS_SIGNING_KEY "$COMMONS" publish collection "$W/z2.json" "C: unsigned z2" \
     --license CC-BY-4.0 --link "supersedes:$Z1" 2>/dev/null | tail -1)
check "an unsigned successor with no policy does not refuse" "$(pubds "$(csv ts,account_id,z)" "$Z1")" "0"
check "  but a note says it was not followed" \
  "$(grep -c "$Z2: supersedes $Z1 but has no verified signed publish here; not followed" "$W/err.txt")" "1"

head_ "malformed manifests and ledger lines cannot crash the gate"
python3 - "$COMMONS_ROOT" "$V1" <<'PY'
import json, os, sys
root, v1 = sys.argv[1:3]
art = os.path.join(root, "registry", "artifacts")
bad = {
    "cl-badlink1": {"id": "cl-badlink1", "type": "collection", "links": "supersedes:" + v1},
    "cl-badlink2": {"id": "cl-badlink2", "type": "collection",
                    "links": [{"rel": "supersedes", "id": 7}, "x", None]},
    "cl-badcont1": {"id": "cl-badcont1", "type": "collection", "content": ["no"],
                    "links": [{"rel": "supersedes", "id": v1}]},
    "cl-badid001": {"id": ["cl-x"], "type": "collection",
                    "links": [{"rel": "supersedes", "id": v1}]},
}
for name, m in bad.items():
    json.dump(m, open(os.path.join(art, name + ".json"), "w"))
open(os.path.join(art, "cl-notjson1.json"), "w").write("{not json")
with open(os.path.join(root, "registry", "ledger", "zz-malformed.jsonl"), "w") as f:
    for e in ({"action": "publish", "id": ["x"], "sig": "0x00"},
              {"action": "publish", "id": "cl-badcont1", "sig": 5, "addr": 7},
              {"action": "publish", "id": "cl-badcont1", "sig": "0x00", "addr": ["a"]}):
        f.write(json.dumps(e) + "\n")
    f.write("[1,2]\n")
PY
check "a leak part-of v1 is still refused with junk in the registry" "$(pubds "$(csv ts,account_id,junk)" "$V1")" "1"
check "  for the real policy" "$(grep -c "forbidden key 'account_id'.*(policy of $V2)" "$W/err.txt")" "1"
check "  with no traceback" "$(grep -c Traceback "$W/err.txt")" "0"
for f in cl-badlink1 cl-badlink2 cl-badcont1 cl-badid001 cl-notjson1; do
  rm -f "$COMMONS_ROOT/registry/artifacts/$f.json"
done
rm -f "$COMMONS_ROOT/registry/ledger/zz-malformed.jsonl"

# ---------------------------------------------------------------- hub check --base
head_ "hub check --base: the same union, with the lineage read at base"

h() { ( cd "$HUB" && COMMONS_ROOT="$HUB" "$COMMONS" "$@" ); }
hrc() { ( cd "$HUB" && COMMONS_ROOT="$HUB" "$COMMONS" "$@" ) >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
hgit() { git -C "$HUB" "$@"; }
h hub init "$HUB" --name "hub" >/dev/null 2>&1
hgit config user.email t@example.com; hgit config user.name t
h peer add "$ADDR" --agent-id lead --trust full --note me >/dev/null 2>&1
mkcoll "$W/h1.json" "hub lineage" "$ADDR" ""
H1=$(h publish collection "$W/h1.json" "C: hub v1" --license CC-BY-4.0 2>/dev/null | tail -1)
mkcoll "$W/h2.json" "hub lineage" "$ADDR" "$ACCT" "$H1"
H2=$(h publish collection "$W/h2.json" "C: hub v2" --license CC-BY-4.0 --link "supersedes:$H1" 2>/dev/null | tail -1)
# Explicit paths only. The original repro used `git add -A`, which also staged a stray
# leak.csv at the hub root, so `hub check` failed on "non-data path changed" — the right
# exit code for the wrong reason. A stray file is planted on purpose to keep that honest.
printf 'ts,account_id\nx,1\n' > "$HUB/leak.csv"
hgit add .commons-hub .gitignore README.md .github registry store
hgit commit -qm "hub: v1, and v2 adding a policy"
BASE=$(hgit rev-parse HEAD)
check "the base hub passes" "$(hrc hub check)" "0"

# A contribution that never saw the publish gate: hand-assembled manifest + blob, part-of
# the RETIRED id. This is what the unfixed tool's own gate would also have let through.
sneak() {  # sneak <collection> <csv-file> -> prints the dataset id; writes into the hub
  python3 - "$HUB" "$1" "$2" <<'PY'
import hashlib, json, os, shutil, sys
root, cid, src = sys.argv[1:4]
raw = open(src, "rb").read(); d = hashlib.sha256(raw).hexdigest(); aid = "ds-" + d[:8]
os.makedirs(os.path.join(root, "store", "sha256", d[:2]), exist_ok=True)
shutil.copy(src, os.path.join(root, "store", "sha256", d[:2], d))
json.dump({"id": aid, "type": "dataset", "schema": "rc.v1", "title": "sneaked",
           "agent": "outsider", "created": "2026-09-30T00:00:00Z", "description": "",
           "tags": [], "content": {"sha256": d, "filename": os.path.basename(src),
                                   "bytes": len(raw)},
           "links": [{"rel": "part-of", "id": cid}], "license": "CC0-1.0",
           "availability": {"obtainability": "open"},
           "verification": {"tier": "T3", "criteria": "x"}},
          open(os.path.join(root, "registry", "artifacts", aid + ".json"), "w"),
          indent=1, sort_keys=True)
print(aid)
PY
}
LEAKF=$(csv ts,account_id,usd)
SNEAK=$(sneak "$H1" "$LEAKF")
SD=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$LEAKF")
hgit add "registry/artifacts/$SNEAK.json" "store/sha256/${SD:0:2}/$SD"
hgit commit -qm "contribution: part-of the retired id"
check "hub check --base refuses a leak claiming part-of the retired id" "$(hrc hub check --base "$BASE")" "1"
check "  for the policy violation, attributed to the successor" \
  "$(grep -c "PROBLEM: $SNEAK violates the ingest policy of $H1: forbidden key 'account_id'.*(policy of $H2)" "$W/out.txt")" "1"
check "  and for nothing else (no stray non-data path)" "$(grep -c 'PROBLEM' "$W/out.txt")" "1"
check "  it notes the claim is against a superseded collection" \
  "$(grep -c "note: $SNEAK claims part-of $H1, which is superseded (current: $H2)" "$W/out.txt")" "1"
check "  and which version contributed the key" "$(grep -c "policy of $H2: account_id" "$W/out.txt")" "1"

# The lineage is read from git at base, not from the working tree's store: with v2's blob
# missing from disk (but committed at base), the backstop still applies v2's policy.
HB=$(COMMONS_ROOT="$HUB" "$COMMONS" get "$H2" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])')
mv "$HUB/store/sha256/${HB:0:2}/$HB" "$W/stash-h2"
check "with v2's blob gone from the working tree, hub check --base still refuses" \
  "$(hrc hub check --base "$BASE")" "1"
check "  for the same violation, attributed to v2" \
  "$(grep -c "$SNEAK violates the ingest policy of $H1.*(policy of $H2)" "$W/out.txt")" "1"
mv "$W/stash-h2" "$HUB/store/sha256/${HB:0:2}/$HB"

# A PR adding a non-maintainer "successor" changes nothing: it is not maintainer-signed,
# and at base it does not exist at all.
BASE2=$(hgit rev-parse HEAD)
mkcoll "$W/h-out.json" "hub lineage" "$OADDR" "" "$H2"
HO=$(cd "$HUB" && COMMONS_ROOT="$HUB" COMMONS_SIGNING_KEY="$OKEY" COMMONS_AGENT=outsider \
     "$COMMONS" publish collection "$W/h-out.json" "C: outsider" --license CC-BY-4.0 \
     --link "supersedes:$H2" 2>/dev/null | tail -1)
LEAK2=$(csv ts,account_id,usd2)
SNEAK2=$(sneak "$H1" "$LEAK2")
check "fixture: the outsider successor and a second leak exist" \
  "$(echo "$HO $SNEAK2" | grep -cE '^cl-[0-9a-f]+ ds-[0-9a-f]+$')" "1"
hgit add registry store
hgit commit -qm "contribution: a laxer successor and a claim in one commit"
check "a PR adding a laxer successor and a leak in one commit is refused" \
  "$(hrc hub check --base "$BASE2")" "1"
check "  for the leak, still attributed to v2" \
  "$(grep -c "PROBLEM: $SNEAK2 violates the ingest policy of $H1: forbidden key 'account_id'.*(policy of $H2)" "$W/out.txt")" "1"
check "  and v2, not the outsider's version, is reported as current" \
  "$(grep -c "note: $SNEAK2 claims part-of $H1, which is superseded (current: $H2)" "$W/out.txt")" "1"
check "  with no other problem" "$(grep -c 'PROBLEM' "$W/out.txt")" "1"

head_ "housekeeping"
check "fsck clean" "$(rc c fsck)" "0"
check "ledger verifies" "$(rc c log --verify)" "0"

printf '\n\033[1mtest-ingest-supersede: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
