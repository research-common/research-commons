#!/usr/bin/env bash
# Topic-scoped ingest policy: a collection declares field NAMES it refuses to accept.
#
# What this pins:
#   1. the policy lives in the collection spec; the manifest only FLAGS that one exists
#   2. the flag is derived from the spec, never from a CLI argument
#   3. THE BLOB ALWAYS WINS when the flag and the spec disagree, in both directions
#   4. coverage is JSON keys through depth 64, JSONL, CSV headers — and anything else is
#      reported as NOT covered rather than passed silently
#   5. it fails CLOSED: a policy that cannot be read refuses the publish, with two named
#      ways out, and a policy HIT has no override at all
#   6. a deliberate skip is recorded in the ledger and shown by verify/status
#   7. `hub check` compares flag against spec, and enforces policies read from --base
#
# (5) is the load-bearing one and the reason this differs from every other gate here. A
# missed schema check is caught downstream by whoever the bad data breaks. A leak cannot be
# undone: once a signed publish replicates, `retract` is best-effort recall, not erasure.
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

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-test-ingest-XXXXXX)"
export COMMONS_AGENT=test-ingest
trap 'rm -rf "$COMMONS_ROOT" "$HUB"' EXIT
W="$COMMONS_ROOT/work"; mkdir -p "$W"
KEY="$COMMONS_ROOT/signing.key"
python3 -c "import secrets;print('0x'+secrets.token_hex(32))" > "$KEY"; chmod 600 "$KEY"
export COMMONS_SIGNING_KEY="$KEY"

c() { "$COMMONS" "$@"; }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }

ADDR=$(c peer whoami 2>/dev/null | head -1)
c peer add "$ADDR" --agent-id "$COMMONS_AGENT" --trust full --note me >/dev/null 2>&1
if [ -z "$ADDR" ]; then
  printf '\033[33mtest-ingest-policy: signer not functional — skipping\033[0m\n'; exit 0
fi

mkcoll() {  # mkcoll <outfile> <ingest-json-or-empty>
  python3 - "$1" "$ADDR" "$2" <<'PY'
import json, sys
out, addr, ing = sys.argv[1:4]
spec = {"scope": "What a provider earns per resident GB-hour, per hardware class",
        "maintainers": [{"agent": "test-ingest", "addr": addr}],
        "members": [],
        "task_criteria": ">=4 round-robin rounds per arm"}
if ing:
    spec["ingest"] = json.loads(ing)
json.dump(spec, open(out, "w"), indent=2)
PY
}

# Fixtures. Distinct bytes per artifact: ids are content hashes, so reusing a file
# silently collapses two publishes onto one id and short-circuits the gate being tested.
printf '{"ts":"t1","account_id":"acct_81234","job_id":"j1","earned_usd":0.0412}\n' > "$W/leak.jsonl"
printf 'ts,account_id,provider_key,earned_usd\n2026-01-01,a1,pk_live_x,0.04\n'      > "$W/leak.csv"
printf '{"machine":{"machine_ref":"h"},"models":[{"model_id":"m","job_id":"j7"}]}\n' > "$W/leak-nested.json"
printf 'slot,usd_per_gbh\n1,0.041\n2,0.006\n'                                       > "$W/clean.csv"
printf '{"machine_ref":"hmac","models":[{"model_id":"m","acct":"a"}]}\n'             > "$W/nearmiss.json"
printf '{"Account_ID":"acct_81234"}\n'                                              > "$W/case.json"
printf '# notes\nthe account_id field is discussed but is not a key here\n'          > "$W/prose.md"
printf 'slot,usd\n3,0.02\n'                                                         > "$W/clean2.csv"
printf 'slot,usd\n4,0.03\n'                                                         > "$W/clean3.csv"
printf 'slot,usd\n5,0.04\n'                                                         > "$W/clean4.csv"
printf 'slot,usd\n6,0.05\n'                                                         > "$W/clean5.csv"
printf 'slot,usd\n7,0.06\n'                                                         > "$W/t3-criteria.csv"
tar -cf "$W/bundle.tar" -C "$W" clean.csv 2>/dev/null

POLICY='{"forbidden_keys":["account_id","provider_id","provider_key","job_id"]}'

# ---------------------------------------------------------------- the flag is derived
head_ "the manifest flag is derived from the spec, never supplied"

mkcoll "$W/c-policy.json" "$POLICY"
CL=$(c publish collection "$W/c-policy.json" "Collection: with a policy" --license CC-BY-4.0 2>/dev/null)
check "a collection with an ingest block publishes" "$(echo "$CL" | grep -c '^cl-')" "1"
flag() { c get "$1" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin).get("ingest_policy"))'; }
check "its manifest carries ingest_policy" "$(flag "$CL")" "True"
mkcoll "$W/c-nopolicy.json" ""
CL0=$(c publish collection "$W/c-nopolicy.json" "Collection: no policy" --license CC-BY-4.0 2>/dev/null)
check "a collection without one does not carry the flag" "$(flag "$CL0")" "None"
# Derived, so it cannot be asserted independently of the bytes it describes.
check "there is no --ingest-policy argument to set it by hand" \
  "$(rc c publish collection "$W/c-nopolicy.json" "x" --ingest-policy)" "2"

# ---------------------------------------------------------------- the gate
head_ "a claimed collection's policy refuses the publish, per format"

check "JSONL: a forbidden key refuses" \
  "$(rc c publish dataset "$W/leak.jsonl" "raw ledger" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "1"
check "  both offending names are named" \
  "$(grep -cE "forbidden key '(account_id|job_id)'" "$W/err.txt")" "2"
check "  the refusal names the collection whose policy it was" \
  "$(grep -c "ingest policy of $CL" "$W/err.txt")" "1"
check "  and says there is no override" "$(grep -c 'no override' "$W/err.txt")" "1"
# #26: a refused T3 publish must not open with "T3 artifact published …".
check "  a refused T3 publish does not claim it was published" \
  "$(grep -c 'T3 artifact published with default attestation criteria' "$W/err.txt")" "0"
check "CSV header: a forbidden key refuses" \
  "$(rc c publish dataset "$W/leak.csv" "raw ledger csv" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "1"
check "  both CSV header cells are named as such" "$(grep -c 'CSV header cell' "$W/err.txt")" "2"
check "nested JSON: a key at depth refuses" \
  "$(rc c publish dataset "$W/leak-nested.json" "nested" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "1"
check "  the line carrying the key is reported, not '?'" \
  "$(grep -c "line 1: forbidden key 'job_id'" "$W/err.txt")" "1"
# --allow-secrets is for credential-shaped false positives. A policy hit is not one.
check "--allow-secrets does not override a policy hit" \
  "$(rc c publish dataset "$W/leak.csv" "x" --license CC0-1.0 --obtainability open --link "part-of:$CL" --allow-secrets)" "1"
check "--allow-unchecked-ingest does not override a policy hit either" \
  "$(rc c publish dataset "$W/leak.csv" "x" --license CC0-1.0 --obtainability open --link "part-of:$CL" --allow-unchecked-ingest)" "1"

head_ "malformed tails, large datasets, and UTF-8 BOMs cannot hide keys"
python3 - "$W" <<'PY'
import pathlib, sys
w = pathlib.Path(sys.argv[1])
(w / "truncated.jsonl").write_text('{"account_id":1,"x":2}\n{"account_id":5,"x"\n')
(w / "partial-clean.jsonl").write_text('{"slot":1,"x":2}\n{"slot":5,"x"\n')
(w / "malformed.json").write_text('{"account_id":1,"x":\n')
(w / "bom.csv").write_text('\ufeffaccount_id,x\n81234,1\n')
(w / "bom.json").write_text('\ufeff{"account_id":81234,"x":3}\n')
with (w / "late.jsonl").open("w") as f:
    row = '{"slot":1,"x":2}\n'
    f.write(row * ((9 << 20) // len(row)))
    f.write('{"account_id":81234,"x":4}\n')
PY
for fixture in truncated.jsonl late.jsonl bom.csv bom.json; do
  check "$fixture: publish refuses" \
    "$(rc c publish dataset "$W/$fixture" "$fixture" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "1"
  check "  $fixture: refusal is a forbidden-key hit" \
    "$(grep -c "BLOCK.*forbidden key 'account_id'" "$W/err.txt")" "1"
done
for fixture in partial-clean.jsonl malformed.json; do
  check "$fixture: uncovered content may publish" \
    "$(rc c publish dataset "$W/$fixture" "$fixture" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "0"
  check "  $fixture: explicitly reports the malformed line" \
    "$(grep -c '1 line(s) not covered' "$W/err.txt")" "1"
done

head_ "nesting limits disclose incomplete coverage without losing other hits"
python3 - "$W" <<'PY'
import json, pathlib, sys
w = pathlib.Path(sys.argv[1])
def nested(depth):
    node = {"account_id": 7}
    for _ in range(depth):
        node = [node]
    return node
(w / "depth64.json").write_text(json.dumps(nested(64)))
(w / "depth65.json").write_text(json.dumps(nested(65)))
(w / "depth65.jsonl").write_text('{"slot":1}\n' + json.dumps(nested(65)) + '\n')
# Siblings AFTER a skipped subtree must still be visited, in objects and arrays.
(w / "depth-hit.json").write_text(json.dumps({"deep": nested(65), "job_id": 9}))
(w / "depth-hit.jsonl").write_text(
    json.dumps([nested(65), {"provider_id": 8}]) + '\n{"account_id":9}\n')
# Very deep input may hit the parser's recursion limit, depending on Python version.
(w / "depth-bomb.json").write_text('[' * 2000 + '{"account_id":7}' + ']' * 2000)
PY
check "depth 64 is still scanned and blocks" \
  "$(rc c publish dataset "$W/depth64.json" "boundary" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "1"
check "  the boundary key is named" "$(grep -c "BLOCK.*forbidden key 'account_id'" "$W/err.txt")" "1"
check "  a scalar value below the boundary does not cause a coverage warning" \
  "$(grep -c 'not covered' "$W/err.txt")" "0"
for fixture in depth65.json depth65.jsonl; do
  check "$fixture: coverage gap alone does not refuse publish" \
    "$(rc c publish dataset "$W/$fixture" "$fixture" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "0"
  check "  $fixture: nesting limit is explicitly disclosed" \
    "$(grep -c 'nesting beyond 64 levels not covered' "$W/err.txt")" "1"
done
check "JSONL coverage warning identifies the affected line" \
  "$(grep -c 'line 2: nesting beyond 64 levels' "$W/err.txt")" "1"
for fixture in depth-hit.json depth-hit.jsonl; do
  check "$fixture: covered keys still block" \
    "$(rc c publish dataset "$W/$fixture" "$fixture" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "1"
  check "  $fixture: also discloses the nesting gap" \
    "$(grep -c 'nesting beyond 64 levels not covered' "$W/err.txt")" "1"
done
check "array sibling and subsequent JSONL row are both checked" \
  "$(grep -cE "BLOCK.*forbidden key '(provider_id|account_id)'" "$W/err.txt")" "2"
check "very deep JSON publishes with a coverage warning" \
  "$(rc c publish dataset "$W/depth-bomb.json" "depth bomb" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "0"
check "  very deep JSON is explicitly uncovered, whether parsing succeeds or fails" \
  "$(grep -cE '1 line\(s\) not covered|nesting beyond 64 levels not covered' "$W/err.txt")" "1"
check "  very deep JSON does not produce a traceback" \
  "$(grep -c 'Traceback' "$W/err.txt")" "0"

head_ "what the policy must NOT refuse"

check "clean data in the same collection publishes" \
  "$(rc c publish dataset "$W/clean.csv" "measured yield" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "0"
check "  a T3 publish that lands still warns about default criteria, once (#26)" \
  "$(grep -c 'T3 artifact published with default attestation criteria' "$W/err.txt")" "1"
T3WARN='T3 artifact published with default attestation criteria'
rc c publish dataset "$W/clean.csv" "measured yield" --license CC0-1.0 --obtainability open --link "part-of:$CL" >/dev/null
check "  re-publishing the same bytes is a no-op and does not warn again" \
  "$(grep -c "$T3WARN" "$W/err.txt")" "0"
check "  explicit --criteria publishes without the warning" \
  "$(rc c publish dataset "$W/t3-criteria.csv" "with criteria" --license CC0-1.0 --obtainability open --criteria 'one-off export of slot table')" "0"
check "    (no default-criteria warning)" "$(grep -c "$T3WARN" "$W/err.txt")" "0"
# The topic decides, so the same bytes are fine anywhere that has not declared them unsafe.
check "the same leak with no part-of link is unchanged from today" \
  "$(rc c publish dataset "$W/leak.jsonl" "unclaimed ledger" --license CC0-1.0 --obtainability open)" "0"
check "a collection without a policy does not refuse it" \
  "$(rc c publish dataset "$W/leak.csv" "unclaimed csv" --license CC0-1.0 --obtainability open --link "part-of:$CL0")" "0"
# Whole names only: substring matching would flag machine_id, model_id and every other
# legitimate column, and a lint that cries wolf gets bypassed.
check "near-miss names are not flagged (machine_id, model_id, acct)" \
  "$(rc c publish dataset "$W/nearmiss.json" "near miss" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "0"
check "  and nothing was reported about them" "$(grep -c 'forbidden key' "$W/err.txt")" "0"
check "a name differing only in case IS flagged" \
  "$(rc c publish dataset "$W/case.json" "case" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "1"

head_ "uncovered content is reported as uncovered, never as clean"

check "prose publishes, since there are no field names to check" \
  "$(rc c publish dataset "$W/prose.md" "notes" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "0"
check "  but the output says the format is not covered" \
  "$(grep -c 'does not cover this content' "$W/err.txt")" "1"
check "an archive publishes" \
  "$(rc c publish dataset "$W/bundle.tar" "bundle" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "0"
check "  and says the interior was not scanned" \
  "$(grep -c 'archive interior not scanned' "$W/err.txt")" "1"

# ---------------------------------------------------------------- lazy replication
head_ "a policy that cannot be read refuses, with two named ways out"

BLOB=$(c get "$CL" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])')
mv "$COMMONS_ROOT/store/sha256/${BLOB:0:2}/$BLOB" "$W/stashed-blob"
check "manifest-only + flagged refuses even for clean data" \
  "$(rc c publish dataset "$W/clean2.csv" "yield 2" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "1"
check "  the refusal offers commons fetch" "$(grep -c "commons fetch $CL" "$W/err.txt")" "1"
check "  and the flag as the alternative" "$(grep -c '\-\-allow-unchecked-ingest' "$W/err.txt")" "1"
check "  and says why it refuses rather than warns" \
  "$(grep -c 'best-effort recall' "$W/err.txt")" "1"
UNCHECKED=$(c publish dataset "$W/clean3.csv" "yield 3" --license CC0-1.0 --obtainability open \
            --link "part-of:$CL" --allow-unchecked-ingest 2>"$W/err.txt" | tail -1)
check "--allow-unchecked-ingest publishes" "$(echo "$UNCHECKED" | grep -c '^ds-')" "1"
check "  and warns that the policy was not applied" \
  "$(grep -c 'ingest policy NOT applied' "$W/err.txt")" "1"
check "the skip is recorded in the publish ledger event" \
  "$(cat "$COMMONS_ROOT"/registry/ledger/*.jsonl | python3 -c '
import json,sys
print(sum(1 for l in sys.stdin if l.strip() and
          json.loads(l).get("ingest_unchecked") == sys.argv[1]))' "$CL")" "1"
check "verify surfaces the skip" \
  "$([ "$(rc c verify "$UNCHECKED")" = "3" ] && grep -c 'policy NOT applied' "$W/out.txt")" "1"
check "status surfaces the skip" \
  "$([ "$(rc c status "$UNCHECKED")" = "3" ] && grep -c 'policy NOT applied' "$W/out.txt")" "1"
# Disclosure, never grading: the same rule as availability and freshness. Both exit codes
# are the ones a T3 artifact gives anyway (verify: NOT-MACHINE-VERIFIABLE; status: the same
# for a T3 chain grade), and the control below is what makes that assertion non-vacuous.
check "surfacing it does not move verify's exit code" "$(rc c verify "$UNCHECKED")" "3"
check "surfacing it does not move status's exit code" "$(rc c status "$UNCHECKED")" "3"
CONTROL=$(c publish dataset "$W/clean5.csv" "yield 5" --license CC0-1.0 --obtainability open 2>/dev/null | tail -1)
check "  guard the guard: an artifact with no skip exits the same" \
  "$(rc c status "$CONTROL")" "3"
check "  and says nothing about ingest" \
  "$([ "$(rc c status "$CONTROL")" = "3" ] && grep -c 'policy NOT applied' "$W/out.txt")" "0"
# Rule 3 of the design: no flag means nothing to fetch, so nothing changes.
BLOB0=$(c get "$CL0" 2>/dev/null | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])')
mv "$COMMONS_ROOT/store/sha256/${BLOB0:0:2}/$BLOB0" "$W/stashed-blob0"
check "manifest-only + NOT flagged is unchanged from today" \
  "$(rc c publish dataset "$W/clean4.csv" "yield 4" --license CC0-1.0 --obtainability open --link "part-of:$CL0")" "0"
mv "$W/stashed-blob0" "$COMMONS_ROOT/store/sha256/${BLOB0:0:2}/$BLOB0"
mv "$W/stashed-blob" "$COMMONS_ROOT/store/sha256/${BLOB:0:2}/$BLOB"

head_ "the blob wins when the flag disagrees with it, in both directions"

strip_flag() { python3 - "$COMMONS_ROOT" "$1" "$2" <<'PY'
import json, os, sys
root, cid, mode = sys.argv[1:4]
p = os.path.join(root, "registry", "artifacts", cid + ".json")
m = json.load(open(p))
if mode == "strip": m.pop("ingest_policy", None)
else: m["ingest_policy"] = True
json.dump(m, open(p, "w"), indent=1, sort_keys=True)
PY
}
# A peer could strip the flag: manifest fields are outside SIGNED_FIELDS. The policy must
# still be enforced, because the bytes of the spec are what actually declare it.
strip_flag "$CL" strip
check "spec declares a policy, manifest does not: still enforced" \
  "$(rc c publish dataset "$W/leak.csv" "y" --license CC0-1.0 --obtainability open --link "part-of:$CL")" "1"
check "  with a warning that the spec wins" "$(grep -c 'the spec wins' "$W/err.txt")" "1"
strip_flag "$CL" set
# The reverse is benign: a flag over a spec with no policy enforces nothing.
strip_flag "$CL0" set
check "manifest flags a policy, spec has none: nothing enforced" \
  "$(rc c publish dataset "$W/leak.jsonl" "z" --license CC0-1.0 --obtainability open --link "part-of:$CL0")" "0"
check "  with a warning that there is nothing to enforce" \
  "$(grep -c 'nothing.*to enforce' "$W/err.txt")" "1"
strip_flag "$CL0" strip

# ---------------------------------------------------------------- spec lint
head_ "a malformed policy is refused, not silently ignored"
# A policy that looks present and protects nothing is worse than no policy: the maintainer
# stops worrying about the thing it was supposed to catch.
mkcoll "$W/c-badtype.json" '{"forbidden_keys":"account_id"}'
check "forbidden_keys as a bare string is refused" \
  "$(rc c publish collection "$W/c-badtype.json" "x")" "1"
check "  refusal names the field" "$(grep -c 'ingest.forbidden_keys must be' "$W/err.txt")" "1"
mkcoll "$W/c-empty.json" '{"forbidden_keys":[]}'
check "an empty forbidden_keys list is refused" "$(rc c publish collection "$W/c-empty.json" "x")" "1"
mkcoll "$W/c-nonstr.json" '{"forbidden_keys":["ok",7]}'
check "a non-string entry is refused" "$(rc c publish collection "$W/c-nonstr.json" "x")" "1"
mkcoll "$W/c-space.json" '{"forbidden_keys":[" account_id"]}'
check "a key with surrounding whitespace is refused" "$(rc c publish collection "$W/c-space.json" "x")" "1"
mkcoll "$W/c-unknown.json" '{"forbiden_keys":["account_id"]}'
check "a misspelled policy key is refused, not ignored" \
  "$(rc c publish collection "$W/c-unknown.json" "x")" "1"
check "  refusal names the only understood key" \
  "$(grep -c 'only forbidden_keys is understood' "$W/err.txt")" "1"

# ---------------------------------------------------------------- hub check
head_ "hub check: the flag matches the spec, and policies come from --base"

HUB="$(mktemp -d -t commons-test-ingest-hub-XXXXXX)"
h() { COMMONS_ROOT="$HUB" "$COMMONS" "$@"; }
h hub init "$HUB" --name "hub" >/dev/null 2>&1
( cd "$HUB" && git config user.email t@example.com && git config user.name t ) >/dev/null 2>&1
h peer add "$ADDR" --agent-id "$COMMONS_AGENT" --trust full --note me >/dev/null 2>&1
HCL=$(h publish collection "$W/c-policy.json" "Collection: with a policy" --license CC-BY-4.0 2>/dev/null)
( cd "$HUB" && git add -A && git commit -qm "hub: collection with a policy" ) >/dev/null 2>&1
BASE=$( cd "$HUB" && git rev-parse HEAD )
hrc() { ( cd "$HUB" && COMMONS_ROOT="$HUB" "$COMMONS" "$@" ) >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
check "a consistent hub passes" "$(hrc hub check)" "0"
check "  and says it checked the flag" "$(grep -c 'collection manifest hints match the spec' "$W/out.txt")" "1"

# Stripping the flag is the one route that makes a contributor's gate fail open, and the
# hub is the only place holding both halves, so this is where it must be caught.
python3 - "$HUB" "$HCL" strip <<'PY'
import json, os, sys
p = os.path.join(sys.argv[1], "registry", "artifacts", sys.argv[2] + ".json")
m = json.load(open(p)); m.pop("ingest_policy", None)
json.dump(m, open(p, "w"), indent=1, sort_keys=True)
PY
check "a stripped flag fails the gate" "$(hrc hub check)" "1"
check "  and says peers would not know to fetch it" \
  "$(grep -c 'peers would not know to fetch' "$W/out.txt")" "1"
python3 - "$HUB" "$HCL" <<'PY'
import json, os, sys
p = os.path.join(sys.argv[1], "registry", "artifacts", sys.argv[2] + ".json")
m = json.load(open(p)); m["ingest_policy"] = True
json.dump(m, open(p, "w"), indent=1, sort_keys=True)
PY
check "restored, the hub passes again" "$(hrc hub check)" "0"

# A contributor whose tool never ran the gate: hand-assembled manifest + blob, exactly what
# an older build or a peer with the flag stripped would leave behind.
printf 'ts,account_id,provider_key,earned_usd\n2026-02-02,a9,pk_y,0.09\n' > "$W/sneak.csv"
SNEAK=$(python3 - "$HUB" "$HCL" "$W/sneak.csv" <<'PY'
import hashlib, json, os, shutil, sys
root, cid, src = sys.argv[1:4]
raw = open(src, "rb").read(); d = hashlib.sha256(raw).hexdigest(); aid = "ds-" + d[:8]
os.makedirs(os.path.join(root, "store", "sha256", d[:2]), exist_ok=True)
shutil.copy(src, os.path.join(root, "store", "sha256", d[:2], d))
json.dump({"id": aid, "type": "dataset", "schema": "rc.v1", "title": "sneaked ledger",
           "agent": "outsider", "created": "2026-09-28T00:00:00Z", "description": "",
           "tags": [], "content": {"sha256": d, "filename": "sneak.csv", "bytes": len(raw)},
           "links": [{"rel": "part-of", "id": cid}], "license": "CC0-1.0",
           "availability": {"obtainability": "open"},
           "verification": {"tier": "T3", "criteria": "x"}},
          open(os.path.join(root, "registry", "artifacts", aid + ".json"), "w"),
          indent=1, sort_keys=True)
print(aid)
PY
)
( cd "$HUB" && git add -A && git commit -qm "contribution: never saw the gate" ) >/dev/null 2>&1
check "hub check --base catches an artifact that bypassed the publish gate" \
  "$(hrc hub check --base "$BASE")" "1"
check "  naming the artifact and the policy it violates" \
  "$(grep -c "$SNEAK violates the ingest policy of $HCL" "$W/out.txt")" "2"
check "  and saying which ref the policy was read from" \
  "$(grep -c "read from ${BASE:0:12}" "$W/out.txt")" "1"
# Without --base there is no diff to walk, so the backstop is scoped to PRs by design.
check "without --base the same hub passes (no PR scope to check)" "$(hrc hub check)" "0"

# Exercise the same failures through HEAD blob reads, bypassing publish entirely.
python3 - "$HUB" "$SNEAK" "$W" <<'PY'
import hashlib, json, pathlib, sys
root, template, work = pathlib.Path(sys.argv[1]), sys.argv[2], pathlib.Path(sys.argv[3])
for filename in ("truncated.jsonl", "late.jsonl", "bom.csv", "bom.json", "depth65.jsonl"):
    raw = (work / filename).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    aid = "ds-" + digest[:8]
    blob = root / "store" / "sha256" / digest[:2] / digest
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(raw)
    m = json.loads((root / "registry" / "artifacts" / (template + ".json")).read_text())
    m.update(id=aid, title=filename,
             content={"sha256": digest, "filename": filename, "bytes": len(raw)})
    (root / "registry" / "artifacts" / (aid + ".json")).write_text(json.dumps(m))
    (work / (filename + ".id")).write_text(aid)
PY
( cd "$HUB" && git add -A && git commit -qm "contribution: scanner regression inputs" ) >/dev/null 2>&1
check "hub check refuses the regression inputs" "$(hrc hub check --base "$BASE")" "1"
for fixture in truncated.jsonl late.jsonl bom.csv bom.json; do
  check "  $fixture: HEAD blob has an explicit policy violation" \
    "$(grep -c "$(cat "$W/$fixture.id") violates.*forbidden key 'account_id'" "$W/out.txt")" "1"
done
check "hub check discloses partial JSONL coverage" \
  "$(grep -c '1 line(s) not covered' "$W/out.txt")" "1"
check "hub check discloses the nesting limit on a HEAD blob" \
  "$(grep -c "$(cat "$W/depth65.jsonl.id") vs $HCL: nesting beyond 64 levels not covered" "$W/out.txt")" "1"
check "an uncovered deep member is not called a policy violation" \
  "$(grep -c "$(cat "$W/depth65.jsonl.id") violates" "$W/out.txt")" "0"

# Datasets are routinely Parquet/SQLite/tar. Reading blobs through the text-mode `git`
# helper raised UnicodeDecodeError on the first such member, taking the whole gate down —
# so an ordinary binary contribution broke the hub's CI. It must report, not crash.
python3 - "$HUB" "$HCL" <<'PY'
import hashlib, json, os, sys
root, cid = sys.argv[1:3]
raw = bytes(range(256)) * 40 + b"\xff\xfe\x00not utf8"
d = hashlib.sha256(raw).hexdigest(); aid = "ds-" + d[:8]
os.makedirs(os.path.join(root, "store", "sha256", d[:2]), exist_ok=True)
open(os.path.join(root, "store", "sha256", d[:2], d), "wb").write(raw)
json.dump({"id": aid, "type": "dataset", "schema": "rc.v1", "title": "binary member",
           "agent": "outsider", "created": "2026-09-28T00:00:00Z", "description": "",
           "tags": [], "content": {"sha256": d, "filename": "blob.bin", "bytes": len(raw)},
           "links": [{"rel": "part-of", "id": cid}], "license": "CC0-1.0",
           "availability": {"obtainability": "open"},
           "verification": {"tier": "T3", "criteria": "x"}},
          open(os.path.join(root, "registry", "artifacts", aid + ".json"), "w"),
          indent=1, sort_keys=True)
PY
( cd "$HUB" && git add -A && git commit -qm "contribution: a binary dataset" ) >/dev/null 2>&1
BINRC=$(hrc hub check --base "$BASE")
# Exit 1 alone proves nothing here — the sneaked CSV above already earns it, and a crash
# would look the same. What proves the gate survived is that it ran to its LAST check.
check "the gate runs to completion with a binary member present" \
  "$(grep -c 'check: ledger signatures' "$W/out.txt")" "1"
check "  and no traceback reaches the operator" \
  "$(cat "$W/out.txt" "$W/err.txt" | grep -c 'Traceback')" "0"
check "  the binary member is reported as not scanned, not as a violation" \
  "$(grep -c 'binary content not scanned for forbidden keys' "$W/out.txt")" "1"
check "  it is not counted as a policy violation" \
  "$(grep -c 'binary member violates' "$W/out.txt")" "0"
check "  and the real CSV violation is still caught alongside it" \
  "$(grep -c "$SNEAK violates the ingest policy" "$W/out.txt")" "2"
check "  exit code still reflects the real violation" "$BINRC" "1"

head_ "housekeeping"
check "fsck clean" "$(rc c fsck)" "0"
check "reindex clean" "$(rc c reindex)" "0"
check "ledger verifies" "$(rc c log --verify)" "0"

printf '\n\033[1mtest-ingest-policy: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
