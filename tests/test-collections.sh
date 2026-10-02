#!/usr/bin/env bash
# P6 gate (part 1) — collections as the newcomer front door: publish lint, the two
# membership views (endorsed vs claimed) which are ALLOWED to disagree, open-task
# routing, and the machine-readable queue that bridges consume.
set -uo pipefail

# Hermeticity: never inherit the operator's registry/key/exec settings.
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
  echo "test-collections: signer not functional"; exit 1
fi
rm -f "$_PROBEKEY"

LAB="$(mktemp -d -t commons-coll-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export COMMONS_ROOT="$LAB/reg"; export COMMONS_AGENT=test-p6
mkdir -p "$COMMONS_ROOT/registry" "$LAB/w"
cp "$REPO/registry/exec-policy.example.json" "$COMMONS_ROOT/registry/exec-policy.json"
W="$LAB/w"

MKEY="$LAB/m.key"; OKEY="$LAB/o.key"
python3 -c "import secrets;open('$MKEY','w').write('0x'+secrets.token_hex(32))"
python3 -c "import secrets;open('$OKEY','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$MKEY" "$OKEY"
m()   { COMMONS_SIGNING_KEY="$MKEY" "$COMMONS" "$@"; }              # maintainer
o()   { COMMONS_SIGNING_KEY="$OKEY" COMMONS_AGENT=outsider "$COMMONS" "$@"; }
rc()  { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }

# Property, not position: select the address-shaped token, don't hope it's line 1.
MADDR=$(m peer whoami | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
OADDR=$(o peer whoami | grep -oE '0x[0-9a-fA-F]{40}' | head -1)
m peer add "$MADDR" --agent-id test-p6 --trust full >/dev/null
m peer add "$OADDR" --agent-id outsider --trust full >/dev/null

head_ "fixtures"
printf 'avs,claimed\nalpha,900\nbeta,500\n' > "$W/d.csv"
DS=$(m publish dataset "$W/d.csv" "collection dataset" --license CC0-1.0 2>/dev/null)
printf '# Notes\n\nSome prose about the topic.\n' > "$W/wk.md"
WK=$(m publish wiki "$W/wk.md" "Topic wiki" 2>/dev/null)
cat > "$W/body.py" <<'PY'
import csv, json, os
rows = list(csv.DictReader(open(os.environ["IN_D"])))
json.dump({"total": sum(int(r["claimed"]) for r in rows)},
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
WF=$(m publish workflow "$W/wf.json" "collection workflow" 2>/dev/null)
check "fixtures published" "$([ -n "$DS" ] && [ -n "$WK" ] && [ -n "$WF" ] && echo yes)" "yes"

mkcoll() {  # mkcoll <outfile> <overrides-json>
  python3 - "$1" "$DS" "$WK" "$MADDR" "$2" <<'PY'
import json, sys
out, ds, wk, addr, over = sys.argv[1:6]
spec = {"scope": "How much of the promised total actually lands",
        "maintainers": [{"agent": "test-p6", "addr": addr}],
        "members": [{"id": ds, "role": "primary-dataset"},
                    {"id": wk, "role": "canonical-wiki"}],
        "task_criteria": "T0 re-derivations that widen the evidence base",
        "open_questions": ["Is the sample representative?"]}
spec.update(json.loads(over))
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
}

head_ "publish lint — an unowned or unscoped collection cannot curate"
mkcoll "$W/c-ok.json" '{}'
CL=$(m publish collection "$W/c-ok.json" "Claim efficiency" 2>/dev/null)
check "valid collection publishes" "$(echo "$CL" | grep -c '^cl-')" "1"

mkcoll "$W/c-noscope.json" '{"scope": ""}'
check "collection without scope refused" "$(rc m publish collection "$W/c-noscope.json" "x")" "1"
check "refusal names scope" "$(grep -c 'scope is required' "$W/err.txt")" "1"

mkcoll "$W/c-nomaint.json" '{"maintainers": []}'
check "collection without maintainers refused" "$(rc m publish collection "$W/c-nomaint.json" "x")" "1"
check "refusal explains curation needs an owner" \
  "$(grep -c 'unowned collection cannot curate' "$W/err.txt")" "1"

mkcoll "$W/c-noaddr.json" '{"maintainers": [{"agent": "nokey"}]}'
check "maintainer without an addr refused" "$(rc m publish collection "$W/c-noaddr.json" "x")" "1"
check "refusal names the maintainer slot" "$(grep -c 'maintainers\[0\] needs an addr' "$W/err.txt")" "1"

mkcoll "$W/c-badmember.json" '{"members": [{"id": "not-an-id"}]}'
check "malformed member id refused" "$(rc m publish collection "$W/c-badmember.json" "x")" "1"
check "refusal names the member slot" \
  "$(grep -c 'members\[0\] id' "$W/err.txt")" "1"

# Endorsing an artifact we hold only as a manifest must stay legal: curation is an
# editorial act, and coupling it to replication state would defeat lazy blobs.
mkcoll "$W/c-absent.json" '{"members": [{"id": "ds-00000000", "role": "not-here-yet"}]}'
check "endorsing a not-yet-replicated artifact is legal" \
  "$(rc m publish collection "$W/c-absent.json" "Forward reference")" "0"

head_ "collection show — the two membership views"
check "show succeeds" "$(rc m collection show "$CL")" "0"
check "scope rendered" "$(grep -c 'How much of the promised total' "$W/out.txt")" "1"
check "endorsed view labelled" "$(grep -c 'curated-in (ENDORSED' "$W/out.txt")" "1"
check "claimed view labelled" "$(grep -c 'self-declared (CLAIMED' "$W/out.txt")" "1"
check "endorsed count correct" "$(grep -c 'curated-in (ENDORSED — signed editorial list): 2' "$W/out.txt")" "1"
check "dataset listed with its role" \
  "$([ "$(grep -c "$DS.*role primary-dataset" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "member tier shown" "$([ "$(grep -c "$DS.*T3" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "no self-declared members yet" "$(grep -c 'self-declared (CLAIMED — not endorsed by the maintainers): 0' "$W/out.txt")" "1"
check "task_criteria surfaced as 'wanted'" "$(grep -c 'wanted: T0 re-derivations' "$W/out.txt")" "1"
check "open questions surfaced" "$(grep -c 'Is the sample representative' "$W/out.txt")" "1"
check "curator attribution shown" \
  "$([ "$(grep -ci "curated by: $MADDR" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "curator recognised as a maintainer" "$(grep -c '— maintainer' "$W/out.txt")" "1"

# Display label must not overstate an unsigned collection (issue #23): the header
# used to say "ENDORSED — signed editorial list" unconditionally, directly
# contradicting the "curated by: (no verified signed publish event ...)" line
# printed right above it for a collection with no verified signed publish event.
unset COMMONS_SIGNING_KEY
mkcoll "$W/c-unsigned.json" "{\"members\": [{\"id\": \"$DS\", \"role\": \"primary-dataset\"}]}"
CLUNSIGNED=$(COMMONS_SIGNING_KEY= "$COMMONS" publish collection "$W/c-unsigned.json" "Unsigned Collection" --force 2>/dev/null)
check "unsigned collection published" "$([ -n "$CLUNSIGNED" ] && echo yes)" "yes"
check "unsigned collection show succeeds" "$(rc "$COMMONS" collection show "$CLUNSIGNED")" "0"
check "unsigned collection: curated-by says unattributable" \
  "$(grep -c 'no verified signed publish event' "$W/out.txt")" "1"
check "unsigned collection: header is NOT the ENDORSED/signed claim" \
  "$(grep -c 'curated-in (ENDORSED' "$W/out.txt")" "0"
check "unsigned collection: header says UNSIGNED instead" \
  "$(grep -c 'curated-in (UNSIGNED — editorial list, not attributable): 1' "$W/out.txt")" "1"
check "unsigned collection display fix does not change the exit code" "$(rc "$COMMONS" collection show "$CLUNSIGNED")" "0"

head_ "a non-collection is refused, a missing member is reported"
check "collection show on a dataset refused" "$(rc m collection show "$DS")" "1"
check "refusal names the real type" "$(grep -c 'is a dataset, not a collection' "$W/err.txt")" "1"
CLABS=$(m publish collection "$W/c-absent.json" "Forward reference" 2>/dev/null || true)
CLABS=$(m list --type collection 2>/dev/null | awk '{print $1}' | grep -v "^$CL$" | head -1)
check "absent member reported as MISSING, not crashed" \
  "$([ "$(rc m collection show "$CLABS")" = "0" ] && grep -c 'MISSING from this registry' "$W/out.txt")" "1"

head_ "self-declared membership: anyone may claim, nobody is auto-endorsed"
# An outsider points `part-of` at someone else's collection. This must show up as a
# CLAIM and must never appear endorsed — there are no membership permissions by design,
# so the honesty of the rendering is the whole defence.
printf 'outsider,contribution\n1,2\n' > "$W/o.csv"
ODS=$(o publish dataset "$W/o.csv" "outsider contribution" --license MIT \
        --link "part-of:$CL" 2>/dev/null)
check "outsider artifact published with part-of" "$(echo "$ODS" | grep -c '^ds-')" "1"
check "show still succeeds" "$(rc m collection show "$CL")" "0"
check "claim appears in the self-declared view" \
  "$([ "$(grep -c "$ODS" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "self-declared count updated" \
  "$(grep -c 'self-declared (CLAIMED — not endorsed by the maintainers): 1' "$W/out.txt")" "1"
check "marked as claimed, not endorsed" \
  "$([ "$(grep -c "$ODS.*(claimed)" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "endorsed count unchanged by an outsider's claim" \
  "$(grep -c 'curated-in (ENDORSED — signed editorial list): 2' "$W/out.txt")" "1"
check "explains how to endorse" "$(grep -c 'republish' "$W/out.txt")" "1"

head_ "🔒 membership is not evidence — it cannot move a chain grade"
# A collection listing an artifact says "this is relevant", never "this is correct".
# If part-of were an evidence relation, a maintainer could raise or poison the grade
# of work they merely listed.
OUT=$(m run "$WF" --publish --publish-type synthesis --title "derived" 2>/dev/null | awk '{print $1}')
check "T0 derivation grades T3 through its attested-tier dataset (baseline)" \
  "$(rc m status "$OUT")" "3"
# Property, not position: extract the labeled field's value directly.
BEFORE=$(m status "$OUT" 2>/dev/null | sed -n 's/^chain grade: //p')
# Now claim membership in the collection and re-grade: nothing may change.
python3 - "$COMMONS_ROOT/registry/artifacts/$OUT.json" "$CL" <<'PY'
import json, sys
p, cl = sys.argv[1], sys.argv[2]
mm = json.load(open(p))
mm.setdefault("links", []).append({"rel": "part-of", "id": cl})
json.dump(mm, open(p, "w"), indent=2, sort_keys=True)
PY
m reindex >/dev/null 2>&1
AFTER=$(m status "$OUT" 2>/dev/null | sed -n 's/^chain grade: //p')
check "chain grade unchanged by collection membership" "$AFTER" "$BEFORE"
check "part-of does not appear as an evidence edge" \
  "$(m status "$OUT" 2>/dev/null | grep -c 'part-of')" "0"

head_ "mutual membership is marked, not double-counted"
# Endorse the outsider's artifact: it is now in BOTH views and must say so once.
mkcoll "$W/c-mutual.json" "{\"members\": [{\"id\": \"$DS\", \"role\": \"primary-dataset\"}, {\"id\": \"$ODS\", \"role\": \"contributed\"}]}"
CLM=$(m publish collection "$W/c-mutual.json" "Mutual" 2>/dev/null)
# The outsider's part-of points at $CL, not $CLM, so re-point a copy for this check.
ODS2=$(o publish dataset "$W/o.csv" "outsider contribution" --license MIT \
        --link "part-of:$CLM" --force 2>/dev/null)
check "show handles mutual membership" "$(rc m collection show "$CLM")" "0"
check "mutual entry marked in the endorsed view" \
  "$([ "$(grep -c 'also self-declared — mutual' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "mutual entry not repeated as unendorsed" \
  "$(grep -c 'self-declared (CLAIMED — not endorsed by the maintainers): 0' "$W/out.txt")" "1"

head_ "open-task routing: the collection is a front door to work"
mktask() {  # mktask <outfile> <overrides>
  python3 - "$1" "$DS" "$WF" "$MADDR" "$CL" "$2" <<'PY'
import json, sys
out, ds, wf, addr, cl, over = sys.argv[1:7]
spec = {"objective": "Total the claimed column", "priority": 2,
        "expires": "2099-01-01T00:00:00Z",
        "inputs": [{"id": ds}], "execution": {"workflow": wf},
        "verification": {"tier": "T0", "criteria": "byte-identical re-derivation"},
        "beneficiary": {"agent": "test-p6", "addr": addr},
        "collections": [cl]}
spec.update(json.loads(over))
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
}
mktask "$W/t1.json" '{}'
TK=$(m publish task "$W/t1.json" "Routed task" 2>/dev/null)
check "task publishes into the collection" "$(echo "$TK" | grep -c '^tk-')" "1"
check "queue --collection finds it" "$(m queue --collection "$CL" 2>/dev/null | grep -c "$TK")" "1"
check "show counts it as open" \
  "$([ "$(rc m collection show "$CL")" = "0" ] && grep -c 'open tasks: 1' "$W/out.txt")" "1"
check "show lists the open task" "$([ "$(grep -c "$TK" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "show tells a newcomer how to claim" "$(grep -c 'commons claim' "$W/out.txt")" "1"

# A task in a DIFFERENT collection must not be counted here.
mktask "$W/t2.json" "{\"collections\": [\"$CLM\"], \"objective\": \"other collection\"}"
TK2=$(m publish task "$W/t2.json" "Other collection task" 2>/dev/null)
check "other collection's task excluded" \
  "$([ "$(rc m collection show "$CL")" = "0" ] && grep -c 'open tasks: 1' "$W/out.txt")" "1"
check "the other collection sees its own" \
  "$([ "$(rc m collection show "$CLM")" = "0" ] && grep -c 'open tasks: 1' "$W/out.txt")" "1"

# Claiming moves it out of the open count without losing it.
o claim "$TK" >/dev/null 2>&1
check "claimed task no longer counted as open" \
  "$([ "$(rc m collection show "$CL")" = "0" ] && grep -c 'open tasks: 0  (1 claimed' "$W/out.txt")" "1"

head_ "publish lint rejects a task naming a non-collection"
mktask "$W/t-badcoll.json" "{\"collections\": [\"$DS\"]}"
check "task routed to a dataset refused" "$(rc m publish task "$W/t-badcoll.json" "x")" "1"
check "refusal names the real type" \
  "$([ "$(grep -c 'is a dataset, not a collection' "$W/err.txt")" -ge 1 ] && echo yes)" "yes"
mktask "$W/t-nocoll.json" '{"collections": ["cl-deadbeef"]}'
check "task routed to an unknown collection refused" "$(rc m publish task "$W/t-nocoll.json" "x")" "1"

head_ "queue --json: bridges must never scrape the human table"
check "queue --json is valid JSON" \
  "$(m queue --json --all 2>/dev/null | python3 -c 'import json,sys;json.load(sys.stdin);print("yes")')" "yes"
check "carries the fields a bridge needs" \
  "$(m queue --json --all 2>/dev/null | python3 -c '
import json,sys
rows = json.load(sys.stdin)
need = {"id","state","priority","tier","criteria","objective","workflow","beneficiary","collections","expires"}
print("yes" if rows and all(need <= set(r) for r in rows) else "no")')" "yes"
check "queue rejects an unknown collection" "$(rc m queue --json --collection cl-deadbeef)" "1"
check "unknown collection diagnostic names the subject" \
  "$(grep -c 'no such artifact: cl-deadbeef' "$W/err.txt")" "1"
check "queue rejects a malformed collection id" "$(rc m queue --json --collection bad/id)" "1"
check "valid collection filter may return an empty JSON array" \
  "$(m queue --json --claimed --collection "$CLM" 2>/dev/null | tr -d ' \n')" "[]"
check "queue rejects an unknown peer name" "$(rc m queue --json --peer typo-peer)" "1"
check "unknown peer diagnostic names the subject" \
  "$(grep -c 'no such peer: typo-peer' "$W/err.txt")" "1"
check "valid peer filter still finds its task" \
  "$(m queue --json --peer test-p6 2>/dev/null | python3 -c 'import json,sys; print(any(r["id"] == sys.argv[1] for r in json.load(sys.stdin)))' "$TK")" "True"
check "--json respects --collection" \
  "$(m queue --json --all --collection "$CL" 2>/dev/null | python3 -c '
import json,sys; print(len(json.load(sys.stdin)))')" "1"

head_ "front-door disambiguation (2026-08-28)"
# Duplicate scope, NOT supersede-linked: $CL and $CLM share the exact scope text
# from mkcoll's default (c-mutual.json only overrides members): an accidental mirror
# of one collection under a second id, minus the supersede link.
# The flagged ids are sorted by content-derived id, so which one prints FIRST after
# "duplicate-scope:" varies per run (fixture hashes differ each run). Match the id
# anywhere on the advisory line, not at a fixed position — this was a 1-in-3 flake.
check "collection show flags duplicate scope (no supersede link)" \
  "$([ "$(rc m collection show "$CL")" = "0" ] && grep '^⚠ duplicate-scope:' "$W/out.txt" | grep -c "$CLM")" "1"
check "duplicate-scope flag is symmetric" \
  "$([ "$(rc m collection show "$CLM")" = "0" ] && grep '^⚠ duplicate-scope:' "$W/out.txt" | grep -c "$CL")" "1"
check "duplicate-scope advisory does not move the exit code" "$(rc m collection show "$CL")" "0"

# Now build the actual retirement case: a new collection that supersedes $CL, with
# the same scope text (the live fixture is byte-identical scope across the pair).
mkcoll "$W/c-super.json" '{"open_questions": ["Is the sample representative?", "successor fixture"]}'
CLSUP=$(m publish collection "$W/c-super.json" "Successor" --link "supersedes:$CL" 2>/dev/null)
m reindex >/dev/null 2>&1
check "successor collection publishes" "$(echo "$CLSUP" | grep -c '^cl-')" "1"
check "collection show marks the retired one SUPERSEDED" \
  "$([ "$(rc m collection show "$CL")" = "0" ] && grep -c "SUPERSEDED by $CLSUP" "$W/out.txt")" "1"
check "SUPERSEDED marker does not move the exit code" "$(rc m collection show "$CL")" "0"
check "a supersede-linked pair is NOT ALSO flagged duplicate-scope against its own successor" \
  "$([ "$(rc m collection show "$CL")" = "0" ] && grep -c "duplicate-scope: $CLSUP\b" "$W/out.txt")" "0"
check "the successor itself carries no SUPERSEDED marker" \
  "$([ "$(rc m collection show "$CLSUP")" = "0" ] && grep -c 'SUPERSEDED by' "$W/out.txt")" "0"

head_ "front-door disambiguation: list/search --json and --tips-only"
check "list --json carries superseded_by on the retired collection" \
  "$(m list --type collection --json 2>/dev/null | python3 -c '
import json,sys
rows={r["id"]:r for r in json.load(sys.stdin)}
print(rows["'"$CL"'"]["superseded_by"])' )" "['"$CLSUP"']"
check "list --json reports empty superseded_by for a non-superseded collection" \
  "$(m list --type collection --json 2>/dev/null | python3 -c '
import json,sys
rows={r["id"]:r for r in json.load(sys.stdin)}
print(rows["'"$CLSUP"'"]["superseded_by"])' )" "[]"
check "list --tips-only hides the retired collection" \
  "$(m list --type collection --tips-only 2>/dev/null | grep -c "$CL ")" "0"
check "list --tips-only keeps the successor" \
  "$(m list --type collection --tips-only 2>/dev/null | grep -c "$CLSUP")" "1"
check "plain list (no flag) is byte-identical to before --tips-only existed" \
  "$(m list --type collection 2>/dev/null | grep -c "$CL ")" "1"
check "search --tips-only also hides the retired collection" \
  "$(m search promised --type collection --tips-only 2>/dev/null | grep -c "$CL ")" "0"
check "non-collection JSON rows still carry the new keys (additive, not type-gated)" \
  "$(m list --type dataset --json 2>/dev/null | python3 -c 'import json,sys; r=json.load(sys.stdin)[0]; print("superseded_by" in r and "agent_mismatch" in r)')" "True"

head_ "front-door disambiguation: signed-publisher mismatch marker"
# The maintainer publishes with an --agent string that does NOT match their own
# registered peer agent name ("test-p6"): the manifest says one agent, but the
# signature resolves to a registered peer with a different name.
MSPOOF() { COMMONS_SIGNING_KEY="$MKEY" COMMONS_AGENT=someone-else "$COMMONS" "$@"; }
mkcoll "$W/c-spoof.json" '{"scope": "A distinct scope so this is new content, not a republish"}'
SPOOFCL=$(MSPOOF publish collection "$W/c-spoof.json" "Spoofed agent field" 2>/dev/null)
m reindex >/dev/null 2>&1
check "spoofed-agent collection publishes" "$(echo "$SPOOFCL" | grep -c '^cl-')" "1"
check "list --json flags the agent mismatch" \
  "$(m list --type collection --json 2>/dev/null | python3 -c '
import json,sys
rows={r["id"]:r for r in json.load(sys.stdin)}
print(rows["'"$SPOOFCL"'"]["agent_mismatch"], rows["'"$SPOOFCL"'"]["verified_agent"])' )" "True test-p6"
check "list --json shows no mismatch for a normally-published collection" \
  "$(m list --type collection --json 2>/dev/null | python3 -c '
import json,sys
rows={r["id"]:r for r in json.load(sys.stdin)}
print(rows["'"$CL"'"]["agent_mismatch"])' )" "False"

head_ "collection add-member: endorsement without hand-editing JSON"
# The documented endorsement flow was: edit collection.json, `publish collection …
# --link supersedes:<old>`. add-member must produce exactly that, through the same lint.
#
# These arms deliberately publish their OWN base collection rather than reusing $CL.
# $CL is superseded by $CLSUP above, and building an update on a retired version is the
# defect the stale-base arms below exist to pin — so using it for the happy path would
# assert the buggy behaviour as correct.
mkcoll "$W/c-am.json" '{"scope": "add-member fixture: endorsement without a hand-edit"}'
AMCL=$(m publish collection "$W/c-am.json" "Add-member fixture" --license CC-BY-4.0 2>/dev/null)
printf 'late,1\n' > "$W/late.csv"
LATE=$(o publish dataset "$W/late.csv" "late contribution" --license CC0-1.0 --obtainability open 2>/dev/null)
NEWCL=$(m collection add-member "$AMCL" "$LATE" --role primary-dataset 2>"$W/am-err.txt")
check "add-member publishes a new collection" "$(echo "$NEWCL" | grep -cE '^cl-[0-9a-f]{8}$')" "1"
check "new id differs (content-addressed update)" "$([ "$NEWCL" != "$AMCL" ] && echo yes)" "yes"
check "reports the change on stderr" "$(grep -c "$LATE added as primary-dataset" "$W/am-err.txt")" "1"
check "new collection supersedes the old one" \
  "$(m get "$NEWCL" | python3 -c "import json,sys;m=json.load(sys.stdin);print([l['id'] for l in m['links'] if l['rel']=='supersedes'])")" "['$AMCL']"
check "member endorsed in the new collection, with its role" \
  "$(m collection show "$NEWCL" | grep "$LATE" | grep -c 'role primary-dataset')" "1"
check "existing members carried over" \
  "$(m collection show "$NEWCL" | grep -c 'curated-in (ENDORSED — signed editorial list): 3')" "1"
check "scope/maintainers/task_criteria carried over" \
  "$(m collection show "$NEWCL" | grep -cE 'add-member fixture|wanted: T0 re-derivations')" "2"
check "title carried over" "$(m get "$NEWCL" | python3 -c "import json,sys;print(json.load(sys.stdin)['title'])")" "Add-member fixture"
lic() { m get "$1" | python3 -c 'import json,sys;print(json.load(sys.stdin).get("license"))'; }
# Endorsing must not strip a disclosure the maintainers made, for the same reason
# title/description/tags are carried: nothing would report the loss.
check "  the base declared a licence (guard the guard)" "$(lic "$AMCL")" "CC-BY-4.0"
check "licence carried over" "$(lic "$NEWCL")" "CC-BY-4.0"
check "old collection untouched (still 2 members)" \
  "$(m collection show "$AMCL" | grep -c 'curated-in (ENDORSED — signed editorial list): 2')" "1"
check "old collection now shows it is superseded" \
  "$(m collection show "$AMCL" | grep -c "$NEWCL")" "1"
check "re-adding the same member is refused" "$(rc m collection add-member "$NEWCL" "$LATE" --role primary-dataset)" "1"
check "refusal says nothing to publish" "$(grep -c 'already a member' "$W/err.txt")" "1"
ROLECL=$(m collection add-member "$NEWCL" "$LATE" --role secondary-dataset 2>"$W/am-err.txt")
check "role change on an existing member republishes" "$(echo "$ROLECL" | grep -c '^cl-')" "1"
check "role change reported" "$(grep -c 'role primary-dataset -> secondary-dataset' "$W/am-err.txt")" "1"
check "role change does not duplicate the member" \
  "$(m collection show "$ROLECL" | grep -c "$LATE")" "1"
check "malformed member id refused" "$(rc m collection add-member "$NEWCL" not-an-id)" "1"
check "non-collection target refused" "$(rc m collection add-member "$DS" "$LATE")" "1"
check "a collection cannot endorse itself" "$(rc m collection add-member "$ROLECL" "$ROLECL")" "1"
check "method role on a dataset refused by the shared lint" \
  "$(rc m collection add-member "$ROLECL" "$DS" --role method)" "1"
check "  refusal comes from lint_collection_spec" "$(grep -c 'a method is a skill or workflow' "$W/err.txt")" "1"
check "outsider refused (would be a fork, not an update)" \
  "$(rc o collection add-member "$ROLECL" "$WF")" "1"
check "  refusal names maintainer + fork" "$(grep -c 'not a listed maintainer' "$W/err.txt")" "1"
check "outsider --force publishes the fork" "$(rc o collection add-member "$ROLECL" "$WF" --force)" "0"
check "not-held member is endorsed with a warning (lazy replication)" \
  "$(rc m collection add-member "$ROLECL" ds-0000beef)" "0"
check "  warning names lazy replication" "$(grep -c 'lazy replication' "$W/err.txt")" "1"
check "show rejects a stray member argument" "$(rc m collection show "$AMCL" "$LATE")" "1"
check "ledger verifies after add-member" "$(rc m log --verify)" "0"

head_ "add-member: a retired base is refused, because the drop would be silent"
# The one failure a hand-edit cannot catch. Adding to a superseded version republishes a
# spec that predates every endorsement made since; the result is well-formed, correctly
# signed, and passes `hub check`, so the dropped members just stop being endorsed with
# nothing reporting it. Build the case with add-member itself, which also proves the
# command's own output is a usable base.
mkcoll "$W/c-stale.json" '{"scope": "stale-base fixture"}'
STALECL=$(m publish collection "$W/c-stale.json" "Stale base" 2>/dev/null)
STALESUP=$(m collection add-member "$STALECL" "$LATE" --role primary-dataset 2>/dev/null)
# Two hops, not one. A one-hop lookup suggested a version that is ITSELF retired, so the
# operator ran the suggested command, got refused again, and walked the chain by hand — and
# the dropped-member list, measured against the near successor, understated the loss.
printf 'hop,2\n' > "$W/hop2.csv"
HOP2=$(o publish dataset "$W/hop2.csv" "second-hop contribution" --license CC0-1.0 --obtainability open 2>/dev/null)
STALETIP=$(m collection add-member "$STALESUP" "$HOP2" --role instance 2>/dev/null)
m reindex >/dev/null 2>&1
check "add-member on a superseded base is refused" \
  "$(rc m collection add-member "$STALECL" "$WF" --role method)" "1"
check "  refusal says the base is retired" \
  "$(grep -c "$STALECL has been superseded" "$W/err.txt")" "1"
check "  the suggested command names the TIP, not the next hop" \
  "$(grep -c "collection add-member $STALETIP $WF --role method" "$W/err.txt")" "1"
check "  and does not name the intermediate version as the one to use" \
  "$(grep -c "collection add-member $STALESUP " "$W/err.txt")" "0"
check "  it says how far behind the base is" \
  "$(grep -c '2 supersedes later' "$W/err.txt")" "1"
check "  refusal names BOTH endorsements that would be dropped" \
  "$(grep -A3 'would be dropped' "$W/err.txt" | grep -cE "$LATE|$HOP2")" "2"
check "  refusal points at its own named hatch" \
  "$(grep -c '\-\-allow-retired-base republishes from this version' "$W/err.txt")" "1"
# The two refusals cost different amounts, so they get different opt-ins. --force means
# "I am not a maintainer and mean to fork"; it must NOT also wave through the refusal whose
# failure mode is silent data loss. The planned member-schema gate wants --force too,
# so this separation is what stops a
# future schema override from silently dropping endorsements as a side effect.
check "--force alone does NOT bypass the retired-base refusal" \
  "$(rc m collection add-member "$STALECL" "$WF" --role method --force)" "1"
check "  still refuses for the retired base, not the maintainer check" \
  "$(grep -c "$STALECL has been superseded" "$W/err.txt")" "1"
check "--allow-retired-base publishes from the retired base" \
  "$(rc m collection add-member "$STALECL" "$WF" --role method --allow-retired-base)" "0"
check "  and warns rather than forking silently" \
  "$(grep -c "warning: $STALECL has been superseded" "$W/err.txt")" "1"
# The override path is the ONLY one where a member is really lost, and it was the one that
# truncated the list naming them: the trailing-hint slice removed a dropped id instead.
check "  the dropped endorsements are still named on the override path" \
  "$(grep -A3 'would be dropped' "$W/err.txt" | grep -cE "$LATE|$HOP2")" "2"
check "  both dropped ids are present as list entries, not one" \
  "$(grep -A3 'would be dropped' "$W/err.txt" | grep -cE '^ {4}ds-')" "2"
check "a live collection is not treated as retired" \
  "$(rc m collection add-member "$STALETIP" "$WF" --role method)" "0"

# A fork has no single current version, so choosing one for the operator would be
# settling an editorial dispute. Refuse and list them instead.
mkcoll "$W/c-fork.json" '{"scope": "fork-base fixture"}'
FORKCL=$(m publish collection "$W/c-fork.json" "Fork base" 2>/dev/null)
mkcoll "$W/c-forkA.json" '{"scope": "fork-base fixture, branch A"}'
FORKA=$(m publish collection "$W/c-forkA.json" "Fork A" --link "supersedes:$FORKCL" 2>/dev/null)
mkcoll "$W/c-forkB.json" '{"scope": "fork-base fixture, branch B"}'
FORKB=$(m publish collection "$W/c-forkB.json" "Fork B" --link "supersedes:$FORKCL" 2>/dev/null)
m reindex >/dev/null 2>&1
check "a forked base is refused" "$(rc m collection add-member "$FORKCL" "$LATE")" "1"
check "  both successors are listed" \
  "$(grep -cE "$FORKA|$FORKB" "$W/err.txt")" "2"
check "  no single winner is recommended" \
  "$(grep -c 'Use the current version instead' "$W/err.txt")" "0"
check "  the operator is told to resolve the fork" "$(grep -c 'Resolve the fork first' "$W/err.txt")" "1"

head_ "add-member: nothing but members[] changes"
# The blob HAS to change — a new member is new content and so a new id — so "preserve"
# can only mean semantic: every other key identical, including keys this tool knows
# nothing about, and the maintainer's own key order left alone so two versions of a spec
# still diff readably.
python3 - "$W/c-order.json" "$DS" "$MADDR" <<'PY'
import json, sys
out, ds, addr = sys.argv[1:4]
# Deliberately NOT alphabetical, and carrying a key the tool has never heard of.
spec = {"scope": "key-order fixture",
        "zz_house_style": {"review": "two maintainers", "nested": [1, 2, 3]},
        "maintainers": [{"agent": "test-p6", "addr": addr}],
        "members": [{"id": ds, "role": "primary-dataset"}],
        "aa_custom": "must survive",
        "task_criteria": "T0 re-derivations that widen the evidence base"}
json.dump(spec, open(out, "w"), indent=2)   # no sort_keys: the point of the fixture
PY
ORDCL=$(m publish collection "$W/c-order.json" "Order fixture" 2>/dev/null)
ORDNEW=$(m collection add-member "$ORDCL" "$LATE" --role instance 2>/dev/null)
m cat "$ORDCL" > "$W/ord-old.json" 2>/dev/null
m cat "$ORDNEW" > "$W/ord-new.json" 2>/dev/null
check "every key except members is byte-identical in value" \
  "$(python3 -c '
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
print({k: v for k, v in a.items() if k != "members"} == {k: v for k, v in b.items() if k != "members"})' \
  "$W/ord-old.json" "$W/ord-new.json")" "True"
check "key order is preserved, not sorted" \
  "$(python3 -c '
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
print(list(a.keys()) == list(b.keys()))' "$W/ord-old.json" "$W/ord-new.json")" "True"
check "  and that order was genuinely unsorted (guard the guard)" \
  "$(python3 -c '
import json, sys
k = list(json.load(open(sys.argv[1])).keys())
print(k != sorted(k))' "$W/ord-new.json")" "True"
check "an unknown top-level key survives intact" \
  "$(python3 -c '
import json, sys
print(json.load(open(sys.argv[1]))["zz_house_style"]["nested"])' "$W/ord-new.json")" "[1, 2, 3]"
check "members gains exactly one entry" \
  "$(python3 -c '
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
print(len(b["members"]) - len(a["members"]))' "$W/ord-old.json" "$W/ord-new.json")" "1"
check "the pre-existing member entry is untouched" \
  "$(python3 -c '
import json, sys
a = json.load(open(sys.argv[1])); b = json.load(open(sys.argv[2]))
print(b["members"][0] == a["members"][0])' "$W/ord-old.json" "$W/ord-new.json")" "True"

head_ "add-member: an unrecognised role warns, because a typo is a silent re-filing"
# Roles are free text and only `method`/`instance` are interpreted, so a misspelling is
# not an error — it files the member under a bucket the maintainer did not mean. Warn,
# never refuse: a genuinely new role has to be addable.
TYPOCL=$(m collection add-member "$ORDNEW" "$WK" --role primry-dataset 2>"$W/am-err.txt")
check "an unseen role warns" "$(grep -c "role 'primry-dataset' appears nowhere else" "$W/am-err.txt")" "1"
check "  the warning lists the roles actually in use" \
  "$(grep -c 'roles in use: instance, primary-dataset' "$W/am-err.txt")" "1"
check "  and it is a warning, not a refusal" "$(echo "$TYPOCL" | grep -c '^cl-')" "1"
m collection add-member "$TYPOCL" "$WF" --role primary-dataset 2>"$W/am-err.txt" >/dev/null
check "a role already in use does not warn" "$(grep -c 'appears nowhere else' "$W/am-err.txt")" "0"
mkcoll "$W/c-firstrole.json" '{"scope": "first-role fixture", "members": []}'
FRCL=$(m publish collection "$W/c-firstrole.json" "First role" 2>/dev/null)
m collection add-member "$FRCL" "$WF" --role method 2>"$W/am-err.txt" >/dev/null
check "the interpreted roles never warn, even as the first member" \
  "$(grep -c 'appears nowhere else' "$W/am-err.txt")" "0"

head_ "add-member: a change that reproduces an existing version is refused"
# r1 -> r2 -> r1 reproduces the first version's exact bytes. `publish` would then report
# "already published … manifest unchanged" and exit 0, while the live head stayed on r2 — a
# success message over a state the operator did not get, which is the same silent-wrong-state
# shape the retired-base guard exists for.
mkcoll "$W/c-flip.json" '{"scope": "flip-back fixture", "members": []}'
FLIP1=$(m publish collection "$W/c-flip.json" "Flip fixture" 2>/dev/null)
FLIP2=$(m collection add-member "$FLIP1" "$LATE" --role instance 2>/dev/null)
FLIP3=$(m collection add-member "$FLIP2" "$LATE" --role other-role 2>/dev/null)
check "flipping the role back is refused rather than reported as success" \
  "$(rc m collection add-member "$FLIP3" "$LATE" --role instance)" "1"
check "  the refusal names the version it would reproduce" \
  "$(grep -c "reproduces $FLIP2" "$W/err.txt")" "1"
check "  and names the version that would stay live" \
  "$(grep -c "leaving $FLIP3 as the live version" "$W/err.txt")" "1"
check "  a role change to something genuinely new still works" \
  "$(rc m collection add-member "$FLIP3" "$LATE" --role third-role)" "0"

head_ "the newcomer path works end to end"
# list collections -> show one -> queue it -> claim. This is the documented front door,
# so it is worth asserting as a path rather than as four unrelated commands.
check "collections are discoverable by type" \
  "$(m list --type collection 2>/dev/null | grep -c "$CL")" "1"
check "search finds a collection by scope text" \
  "$(m search promised --type collection 2>/dev/null | grep -c "$CL")" "1"
# Same reasoning for tasks: the objective lives in the signed blob, but a queue you
# can only browse by priority is not discoverable by subject.
check "search finds a task by its objective" \
  "$(m search claimed --type task 2>/dev/null | grep -c "$TK")" "1"
check "search finds a collection by its task_criteria" \
  "$([ "$(m search re-derivations --type collection 2>/dev/null | grep -c "$CL")" -ge 1 ] && echo yes)" "yes"
# The index is derived state: a rebuild must not lose spec-sourced text.
m reindex >/dev/null 2>&1
check "spec text survives a reindex" \
  "$(m search promised --type collection 2>/dev/null | grep -c "$CL")" "1"
check "ledger recorded the collection publish" \
  "$(m log -n 50 2>/dev/null | grep -c "\"id\": \"$CL\"")" "1"
check "log --verify clean after all of it" "$(rc m log --verify)" "0"
check "fsck clean" "$(rc m fsck)" "0"

printf '\n\033[1mtest-collections: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
