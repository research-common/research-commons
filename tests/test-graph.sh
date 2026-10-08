#!/usr/bin/env bash
# Provenance graph rendering + compact/depth-limited status.
# Runs entirely against a throwaway COMMONS_ROOT. Never touches the staged registry.
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

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-test-graph-XXXXXX)"
export COMMONS_AGENT=test-graph
trap 'rm -rf "$COMMONS_ROOT"' EXIT
W="$COMMONS_ROOT/work"; mkdir -p "$W"

c() { "$COMMONS" "$@"; }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
put() { printf '# %s\n' "$1" >"$W/$1.md"; }

head_ "linear evidence tree"
put leaf; LEAF=$(c publish wiki "$W/leaf.md" "Leaf evidence" --tier T0 --force)
put middle; MID=$(c publish wiki "$W/middle.md" "Middle analysis" --tier T0 --link "cites:$LEAF")
put top; TOP=$(c publish wiki "$W/top.md" "Top report" --tier T0 --link "derives:$MID")
check "graph viewer exits 0" "$(rc c graph "$TOP")" "0"
check "linear graph contains all nodes" "$(grep -Ec "$TOP|$MID|$LEAF" "$W/out.txt")" "3"
check "node lines carry type and tier badge" "$(grep "$LEAF" "$W/out.txt" | grep -c 'wiki \[T0\] Leaf evidence')" "1"
check "edge relation is rendered" "$(grep "$MID" "$W/out.txt" | grep -c '(derives)')" "1"

head_ "diamond and cycle safety"
put left; LEFT=$(c publish wiki "$W/left.md" "Left branch" --tier T0 --link "cites:$LEAF")
put right; RIGHT=$(c publish wiki "$W/right.md" "Right branch" --tier T0 --link "supports:$LEAF")
put diamond; DIAMOND=$(c publish wiki "$W/diamond.md" "Diamond root" --tier T0 \
  --link "cites:$LEFT" --link "cites:$RIGHT")
check "diamond graph exits 0" "$(rc c graph "$DIAMOND")" "0"
check "shared node gets one repeat marker" "$(grep "$LEAF" "$W/out.txt" | grep -c '(seen above)')" "1"
check "shared subtree body is expanded once" "$(grep "$LEAF" "$W/out.txt" | grep -vc '(seen above)')" "1"

put cycle-a; CYA=$(c publish wiki "$W/cycle-a.md" "Cycle A" --tier T0 --force)
put cycle-b; CYB=$(c publish wiki "$W/cycle-b.md" "Cycle B" --tier T0 --link "cites:$CYA")
python3 - "$COMMONS_ROOT/registry/artifacts/$CYA.json" "$CYB" <<'PYEDIT'
import json, sys
p = sys.argv[1]; m = json.load(open(p)); m["links"] = [{"rel": "cites", "id": sys.argv[2]}]
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PYEDIT
timeout 20 "$COMMONS" graph "$CYA" >"$W/out.txt" 2>"$W/err.txt"; CYRC=$?
check "cycle terminates without hanging" "$CYRC" "0"
check "cycle closes with seen marker" "$(grep "$CYA" "$W/out.txt" | grep -c '(seen above)')" "1"

head_ "depth and relation controls"
check "graph --depth exits 0" "$(rc c graph "$TOP" --depth 1)" "0"
check "depth truncation is visible" "$(grep -c 'depth cap reached' "$W/out.txt")" "1"
check "nodes beyond depth are omitted" "$(grep -c "$LEAF" "$W/out.txt")" "0"
check "status --depth caps node count" "$(c status "$TOP" --depth 0 --brief 2>/dev/null | grep -c 'nodes=1')" "1"

put relations; REL=$(c publish wiki "$W/relations.md" "Relations" --tier T0 \
  --link "part-of:$LEAF" --link "fulfills:$MID")
c graph "$REL" >"$W/default-rel.txt"
check "default graph omits non-evidence links" "$(grep -Ec "$LEAF|$MID" "$W/default-rel.txt")" "0"
check "--rel all includes the publisher link and ignores unbacked fulfills" \
  "$(c graph "$REL" --rel all | grep 'non-evidence:' | grep -Ec "$LEAF|$MID")" "1"
check "backed non-evidence links are marked" "$(c graph "$REL" --rel all | grep -c 'non-evidence:')" "1"

head_ "brief status exit parity"
put attested; T3=$(c publish dataset "$W/attested.md" "Attested leaf")
put unknown; UV=$(c publish wiki "$W/unknown.md" "Unknown claim")
for spec in "$TOP:0" "$T3:3" "$UV:4"; do
  aid=${spec%:*}; want=${spec#*:}
  full=$(rc c status "$aid")
  brief=$(rc c status "$aid" --brief)
  check "brief exit matches full for $want" "$brief/$full" "$want/$want"
done
check "brief is exactly one line" "$(wc -l <"$W/out.txt" | tr -d ' ')" "1"
check "brief exposes badge, grade, nodes, weakest" \
  "$(grep -Ec "^$UV \[unverified\] chain=unverified nodes=1 weakest=$UV view=legacy$" "$W/out.txt")" "1"
check "negative graph depth is refused" "$(rc c graph "$TOP" --depth -1)" "2"

head_ "unknown ids are reported, not silently empty"
# A typo'd id used to print "outbound:/inbound:" with nothing under either and exit 0,
# which reads as "this artifact has no links" — the wrong answer, and the one a
# newcomer is least equipped to catch. Both readers now fail and name the missing subject.
check "links on an unknown id fails" "$(rc c links sy-deadbeef)" "1"
check "links names the missing artifact" "$(grep -c 'no such artifact' "$W/err.txt")" "1"
check "links on a real id still works" "$(rc c links "$TOP")" "0"
check "graph on an unknown id fails" "$(rc c graph sy-deadbeef)" "1"
check "graph names the missing artifact on stderr" \
  "$(grep -c 'missing: sy-deadbeef is MISSING from registry' "$W/err.txt")" "1"
check "graph keeps stdout clean on a missing root" "$(wc -c <"$W/out.txt" | tr -d ' ')" "0"
check "graph on a malformed id fails" "$(rc c graph bad/id)" "1"
check "graph reports a malformed id clearly" "$(grep -c 'missing: bad/id' "$W/err.txt")" "1"

head_ "signed lifecycle verbs resolve subjects before authority checks"
TASK=tk-11111111
RESULT=rp-22222222
# Compute the dummy hashes: a bare 64-hex literal trips secret scanners that flag key-shaped strings.
ZERO64=$(printf '0%.0s' $(seq 64)); ONE64=$(printf '1%.0s' $(seq 64)); TWO64=$(printf '2%.0s' $(seq 64))
printf '%s
'   '{"schema":"rc.v1","id":"tk-11111111","type":"task","content":{"sha256":"'"$ZERO64"'"}}'   >"$COMMONS_ROOT/registry/artifacts/$TASK.json"
printf '%s
'   '{"schema":"rc.v1","id":"rp-22222222","type":"report","content":{"sha256":"'"$ONE64"'"}}'   >"$COMMONS_ROOT/registry/artifacts/$RESULT.json"

life() {
  verb=$1; id=$2
  case "$verb" in
    claim|heartbeat|release|settle) c "$verb" "$id" ;;
    commit-derivation) c "$verb" "$id" --result-hash       "$TWO64" ;;
    submit|accept) c "$verb" "$id" "$RESULT" ;;
    reject) c reject "$id" "$RESULT" --reason control ;;
  esac
}
for verb in claim heartbeat release commit-derivation submit accept reject settle; do
  check "$verb rejects a missing task before signing" "$(rc life "$verb" tk-deadbeef)" "1"
  check "$verb missing-task diagnostic names the subject"     "$(grep -c 'no such artifact: tk-deadbeef' "$W/err.txt")" "1"
  check "$verb rejects a malformed task before signing" "$(rc life "$verb" bad/id)" "1"
  check "$verb valid subjects still reach the signing guard" "$(rc life "$verb" "$TASK")" "1"
  check "$verb control is not an always-missing fix"     "$(grep -c 'must be signed' "$W/err.txt")" "1"
done

check "submit rejects a missing result before signing" "$(rc c submit "$TASK" rp-deadbeef)" "1"
check "submit missing-result diagnostic names the subject"   "$(grep -c 'result rp-deadbeef is not published' "$W/err.txt")" "1"
check "submit rejects a malformed result before signing" "$(rc c submit "$TASK" bad/result)" "1"
for verb in accept reject; do
  if [ "$verb" = reject ]; then
    check "$verb rejects a missing result before signing"       "$(rc c "$verb" "$TASK" rp-deadbeef --reason control)" "1"
  else
    check "$verb rejects a missing result before signing"       "$(rc c "$verb" "$TASK" rp-deadbeef)" "1"
  fi
  check "$verb missing-result diagnostic names the subject"     "$(grep -c 'no such artifact: rp-deadbeef' "$W/err.txt")" "1"
  if [ "$verb" = reject ]; then
    check "$verb rejects a malformed result before signing"       "$(rc c "$verb" "$TASK" bad/result --reason control)" "1"
  else
    check "$verb rejects a malformed result before signing"       "$(rc c "$verb" "$TASK" bad/result)" "1"
  fi
done

printf '\n\033[1mtest-graph: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
