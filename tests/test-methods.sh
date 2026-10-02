#!/usr/bin/env bash
# Analysis templates — category-level methods as discoverable artifacts
# (README.md §Analysis templates).
#   stage 1: SKILL.md bundle skills, `methodology` + `category:` tags, `applies:` links
#   stage 2: `collection show` groups method vs instances; `list --category`
#   stage 3: rubric.json inside the bundle → manifest.rubric → `publish task --method`
# Invariant under test throughout: none of this moves a chain grade.
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

LAB="$(mktemp -d -t commons-methods-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export COMMONS_ROOT="$LAB/reg"; export COMMONS_AGENT=test-methods
mkdir -p "$COMMONS_ROOT/registry" "$LAB/w"
cp "$REPO/registry/exec-policy.example.json" "$COMMONS_ROOT/registry/exec-policy.json"
W="$LAB/w"
c()   { "$COMMONS" "$@"; }
rc()  { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
both(){ cat "$W/out.txt" "$W/err.txt"; }
ADDR=0x00000000000000000000000000000000000000A1

mkbundle() {  # mkbundle <dir> <out.tar> [rubric-json|-]
  mkdir -p "$1"; printf '# Method\n\nFollow the steps.\n' > "$1/SKILL.md"
  if [ -n "${3:-}" ] && [ "$3" != "-" ]; then printf '%s' "$3" > "$1/rubric.json"; fi
  tar -C "$1" -cf "$2" .
}
RUBRIC='{"criteria_list":[{"id":"claims-ledger","text":"CLAIMS.md present, every claim has verdict + evidence"},{"id":"raw-persisted","text":"every number traces to a persisted snapshot with height + date"}]}'

head_ "stage 1: bundle publish + convention lint"
mkbundle "$W/m1" "$W/m1.tar" "$RUBRIC"
SK=$(c publish skill "$W/m1.tar" "Method: demo analysis v1" -d "demo method" \
       -t methodology -t category:demo 2>"$W/err.txt")
check "method bundle publishes as sk-" "$(echo "$SK" | grep -c '^sk-')" "1"
check "  publish notes bundle + rubric count" "$(grep -c 'SKILL.md bundle.*rubric.json with 2 criteria' "$W/err.txt")" "1"
check "  manifest carries rubric (2)" "$(c get "$SK" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["rubric"]))')" "2"

mkdir -p "$W/plain"; echo data > "$W/plain/x.csv"; tar -C "$W/plain" -cf "$W/plain.tar" .
check "tar without SKILL.md refused as a skill" "$(rc c publish skill "$W/plain.tar" "Skill: notabundle")" "1"
check "  refusal names SKILL.md" "$(both | grep -c 'has no SKILL.md')" "1"

mkbundle "$W/m2" "$W/m2.tar" '{"criteria_list":[{"id":"a","text":"must be written by Claude"}]}'
check "rubric naming model pedigree refused" "$(rc c publish skill "$W/m2.tar" "Method: ped" -t methodology -t category:x)" "1"
check "  refusal cites pedigree rule" "$(both | grep -c 'model pedigree')" "1"

mkbundle "$W/m3" "$W/m3.tar" '{"criteria_list":[{"id":"a","text":"one"},{"id":"a","text":"two"}]}'
check "rubric with duplicate ids refused" "$(rc c publish skill "$W/m3.tar" "Method: dup" -t methodology -t category:x)" "1"

mkbundle "$W/m4" "$W/m4.tar" 'not json'
check "rubric that is not JSON refused" "$(rc c publish skill "$W/m4.tar" "Method: badjson" -t methodology -t category:x)" "1"

mkdir -p "$W/m5"; printf 'x' > "$W/m5/SKILL.md"; ln -s /etc/passwd "$W/m5/evil"
tar -C "$W/m5" -cf "$W/m5.tar" .
check "bundle with a symlink member refused" "$(rc c publish skill "$W/m5.tar" "Method: link" -t methodology -t category:x)" "1"
check "  refusal names the unsafe member" "$(both | grep -c "member './evil' is unsafe")" "1"

# Distinct bytes: republishing m1.tar would dedup onto $SK and silently
# overwrite its metadata.
mkbundle "$W/m1b" "$W/m1b.tar" "-"; printf 'variant\n' >> "$W/m1b/SKILL.md"; tar -C "$W/m1b" -cf "$W/m1b.tar" .
check "category tag must be kebab-case" "$(rc c publish skill "$W/m1b.tar" "Method: demo" -t methodology -t 'category:Not Kebab')" "1"
c publish skill "$W/m1b.tar" "Method: demo" -t methodology >"$W/out.txt" 2>"$W/err.txt"
check "methodology without category: warns" "$(grep -c 'no category:<slug> tag' "$W/err.txt")" "1"
printf '#!/bin/sh\necho hi\n' > "$W/bare.sh"
c publish skill "$W/bare.sh" "some tool" -t methodology -t category:demo >"$W/out.txt" 2>"$W/err.txt"
check "bare-script method: warns about title prefix" "$(grep -c 'title prefix' "$W/err.txt")" "1"
check "bare-script method: warns no rubric" "$(grep -c 'carries no rubric' "$W/err.txt")" "1"
BARE=$(cat "$W/out.txt" | tail -1)

# Layout tolerance: `tar dir` (one top-level directory) is also a bundle.
mkdir -p "$W/top/mydir"; printf '# M\n' > "$W/top/mydir/SKILL.md"; printf '%s' "$RUBRIC" > "$W/top/mydir/rubric.json"
tar -C "$W/top" -cf "$W/top.tar" mydir
SK_TOP=$(c publish skill "$W/top.tar" "Method: nested layout" -t methodology -t category:nested 2>/dev/null)
check "one-top-level-dir bundle layout accepted" "$(echo "$SK_TOP" | grep -c '^sk-')" "1"
check "  rubric read through the prefix" "$(c rubric "$SK_TOP" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["criteria_list"]))')" "2"

head_ "stage 1: applies links"
printf '# Report: instance A\n\nMethod: %s\n' "$SK" > "$W/a.md"
RP_A=$(c publish report "$W/a.md" "Report: instance A" --link applies:"$SK" 2>/dev/null)
check "instance with applies:sk publishes" "$(echo "$RP_A" | grep -c '^rp-')" "1"
check "applies is inbound-discoverable via links" "$(c links "$SK" | grep -c "<- $RP_A \[applies\]")" "1"
check "applies is NOT an evidence edge (status ignores it)" "$(c status "$RP_A" --brief | grep -c 'nodes=1')" "1"
check "graph --rel all labels it non-evidence" "$(c graph "$RP_A" --rel all | grep -c 'non-evidence: applies')" "1"
check "graph (evidence only) omits it" "$(c graph "$RP_A" | grep -c "$SK")" "0"
printf '# r\n' > "$W/b.md"
check "applies at a non-skill refused" "$(rc c publish report "$W/b.md" "Report: bad applies" --link applies:"$RP_A")" "1"
check "  refusal explains rel semantics" "$(both | grep -c 'a method is a skill')" "1"
c publish report "$W/b.md" "Report: absent target" --link applies:sk-00000000 >"$W/out.txt" 2>"$W/err.txt"
check "applies at an absent target warns, does not refuse" "$(grep -c 'not held locally' "$W/err.txt")" "1"
RP_ABS=$(cat "$W/out.txt")
printf '# r2\n' > "$W/b2.md"
c publish report "$W/b2.md" "Report: untagged method" --link applies:"$BARE" >"$W/out.txt" 2>"$W/err.txt"
check "applies at a methodology-tagged bare script: no warning" "$(grep -c 'not tagged' "$W/err.txt")" "0"

head_ "stage 2: list --category"
check "list --category demo finds the method" "$(c list --category demo 2>/dev/null | grep -c "$SK")" "1"
check "  row shows applied-by count" "$(c list --category demo 2>/dev/null | grep "$SK" | grep -c 'applied by 1')" "1"
check "  row shows rubric count" "$(c list --category demo 2>/dev/null | grep "$SK" | grep -c 'rubric:2')" "1"
check "  bare-script method in same category listed without rubric" "$(c list --category demo 2>/dev/null | grep "$BARE" | grep -c 'rubric:')" "0"
check "bare --category lists every method" "$(c list --category 2>/dev/null | grep -c '^sk-')" "4"
check "  bare --category excludes untagged skills" "$(c list --category 2>/dev/null | grep -c "$SK_TOP")" "1"
check "unknown category lists nothing" "$(c list --category nope 2>/dev/null | wc -l | tr -d ' ')" "0"
check "--category + --type report refused" "$(rc c list --category demo --type report)" "1"
check "--json rows carry categories/applied_by" \
  "$(c list --category demo --json | python3 -c 'import json,sys;r=json.load(sys.stdin)[0];print(r["categories"],len(r["applied_by"]),r["rubric_criteria"])')" \
  "['demo'] 1 2"
check "plain list unchanged (no category column)" "$(c list --type skill 2>/dev/null | grep -c 'applied by')" "0"

head_ "stage 2: collection show groups method vs instances"
mkcoll() {  # mkcoll <out> <members-json>
  python3 - "$1" "$ADDR" "$2" <<'PY'
import json, sys
out, addr, members = sys.argv[1:4]
json.dump({"scope": "Demo category: how instances of demo are analyzed",
           "maintainers": [{"agent": "test-methods", "addr": addr}],
           "members": json.loads(members),
           "task_criteria": "apply the method to an instance not yet covered"},
          open(out, "w"), indent=2, sort_keys=True)
PY
}
mkcoll "$W/cl.json" "[{\"id\":\"$SK\",\"role\":\"method\"},{\"id\":\"$RP_A\",\"role\":\"instance\"}]"
CL=$(c publish collection "$W/cl.json" "Demo analyses" 2>/dev/null)
check "category collection publishes" "$(echo "$CL" | grep -c '^cl-')" "1"
c collection show "$CL" > "$W/show.txt"
# This collection is published unsigned, so since #23 the sections say UNSIGNED, not
# ENDORSED (the signed-publisher wording is covered in test-collections.sh / test-signing.sh).
check "method section rendered" "$(grep -c 'method (UNSIGNED): 1' "$W/show.txt")" "1"
check "instances section rendered" "$(grep -c 'instances (UNSIGNED): 1' "$W/show.txt")" "1"
check "unsigned collection is not labelled ENDORSED" "$(grep -c 'ENDORSED' "$W/show.txt")" "0"
check "method row carries applied-by" "$(grep -c "$SK.*applied by 1" "$W/show.txt")" "1"
check "method row carries category + rubric" "$(grep -c "category:demo.*rubric:2" "$W/show.txt")" "1"
check "instance row shows applies target" "$(grep -c "$RP_A.*applies $SK" "$W/show.txt")" "1"
check "curated total still 2" "$(grep -c 'curated-in (UNSIGNED — editorial list, not attributable): 2' "$W/show.txt")" "1"

# An unendorsed instance that applied the method is the maintainer's review queue.
printf '# Report: instance B\n' > "$W/ib.md"
RP_B=$(c publish report "$W/ib.md" "Report: instance B" --link applies:"$SK" --link part-of:"$CL" 2>/dev/null)
c collection show "$CL" > "$W/show.txt"
check "applied-but-unendorsed queue rendered" "$(grep -c 'applied the method, not yet endorsed: 1' "$W/show.txt")" "1"
check "  names the pending instance" "$(grep -c "$RP_B.*(applies, unendorsed)" "$W/show.txt")" "1"
check "  self-declared row also shows applies" "$(grep -A3 'self-declared (CLAIMED' "$W/show.txt" | grep -c "$RP_B.*(claimed)  applies $SK")" "1"
check "method applied-by now 2" "$(grep -c "$SK.*applied by 2" "$W/show.txt")" "1"

# Different-method and superseded markers.
mkbundle "$W/m6" "$W/m6.tar" "$RUBRIC"; printf 'v2\n' >> "$W/m6/SKILL.md"; tar -C "$W/m6" -cf "$W/m6.tar" .
SK2=$(c publish skill "$W/m6.tar" "Method: demo analysis v2" -t methodology -t category:demo --link supersedes:"$SK" 2>/dev/null)
printf '# Report: instance C\n' > "$W/ic.md"
RP_C=$(c publish report "$W/ic.md" "Report: instance C (other method)" --link applies:"$SK_TOP" 2>/dev/null)
mkcoll "$W/cl2.json" "[{\"id\":\"$SK2\",\"role\":\"method\"},{\"id\":\"$RP_A\",\"role\":\"instance\"},{\"id\":\"$RP_C\",\"role\":\"instance\"}]"
CL2=$(c publish collection "$W/cl2.json" "Demo analyses v2" 2>/dev/null)
c collection show "$CL2" > "$W/show.txt"
check "instance on a superseded version marked (superseded), not wrong" "$(grep -c "$RP_A.*applies $SK (superseded)" "$W/show.txt")" "1"
check "instance on an unrelated method marked (different method)" "$(grep -c "$RP_C.*applies $SK_TOP (different method)" "$W/show.txt")" "1"

# Guards on the role itself.
mkcoll "$W/cl3.json" "[{\"id\":\"$RP_A\",\"role\":\"method\"}]"
check "role method on a non-skill refused" "$(rc c publish collection "$W/cl3.json" "Bad")" "1"
check "  refusal says a method is a skill or workflow" "$(both | grep -c 'a method is a skill or workflow')" "1"
# Pre-convention usage: a WORKFLOW as role method is legal (tests/test-subscription.sh
# relies on it) and renders in the method section without a rubric/category.
python3 - "$W/wf.json" <<'PY'
import json,sys
json.dump({"interpreter":"bash","inputs":{},"steps":["true"],"outputs":{},"env":{"TZ":"UTC","LC_ALL":"C","PYTHONHASHSEED":"0"}},open(sys.argv[1],"w"))
PY
WF=$(c publish workflow "$W/wf.json" "wf as method" 2>/dev/null)
mkcoll "$W/clwf.json" "[{\"id\":\"$WF\",\"role\":\"method\"}]"
CLWF=$(c publish collection "$W/clwf.json" "Workflow method" 2>/dev/null)
check "workflow with role method still publishes (pre-convention usage)" "$(echo "$CLWF" | grep -c '^cl-')" "1"
check "  renders in the method section, no tag marker" "$(c collection show "$CLWF" | grep "$WF" | grep -c 'applied by 0$')" "1"
mkcoll "$W/cl4.json" "[{\"id\":\"sk-00000000\",\"role\":\"method\"}]"
check "role method on an absent skill still publishes (lazy replication)" \
  "$(c publish collection "$W/cl4.json" "Absent method" 2>/dev/null | grep -c '^cl-')" "1"

# Collections without a method member render exactly as before.
mkcoll "$W/cl5.json" "[{\"id\":\"$RP_A\",\"role\":\"report\"}]"
CL5=$(c publish collection "$W/cl5.json" "Plain collection" 2>/dev/null)
c collection show "$CL5" > "$W/show.txt"
check "no method member: no method section" "$(grep -c '^  method (' "$W/show.txt")" "0"
check "no method member: no applies annotation" "$(grep -c 'applies ' "$W/show.txt")" "0"
check "no method member: legacy role line intact" "$(grep -c "$RP_A.*\[role report\]$" "$W/show.txt")" "1"

head_ "stage 3: rubric bundling"
c rubric "$SK" > "$W/rub.json"
check "rubric <sk> emits task-ready JSON" "$(python3 -c 'import json;d=json.load(open("'"$W"'/rub.json"));print(d["method"]==sys.argv[1] if False else d["method"], len(d["criteria_list"]), len(d["applied_by"]))' 2>/dev/null)" "$SK 2 2"
check "rubric on a method without one: exit 1" "$(rc c rubric "$BARE")" "1"
check "rubric on a dataset-type artifact: exit 1" "$(rc c rubric "$RP_A")" "1"

mktask() {  # mktask <out> <overrides-json>
  python3 - "$1" "$ADDR" "$2" <<'PY'
import json, sys
out, addr, over = sys.argv[1:4]
spec = {"objective": "apply the demo method to protocol Y", "priority": 2,
        "expires": "2099-01-01T00:00:00Z",
        "verification": {"tier": "T2"},
        "execution": {"brief": "follow the method; ship CLAIMS.md"},
        "beneficiary": {"agent": "test-methods", "addr": addr},
        "max_claims": 2, "diversity_quorum": {"k": 2, "distinct_families": 1}}
spec.update(json.loads(over))
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
}
mktask "$W/t.json" '{}'
check "T2 k=2 without rubric refused (unchanged)" "$(rc c publish task "$W/t.json" "no rubric")" "1"
TK=$(c publish task "$W/t.json" "apply demo" --method "$SK" 2>"$W/err.txt")
check "publish task --method copies the rubric and publishes" "$(echo "$TK" | grep -c '^tk-')" "1"
check "  note reports 2 copied" "$(grep -c 'copied (2 criteria, 2 added)' "$W/err.txt")" "1"
check "  sibling .with-method.json written" "$(test -f "$W/t.with-method.json" && echo yes)" "yes"
check "  spec records method" "$(python3 -c 'import json;print(json.load(open("'"$W"'/t.with-method.json"))["method"])')" "$SK"
check "status shows rubric-from line" "$(c status "$TK" | grep -c "rubric from: $SK")" "1"
check "rubric <tk> echoes the copied rubric" "$(c rubric "$TK" | python3 -c 'import json,sys;d=json.load(sys.stdin);print(d["method"],len(d["criteria_list"]))')" "$SK 2"
check "queue --json carries criteria_list from the method" \
  "$(c queue --json | python3 -c 'import json,sys;print([len(t["criteria_list"]) for t in json.load(sys.stdin) if t["id"]=="'"$TK"'"][0])')" "2"

mktask "$W/t2.json" "{\"method\":\"$SK\",\"verification\":{\"tier\":\"T2\",\"criteria\":\"x\",\"criteria_list\":[{\"id\":\"claims-ledger\",\"text\":\"y\"}]}}"
check "method + rubric omitting a method criterion refused" "$(rc c publish task "$W/t2.json" "partial")" "1"
check "  refusal names the missing id" "$(both | grep -c 'omits: raw-persisted')" "1"
mktask "$W/t3.json" "{\"method\":\"$SK\",\"verification\":{\"tier\":\"T2\",\"criteria\":\"x\",\"criteria_list\":[{\"id\":\"claims-ledger\",\"text\":\"y\"},{\"id\":\"raw-persisted\",\"text\":\"z\"},{\"id\":\"extra\",\"text\":\"task-specific\"}]}}"
check "method + rubric EXTENDING the method accepted (task owns its rubric)" \
  "$(c publish task "$W/t3.json" "extended" 2>/dev/null | grep -c '^tk-')" "1"
mktask "$W/t4.json" "{\"method\":\"$SK\",\"verification\":{\"tier\":\"T2\",\"criteria\":\"prose only\"}}"
check "method with rubric but no criteria_list refused" "$(rc c publish task "$W/t4.json" "no list")" "1"
check "  refusal points at --method / rubric" "$(both | grep -c 'commons rubric')" "1"
mktask "$W/t5.json" "{\"method\":\"$RP_A\"}"
check "method naming a non-skill refused" "$(rc c publish task "$W/t5.json" "bad method")" "1"
mktask "$W/t6.json" "{\"method\":\"$SK\",\"verification\":{\"tier\":\"T0\",\"criteria\":\"bytes\"},\"execution\":{\"workflow\":\"wf-00000000\"}}"
check "method on a T0 task refused" "$(rc c publish task "$W/t6.json" "t0 method")" "1"
check "  refusal says judged work" "$(both | grep -c 'only meaningful on T2')" "1"
check "--method on a non-task refused" "$(rc c publish report "$W/a.md" "x" --method "$SK")" "1"
check "--method at a method without a rubric refused" "$(rc c publish task "$W/t.json" "x" --method "$BARE")" "1"

head_ "invariants"
check "run-skill on a bundle refuses with guidance" "$(rc c run-skill "$SK")" "1"
check "  refusal points at export + rubric" "$(both | grep -c 'commons rubric')" "1"
check "method skill still shows tier '—' in listings" "$(c list --type skill 2>/dev/null | grep "$SK" | grep -c ' — ')" "1"
check "chain grade of an endorsed instance unmoved by membership + applies" "$(c status "$RP_A" --brief | grep -c 'chain=unverified')" "1"
check "reindex preserves applies edges" "$(c reindex >/dev/null 2>&1; c links "$SK" | grep -c '\[applies\]')" "2"
check "search finds the method by tag" "$(c search methodology 2>/dev/null | grep -c "$SK")" "1"
check "search finds the method by category tag" "$(c search 'category:demo' 2>/dev/null | grep -c "$SK")" "1"
check "fsck clean" "$(rc c fsck)" "0"
check "log --verify clean" "$(rc c log --verify)" "0"

printf '\n\033[1mtest-methods: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
