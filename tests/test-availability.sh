#!/usr/bin/env bash
# Licence validation + dataset obtainability disclosure.
#
# What this pins (licence = may I redistribute; obtainability = can a peer re-acquire):
#   1. --license is a validated identifier, not free text (a typo must not read as a licence)
#   2. --obtainability is a separate, orthogonal field; undeclared is NOT assumed open
#   3. licensed-obtainable requires --source, because an unactionable claim is not a disclosure
#   4. availability is surfaced in verify / status / list / search
#   5. availability NEVER moves a tier, a chain grade, or an exit code
#   6. push refuses undisclosed availability, with an honest escape hatch
#
# (5) is the load-bearing one. Availability changes WHO CAN CHECK a result, not WHAT WAS
# CHECKED — the same category error as methods-carry-no-tier. If a future change lets it
# touch grading arithmetic, these assertions go red.
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

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-test-avail-XXXXXX)"
export COMMONS_AGENT=test-avail
trap 'rm -rf "$COMMONS_ROOT"' EXIT
W="$COMMONS_ROOT/work"; mkdir -p "$W"

c() { "$COMMONS" "$@"; }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
field() { python3 -c 'import json,sys;d=json.load(sys.stdin)
for k in sys.argv[1].split("."):
    d = (d or {}).get(k) if isinstance(d, dict) else None
print("" if d is None else d)' "$1"; }

# Ids are derived from CONTENT, so every fixture that must be a DISTINCT artifact needs
# distinct bytes. Reusing one file across publishes silently collapses them onto a single
# id and the suite then asserts about an artifact it did not think it was looking at.
printf 'avs,promised_usd,claimed_usd\nalpha,100,50\nbeta,200,180\n' > "$W/r.csv"
printf 'x,y\n1,2\n' > "$W/o.csv"
printf 'p,q\n3,4\n' > "$W/p.csv"
printf 'm,n\n5,6\n' > "$W/m.csv"
printf 'u,v\n7,8\n' > "$W/undec.csv"
printf 'k,l\n9,10\n' > "$W/lic.csv"
printf 'reject,me\n0,0\n' > "$W/scratch.csv"
printf 'note text\n' > "$W/note.txt"

# ---------------------------------------------------------------- licence validation
head_ "licence is a validated identifier, not free text"

OPEN=$(c publish dataset "$W/o.csv" "open data" --license cc0-1.0 --obtainability open 2>/dev/null)
check "publish with a valid SPDX id succeeds" "$(echo "$OPEN" | grep -c '^ds-')" "1"
# SPDX ids match case-insensitively per the spec; canonicalising means two manifests
# carrying the same licence compare equal instead of differing by keystroke.
check "lowercase spdx id canonicalises" "$(c get "$OPEN" | field license)" "CC0-1.0"

# The exact failure this replaces: `propietary-internal` was accepted silently, so a
# misspelt licence read as a real one — a silent wrong answer, not an error.
# These all publish the SAME scratch bytes on purpose: each must be refused before any
# artifact is created, so no id is ever minted and there is nothing to collide.
check "misspelt licence is refused" \
  "$(rc c publish dataset "$W/scratch.csv" "typo" --license propietary-internal --obtainability open)" "1"
check "refusal names the variable" "$(grep -c -- '--license' "$W/err.txt")" "1"
check "refusal lists the accepted non-open terms" \
  "$(grep -c 'proprietary-internal' "$W/err.txt")" "1"
check "arbitrary prose is refused" \
  "$(rc c publish dataset "$W/scratch.csv" "prose" --license 'ask me nicely' --obtainability open)" "1"
check "empty licence is refused" \
  "$(rc c publish dataset "$W/scratch.csv" "empty" --license '' --obtainability open)" "1"
check "nothing was published by the refused attempts" \
  "$(c list --type dataset | grep -c 'typo\|prose\|empty')" "0"

# The escape hatch is SPDX's own convention, so an unusual licence still arrives as an
# identifier someone can look up rather than a paragraph nobody can index.
REF=$(c publish dataset "$W/p.csv" "vendor terms" \
        --license LicenseRef-VendorX-Eval-2026 --obtainability restricted 2>/dev/null)
check "LicenseRef-<name> is accepted" "$(echo "$REF" | grep -c '^ds-')" "1"
check "LicenseRef stored verbatim" "$(c get "$REF" | field license)" "LicenseRef-VendorX-Eval-2026"
check "honest non-open term accepted" \
  "$(rc c publish dataset "$W/m.csv" "internal" --license proprietary-internal --obtainability restricted)" "0"

# ------------------------------------------------------------------- obtainability
head_ "obtainability is separate from licence"

REST=$(c publish dataset "$W/r.csv" "internal telemetry" \
         --license proprietary-internal --obtainability restricted 2>/dev/null)
check "restricted recorded" "$(c get "$REST" | field availability.obtainability)" "restricted"
check "licence recorded independently" "$(c get "$REST" | field license)" "proprietary-internal"

# The whole point of the split: restrictively licensed data can still be genuinely
# obtainable. A peer with their own subscription replicates byte-identically.
LIC=$(c publish dataset "$W/lic.csv" "paywalled feed" --license proprietary \
        --obtainability licensed-obtainable --source "VendorX Terminal, product ABC" \
        2>/dev/null)
check "licensed-obtainable recorded" "$(c get "$LIC" | field availability.obtainability)" "licensed-obtainable"
check "source recorded" "$(c get "$LIC" | field availability.source)" "VendorX Terminal, product ABC"

# 'Independently obtainable' with no way to obtain it is not a disclosure.
check "licensed-obtainable without --source is refused" \
  "$(rc c publish dataset "$W/scratch.csv" "no source" --license proprietary \
       --obtainability licensed-obtainable)" "1"
check "refusal explains why a source is required" "$(grep -c -- '--source' "$W/err.txt")" "1"
check "--source without licensed-obtainable is refused" \
  "$(rc c publish dataset "$W/scratch.csv" "stray source" --license MIT \
       --obtainability restricted --source "somewhere")" "1"
check "--source without --obtainability is refused" \
  "$(rc c publish dataset "$W/scratch.csv" "orphan source" --license MIT --source "somewhere")" "1"
check "unknown obtainability value is refused" \
  "$(rc c publish dataset "$W/scratch.csv" "bad enum" --license MIT --obtainability maybe)" "2"

# Obtainability describes acquiring SOURCE data. A derived work ships its own bytes, so
# stamping one would imply the inputs travel with it.
check "obtainability rejected on non-dataset types" \
  "$(rc c publish synthesis "$W/scratch.csv" "derived" --obtainability open)" "1"

head_ "undeclared is not assumed open"

UNDEC=$(c publish dataset "$W/undec.csv" "undeclared" --license MIT 2>/dev/null)
check "publish without --obtainability still succeeds" "$(echo "$UNDEC" | grep -c '^ds-')" "1"
check "publish warns about the omission" \
  "$(c publish dataset "$W/undec.csv" "undeclared" --license MIT --force 2>&1 \
      | grep -c 'without --obtainability')" "1"
check "warning says undeclared is not open" \
  "$(c publish dataset "$W/undec.csv" "undeclared" --license MIT --force 2>&1 \
      | grep -c 'NOT assumed open')" "1"
check "no availability block is invented" "$(c get "$UNDEC" | field availability.obtainability)" ""

head_ "metadata overwrite does not silently drop a disclosure"

# Same carry-forward reasoning as --license: a --force metadata overwrite that omits the
# flag must not quietly downgrade a stated disclosure back to undeclared.
c publish dataset "$W/r.csv" "internal telemetry (retitled)" \
  --license proprietary-internal --force >/dev/null 2>&1
check "obtainability survives a --force republish" \
  "$(c get "$REST" | field availability.obtainability)" "restricted"

# ---------------------------------------------------- --force republish preserves (#18)
head_ "--force republish keeps what it was not told to change"

# The remediation fsck/push print ("Re-publish with --license/--obtainability") is a
# --force republish. On a workflow-derived dataset it used to drop provenance, links,
# description and created, and reset T0 to an unattested T3. (The workflow must
# transform its input: a byte copy would collapse onto the input's own id.)
printf 'g,h\n11,12\n' > "$W/f-in.csv"
FIN=$(c publish dataset "$W/f-in.csv" "force input" --license CC0-1.0 --obtainability open 2>/dev/null)
cat > "$W/wf-force.json" <<JSON
{"inputs": {"D": "$FIN"},
 "attachments": {"up.py": "import sys\nopen(sys.argv[2], 'w').write(open(sys.argv[1]).read().upper())\n"},
 "steps": ["python3 up.py \"\$IN_D\" \"\$OUT_DIR/derived.csv\""],
 "outputs": {"out": "derived.csv"},
 "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60}
JSON
WFF=$(c publish workflow "$W/wf-force.json" "copy for force test" --license Apache-2.0 2>/dev/null)
DER=$(c run "$WFF" --publish --publish-type dataset 2>/dev/null | awk '{print $1}')
c get "$DER" > "$W/der-before.json"
c export "$DER" -o "$W/der.csv" >/dev/null
check "licence-only --force on a derived dataset succeeds" "$(rc c publish dataset "$W/der.csv" \
  "derived, now licensed" --license CC-BY-4.0 --obtainability open --force)" "0"
check "no spurious unlicensed/undeclared/default-criteria warning" \
  "$(grep -c 'without --license\|without --obtainability\|default attestation' "$W/err.txt")" "0"
c get "$DER" > "$W/der-after.json"
check "tier stays T0" "$(field verification.tier < "$W/der-after.json")" "T0"
check "verify still PASSes" "$(rc c verify "$DER")" "0"
check "only title/licence/availability (and filename) changed" "$(python3 -c '
import json, sys
b, a = (json.load(open(p)) for p in sys.argv[1:])
b["content"].pop("filename"); a["content"].pop("filename")
print(",".join(sorted(k for k in set(a) | set(b) if a.get(k) != b.get(k))))
' "$W/der-before.json" "$W/der-after.json")" "availability,license,title"
check "new licence recorded" "$(field license < "$W/der-after.json")" "CC-BY-4.0"
check "provenance.run.env survives" "$(field provenance.run.env.TZ < "$W/der-after.json")" "UTC"

# Re-running the workflow is first-writer-wins, so it could never repair a damaged
# manifest; with the fix there is nothing to repair. Check it still reports a no-op.
check "re-run after the republish is a no-op" \
  "$(c run "$WFF" --publish --publish-type dataset 2>/dev/null | grep -c 'already published; unchanged')" "1"

# Explicit flags still win: --tag/-d replace, omitted --link leaves links alone.
c publish dataset "$W/der.csv" "retagged" -t wind -d "new description" --force >/dev/null 2>&1
check "--tag replaces tags" "$(c get "$DER" | python3 -c 'import json,sys;print(json.load(sys.stdin)["tags"])')" "['wind']"
check "-d replaces description" "$(c get "$DER" | field description)" "new description"
check "links untouched when --link omitted" \
  "$(c get "$DER" | python3 -c 'import json,sys;print([l["rel"] for l in json.load(sys.stdin)["links"]])')" "['derives']"

# A silent downgrade is refused, naming both escape hatches; an explicit --tier is honoured.
check "--criteria without --tier cannot silently downgrade T0" \
  "$(rc c publish dataset "$W/der.csv" "x" --criteria "hand capture" --force)" "1"
check "refusal names --tier" "$(grep -c -- '--tier T0 to keep it' "$W/err.txt")" "1"
check "refused attempt left tier alone" "$(c get "$DER" | field verification.tier)" "T0"
check "explicit --tier T3 is honoured" \
  "$(c publish dataset "$W/der.csv" "x" --tier T3 --criteria "hand capture" --force >/dev/null 2>&1; c get "$DER" | field verification.tier)" "T3"
check "  ...and keeps the recorded provenance" "$(c get "$DER" | field provenance.workflow.id)" "$WFF"

# ------------------------------------------------------------------------ surfacing
head_ "availability is visible where artifacts are read"

check "list marks the restricted dataset" "$(c list --type dataset | grep -c "^$REST .*\[restricted\]")" "1"
check "list marks the open dataset" "$(c list --type dataset | grep -c "^$OPEN .*\[open\]")" "1"
check "list marks the undeclared dataset with ?" "$(c list --type dataset | grep -c "^$UNDEC .*\[?\]")" "1"
check "list marks the licensed-obtainable dataset" \
  "$(c list --type dataset | grep -c "^$LIC .*\[licensed\]")" "1"
check "list --json carries obtainability" \
  "$(c list --type dataset --json | python3 -c 'import json,sys
rows={r["id"]:r for r in json.load(sys.stdin)}
print(rows["'"$REST"'"]["obtainability"])')" "restricted"
# Explicit null, so a consumer can tell "undeclared" from "this build predates the field".
check "list --json reports undeclared as null" \
  "$(c list --type dataset --json | python3 -c 'import json,sys
rows={r["id"]:r for r in json.load(sys.stdin)}
print(rows["'"$UNDEC"'"]["obtainability"] is None)')" "True"
check "non-dataset rows carry no obtainability key" \
  "$(c publish wiki "$W/note.txt" "a note" >/dev/null 2>&1; c list --type wiki --json \
      | python3 -c 'import json,sys;print("obtainability" in json.load(sys.stdin)[0])')" "False"
check "verify prints availability for a T3 dataset" \
  "$(c verify "$REST" 2>&1 | grep -c 'availability: restricted')" "1"
check "verify prints the source for licensed-obtainable" \
  "$(c verify "$LIC" 2>&1 | grep -c 'source    : VendorX Terminal')" "1"
check "verify flags an undeclared dataset as UNDECLARED" \
  "$(c verify "$UNDEC" 2>&1 | grep -c 'availability: UNDECLARED')" "1"
check "tiers documents the obtainability values" \
  "$(c tiers | grep -c 'licensed-obtainable')" "1"

# ------------------------------------------------------------ the load-bearing rule
head_ "availability never moves a tier, grade, or exit code"

python3 - "$W/wf.json" "$REST" <<'PY'
import json, sys
spec = {"inputs": {"REWARDS": sys.argv[2]},
        "attachments": {"agg.py": (
            "import csv, json, sys\n"
            "rows = list(csv.DictReader(open(sys.argv[1])))\n"
            "json.dump({r['avs']: int(r['claimed_usd']) for r in rows},\n"
            "          open(sys.argv[2], 'w'), indent=2, sort_keys=True)\n")},
        "steps": ['python3 agg.py "$IN_REWARDS" "$OUT_DIR/agg.json"'],
        "outputs": {"agg": "agg.json"},
        "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"},
        "timeout": 60}
json.dump(spec, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WF=$(c publish workflow "$W/wf.json" "aggregate rewards" 2>/dev/null)
OUT=$(c run "$WF" --publish --publish-type synthesis --title "restricted-input result" \
        2>/dev/null | awk '{print $1}')

# The computation genuinely reproduced. The exit code must say so.
check "T0 over a restricted input still PASSes" "$(rc c verify "$OUT")" "0"
check "verify still reports PASS" "$(grep -c '^PASS' "$W/out.txt")" "1"
# ...and must simultaneously say the quiet part out loud.
check "verify cautions that nobody else can re-run it" \
  "$(grep -c 'no independent party can re-run it' "$W/out.txt")" "1"
check "caution names the unobtainable input" "$(grep -c "$REST" "$W/out.txt")" "1"
check "tier is unchanged by availability" \
  "$(c get "$OUT" | field verification.tier)" "T0"

# status: the grade is set by the weakest TIER (T3 dataset), never by availability.
STATUS_RC=$(rc c status "$OUT")
check "status exit code follows the tier (T3 -> 3)" "$STATUS_RC" "3"
check "chain grade is the weakest tier" "$(grep -c 'chain grade: T3' "$W/out.txt")" "1"
check "status reports unobtainable inputs separately" \
  "$(grep -c 'NOT independently obtainable' "$W/out.txt")" "1"
check "status names the unobtainable node" \
  "$(grep -c "obtainable: .*$REST" "$W/out.txt")" "1"
check "status --brief carries the flag" "$(c status "$OUT" --brief | grep -c 'unobtainable=1')" "1"

# Control: same chain shape, obtainable input → identical grade, no caution. This is what
# proves the caution tracks availability rather than just firing on every T3 chain.
python3 - "$W/wf2.json" "$OPEN" <<'PY'
import json, sys
spec = {"inputs": {"D": sys.argv[2]},
        "attachments": {"cp.py": (
            "import sys, shutil\nshutil.copyfile(sys.argv[1], sys.argv[2])\n")},
        "steps": ['python3 cp.py "$IN_D" "$OUT_DIR/out.csv"'],
        "outputs": {"out": "out.csv"},
        "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"},
        "timeout": 60}
json.dump(spec, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WF2=$(c publish workflow "$W/wf2.json" "copy open data" 2>/dev/null)
OUT2=$(c run "$WF2" --publish --publish-type synthesis --title "open-input result" \
         2>/dev/null | awk '{print $1}')
check "control: open-input chain also PASSes" "$(rc c verify "$OUT2")" "0"
check "control: no caution on obtainable inputs" \
  "$(grep -c 'no independent party' "$W/out.txt")" "0"
CTRL_RC=$(rc c status "$OUT2")
check "control: same tier-driven exit code as the restricted run" "$CTRL_RC" "3"
check "control: same chain grade as the restricted run" \
  "$(grep -c 'chain grade: T3' "$W/out.txt")" "1"
check "control: status reports no unobtainable inputs" \
  "$(grep -c 'NOT independently obtainable' "$W/out.txt")" "0"

# ------------------------------------------------------------------------ push gate
head_ "push refuses undisclosed availability"

BARE="$W/bare.git"; git init -q --bare "$BARE"
( cd "$COMMONS_ROOT" && git init -q . \
    && git config user.email t@example.invalid && git config user.name tester \
    && git remote add origin "$BARE" && git add -A && git commit -qm "seed" ) >/dev/null 2>&1

check "push blocked while a dataset is undeclared" "$(rc c push origin)" "1"
check "refusal names the undeclared artifact" "$(grep -c "$UNDEC" "$W/err.txt")" "1"
check "refusal says proprietary data is welcome" \
  "$(grep -c 'welcome here' "$W/err.txt")" "1"
# A disclosure gate, not a content ban: the escape hatch exists, it just forces the
# operator to choose silence deliberately rather than by omission.
check "--allow-undisclosed overrides" "$(rc c push origin --allow-undisclosed)" "0"

# Declaring it is the ordinary fix, and then the gate is simply quiet.
c publish dataset "$W/undec.csv" "undeclared" --license MIT --obtainability restricted \
  --force >/dev/null 2>&1
( cd "$COMMONS_ROOT" && git add -A && git commit -qm "declare availability" ) >/dev/null 2>&1
check "push clean once availability is declared" "$(rc c push origin)" "0"

# A licensed-obtainable entry that lost its source is undisclosed too: the manifest
# claims a peer can acquire it while giving them no way to.
python3 - "$COMMONS_ROOT/registry/artifacts/$LIC.json" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
m["availability"].pop("source", None)
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
( cd "$COMMONS_ROOT" && git add -A && git commit -qm "strip source" ) >/dev/null 2>&1
check "push blocked on licensed-obtainable with no source" "$(rc c push origin)" "1"
check "refusal names the sourceless artifact" "$(grep -c "$LIC" "$W/err.txt")" "1"

head_ "availability surfaces at the task/queue/collection front door too"
# Same load-bearing rule (5), applied to the OTHER place a newcomer meets a dataset
# before it has ever been run: a task that cites it as an input, and the queue/
# collection views built on top of tasks. A restricted or undeclared input must be
# visible browsing the queue, not just after `verify`/`status` on a finished result.

cat > "$W/wf-avail.json" <<PYEOF
{"interpreter": "bash", "inputs": {"D": "$REST"},
 "attachments": {"cp.sh": "cp \"\$IN_D\" \"\$OUT_DIR/out.csv\"\n"},
 "steps": ["bash cp.sh"], "outputs": {"out": "out.csv"},
 "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60}
PYEOF
WFAV=$(c publish workflow "$W/wf-avail.json" "availability-tagged workflow" 2>/dev/null)

BADDR=$(python3 -c "import secrets;print('0x'+secrets.token_hex(20))")
python3 - "$W/t-avail.json" "$REST" "$WFAV" "$BADDR" <<'PY'
import json, sys
out, ds, wf, addr = sys.argv[1:5]
spec = {"objective": "copy the restricted input", "priority": 2,
        "expires": "2099-01-01T00:00:00Z",
        "inputs": [{"id": ds}], "execution": {"workflow": wf},
        "verification": {"tier": "T0", "criteria": "byte-identical re-derivation"},
        "beneficiary": {"agent": "test-avail", "addr": addr}}
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
TKAV=$(c publish task "$W/t-avail.json" "Availability task" 2>/dev/null)
check "task citing a restricted dataset publishes" "$(echo "$TKAV" | grep -c '^tk-')" "1"

check "queue marks the restricted-input task" \
  "$(c queue --all 2>/dev/null | grep "$TKAV" | grep -c 'restricted input')" "1"
check "queue --json reports the restricted input" \
  "$(c queue --json --all 2>/dev/null | python3 -c '
import json,sys
rows={r["id"]:r for r in json.load(sys.stdin)}
print(rows["'"$TKAV"'"]["restricted_inputs"])')" "['$REST']"
check "queue --json reports no undeclared inputs for this task" \
  "$(c queue --json --all 2>/dev/null | python3 -c '
import json,sys
rows={r["id"]:r for r in json.load(sys.stdin)}
print(rows["'"$TKAV"'"]["undeclared_inputs"])')" "[]"
check "task status surfaces the restricted input" \
  "$(c status "$TKAV" 2>/dev/null | grep -c "restricted.*$REST")" "1"

# Control: a task citing only an open dataset gets no marker and no availability line.
python3 - "$W/wf-open.json" "$OPEN" <<'PY'
import json, sys
spec = {"interpreter": "bash", "inputs": {"D": sys.argv[2]},
        "attachments": {"cp.sh": "cp \"$IN_D\" \"$OUT_DIR/out.csv\"\n"},
        "steps": ["bash cp.sh"], "outputs": {"out": "out.csv"},
        "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60}
json.dump(spec, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WFOP=$(c publish workflow "$W/wf-open.json" "open-input workflow" 2>/dev/null)
python3 - "$W/t-open.json" "$OPEN" "$WFOP" "$BADDR" <<'PY'
import json, sys
out, ds, wf, addr = sys.argv[1:5]
spec = {"objective": "copy the open input", "priority": 2,
        "expires": "2099-01-01T00:00:00Z",
        "inputs": [{"id": ds}], "execution": {"workflow": wf},
        "verification": {"tier": "T0", "criteria": "byte-identical re-derivation"},
        "beneficiary": {"agent": "test-avail", "addr": addr}}
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
TKOP=$(c publish task "$W/t-open.json" "Open-input task" 2>/dev/null)
check "control: task citing only an open dataset gets no marker" \
  "$(c queue --all 2>/dev/null | grep "$TKOP" | grep -c 'input\]')" "0"
check "control: queue --json reports empty restricted/undeclared lists" \
  "$(c queue --json --all 2>/dev/null | python3 -c '
import json,sys
rows={r["id"]:r for r in json.load(sys.stdin)}
r=rows["'"$TKOP"'"]
print(r["restricted_inputs"]==[] and r["undeclared_inputs"]==[])')" "True"

head_ "fsck --availability previews the push gate without becoming one"
# Entering this section the registry holds: OPEN (open), REF/m.csv/REST/UNDEC (restricted),
# and LIC (licensed-obtainable whose --source was stripped above) — i.e. the gate is
# currently RED for exactly one reason. That makes it a real test of agreement rather
# than of two independently-quiet code paths.

AV_RC=$(rc c fsck --availability); AV_OUT="$W/out.txt"
cp "$AV_OUT" "$W/av1.txt"
check "fsck --availability exits 0 while the push gate is RED" "$AV_RC" "0"
check "availability section is present" \
  "$(grep -c '^--- dataset availability ---$' "$W/av1.txt")" "1"
# Rule (5), stated as bluntly as it can be stated: the advisory view is not allowed to
# move an exit code, so the flag's presence must be invisible to $?.
check "--availability does not change fsck's exit code" \
  "$(rc c fsck --availability)" "$(rc c fsck)"
check "restricted datasets are counted, not treated as errors" \
  "$(grep -cE '^  restricted +[0-9]+ —' "$W/av1.txt")" "1"
check "open datasets are bucketed separately" \
  "$(grep -cE '^  open +[0-9]+ —' "$W/av1.txt")" "1"
# The whole point of the view: learn the refusal before `push` delivers it.
check "preview warns push WOULD REFUSE" "$(grep -c 'push gate: WOULD REFUSE' "$W/av1.txt")" "1"
# Named twice by design — once in its obtainability bucket, once on the blocking
# `sourceless:` line — so assert the BLOCKING mention rather than a raw occurrence
# count, which would silently track the bucket listing instead.
check "preview names the sourceless dataset as blocking" \
  "$(grep '^      sourceless:' "$W/av1.txt" | grep -c "$LIC")" "1"
check "the sourceless dataset still appears in its own bucket" \
  "$(grep -c "^      $LIC$" "$W/av1.txt")" "1"
check "preview states availability never moves a grade or exit code" \
  "$(grep -c 'disclosure only' "$W/av1.txt")" "1"
# Agreement, direction 1: preview says refuse, gate refuses.
check "gate agrees with the preview (refuses)" "$(rc c push origin)" "1"

# Restore the source and both sides must flip together. If the preview and the gate ever
# computed disclosure separately, this is the assertion that would catch the drift.
python3 - "$COMMONS_ROOT/registry/artifacts/$LIC.json" <<'PY'
import json, sys
p = sys.argv[1]
m = json.load(open(p))
m["availability"]["source"] = "VendorX Terminal, product ABC"
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
( cd "$COMMONS_ROOT" && git add -A && git commit -qm "restore source" ) >/dev/null 2>&1
rc c fsck --availability >/dev/null; cp "$W/out.txt" "$W/av2.txt"
check "preview flips to would-pass once disclosed" \
  "$(grep -c 'push gate: would pass' "$W/av2.txt")" "1"
check "gate agrees with the preview (passes)" "$(rc c push origin)" "0"

# Undeclared is its own bucket, never folded into `open` — silence is the finding.
printf 'fresh,undeclared\n11,12\n' > "$W/av-undec.csv"
AVU=$(c publish dataset "$W/av-undec.csv" "fresh undeclared" --license MIT 2>/dev/null)
rc c fsck --availability >/dev/null; cp "$W/out.txt" "$W/av3.txt"
check "undeclared gets its own bucket" \
  "$(grep -cE '^  undeclared +1 —' "$W/av3.txt")" "1"
check "the undeclared dataset is named" "$(grep -c "$AVU" "$W/av3.txt")" "1"
check "undeclared is not counted as open" \
  "$(grep -A1 '^  open ' "$W/av3.txt" | grep -c "$AVU")" "0"
check "preview flips back to WOULD REFUSE" \
  "$(grep -c 'push gate: WOULD REFUSE' "$W/av3.txt")" "1"
check "still exits 0 with an undeclared dataset present" "$(rc c fsck --availability)" "0"

# Leave the registry disclosed so later sections start from a quiet gate.
c publish dataset "$W/av-undec.csv" "fresh undeclared" --license MIT \
  --obtainability open --force >/dev/null 2>&1

# ------------------------------------------------------------------- freshness marker
# Freshness rides the same title column as availability and under the same rule: it is
# disclosure, never grading. What it must never do is conflate the two timestamps —
# `observed` is a SIGNED statement field that only exists after `attest`, while `created`
# is the publisher's own self-declared publish time. Showing the second as if it were the
# first would be a new silent wrong answer, and for a measurement published months after
# capture the gap is the whole point.
head_ "freshness: observed age vs publish age, never conflated"

printf 'slot,usd_per_gbh\n1,0.041\n2,0.006\n' > "$W/fresh.csv"
FRESH=$(c publish dataset "$W/fresh.csv" "measured yield" --license CC0-1.0 \
        --obtainability open --criteria "captured on one machine" 2>/dev/null)
c list > "$W/fr1.txt" 2>&1
check "an unattested artifact reports PUBLISH age, labelled" \
  "$(grep -c "\[pub .*\] measured yield" "$W/fr1.txt")" "1"
check "an unattested artifact never claims an observation age" \
  "$(grep -c "\[obs .*\] measured yield" "$W/fr1.txt")" "0"
check "a just-published artifact reads <1h, not a minute count" \
  "$(grep -c '\[pub <1h\] measured yield' "$W/fr1.txt")" "1"
# No minute unit exists on purpose: `5m` and `5mo` differ by one character in the one
# column whose job is telling fresh from stale, so misreading it inverts the answer.
check "no minute unit is ever emitted" "$(grep -cE '\[(pub|obs) [0-9]+m\]' "$W/fr1.txt")" "0"

# This arm exercises the RENDERER, so the statement is written directly rather than via
# `attest`: this suite is deliberately signer-free (the signing path and the statement's
# signature are covered by test-signing.sh). The `observed` value is months old while
# `created` is seconds old, which is exactly the case the labels exist to separate.
python3 - "$COMMONS_ROOT" "$FRESH" <<'P'
import json, sys, os
root, aid = sys.argv[1], sys.argv[2]
p = os.path.join(root, "registry", "artifacts", aid + ".json")
m = json.load(open(p))
m.setdefault("verification", {}).setdefault("tier", "T3")
m["verification"]["attested_by"] = {
    "addr": "0x00000000000000000000000000000000000000ff",
    "statement": {"attests": aid, "sha256": m["content"]["sha256"],
                  "criteria": m["verification"].get("criteria", ""),
                  "observed": "2026-01-05T00:00:00Z"}}
json.dump(m, open(p, "w"), sort_keys=True, indent=1)
P
c reindex >/dev/null 2>&1
c list > "$W/fr2.txt" 2>&1
check "an attested artifact reports OBSERVED age, labelled" \
  "$(grep -c "\[obs .*\] measured yield" "$W/fr2.txt")" "1"
check "the observed age replaces the publish age, not sits beside it" \
  "$(grep -c "\[pub .*\] measured yield" "$W/fr2.txt")" "0"
check "observed months ago does not render as freshly published" \
  "$(grep -c '\[obs <1h\] measured yield' "$W/fr2.txt")" "0"

# --json must not change just because time passed, so it carries the absolute instants.
c list --json > "$W/fr.json" 2>/dev/null
OBS=$(python3 -c 'import json,sys
rows={r["id"]:r for r in json.load(open(sys.argv[1]))}
print(rows[sys.argv[2]].get("observed"))' "$W/fr.json" "$FRESH")
check "--json emits absolute observed, not a rendered age" "$OBS" "2026-01-05T00:00:00Z"
check "--json still carries created (additive only)" \
  "$(python3 -c 'import json,sys
rows={r["id"]:r for r in json.load(open(sys.argv[1]))}
print(1 if rows[sys.argv[2]].get("created") else 0)' "$W/fr.json" "$FRESH")" "1"
check "--json observed is explicit null when unattested, not absent" \
  "$(python3 -c 'import json,sys
rows=json.load(open(sys.argv[1]))
print(sum(1 for r in rows if "observed" in r and r["observed"] is None) > 0)' "$W/fr.json")" "True"

# Same invariant as availability: a stale member is a marker, never a verdict.
# The exit-code arms use an untouched artifact on purpose. The doctored fixture above
# carries a statement with no signature, which `verify` correctly calls INVALID (exit 1)
# — that is the one machine-checkable part of T3 doing its job, and asserting 3 there
# would pin the wrong behaviour. Its own age is months old either way.
printf 'slot,usd_per_gbh\n3,0.019\n' > "$W/fresh2.csv"
STALEABLE=$(c publish dataset "$W/fresh2.csv" "second measured yield" --license CC0-1.0 \
            --obtainability open --criteria "captured on one machine" 2>/dev/null)
check "freshness does not move list's exit code" "$(rc c list)" "0"
check "freshness does not move verify's exit code" "$(rc c verify "$STALEABLE")" "3"
check "freshness does not move fsck's exit code" "$(rc c fsck --availability)" "0"
check "the untouched artifact still shows a publish age" \
  "$(c list 2>&1 | grep -c '\[pub <1h\] second measured yield')" "1"

head_ "housekeeping"
check "fsck clean" "$(rc c fsck)" "0"
check "fsck --availability clean" "$(rc c fsck --availability)" "0"
check "reindex clean" "$(rc c reindex)" "0"

printf '\n\033[1mtest-availability: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
