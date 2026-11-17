#!/bin/sh
# two-hub-drill.sh: RELEASING criterion 3, scripted. Two throwaway hubs (bare git repos), two stores (hub
# checkouts) with distinct keys, no network. A publishes; B pulls from A; B publishes a corroborating
# observation; A pulls from B; both stores answer show / explain / verify for the same ids and the script
# compares the binary's own --json answers byte for byte. Exit 0 only if every comparison agrees.
#
#   COMMONS=<binary>            the built commons (default: commons on PATH)
#   TWOHUB_KEEP=1               keep the work directory
#   TWOHUB_CALENDAR=<url>       an OpenTimestamps calendar to stamp A's log against; without it the anchor
#                               step is SKIPPED (and says so); the constructions use --anchor-policy none
#   TWOHUB_MUTATE=1             mutation check: B alone signs one more statement before the comparison;
#                               the drill must then exit non-zero
#   TWOHUB_SKIP_NO_GIT=1        exit 0 with a message when git is missing (default: exit 2)
set -eu
COMMONS=${COMMONS:-commons}
command -v git >/dev/null 2>&1 || {
	echo "two-hub-drill: git is not installed; the drill needs it" >&2
	[ "${TWOHUB_SKIP_NO_GIT:-}" = 1 ] && exit 0
	exit 2
}
# Isolate from the user's git configuration and environment.
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_SYSTEM=/dev/null GIT_TERMINAL_PROMPT=0
export GIT_AUTHOR_NAME=drill GIT_AUTHOR_EMAIL=drill@example.invalid
export GIT_COMMITTER_NAME=drill GIT_COMMITTER_EMAIL=drill@example.invalid
unset COMMONS_KEY COMMONS_POLICY COMMONS_ROOT 2>/dev/null || true
G="git -c commit.gpgsign=false -c tag.gpgsign=false"

W=$(mktemp -d "${TMPDIR:-/tmp}/twohub.XXXXXX")
[ "${TWOHUB_KEEP:-}" = 1 ] || trap 'rm -rf "$W"' EXIT
echo "drill dir: $W"
FAIL=0
step() { printf '\n== %s\n' "$*"; }
bad() { echo "DISAGREE/FAIL: $*"; FAIL=1; }
need() { # need <what> <cmd...>: the command must exit 0
	what=$1; shift
	"$@" >"$W/need.out" 2>&1 || { bad "$what (exit $?)"; sed 's/^/    /' "$W/need.out" | head -20; exit 1; }
}
idof() { sed -n "s/.*\"$1\":\"\\([0-9a-f]\\{64\\}\\)\".*/\\1/p" "$2" | head -1; }

cd "$W"
printf 'drill content, written by A\n' > a.txt
$COMMONS key new --out kA.json >/dev/null
$COMMONS key new --out kB.json >/dev/null

step "two hubs: bare repos with one shared base commit (marker + ignore rules)"
git init -q --bare -b main A.git
git init -q --bare -b main B.git
mkdir seed
$COMMONS init seed/s >/dev/null
( cd seed/s && git init -q -b main && printf 'journal/\nquarantine/\ntmp/\ncache/\n' > .gitignore &&
  git add -A && $G commit -qm "base: rc-store marker" && git push -q "$W/A.git" main && git push -q "$W/B.git" main )
git clone -q A.git wA
git clone -q B.git wB
( cd wA && git remote add b ../B.git )
( cd wB && git remote add a ../A.git )
[ -e wA/rc-store ] && [ -e wB/rc-store ] || { bad "hub checkouts lack the store marker"; exit 1; }

step "A publishes: construction, observation, resource edition"
cd wA
export COMMONS_KEY=$W/kA.json
need "A construction" $COMMONS publish --kind authored --content ../a.txt --media-type text/plain --json
DIG=sha256:$(sha256sum ../a.txt | cut -d' ' -f1)
SIZE=$(wc -c < ../a.txt | tr -d ' ')
cat > ../obsA.json <<J
{"kind":"observed","body":{"content":{"digest":"$DIG","size":$SIZE},"class":"source","referent":{"endpoint":"https://api.example/drill","parameters":{},"response_digest":"$DIG"},"capture":{"at":"2026-01-02T00:00:00Z","evidence":"self-asserted"}}}
J
$COMMONS publish --draft ../obsA.json --json > ../obsA.out || { bad "A observation"; cat ../obsA.out; exit 1; }
OBS_A=$(idof statement ../obsA.out)
SIGNER_A=$($COMMONS key show ../kA.json | sed -n 's/^signer: //p')
printf '{"profile":"task-contract-v1","question":"is a.txt reproducible?","beneficiary":"%s","any_issuer":true,"quorum":{"k":1,"independence":"not-required"}}\n' "$SIGNER_A" > ../ct.json
$COMMONS publish task --name drill-task --contract ../ct.json --json > ../task.out || { bad "A resource edition"; cat ../task.out; exit 1; }
EDITION=$(idof edition ../task.out)
$COMMONS list --json > ../listA.out
RES=$(sed -n 's/.*"resource":"\([0-9a-f]\{64\}\)".*/\1/p' ../listA.out | head -1)
[ -n "$EDITION" ] && [ -n "$RES" ] && [ -n "$OBS_A" ] || { bad "could not read ids from A's answers"; exit 1; }
echo "digest $DIG · observation $OBS_A · resource $RES · edition $EDITION"

step "anchor stamp (optional, needs a calendar)"
if [ -n "${TWOHUB_CALENDAR:-}" ]; then
	need "anchor stamp" $COMMONS anchor stamp --calendar "$TWOHUB_CALENDAR" --allow-private --json
	ANCHOR_POLICY=required
else
	echo "SKIPPED: no TWOHUB_CALENDAR; the anchor stamp needs a calendar and a calendar needs a network; set TWOHUB_CALENDAR to include it"
	ANCHOR_POLICY=none
fi

step "A commits and pushes into hub A"
git add -A && $G commit -qm "A: construction, observation, task"
need "A push" $COMMONS push --base origin/main --anchor-policy $ANCHOR_POLICY --json
cd ..

step "B pulls from hub A"
git clone -q A.git cloneA
cd wB
export COMMONS_KEY=$W/kB.json
need "B pull from A" $COMMONS pull --from-checkout ../cloneA --json

step "B publishes a corroborating observation, commits, pushes to hub B and into hub A"
sed 's#api.example/drill#api.example/drill-b#' ../obsA.json > ../obsB.json
$COMMONS publish --draft ../obsB.json --json > ../obsB.out || { bad "B observation"; cat ../obsB.out; exit 1; }
OBS_B=$(idof statement ../obsB.out)
git add -A && $G commit -qm "B: pulled A's statements, corroborating observation"
need "B push to hub B" $COMMONS push --base origin/main --anchor-policy none --json
git fetch -q a
need "B push into hub A" $COMMONS push --remote a --base a/main --branch from-b --anchor-policy none --json
cd ..

step "A pulls from hub B"
git clone -q B.git cloneB
cd wA
export COMMONS_KEY=$W/kA.json
need "A pull from B" $COMMONS pull --from-checkout ../cloneB --json
cd ..

if [ "${TWOHUB_MUTATE:-}" = 1 ]; then
	step "MUTATION: B alone signs one more statement"
	( cd wB && COMMONS_KEY=$W/kB.json $COMMONS publish --kind describes --about "$DIG" --note "only B holds this" --json >/dev/null )
fi

step "both stores answer the same questions"
CMP=0
compare() { # compare <name> <command words...>: run in both stores, cmp the --json output
	name=$1; shift
	( cd wA && $COMMONS "$@" --json > ../ans-A.out 2>/dev/null; echo $? > ../ans-A.rc ) || true
	( cd wB && $COMMONS "$@" --json > ../ans-B.out 2>/dev/null; echo $? > ../ans-B.rc ) || true
	CMP=$((CMP + 1))
	if [ "$(cat ans-A.rc)" != "$(cat ans-B.rc)" ]; then
		bad "$name: exit A=$(cat ans-A.rc) B=$(cat ans-B.rc)"
	elif [ ! -s ans-A.out ]; then
		bad "$name: empty answer"
	elif cmp -s ans-A.out ans-B.out; then
		echo "same   $name (exit $(cat ans-A.rc), $(wc -c < ans-A.out | tr -d ' ') bytes)"
	else
		bad "$name: the --json answers differ"; diff ans-A.out ans-B.out | head -c 1500 | sed 's/^/    /'
	fi
}
for ref in "$DIG" "$OBS_A" "$OBS_B" "$RES" "$EDITION"; do
	short=$(printf '%s' "$ref" | cut -c1-19)
	compare "show $short" show "$ref"
	compare "explain $short" explain "$ref"
	compare "verify $short" verify "$ref"
done
compare "list" list
compare "show key A" show "$SIGNER_A"

step "a tampered byte in one hub is refused on pull"
rm -rf tampered; git clone -q B.git tampered
T=$(find tampered/blobs -type f | head -1)
[ -n "$T" ] || { bad "no blob to tamper with"; exit 1; }
chmod u+w "$T"; printf 'X' >> "$T"
( cd wA && $COMMONS fsck --json > ../fsck-before.out 2>&1; $COMMONS explain "$DIG" --json > ../ex-before.out 2>&1 )
set +e
( cd wA && $COMMONS pull --from-checkout ../tampered --json > ../tamper.out 2>&1 ); RC=$?
set -e
echo "pull of the tampered hub: exit $RC"
[ "$RC" = 1 ] || bad "tampered blob: expected exit 1, got $RC"
grep -q '"refused":[1-9]' tamper.out || bad "tampered blob: the report counts no refusal"
( cd wA && $COMMONS fsck --json > ../fsck-after.out 2>&1; $COMMONS explain "$DIG" --json > ../ex-after.out 2>&1 )
cmp -s fsck-before.out fsck-after.out || bad "fsck changed after the refused pull"
cmp -s ex-before.out ex-after.out || bad "explain changed after the refused pull"

echo
if [ "$FAIL" = 0 ]; then echo "two-hub drill: PASS ($CMP comparisons agree; tampered pull refused)"; exit 0; fi
echo "two-hub drill: FAIL"; exit 1
