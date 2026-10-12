#!/usr/bin/env bash
# Incoming artifacts are attributed by signatures that verify, not by populated fields (#72).
#
# What this pins:
#   1. a forged attestation (garbage signature naming a trusted peer) is refused at pull,
#      with and without COMMONS_REQUIRE_SIG
#   2. COMMONS_REQUIRE_SIG=1 accepts a dataset whose publish is verified-signed, with no
#      attestation (it used to mean "requires a T3 attestation")
#   3. COMMONS_REQUIRE_SIG=1 still refuses a fully unsigned dataset
#   4. a signed dataset from a peer registered here with trust=none is refused
#   5. a signed dataset from a peer this host never registered is still admitted (open
#      federation is unchanged; only explicit distrust refuses)
#   6. a valid attestation by a registered, trusted peer is still admitted
set -uo pipefail

unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"
PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_(){ printf '\n\033[1m%s\033[0m\n' "$1"; }

P="$(mktemp -d -t commons-test-ingest-attr-XXXXXX)"; trap 'rm -rf "$P"' EXIT
gx() { git -c user.email=t@t -c user.name=t -c commit.gpgsign=false "$@"; }
for k in t m u; do
  python3 -c "import secrets;open('$P/$k.key','w').write('0x'+secrets.token_hex(32))"; chmod 600 "$P/$k.key"
done
mkdir -p "$P/w0/registry"
addr() { COMMONS_ROOT="$P/w0" COMMONS_SIGNING_KEY="$P/$1.key" "$COMMONS" peer whoami 2>/dev/null | head -1; }
T=$(addr t); M=$(addr m); U=$(addr u)
if [ -z "$T" ] || [ -z "$M" ] || [ -z "$U" ]; then
  echo "cannot derive signing addresses (is node + viem available?)"; exit 1
fi

R="$P/recv"; "$COMMONS" hub init "$R" >/dev/null 2>&1; ( cd "$R" && gx add -A && gx commit -qm init )
COMMONS_ROOT="$R" "$COMMONS" peer add "$T" --agent-id trusted --trust full >/dev/null 2>&1
COMMONS_ROOT="$R" "$COMMONS" peer add "$M" --agent-id mallory --trust none >/dev/null 2>&1
S="$P/send"; git clone -q "$R" "$S"; ( cd "$R" && git remote add s "$S" )

pub() {  # pub <branch> <key|-> <agent> <file> <title> [extra publish args…]
  local br=$1 key=$2 agent=$3 f=$4 title=$5; shift 5
  ( cd "$S" && gx checkout -q main && gx checkout -q -b "$br" )
  if [ "$key" = "-" ]; then
    ( cd "$S" && COMMONS_ROOT="$S" COMMONS_AGENT="$agent" "$COMMONS" publish dataset "$f" "$title" \
        --license CC0-1.0 --obtainability open "$@" 2>/dev/null | tail -1 )
  else
    ( cd "$S" && COMMONS_ROOT="$S" COMMONS_AGENT="$agent" COMMONS_SIGNING_KEY="$P/$key.key" \
        "$COMMONS" publish dataset "$f" "$title" --license CC0-1.0 --obtainability open "$@" 2>/dev/null | tail -1 )
  fi
}
commit() { ( cd "$S" && gx add -A registry store && gx commit -qm "$1" ); }
pull() {  # pull <branch> <require_sig 0|1>  -> exit code; output in $P/out.txt
  ( cd "$R" && COMMONS_ROOT="$R" COMMONS_REQUIRE_SIG="$2" "$COMMONS" pull s --branch "$1" --dry-run ) \
    >"$P/out.txt" 2>&1; echo $?
}
out() { cat "$P/out.txt"; }

head_ "1. a forged attestation naming a trusted peer is refused"
printf 'a\n1\n' > "$P/a.csv"
ID=$(pub forged - anon "$P/a.csv" forged --tier T3 --criteria c)
python3 - "$S/registry/artifacts/$ID.json" "$T" <<'PY'
import json, sys
p, addr = sys.argv[1:]; m = json.load(open(p))
m["verification"]["attested_by"] = {"addr": addr, "sig": "0x" + "11" * 65,
  "statement": {"attests": m["id"], "sha256": m["content"]["sha256"], "criteria": "c",
                "observed": "2026-10-11T00:00:00Z"}}
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
commit forged
check "🔒 refused without COMMONS_REQUIRE_SIG" "$(pull forged 0)" "1"
check "  naming the invalid attestation" "$(out | grep -c "attestation by .* is invalid")" "1"
check "🔒 refused with COMMONS_REQUIRE_SIG=1" "$(pull forged 1)" "1"

head_ "2–3. COMMONS_REQUIRE_SIG=1 means a verified signature, not an attestation"
printf 'b\n2\n' > "$P/b.csv"; pub signed t trusted "$P/b.csv" "signed T0" >/dev/null; commit signed
check "a verified signed publish (no attestation) is admitted" "$(pull signed 1)" "0"
printf 'c\n3\n' > "$P/c.csv"; pub unsigned - anon "$P/c.csv" "unsigned" >/dev/null; commit unsigned
check "🔒 a fully unsigned dataset is refused" "$(pull unsigned 1)" "1"
check "  naming the rule" "$(out | grep -c 'unsigned artifact and COMMONS_REQUIRE_SIG=1')" "1"
check "an unsigned dataset is still admitted without the flag" "$(pull unsigned 0)" "0"

head_ "4–5. trust=none refuses every type; unregistered publishers are unchanged"
printf 'd\n4\n' > "$P/d.csv"; pub distrusted m mallory "$P/d.csv" "from mallory" >/dev/null; commit distrusted
check "🔒 a signed dataset from a trust=none peer is refused" "$(pull distrusted 0)" "1"
check "  naming trust=none" "$(out | grep -c 'registered here with trust=none')" "1"
printf 'e\n5\n' > "$P/e.csv"; pub stranger u stranger "$P/e.csv" "from a stranger" >/dev/null; commit stranger
check "a signed dataset from an unregistered publisher is admitted" "$(pull stranger 0)" "0"

head_ "6. a valid attestation by a trusted peer is still admitted"
printf 'f\n6\n' > "$P/f.csv"
ID6=$(pub attested t trusted "$P/f.csv" "attested" --tier T3 --criteria "probe capture")
( cd "$S" && COMMONS_ROOT="$S" COMMONS_AGENT=trusted COMMONS_SIGNING_KEY="$P/t.key" \
    "$COMMONS" attest "$ID6" --criteria "probe capture" >/dev/null 2>&1 )
commit attested
check "admitted with COMMONS_REQUIRE_SIG=1" "$(pull attested 1)" "0"

printf '\n\033[1mtest-ingest-attribution: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
