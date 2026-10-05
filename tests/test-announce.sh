#!/usr/bin/env bash
# Peer-announce artifact + command gate. Uses only a throwaway registry and local git remote.
set -uo pipefail
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"
PASS=0; FAIL=0
ok() { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad(){ printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
expect_fail() {
  local label="$1" pattern="$2"; shift 2
  if "$@" >"$W/out" 2>"$W/err"; then
    bad "$label (unexpected success)"
  elif grep -qi "$pattern" "$W/err"; then
    ok "$label"
  else
    bad "$label (missing error pattern: $pattern)"
  fi
}

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-announce-XXXXXX)"
export COMMONS_AGENT=test-announce
trap 'rm -rf "$COMMONS_ROOT"' EXIT
W="$COMMONS_ROOT/work"; mkdir -p "$W"
KEY="$W/key"; printf '11%.0s' $(seq 1 32) >"$KEY"
export COMMONS_SIGNING_KEY="$KEY"
c() { "$COMMONS" "$@"; }

if ! MESSAGE=probe node "$REPO/lib/sign-message.mjs" >/dev/null 2>&1; then
  # The cleanroom has no vendored viem. Supply its documented module seam with a
  # deterministic offline test double; production still invokes the normal scripts.
  mkdir -p "$W/node_modules/viem"
  cat >"$W/node_modules/viem/package.json" <<'MOCK'
{"type":"module","exports":{".":"./index.js","./accounts":"./accounts.js"}}
MOCK
  cat >"$W/node_modules/viem/accounts.js" <<'MOCK'
const address = "0x" + "12".repeat(20);
export function privateKeyToAccount() {
  return {address, async signMessage() { return "0x" + "ab".repeat(65); }};
}
MOCK
  cat >"$W/node_modules/viem/index.js" <<'MOCK'
const address = "0x" + "12".repeat(20);
export async function recoverMessageAddress() { return address; }
MOCK
  export COMMONS_VIEM_DIR="$W"
fi
SIGNER="$(c peer whoami | head -1)"
REFRESHED="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
EXPIRES="$(date -u -d '+90 days' +%Y-%m-%dT%H:%M:%SZ)"
TOO_FAR="$(date -u -d '+200 days' +%Y-%m-%dT%H:%M:%SZ)"
REMOTE="$W/remote.git"; git init --bare -q "$REMOTE"

spec() {
  jq -n --arg announcer "$1" --arg url "$2" --arg refreshed "$REFRESHED"     --arg expires "$3" --arg collection "${4:-cl-1234abcd}"     '{announcer:$announcer,remotes:(if $url == "" then [] else [{url:$url}] end),
      hosts:[{collection:$collection,blobs:"all"}],refreshed:$refreshed,
      expires:$expires}' >"$W/spec.json"
}

printf 'lint refusals\n'
OTHER="0x$(printf other | sha256sum | cut -c1-40)"
spec "$OTHER" "$REMOTE" "$EXPIRES"
expect_fail "announcer must equal signer" "must equal.*signer"   c publish peer-announce "$W/spec.json" mismatch

spec "$SIGNER" "" "$EXPIRES"
expect_fail "empty remotes refused" "non-empty list"   c publish peer-announce "$W/spec.json" empty

spec "$SIGNER" "https://user:pass@example.invalid/repo.git" "$EXPIRES"
expect_fail "credentialed URL refused" "credentials"   c publish peer-announce "$W/spec.json" credentials

spec "$SIGNER" "not-a-git-url" "$EXPIRES"
expect_fail "malformed git URL refused" "plausible git URL"   c publish peer-announce "$W/spec.json" malformed-url

spec "$SIGNER" "$REMOTE" "$EXPIRES" "cl-bad"
expect_fail "malformed hosted collection refused" "well-formed collection"   c publish peer-announce "$W/spec.json" malformed-host

spec "$SIGNER" "$REMOTE" "$EXPIRES"
jq 'del(.expires)' "$W/spec.json" >"$W/missing.json"
expect_fail "missing expires refused" "expires is required"   c publish peer-announce "$W/missing.json" missing-expiry

spec "$SIGNER" "$REMOTE" "$EXPIRES"
jq 'del(.refreshed)' "$W/spec.json" >"$W/missing-refreshed.json"
expect_fail "missing refreshed refused" "refreshed is required"   c publish peer-announce "$W/missing-refreshed.json" missing-refreshed

spec "$SIGNER" "$REMOTE" "$TOO_FAR"
expect_fail "expiry beyond six months refused" "no more than 6 months"   c publish peer-announce "$W/spec.json" far-expiry

spec "$SIGNER" "$REMOTE" "$EXPIRES"
expect_fail "announce cannot carry evidence links" "cannot carry evidence links"   c publish peer-announce "$W/spec.json" evidence-link --link "supports:cl-1234abcd"

env -u COMMONS_SIGNING_KEY "$COMMONS" announce --remote-url "$REMOTE" >"$W/out" 2>"$W/err"
if [ "$?" -ne 0 ] && grep -q COMMONS_SIGNING_KEY "$W/err"; then
  ok "announce refuses without signing key"
else
  bad "announce refuses without signing key"
fi

printf 'publish and refresh\n'
BEFORE="$(c peer stats --json)"
PA1="$(c announce --remote-url "$REMOTE" --hosts cl-1234abcd:members --note local | tail -1)"
if [[ "$PA1" =~ ^pa-[0-9a-f]{8}$ ]]; then ok "announce emits well-formed pa id"; else bad "malformed id: $PA1"; fi
if c cat "$PA1" | jq -e --arg signer "$SIGNER" --arg remote "$REMOTE"   '.announcer == $signer and .remotes[0].url == $remote and
   .hosts[0] == {collection:"cl-1234abcd",blobs:"members"} and
   (.refreshed | type == "string") and (.expires | type == "string")' >/dev/null; then
  ok "announce blob round-trips"
else
  bad "announce blob round-trip"
fi
AFTER="$(c peer stats --json)"
if [ "$BEFORE" = "$AFTER" ]; then ok "peer stats unchanged by pa publish"; else bad "pa changed peer stats"; fi

PA2="$(c announce --remote-url "$REMOTE" --hosts cl-1234abcd:all | tail -1)"
if [ "$PA2" != "$PA1" ] && c get "$PA2" | jq -e --arg old "$PA1"   '.links | any(.rel == "supersedes" and .id == $old)' >/dev/null; then
  ok "re-announce supersedes prior same-signer announce"
else
  bad "re-announce supersedes chain"
fi

printf 'remote exposure warnings (advisory)\n'
warn_case() {
  local label="$1" url="$2" want="$3"
  spec "$SIGNER" "$url" "$EXPIRES"
  if c publish peer-announce "$W/spec.json" "warn-$label" >"$W/out" 2>"$W/err"; then
    if [ -n "$want" ]; then
      if grep -q "warning: remotes\[0\].url $want" "$W/err" && grep -q "public and permanent" "$W/err"; then
        ok "$label warns, exit 0"
      else
        bad "$label: missing warning ($want): $(cat "$W/err")"
      fi
    elif grep -q "warning: remotes" "$W/err"; then
      bad "$label: unexpected warning: $(cat "$W/err")"
    else
      ok "$label publishes without a warning"
    fi
  else
    bad "$label refused: $(cat "$W/err")"
  fi
}
warn_case local-path "$W/private-hub" "is a local filesystem path"
warn_case rfc1918 "https://192.168.1.20/hub.git" "points at a private"
warn_case single-label "ssh://git@nas/hub.git" "points at a single-label host"
warn_case dot-local "git@builder.local:hub.git" "points at an internal hostname"
warn_case username "ssh://alice@git.example.org/hub.git" "includes a username"
warn_case public-https "https://git.example.org/team/hub.git" ""
warn_case public-scp "git@git.example.org:team/hub.git" ""
if c announce --remote-url /tmp/commons-announce-probe >"$W/out" 2>"$W/err" \
   && grep -q "is a local filesystem path" "$W/err"; then
  ok "announce command warns on a local path, exit 0"
else
  bad "announce command local-path warning"
fi
if "$COMMONS" announce --help | tr -s ' \n' ' ' | grep -q "public and permanent"; then
  ok "announce --help says announces are public and permanent"
else
  bad "announce --help missing the permanence note"
fi

printf 'evidence exclusion\n'
printf 'analysis\n' >"$W/report.txt"
REPORT="$(c publish report "$W/report.txt" guarded --tier T2 --criteria reviewed   --link "supports:$PA2" | tail -1)"
STATUS="$(c status "$REPORT" --brief 2>&1 || true)"
if [[ "$STATUS" == *"chain=T2 nodes=1"* ]]; then
  ok "pa target cannot weaken or expand evidence chain"
else
  bad "pa affected chain grade ($STATUS)"
fi
if ! c graph "$REPORT" --rel evidence | grep -q "$PA2"; then
  ok "evidence graph omits links to pa"
else
  bad "evidence graph traversed pa"
fi
if c graph "$REPORT" --rel all | grep -q "$PA2"; then
  ok "all-rel graph retains structural visibility"
else
  bad "all-rel graph lost structural pa link"
fi

printf '\n\033[1mtest-announce: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
