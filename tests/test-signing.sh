#!/usr/bin/env bash
# P2 gate — signed ledger, peer registry, key validity windows, hash chain,
# license metadata, publish-time secret lint.
set -uo pipefail

# Hermeticity: never inherit the operator's registry/key/exec settings. A suite that
# behaves differently depending on the invoking shell is measuring the shell.
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG


HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"

PASS=0; FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

if ! command -v node >/dev/null 2>&1; then
  echo "test-signing: node unavailable — cannot validate P2"; exit 1
fi
# Hermetic identity: a throwaway key unless the caller supplies one. (Previously
# defaulted to the maintainer's key path, so a fresh clone could never run P2.)
if [ -z "${COMMONS_SIGNING_KEY:-}" ]; then
  _TMPKEY="$(mktemp -t commons-sign-key-XXXXXX)"
  python3 -c "import secrets,sys;open(sys.argv[1],'w').write('0x'+secrets.token_hex(32))" "$_TMPKEY"
  chmod 600 "$_TMPKEY"; export COMMONS_SIGNING_KEY="$_TMPKEY"
fi
if ! MESSAGE=probe node "$REPO/lib/sign-message.mjs" >/dev/null 2>&1; then
  echo "test-signing: signer not functional (viem missing or no key) — cannot validate P2"
  exit 1
fi

export COMMONS_ROOT; COMMONS_ROOT="$(mktemp -d -t commons-test-sign-XXXXXX)"
export COMMONS_AGENT=test-p2
trap 'rm -rf "$COMMONS_ROOT" ${_TMPKEY:+"$_TMPKEY"}' EXIT
W="$COMMONS_ROOT/work"; mkdir -p "$W" "$COMMONS_ROOT/registry"

c() { "$COMMONS" "$@"; }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
# P4 split the ledger per writer: this host's own log is named after its address.
# Resolved lazily, because the address isn't known until the first `peer whoami`.
mylog() { echo "$COMMONS_ROOT/registry/ledger/$(echo "$ME" | tr 'A-Z' 'a-z').jsonl"; }

# Two identities: this host's real key, plus a throwaway "peer" key.
ME=$(c peer whoami | head -1)
PEERKEY="$W/peer.key"
python3 -c "import secrets;open('$PEERKEY','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$PEERKEY"
THEM=$(COMMONS_SIGNING_KEY="$PEERKEY" c peer whoami | head -1)

head_ "identity"
check "whoami returns an address" "$(echo "$ME" | grep -c '^0x[0-9a-fA-F]\{40\}$')" "1"
check "second key is a different identity" "$([ "$ME" != "$THEM" ] && echo yes)" "yes"
check "whoami without a key exits 1" "$(COMMONS_SIGNING_KEY= rc c peer whoami)" "1"
check "warns that entries will be unsigned" "$(COMMONS_SIGNING_KEY= c peer whoami 2>&1 | grep -c 'unsigned')" "1"

head_ "signer key source: COMMONS_SIGNING_KEY or ~/.commons/signing.key, nothing else"
# ETH_SIGNER_KEY_PATH used to be a second fallback. A variable exported for some other
# signing tool (often a payment wallet) would then silently become the commons identity,
# so it was removed. Isolate HOME so the ~/.commons fallback is under test control.
_SH="$W/signer-home"; mkdir -p "$_SH/.commons"
_ETHKEY="$W/other-tool.key"; _HOMEKEY="$_SH/.commons/signing.key"
python3 -c "import secrets,sys;[open(p,'w').write('0x'+secrets.token_hex(32)) for p in sys.argv[1:]]" "$_ETHKEY" "$_HOMEKEY"
chmod 600 "$_ETHKEY" "$_HOMEKEY"
_addr() { python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["address"])'; }
_ETHADDR=$(MESSAGE=probe COMMONS_SIGNING_KEY="$_ETHKEY" node "$REPO/lib/sign-message.mjs" | _addr)
_HOMEADDR=$(MESSAGE=probe COMMONS_SIGNING_KEY="$_HOMEKEY" node "$REPO/lib/sign-message.mjs" | _addr)
check "ETH_SIGNER_KEY_PATH alone is ignored: signer uses ~/.commons/signing.key" \
  "$(env -u COMMONS_SIGNING_KEY HOME="$_SH" ETH_SIGNER_KEY_PATH="$_ETHKEY" MESSAGE=probe \
       node "$REPO/lib/sign-message.mjs" | _addr)" "$_HOMEADDR"
check "  ...and never the ETH_SIGNER_KEY_PATH identity" \
  "$([ "$_HOMEADDR" != "$_ETHADDR" ] && echo distinct)" "distinct"
rm -f "$_HOMEKEY"
check "ETH_SIGNER_KEY_PATH alone with no ~/.commons key: signer refuses (exit 2)" \
  "$(env -u COMMONS_SIGNING_KEY HOME="$_SH" ETH_SIGNER_KEY_PATH="$_ETHKEY" MESSAGE=probe \
       node "$REPO/lib/sign-message.mjs" >/dev/null 2>&1; echo $?)" "2"
check "  refusal names the ~/.commons path, not the ETH_SIGNER_KEY_PATH file" \
  "$(env -u COMMONS_SIGNING_KEY HOME="$_SH" ETH_SIGNER_KEY_PATH="$_ETHKEY" MESSAGE=probe \
       node "$REPO/lib/sign-message.mjs" 2>&1 | grep -c "$_SH/.commons/signing.key")" "1"
check "COMMONS_SIGNING_KEY wins over ETH_SIGNER_KEY_PATH" \
  "$(ETH_SIGNER_KEY_PATH="$_ETHKEY" MESSAGE=probe COMMONS_SIGNING_KEY="$PEERKEY" \
       node "$REPO/lib/sign-message.mjs" | _addr)" "$THEM"

head_ "signed publish"
printf 'avs,claimed\nalpha,900\n' > "$W/d.csv"
DS=$(c publish dataset "$W/d.csv" "signed dataset" --license CC0-1.0 2>/dev/null)
check "publish succeeds" "$(echo "$DS" | grep -c '^ds-')" "1"
check "ledger entry carries addr" "$(tail -1 "$(mylog)" | python3 -c 'import json,sys;print(json.load(sys.stdin)["addr"])')" "$ME"
check "ledger entry carries sig" "$(tail -1 "$(mylog)" | python3 -c 'import json,sys;print(json.load(sys.stdin)["sig"][:2])')" "0x"
check "license recorded" "$(c get "$DS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["license"])')" "CC0-1.0"
# A --force republish that omits --license keeps the recorded one (carry-forward), so it
# must NOT claim the dataset is unlicensed: the warning reads the final manifest (#18).
check "force republish keeping a licence does not warn" "$(c publish dataset "$W/d.csv" "x" --force 2>&1 | grep -c 'without --license')" "0"
check "  ...and the licence is still recorded" "$(c get "$DS" | python3 -c 'import json,sys;print(json.load(sys.stdin)["license"])')" "CC0-1.0"
printf 'avs,claimed\nbeta,1\n' > "$W/d-unlic.csv"
check "dataset without license warns" "$(c publish dataset "$W/d-unlic.csv" "x" 2>&1 | grep -c 'without --license')" "1"

head_ "publish-time license advisory (non-dataset types)"
printf '# Report\n\nSome findings.\n' > "$W/adv-report.md"
RPUL=$(c publish report "$W/adv-report.md" "unlicensed report" 2>"$W/err.txt")
check "unlicensed report publishes" "$(echo "$RPUL" | grep -c '^rp-')" "1"
check "unlicensed report warns" "$(grep -c 'report published without --license' "$W/err.txt")" "1"
check "unlicensed report warning names all-rights-reserved" \
  "$(grep -c 'all rights reserved by default' "$W/err.txt")" "1"
check "unlicensed report exits 0" "$(rc c publish report "$W/adv-report.md" "unlicensed report" --force)" "0"

printf '{"interpreter": "bash", "steps": ["true"], "outputs": {}}' > "$W/adv-wf.json"
WFUL=$(c publish workflow "$W/adv-wf.json" "unlicensed workflow" 2>"$W/err.txt")
check "unlicensed workflow publishes" "$(echo "$WFUL" | grep -c '^wf-')" "1"
check "unlicensed workflow warns" "$(grep -c 'workflow published without --license' "$W/err.txt")" "1"

printf '#!/bin/sh\necho hi\n' > "$W/adv-sk.sh"
SKUL=$(c publish skill "$W/adv-sk.sh" "unlicensed skill" 2>"$W/err.txt")
check "unlicensed skill publishes" "$(echo "$SKUL" | grep -c '^sk-')" "1"
check "unlicensed skill warns" "$(grep -c 'skill published without --license' "$W/err.txt")" "1"

printf '# Wiki\n\nprose.\n' > "$W/adv-wk.md"
WKUL=$(c publish wiki "$W/adv-wk.md" "unlicensed wiki" 2>"$W/err.txt")
check "unlicensed wiki publishes" "$(echo "$WKUL" | grep -c '^wk-')" "1"
check "unlicensed wiki warns" "$(grep -c 'wiki published without --license' "$W/err.txt")" "1"

printf 'Some prose.\n' > "$W/adv-sy.txt"
SYUL=$(c publish synthesis "$W/adv-sy.txt" "unlicensed synthesis" 2>"$W/err.txt")
check "unlicensed synthesis publishes" "$(echo "$SYUL" | grep -c '^sy-')" "1"
check "unlicensed synthesis warns" "$(grep -c 'synthesis published without --license' "$W/err.txt")" "1"

# Licensed: no warning at all.
printf '# Licensed report\n\nfindings.\n' > "$W/adv-report-lic.md"
RPLIC=$(c publish report "$W/adv-report-lic.md" "licensed report" --license CC-BY-4.0 2>"$W/err.txt")
check "licensed report has no advisory warning" "$(grep -c 'without --license' "$W/err.txt")" "0"

# Bibliography: same editorial-metadata shape as collection/task (justified in the
# LICENSE_ADVISORY_TYPES comment in bin/commons) — no warning either.
printf '[]' > "$W/adv-bb.json"
BBUL=$(c publish bibliography "$W/adv-bb.json" "unlicensed bibliography" 2>"$W/err.txt")
check "unlicensed bibliography publishes" "$(echo "$BBUL" | grep -c '^bb-')" "1"
check "unlicensed bibliography has no advisory warning" "$(grep -c 'without --license' "$W/err.txt")" "0"

# Collection and task: editorial metadata, explicitly excluded from the advisory.
printf '{"scope": "test", "maintainers": [{"addr": "%s"}], "members": []}' "$ME" > "$W/adv-cl.json"
CLUL=$(c publish collection "$W/adv-cl.json" "unlicensed collection" 2>"$W/err.txt")
check "unlicensed collection publishes" "$(echo "$CLUL" | grep -c '^cl-')" "1"
check "unlicensed collection has no advisory warning" "$(grep -c 'without --license' "$W/err.txt")" "0"

printf '{"objective": "do a thing", "priority": 2, "expires": "2099-01-01T00:00:00Z", "execution": {"brief": "just do it"}, "verification": {"tier": "T2", "criteria": "prose review"}, "beneficiary": {"agent": "x", "addr": "%s"}}' "$ME" > "$W/adv-tk.json"
TKUL=$(c publish task "$W/adv-tk.json" "unlicensed task" 2>"$W/err.txt")
check "unlicensed task publishes" "$(echo "$TKUL" | grep -c '^tk-')" "1"
check "unlicensed task has no advisory warning" "$(grep -c 'without --license' "$W/err.txt")" "0"

# Dedup no-op path (identical bytes, no --force): must not re-warn on a re-publish
# that produces no new artifact.
DEDUP_OUT=$(c publish report "$W/adv-report.md" "unlicensed report" 2>"$W/err.txt")
check "dedup no-op still reports already published" "$(echo "$DEDUP_OUT" | grep -c 'already published')" "1"
check "dedup no-op does not re-warn" "$(grep -c 'without --license' "$W/err.txt")" "0"

head_ "log --verify"
check "unknown signer flagged (empty registry)" "$(rc c log --verify)" "1"
check "flag names the address" \
  "$([ "$(grep -c "UNKNOWN SIGNER $ME" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
c peer add "$ME" --agent-id test-p2 --trust full --note "this host" >/dev/null
check "peer add works" "$(c peer list | grep -c "$ME")" "1"
check "clean once signer is registered" "$(rc c log --verify)" "0"
check "reports OK" "$(grep -c 'log --verify: .* OK' "$W/out.txt")" "1"

head_ "tampering"
cp "$(mylog)" "$W/ledger.bak"
# flip a signed field: signature must no longer recover the claimed address
python3 - "$(mylog)" <<'PY'
import json, sys
p = sys.argv[1]
lines = [json.loads(l) for l in open(p) if l.strip()]
lines[-1]["id"] = "ds-deadbeef"
open(p, "w").write("".join(json.dumps(e, sort_keys=True) + "\n" for e in lines))
PY
check "tampered field flagged" "$(rc c log --verify)" "1"
check "reported as bad signature" "$(grep -c 'BAD SIGNATURE' "$W/out.txt")" "1"
cp -f "$W/ledger.bak" "$(mylog)"
check "restored ledger verifies" "$(rc c log --verify)" "0"

# a foreign signature that is cryptographically valid but from an unregistered key
PEERKEY="$PEERKEY" REPO="$REPO" python3 - "$(mylog)" <<'PY'
import hashlib, json, os, subprocess, sys
p = sys.argv[1]
raw = [l for l in open(p).read().splitlines() if l.strip()]
e = dict(json.loads(raw[-1]))
e.pop("sig2", None)   # a v1-only event signed by the foreign key below
e["action"] = "publish"; e["id"] = "ds-11111111"
payload = {k: e[k] for k in ("action", "agent", "id", "sha256", "ts") if k in e}
msg = json.dumps(payload, sort_keys=True, separators=(",", ":"))
env = dict(os.environ, COMMONS_SIGNING_KEY=os.environ["PEERKEY"])
out = subprocess.run(["node", os.environ["REPO"] + "/lib/sign-message.mjs", "--stdin"],
                     input=msg, capture_output=True, text=True, env=env)
s = json.loads(out.stdout)
e["addr"], e["sig"] = s["address"], s["signature"]
e["prev"] = hashlib.sha256(raw[-1].encode()).hexdigest()
with open(p, "a") as f: f.write(json.dumps(e, sort_keys=True) + "\n")
PY
check "valid sig from unregistered key flagged" "$(rc c log --verify)" "1"
check "reported as unknown signer" "$(grep -c "UNKNOWN SIGNER $THEM" "$W/out.txt")" "1"

head_ "key validity windows"
c peer add "$THEM" --agent-id peer-two --trust datasets-only >/dev/null
check "registered peer now verifies" "$(rc c log --verify)" "0"
# NB: only ever narrow the window of $THEM (the foreign key). Revoking $ME would
# invalidate this host's own entries and every later publish in the suite.
THEM_TS=$(python3 -c "
import glob, json
ls = []
for f in glob.glob('$COMMONS_ROOT/registry/ledger/*.jsonl'):
    ls += [json.loads(l) for l in open(f) if l.strip()]
print([e for e in ls if (e.get('addr') or '').lower()=='$THEM'.lower()][-1]['ts'])")
c peer revoke "$THEM" --at "$THEM_TS" >/dev/null
check "entry signed at/after revocation is flagged" "$(rc c log --verify)" "1"
check "flagged as key not valid" "$(grep -c 'KEY NOT VALID' "$W/out.txt")" "1"
check "reason names revoked_at" "$(grep -c 'revoked_at' "$W/out.txt")" "1"
# push revocation into the future: that same entry is historically valid again
c peer revoke "$THEM" --at "2099-01-01T00:00:00Z" >/dev/null
check "history before revocation stays valid" "$(rc c log --verify)" "0"
# a valid_from after the entry invalidates it from the other direction
c peer add "$THEM" --force --valid-from "2099-01-01T00:00:00Z" --trust datasets-only >/dev/null
check "entry before valid_from flagged" "$(rc c log --verify)" "1"
check "reason names valid_from" "$(grep -c 'valid_from' "$W/out.txt")" "1"
c peer add "$THEM" --force --valid-from "2000-01-01T00:00:00Z" --trust datasets-only >/dev/null
c peer revoke "$THEM" --at "2099-01-01T00:00:00Z" >/dev/null
check "sane window verifies again" "$(rc c log --verify)" "0"

head_ "rotation chain"
# A fresh third key that claims to replace $THEM.
ROTKEY="$W/rot.key"
python3 -c "import secrets;open('$ROTKEY','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$ROTKEY"
ROT=$(COMMONS_SIGNING_KEY="$ROTKEY" c peer whoami | head -1)
c peer add "$ROT" --agent-id peer-two --trust datasets-only --rotated-from "$THEM" >/dev/null
check "rotation recorded" "$(c peer list | grep -c 'rotated')" "1"
check "rotated-from address preserved" \
  "$(python3 -c "
import json;d=json.load(open('$COMMONS_ROOT/registry/peers.json'))
print([p for p in d['peers'] if p['addr'].lower()=='$ROT'.lower()][0]['rotated_from'])")" "$THEM"
check "rotation does not break history" "$(rc c log --verify)" "0"

head_ "hash chain"
cp "$(mylog)" "$W/ledger2.bak"
python3 - "$(mylog)" <<'PY'
import sys
p = sys.argv[1]
lines = [l for l in open(p).read().splitlines() if l.strip()]
del lines[1]                      # excise a line from the middle
open(p, "w").write("\n".join(lines) + "\n")
PY
check "deleted line breaks the chain" "$(rc c log --verify)" "1"
check "reported as chain break" "$(grep -c 'CHAIN BREAK' "$W/out.txt")" "1"
cp -f "$W/ledger2.bak" "$(mylog)"
python3 - "$(mylog)" <<'PY'
import sys
p = sys.argv[1]
lines = [l for l in open(p).read().splitlines() if l.strip()]
lines[1], lines[2] = lines[2], lines[1]     # reorder
open(p, "w").write("\n".join(lines) + "\n")
PY
check "reordered lines break the chain" "$(rc c log --verify)" "1"
cp -f "$W/ledger2.bak" "$(mylog)"
check "intact chain verifies" "$(rc c log --verify)" "0"

head_ "unsigned entries are tolerated locally, flagged in strict mode"
printf 'unsigned,local\nonly,1\n' > "$W/unsigned-local.csv"
COMMONS_SIGNING_KEY= c publish dataset "$W/unsigned-local.csv" "unsigned pub" >/dev/null 2>&1
# P4 routes unsigned writes to their own `local-unsigned` log: unsigned work is
# segregated by construction, never interleaved into a signed chain.
UNSIGNED_LOG="$COMMONS_ROOT/registry/ledger/local-unsigned.jsonl"
check "unsigned entry segregated into its own log" "$([ -f "$UNSIGNED_LOG" ] && echo yes)" "yes"
check "unsigned entry has null sig" "$(tail -1 "$UNSIGNED_LOG" | python3 -c 'import json,sys;print(json.load(sys.stdin)["sig"])')" "None"
check "signed log untouched by the unsigned write" \
  "$(tail -1 "$(mylog)" | python3 -c 'import json,sys;print(json.load(sys.stdin)["sig"][:2])')" "0x"
check "tolerated by default" "$(rc c log --verify)" "0"
check "counted in the summary" "$(grep -c 'unsigned (local, tolerated)' "$W/out.txt")" "1"
check "flagged under --strict" "$(rc c log --verify --strict)" "1"
check "reported as UNSIGNED" "$(grep -c 'UNSIGNED' "$W/out.txt")" "1"

head_ "fsck --ledger"
check "fsck --ledger runs the audit" "$(rc c fsck --ledger)" "0"
check "audit section printed" "$(grep -c 'ledger signature audit' "$W/out.txt")" "1"
check "fsck --ledger --strict fails on unsigned" "$(rc c fsck --ledger --strict)" "1"

head_ "secret lint (prevention beats retraction)"
cat > "$W/leak.txt" <<'EOF'
service_token = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
EOF
check "publish refused on blocking finding" "$(rc c publish dataset "$W/leak.txt" "leak")" "1"
check "refusal explains immutability" "$(grep -c 'best-effort' "$W/err.txt")" "1"
check "secret never echoed in full" "$(grep -c 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' "$W/err.txt")" "0"
check "blob not stored" "$(c list 2>/dev/null | grep -c 'leak$')" "0"
check "--allow-secrets overrides" "$(rc c publish dataset "$W/leak.txt" "leak ok" --allow-secrets --license MIT)" "0"
cat > "$W/pii.txt" <<'EOF'
respondent contact: person@example.org
EOF
check "PII only warns, does not block" "$(rc c publish dataset "$W/pii.txt" "pii" --license MIT)" "0"
check "warning surfaced" "$(grep -c 'email address' "$W/err.txt")" "1"
cat > "$W/clean.csv" <<'EOF'
avs,claimed
alpha,900
EOF
check "clean file publishes silently" "$(rc c publish dataset "$W/clean.csv" "clean" --license MIT)" "0"
check "self-test: lint flags an eth private key" \
  "$(printf 'key: 0x%064d\n' 1 > "$W/k.txt"; rc python3 "$REPO/lib/publish_lint.py" "$W/k.txt")" "1"
check "lint ignores sha256 fields" \
  "$(printf '{\"sha256\": \"%064d\"}\n' 2 > "$W/h.json"; rc python3 "$REPO/lib/publish_lint.py" "$W/h.json")" "0"
check "lint respects an allow marker" \
  "$(printf 'token = \"ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\"  # lint: allow\n' > "$W/a.txt"; rc python3 "$REPO/lib/publish_lint.py" "$W/a.txt")" "0"
check "lint skips harmless binary content" \
  "$(printf 'just some plain binary bytes here\0\0tail' > "$W/b.bin"; rc python3 "$REPO/lib/publish_lint.py" "$W/b.bin")" "0"
# Binary scan path (P2, TODO 2026-08-23 §2.3): in a packed record the key can be
# glued directly to the preceding column value with no word-boundary character
# between them ("...api_keysk-proj-..."), so a leading \b anchor silently
# fails to match a credential sitting there in plaintext bytes. The binary
# path now uses a leading-\b-stripped copy of BLOCK_PATTERNS so this shape is
# still caught; the text path keeps its anchors, so text-mode false-positive
# behaviour is unchanged (proven by the control case right below).
check "lint catches a credential glued to prior bytes in a binary record" \
  "$(printf 'api_keysk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\0\0tail' > "$W/b2.bin"; rc python3 "$REPO/lib/publish_lint.py" "$W/b2.bin")" "1"
check "text-path control: the identical glued shape (no NUL) is still NOT flagged" \
  "$(printf 'api_keysk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789\n' > "$W/b2.txt"; rc python3 "$REPO/lib/publish_lint.py" "$W/b2.txt")" "0"

# Truncation must be said out loud ("a partial scan that prints clean is worse").
# The cap is now 100 MiB (GitHub's per-file push limit) and the scan streams. Crossing
# a real 100 MiB cap in every run is slow, so the truncation checks lower the cap with
# COMMONS_LINT_MAX_BYTES, which can only LOWER it (checked below).
python3 - "$W" <<'PY'
import sys, os
w = sys.argv[1]
row = '{"block":1,"note":"filler row for the truncation test"}\n'
cap = 8 << 20
with open(os.path.join(w, "big.jsonl"), "w") as f:          # key past 8 MiB
    f.write(row * (cap // len(row) + 2000))
    f.write('{"k":"AKIA' + 'QQQQRRRRSSSSTTTT' + '"}\n')
with open(os.path.join(w, "exact.jsonl"), "wb") as f:       # exactly at the lowered cap
    f.write((b"x" * 1023 + b"\n") * (cap // 1024))
with open(os.path.join(w, "bigbin.bin"), "wb") as f:        # binary, over the lowered cap
    f.write(b"\0\0" + (b"y" * 1023 + b"\n") * (cap // 1024 + 10))
# key straddling the 1 MiB read-chunk boundary, on ordinary short lines
C = 1 << 20
with open(os.path.join(w, "straddle.txt"), "wb") as f:
    f.write((b"y" * 99 + b"\n") * ((C - 50) // 100) + b"z" * 40 + b" AKIA" + b"QQQQRRRRSSSSTTTT\n")
with open(os.path.join(w, "straddle.bin"), "wb") as f:
    f.write(b"\0\0" + b"\n" * (C - 12) + b"api_keysk-proj-" + b"B" * 30 + b"\n")
# multibyte characters straddling the chunk boundary must decode intact: no replacement
# chars, so no spurious findings, and a key after them is still seen on the right line
with open(os.path.join(w, "utf8.txt"), "wb") as f:
    f.write(b"a" * (C - 3) + "\u00e9\u20ac\U0001F600".encode() * 4 + b"\nk AKIA" + b"QQQQRRRRSSSSTTTT\n")
# one 3 MiB line (minified JSON shape) with a key near its end: scanned in windows
with open(os.path.join(w, "longline.json"), "w") as f:
    f.write('{"rows":[' + '{"a":1},' * (3 * C // 8) + '{"k":"AKIA' + 'QQQQRRRRSSSSTTTT"}]}\n')
PY
LOWCAP=8388608
check "streamed scan: key past the OLD 8 MiB cap is now BLOCKED (default cap 100 MiB)" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/big.jsonl")" "1"
check "streamed scan: no truncation warn under the default cap" \
  "$(grep -c 'scan incomplete' "$W/out.txt")" "0"
check "COMMONS_LINT_MAX_BYTES cannot RAISE the cap (ignored above the default)" \
  "$(COMMONS_LINT_MAX_BYTES=$((1<<40)) python3 -c 'import sys; sys.path.insert(0, sys.argv[1]); import publish_lint as p; print(p.default_max_bytes() == p.DEFAULT_MAX_BYTES == 100 << 20)' "$REPO/lib")" "True"
check "lint over the cap: past-cap key is NOT seen (exit 0)" \
  "$(COMMONS_LINT_MAX_BYTES=$LOWCAP rc python3 "$REPO/lib/publish_lint.py" "$W/big.jsonl")" "0"
check "lint over the cap: emits a 'scan incomplete' warn" \
  "$(grep -c 'WARN  big.jsonl:?  scan incomplete' "$W/out.txt")" "1"
check "lint over the cap: warn names the unscanned remainder" \
  "$(grep -c 'was NOT scanned for secrets' "$W/out.txt")" "1"
check "lint over the cap: verdict is marked PARTIAL, not a bare 'clean'" \
  "$(grep -c '^secret-lint: clean (PARTIAL: 1 file(s) only partly scanned)$' "$W/out.txt")" "1"
check "lint exactly at the cap: no truncation warn" \
  "$(COMMONS_LINT_MAX_BYTES=$LOWCAP python3 "$REPO/lib/publish_lint.py" "$W/exact.jsonl" | grep -c 'scan incomplete')" "0"
check "lint over the cap, binary path: truncation warned too" \
  "$(COMMONS_LINT_MAX_BYTES=$LOWCAP python3 "$REPO/lib/publish_lint.py" "$W/bigbin.bin" | grep -c 'scan incomplete')" "1"
BIGID_RC=$(COMMONS_LINT_MAX_BYTES=$LOWCAP rc c publish dataset "$W/big.jsonl" "over-cap dataset" --license CC0-1.0 --obtainability open)
check "publish over the cap: exit code unchanged (advisory only)" "$BIGID_RC" "0"
check "publish over the cap: stderr says the tail is unchecked" \
  "$(grep -c 'secret lint only partly scanned big.jsonl' "$W/err.txt")" "1"
check "streamed scan: key straddling a read-chunk boundary is caught (text)" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/straddle.txt")" "1"
check "streamed scan: key straddling a read-chunk boundary is caught (binary)" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/straddle.bin")" "1"
check "streamed scan: multibyte chars at a chunk boundary decode intact; key found on line 2" \
  "$(python3 "$REPO/lib/publish_lint.py" "$W/utf8.txt" | grep -c '^BLOCK utf8.txt:2  aws access key')" "1"
check "streamed scan: a 3 MiB single line is scanned in windows and the key is still caught" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/longline.json")" "1"
check "streamed scan: windowed long line is reported, never silent" \
  "$(grep -c 'very long line' "$W/out.txt")" "1"

# Archive members are invisible to this lint: the scan reads raw bytes only, so a
# secret inside a compressed member of a zip/tar/gzip is never examined (issue #20).
# Before this fix, `scan_file` printed nothing to say so. The cheap fix recognises
# the container by its leading magic bytes and reports it the same way the over-cap
# case is reported: a WARN plus the shared PARTIAL verdict, never a silent 'clean'.
python3 - "$W" <<'PY'
import gzip, os, sys, tarfile, zipfile
w = sys.argv[1]
with gzip.open(os.path.join(w, "arc.tar.gz"), "wb") as f:
    f.write(b"AKIA" + b"Q" * 16)  # a credential INSIDE the compressed bytes
with zipfile.ZipFile(os.path.join(w, "arc.zip"), "w") as z:
    z.writestr("a.txt", "AKIA" + "Q" * 16)
with tarfile.open(os.path.join(w, "arc.tar"), "w") as t:
    data = b"hello"
    import io
    ti = tarfile.TarInfo(name="a.txt"); ti.size = len(data)
    t.addfile(ti, io.BytesIO(data))
PY
check "archive detection: a .tar.gz is flagged, not silently clean" \
  "$(python3 "$REPO/lib/publish_lint.py" "$W/arc.tar.gz" | grep -c 'archive members not scanned')" "1"
check "archive detection: gzip verdict is PARTIAL" \
  "$(python3 "$REPO/lib/publish_lint.py" "$W/arc.tar.gz" | grep -c '^secret-lint: clean (PARTIAL: 1 file(s) only partly scanned)$')" "1"
check "archive detection: a credential inside the compressed bytes does not falsely BLOCK" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/arc.tar.gz")" "0"
check "archive detection: zip magic is recognised" \
  "$(python3 "$REPO/lib/publish_lint.py" "$W/arc.zip" | grep -c 'zip archive detected')" "1"
check "archive detection: uncompressed ustar tar magic is recognised" \
  "$(python3 "$REPO/lib/publish_lint.py" "$W/arc.tar" | grep -c 'tar archive detected')" "1"
printf 'hello\n' > "$W/plain_not_archive.txt"
check "archive detection: an ordinary text file is unaffected" \
  "$(python3 "$REPO/lib/publish_lint.py" "$W/plain_not_archive.txt" | grep -c 'archive members not scanned')" "0"
ARCID_RC=$(rc c publish dataset "$W/arc.tar.gz" "archive dataset" --license CC0-1.0 --obtainability open --allow-secrets)
check "publish an archive: exit code unchanged (advisory only)" "$ARCID_RC" "0"
check "publish an archive: stderr says members were not scanned" \
  "$(grep -c 'archive members not scanned' "$W/err.txt")" "1"
check "publish an archive: no over-cap 'split it' advice (wrong remedy for an archive)" \
  "$(grep -c 'secret lint only partly scanned' "$W/err.txt")" "0"

# Context exemption for hash-shaped fields (issue #9): a bare 32-byte hex value is
# indistinguishable between a private key and a tx/block hash by shape alone, so
# on-chain datasets (every row has a txHash) tripped the eth-key block pattern
# hundreds of thousands of times, forcing --allow-secrets — the blanket bypass
# this lint exists to avoid. Fix is CONTEXT: a bare-64-hex value under a JSON key
# or CSV header from a conservative built-in allowlist is exempted; the same value
# under a key-danger name (privateKey, private_key, secret, ...) still blocks, and
# an unrecognised/ambiguous field name still blocks (err toward blocking). Uses
# fresh SYNTHETIC hex per assertion, never real chain data.
HEXV="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
HEXV2="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
printf '{"block": 1, "txHash": "0x%s", "blockHash": "0x%s", "topics": ["0x%s", "0x%s"]}\n' \
  "$HEXV" "$HEXV2" "$HEXV" "$HEXV2" > "$W/tx.json"
check "NDJSON txHash/blockHash/topics values do not block" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/tx.json")" "0"
check "suppression is never silent: summary warn is emitted" \
  "$(grep -c 'hash-named fields not treated as keys' "$W/out.txt")" "1"
printf '{"privateKey": "0x%s"}\n' "$HEXV" > "$W/pk1.json"
check "same value under privateKey (camelCase) still blocks" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/pk1.json")" "1"
printf '{"private_key": "0x%s"}\n' "$HEXV" > "$W/pk2.json"
check "same value under private_key (snake_case) still blocks" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/pk2.json")" "1"
printf '{"secret": "0x%s"}\n' "$HEXV" > "$W/pk3.json"
check "same value under a generic secret field still blocks" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/pk3.json")" "1"
printf 'seed value observed: 0x%s in the wild\n' "$HEXV" > "$W/prose.txt"
check "bare value in prose still blocks (text path unchanged)" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/prose.txt")" "1"
printf 'PRIVATE_KEY=0x%s\n' "$HEXV" > "$W/env.env"
check "PRIVATE_KEY=0x... in a .env file still blocks" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/env.env")" "1"
printf 'tx_hash,amount\n0x%s,100\n' "$HEXV" > "$W/hash.csv"
check "CSV with a tx_hash header does not block" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/hash.csv")" "0"
printf 'key,amount\n0x%s,100\n' "$HEXV" > "$W/keycol.csv"
check "CSV with a bare 'key' header still blocks" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/keycol.csv")" "1"
printf '{"txHash": "0x%s", "privateKey": "0x%s"}\n' "$HEXV" "$HEXV2" > "$W/mixed.json"
check "mixed line (txHash exempt + privateKey not) still blocks overall" \
  "$(rc python3 "$REPO/lib/publish_lint.py" "$W/mixed.json")" "1"
printf '{"txHash": "0x%s"}\n{"txHash": "0x%s"}\n{"txHash": "0x%s"}\n' \
  "$HEXV" "$HEXV2" "$(python3 -c 'import secrets; print(secrets.token_hex(32))')" \
  > "$W/onchain3.ndjson"
check "publish of a 3-row on-chain-shaped NDJSON succeeds without --allow-secrets" \
  "$(rc c publish dataset "$W/onchain3.ndjson" "onchain sample" --license CC0-1.0 --obtainability open --force)" "0"

head_ "T3 attester identity (attested-by-whom)"
AT=$(c publish dataset "$W/clean.csv" "attested capture" --license MIT \
      --tier T3 --criteria "GET /demo at a fixed instant" --force 2>/dev/null)
check "unattested T3 reports NONE" "$(c verify "$AT" 2>&1 | grep -c 'attester : NONE')" "1"
# `status` display labels (issue #23): the evidence-chain view used to say the bare
# tier name ("T3 attested") for every T3 node, even with no attester on file, which
# overstates a self-reported artifact and disagrees with `verify`'s own "attester :
# NONE" right above. Display only: no tier, grade, or exit code should move.
check "status on an unattested T3: no bare 'attested' claim in the header" \
  "$(c status "$AT" 2>&1 | grep -c '\[T3 attested\]')" "0"
check "status on an unattested T3: header says self-reported, no attester" \
  "$(c status "$AT" 2>&1 | grep -c '\[T3 self-reported (no attester)\]')" "1"
check "status on an unattested T3: chain-grade line matches the header, not a bare 'attested'" \
  "$(c status "$AT" 2>&1 | grep -c '^chain grade: T3 self-reported (no attester)$')" "1"
check "status on an unattested T3: exit code unchanged (T2/T3 == not-machine-verifiable)" \
  "$(rc c status "$AT")" "3"
check "attest succeeds" "$(rc c attest "$AT" --observed 2026-07-01T00:00:00Z)" "0"
check "attester recorded" \
  "$(c get "$AT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["verification"]["attested_by"]["addr"])')" "$ME"
check "attestation verifies" "$(c verify "$AT" 2>&1 | grep -c 'attester : VALID')" "1"
check "status on an attested T3: header names the attester address" \
  "$(c status "$AT" 2>&1 | grep -c "\[T3 attested by $ME\]")" "1"
check "status on an attested T3: chain-grade line names the attester too" \
  "$(c status "$AT" 2>&1 | grep -c "^chain grade: T3 attested by $ME\$")" "1"
check "verify still exits 3 (judgement is not machine work)" "$(rc c verify "$AT")" "3"
check "re-attest refused without --force" "$(rc c attest "$AT")" "1"
check "attest logged" "$(c log -n 3 | grep -c '\"attest\"')" "1"
check "attest refuses non-T3" "$(rc c attest "$DS")" "1"
# tamper with the attested statement: the one machine-checkable part of T3 must FAIL
python3 - "$COMMONS_ROOT/registry/artifacts/$AT.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m["verification"]["attested_by"]["statement"]["criteria"] = "a different claim entirely"
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
check "tampered attestation FAILs (exit 1, not 3)" "$(rc c verify "$AT")" "1"
check "reported as a failed attestation" \
  "$([ "$(grep -cE 'attester : (INVALID|STALE)' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
# point the attestation at content it does not cover
python3 - "$COMMONS_ROOT/registry/artifacts/$AT.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m["verification"]["attested_by"]["statement"]["sha256"] = "00" * 32
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
check "attestation over other content is STALE" "$(rc c verify "$AT")" "1"
check "reported as stale" "$(grep -c 'attester : STALE' "$W/out.txt")" "1"
# Changing the criteria on the manifest also orphans the signature: the attester
# vouched for a specific claim, so a different claim is not covered by it.
# A genuinely signed legacy fixture keeps coverage of attestation staleness
# independently of the publisher-view failure exercised by test-view-writers.
printf 'legacy capture for attestation criteria drift\n' >"$W/legacy-attestation.txt"
AT2=$(python3 "$HERE/legacy-writer-fixture.py" "$COMMONS" publish dataset \
       "$W/legacy-attestation.txt" "criteria drift" --license MIT --tier T3 \
       --criteria "original detailed capture note" --force 2>/dev/null)
c attest "$AT2" >/dev/null 2>&1
check "attested cleanly" "$(c verify "$AT2" 2>&1 | grep -c 'attester : VALID')" "1"
python3 - "$COMMONS_ROOT/registry/artifacts/$AT2.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p))
m["verification"]["criteria"] = "a different claim entirely"
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
check "criteria drift is STALE" "$(rc c verify "$AT2")" "1"
check "stale message names the signed text" \
  "$(grep -c 'covers different criteria' "$W/out.txt")" "1"

head_ "attested observation is a validated instant, not a free string"
# Until 2026-08-25 `--observed` was stored unparsed and then compared to the key's
# validity window with Python string `<`/`>=`. Lexicographic order is not an order
# over RFC 3339: a REVOKED key attested successfully just by writing the same instant
# with a timezone offset (VALID exit 3) instead of Zulu (INVALID exit 1). Since the
# field is signed permanently AND decides key validity, it is canonicalised at
# `attest` time -- the statement holds the instant, not its rendering.
obs_of() { c get "$1" | python3 -c \
  'import json,sys;print(json.load(sys.stdin)["verification"]["attested_by"]["statement"]["observed"])'; }
mk_t3() {  # unique content per arm: ids are content-addressed, so reuse collides
  printf 'arm,%s\n' "$1" > "$W/obs$1.csv"
  c publish dataset "$W/obs$1.csv" "observed arm $1" --license MIT \
    --tier T3 --criteria "GET /obs$1" 2>/dev/null
}
# A throwaway identity revoked at a known instant. Never narrow $ME's window here:
# this host's own key signs every later publish in the suite.
OBSKEY="$W/obs.key"
python3 -c "import secrets;open('$OBSKEY','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$OBSKEY"
OBSADDR=$(COMMONS_SIGNING_KEY="$OBSKEY" c peer whoami | head -1)
c peer add "$OBSADDR" --agent-id obs-lab --trust datasets-only >/dev/null
c peer revoke "$OBSADDR" --at "2026-08-10T00:00:00Z" >/dev/null

# arm 1 -- canonical Zulu is stored verbatim
O1=$(mk_t3 1)
COMMONS_SIGNING_KEY="$OBSKEY" c attest "$O1" --observed "2026-08-10T07:00:00Z" >/dev/null 2>&1
check "canonical Zulu stored verbatim" "$(obs_of "$O1")" "2026-08-10T07:00:00Z"
# arm 2 -- the offset form is the SAME INSTANT and must be stored normalised
O2=$(mk_t3 2)
COMMONS_SIGNING_KEY="$OBSKEY" c attest "$O2" --observed "2026-08-09T23:00:00-08:00" >/dev/null 2>&1
check "offset normalised to UTC before signing" "$(obs_of "$O2")" "2026-08-10T07:00:00Z"
# arm 3 -- THE REGRESSION: both renderings must be judged identically
check "revoked key: Zulu form INVALID (exit 1)" "$(rc c verify "$O1")" "1"
check "revoked key: offset form INVALID (exit 1)" "$(rc c verify "$O2")" "1"
check "offset form cannot buy exit 3" \
  "$([ "$(rc c verify "$O1")" = "$(rc c verify "$O2")" ] && echo same)" "same"
# arm 4 -- prose is refused, and the message names the expected form
O4=$(mk_t3 4)
check "prose observation refused" \
  "$(rc env COMMONS_SIGNING_KEY="$OBSKEY" "$COMMONS" attest "$O4" --observed 'last Tuesday-ish')" "1"
check "refusal names RFC 3339" "$(grep -c 'RFC 3339' "$W/err.txt")" "1"
check "refused attestation was never written" \
  "$(c get "$O4" | grep -c attested_by)" "0"
# a bare local datetime has no instant, so it cannot gate a validity window
check "zone-less timestamp refused" \
  "$(rc env COMMONS_SIGNING_KEY="$OBSKEY" "$COMMONS" attest "$O4" --observed '2026-08-10T07:00:00')" "1"
# arm 5 -- an observation cannot have been made tomorrow
check "future observation refused" \
  "$(rc env COMMONS_SIGNING_KEY="$OBSKEY" "$COMMONS" attest "$O4" --observed '2099-01-01T00:00:00Z')" "1"
check "refusal says future" "$(grep -c 'in the future' "$W/err.txt")" "1"
# arm 6 -- the default path is unchanged: now(), already canonical
O6=$(mk_t3 6)
COMMONS_SIGNING_KEY="$OBSKEY" c attest "$O6" >/dev/null 2>&1
check "default observation is canonical Zulu" \
  "$(obs_of "$O6" | grep -cE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$')" "1"
# arm 8 -- guard the guard: prove arm 3 isn't vacuously passing
check "guard: canonical ts vs revoked peer still INVALID" "$(rc c verify "$O6")" "1"
# ...and that a valid window still verifies, so the check isn't just always-INVALID
c peer revoke "$OBSADDR" --at "2099-01-01T00:00:00Z" >/dev/null
check "guard: same attestation VALID inside the window" \
  "$(c verify "$O2" 2>&1 | grep -c 'attester : VALID')" "1"
check "unrevoked T3 is back to not-machine-verifiable (exit 3)" "$(rc c verify "$O2")" "3"
# key_valid_at parses rather than string-compares, so a legacy hand-written peer
# record carrying an offset window is ordered as an instant too.
c peer add "$OBSADDR" --force --trust datasets-only \
  --valid-from "2026-08-10T00:00:00+00:00" >/dev/null
check "offset valid_from ordered as an instant" "$(rc c verify "$O2")" "3"
# A metadata-only republish must PRESERVE the attested criteria rather than silently
# resetting it to a tier default, which would orphan the signature. Re-attest first so
# this tests the republish path, not the drift above.
c attest "$AT2" --force >/dev/null 2>&1
check "re-attested to current text" "$(c verify "$AT2" 2>&1 | grep -c 'attester : VALID')" "1"
c publish dataset "$W/legacy-attestation.txt" "criteria drift, retitled" --license MIT --force >/dev/null 2>&1
check "republish preserves attested criteria" "$(rc c verify "$AT2")" "3"
check "still VALID after republish" "$(grep -c 'attester : VALID' "$W/out.txt")" "1"

head_ "signature covers only the declared field set"
# `sig` covers SIGNED_FIELDS only, so a v1-only entry tolerates an added field (readers
# ignore unknown fields). `sig2` covers the whole entry: a field added to a dual-signed
# entry is a change to a signed event, so it no longer verifies (#45, #49).
cp "$(mylog)" "$W/annot.bak"
python3 - "$(mylog)" <<'PY'
import json, sys
p = sys.argv[1]
lines = [json.loads(l) for l in open(p) if l.strip()]
lines[-1].pop("sig2", None)
lines[-1]["received_at"] = "2026-07-25T00:00:00Z"
open(p, "w").write("".join(json.dumps(e, sort_keys=True) + "\n" for e in lines))
PY
rc c log --verify >/dev/null 2>&1
check "annotation on a v1-only entry does not invalidate" "$(grep -c 'BAD SIGNATURE' "$W/out.txt")" "0"
cp -f "$W/annot.bak" "$(mylog)"
python3 - "$(mylog)" <<'PY'
import json, sys
p = sys.argv[1]
lines = [json.loads(l) for l in open(p) if l.strip()]
assert lines[-1].get("sig2"), "new entries are dual-signed"
lines[-1]["received_at"] = "2026-07-25T00:00:00Z"
open(p, "w").write("".join(json.dumps(e, sort_keys=True) + "\n" for e in lines))
PY
rc c log --verify >/dev/null 2>&1
check "annotation on a dual-signed entry invalidates it" "$(grep -c 'BAD SIGNATURE' "$W/out.txt")" "1"
cp -f "$W/annot.bak" "$(mylog)"
check "restored ledger verifies" "$(rc c log --verify)" "0"

head_ "retroactive ledger correction is caught (adversarial matrix T-1)"
# The "tampering" section above only ever mutates the LAST line of the log, so a live
# forward append never has to build on a corrupted past. A "scoring correction" is the
# opposite shape: an EARLIER already-banked line is rewritten in place, generations
# after it was written, with everything downstream of it left alone. That is exactly
# the retroactive-rewrite mode (adversarial matrix case T-1), and it is untested by the
# tampering section above because that section never leaves a line downstream of the
# mutation.
cp "$(mylog)" "$W/t1.bak"
# Bank three honest lines so there is a real "earlier" line with descendants.
for i in 1 2 3; do
  printf 'a,b\n%d,%d\n' "$i" "$i" > "$W/t1-$i.csv"
  c publish dataset "$W/t1-$i.csv" "t1 probe $i" --license CC0-1.0 --force >/dev/null 2>&1
done
T1_SUM_BEFORE=$(sha256sum "$(mylog)" | cut -d' ' -f1)
check "control: intact multi-line chain verifies before any tamper" "$(rc c log --verify)" "0"
# Rewrite the MIDDLE banked line's signed `agent` field — the "scoring correction"
# shape: content changes, nothing about the chain's length or ordering does.
python3 - "$(mylog)" <<'PY'
import json, sys
p = sys.argv[1]
lines = [json.loads(l) for l in open(p) if l.strip()]
# Target the line two-from-the-end: guaranteed to have at least one live descendant
# whose "prev" commits to the pre-tamper bytes, so the chain-break signal is real.
idx = len(lines) - 2
lines[idx]["agent"] = "rescored-agent"
open(p, "w").write("".join(json.dumps(e, sort_keys=True) + "\n" for e in lines))
PY
T1_SUM_AFTER=$(sha256sum "$(mylog)" | cut -d' ' -f1)
check "guard-the-guard: the tamper actually flipped the ledger bytes" \
  "$([ "$T1_SUM_BEFORE" != "$T1_SUM_AFTER" ] && echo yes)" "yes"
check "retroactive rewrite of an earlier banked line is caught" "$(rc c log --verify)" "1"
check "caught as a chain break, naming the break" \
  "$([ "$(grep -c 'CHAIN BREAK' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
# fsck --ledger is the other command that walks the chain (it shells out to the same
# cmd_log under the hood) — the same "a human meets this a second way" property the
# anchor-drift warning has via `status`, but for a hard verify failure rather than an
# advisory.
check "fsck --ledger also flags the retroactive rewrite" "$(rc c fsck --ledger)" "1"
cp -f "$W/t1.bak" "$(mylog)"
# Forward control: a brand-new LIVE append on the same (now-restored) ledger, which
# only ever has to build on a clean head, must still pass — proving the failure above
# was specific to rewriting the past, not a general chain-verification regression.
printf 'a,b\nfwd,fwd\n' > "$W/t1-fwd.csv"
c publish dataset "$W/t1-fwd.csv" "t1 forward control" --license CC0-1.0 --force >/dev/null 2>&1
check "a live forward append on the restored chain still verifies" "$(rc c log --verify)" "0"

head_ "anchor staleness warning"
# Anchoring became epistemically load-bearing (first-publisher priority is adjudicated
# by anchored upper bound), but nothing enforced the cadence and nothing told you it
# had lapsed. The warning is ADVISORY: stderr only, never changes an exit code, so it
# cannot break a caller parsing stdout. A warning that broke scripts would get silenced,
# and a silenced warning protects nobody.
DRIFT="$COMMONS_ROOT/driftlab"
mkdir -p "$DRIFT/registry/ledger" "$DRIFT/registry/anchors" "$DRIFT/store/sha256"
DRIFTLOG="$DRIFT/registry/ledger/0xdeadbeef00000000000000000000000000000001.jsonl"
# One unsigned line aged N hours in a throwaway root. Unsigned is fine: the check keys
# on anchor coverage and age, not on signature validity.
seed_drift() {
  python3 - "$DRIFTLOG" "$1" <<'PY'
import json, sys, time
path, hours = sys.argv[1], float(sys.argv[2])
ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - hours * 3600))
e = {"schema": "commons/v1", "action": "publish", "agent": "t", "id": "sy-drift01",
     "sha256": "a" * 64, "ts": ts,
     "addr": "0xDEADbeef00000000000000000000000000000001", "sig": None, "prev": None}
open(path, "w").write(json.dumps(e, sort_keys=True) + "\n")
PY
}
drift_warned() {
  COMMONS_ROOT="$DRIFT" "$COMMONS" log --verify >"$W/d.out" 2>"$W/d.err"
  if grep -q 'past last anchor' "$W/d.err"; then echo yes; else echo no; fi
}

seed_drift 2
check "fresh chain does not warn" "$(drift_warned)" "no"
seed_drift 23
check "just under 24h does not warn" "$(drift_warned)" "no"
seed_drift 26
check "past 24h warns" "$(drift_warned)" "yes"
check "warning reports the drift in hours" "$(grep -c 'drifted 26h' "$W/d.err")" "1"
check "warning states the stake" "$(grep -c 'derivation priority unprotected' "$W/d.err")" "1"
check "warning names the remedy" "$(grep -c 'commons anchor' "$W/d.err")" "1"
# The whole point of stderr: stdout stays machine-parseable.
check "warning stays off stdout" "$(grep -c 'past last anchor' "$W/d.out")" "0"
check "warning does not change the exit code" \
  "$(COMMONS_ROOT="$DRIFT" "$COMMONS" log --verify >/dev/null 2>&1; echo $?)" "0"
# Measured from the OLDEST unanchored line: exposure is how long the earliest
# unprotected claim has sat there, not how recently you happened to append.
python3 - "$DRIFTLOG" <<'PY'
import json, sys, time
def line(hours, aid):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - hours * 3600))
    return json.dumps({"schema": "commons/v1", "action": "publish", "agent": "t",
                       "id": aid, "sha256": "a" * 64, "ts": ts,
                       "addr": "0xDEADbeef00000000000000000000000000000001",
                       "sig": None, "prev": None}, sort_keys=True)
open(sys.argv[1], "w").write(line(100, "sy-old01") + "\n" + line(1, "sy-new01") + "\n")
PY
check "drift measured from the oldest unanchored line" \
  "$(drift_warned)" "yes"
check "oldest-line age is the number reported" "$(grep -c 'drifted 100h' "$W/d.err")" "1"
# status is the other place a human meets this, per Open Question 1. Needs a REAL
# published artifact: status resolves the manifest first and exits before the warning
# if the id is unknown.
printf 'x,y\n1,2\n' > "$W/drift.csv"
DID=$(COMMONS_ROOT="$DRIFT" COMMONS_SIGNING_KEY= "$COMMONS" publish dataset \
        "$W/drift.csv" "drift probe" --license CC0-1.0 --force 2>/dev/null)
# Backdate every line in the lab so the publish we just made is also unanchored+old.
python3 - "$DRIFT/registry/ledger" <<'PY'
import json, os, sys, time
old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 200 * 3600))
d = sys.argv[1]
for fn in os.listdir(d):
    if not fn.endswith(".jsonl") or fn.startswith("0xfeedface"): continue
    p = os.path.join(d, fn)
    out = []
    for line in open(p):
        if not line.strip(): continue
        e = json.loads(line); e["ts"] = old
        out.append(json.dumps(e, sort_keys=True))
    open(p, "w").write("\n".join(out) + "\n")
PY
COMMONS_ROOT="$DRIFT" "$COMMONS" status "$DID" >"$W/s.out" 2>"$W/s.err"
check "status warns too" "$(grep -c 'past last anchor' "$W/s.err")" "1"
check "status warning stays off stdout" "$(grep -c 'past last anchor' "$W/s.out")" "0"
# A registered peer's stale log is THEIR problem. Warning on it would fire constantly
# on a healthy node and train the operator to ignore the warning entirely.
python3 - "$DRIFT/registry/ledger/0xfeedface00000000000000000000000000000002.jsonl" <<'PY'
import json, sys, time
ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 400 * 3600))
e = {"schema": "commons/v1", "action": "publish", "agent": "remote", "id": "sy-peer01",
     "sha256": "b" * 64, "ts": ts,
     "addr": "0xFEEDface00000000000000000000000000000002", "sig": None, "prev": None}
open(sys.argv[1], "w").write(json.dumps(e, sort_keys=True) + "\n")
PY
cat > "$DRIFT/registry/peers.json" <<'JSON'
{"peers": [{"addr": "0xfeedface00000000000000000000000000000002",
            "agent": "remote", "trust": "full"}]}
JSON
# Drop the logs the status probe above created/backdated, so the only ancient log left
# is the registered peer's. Otherwise this would re-detect our own stale lines and
# assert nothing about peer exclusion.
find "$DRIFT/registry/ledger" -name '*.jsonl' ! -name '0xfeedface*' -delete
seed_drift 2
check "a registered peer's stale log does not warn" "$(drift_warned)" "no"

head_ "advisory invariant: drift cannot move an exit code"
# The checks above pin the warning's BEHAVIOUR (threshold, text, stream, oldest-line).
# They assert the never-changes-an-exit-code property only for one command in one state:
# `log --verify` on a healthy chain, where the expected code is 0 and a regression that
# forced 0 would be invisible. That is the weakest possible form of the assertion, and
# `warn_anchor_drift` is the precedent every later advisory cites by name (availability
# in `list`/`search`/`status`/`queue`/`collection show`, the `fsck --availability`
# preview). If the pattern's founding case is only indirectly pinned, every citation of
# it inherits that weakness.
#
# Pin it DIRECTLY and differentially instead: run the same commands twice over a lab
# whose ledger BYTES ARE IDENTICAL between arms, with anchor coverage as the only
# variable, and require identical exit codes while the warning text differs. Byte
# identity is what makes this an anchor-drift test rather than a ledger-content test —
# any other construction (re-seeding with different timestamps) changes the input to the
# code under test, so an exit-code difference would be uninterpretable.
#
# Coverage spans the three distinct exit values status can produce (0/3/4) plus a
# genuinely FAILING command (1), because "advisory" has two halves: it must not turn a
# pass into a failure, and it must not mask a failure into a pass.
ADV="$COMMONS_ROOT/advisorylab"
mkdir -p "$ADV/registry/ledger" "$ADV/registry/anchors" "$ADV/store/sha256"
ADVLOG="$ADV/registry/ledger/local-unsigned.jsonl"

# Unsigned publishes: this lab is about anchor coverage, and an unsigned local line is
# explicitly tolerated by `log --verify` (exit 0). Three tiers, so status has a reason to
# return each of its codes.
printf 'a,b\n1,2\n' > "$W/adv-t0.csv"
printf 'capture note\n'  > "$W/adv-t3.txt"
printf 'x\n9\n'          > "$W/adv-uv.csv"
adv() { COMMONS_ROOT="$ADV" COMMONS_SIGNING_KEY= "$COMMONS" "$@"; }
A_T0=$(adv publish dataset "$W/adv-t0.csv" "advisory t0" --license CC0-1.0 \
         --obtainability open --tier T0 2>/dev/null)
A_T3=$(adv publish dataset "$W/adv-t3.txt" "advisory t3" --license CC0-1.0 \
         --obtainability open 2>/dev/null)
A_UV=$(adv publish dataset "$W/adv-uv.csv" "advisory unverified" --license CC0-1.0 \
         --obtainability open --tier unverified 2>/dev/null)
check "advisory lab published three tiers" \
  "$(printf '%s\n%s\n%s\n' "$A_T0" "$A_T3" "$A_UV" | grep -c '^ds-')" "3"

# Age every line well past the threshold and re-chain, so the ONLY thing standing
# between this lab and a warning is whether an anchor covers the head.
python3 - "$ADVLOG" <<'PY'
import hashlib, json, sys, time
p = sys.argv[1]
old = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - 200 * 3600))
entries = [json.loads(l) for l in open(p) if l.strip()]
prev, out = None, []
for e in entries:
    e["ts"] = old
    e["prev"] = prev            # backdating rewrites bytes, so the chain must be rebuilt
    s = json.dumps(e, sort_keys=True)
    out.append(s)
    prev = hashlib.sha256(s.encode()).hexdigest()
open(p, "w").write("\n".join(out) + "\n")
PY

# Toggle: write an anchor committing to the CURRENT head (drift suppressed), or remove
# it (drift exposed). Never touches the ledger — that is the whole point.
anchor_on()  {
  python3 - "$ADVLOG" "$ADV/registry/anchors/anchor-20260801T000000Z.json" <<'PY'
import hashlib, json, sys
log, out = sys.argv[1], sys.argv[2]
last = [l.rstrip("\n") for l in open(log) if l.strip()][-1]
# This unsigned checkpoint covers only the unsigned log. Its root must actually
# commit to the head; a fabricated root must never suppress the drift warning.
heads = {"local-unsigned.jsonl": hashlib.sha256(last.encode()).hexdigest()}
root = hashlib.sha256(("local-unsigned.jsonl:" + heads["local-unsigned.jsonl"]).encode()).hexdigest()
json.dump({"schema": "commons/v1", "created": "2026-08-01T00:00:00Z",
           "root": root, "leaves": [root], "anchored": "none", "heads": heads},
          open(out, "w"), indent=2, sort_keys=True)
PY
}
anchor_off() { rm -f "$ADV"/registry/anchors/*.json; }

# Run a command in both arms. Emits "<exit_drift>|<exit_anchored>|<warn_drift><warn_anchored>"
# so one check pins the exit codes and their equality, and a second pins that the arms
# genuinely differed (guarding against a lab where the warning never fired at all and
# equality was therefore vacuous).
adv_ab() {
  local ed ea wd wa
  anchor_off
  COMMONS_ROOT="$ADV" COMMONS_SIGNING_KEY= "$COMMONS" "$@" >"$W/a1.out" 2>"$W/a1.err"; ed=$?
  anchor_on
  COMMONS_ROOT="$ADV" COMMONS_SIGNING_KEY= "$COMMONS" "$@" >"$W/a2.out" 2>"$W/a2.err"; ea=$?
  wd=$(grep -c 'past last anchor' "$W/a1.err")
  wa=$(grep -c 'past last anchor' "$W/a2.err")
  echo "$ed|$ea|$wd$wa"
}

# Guard the guard: if the toggle silently stopped working, every equality check below
# would still pass while asserting nothing.
anchor_off; adv log --verify >/dev/null 2>"$W/a0.err"
check "toggle exposes drift when no anchor covers the head" \
  "$(grep -c 'past last anchor' "$W/a0.err")" "1"
anchor_on;  adv log --verify >/dev/null 2>"$W/a0.err"
check "toggle suppresses drift once an anchor covers the head" \
  "$(grep -c 'past last anchor' "$W/a0.err")" "0"
ADV_SUM=$(sha256sum "$ADVLOG" | cut -d' ' -f1)

# status, once per exit code it can return. Equality is the assertion; the specific
# value is pinned too, so a regression that collapsed every code to 0 fails here rather
# than passing as "equal".
check "status T0: drift changes nothing (0 both arms, warning differs)" \
  "$(adv_ab status "$A_T0")" "0|0|10"
check "status T3: drift changes nothing (3 both arms, warning differs)" \
  "$(adv_ab status "$A_T3")" "3|3|10"
check "status unverified: drift changes nothing (4 both arms, warning differs)" \
  "$(adv_ab status "$A_UV")" "4|4|10"
# --brief takes a different exit path (it returns before the long render), so the
# advisory sits in a separate branch and needs its own assertion.
check "status --brief: drift changes nothing (3 both arms, warning differs)" \
  "$(adv_ab status --brief "$A_T3")" "3|3|10"
check "log --verify on a healthy chain: drift changes nothing" \
  "$(adv_ab log --verify)" "0|0|10"

# The other half of "advisory": a warning must not MASK a failure. Break the hash chain
# so `log --verify` genuinely fails, and require exit 1 in both arms.
cp "$ADVLOG" "$W/adv-healthy.jsonl"
python3 - "$ADVLOG" <<'PY'
import json, sys
p = sys.argv[1]
entries = [json.loads(l) for l in open(p) if l.strip()]
entries[-1]["prev"] = "00" * 32
open(p, "w").write("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))
PY
check "a failing command still fails under drift (never masked)" \
  "$(adv_ab log --verify)" "1|1|10"
cp "$W/adv-healthy.jsonl" "$ADVLOG"

# Byte identity is the load-bearing claim of this whole section: if the arms differed in
# ledger content, an equal exit code would prove nothing about anchoring.
check "both arms ran over byte-identical ledgers" \
  "$(sha256sum "$ADVLOG" | cut -d' ' -f1)" "$ADV_SUM"

head_ "publish/sign ordering (2026-09-21 bug)"
# A bad key must fail BEFORE anything becomes visible, and the retry must not report
# "already published" over an artifact that has no attribution event.
printf 'orphan,probe\n1,%s\n' "$RANDOM$RANDOM" > "$W/ord.csv"
ORDID="ds-$(sha256sum "$W/ord.csv" | cut -c1-8)"
check "publish with unreadable key exits 1" \
  "$(COMMONS_SIGNING_KEY="$W/no-such.key" rc c publish dataset "$W/ord.csv" "ord" --license CC0-1.0)" "1"
check "failed publish leaves no manifest" \
  "$([ -e "$COMMONS_ROOT/registry/artifacts/$ORDID.json" ] && echo present || echo absent)" "absent"
check "failed publish is not visible to get" "$(rc c get "$ORDID")" "1"
check "failed publish is not in list" "$(c list 2>/dev/null | grep -c "$ORDID")" "0"
ORD2=$(c publish dataset "$W/ord.csv" "ord" --license CC0-1.0 2>/dev/null)
check "retry with good key publishes (not 'already published')" "$ORD2" "$ORDID"
check "retry wrote a signed publish event" \
  "$(tail -1 "$(mylog)" | python3 -c 'import json,sys;e=json.load(sys.stdin);print(e["action"],e["id"],e["sig"][:2])')" \
  "publish $ORDID 0x"
# Earlier sections restore ledger backups, so the shared fixture legitimately holds
# unattributed residue; assert on THIS section's artifacts, not the global count.
rc c fsck --attribution >/dev/null
check "fsck --attribution does not flag a good publish" "$(grep -c "UNATTRIBUTED: $ORDID" "$W/out.txt")" "0"

# Legacy residue: a manifest with no ledger event (what the old ordering left behind).
printf 'legacy,residue\n1,%s\n' "$RANDOM$RANDOM" > "$W/leg.csv"
LEG=$(c publish dataset "$W/leg.csv" "legacy" --license CC0-1.0 2>/dev/null)
python3 - "$(mylog)" "$LEG" <<'PY'
import json, sys
path, aid = sys.argv[1], sys.argv[2]
lines = open(path).read().splitlines()
keep = [l for l in lines if json.loads(l).get("id") != aid]
open(path, "w").write("\n".join(keep) + ("\n" if keep else ""))
PY
check "fsck --attribution flags the unattributed artifact" "$(rc c fsck --attribution)" "1"
check "fsck --attribution names it" "$(grep -c "UNATTRIBUTED: $LEG" "$W/out.txt")" "1"
check "plain fsck unchanged (attribution is opt-in)" "$(rc c fsck)" "0"
COUNT_BEFORE=$(wc -l < "$(mylog)" | tr -d ' ')
check "dedup refuses orphan ownership backfill" \
  "$(rc c publish dataset "$W/leg.csv" "legacy" --license CC0-1.0)" "1"
check "refusal identifies orphan authority" "$(grep -c 'orphan' "$W/err.txt")" "1"
check "refused backfill appends no event" \
  "$(wc -l < "$(mylog)" | tr -d ' ')" "$COUNT_BEFORE"
rc c fsck --attribution >/dev/null
check "fsck still reports the unresolved orphan" "$(grep -c "UNATTRIBUTED: $LEG" "$W/out.txt")" "1"
check "second retry still refuses ownership adoption" \
  "$(rc c publish dataset "$W/leg.csv" "legacy" --license CC0-1.0)" "1"

head_ "fsck --attribution: unsigned-only attribution is visible (advisory)"
# An artifact whose only publish event is unsigned HAS a ledger event, so it is not
# UNATTRIBUTED, but no verified signed publisher exists. That class once let the
# commit-reveal ordering check fail open; fsck must at least make it visible.
printf 'unsigned,only\n1,%s\n' "$RANDOM$RANDOM" > "$W/uns.csv"
UNS=$(env -u COMMONS_SIGNING_KEY COMMONS_AGENT=legacy "$COMMONS" publish dataset "$W/uns.csv" "unsigned only" --license CC0-1.0 2>/dev/null)
rc c fsck --attribution >/dev/null
check "unsigned-only artifact is reported" "$(grep -c "UNSIGNED-ONLY: $UNS" "$W/out.txt")" "1"
check "unsigned-only artifact is not UNATTRIBUTED" "$(grep -c "UNATTRIBUTED: $UNS" "$W/out.txt")" "0"
check "summary line counts unsigned-only" "$(grep -c '^unsigned-only (advisory): [1-9]' "$W/out.txt")" "1"
check "a signed publish is not reported" "$(grep -c "UNSIGNED-ONLY: $ORDID" "$W/out.txt")" "0"
c publish dataset "$W/uns.csv" "unsigned only" --license CC0-1.0 --force >/dev/null 2>&1
rc c fsck --attribution >/dev/null
check "a signed republish does not clear it (a republish claims no authorship, #46)" \
  "$(grep -c "UNSIGNED-ONLY: $UNS" "$W/out.txt")" "1"

head_ "housekeeping"
check "peer list is readable" "$(rc c peer list)" "0"
check "peer add rejects bad address" "$(rc c peer add 0xnope --agent-id x)" "1"
check "peer add rejects unknown trust" "$(rc c peer add 0x1111111111111111111111111111111111111111 --trust wat)" "2"
check "peer rm works" "$(rc c peer rm "$ROT")" "0"
check "peer rm of unknown fails" "$(rc c peer rm 0x2222222222222222222222222222222222222222)" "1"
check "duplicate add refused without --force" "$(rc c peer add "$ME" --agent-id dup)" "1"
check "fsck clean" "$(rc c fsck)" "0"
check "reindex clean" "$(rc c reindex)" "0"

printf '\n\033[1mtest-signing: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
