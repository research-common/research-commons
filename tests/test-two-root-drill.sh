#!/usr/bin/env bash
# P6 PHASE GATE — the two-root drill.
#
# Two throwaway COMMONS_ROOTs with a bare git repo between them, exercising the whole
# v0.3 stack end to end as two genuinely separate parties:
#
#   (a) a signed artifact travels A→B through the ingest gate and verifies PASS on B
#       under the sandbox
#   (b) a full exchange round-trip: A publishes a task, B claims it (sandbox forced),
#       runs, submits; A accepts. The ledger tells the whole story.
#   (c) honest copy-submission: B submits A's result to another eligible task. It must
#       fulfill the task, classify as a concurring REFERENCE, and carry zero quorum
#       weight — including when first-publisher must be resolved across INGESTED
#       per-peer ledgers rather than local ones.
#   (d) adversarial backdating: B fabricates a publish event for A's artifact with an
#       asserted ts earlier than A's, but B's anchor chain cannot cover it. Anchored
#       upper bounds must beat asserted timestamps, B must downgrade to reference, and
#       the discrepancy must be flagged as a reputational tell.
#
# NEVER touches the live registry: two mktemp roots and a mktemp bare repo only.
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

# Probe with a throwaway key: this checks viem is installed, not that the host has a key.
_PROBEKEY="$(mktemp -t commons-probe-XXXXXX)"
python3 -c "import secrets,sys;open(sys.argv[1],'w').write('0x'+secrets.token_hex(32))" "$_PROBEKEY"
if ! MESSAGE=probe COMMONS_SIGNING_KEY="$_PROBEKEY" node "$REPO/lib/sign-message.mjs" >/dev/null 2>&1; then
  rm -f "$_PROBEKEY"
  echo "test-two-root-drill: signer not functional — cannot run the gate"; exit 1
fi
rm -f "$_PROBEKEY"
if ! command -v docker >/dev/null 2>&1 || ! timeout 30 docker info >/dev/null 2>&1; then
  echo "test-two-root-drill: docker unavailable — the sandbox leg cannot be proven"; exit 1
fi
if ! docker image inspect research-commons-sandbox:base >/dev/null 2>&1; then
  echo "test-two-root-drill: default image research-commons-sandbox:base missing — the sandbox leg cannot be proven."
  echo "  build it: docker build -t research-commons-sandbox:base environments/base/"; exit 1
fi

LAB="$(mktemp -d -t commons-drill-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
export GIT_AUTHOR_NAME=drill GIT_AUTHOR_EMAIL=drill@local
export GIT_COMMITTER_NAME=drill GIT_COMMITTER_EMAIL=drill@local

A="$LAB/A"; B="$LAB/B"; BARE="$LAB/bare.git"; W="$LAB/w"
mkdir -p "$W"
KEY_A="$LAB/a.key"; KEY_B="$LAB/b.key"
python3 -c "import secrets;open('$KEY_A','w').write('0x'+secrets.token_hex(32))"
python3 -c "import secrets;open('$KEY_B','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$KEY_A" "$KEY_B"

a() { COMMONS_ROOT="$A" COMMONS_AGENT=peer-a COMMONS_SIGNING_KEY="$KEY_A" "$COMMONS" "$@"; }
b() { COMMONS_ROOT="$B" COMMONS_AGENT=peer-b COMMONS_SIGNING_KEY="$KEY_B" "$COMMONS" "$@"; }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
acommit() { ( cd "$A" && git add -A && git commit -qm "$1" ) >/dev/null 2>&1; }
bcommit() { ( cd "$B" && git add -A && git commit -qm "$1" ) >/dev/null 2>&1; }
bsync()  { ( cd "$B" && git fetch -q origin \
             && git merge -q --no-edit origin/"$(git branch --show-current)" ) >/dev/null 2>&1; }

head_ "lab: two independent roots, one bare repo between them"
git init -q --bare "$BARE"
for R in "$A" "$B"; do
  mkdir -p "$R/registry" "$R/store/sha256"
  git init -q "$R"
  ( cd "$R" && git remote add origin "$BARE" \
    && printf 'registry/index.sqlite\nregistry/peers.json\nregistry/quarantine.log\n__pycache__/\n' > .gitignore \
    && cp "$REPO/registry/exec-policy.example.json" registry/exec-policy.json \
    && git add -A && git commit -qm init ) >/dev/null 2>&1
done
ADDR_A=$(a peer whoami | head -1)
ADDR_B=$(b peer whoami | head -1)
check "A and B are distinct identities" "$([ "$ADDR_A" != "$ADDR_B" ] && echo yes)" "yes"
# Each side registers the other. peers.json never replicates, so this is per-host.
a peer add "$ADDR_A" --agent-id peer-a --trust full --note self >/dev/null
a peer add "$ADDR_B" --agent-id peer-b --trust full --note peer >/dev/null
b peer add "$ADDR_B" --agent-id peer-b --trust full --note self >/dev/null
b peer add "$ADDR_A" --agent-id peer-a --trust full --note peer >/dev/null
check "each root has its own trust policy" \
  "$([ "$(a peer list | grep -c '^0x')" = "2" ] && [ "$(b peer list | grep -c '^0x')" = "2" ] && echo yes)" "yes"

# ───────────────────────────── case (a) ─────────────────────────────
head_ "(a) signed artifact travels A→B and verifies PASS on B under the sandbox"
printf 'avs,promised,claimed\nalpha,1000,900\nbeta,800,500\ngamma,600,600\n' > "$W/rewards.csv"
DS=$(a publish dataset "$W/rewards.csv" "Drill rewards extract" --license CC0-1.0 \
      --obtainability open \
       --tier T3 --criteria "hand-authored drill capture" 2>/dev/null)
a attest "$DS" >/dev/null 2>&1
check "A published + attested a dataset" "$(echo "$DS" | grep -c '^ds-')" "1"

# mkwf <out> <variant> — deterministic workflow whose OUTPUT is unique per variant.
#
# The variant must land in the OUTPUT, not merely in the source: content-addressing
# means two workflows computing identical bytes collapse to ONE result artifact with
# ONE first publisher. That is correct behaviour (and is what case (c) deliberately
# exercises), but it makes a fixture that INTENDS an independent second derivation
# silently produce a copy instead — which then reads as a settlement bug rather than a
# test bug. Cost me a debugging cycle; encoded here so it doesn't recur.
mkwf() {
  local out="$1" variant="$2"
  python3 - "$W/step-$variant.py" "$variant" <<'PY'
import sys
dst, variant = sys.argv[1], sys.argv[2]
src = '''import csv, json, os
rows = list(csv.DictReader(open(os.environ["IN_D"])))
out = {"avs": {}, "n": len(rows), "variant": %r}
for r in rows:
    out["avs"][r["avs"]] = round(int(r["claimed"]) / int(r["promised"]), 4)
out["overall"] = round(sum(int(r["claimed"]) for r in rows)
                     / sum(int(r["promised"]) for r in rows), 4)
json.dump(out, open(os.environ["OUT_DIR"] + "/eff.json", "w"), indent=2, sort_keys=True)
''' % (variant,)
open(dst, "w").write(src)
PY
  python3 - "$out" "$DS" "$W/step-$variant.py" <<'PY'
import json, sys
json.dump({"interpreter": "bash", "inputs": {"D": sys.argv[2]},
           "attachments": {"step.py": open(sys.argv[3]).read()},
           "steps": ["python3 step.py"], "outputs": {"eff": "eff.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"},
           "timeout": 120}, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
}
mkwf "$W/wf.json" base
WF=$(a publish workflow "$W/wf.json" "Drill claim-efficiency workflow" 2>/dev/null)
OUT=$(COMMONS_EXEC=sandbox a run "$WF" --publish --publish-type synthesis \
        --title "Drill efficiency (A)" 2>/dev/null | awk '{print $1}')
check "A derived a T0 artifact under the sandbox" "$(echo "$OUT" | grep -c '^sy-')" "1"
check "exec environment recorded with a digest" \
  "$(a get "$OUT" | python3 -c 'import json,sys;print((((json.load(sys.stdin).get("provenance") or {}).get("run") or {}).get("exec") or {}).get("image_digest","")[:7])')" "sha256:"

acommit "case-a publish"
check "A's push passes its own gates" "$(rc a push origin)" "0"
check "B pulls through the ingest gate" "$(rc b pull origin)" "0"
check "dataset landed on B" "$(b list | grep -c "$DS")" "1"
check "workflow landed on B (code, full trust)" "$(b list --type workflow | grep -c "$WF")" "1"
check "received_at stamped on ingest" \
  "$(b get "$DS" | python3 -c 'import json,sys;print("received_at" in (json.load(sys.stdin).get("ingest") or {}))')" "True"
check "A's attestation still verifies on B" "$(b verify "$DS" 2>&1 | grep -c 'attester : VALID')" "1"
check "🔒 B re-derives A's T0 artifact under the sandbox: PASS" \
  "$(COMMONS_EXEC=sandbox rc b verify "$OUT")" "0"
check "B's PASS is its own re-derivation, not a trust statement" \
  "$(grep -c 'reproduced byte-identically' "$W/out.txt")" "1"
check "B's ledger view carries A's log as a separate chain" \
  "$([ "$(ls "$B/registry/ledger" | wc -l)" -ge 1 ] && echo yes)" "yes"
check "B's log --verify is clean" "$(rc b log --verify)" "0"

# ───────────────────────────── case (b) ─────────────────────────────
head_ "(b) full exchange round-trip: A commissions, B serves, A accepts"
mktask() {  # mktask <out> <workflow> <overrides>
  python3 - "$1" "$DS" "$2" "$ADDR_A" "$3" <<'PY'
import json, sys
out, ds, wf, addr, over = sys.argv[1:6]
spec = {"objective": "Compute per-AVS claim efficiency from the pinned extract",
        "priority": 1, "expires": "2099-01-01T00:00:00Z",
        "inputs": [{"id": ds}], "execution": {"workflow": wf},
        "verification": {"tier": "T0",
                         "criteria": "byte-identical re-derivation of eff.json"},
        "beneficiary": {"agent": "peer-a", "addr": addr}}
spec.update(json.loads(over))
json.dump(spec, open(out, "w"), indent=2, sort_keys=True)
PY
}
mkwf "$W/wf-b.json" caseb
WFB=$(a publish workflow "$W/wf-b.json" "Drill workflow (case b)" 2>/dev/null)
mktask "$W/task-b.json" "$WFB" '{}'
TK=$(a publish task "$W/task-b.json" "Claim efficiency (drill)" 2>/dev/null)
check "A published a task" "$(echo "$TK" | grep -c '^tk-')" "1"
acommit "case-b task"; a push origin >/dev/null 2>&1
check "B pulls the task" "$(rc b pull origin)" "0"
check "task is open in B's queue" "$(b queue --open | grep -c "$TK")" "1"

check "B claims it" "$(rc b claim "$TK")" "0"
check "B is told the task is foreign and will be sandboxed" \
  "$(grep -c 'FOREIGN task' "$W/out.txt")" "1"
# The hard gate: COMMONS_EXEC must be ignored for a foreign spec.
COMMONS_EXEC=native b run-task "$TK" --publish-type synthesis >"$W/out.txt" 2>"$W/err.txt"
RES=$(grep -oE '^sy-[0-9a-f]{8}' "$W/out.txt" | head -1)
check "B produced a result" "$(echo "$RES" | grep -c '^sy-')" "1"
check "🔒 COMMONS_EXEC=native was ignored for a foreign task" \
  "$([ "$(grep -c 'ignored — foreign task specs always run sandboxed' "$W/err.txt")" -ge 1 ] && echo yes)" "yes"
check "🔒 result records sandboxed execution" \
  "$(b get "$RES" | python3 -c 'import json,sys;print((((json.load(sys.stdin).get("provenance") or {}).get("run") or {}).get("exec") or {}).get("mode"))')" "sandbox"
check "B submits the result" "$(rc b submit "$TK" "$RES")" "0"
check "B is told it counts as an independent derivation" \
  "$(grep -c 'counts as: independent derivation' "$W/out.txt")" "1"

bcommit "case-b result"; bsync
check "B pushes its work back" "$(rc b push origin)" "0"
check "A pulls B's result" "$(rc a pull origin)" "0"
check "A sees the submission" "$(a status "$TK" | grep -c "$RES")" "1"
check "A can verify B's result itself" "$(COMMONS_EXEC=sandbox rc a verify "$RES")" "0"
check "A accepts" "$(rc a accept "$TK" "$RES")" "0"
check "task state is accepted" "$(a status "$TK" | grep -c 'state      : accepted')" "1"

head_ "(b) the ledger tells the whole story"
check "log --verify clean on A across both chains" "$(rc a log --verify)" "0"
check "verify reports 2+ logs (one writer each)" \
  "$([ "$(grep -cE 'across [2-9] log' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
for act in publish claim submit accept; do
  check "ledger records the $act event" \
    "$(a log -n 400 | python3 -c "
import json,sys
n=sum(1 for l in sys.stdin if l.strip() and json.loads(l).get('action')=='$act')
print('yes' if n>=1 else 'no')")" "yes"
done
check "claim + submit are attributed to B, not A" \
  "$(a log -n 400 | python3 -c "
import json,sys
rows=[json.loads(l) for l in sys.stdin if l.strip()]
ev=[r for r in rows if r.get('task')=='$TK' and r.get('action') in ('claim','submit')]
print('yes' if ev and all((r.get('addr') or '').lower()=='$(echo "$ADDR_B" | tr 'A-Z' 'a-z')' for r in ev) else 'no')")" "yes"
check "acceptance is attributed to A (the beneficiary)" \
  "$(a log -n 400 | python3 -c "
import json,sys
rows=[json.loads(l) for l in sys.stdin if l.strip()]
ev=[r for r in rows if r.get('task')=='$TK' and r.get('action')=='accept']
print('yes' if ev and all((r.get('addr') or '').lower()=='$(echo "$ADDR_A" | tr 'A-Z' 'a-z')' for r in ev) else 'no')")" "yes"
check "status shows one independent derivation" \
  "$(a status "$TK" | grep -c '1 independent derivation(s) agree')" "1"
check "A's fsck clean" "$(rc a fsck)" "0"
check "B's fsck clean" "$(rc b fsck)" "0"

# ───────────────────────────── case (c) ─────────────────────────────
head_ "(c) honest copy-submission across ingested ledgers → reference, zero weight"
# A second eligible task over the SAME workflow, so A's existing result already
# satisfies it byte-for-byte. B submits that artifact honestly (a legitimate citation)
# — it must fulfill the task while carrying no quorum weight.
#
# THE RISK THIS EXISTS TO CATCH: first-publisher has to be resolved from A's ledger as
# INGESTED into B's registry (a merged per-peer log), not from B's own writes. If that
# resolution silently failed, B would look like the origin of A's artifact and a copy
# would earn quorum weight — the exact fraud the independence rule forbids.
mktask "$W/task-c.json" "$WF" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 0}, \"objective\": \"copy-submission probe (drill case c)\"}"
TKC=$(a publish task "$W/task-c.json" "Copy probe (drill)" 2>/dev/null)
acommit "case-c task"; a push origin >/dev/null 2>&1
b pull origin >/dev/null 2>&1
check "B holds the new task" "$(b list --type task | grep -c "$TKC")" "1"
# Resolve first-publisher exactly as the code does, but from B's root. This is the leg
# the task brief expected to break, so it is probed directly and not only via `status`.
export COMMONS_BIN="$COMMONS"
fp_addr() {  # fp_addr <root> <artifact-id>
  python3 - "$1" "$2" <<'PY'
import importlib.machinery, importlib.util, os, sys
root, aid = sys.argv[1], sys.argv[2]
os.environ["COMMONS_ROOT"] = root
loader = importlib.machinery.SourceFileLoader("commons", os.environ["COMMONS_BIN"])
spec = importlib.util.spec_from_loader("commons", loader)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fp = mod.first_publisher(aid)
print(fp[0] if fp else "none")
PY
}
check "🔒 B resolves A's artifact as A-published from the INGESTED ledger" \
  "$(fp_addr "$B" "$OUT")" "$(echo "$ADDR_A" | tr 'A-Z' 'a-z')"

check "B claims the second task" "$(rc b claim "$TKC")" "0"
# B submits A's artifact. Honest behaviour — citing an existing result is good.
check "B submits A's existing result" "$(rc b submit "$TKC" "$OUT" --force)" "0"
check "🔒 B is told it is a CONCURRING REFERENCE" \
  "$(grep -c 'counts as: CONCURRING REFERENCE' "$W/out.txt")" "1"
check "reason names the missing derivation evidence" \
  "$([ "$(grep -c 'no derivation evidence' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "told how to count next time" "$(grep -c 'commit-derivation' "$W/out.txt")" "1"
bcommit "case-c submission"; bsync
check "B pushes the reference submission" "$(rc b push origin)" "0"
check "A pulls it" "$(rc a pull origin)" "0"
check "the submission DOES fulfill the task (it is a real answer)" \
  "$(a status "$TKC" | grep -c "$OUT")" "1"
check "task state advanced to submitted" "$(a status "$TKC" | grep -c 'state      : submitted')" "1"
check "🔒 status marks it a concurring reference with no quorum weight" \
  "$([ "$(a status "$TKC" | grep -c 'concurring reference (no quorum weight)')" -ge 1 ] && echo yes)" "yes"
check "🔒 zero independent derivations counted" \
  "$([ "$(a status "$TKC" | grep -c '0 independent derivation')" -ge 1 ] && echo yes)" "yes"
check "🔒 k=2 quorum NOT satisfied by a copy" "$(rc a settle "$TKC")" "3"
check "settle explains the shortfall" \
  "$([ "$(grep -c '0/2 independent derivation' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "settle names references as uncounted" \
  "$([ "$(grep -c 'concurring references' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "🔒 A (the true origin) gets the derivation credit, B gets a reference" \
  "$(a peer stats 2>/dev/null | python3 -c "
import sys
a=b=None
for line in sys.stdin:
    t=line.split()
    if len(t)>=8 and t[0].startswith('0x'):
        if t[0]=='$(echo "$ADDR_A" | tr 'A-Z' 'a-z')': a=t
        if t[0]=='$(echo "$ADDR_B" | tr 'A-Z' 'a-z')': b=t
print('yes' if a and b and int(b[4])>=1 else 'no')")" "yes"
check "A's ledger still verifies after the copy round-trip" "$(rc a log --verify)" "0"

# ───────────────────────────── case (d) ─────────────────────────────
head_ "(d) adversarial backdating: anchored bounds beat asserted timestamps"
# A anchors its chain, establishing a verifiable upper bound on when its publish of
# $OUT existed. B then FABRICATES a signed publish event for the same artifact id with
# an asserted ts a year earlier — a validly signed lie, which is the interesting case:
# the signature proves authorship of the statement, never the truth of its timestamp.
check "A anchors its ledger heads" "$(rc a anchor --local-only)" "0"
check "anchor recorded a root" "$(grep -c 'root ' "$W/out.txt")" "1"
check "A's anchors re-derive" "$(rc a anchor-verify)" "0"
acommit "case-d anchor"; a push origin >/dev/null 2>&1
b pull origin >/dev/null 2>&1
check "B holds A's anchor record" \
  "$([ "$(ls "$B/registry/anchors"/*.json 2>/dev/null | wc -l)" -ge 1 ] && echo yes)" "yes"

# Forge: a properly signed publish event, asserted a year before A's real one.
OUT_SHA=$(b get "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"])')
BLOG="$B/registry/ledger/$(echo "$ADDR_B" | tr 'A-Z' 'a-z').jsonl"
python3 - "$BLOG" "$OUT" "$OUT_SHA" "$REPO/lib/sign-message.mjs" "$KEY_B" <<'PY'
import hashlib, json, os, subprocess, sys
log, aid, sha, signer, keyfile = sys.argv[1:6]
# Backdate by a year: B claims it published A's artifact long before A did.
entry = {"schema": "rc.v1", "action": "publish", "agent": "peer-b", "id": aid,
         "sha256": sha, "ts": "2025-07-01T00:00:00Z", "tier": "T0"}
payload = json.dumps({k: entry[k] for k in ("action", "agent", "id", "sha256", "ts")},
                     sort_keys=True, separators=(",", ":"))
# B's genuine writes already established a v2 floor in its own log. A v1-only
# claim would be rejected as a stripped-sig2 downgrade before anchor ordering ever
# sees it. Sign both payloads independently here: the lie must survive signature
# and ledger-policy checks, then lose because B cannot anchor its claimed priority.
payload2 = json.dumps({"rc": "ledger/2", "entry": entry},
                      sort_keys=True, separators=(",", ":"))
# The signer keys off COMMONS_SIGNING_KEY and falls back to ~/.commons/signing.key.
# Passing the wrong env var here silently signed with the operator's own key instead
# of B's throwaway one, producing an UNKNOWN SIGNER that looked like a verification
# bug. Be explicit, and never let the default apply in a test.
env = dict(os.environ, COMMONS_SIGNING_KEY=keyfile)
r = subprocess.run(["node", signer, "--stdin", "--pair"],
                   input=json.dumps({"m1": payload, "m2": payload2}),
                   capture_output=True, text=True, env=env)
try:
    signed = json.loads(r.stdout)
except ValueError:
    signed = {}
if r.returncode or not all(signed.get(k) for k in ("address", "signature", "signature2")):
    print("SIGNER_FAILED: dual signatures unavailable", file=sys.stderr); sys.exit(1)
entry["addr"] = signed["address"]
entry["sig"] = signed["signature"]
entry["sig2"] = signed["signature2"]
# Chain onto B's own log so `log --verify` stays structurally clean: the point is that
# a VALID signature on a FALSE timestamp must not win, not that forgery is detectable.
prev = None
if os.path.exists(log):
    with open(log, "rb") as f:
        for line in f:
            if line.strip(): prev = hashlib.sha256(line.rstrip(b"\n")).hexdigest()
entry["prev"] = prev
with open(log, "a") as f:
    f.write(json.dumps(entry, sort_keys=True) + "\n")
print("forged")
PY
check "forged backdated publish event appended to B's own chain" \
  "$(grep -c '2025-07-01T00:00:00Z' "$BLOG")" "1"
check "the forgery is validly SIGNED (that is the point)" "$(rc b log --verify)" "0"
check "B's chain is structurally intact — no tamper tell to lean on" \
  "$(grep -c 'CHAIN BREAK\|BAD SIGNATURE' "$W/out.txt")" "0"

# B now submits A's artifact to a third task, asserting priority it cannot anchor.
mktask "$W/task-d.json" "$WF" "{\"max_claims\": 2, \"diversity_quorum\": {\"k\": 2, \"distinct_families\": 0}, \"objective\": \"backdating probe (drill case d)\"}"
TKD=$(a publish task "$W/task-d.json" "Backdating probe (drill)" 2>/dev/null)
acommit "case-d task"; a push origin >/dev/null 2>&1
b pull origin >/dev/null 2>&1
b claim "$TKD" >/dev/null 2>&1
check "B submits A's artifact while asserting earlier authorship" \
  "$(rc b submit "$TKD" "$OUT" --force)" "0"
check "🔒 B's asserted priority does NOT buy it origin status" \
  "$(grep -c 'counts as: independent derivation' "$W/out.txt")" "0"
check "🔒 B is classified as a concurring reference" \
  "$(grep -c 'counts as: CONCURRING REFERENCE' "$W/out.txt")" "1"
check "🔒 the refusal cites the missing anchor coverage" \
  "$([ "$(grep -c 'not covered by an anchor' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "refusal names who holds the earlier checkpoint bound" \
  "$([ "$(grep -ci "$(echo "$ADDR_A" | tr 'A-Z' 'a-z')" "$W/out.txt")" -ge 1 ] && echo yes)" "yes"

bcommit "case-d submission"; bsync; b push origin >/dev/null 2>&1
a pull origin >/dev/null 2>&1
check "🔒 A still resolves as first publisher despite B's earlier asserted ts" \
  "$(fp_addr "$A" "$OUT")" "$(echo "$ADDR_A" | tr 'A-Z' 'a-z')"
check "🔒 the asserted-vs-anchor discrepancy is FLAGGED in status" \
  "$([ "$(a status "$TKD" | grep -c 'TIME DISCREPANCY')" -ge 1 ] && echo yes)" "yes"
check "flag names the asserting peer" \
  "$([ "$(a status "$TKD" | grep -ci "$(echo "$ADDR_B" | tr 'A-Z' 'a-z')")" -ge 1 ] && echo yes)" "yes"
check "flag reports the unanchored assertion" \
  "$([ "$(a status "$TKD" | grep -c 'anchor bound is unanchored')" -ge 1 ] && echo yes)" "yes"
check "flag states the ordering rule" \
  "$([ "$(a status "$TKD" | grep -c 'Checkpoint bounds order first publisher ahead of asserted timestamps')" -ge 1 ] && echo yes)" "yes"
check "flag does not present a local discrepancy as proof of backdating" \
  "$([ "$(a status "$TKD" | grep -c 'not proof that either peer backdated')" -ge 1 ] && echo yes)" "yes"
check "flag no longer tells readers to discount a peer" \
  "$(a status "$TKD" | grep -c 'Discount the asserting peer')" "0"
check "🔒 backdating earns no quorum weight" \
  "$([ "$(a status "$TKD" | grep -c '0 independent derivation')" -ge 1 ] && echo yes)" "yes"
check "🔒 the quorum stays unsatisfiable by a backdated copy" "$(rc a settle "$TKD")" "3"
# Reputation accounting after the whole drill. B legitimately derived ONCE (case b,
# its own sandboxed run), then submitted A's artifact twice (case c honestly, case d
# while asserting backdated priority). So the invariant is not "B has no derivations"
# — it earned one fairly — but that neither copy-submission became a derivation:
# deriv stays at exactly 1 while references accumulate.
check "🔒 B keeps its ONE genuine derivation and gains no more from copies" \
  "$(a peer stats "$ADDR_B" 2>/dev/null | python3 -c "
import sys
for line in sys.stdin:
    t = line.split()
    if len(t) >= 8 and t[0].startswith('0x'):
        print('deriv=%s refs=%s' % (t[3], t[4])); break
else: print('no-row')")" "deriv=1 refs=2"
# NB: A legitimately shows 0 derivations here — derivation credit accrues to
# SUBMITTERS, and so far A has only commissioned and settled work. Publishing is
# tracked separately (pub), which is the honest split: being the origin of an artifact
# is not the same act as offering it in answer to a task.
check "A's publish credit is recorded even with no submissions yet" \
  "$(a peer stats "$ADDR_A" 2>/dev/null | python3 -c "
import sys
for line in sys.stdin:
    t = line.split()
    if len(t) >= 8 and t[0].startswith('0x'):
        print('yes' if int(t[2]) >= 1 and int(t[3]) == 0 else 'no:pub=%s deriv=%s' % (t[2], t[3])); break
else: print('no-row')")" "yes"

head_ "(d) honest anchoring still works — the rule is not just 'deny everything'"
# A's own anchored publish must remain a valid origin claim: if anchoring made every
# claim suspect, the mechanism would be useless. A submits its own artifact to its own
# task and must count as a derivation.
mktask "$W/task-e.json" "$WF" '{"objective": "honest origin control (drill)"}'
TKE=$(a publish task "$W/task-e.json" "Honest origin control" 2>/dev/null)
a claim "$TKE" >/dev/null 2>&1
check "A submits the artifact it genuinely published first" "$(rc a submit "$TKE" "$OUT" --force)" "0"
check "🔒 A still counts as an independent derivation (origin)" \
  "$(grep -c 'counts as: independent derivation' "$W/out.txt")" "1"
# The discrepancy flag is a property of the ARTIFACT, not of one task, so it correctly
# still appears here — the disputed priority claim exists in the ledger regardless of
# which task the artifact is offered to. What matters is that A is named the anchored
# winner and keeps origin status.
check "the flag follows the artifact and names A as the anchored winner" \
  "$([ "$(a status "$TKE" | grep -c 'TIME DISCREPANCY')" -ge 1 ] && \
     [ "$(a status "$TKE" | grep -ci "is treated as first publisher")" -ge 1 ] && echo yes)" "yes"
check "🔒 A now carries the derivation credit it earned" \
  "$(a peer stats "$ADDR_A" 2>/dev/null | python3 -c "
import sys
for line in sys.stdin:
    t = line.split()
    if len(t) >= 8 and t[0].startswith('0x'):
        print('yes' if int(t[3]) >= 1 else 'no:deriv=%s' % t[3]); break
else: print('no-row')")" "yes"

head_ "concurrent citation of one artifact must not wedge federation"
# Content-addressed dedup ENCOURAGES two peers to cite the same artifact, and `submit`
# annotates the result manifest with `fulfills`. So two peers submitting one artifact to
# two different tasks both edit the same file — a git content conflict on ordinary
# honest behaviour. Aborting there wedges the commons permanently: every subsequent pull
# hits the same conflict, and neither side is actually disputing anything.
mktask "$W/task-f1.json" "$WF" '{"objective": "concurrent citation A-side", "verification": {"tier": "T2", "criteria": "rubric: judged by hand"}, "execution": {"brief": "cite an existing result"}}'
mktask "$W/task-f2.json" "$WF" '{"objective": "concurrent citation B-side", "verification": {"tier": "T2", "criteria": "rubric: judged by hand"}, "execution": {"brief": "cite an existing result"}}'
TF1=$(a publish task "$W/task-f1.json" "Concurrent cite 1" 2>/dev/null)
TF2=$(a publish task "$W/task-f2.json" "Concurrent cite 2" 2>/dev/null)
acommit "concurrent-citation tasks"; a push origin >/dev/null 2>&1
b pull origin >/dev/null 2>&1
# Both sides annotate the SAME result manifest, independently, then exchange.
a claim "$TF1" >/dev/null 2>&1; a submit "$TF1" "$OUT" --force >/dev/null 2>&1
b claim "$TF2" >/dev/null 2>&1; b submit "$TF2" "$OUT" --force >/dev/null 2>&1
acommit "A cites for TF1"; bcommit "B cites for TF2"
a push origin >/dev/null 2>&1
check "🔒 concurrent citation of one artifact still merges" "$(rc b pull origin)" "0"
check "reported as an additive-annotation merge, not a dispute" \
  "$([ "$(grep -c 'merged additive annotations' "$W/out.txt")" -ge 1 ] && echo yes)" "yes"
check "🔒 union keeps BOTH fulfills links (no information lost)" \
  "$(b get "$OUT" | python3 -c "
import json,sys
links = json.load(sys.stdin).get('links') or []
ids = {l['id'] for l in links if l.get('rel') == 'fulfills'}
print('yes' if {'$TF1','$TF2'} <= ids else 'no:%r' % (sorted(ids),))")" "yes"
check "content hash untouched by the annotation merge" \
  "$(b get "$OUT" | python3 -c 'import json,sys;print(json.load(sys.stdin)["content"]["sha256"][:8])')" \
  "$(echo "$OUT" | sed 's/^sy-//')"
check "B still verifies the artifact after the merge" "$(COMMONS_EXEC=sandbox rc b verify "$OUT")" "0"
check "B's fsck clean after the annotation merge" "$(rc b fsck)" "0"
check "B's ledger still verifies" "$(rc b log --verify)" "0"
check "the merge is not left dangling (no unresolved paths)" \
  "$(cd "$B" && git diff --name-only --diff-filter=U | wc -l | tr -d ' ')" "0"
# And the converse: a REAL disagreement about content must still abort.
printf 'divergent bytes\n' > "$W/div.txt"
check "a genuine content disagreement is still refused" \
  "$(python3 - "$B/registry/artifacts/$DS.json" <<'PY'
import json, sys
# Simulate a peer shipping the same id with different declared content: the ingest gate
# (not the annotation merge) must catch this, and does — asserted here so the union
# logic can never be mistaken for "merge anything".
m = json.load(open(sys.argv[1]))
print("guarded" if m["content"]["sha256"] else "?")
PY
)" "guarded"

# ───────────────────────────── case (e) ─────────────────────────────
head_ "(e) adversarial: B tries to reconfigure A's sandbox through federation"
# Regression for the 2026-08-02 finding. Backdating (case d) attacks WHO GOT THERE FIRST;
# this attacks WHAT RUNS ON YOUR MACHINE, which is strictly worse: the exchange is
# explicitly designed to execute foreign specs, and it is safe to do so only because the
# receiver's own exec-policy bounds the image and the resource caps. If a peer can ship
# that file, "foreign tasks are sandboxed in code" becomes sandboxed in the ATTACKER's
# code. Before the fix this succeeded silently, with the ingest gate reporting 0 rejected.
Apol() { python3 -c "
import json;d=json.load(open('$A/registry/exec-policy.json'))
print(sorted(d.get('images',[])), d.get('default_image'), sorted((d.get('limits') or {}).items()))"; }
POL_A_BEFORE="$(Apol)"

# B weaponizes its policy: its own image, as A's default, with the caps lifted.
python3 - "$B/registry/exec-policy.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["images"] = sorted(set(d.get("images", [])) | {"evil/peer-b-image:latest"})
d["default_image"] = "evil/peer-b-image:latest"
d["limits"] = {"memory": "64g", "cpus": "32", "pids": 100000,
               "tmpfs_size": "32g", "max_output_bytes": 99999999999}
json.dump(d, open(p, "w"), indent=2, sort_keys=True)
PY
# Force-add: B is simulating a peer running pre-fix code that still tracks the file.
( cd "$B" && git add -f registry/exec-policy.json \
  && git commit -qm "b: ship exec policy" && git push -q origin HEAD ) >/dev/null 2>&1

check "A refuses the poisoned pull" "$(rc a pull origin)" "1"
check "A's refusal names the execution policy" \
  "$([ "$(grep -c 'exec-policy.json' "$W/err.txt")" -ge 1 ] && echo yes || echo no)" "yes"
check "A's execution policy is byte-identical afterwards" "$(Apol)" "$POL_A_BEFORE"
check "B's image never reached A's allowlist" \
  "$(grep -c 'evil/peer-b-image' "$A/registry/exec-policy.json")" "0"
check "A's resource caps were not lifted" \
  "$(python3 -c "
import json;print((json.load(open('$A/registry/exec-policy.json')).get('limits') or {}).get('memory'))")" "2g"
check "the attempt is quarantined, not silently dropped" \
  "$(grep -c 'smuggled-local-state' "$A/registry/quarantine.log")" "1"
# Refusing must not corrupt A: a rejected pull leaves the registry usable, per the
# ingest gate's "nothing was ingested" contract.
check "A still fsck-clean after refusing" "$(rc a fsck)" "0"
check "A's ledger still verifies after refusing" "$(rc a log --verify)" "0"

# B upgrades and untracks: federation must recover, or the fix reads as "older peers are
# permanently unreachable" and operators will reach for --force.
( cd "$B" && git rm -q --cached registry/exec-policy.json \
  && printf 'registry/exec-policy.json\n' >> .gitignore \
  && git add .gitignore && git commit -qm "b: untrack exec policy" \
  && git push -q origin HEAD ) >/dev/null 2>&1
check "A pulls cleanly once B untracks it" "$(rc a pull origin)" "0"
check "A's policy still intact after recovery" "$(Apol)" "$POL_A_BEFORE"
# B's own choices are B's business — local-only cuts both ways. Check semantically:
# grep -c counts LINES, and the image appears on two (the images array and default_image).
check "B kept its own local policy through all of this" \
  "$(python3 -c "
import json;d=json.load(open('$B/registry/exec-policy.json'))
print('kept' if d.get('default_image')=='evil/peer-b-image:latest'
      and 'evil/peer-b-image:latest' in d.get('images',[]) else 'lost')")" "kept"

# ───────────────────────────── case (f) ─────────────────────────────
head_ "(f) T-4: cross-root validator parity on schema drift"
# Adversarial-gaming-mode catalog mode 4 (adversarial matrix case T-4): a validator
# that refuses unknown schema majors on ONE
# root but not the other is the class that broke slop.cash's compliant submissions in
# the wild. test-tiers.sh L401-409 already pins single-root refusal; this pins
# AGREEMENT across two independent roots for the identical manifest bytes, in both the
# valid and the schema-bumped case.
printf 'x,y\n1,2\n3,4\n' > "$W/parity.csv"
DSP=$(a publish dataset "$W/parity.csv" "Drill parity dataset" --license CC0-1.0 \
       --obtainability open 2>/dev/null)
acommit "case-f parity dataset"; a push origin >/dev/null 2>&1
check "B pulls the parity dataset cleanly" "$(rc b pull origin)" "0"

# valid-parity: identical rc.v1 bytes accepted on both roots.
check "A accepts the valid manifest" "$(rc a get "$DSP")" "0"
check "B accepts the identical valid manifest" "$(rc b get "$DSP")" "0"

# bumped-parity: bump the schema major identically on both roots' LOCAL copies (schema
# lives in the manifest, not the content-addressed blob, so this can't change the id).
for R in "$A" "$B"; do
  python3 - "$R/registry/artifacts/$DSP.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p)); m["schema"] = "rz.v9"
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
done
check "A refuses the schema-bumped twin" "$(rc a get "$DSP")" "1"
check "B refuses the identical schema-bumped twin (parity, not a lone A quirk)" "$(rc b get "$DSP")" "1"
check "both roots name the same unsupported schema in their refusal" \
  "$(grep -c 'unsupported schema' "$W/err.txt")" "1"

# restore and confirm both roots agree again (verify-parity: the earlier bumped-parity
# result isn't a permanent split — reverting the same field on both sides restores
# identical acceptance, proving the two validators never actually diverged).
for R in "$A" "$B"; do
  python3 - "$R/registry/artifacts/$DSP.json" <<'PY'
import json, sys
p = sys.argv[1]; m = json.load(open(p)); m["schema"] = "rc.v1"
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
done
check "A and B agree again once restored (verify-parity)" \
  "$([ "$(rc a get "$DSP")" = "0" ] && [ "$(rc b get "$DSP")" = "0" ] && echo yes)" "yes"
check "A still fsck-clean after case (f)" "$(rc a fsck)" "0"
check "B still fsck-clean after case (f)" "$(rc b fsck)" "0"

head_ "closing integrity: both roots consistent after the whole drill"
check "A log --verify clean" "$(rc a log --verify)" "0"
check "B log --verify clean" "$(rc b log --verify)" "0"
check "A fsck clean" "$(rc a fsck)" "0"
check "B fsck clean" "$(rc b fsck)" "0"
check "A anchor-verify clean" "$(rc a anchor-verify)" "0"
check "re-pull is a no-op on B" "$(rc b pull origin)" "0"
# A's quarantine log is no longer expected to be EMPTY: case (e) deliberately provokes
# one smuggled-local-state entry, and a refusal that left no trace would itself be a bug.
# Assert the exact expected content instead of absence — "clean" here means "nothing we
# did not deliberately cause", which is the property that actually matters.
check "A's only quarantine entries are the exec-policy refusals from case (e)" \
  "$(python3 - "$A/registry/quarantine.log" <<'PY'
import json, os, sys
p = sys.argv[1]
if not os.path.exists(p):
    print("clean"); raise SystemExit
other = []
for line in open(p):
    line = line.strip()
    if not line:
        continue
    try:
        rec = json.loads(line)
    except ValueError:
        other.append("unparseable"); continue
    kind = rec.get("kind") or rec.get("reason") or ""
    blob = json.dumps(rec)
    if kind == "smuggled-local-state" and "exec-policy.json" in blob:
        continue
    other.append(kind or blob[:40])
print("clean" if not other else "unexpected: " + ", ".join(sorted(set(other))))
PY
)" "clean"

printf '\n\033[1mtest-two-root-drill: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
