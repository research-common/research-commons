#!/usr/bin/env bash
# Issue #41: an edit to the manifest of an already-held artifact must not merge unchecked.
#
# Before #41, `pull` compared content hashes, called a manifest-only edit "already
# present", skipped every check and then merged it; `hub check --base` only looked at
# added and deleted manifests. A peer could rewrite tier, criteria, licence,
# obtainability, title or links and every gate passed.
#
# What this pins:
#   1. the issue's repro (manifest-only edit, no ledger line) is refused by `pull`
#      (also on --dry-run) and fails `hub check --base`, with the changed fields named
#   2. a `publish --force` by the artifact's own publisher passes both gates
#   3. a `publish --force` by a key with no authority over the artifact does not
#   4. the legitimate unsigned-by-republish writers still flow: submit (fulfills),
#      accept (accepted), attest (attested_by)
#   5. an annotation with no ledger event behind it, and a link removal, are refused
#   6. a second branch carrying the same authorised republish still pulls cleanly
#   7. replaying an old publish, including an equivalent signature encoding, cannot
#      authorise an edit; trust=none attestations and unbacked rebaselines are refused
#   8. independent local and incoming annotations union on an add/add manifest,
#      but an incoming unbacked link is still refused; an unreadable task spec
#      never grants a foreign accept authority
#   8b. a collection maintainer named by the spec may republish it, nobody else
#   9. a foreign publish-only event grants no authority (refused where it would be
#      the only signed publish), and a rewritten incoming ledger is refused
#  10. a copied accept or submit with a changed unsigned result, and a republish-only
#      authority-laundering sequence, cannot authorise manifest edits; links bind to
#      the backing event's signed fields, and an already-held event still backs one;
#      replay detection keys on changed bytes, and ledger folds prefer the signer's own
#      log. Which result an accept names is bound: by sig2, or for a v1 accept by a
#      submission whose signed hash covers it (#45)
#  10b. the publisher may restate criteria through its own attestation, nobody else;
#      same-second events by one signer stay distinct; pull from an unrelated history
#      still runs the replay check; a no-op pull is quick; hub check never tracebacks
#  11. KNOWN GAP, pinned so it is not mistaken for coverage: an edit committed after a
#      genuine republish in the same range rides on it (closed by signing manifests,
#      the follow-up designed with #10)
set -uo pipefail

unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"

PASS=0 FAIL=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL+1)); }
check(){ if [ "$2" = "$3" ]; then ok "$1"; else bad "$1 (want $3, got $2)"; fi; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

LAB="$(mktemp -d -t commons-test-manifest-edit-XXXXXX)"
trap 'rm -rf "$LAB"' EXIT
W="$LAB/work"; mkdir -p "$W"
export GIT_AUTHOR_NAME=t GIT_AUTHOR_EMAIL=t@example.com
export GIT_COMMITTER_NAME=t GIT_COMMITTER_EMAIL=t@example.com
KL="$LAB/lead.key"; KC="$LAB/contrib.key"
for k in "$KL" "$KC"; do
  python3 -c "import secrets;print('0x'+secrets.token_hex(32))" > "$k"; chmod 600 "$k"
done
HL="$LAB/hub-lead"; HC="$LAB/hub-contrib"; BARE="$LAB/hub.git"

L()  { ( cd "$HL" && COMMONS_ROOT="$HL" COMMONS_AGENT=lead    COMMONS_SIGNING_KEY="$KL" "$COMMONS" "$@" ); }
C()  { ( cd "$HC" && COMMONS_ROOT="$HC" COMMONS_AGENT=contrib COMMONS_SIGNING_KEY="$KC" "$COMMONS" "$@" ); }
# The lead's own key, working in the contributor's clone (a second machine, same identity).
LC() { ( cd "$HC" && COMMONS_ROOT="$HC" COMMONS_AGENT=lead    COMMONS_SIGNING_KEY="$KL" "$COMMONS" "$@" ); }
CL() { ( cd "$HL" && COMMONS_ROOT="$HL" COMMONS_AGENT=contrib COMMONS_SIGNING_KEY="$KC" "$COMMONS" "$@" ); }
rc() { "$@" >"$W/out.txt" 2>"$W/err.txt"; echo $?; }
both() { cat "$W/out.txt" "$W/err.txt"; }

"$COMMONS" hub init "$HL" --name manifest-edit >/dev/null 2>&1
ADDR_L=$(L peer whoami 2>/dev/null | head -1)
if [ -z "$ADDR_L" ]; then
  printf '\033[33mtest-manifest-edit: signer not functional — skipping\033[0m\n'; exit 0
fi
# Not C(): the contributor clone does not exist yet.
ADDR_C=$( (cd "$HL" && COMMONS_ROOT="$HL" COMMONS_SIGNING_KEY="$KC" "$COMMONS" peer whoami) 2>/dev/null | head -1)
ADDR_Cl=$(echo "$ADDR_C" | tr 'A-Z' 'a-z')
L peer add "$ADDR_L" --agent-id lead --trust full >/dev/null 2>&1
L peer add "$ADDR_C" --agent-id contrib --trust full >/dev/null 2>&1
cp "$REPO/registry/exec-policy.example.json" "$HL/registry/exec-policy.json"

edit() {  # edit <root> <id> <python statements on m>
  python3 - "$1/registry/artifacts/$2.json" "$3" <<'PY'
import json, sys
p, code = sys.argv[1:3]; m = json.load(open(p)); exec(code)
json.dump(m, open(p, "w"), indent=2, sort_keys=True)
PY
}
field() { python3 -c 'import json,sys;m=json.load(open(sys.argv[1]));print(eval(sys.argv[2]))' \
            "$1/registry/artifacts/$2.json" "$3"; }
branch() { ( cd "$HC" && git checkout -q main && git reset -q --hard origin/main \
             && git checkout -q -B "$1" ); }
cpush()  { ( cd "$HC" && git add registry store && git commit -qm "$1" \
             && git push -q -f origin "HEAD:$(git rev-parse --abbrev-ref HEAD)" ); }
lpull()  { rc L pull origin --branch "$1" "${@:2}"; }
hcheck() { ( cd "$HC" && COMMONS_ROOT="$HC" "$COMMONS" hub check --base origin/main ) \
             >"$W/out.txt" 2>&1; echo $?; }
lreset() { ( cd "$HL" && git reset -q --hard "$1" ); }
replay_publish() {  # replay_publish <root> <id> <plain|equivalent>
  python3 - "$1" "$2" "$3" "$REPO/lib/verify-message.mjs" <<'PY'
import hashlib, json, os, pathlib, subprocess, sys
root = pathlib.Path(sys.argv[1])
aid, variant, verifier = sys.argv[2:]
for path in (root / "registry/ledger").glob("*.jsonl"):
    lines = path.read_text().splitlines()
    old = next((entry for line in lines
                if (entry := json.loads(line)).get("action") == "publish"
                and entry.get("id") == aid), None)
    if old is None:
        continue
    event = dict(old)
    event["prev"] = hashlib.sha256(lines[-1].encode()).hexdigest()
    if variant == "equivalent":
        sig = event["sig"]
        v = int(sig[-2:], 16)
        alt = {27: 0, 28: 1, 0: 27, 1: 28}.get(v)
        if alt is None:
            raise SystemExit("unsupported recovery byte")
        event["sig"] = sig[:-2] + f"{alt:02x}"
        payload = {k: event[k] for k in ("action", "agent", "id", "sha256", "ts")
                   if k in event}
        probe = subprocess.run(
            ["node", verifier, "--stdin"],
            input=json.dumps(payload, sort_keys=True, separators=(",", ":")),
            text=True, capture_output=True,
            env={**os.environ, "SIGNATURE": event["sig"], "ADDRESS": event["addr"]})
        if not json.loads(probe.stdout or "{}").get("valid"):
            raise SystemExit("equivalent recovery-byte encoding was not verified")
    with path.open("a") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")
    raise SystemExit(0)
raise SystemExit("original signed publish not found")
PY
}
replay_accept() {  # copy a valid accept, alter its unsigned result, append to its log
  COMMONS_ROOT="$HC" python3 - "$COMMONS" "$HC" "$TK" "$DS" "$T3" <<'PY'
import hashlib, json, pathlib, runpy, sys
commons, root, task, original, replacement = sys.argv[1:]
verify = runpy.run_path(commons)["verify_entry"]
for path in (pathlib.Path(root) / "registry/ledger").glob("*.jsonl"):
    lines = path.read_text().splitlines()
    old = next((e for line in lines
                if (e := json.loads(line)).get("action") == "accept"
                and e.get("id") == task and e.get("result") == original), None)
    if old is None:
        continue
    tampered = dict(old, result=replacement)
    if "sig2" in old and verify(tampered, tampered["sig"], tampered["addr"])[0]:
        raise SystemExit("a dual-signed accept still verifies with its result changed")
    # Strip sig2 (a downgrade to a v1-only event): what remains is a valid v1 copy.
    event = {k: v for k, v in tampered.items() if k != "sig2"}
    event["prev"] = hashlib.sha256(lines[-1].encode()).hexdigest()
    if not verify(event, event["sig"], event["addr"])[0]:
        raise SystemExit("altered-result accept no longer verifies")
    with path.open("a") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")
    raise SystemExit(0)
raise SystemExit("original signed accept not found")
PY
}
replay_altered() {  # replay_altered <ledger-addr> <action> <id> <new-result>
  # Copy a genuine signed lifecycle event, change its unsigned `result`, rechain.
  COMMONS_ROOT="$HC" python3 - "$COMMONS" "$HC" "$@" <<'PY'
import hashlib, json, pathlib, runpy, sys
commons, root, addr, action, aid, result = sys.argv[1:]
path = pathlib.Path(root) / "registry/ledger" / (addr.lower() + ".jsonl")
lines = path.read_text().splitlines()
old = [e for e in map(json.loads, lines)
       if e.get("action") == action and e.get("id") == aid]
if not old:
    raise SystemExit("original signed %s not found" % action)
tampered = dict(old[-1], result=result)
if "sig2" in tampered and runpy.run_path(commons)["verify_entry"](
        tampered, tampered["sig"], tampered["addr"])[0]:
    raise SystemExit("a dual-signed event still verifies with its result changed")
# Strip sig2 (a downgrade to a v1-only event): what remains is a valid v1 copy.
event = {k: v for k, v in tampered.items() if k != "sig2"}
event["prev"] = hashlib.sha256(lines[-1].encode()).hexdigest()
if not runpy.run_path(commons)["verify_entry"](event, event["sig"], event["addr"])[0]:
    raise SystemExit("altered copy no longer verifies")
with path.open("a") as f:
    f.write(json.dumps(event, sort_keys=True) + "\n")
PY
}
append_foreign_publish() {  # append_foreign_publish <id>: a fresh signed event, no manifest change
  COMMONS_ROOT="$HC" COMMONS_SIGNING_KEY="$KC" python3 - "$COMMONS" "$1" "$HC" <<'PY'
import json, pathlib, runpy, sys
commons, aid, root = sys.argv[1:]
m = json.loads((pathlib.Path(root) / "registry/artifacts" / (aid + ".json")).read_text())
runpy.run_path(commons)["ledger_append"](
    {"agent": "contrib", "action": "publish", "id": aid,
     "sha256": m["content"]["sha256"],
     "tier": (m.get("verification") or {}).get("tier") or "method"})
PY
}
append_rebaseline() {  # append_rebaseline <key> <agent> <id> <with|without digest>
  COMMONS_ROOT="$HC" COMMONS_SIGNING_KEY="$1" python3 - "$COMMONS" "$2" "$3" "$4" "$HC" <<'PY'
import json, pathlib, runpy, sys
commons, agent, aid, variant, root = sys.argv[1:]
m = json.loads((pathlib.Path(root) / "registry/artifacts" / (aid + ".json")).read_text())
digest = m["content"]["sha256"]
image = m["provenance"]["run"]["exec"]["image_digest"]
event = {"agent": agent, "action": "rebaseline", "id": aid, "sha256": digest,
         "tier": "T0", "result": "match", "exec_mode": "sandbox"}
if variant == "with":
    event["image_digest"] = image
runpy.run_path(commons)["ledger_append"](event)
PY
}
rebaseline_digest_signed() {
  COMMONS_ROOT="$HC" python3 - "$COMMONS" "$RB" "$HL" <<'PY'
import json, pathlib, runpy, sys
ns = runpy.run_path(sys.argv[1])
aid, lead = sys.argv[2:]
m = json.loads((pathlib.Path(lead) / "registry/artifacts" / (aid + ".json")).read_text())
events = [e for e in ns["ManifestEditGate"]._parse(ns["_ledger_raw_lines_at"]("HEAD"))
          if e.get("action") == "rebaseline" and e.get("id") == aid]
if len(events) != 1:
    raise SystemExit("expected one rebaseline event")
event = events[0]
altered = dict(event, image_digest="sha256:" + "0" * 64)
print(bool(event.get("sig2"))
      and event.get("image_digest") == m["provenance"]["run"]["exec"]["image_digest"]
      and ns["verify_entry"](event, event["sig"], event["addr"])[0]
      and not ns["verify_entry"](altered, altered["sig"], altered["addr"])[0])
PY
}
append_foreign_accept() {  # signed event without using the CLI's beneficiary check
  COMMONS_ROOT="$HC" COMMONS_SIGNING_KEY="$KC" python3 - "$COMMONS" "$TK" "$T3" "$HC" <<'PY'
import json, pathlib, runpy, sys
commons, task, result, root = sys.argv[1:]
m = json.loads((pathlib.Path(root) / "registry/artifacts" / (task + ".json")).read_text())
runpy.run_path(commons)["ledger_append"](
    {"agent": "contrib", "action": "accept", "id": task, "task": task,
     "sha256": m["content"]["sha256"], "result": result})
PY
}
unreadable_accept_gate() {  # exercise both gate modes with an unavailable task spec
  ( cd "$HC" && COMMONS_ROOT="$HC" python3 - "$COMMONS" "$TK" "$T3" "$ADDR_C" <<'PY'
import runpy, sys
ns = runpy.run_path(sys.argv[1])
task, result, foreign = sys.argv[2:]
rel = "registry/artifacts/" + task + ".json"
old = ns["_git_json_at"]("origin/main", rel)
new = ns["_git_json_at"]("HEAD", rel)
base = ns["_ledger_raw_lines_at"]("origin/main")
head = ns["_ledger_raw_lines_at"]("HEAD")
events = [e for e in ns["ManifestEditGate"]._parse(head)
          if e.get("action") == "accept" and e.get("task") == task
          and e.get("result") == result and e.get("addr", "").lower() == foreign.lower()]
if len(events) != 1 or not ns["verify_entry"](events[0], events[0]["sig"], foreign)[0]:
    raise SystemExit("fixture lacks a verified foreign accept event")
for peers in (None, ns["load_peers"]()):
    gate = ns["ManifestEditGate"](base, head, lambda _: None,
                                   peers=peers, trust=ns["trust_allows"])
    reasons = gate.problems(task, old, new)
    if not any("link accepted:" + result + " added with no signed ledger event behind it"
               in reason for reason in reasons):
        raise SystemExit("unreadable task spec backed a foreign accepted link")
print("foreign signature verified; both gate modes rejected the unreadable spec")
PY
  )
}

# ---------------------------------------------------------------- fixtures
head_ "fixtures: the lead's T3 dataset, a workflow and a task (beneficiary = lead)"
printf 'reading\n1\n2\n' > "$W/r.csv"
DS=$(L publish dataset "$W/r.csv" "readings" --tier T3 --criteria "hand-transcribed" \
       --license CC0-1.0 --obtainability restricted 2>/dev/null | tail -1)
check "dataset published" "$(echo "$DS" | grep -cE '^ds-[0-9a-f]{8}$')" "1"
printf 'reading\n3\n' > "$W/t3.csv"
T3=$(L publish dataset "$W/t3.csv" "observation" --tier T3 --criteria "GET /x" \
       --license CC0-1.0 --obtainability open 2>/dev/null | tail -1)
cat > "$W/step.py" <<'PY'
import json, os
json.dump({"n": 1}, open(os.environ["OUT_DIR"] + "/r.json", "w"))
PY
python3 - "$W/wf.json" "$DS" "$W/step.py" <<'PY'
import json, sys
json.dump({"interpreter": "bash", "inputs": {"D": sys.argv[2]},
           "attachments": {"step.py": open(sys.argv[3]).read()},
           "steps": ["python3 step.py"], "outputs": {"r": "r.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"}, "timeout": 60},
          open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WF=$(L publish workflow "$W/wf.json" "wf" 2>/dev/null | tail -1)
RB=$(L run "$WF" --publish --publish-type synthesis --exec native \
       --title "native baseline" 2>/dev/null | awk '{print $1}')
check "native result published for rebaseline cases" "$(echo "$RB" | grep -cE '^sy-[0-9a-f]{8}$')" "1"
check "  with a native execution record" "$(field "$HL" "$RB" 'm["provenance"]["run"]["exec"]["mode"]')" "native"
python3 - "$W/task.json" "$DS" "$WF" "$ADDR_L" <<'PY'
import json, sys
out, ds, wf, ben = sys.argv[1:5]
json.dump({"objective": "count", "priority": 2, "expires": "2099-01-01T00:00:00Z",
           "inputs": [{"id": ds}], "execution": {"workflow": wf}, "max_claims": 2,
           "verification": {"tier": "T0", "criteria": "byte-identical re-derivation"},
           "beneficiary": {"agent": "lead", "addr": ben}},
          open(out, "w"), indent=2, sort_keys=True)
PY
TK=$(L publish task "$W/task.json" "count task" 2>/dev/null | tail -1)
check "task published" "$(echo "$TK" | grep -cE '^tk-[0-9a-f]{8}$')" "1"
python3 - "$W/task.json" "$W/task2.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
m["objective"] = "independent count"
json.dump(m, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PY
TK2=$(L publish task "$W/task2.json" "second count task" 2>/dev/null | tail -1)
check "second task published for annotation union" "$(echo "$TK2" | grep -cE '^tk-[0-9a-f]{8}$')" "1"
( cd "$HL" && git add -A && git commit -qm base )
git init -q --bare -b main "$BARE"
( cd "$HL" && git remote add origin "$BARE" && git push -q origin HEAD:main )
git clone -q "$BARE" "$HC"
C peer add "$ADDR_C" --agent-id contrib --trust full >/dev/null 2>&1
C peer add "$ADDR_L" --agent-id lead --trust full >/dev/null 2>&1
BASE=$(git -C "$HL" rev-parse HEAD)

# ---------------------------------------------------------------- 1. the repro
head_ "1. the #41 repro: a manifest-only edit is refused"
branch edit
edit "$HC" "$DS" '
m["verification"] = {"tier": "T0"}
m["license"] = "proprietary-internal"
m["availability"] = {"obtainability": "open"}
m["title"] = "readings (official, verified)"
m["links"] = [{"rel": "derives", "id": "wf-00000000"}]'
cpush edit
check "pull --dry-run refuses it" "$(lpull edit --dry-run)" "1"
check "  counted as rejected, not already present" \
  "$(grep -cE 'incoming: 0 new/changed, [0-9]+ already present, 1 rejected' "$W/out.txt")" "1"
check "  naming the changed fields" \
  "$(both | grep -c "edited without an authorised signed republish: availability changed, license changed, link derives:wf-00000000 added with no signed ledger event behind it, title changed, verification.criteria changed, verification.tier changed")" "1"
check "pull refuses it" "$(lpull edit)" "1"
check "  and the lead's manifest is untouched" "$(field "$HL" "$DS" 'm["verification"]["tier"]')" "T3"
check "  and the rejection is quarantined" \
  "$([ "$(grep -c "\"artifact\": \"$DS\"" "$HL/registry/quarantine.log")" -ge 1 ] && echo yes)" "yes"
check "hub check --base fails it" "$(hcheck)" "1"
check "  with the same reason" "$(grep -c "PROBLEM: manifest of already-held $DS edited" "$W/out.txt")" "1"

head_ "1b. single-field edits each fail (criteria, licence)"
branch crit
edit "$HC" "$DS" 'm["verification"]["criteria"] = "machine-verified"'
cpush crit
check "a criteria-only edit is refused by pull" "$(lpull crit --dry-run)" "1"
check "  and by hub check --base" "$(hcheck)" "1"

# ---------------------------------------------------------------- 2. authorised republish
head_ "2. publish --force by the artifact's own publisher is accepted"
branch repub
check "the lead republishes from the contributor's clone (same key)" \
  "$(rc LC publish dataset "$W/r.csv" "readings, corrected title" --force)" "0"
cpush repub
# Both branches descend from the same base and carry byte-identical manifests and
# signed republish lines, but their Git commits differ.
branch repub-copy
( cd "$HC" && git restore --source repub -- registry )
cpush repub-copy
check "second branch has the same republished manifest" \
  "$(git -C "$HC" diff repub:registry/artifacts/$DS.json repub-copy:registry/artifacts/$DS.json | wc -l | tr -d ' ')" "0"
git -C "$HC" checkout -q repub
check "hub check --base passes" "$(hcheck)" "0"
check "pull accepts it" "$(lpull repub)" "0"
check "  and says the edit is backed" "$(grep -c 'carry edits backed by a signed republish' "$W/out.txt")" "1"
check "  and the lead holds the new title" "$(field "$HL" "$DS" 'm["title"]')" "readings, corrected title"
check "  with the verification carried forward" "$(field "$HL" "$DS" 'm["verification"]["criteria"]')" "hand-transcribed"
check "pull accepts the identical republish from another branch" "$(lpull repub-copy)" "0"
check "  and keeps the authorised title" "$(field "$HL" "$DS" 'm["title"]')" "readings, corrected title"
lreset "$BASE"

head_ "2b. a collection maintainer named by the spec may republish; others may not"
# The lead publishes a collection whose spec names the contributor as a co-maintainer.
python3 - "$W/coll.json" "$DS" "$ADDR_L" "$ADDR_C" <<'PY'
import json, sys
out, ds, lead, contrib = sys.argv[1:5]
json.dump({"scope": "manifest gate maintainer authority",
           "maintainers": [{"agent": "lead", "addr": lead},
                           {"agent": "contrib", "addr": contrib}],
           "members": [{"id": ds, "role": "primary-dataset"}],
           "task_criteria": "none"}, open(out, "w"), indent=2, sort_keys=True)
PY
CO=$(L publish collection "$W/coll.json" "gate collection" 2>/dev/null | tail -1)
check "collection fixture published" "$(echo "$CO" | grep -cE '^cl-[0-9a-f]{8}$')" "1"
( cd "$HL" && git add -A && git commit -qm "collection" && git push -q origin HEAD:main )
git -C "$HC" fetch -q origin
branch maintainer-edit
check "the co-maintainer republishes the collection with a new title" \
  "$(rc C publish collection "$W/coll.json" "gate collection (co-maintainer)" --force)" "0"
cpush maintainer-edit
check "hub check --base accepts a named maintainer's republish" "$(hcheck)" "0"
check "pull accepts it" "$(lpull maintainer-edit --dry-run)" "0"
python3 - "$W/coll.json" "$W/coll-lead-only.json" "$ADDR_L" <<'PY'
import json, sys
spec = json.load(open(sys.argv[1])); spec["maintainers"] = [{"agent": "lead", "addr": sys.argv[3]}]
json.dump(spec, open(sys.argv[2], "w"), indent=2, sort_keys=True)
PY
CO2=$(L publish collection "$W/coll-lead-only.json" "lead-only collection" 2>/dev/null | tail -1)
( cd "$HL" && git add -A && git commit -qm "lead-only collection" && git push -q origin HEAD:main )
git -C "$HC" fetch -q origin
branch non-maintainer-edit
check "a key the spec does not name republishes the lead-only collection" \
  "$(rc C publish collection "$W/coll-lead-only.json" "hijacked" --force)" "0"
cpush non-maintainer-edit
check "hub check --base refuses it" "$(hcheck)" "1"
check "pull refuses it" "$(lpull non-maintainer-edit --dry-run)" "1"
check "  for lack of authority" "$(both | grep -c "$ADDR_Cl (no authority over $CO2)")" "1"
( cd "$HL" && git push -q -f origin "$BASE:main" ) && git -C "$HC" fetch -q origin
lreset "$BASE"

# ---------------------------------------------------------------- 3. unauthorised republish
head_ "3. publish --force by a key with no authority over the artifact is refused"
branch foreign
check "the contributor republishes the lead's dataset as T0" \
  "$(rc C publish dataset "$W/r.csv" "readings (contrib)" --force --tier T0 --criteria x)" "0"
cpush foreign
check "pull refuses it" "$(lpull foreign --dry-run)" "1"
check "  saying the republish does not authorise it" \
  "$(both | grep -c "does not authorise it: $(echo "$ADDR_C" | tr 'A-Z' 'a-z') (no authority over $DS)")" "1"
check "hub check --base refuses it" "$(hcheck)" "1"

# ---------------------------------------------------------------- 3a. publish-only authority
head_ "3a. a foreign publish-only event never makes its signer an owner"
# DS has a verified signed publisher (the lead). A second key's `publish` of it (a
# backdated forgery, or an honest concurrent publish of the same bytes) is ingested and
# reported, never refused: its log is append-only, so refusing would wedge federation
# with that peer for good, and priority between the two is the anchors' call (see the
# two-root drill, case d). It grants no authority; with two signed publishers no key
# may rewrite the manifest (fail closed until #43's signed publisher views).
branch foreign-publish-only
check "contributor appends a fresh signed publish for the lead's dataset" \
  "$(rc append_foreign_publish "$DS")" "0"
cpush foreign-publish-only
check "fixture leaves the manifest unchanged" \
  "$(git -C "$HC" diff --name-only origin/main HEAD -- "registry/artifacts/$DS.json" | wc -l | tr -d ' ')" "0"
check "hub check --base passes the publish-only event" "$(hcheck)" "0"
check "  and reports that it grants no authority" \
  "$(grep -c "publish of already-held $DS by $ADDR_Cl grants no edit authority" "$W/out.txt")" "1"
check "pull ingests it" "$(lpull foreign-publish-only)" "0"
check "  and reports that it grants no authority" \
  "$(both | grep -c "publish of already-held $DS by $ADDR_Cl grants no edit authority")" "1"
( cd "$HL" && git push -q origin HEAD:main ) && git -C "$HC" fetch -q origin
branch foreign-publish-edit
check "contributor then republishes it with a new title" \
  "$(rc C publish dataset "$W/r.csv" "contributor title" --force)" "0"
cpush foreign-publish-edit
check "hub check --base refuses the edit" "$(hcheck)" "1"
check "pull refuses the edit" "$(lpull foreign-publish-edit --dry-run)" "1"
check "  the contributor has no authority over it" \
  "$(both | grep -c "$ADDR_Cl (no authority over $DS)")" "1"
check "  and the lead keeps its title" "$(field "$HL" "$DS" 'm["title"]')" "readings"
( cd "$HL" && git push -q -f origin "$BASE:main" ) && git -C "$HC" fetch -q origin
lreset "$BASE"

head_ "3a1. a foreign publish of an artifact with no signed publisher is refused"
# Here landing the event WOULD mint authority: it would be the only verified signed
# publish, so its signer would become the owner.
printf 'legacy\n' > "$W/legacy.csv"
UL=$( (cd "$HL" && COMMONS_ROOT="$HL" COMMONS_AGENT=lead COMMONS_SIGNING_KEY= "$COMMONS" \
        publish dataset "$W/legacy.csv" "legacy unsigned" --license CC0-1.0 \
        --obtainability open) 2>/dev/null | tail -1)
check "an unsigned (legacy) publish fixture" "$(echo "$UL" | grep -cE '^ds-[0-9a-f]{8}$')" "1"
( cd "$HL" && git add -A && git commit -qm "legacy unsigned artifact" && git push -q origin HEAD:main )
git -C "$HC" fetch -q origin
branch foreign-claim
check "contributor appends a signed publish for it" "$(rc append_foreign_publish "$UL")" "0"
cpush foreign-claim
check "hub check --base refuses it" "$(hcheck)" "1"
check "  naming the authority grab" \
  "$(grep -c "publish by $ADDR_Cl does not authorise already-held $UL (it has no signed publisher" "$W/out.txt")" "1"
check "pull refuses it" "$(lpull foreign-claim --dry-run)" "1"
check "  naming the authority grab" \
  "$(both | grep -c "already-held artifact(s): $UL by $ADDR_Cl (it has no signed publisher")" "1"
( cd "$HL" && git push -q -f origin "$BASE:main" ) && git -C "$HC" fetch -q origin
lreset "$BASE"

# ---------------------------------------------------------------- 3a2. republish-only authority laundering
head_ "3a2. a republish-only push does not grant its signer authority"
branch republish-only
check "contributor signs a republish of the lead's dataset" \
  "$(rc C publish dataset "$W/r.csv" "temporary contributor title" --force)" "0"
( cd "$HC" && git restore --source origin/main -- "registry/artifacts/$DS.json" )
cpush republish-only
check "first push leaves the manifest unchanged" \
  "$(git -C "$HC" diff --name-only origin/main HEAD -- "registry/artifacts/$DS.json" | wc -l | tr -d ' ')" "0"
check "lead accepts the event-only push" "$(lpull republish-only)" "0"
check "lead still holds the original title" "$(field "$HL" "$DS" 'm["title"]')" "readings"
( cd "$HC" && git checkout -q -B republish-laundered )
check "contributor tries to rewrite title, tier and licence" \
  "$(rc C publish dataset "$W/r.csv" "laundered title" --force \
    --tier T0 --criteria x --license MIT)" "0"
cpush republish-laundered
check "hub check --base rejects the laundered edit" "$(hcheck)" "1"
check "pull rejects the laundered edit" "$(lpull republish-laundered --dry-run)" "1"
check "  contributor has no authority over the dataset" \
  "$(both | grep -c "no authority over $DS")" "1"
check "  lead's title remains unchanged" "$(field "$HL" "$DS" 'm["title"]')" "readings"
check "  lead's tier remains T3" "$(field "$HL" "$DS" 'm["verification"]["tier"]')" "T3"
check "  lead's licence remains CC0-1.0" "$(field "$HL" "$DS" 'm["license"]')" "CC0-1.0"
lreset "$BASE"

# ---------------------------------------------------------------- 3b. replayed owner publish
head_ "3b. an old signed publish does not authorise a forged edit"
for variant in plain equivalent; do
  branch "replay-$variant"
  edit "$HC" "$DS" 'm["title"] = "forged title via old publish"'
  check "$variant replay fixture uses a verifiable old owner signature" \
    "$(rc replay_publish "$HC" "$DS" "$variant")" "0"
  cpush "replay-$variant"
  check "$variant replay is refused by pull" "$(lpull "replay-$variant" --dry-run)" "1"
  check "  pull identifies the replayed signed event" \
    "$(both | grep -c "replayed signed ledger event(s): publish $DS")" "1"
  check "$variant replay is refused by hub check --base" "$(hcheck)" "1"
  check "  hub check identifies the replayed signed event" \
    "$(grep -c "replayed signed ledger event: publish $DS" "$W/out.txt")" "1"
done

# ---------------------------------------------------------------- 3c. incoming ledger rewrite
head_ "3c. pull refuses a rewritten incoming ledger"
branch ledger-rewrite
LEAD_LEDGER="registry/ledger/$(echo "$ADDR_L" | tr 'A-Z' 'a-z').jsonl"
python3 - "$HC/$LEAD_LEDGER" <<'PY'
from pathlib import Path
import sys
path = Path(sys.argv[1])
lines = path.read_text().splitlines(keepends=True)
if len(lines) < 2:
    raise SystemExit("fixture needs at least two owner ledger events")
path.write_text("".join(lines[1:]))
PY
cpush ledger-rewrite
check "pull refuses the incoming ledger rewrite" "$(lpull ledger-rewrite --dry-run)" "1"
check "  and identifies the rewritten ledger" \
  "$(both | grep -c "ledger rewritten, not appended: $LEAD_LEDGER")" "1"

# ---------------------------------------------------------------- 3d. add/add with independent annotations
head_ "3d. independent annotations union when both branches add the same manifest"
printf 'independent result\n' > "$W/add-add.csv"
branch add-add
AD=$(LC publish dataset "$W/add-add.csv" "shared new result" --tier T3 \
       --criteria "hand-transcribed" --license CC0-1.0 --obtainability open \
       2>/dev/null | tail -1)
check "incoming branch publishes the new artifact" "$(echo "$AD" | grep -cE '^ds-[0-9a-f]{8}$')" "1"
AD_DIGEST=$(field "$HC" "$AD" 'm["content"]["sha256"]')
mkdir -p "$HL/store/sha256/${AD_DIGEST:0:2}"
cp "$HC/registry/artifacts/$AD.json" "$HL/registry/artifacts/$AD.json"
cp "$HC/store/sha256/${AD_DIGEST:0:2}/$AD_DIGEST" \
   "$HL/store/sha256/${AD_DIGEST:0:2}/$AD_DIGEST"
check "incoming side adds its own fulfills link" "$(rc LC submit "$TK2" "$AD" --force)" "0"
cpush add-add
check "local side adds a different fulfills link" "$(rc CL submit "$TK" "$AD" --force)" "0"
( cd "$HL" && git add registry store && git commit -qm "local annotation on add-add artifact" )
merge_rc=$(lpull add-add)
check "pull merges independent add/add annotations" "$merge_rc" "0"
if [ "$merge_rc" != 0 ]; then both; fi
check "  both links survive the merge" \
  "$(field "$HL" "$AD" 'sorted(l["id"] for l in m["links"] if l["rel"] == "fulfills")')" \
  "$(python3 - "$TK" "$TK2" <<'PY'
import sys
print(sorted(sys.argv[1:]))
PY
)"
lreset "$BASE"

# ---------------------------------------------------------------- 3e. add/add tags and unbacked incoming links
head_ "3e. add/add accepts local tags but rejects an incoming unbacked link"
for variant in tags unbacked-link; do
  branch "add-add-$variant"
  printf 'independent %s\n' "$variant" > "$W/add-add-$variant.csv"
  ADD_ID=$(LC publish dataset "$W/add-add-$variant.csv" "shared $variant result" \
    --tier T3 --criteria "hand-transcribed" --license CC0-1.0 \
    --obtainability open 2>/dev/null | tail -1)
  check "$variant fixture publishes a shared artifact" \
    "$(echo "$ADD_ID" | grep -cE '^ds-[0-9a-f]{8}$')" "1"
  ADD_DIGEST=$(field "$HC" "$ADD_ID" 'm["content"]["sha256"]')
  mkdir -p "$HL/store/sha256/${ADD_DIGEST:0:2}"
  cp "$HC/registry/artifacts/$ADD_ID.json" "$HL/registry/artifacts/$ADD_ID.json"
  cp "$HC/store/sha256/${ADD_DIGEST:0:2}/$ADD_DIGEST" \
     "$HL/store/sha256/${ADD_DIGEST:0:2}/$ADD_DIGEST"
  if [ "$variant" = tags ]; then
    cpush add-add-tags
    edit "$HL" "$ADD_ID" 'm["tags"] = ["local-tag"]'
    ( cd "$HL" && git add registry store && git commit -qm "local tags on add-add artifact" )
    check "pull accepts a local tags change on an add/add manifest" \
      "$(lpull add-add-tags)" "0"
    check "  merged manifest retains the local tag" \
      "$(field "$HL" "$ADD_ID" 'm["tags"]')" "['local-tag']"
  else
    edit "$HC" "$ADD_ID" 'm["links"].append({"rel": "fulfills", "id": "'"$TK2"'"})'
    cpush add-add-unbacked-link
    ( cd "$HL" && git add registry store && git commit -qm "local copy of add-add artifact" )
    check "pull refuses an unbacked incoming link on an add/add manifest" \
      "$(lpull add-add-unbacked-link --dry-run)" "1"
    check "  rejection names the missing signed event" \
      "$(both | grep -c "link fulfills:$TK2 added with no signed ledger event behind it")" "1"
    check "  local manifest remains free of the unbacked link" \
      "$(field "$HL" "$ADD_ID" 'm["links"]')" "[]"
  fi
  lreset "$BASE"
done

# ---------------------------------------------------------------- 4. legitimate annotations
head_ "4. submit / accept / attest annotations still flow"
branch exchange
check "contributor claims the task" "$(rc C claim "$TK")" "0"
check "contributor submits the lead's dataset (adds fulfills to it)" \
  "$(rc C submit "$TK" "$DS" --force)" "0"
check "  fulfills link written" "$(field "$HC" "$DS" '[l["rel"] for l in m["links"]]')" "['fulfills']"
cpush exchange
check "hub check --base passes the submission" "$(hcheck)" "0"
check "lead pulls the submission" "$(lpull exchange)" "0"
check "  fulfills link landed" "$(field "$HL" "$DS" '[l["rel"] for l in m["links"]]')" "['fulfills']"
check "lead accepts (adds accepted to the task)" "$(rc L accept "$TK" "$DS" --force)" "0"
( cd "$HL" && git add registry && git commit -qm accept && git push -q origin HEAD:main )
( cd "$HC" && git checkout -q main )
check "contributor pulls the acceptance" "$(rc C pull origin)" "0"
check "  accepted link landed" "$(field "$HC" "$TK" '[l["rel"] for l in m.get("links",[])]')" "['accepted']"
BASE2=$(git -C "$HL" rev-parse HEAD)

branch attest
check "contributor attests the lead's T3 dataset" \
  "$(rc C attest "$T3" --observed 2026-09-01T00:00:00Z)" "0"
cpush attest
check "hub check --base passes the attestation" "$(hcheck)" "0"
check "lead pulls it" "$(lpull attest)" "0"
check "  attested_by landed" "$(field "$HL" "$T3" 'm["verification"]["attested_by"]["addr"].lower()')" \
  "$(echo "$ADDR_C" | tr 'A-Z' 'a-z')"
lreset "$BASE2"

# ---------------------------------------------------------------- 4a. replayed lifecycle authorization
head_ "4a. changing an unsigned result on a copied accept cannot add an accepted link"
branch replay-accept
check "copied accept still carries a valid owner signature" \
  "$(rc replay_accept)" "0"
edit "$HC" "$TK" 'm["links"].append({"rel": "accepted", "id": "'"$T3"'"})'
cpush replay-accept
check "hub check --base rejects the altered accept" "$(hcheck)" "1"
check "  hub check identifies the replayed accept" \
  "$(grep -c "replayed signed ledger event: accept $TK" "$W/out.txt")" "1"
check "pull rejects the altered accept" "$(lpull replay-accept --dry-run)" "1"
check "  pull identifies the replayed accept" \
  "$(both | grep -c "replayed signed ledger event(s): accept $TK")" "1"
check "  lead retains only the genuine accepted result" \
  "$(field "$HL" "$TK" 'sorted(l["id"] for l in m["links"] if l["rel"] == "accepted")')" \
  "['$DS']"

# ---------------------------------------------------------------- 4a2. altered submit copy
head_ "4a2. changing an unsigned result on a copied submit cannot add a fulfills link"
branch altered-submit
check "copy of the contributor's submit, result changed, still verifies" \
  "$(rc replay_altered "$ADDR_C" submit "$TK" "$T3")" "0"
edit "$HC" "$T3" 'm.setdefault("links", []).append({"rel": "fulfills", "id": "'"$TK"'"})'
cpush altered-submit
check "hub check --base refuses the altered submit" "$(hcheck)" "1"
check "  as a replayed signed event" "$(grep -c "replayed signed ledger event: submit $TK" "$W/out.txt")" "1"
check "pull refuses it" "$(lpull altered-submit)" "1"
check "  as a replayed signed event" "$(both | grep -c "replayed signed ledger event(s): submit $TK")" "1"
check "  and the result carries no fulfills link" "$(field "$HL" "$T3" 'm.get("links", [])')" "[]"
lreset "$BASE2"

# ---------------------------------------------------------------- 4a3. links bind to signed fields
head_ "4a3. a relayed submit cannot back a link on another result; held events still back links"
branch relayed-submit
check "contributor submits DS for the task on an unmerged branch" "$(rc C submit "$TK2" "$DS" --force)" "0"
python3 - "$HC/registry/ledger/$ADDR_Cl.jsonl" "$T3" <<'PY'
import json, sys
path, other = sys.argv[1:]
lines = open(path).read().splitlines()
e = json.loads(lines[-1]); assert e["action"] == "submit"
e.pop("sig2", None)          # downgrade to v1: `result` is then outside every signature
e["result"] = other
lines[-1] = json.dumps(e, sort_keys=True)
open(path, "w").write("\n".join(lines) + "\n")
PY
( cd "$HC" && git checkout -q origin/main -- "registry/artifacts/$DS.json" )
edit "$HC" "$T3" 'm.setdefault("links", []).append({"rel": "fulfills", "id": "'"$TK2"'"})'
cpush relayed-submit
check "hub check --base refuses a fulfills link the submit's signed hash doesn't cover" "$(hcheck)" "1"
check "pull refuses it" "$(lpull relayed-submit --dry-run)" "1"
check "  naming the unbacked link" "$(both | grep -c "link fulfills:$TK2 added with no signed ledger event")" "1"

branch held-1
check "contributor submits DS for the second task" "$(rc C submit "$TK2" "$DS" --force)" "0"
( cd "$HC" && git checkout -q origin/main -- "registry/artifacts/$DS.json" )
cpush held-1
check "lead pulls the submit without its link" "$(lpull held-1)" "0"
( cd "$HL" && git push -q origin HEAD:main ) && git -C "$HC" fetch -q origin
branch held-2
edit "$HC" "$DS" 'm["links"].append({"rel": "fulfills", "id": "'"$TK2"'"})'
cpush held-2
check "a link backed by an already-held submit passes hub check --base" "$(hcheck)" "0"
check "  and pull" "$(lpull held-2)" "0"
check "  and lands" "$(field "$HL" "$DS" 'sorted(l["id"] for l in m["links"] if l["rel"] == "fulfills")')" \
  "$(python3 -c 'import sys;print(sorted(sys.argv[1:]))' "$TK" "$TK2")"
( cd "$HL" && git push -q -f origin "$BASE2:main" ) && git -C "$HC" fetch -q origin
lreset "$BASE2"

head_ "4a4. replay detection keys on changed bytes, not on duplicates"
check "a byte-identical duplicate is not a replay; a re-chained copy is" \
  "$( cd "$HL" && COMMONS_ROOT="$HL" python3 - "$COMMONS" <<'PY'
import json, runpy, sys
ns = runpy.run_path(sys.argv[1])
lines = ns["_ledger_raw_lines_at"]("HEAD")
line = next(l for l in lines if json.loads(l).get("action") == "accept")
moved = json.dumps(dict(json.loads(line), prev="0" * 64), sort_keys=True)
r = ns["replayed_ledger_events"]
print(r([], [line, line]) == [] and r([line], [line, line]) == []
      and len(r([], [line, moved])) == 1 and len(r([line], [line, moved])) == 1)
PY
)" "True"

check "the fold keeps the copy in the signer's own log, not a relayed one" \
  "$( T="$LAB/fold" && mkdir -p "$T" && cp -r "$HL/." "$T/" && cd "$T" && COMMONS_ROOT="$T" python3 - "$COMMONS" "$TK" "$T3" <<'PY'
import json, pathlib, runpy, sys
commons, task, other = sys.argv[1:]
led = pathlib.Path("registry/ledger")
own = next(p for p in led.glob("*.jsonl")
           if any(json.loads(l).get("action") == "accept" for l in p.read_text().splitlines()))
e = [json.loads(l) for l in own.read_text().splitlines() if json.loads(l).get("action") == "accept"][-1]
# a foreign log whose name sorts before every real address
(led / "0x0000000000000000000000000000000000000000.jsonl").write_text(
    json.dumps({k: v for k, v in dict(e, result=other).items() if k != "sig2"},
               sort_keys=True) + "\n")
ns = runpy.run_path(commons)
rows = [r for r, _p in ns["read_ledger_entries"]() if r.get("action") == "accept" and r.get("id") == task]
print(len(rows) == 1 and rows[0].get("result") == e["result"])
PY
)" "True"

head_ "4a5. which result an accept names is bound (#45)"
# A relayed copy of an unmerged genuine accept with `result` changed. Dual-signed: the
# change breaks sig2, so the event is a forgery. Downgraded (sig2 stripped): a v1
# accept's result must name a submission to the task bound by the submit's signed
# hash, and T3 was never submitted to TK2.
branch relayed-accept
check "the lead accepts DS for the second task on an unmerged branch" \
  "$(rc LC accept "$TK2" "$DS" --force)" "0"
LEADLOG="$HC/registry/ledger/$(echo "$ADDR_L" | tr 'A-Z' 'a-z').jsonl"
cp "$LEADLOG" "$W/leadlog.bak"
python3 - "$LEADLOG" "$T3" <<'PY'
import json, sys
path, other = sys.argv[1:]
lines = open(path).read().splitlines()
e = json.loads(lines[-1]); assert e["action"] == "accept" and e.get("sig2")
lines[-1] = json.dumps(dict(e, result=other), sort_keys=True)
open(path, "w").write("\n".join(lines) + "\n")
PY
edit "$HC" "$TK2" 'm["links"] = [{"rel": "accepted", "id": "'"$T3"'"}]'
cpush relayed-accept
check "dual-signed copy with result changed: hub check --base refuses" "$(hcheck)" "1"
check "  as a bad signature" "$(grep -c "BAD SIGNATURE on accept $TK2" "$W/out.txt")" "1"
check "  and pull refuses it" "$(lpull relayed-accept --dry-run)" "1"
cp "$W/leadlog.bak" "$LEADLOG"
python3 - "$LEADLOG" "$T3" <<'PY'
import json, sys
path, other = sys.argv[1:]
lines = open(path).read().splitlines()
e = json.loads(lines[-1]); assert e["action"] == "accept"
e.pop("sig2"); e["result"] = other
lines[-1] = json.dumps(e, sort_keys=True)
open(path, "w").write("\n".join(lines) + "\n")
PY
cpush relayed-accept
check "downgraded v1 copy: hub check --base refuses the unbacked accepted link" "$(hcheck)" "1"
check "  and pull refuses it" "$(lpull relayed-accept --dry-run)" "1"
check "  naming the unbacked link" \
  "$(both | grep -c "link accepted:$T3 added with no signed ledger event")" "1"

# ---------------------------------------------------------------- 4b. explicit trust denial
head_ "4b. a trust=none attester cannot change a held claim"
check "lead explicitly denies the contributor's trust" \
  "$(rc L peer add "$ADDR_C" --agent-id contrib --trust none --force)" "0"
branch none-attester
check "trust=none peer still produces a valid signed attestation" \
  "$(rc C attest "$T3" --criteria "an attacker-supplied observation" \
    --observed 2026-09-01T00:00:00Z)" "0"
cpush none-attester
check "hub check --base refuses the changed criteria" "$(hcheck)" "1"
check "pull refuses the trust=none attestation" "$(lpull none-attester --dry-run)" "1"
check "  identifies the unsupported edit" \
  "$(both | grep -c 'verification.attested_by changed without a valid attestation')" "1"
check "lead restores full trust for remaining cases" \
  "$(rc L peer add "$ADDR_C" --agent-id contrib --trust full --force)" "0"

head_ "4b2. criteria: the publisher may restate them through an attestation; nobody else"
branch owner-criteria
check "the lead re-attests its own T3 dataset with new criteria" \
  "$(rc LC attest "$T3" --criteria "GET /x, verified mirror" --observed 2026-09-02T00:00:00Z --force)" "0"
cpush owner-criteria
check "hub check --base passes the owner's restated criteria" "$(hcheck)" "0"
check "pull accepts them" "$(lpull owner-criteria --dry-run)" "0"
branch contrib-criteria
check "the contributor attests with new criteria" \
  "$(rc C attest "$T3" --criteria "contributor's criteria" --observed 2026-09-02T00:00:00Z --force)" "0"
cpush contrib-criteria
check "hub check --base refuses a non-owner's criteria" "$(hcheck)" "1"
check "pull refuses them" "$(lpull contrib-criteria --dry-run)" "1"
check "  naming the criteria change" "$(both | grep -c 'verification.criteria changed')" "1"

head_ "4b3. same-second events by one signer stay distinct"
check "two accepts of one task in the same second keep distinct signed timestamps" \
  "$( T="$LAB/same-second" && mkdir -p "$T" && cp -r "$HL/." "$T/" && cd "$T" && \
      COMMONS_ROOT="$T" COMMONS_SIGNING_KEY="$KL" python3 - "$COMMONS" "$TK" "$DS" "$T3" <<'PY'
import json, runpy, sys, time
commons, task, r1, r2 = sys.argv[1:]
ns = runpy.run_path(commons)
digest = ns["load_manifest"](task)["content"]["sha256"]
before = {e.get("sig") for e, _p in ns["read_ledger_entries"]()}
while time.time() % 1 > 0.2:   # start early in a second so both calls share it
    time.sleep(0.02)
for r in (r1, r2):
    ns["ledger_append"]({"agent": "lead", "action": "accept", "id": task, "task": task,
                         "sha256": digest, "result": r})
rows = [e for e, _p in ns["read_ledger_entries"]()
        if e.get("action") == "accept" and e.get("sig") not in before]
lines = ns["_ledger_raw_lines_local"]()
print(len(rows) == 2 and rows[0]["ts"] != rows[1]["ts"]
      and {r["result"] for r in rows} == {r1, r2}
      and ns["replayed_ledger_events"]([], lines) == [])
PY
)" "True"

# ---------------------------------------------------------------- 5. unbacked annotations
head_ "5. annotations with nothing behind them are refused"
branch forged-link
edit "$HC" "$DS" 'm["links"].append({"rel": "fulfills", "id": "tk-00000000"})'
cpush forged-link
check "a fulfills link with no submit is refused" "$(lpull forged-link --dry-run)" "1"
check "  naming it" "$(both | grep -c 'link fulfills:tk-00000000 added with no signed ledger event')" "1"
check "  and hub check --base refuses it" "$(hcheck)" "1"

branch strip
edit "$HC" "$DS" 'm["links"] = []'
cpush strip
check "removing a link without a republish is refused" "$(lpull strip --dry-run)" "1"
check "  naming it" "$(both | grep -c "link fulfills:$TK removed")" "1"

branch forged-att
edit "$HC" "$T3" '
m["verification"]["attested_by"] = {"addr": "0x0000000000000000000000000000000000000001",
  "sig": "0x00", "statement": {"attests": m["id"], "sha256": m["content"]["sha256"],
  "criteria": "GET /x", "observed": "2026-09-01T00:00:00Z"}}'
cpush forged-att
check "a forged attested_by is refused" "$(lpull forged-att --dry-run)" "1"
check "  naming it" "$(both | grep -c 'attested_by changed without a valid attestation')" "1"

# ---------------------------------------------------------------- 6. unreadable task beneficiary
head_ "6. an unreadable task spec cannot give a foreign accept event authority"
branch unreadable-beneficiary
edit "$HC" "$TK" 'm["links"].append({"rel": "accepted", "id": "'"$T3"'"})'
check "foreign signer records a real accept signature" "$(rc append_foreign_accept)" "0"
cpush unreadable-beneficiary
check "hub check --base refuses the foreign accepted link" "$(hcheck)" "1"
check "pull refuses the foreign accepted link" "$(lpull unreadable-beneficiary --dry-run)" "1"
check "both gate modes reject it when the task spec cannot be read" \
  "$(unreadable_accept_gate)" \
  "foreign signature verified; both gate modes rejected the unreadable spec"

# ---------------------------------------------------------------- 7. rebaseline backing
head_ "7. only an authorised rebaseline with a signed matching image digest can replace provenance"
KO="$LAB/outsider.key"
python3 -c "import secrets;print('0x'+secrets.token_hex(32))" > "$KO"
chmod 600 "$KO"
ADDR_O=$( (cd "$HC" && COMMONS_ROOT="$HC" COMMONS_SIGNING_KEY="$KO" \
            "$COMMONS" peer whoami) 2>/dev/null | head -1 )
check "outsider key is not registered with the lead" \
  "$(python3 - "$HL/registry/peers.json" "$ADDR_O" <<'PY'
import json, sys
peers = json.load(open(sys.argv[1]))["peers"]
print(not any(p["addr"].lower() == sys.argv[2].lower() for p in peers))
PY
)" "True"
for variant in outsider missing-digest owner; do
  branch "rebaseline-$variant"
  edit "$HC" "$RB" '
m["provenance"]["run"]["exec"] = {
  "mode": "sandbox", "image_digest": "sha256:" + "f" * 64}
m["provenance"]["run"]["rebaselined"] = "2026-09-01T00:00:00Z"'
  if [ "$variant" = outsider ]; then
    check "outsider signs a matching rebaseline with an image digest" \
      "$(rc append_rebaseline "$KO" outsider "$RB" with)" "0"
  elif [ "$variant" = missing-digest ]; then
    check "owner signs a rebaseline that omits the image digest" \
      "$(rc append_rebaseline "$KL" lead "$RB" without)" "0"
  else
    check "owner signs a rebaseline with the matching image digest" \
      "$(rc append_rebaseline "$KL" lead "$RB" with)" "0"
  fi
  cpush "rebaseline-$variant"
  if [ "$variant" = owner ]; then
    check "owner rebaseline passes hub check --base" "$(hcheck)" "0"
    check "owner rebaseline is accepted by pull" "$(lpull rebaseline-owner)" "0"
    check "  lead holds the sandbox execution record" \
      "$(field "$HL" "$RB" 'm["provenance"]["run"]["exec"]["mode"]')" "sandbox"
    check "  v2 signature covers the matching image digest" \
      "$(rebaseline_digest_signed)" "True"
  else
    check "$variant rebaseline is refused by pull" \
      "$(lpull "rebaseline-$variant" --dry-run)" "1"
    check "  provenance is the rejected edit" \
      "$(both | grep -c 'provenance.run changed with no matching signed rebaseline')" "1"
    check "$variant rebaseline is refused by hub check --base" "$(hcheck)" "1"
  fi
done
lreset "$BASE2"

# ---------------------------------------------------------------- 8. known gap
head_ "9. unrelated histories: the replay and publish checks still run"
# A peer bootstrapped with `git init` shares no merge base with us. What we hold stands
# in for the base: an altered copy of an accept we already hold is still a replay.
U="$LAB/unrelated"
git clone -q "$BARE" "$U" && ( cd "$U" && git checkout -q main && git reset -q --hard "$BASE2" )
rm -rf "$U/.git" && git -C "$U" init -q -b main
python3 - "$U" "$TK" "$T3" <<'PY'
import hashlib, json, pathlib, sys
root, task, other = pathlib.Path(sys.argv[1]), sys.argv[2], sys.argv[3]
led = root / "registry/ledger"
for p in sorted(led.glob("*.jsonl")):
    lines = p.read_text().splitlines()
    hit = [json.loads(l) for l in lines if json.loads(l).get("action") == "accept"
           and json.loads(l).get("id") == task]
    if hit:
        e = dict(hit[-1], result=other, prev=hashlib.sha256(lines[-1].encode()).hexdigest())
        e.pop("sig2", None)   # downgrade to v1, so the copy still verifies: a replay
        with p.open("a") as f:
            f.write(json.dumps(e, sort_keys=True) + "\n")
        break
m = json.loads((root / "registry/artifacts" / (task + ".json")).read_text())
m["links"].append({"rel": "accepted", "id": other})
(root / "registry/artifacts" / (task + ".json")).write_text(json.dumps(m, indent=2, sort_keys=True))
PY
( cd "$U" && git add -A && git commit -qm "unrelated bootstrap" )
( cd "$HL" && git reset -q --hard "$BASE2" && git remote add unrelated "$U" )
check "pull from an unrelated history refuses the altered accept" \
  "$(rc L pull unrelated --branch main)" "1"
check "  as a replayed signed event" "$(both | grep -c "replayed signed ledger event(s): accept $TK")" "1"
check "  and the task keeps only the genuine acceptance" \
  "$(field "$HL" "$TK" '[l["id"] for l in m["links"] if l["rel"] == "accepted"]')" "['$DS']"
check "a pull of a ref we already contain is a no-op" "$(rc L pull origin --branch main)" "0"
check "  that says so" "$(both | grep -c 'nothing new to merge')" "1"
( cd "$HL" && git remote remove unrelated )
lreset "$BASE"

head_ "10. hub check survives malformed edits (reports, never a traceback)"
branch no-content
edit "$HC" "$T3" 'del m["content"]'
cpush no-content
check "hub check --base fails a manifest edit that drops content" "$(hcheck)" "1"
check "  without a traceback" "$(grep -c Traceback "$W/out.txt")" "0"
branch drop-ledger
( cd "$HC" && git rm -q "registry/ledger/$(echo "$ADDR_L" | tr 'A-Z' 'a-z').jsonl" )
cpush drop-ledger
check "hub check --base fails a deleted ledger" "$(hcheck)" "1"
check "  naming it" "$(grep -c 'registry content deleted: registry/ledger/' "$W/out.txt")" "1"
check "  without a traceback" "$(grep -c Traceback "$W/out.txt")" "0"

head_ "8. KNOWN GAP (pinned): an edit after a genuine republish rides on it"
branch ride
LC publish dataset "$W/r.csv" "readings v2" --force >/dev/null 2>&1
( cd "$HC" && git add registry store && git commit -qm "genuine republish" )
edit "$HC" "$DS" 'm["verification"] = {"tier": "T0"}'
cpush "ride-along edit"
check "accepted today: the republish signs the content hash, not the manifest" \
  "$(lpull ride --dry-run)" "0"

head_ "housekeeping"
( cd "$HL" && COMMONS_ROOT="$HL" "$COMMONS" fsck ) >"$W/out.txt" 2>&1
check "lead fsck clean" "$?" "0"

printf '\n\033[1mtest-manifest-edit: %d passed, %d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
