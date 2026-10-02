#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 The Research Commons Authors
#
# demo-hub — build a synthetic demo registry so every id in README.md's "Demo hub
# artifacts" table (and the walkthrough examples above it) resolves against a real
# hub anyone can reproduce.
#
# Usage: scripts/demo-hub.sh [target-dir]
#   target-dir defaults to a mktemp directory, printed on the last line.
#
# DETERMINISM: every artifact id below is content-derived (sha256 of the published
# bytes), and every spec pins its own timestamps (created/expires/observed) rather
# than reading the wall clock, so running this script twice — even under two
# different signing keys, even on two different days — produces byte-identical
# manifests and therefore IDENTICAL ids. Signatures differ (they're over the same
# canonical bytes with different keys) but ids, content hashes, and the ledger's
# recorded `tier`/`sha256` fields do not. Verified by tests/test-demo-hub.sh.
#
# Topic: a small municipal "city weather station readings" dataset — chosen because
# it needs no domain expertise to follow and carries no resemblance to any real
# organization, protocol, or project.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(dirname "$HERE")"
COMMONS="$REPO/bin/commons"

TARGET="${1:-}"
if [ -z "$TARGET" ]; then
  TARGET="$(mktemp -d -t commons-demo-hub-XXXXXX)"
fi
mkdir -p "$TARGET"
if [ -n "$(ls -A "$TARGET" 2>/dev/null)" ]; then
  echo "error: target dir $TARGET is not empty" >&2
  exit 1
fi

# A pinned-bytes signing key. Any 32-byte value produces the same result: signatures
# never affect an artifact's id (ids are content hashes of the manifest's PUBLISHED
# FILE, not of the ledger entry), which is the whole point of this determinism
# argument. Still: never reuse a real/production key here.
KEY="$TARGET/.demo.key"
python3 -c "import secrets;open('$KEY','w').write('0x'+secrets.token_hex(32))"
chmod 600 "$KEY"

ROOT="$TARGET/hub"
mkdir -p "$ROOT/registry"
export COMMONS_ROOT="$ROOT"
export COMMONS_AGENT=demo-hub
export COMMONS_SIGNING_KEY="$KEY"
cp "$REPO/registry/exec-policy.example.json" "$ROOT/registry/exec-policy.json"

W="$TARGET/work"
mkdir -p "$W"
c() { "$COMMONS" "$@"; }

echo "building synthetic demo hub in $ROOT" >&2

# Register this run's own signing identity as a full-trust peer, so `commons fsck
# --ledger` shows every publish as a KNOWN (not "UNKNOWN SIGNER") signature. This is
# per-host trust policy (peers.json never replicates) and has nothing to do with
# the ADDR placeholder used for collection/task maintainer fields below.
SELF_ADDR=$(c peer whoami | head -1)
c peer add "$SELF_ADDR" --agent-id demo-hub --trust full --note self >&2

# ---------------------------------------------------------------------------------
# 1. T3 attested dataset — station readings, as if hand-entered from instrument logs.
# ---------------------------------------------------------------------------------
cat > "$W/readings.csv" << 'CSV'
station,date,temp_c,rainfall_mm
riverside,2026-06-01,18.4,0.0
riverside,2026-06-02,19.1,2.3
riverside,2026-06-03,17.6,0.0
harborview,2026-06-01,16.9,1.1
harborview,2026-06-02,17.8,0.0
harborview,2026-06-03,16.2,4.5
hillcrest,2026-06-01,21.0,0.0
hillcrest,2026-06-02,21.7,0.0
hillcrest,2026-06-03,20.3,0.6
CSV
DS=$(c publish dataset "$W/readings.csv" "City weather station readings, June 2026" \
       -d "Daily temperature and rainfall from three municipal stations, transcribed from instrument logs" \
       -t weather -t demo \
       --license CC0-1.0 --obtainability open \
       --tier T3 --criteria "hand-transcribed from station instrument logs")
c attest "$DS" --observed "2026-06-04T00:00:00Z" >&2

# ---------------------------------------------------------------------------------
# 2. Deterministic workflow — per-station rainfall totals + city-wide average temp.
# ---------------------------------------------------------------------------------
cat > "$W/analyze.py" << 'PY'
import csv, json, os
rows = list(csv.DictReader(open(os.environ["IN_READINGS"])))
by_station = {}
for r in rows:
    by_station.setdefault(r["station"], {"temp_sum": 0.0, "temp_n": 0, "rain_mm": 0.0})
    s = by_station[r["station"]]
    s["temp_sum"] += float(r["temp_c"]); s["temp_n"] += 1
    s["rain_mm"] += float(r["rainfall_mm"])
out = {"stations": {}, "n_readings": len(rows)}
for name, s in sorted(by_station.items()):
    out["stations"][name] = {"avg_temp_c": round(s["temp_sum"] / s["temp_n"], 2),
                              "total_rainfall_mm": round(s["rain_mm"], 2)}
out["city_avg_temp_c"] = round(
    sum(v["avg_temp_c"] for v in out["stations"].values()) / len(out["stations"]), 2)
json.dump(out, open(os.environ["OUT_DIR"] + "/summary.json", "w"),
          indent=2, sort_keys=True)
PY
python3 - "$W/wf.json" "$DS" "$W/analyze.py" << 'PY'
import json, sys
json.dump({"interpreter": "bash", "inputs": {"READINGS": sys.argv[2]},
           "attachments": {"analyze.py": open(sys.argv[3]).read()},
           "steps": ["python3 analyze.py"], "outputs": {"summary": "summary.json"},
           "env": {"TZ": "UTC", "LC_ALL": "C", "PYTHONHASHSEED": "0"},
           "timeout": 120}, open(sys.argv[1], "w"), indent=2, sort_keys=True)
PY
WF=$(c publish workflow "$W/wf.json" "Station summary workflow (deterministic)" \
       --license Apache-2.0)

# ---------------------------------------------------------------------------------
# 3. T0 synthesis — run the workflow, publish the output, verify PASS.
#    Prefer sandbox (matches the README's exec story); fall back to native if
#    docker is unavailable, so the script still completes on a docker-less host.
# ---------------------------------------------------------------------------------
EXEC_MODE=native
if command -v docker >/dev/null 2>&1 && timeout 10 docker info >/dev/null 2>&1 \
    && docker image inspect research-commons-sandbox:base >/dev/null 2>&1; then
  EXEC_MODE=sandbox
fi
SY=$(COMMONS_EXEC="$EXEC_MODE" c run "$WF" --publish --publish-type synthesis \
       --title "Station summary (June 2026)" | awk '{print $1}')

# ---------------------------------------------------------------------------------
# 4. Two comparators (already shipped in comparators/ — same content hash everywhere
#    they are published, so these ids are the same as the README's inline table).
# ---------------------------------------------------------------------------------
CMP_EPS=$(c publish skill "$REPO/comparators/json-numeric-epsilon.py" "json-numeric-epsilon" \
            -d "T1 comparator: JSON with float tolerance" -t comparator --license Apache-2.0)
CMP_SET=$(c publish skill "$REPO/comparators/sorted-set-equality.py" "sorted-set-equality" \
            -d "T1 comparator: line multiset equality" -t comparator --license Apache-2.0)

# ---------------------------------------------------------------------------------
# 5. Wiki page + bibliography + report — same evidence cluster, unverified tier
#    (prose artifacts, not machine-checkable, exactly like the README's originals).
# ---------------------------------------------------------------------------------
cat > "$W/wiki.md" << 'MD'
# City weather stations, June 2026

Three municipal stations (riverside, harborview, hillcrest) logged daily temperature
and rainfall for the first three days of June 2026. Riverside ran driest and warmest
of the three; harborview saw the single wettest day (4.5mm on June 3).

Claims:
- City-wide average temperature over the window was in the high-teens Celsius.
- Harborview's rainfall was concentrated on one day, not spread evenly.
MD
WK=$(c publish wiki "$W/wiki.md" "City weather stations, June 2026" \
       --link cites:"$SY" --link cites:"$DS" --license CC-BY-4.0)

cat > "$W/bib.md" << 'MD'
# Bibliography: city weather stations, June 2026

- Station instrument logs (municipal weather service, transcribed 2026-06-04).
- Station summary workflow output, this hub.
MD
BB=$(c publish bibliography "$W/bib.md" "Bibliography: city weather stations" \
       --license CC-BY-4.0)

cat > "$W/report.md" << 'MD'
# Report: June 2026 station comparison

Hillcrest ran warmest and driest; harborview's rainfall was concentrated in a single
event. See the station summary synthesis for the underlying numbers.
MD
RP=$(c publish report "$W/report.md" "Report: June 2026 station comparison" \
       --input "$DS" --link cites:"$SY" --license CC-BY-4.0)

# ---------------------------------------------------------------------------------
# 6. A fetch-and-run skill (plain script, not a SKILL.md bundle) — csv row counter.
# ---------------------------------------------------------------------------------
cat > "$W/csv-quick-profile.py" << 'PY'
#!/usr/bin/env python3
"""csv-quick-profile — print row/column counts for a CSV file (fetch + run anywhere)."""
import csv, sys
if __name__ == "__main__":
    with open(sys.argv[1]) as f:
        rows = list(csv.reader(f))
    print("rows=%d cols=%d" % (len(rows) - 1, len(rows[0]) if rows else 0))
PY
SK_PROFILE=$(c publish skill "$W/csv-quick-profile.py" "csv-quick-profile" \
               -d "print row/column counts for a CSV file" -t utility --license Apache-2.0)

# ---------------------------------------------------------------------------------
# 7. Collection curating the six artifacts above, with open questions.
#
# ADDR here is a FIXED placeholder address baked into every spec below, deliberately
# NOT this run's signing key (`c peer whoami` mints a fresh key every run, which
# would make every collection/task spec — and therefore their content-derived ids —
# differ run to run). A collection's declared maintainers are just addresses in a
# JSON blob; nothing requires them to match the actual publisher, and `collection
# show` already reports when they don't (see README "curated by ... NOT a listed
# maintainer"). That mismatch is expected and harmless in a synthetic demo hub: the
# maintainer identity is illustrative placeholder data, not a claim about who
# published these bytes.
# ---------------------------------------------------------------------------------
ADDR=0x000000000000000000000000000000000dEEDEE0
python3 - "$W/cl.json" "$ADDR" "$DS" "$WF" "$SY" "$WK" "$BB" "$RP" "$SK_PROFILE" << 'PY'
import json, sys
out, addr, ds, wf, sy, wk, bb, rp, sk = sys.argv[1:10]
json.dump({
    "scope": "Weather station demo — a small, fully-reproducible worked example",
    "maintainers": [{"agent": "demo-hub", "addr": addr}],
    "members": [
        {"id": ds, "role": "primary-dataset"},
        {"id": wf, "role": "workflow"},
        {"id": sy, "role": "synthesis"},
        {"id": wk, "role": "wiki"},
        {"id": bb, "role": "bibliography"},
        {"id": rp, "role": "report"},
        {"id": sk, "role": "tool"},
    ],
    "task_criteria": "extend the station comparison to a station not yet covered",
    "open_questions": [
        "Only three days are covered — does the June 3 rainfall spike at "
        "harborview recur later in the month?",
        "The dataset is T3 (attested transcription): every derivation above it "
        "grades T3 no matter how cleanly it re-derives.",
    ],
}, open(out, "w"), indent=2, sort_keys=True)
PY
CL=$(c publish collection "$W/cl.json" "Weather Station Demo")

# ---------------------------------------------------------------------------------
# 8. Open k=2 replication task routed to the collection.
# ---------------------------------------------------------------------------------
python3 - "$W/tk.json" "$ADDR" "$WF" "$CL" << 'PY'
import json, sys
out, addr, wf, cl = sys.argv[1:5]
json.dump({
    "objective": "re-derive the station summary workflow and confirm the numbers",
    "priority": 2,
    "expires": "2099-01-01T00:00:00Z",
    "verification": {"tier": "T0", "criteria": "byte-identical re-derivation of the workflow output"},
    "execution": {"workflow": wf},
    "beneficiary": {"agent": "demo-hub", "addr": addr},
    "max_claims": 2,
    "diversity_quorum": {"k": 2, "distinct_families": 2},
    "collections": [cl],
}, open(out, "w"), indent=2, sort_keys=True)
PY
TK=$(c publish task "$W/tk.json" "Replicate: station summary")

# ---------------------------------------------------------------------------------
# 9. Method skill (SKILL.md bundle + rubric.json) + method collection + --method task.
# ---------------------------------------------------------------------------------
MBUNDLE="$W/method"
mkdir -p "$MBUNDLE"
cat > "$MBUNDLE/SKILL.md" << 'MD'
# Method: weather-station comparison v1

1. Group readings by station.
2. Compute per-station average temperature and total rainfall.
3. Compute the city-wide average of the per-station averages.
4. Note any single-day outliers (a day contributing >50% of a station's total
   rainfall for the window).
MD
cat > "$MBUNDLE/rubric.json" << 'JSON'
{"criteria_list": [
  {"id": "per-station-stats", "text": "average temperature and total rainfall computed per station"},
  {"id": "city-average", "text": "city-wide average temperature is the average of the per-station averages, not a pooled mean over readings"},
  {"id": "outlier-noted", "text": "any single day contributing over half a station's total rainfall for the window is called out"}
]}
JSON
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner \
    -C "$MBUNDLE" -cf "$W/method.tar" .
SK_METHOD=$(c publish skill "$W/method.tar" "Method: weather-station comparison v1" \
              -d "how a station-readings comparison is analyzed here" \
              -t methodology -t category:weather-station --license CC-BY-4.0)

cat > "$W/mc.json" << MCJSON
{"scope": "Weather-station comparison method: procedure + the instances that applied it",
 "maintainers": [{"agent": "demo-hub", "addr": "$ADDR"}],
 "members": [
   {"id": "$SK_METHOD", "role": "method"},
   {"id": "$RP", "role": "instance"}
 ]}
MCJSON
CL_METHOD=$(c publish collection "$W/mc.json" "Weather-station comparison method")

# The instance report should also declare it applied the method — republish is not
# needed; `applies` is a link on a NEW artifact, so this is a second, distinct report
# rather than a mutation of $RP (immutable content). Kept minimal on purpose.
cat > "$W/report-method.md" << 'MD'
# Report: June 2026 station comparison (method-applied)

Same analysis as the June 2026 station comparison, following
Method: weather-station comparison v1 step by step.
MD
RP_METHOD=$(c publish report "$W/report-method.md" "Report: June 2026 (method-applied)" \
              --input "$DS" --link cites:"$SY" --link applies:"$SK_METHOD" \
              --link part-of:"$CL_METHOD" --license CC-BY-4.0)

python3 - "$W/tk2.json" "$ADDR" << 'PY'
import json, sys
out, addr = sys.argv[1:3]
json.dump({
    "objective": "apply the weather-station comparison method to a station not yet covered",
    "priority": 2,
    "expires": "2099-01-01T00:00:00Z",
    "verification": {"tier": "T2"},
    "execution": {"brief": "follow the method; ship a short report"},
    "beneficiary": {"agent": "demo-hub", "addr": addr},
    "max_claims": 1,
}, open(out, "w"), indent=2, sort_keys=True)
PY
TK_METHOD=$(c publish task "$W/tk2.json" "Apply method: new station" --method "$SK_METHOD")

# ---------------------------------------------------------------------------------
# 10. Superseded collection pair (disambiguation example).
# ---------------------------------------------------------------------------------
cat > "$W/cl-old.json" << OLDJSON
{"scope": "Weather station demo (early draft)",
 "maintainers": [{"agent": "demo-hub", "addr": "$ADDR"}],
 "members": [{"id": "$DS", "role": "primary-dataset"}]}
OLDJSON
CL_OLD=$(c publish collection "$W/cl-old.json" "Weather Station Demo (draft)")
cat > "$W/cl-new.json" << NEWJSON
{"scope": "Weather station demo (early draft, superseded)",
 "maintainers": [{"agent": "demo-hub", "addr": "$ADDR"}],
 "members": [{"id": "$DS", "role": "primary-dataset"}, {"id": "$WF", "role": "workflow"}],
 "supersedes": ["$CL_OLD"]}
NEWJSON
# The lineage is declared in the spec; publish derives the manifest's supersedes link.
CL_NEW=$(c publish collection "$W/cl-new.json" "Weather Station Demo (final draft)")

echo "$ROOT"

# ---------------------------------------------------------------------------------
# Machine-readable id table for anything that consumes this script's output (tests,
# doc regeneration). Human-readable form is `commons list` against $ROOT.
# ---------------------------------------------------------------------------------
python3 - "$TARGET/ids.json" \
  "$DS" "$WF" "$SY" "$WK" "$BB" "$RP" "$SK_PROFILE" "$CL" "$TK" \
  "$SK_METHOD" "$CL_METHOD" "$RP_METHOD" "$TK_METHOD" "$CL_OLD" "$CL_NEW" \
  "$CMP_EPS" "$CMP_SET" << 'PY'
import json, sys
(out, ds, wf, sy, wk, bb, rp, sk_profile, cl, tk,
 sk_method, cl_method, rp_method, tk_method, cl_old, cl_new,
 cmp_eps, cmp_set) = sys.argv[1:19]
json.dump({
    "ds": ds, "wf": wf, "sy": sy, "wk": wk, "bb": bb, "rp": rp,
    "sk_profile": sk_profile, "cl": cl, "tk": tk,
    "sk_method": sk_method, "cl_method": cl_method, "rp_method": rp_method,
    "tk_method": tk_method, "cl_old": cl_old, "cl_new": cl_new,
    "cmp_eps": cmp_eps, "cmp_set": cmp_set,
}, open(out, "w"), indent=2, sort_keys=True)
PY
