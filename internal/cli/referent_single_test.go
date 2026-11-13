package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
)

// singleWorld: a store pinning an ordered-label source profile (SF < R1 RF) and a source-class observation S1 of
// bytes "x" at SF from endpoint A, rule `run >= RF`.
func singleWorld(t *testing.T) (w *world, s1 string, pd string) {
	t.Helper()
	prof := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "https://api.example/settlement",
		"dialect", resolve.DialectOrderedLabel, "labels", []string{"SF", "R1", "RF"}))
	pd = dig(string(prof))
	w = newWorld(t)
	w.blob("p", prof)
	if err := os.WriteFile(filepath.Join(w.root, PolicyFile),
		[]byte(`{"policy":"rc-hub-policy/1","series":{"source_profiles":[{"digest":"`+pd+`"}]}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s1 = w.capture("S1", "O1", "https://api.example/settlement", "SF", "2026-01-02T00:00:00Z", pd)
	return w, s1, pd
}

func (w *world) capture(name, n, endpoint, state, at, pd string) string {
	ref := obj("endpoint", endpoint, "parameters", obj("period", "2026-01"), "response_digest", dig("x"))
	return w.sign(name, n, "observed", obj("content", content("x"), "class", "source", "referent", canon.Value(ref),
		"capture", obj("at", at, "evidence", "self-asserted"),
		"finality", obj("rule", "run >= RF", "rule_source", pd, "state_at_capture", obj("run", state))))
}

// TestSingleRequestReferentCommands: C-core-31, the single-request half through the commands. `explain` and `show`
// print each pinned field of a source referent (endpoint, parameters, response digest) as the observer's statement.
// A final re-capture of identical bytes that pins a different endpoint is never counted as agreement; control: the
// same re-capture pinning the same endpoint corroborates, so the endpoint is what stopped the first. Phenomenon
// referents: instrument, location and time shown; another instrument is not agreement.
func TestSingleRequestReferentCommands(t *testing.T) {
	conformance.Covers(t, "C-core-31")
	w, s1, pd := singleWorld(t)
	for _, cmd := range []string{"explain", "show"} {
		r := w.run(cmd, s1)
		for _, f := range []string{"referent.endpoint", "referent.parameters", "referent.response_digest", "observer's statement"} {
			if !strings.Contains(r.stdout, f) {
				t.Fatalf("%s: want %q:\n%s", cmd, f, r.stdout)
			}
		}
	}
	w.capture("S2", "O2", "https://api.example/other", "RF", "2026-03-01T00:00:00Z", pd)
	r := w.run("explain", s1)
	if strings.Contains(r.stdout, "corroborated 1") {
		t.Fatalf("a different endpoint counted as agreement:\n%s", r.stdout)
	}
	w.capture("S3", "O3", "https://api.example/settlement", "RF", "2026-03-02T00:00:00Z", pd)
	r = w.run("explain", s1)
	if !strings.Contains(r.stdout, "corroborated 1") {
		t.Fatalf("control: the same endpoint at RF does not corroborate:\n%s", r.stdout)
	}
	// phenomenon class: instrument identity, location and time shown as the observer's statement; a second
	// observation from another instrument is not agreement with the first
	phen := func(name, n, instrument string) string {
		return w.sign(name, n, "observed", obj("content", content("t"), "class", "phenomenon",
			"referent", obj("instrument", instrument, "location", "geo:39.74,-104.99;u=10", "at", "2026-07-01T12:00:00Z"),
			"capture", obj("at", "2026-07-01T12:00:05Z", "evidence", "self-asserted")))
	}
	p1 := phen("P1", "O4", "urn:station:DEN-1")
	phen("P2", "O5", "urn:station:DEN-2")
	r = w.run("explain", p1)
	for _, f := range []string{`referent.instrument: "urn:station:DEN-1" (observer's statement)`, "referent.location", "referent.at"} {
		if !strings.Contains(r.stdout, f) {
			t.Fatalf("phenomenon: want %q:\n%s", f, r.stdout)
		}
	}
	if strings.Contains(r.stdout, "corroborated 1") {
		t.Fatalf("another instrument counted as agreement:\n%s", r.stdout)
	}
}
