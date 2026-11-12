package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/store"
)

// TestPullSourceProfiles: `pull` honours `series.source_profiles` in the store-root policy as `hub check` honours it
// in a hub's (one loader, one verdict): profiles come from what this store holds before the pull, never from the
// package. A premature freeze judged on the members' asserted states is refused (exit 1); a pin this store does
// not hold stops the pull (exit 2) naming the entry, with nothing committed. Control: the same package with the
// pin removed is could not check for the shipped reason.
func TestPullSourceProfiles(t *testing.T) {
	src, prof, pd := settlementPackage(t)
	pin := profilePin(pd)
	edition := src.ids["E"]

	// the pin, held in the receiving store: the premature edition is refused on the members' asserted states
	dst := newWorld(t)
	dst.blob("profile", prof)
	os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(pin), 0o644)
	r := dst.run("pull", src.root, "--json")
	if r.code != 1 || !strings.Contains(r.stdout, "series.refuse_premature_freeze") || !strings.Contains(r.stdout, "as captured, not re-checked") ||
		!strings.Contains(r.stdout, edition) {
		t.Fatalf("pinned: exit %d\n%s", r.code, r.stdout)
	}

	// the pin, not held here (the package carrying it does not help): exit 2, naming the entry, nothing committed
	dst2 := newWorld(t)
	os.WriteFile(filepath.Join(dst2.root, PolicyFile), []byte(pin), 0o644)
	src.blob("profile", prof)
	before := snapshot(t, dst2.root)
	r = dst2.run("pull", src.root, "--json")
	if r.code != 2 || !strings.Contains(r.stdout, "series.source_profiles[0] "+pd+" is not held at this store") || snapshot(t, dst2.root) != before {
		t.Fatalf("unheld pin: exit %d\n%s", r.code, r.stdout)
	}

	// control: no pin, same package: could not check, for the shipped reason
	dst3 := newWorld(t)
	os.WriteFile(filepath.Join(dst3.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`), 0o644)
	r = dst3.run("pull", src.root, "--json")
	if r.code != 3 || !strings.Contains(r.stdout, "ships no finality re-check") {
		t.Fatalf("no pin: exit %d\n%s", r.code, r.stdout)
	}
}

// settlementPackage is a store holding a series of five monthly segments citing the settlement profile, whose
// asserted states put the members' boundary at 2025-04-01, and an edition "E" declaring frozen_before 2025-06-01
// (premature on the members' own word). It returns the store, the profile bytes (not installed) and their digest.
func settlementPackage(t *testing.T) (*world, []byte, string) {
	prof := canon.Encode(obj("profile", resolve.SourceProfileTag, "source", "https://api.example/settlement",
		"dialect", resolve.DialectOrderedLabel, "labels", []string{"SF", "R1", "R2", "RF", "DF"}))
	pd := dig(string(prof))
	src := newWorld(t)
	g := src.sign("G", "C", "genesis", obj("type", "series", "name", "settlements", "controllers", []string{src.signer("C")}, "rule", obj("any_one", true)))
	segs := canon.Array{}
	for i, st := range []string{"DF", "RF", "DF", "R2", "SF"} {
		m := fmt.Sprintf("2025-%02d", i+1)
		ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", m), "response_digest", dig(m),
			"window", obj("from", m+"-01T00:00:00Z", "to", m+"-28T00:00:00Z"))
		id := src.sign("S"+m, "O", "observed", obj("content", content(m), "class", "source", "referent", canon.Value(ref),
			"capture", obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"),
			"finality", obj("rule", "run >= RF", "rule_source", pd, "state_at_capture", obj("run", st))))
		segs = append(segs, obj("statement", id, "role", "segment"))
	}
	src.sign("E", "C", "edition", obj("resource", g, "predecessors", []string{g}, "contents", obj("members", segs, "frozen_before", obj("date", "2025-06-01"))))
	return src, prof, pd
}

// profilePin is a store-root policy pinning the profile pd, with the freeze knob on.
func profilePin(pd string) string {
	return `{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true,"source_profiles":[{"digest":"` + pd + `"}]}}`
}

// TestGCKeepsPinnedProfile: a source profile this store holds only because the store-root policy pins it
// (`series.source_profiles`; no statement, journal record or holds names it) survives `gc --apply` past the grace
// window, the plan naming the pin, and a later `pull` still decides on it (exit 1). Control: with the pin removed
// from the policy the same blob is collected, and once the pin is restored `pull` stops (exit 2, not held). A
// policy file gc cannot use stops it before any work (exit 2, naming the file): never a run with no pins.
func TestGCKeepsPinnedProfile(t *testing.T) {
	conformance.Covers(t, "C-core-147")
	src, prof, pd := settlementPackage(t)
	pin := profilePin(pd)
	dst := newWorld(t)
	dst.blob("profile", prof)
	os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(pin), 0o644)

	r := dst.run("gc", "--apply", "--grace", "0s", "--json")
	if r.code != 0 || !dst.s.HasBlob(store.Digest(pd)) || !strings.Contains(r.stdout, "pinned by "+PolicyFile+" series.source_profiles") ||
		strings.Contains(r.stdout, `"deleted":[{`) {
		t.Fatalf("pinned gc: exit %d\n%s", r.code, r.stdout)
	}
	if r := dst.run("pull", src.root, "--dry-run", "--json"); r.code != 1 || !strings.Contains(r.stdout, "as captured, not re-checked") {
		t.Fatalf("pull after gc: exit %d\n%s", r.code, r.stdout)
	}

	// an unusable policy: gc does not start, nothing is deleted
	bad := `{"policy":"rc-hub-policy/1","series":{"source_profiles":[{"digest":"sha256:nothex"}]}}`
	os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(bad), 0o644)
	before := snapshot(t, dst.root)
	if r := dst.run("gc", "--apply", "--grace", "0s", "--json"); r.code != 2 || !strings.Contains(r.stdout, PolicyFile) || snapshot(t, dst.root) != before {
		t.Fatalf("unusable policy: exit %d\n%s", r.code, r.stdout)
	}

	// control: unpinned, the blob is collected, and the restored pin then names a blob this store no longer holds
	os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(`{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true}}`), 0o644)
	if r := dst.run("gc", "--apply", "--grace", "0s", "--json"); r.code != 0 || dst.s.HasBlob(store.Digest(pd)) {
		t.Fatalf("unpinned gc: exit %d\n%s", r.code, r.stdout)
	}
	os.WriteFile(filepath.Join(dst.root, PolicyFile), []byte(pin), 0o644)
	if r := dst.run("pull", src.root, "--dry-run", "--json"); r.code != 2 || !strings.Contains(r.stdout, "is not held at this store") {
		t.Fatalf("pull after unpinned gc: exit %d\n%s", r.code, r.stdout)
	}
}
