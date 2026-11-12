package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/resolve"
)

// TestPullSourceProfiles: `pull` honours `series.source_profiles` in the store-root policy as `hub check` honours it
// in a hub's (one loader, one verdict): profiles come from what this store holds before the pull, never from the
// package. A premature freeze judged on the members' asserted states is refused (exit 1); a pin this store does
// not hold stops the pull (exit 2) naming the entry, with nothing committed. Control: the same package with the
// pin removed is could not check for the shipped reason.
func TestPullSourceProfiles(t *testing.T) {
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

	pin := `{"policy":"rc-hub-policy/1","series":{"refuse_premature_freeze":true,"source_profiles":[{"digest":"` + pd + `"}]}}`
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
