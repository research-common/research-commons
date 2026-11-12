package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// TestRevocationGapThroughPull: C-core-143 through the commands. Key K controls a resource and publishes
// genesis, edition E1, a revoke_key (key_compromise, last_good E1), then an edition E2 and an observed. A
// reader pulls everything except the revocation. Before: E2 and the observation are `detached`, attributed to K
// and counting toward nothing; the resource's current edition is E1 and E2 is shown and not evaluated; nothing
// was refused. Then the revocation arrives by a second pull: E2 is evaluated under it (unauthorized, after
// revoke_key), the observation does not count, the resource view names the revocation, and nothing the reader
// decided before the gap filled (E1, the genesis) is rewritten. Variant: the revocation never arrives; the
// state stays detached through a repeated pull, with no refusal.
func TestRevocationGapThroughPull(t *testing.T) {
	conformance.Covers(t, "C-core-143")
	src := newWorld(t)
	src.blob("X", []byte("X"))
	g := src.genesisOf("G", "K", 0, "K")
	e1stmt, e1 := src.approve("E1", "K", editionBody(g, []string{g}, []string{"X"}))
	rev := src.sign("REV", "K", "revoke_key", obj("reason", "key_compromise", "last_good", e1stmt))
	e2stmt, e2 := src.approve("E2", "K", editionBody(g, []string{e1}, []string{"X", "X2"}))
	ref := obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("a1", 32), "depth", 3)
	ob := src.sign("O", "K", "observed", obj("content", canon.Value(content("X")), "class", "exact-bytes", "referent", canon.Value(ref),
		"capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"))))

	pkg := t.TempDir()
	copyData(t, src.root, pkg)
	revPath := filepath.Join(pkg, stmtPath(src.signer("K"), rev))
	revBytes := mustRead(t, revPath)
	os.Remove(revPath)

	dst := newWorld(t)
	for i := 0; i < 2; i++ { // the second pull is the variant: the gap is still open
		r := dst.run("pull", pkg, "--json")
		if r.code != 0 || !strings.Contains(r.stdout, `"refused":0`) {
			t.Fatalf("pull %d without the revocation: %d %s", i, r.code, r.stdout)
		}
		if i == 0 {
			// the pull report names the gap on each detached line (the gate's label); show names the state
			rep := jsonOf(t, r)
			for _, id := range []string{e2stmt, ob} {
				row := objectRow(t, rep, stmtPath(src.signer("K"), id))
				if row == nil || !strings.Contains(string(canon.Encode(row)), `"detached"`) || !strings.Contains(string(canon.Encode(row)), "waiting for seq 2") {
					t.Fatalf("pull's row for %s does not name the gap: %s", id[:12], canon.Encode(row))
				}
			}
		}
		for _, id := range []string{e2stmt, ob} {
			s := dst.run("show", id)
			if !strings.Contains(s.stdout, "line: detached") ||
				!strings.Contains(s.stdout, "signer: "+src.signer("K")) || !strings.Contains(s.stdout, "counted: not counted") {
				t.Fatalf("show %s while the revocation is missing:\n%s", id[:12], s.stdout)
			}
		}
		rv := dst.run("show", g, "--json")
		if !strings.Contains(rv.stdout, `"current":"`+e1+`"`) || !strings.Contains(rv.stdout, "detached") {
			t.Fatalf("the resource while the revocation is missing: %s", rv.stdout)
		}
		if strings.Contains(dst.run("show", g).stdout, "revoked controllers") {
			t.Fatal("a revocation in force that was never delivered")
		}
	}

	// the revocation arrives
	os.WriteFile(revPath, revBytes, 0o644)
	if r := dst.run("pull", pkg, "--json"); r.code != 0 || !strings.Contains(r.stdout, `"refused":0`) {
		t.Fatalf("the late revocation: %d %s", r.code, r.stdout)
	}
	s := dst.run("show", e2stmt)
	if !strings.Contains(s.stdout, "line: chained") || !strings.Contains(s.stdout, "counted: not counted") || !strings.Contains(s.stdout, "after revoke_key") {
		t.Fatalf("E2 after the revocation:\n%s", s.stdout)
	}
	o := dst.run("show", ob)
	if !strings.Contains(o.stdout, "counted: not counted") || !strings.Contains(o.stdout, "after revoke_key") {
		t.Fatalf("the observation after the revocation:\n%s", o.stdout)
	}
	rv := dst.run("show", g)
	for _, want := range []string{"current: " + e1, "retired by: " + rev, "state: unauthorized", "reason: after revoke_key"} {
		if !strings.Contains(rv.stdout, want) {
			t.Fatalf("the resource after the revocation lacks %q:\n%s", want, rv.stdout)
		}
	}
	if strings.Contains(rv.stdout, "current: "+e2) {
		t.Fatal("an edition after the revocation became current")
	}
	// what was decided before the gap filled is not rewritten: E1 (before the revocation's last_good) is still
	// counted and chained, still an edition, and is the current one
	e := dst.run("show", e1stmt).stdout
	if !strings.Contains(e, "line: chained") || !strings.Contains(e, "counted: counted") || !strings.Contains(e, "state: edition") {
		t.Fatalf("E1 was rewritten when the gap filled:\n%s", e)
	}
}
