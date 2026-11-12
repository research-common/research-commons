package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/resolve"
	"github.com/research-common/research-commons/internal/wire"
)

// TestSiblingOfRevocationThroughPull: C-core-143a through the commands. K controls R (any one); its log is
// genesis, E1 (seq 1). A second holder of K's key signs seq 2′ (prev = seq 1), an edition E2′ naming E1; the owner
// signs seq 2, a revoke_key with prev = seq 1, for (a) key_compromise and (b) superseded. The reader pulls the
// package with the lines in every order (one pull each, and one pull per line). In both: E2′ is shown, attributed
// to K, and counts toward nothing; R's current edition is E1; the resource view names the revocation as the
// reason. Every order gives the same `show` of R and of E2′.
func TestSiblingOfRevocationThroughPull(t *testing.T) {
	conformance.Covers(t, "C-core-143a")
	for _, reason := range []string{"key_compromise", "superseded"} {
		t.Run(reason, func(t *testing.T) {
			src := newWorld(t)
			g := src.genesisOf("G", "K", 0, "K")
			e1stmt, e1 := src.approve("E1", "K", editionBody(g, []string{g}, []string{"a"}))
			prev := src.head["K"]
			k := src.key("K")
			rb := obj("reason", reason)
			if reason != "superseded" {
				rb = obj("reason", reason, "last_good", e1stmt)
			}
			revLine, rev := wire.Sign(wire.Draft{Kind: "revoke_key", Seq: 2, Prev: prev, TS: "2026-10-16T03:00:00Z", Body: rb}, k)
			sibBody := editionBody(g, []string{e1}, []string{"a", "b"})
			sibLine, sib := wire.Sign(wire.Draft{Kind: "edition", Seq: 2, Prev: prev, TS: "2026-10-16T03:00:01Z", Body: sibBody}, k)
			if _, err := src.s.Commit("publish", [][]byte{revLine}, nil); err != nil {
				t.Fatal(err)
			}
			if _, err := src.s.Commit("publish", [][]byte{sibLine}, nil); err != nil {
				t.Fatal(err)
			}
			var first map[string]string
			for i, order := range [][]string{{"rev", "sib"}, {"sib", "rev"}, {"both"}} {
				pkg := t.TempDir()
				copyData(t, src.root, pkg)
				paths := map[string]string{"rev": filepath.Join(pkg, stmtPath(src.signer("K"), rev)), "sib": filepath.Join(pkg, stmtPath(src.signer("K"), sib))}
				held := map[string][]byte{"rev": mustRead(t, paths["rev"]), "sib": mustRead(t, paths["sib"])}
				dst := newWorld(t)
				if order[0] == "both" {
					if r := dst.run("pull", pkg, "--json"); r.code != 0 {
						t.Fatalf("pull: %d %s", r.code, r.stdout)
					}
				} else {
					for _, name := range []string{"rev", "sib"} {
						os.Remove(paths[name])
					}
					for _, name := range order {
						os.WriteFile(paths[name], held[name], 0o644)
						if r := dst.run("pull", pkg, "--json"); r.code != 0 {
							t.Fatalf("pull %s: %d %s", name, r.code, r.stdout)
						}
					}
				}
				r := dst.run("show", g)
				s := dst.run("show", sib)
				for _, want := range []string{"current: " + e1, "state: contested", "(sibling rule)", "revoke_key " + rev[:12], "retired by: " + rev} {
					if !strings.Contains(r.stdout, want) {
						t.Fatalf("order %v: the resource lacks %q:\n%s", order, want, r.stdout)
					}
				}
				if strings.Contains(r.stdout, "current: "+resolve.EditionID(sibBody)) {
					t.Fatalf("order %v: the sibling's edition became current", order)
				}
				if !strings.Contains(s.stdout, "signer: "+src.signer("K")) || !strings.Contains(s.stdout, "counted: not counted") || !strings.Contains(s.stdout, "revoke_key "+rev[:12]) {
					t.Fatalf("order %v: the sibling edition:\n%s", order, s.stdout)
				}
				if v := dst.run("explain", sib).stdout; !strings.Contains(v, "revoke_key "+rev[:12]) {
					t.Fatalf("order %v: explain does not name the revocation:\n%s", order, v)
				}
				got := map[string]string{"resource": r.stdout, "sibling": s.stdout, "explain": dst.run("explain", sib, "--json").stdout}
				if i == 0 {
					first = got
				} else {
					for k, v := range got {
						if v != first[k] {
							t.Fatalf("order %v: %s differs from the first order:\n%s\nvs\n%s", order, k, v, first[k])
						}
					}
				}
			}
		})
	}
}
