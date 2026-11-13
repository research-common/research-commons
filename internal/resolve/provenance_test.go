package resolve

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/refusal"
)

// chainWorld: a derivation chain C0 <- C1 <- ... <- Cn under a bytes workflow, each step derived and re-derived
// by a second key (T0 all the way), C0 resting on a leaf. n steps above the leaf.
func chainWorld(t *testing.T, n int) *world {
	w := newWorld(t)
	w.workflow("WA", "W", "bytes", "")
	w.authored("L", "S", "leaf")
	prev := "leaf"
	for i := 0; i <= n; i++ {
		x := fmt.Sprintf("c%d", i)
		w.authored("A"+x, "A", x, "prov", []string{"W", prev})
		w.authored("B"+x, "BB", x, "prov", []string{"W", prev})
		prev = x
	}
	return w
}

// TestProvenanceDepthBound: the resolver's half of C-core-131. A derivation chain deeper than the reader's bound:
// the grade is not followed past it; the artifact is incomplete with an operational refusal naming the limit,
// its value and the scope it cut; verify exits 3 with `provenance: unchecked`; nothing past the bound reads as
// checked (the grade is `unchecked`, never T0); within the bound the same chain is T0 and complete.
func TestProvenanceDepthBound(t *testing.T) {
	w := chainWorld(t, 6) // c6 rests on c5 ... c0 rests on the leaf: 7 derived blobs and the leaf: 8 blobs on the path, so the bound 8 is the last that follows all of it
	top := dig("c6")
	for _, c := range []struct {
		depth    int
		complete bool
	}{{9, true}, {8, true}, {7, false}, {3, false}, {1, false}} {
		r := w.store(nil, WithProvenanceDepth(c.depth))
		a := r.Artifact(top)
		code, why := r.Verify(top)
		if c.complete {
			if len(a.Incomplete) != 0 || a.Grade.Tier != "T0" || code != 0 {
				t.Fatalf("bound %d: complete chain read %s, incomplete %v, verify %d %v\n%s", c.depth, a.Grade, a.Incomplete, code, why, a.Render())
			}
			continue
		}
		if len(a.Incomplete) == 0 {
			t.Fatalf("bound %d cut nothing: grade %s\n%s", c.depth, a.Grade, a.Render())
		}
		f := a.Incomplete[0]
		if f.Class != refusal.Operational || f.Reason != refusal.DepthLimit ||
			!strings.Contains(f.Detail, fmt.Sprintf("provenance_depth=%d", c.depth)) || !strings.Contains(f.Detail, "scope: ") || !strings.Contains(f.Detail, "incomplete") {
			t.Fatalf("bound %d: refusal %v", c.depth, f)
		}
		if a.Grade.Tier != "" || a.Grade.Why != UncheckedToken {
			t.Fatalf("bound %d: a result resting on a cut read %s, not unchecked", c.depth, a.Grade)
		}
		if code != 3 || !strings.Contains(strings.Join(why, ";"), "provenance: unchecked") {
			t.Fatalf("bound %d: verify %d %v, want 3 with provenance: unchecked", c.depth, code, why)
		}
		out := a.Render()
		if !strings.Contains(out, "incomplete: operational: depth limit (provenance_depth=") {
			t.Fatalf("bound %d: the render does not say incomplete:\n%s", c.depth, out)
		}
		// the artifact one level up the chain, wholly inside the bound, is unaffected by the bound of the other
		if c.depth >= 2 {
			low := w.store(nil, WithProvenanceDepth(c.depth)).Artifact(dig("c0"))
			if len(low.Incomplete) != 0 || low.Grade.Tier != "T0" {
				t.Fatalf("bound %d: c0 (one step above the leaf) read %s, incomplete %v", c.depth, low.Grade, low.Incomplete)
			}
		}
	}
	// the default bound is documented and well above any real chain
	if DefaultProvenanceDepth < 32 {
		t.Fatalf("default bound %d", DefaultProvenanceDepth)
	}
}
