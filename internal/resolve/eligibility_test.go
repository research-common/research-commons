package resolve

import (
	"testing"

	"github.com/research-common/research-commons/internal/wire"
)

func assertEligibility(t *testing.T, r *Resolver, id string, ready, eligible bool) *Placed {
	t.Helper()
	p, ok := r.Statement(id)
	if !ok {
		t.Fatalf("missing statement %s", id)
	}
	if p.EvidenceReady() != ready || p.BareKeyEligible() != eligible || p.Counts() != eligible || p.Evaluable != ready {
		t.Fatalf("%s: evidence=%t eligible=%t counts=%t evaluable=%t; want evidence=%t eligible=%t",
			id, p.EvidenceReady(), p.BareKeyEligible(), p.Counts(), p.Evaluable, ready, eligible)
	}
	return p
}

func TestPlacedEvidenceEligibilityKeyEvents(t *testing.T) {
	for _, by := range []string{"A", "BB"} { // both signature algorithms
		t.Run(by, func(t *testing.T) {
			w := newWorld(t)
			good := w.authored("good", by, "X")
			unsupported := signCritical(w, "unsupported", by, "authored", obj("content", contentOf("X"), "provenance", false))
			unknown := w.sign("unknown", by, "future_kind", obj("content", contentOf("X")))
			revocation := w.sign("revocation", by, "revoke_key", obj("reason", "key_compromise", "last_good", good))
			late := w.authored("late", by, "X")
			for _, order := range [][]int{nil, {4, 3, 2, 1, 0}, {3, 0, 4, 1, 2, 3, 0, 4, 1, 2}} {
				r := w.store(order)
				assertEligibility(t, r, good, true, true)
				for _, id := range []string{unsupported, unknown} {
					p := assertEligibility(t, r, id, false, false)
					if !p.St.Verified || !p.Chained || p.St.Status == wire.Valid || len(p.Doubted) == 0 {
						t.Fatalf("fixture did not reach verified/chained/uninterpreted evidence: %+v", p)
					}
				}
				p := assertEligibility(t, r, revocation, true, false)
				if len(p.After) != 0 || len(p.Doubted) == 0 {
					t.Fatal("hard revocation was not excluded by its own last_good boundary")
				}
				p = assertEligibility(t, r, late, true, false)
				if len(p.After) == 0 {
					t.Fatal("ready but ineligible revocation failed to exclude a descendant")
				}
			}
		})
	}
}

func TestPlacedEvidenceEligibilityDetached(t *testing.T) {
	for _, by := range []string{"A", "BB"} {
		t.Run(by, func(t *testing.T) {
			w := newWorld(t)
			w.authored("first", by, "other")
			w.authored("gap", by, "other")
			id := w.authored("detached", by, "X")
			for _, order := range [][]int{{0, 2}, {2, 0}, {2, 0, 2}} {
				p := assertEligibility(t, w.store(order), id, false, false)
				if !p.St.Verified || p.St.Status != wire.Valid || p.Chained || len(p.After) != 0 || len(p.Doubted) != 0 {
					t.Fatalf("fixture did not isolate the missing-chain boundary: %+v", p)
				}
			}
			assertEligibility(t, w.store(nil), id, true, true)
		})
	}
}

func TestPlacedEvidenceEligibilityUnverified(t *testing.T) {
	for _, by := range []string{"A", "BB"} {
		for _, major := range []bool{false, true} {
			name := by + "/unknown_algorithm"
			if major {
				name = by + "/unknown_major"
			}
			t.Run(name, func(t *testing.T) {
				w := newWorld(t)
				key := w.key(by)
				draft := wire.Draft{Kind: "authored", Body: obj("content", contentOf("X"), "provenance", false)}
				if major {
					draft.RC = "rc/2"
				} else {
					w.keys[by] = unknownAlgorithmKey{key}
				}
				id := signDraft(w, "unverified", by, draft)
				w.keys[by] = key
				vouch := w.authored("vouch", by, "other")
				for _, order := range [][]int{nil, {1, 0}, {1, 0, 1, 0}} {
					r := w.store(order)
					p := assertEligibility(t, r, id, false, false)
					if p.St.Verified || !p.Chained || p.St.Status != wire.Unsupported {
						t.Fatalf("fixture did not reach vouched but unverified placement: %+v", p)
					}
					assertEligibility(t, r, vouch, true, true)
				}
			})
		}
	}
}
