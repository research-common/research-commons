package resolve

import (
	"slices"
	"testing"

	"github.com/research-common/research-commons/internal/wire"
)

// Understanding an exact body through one signature must not promote any other
// signature of that body. Placement and key-event exclusions remain per approval.
func TestUnsupportedEditionMixedDetachedApproval(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "owner", 0, "A", "BB")
	body := w.editionBody(g, []string{g}, []string{"X"})
	unsupported := signCritical(w, "unsupported", "A", "edition", body)
	w.authored("gap", "BB", "other")
	valid := w.sign("valid", "BB", "edition", body)
	for _, order := range [][]int{{0, 1, 3}, {3, 1, 0}, {3, 0, 1, 3, 1, 0}} {
		r := w.store(order)
		requireRetained(t, r, unsupported, wire.Unsupported, true, true)
		requireRetained(t, r, valid, wire.Valid, true, false)
		res, _ := r.Resource(g)
		e := editionOf(t, res, valid)
		if e.ID != w.ed(unsupported) || e.State != Unauthorized || res.Current != g || len(e.Members) != 1 || !slices.Equal(e.Predecessors, []string{g}) {
			t.Fatalf("mixed detached approval changed body or authority: %s", res.Render())
		}
		for _, a := range e.Approvals {
			why := "unsupported"
			if a.Statement == valid {
				why = "detached"
			}
			if a.Counted || a.Doubted || a.Why != why {
				t.Fatalf("exact-body association promoted an approval: %+v", a)
			}
		}
	}
	// Filling the gap authorizes through the valid signer alone, not through the
	// previously chained but unsupported signature.
	everyOrder(t, w, g, func(res *Resource) {
		wantCurrent(t, res, valid)
		wantState(t, res, valid, Authorized, "1 approval(s)")
		for _, a := range editionOf(t, res, valid).Approvals {
			if a.Counted != (a.Statement == valid) || a.Doubted {
				t.Fatalf("gap closure promoted an unsupported co-approval: %+v", a)
			}
		}
	})
}

func TestUnsupportedEditionMixedKeyEvent(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "owner", 2, "A", "BB")
	body := w.editionBody(g, []string{g}, []string{"X"})
	unsupported := signCritical(w, "unsupported", "A", "edition", body)
	valid := w.sign("valid", "BB", "edition", body)
	// A real hard revocation doubts the unsupported signature in the key log.
	// That does not make it a usable doubted controller approval: it never passed
	// the earlier interpretation boundary, even though BB checked the same body.
	w.sign("revocation", "A", "revoke_key", obj("reason", "key_compromise"))
	for _, order := range [][]int{{0, 1, 2, 3}, {3, 2, 1, 0}, {2, 3, 1, 0, 2, 1, 3}} {
		r := w.store(order)
		p := requireRetained(t, r, unsupported, wire.Unsupported, true, true)
		if len(p.Doubted) == 0 {
			t.Fatal("fixture did not reach the key-event doubt boundary")
		}
		res, _ := r.Resource(g)
		wantState(t, res, valid, Pending, "1 of 2 approvals")
		wantCurrent(t, res, g)
		if len(res.Contested) != 0 {
			t.Fatal("unsupported signature supplied contested authority")
		}
		for _, a := range editionOf(t, res, valid).Approvals {
			if a.Counted != (a.Statement == valid) || a.Doubted || (a.Statement == unsupported && a.Why != "unsupported") {
				t.Fatalf("body understanding laundered a key-event exclusion: %+v", a)
			}
		}
	}
}
