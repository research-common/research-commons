package resolve

import (
	"errors"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
)

// TestSoftRevokeRefusesForeignKeyEvent: C-core-127c. A second holder of A forks A's log from A1 and signs a
// rotate_key. The owner, extending its own tip A2, asks for a soft revocation's merge set: refused, naming the
// tip and the rotation, nothing to sign. Why the rule exists is checked too: signing that soft merge anyway lets
// the rotation count and puts the revocation after it. A hard reason with last_good = A2 and no merge cuts the
// rotation; the revocation comes after no other event and A1 still counts. Control: a soft revocation over a
// fork whose other tip is the owner's own authored merges it, and every line of A counts.
func TestSoftRevokeRefusesForeignKeyEvent(t *testing.T) {
	conformance.Covers(t, "C-core-127c")
	build := func() (*world, string, string, string) {
		w := newWorld(t)
		a1 := w.authored("A1", "A", "X", "licence", "CC0-1.0")
		own := w.authored("A2", "A", "Y", "licence", "CC0-1.0")
		w.forkAt("A", a1, 1)
		rot := w.sign("ROT", "A", "rotate_key", obj("successor", w.signer("T")))
		w.forkAt("A", own, 2)
		return w, a1, own, rot
	}
	view := func(w *world) keylog.View { return w.store(nil).logs.Log(w.signer("A")).View() }

	// (a) soft: refused, reader policy, naming the tip and the event on it.
	w, a1, own, rot := build()
	merges, r := view(w).SoftRevokeMerges(own)
	if r == nil || merges != nil {
		t.Fatalf("(a) soft merge set over a foreign rotate_key: got %v, %v", merges, r)
	}
	var rr *refusal.Refusal
	if !errors.As(error(r), &rr) || rr.Class != refusal.Policy || rr.Reason != keylog.SoftMergeKeyEvent {
		t.Fatalf("(a) refusal %v", r)
	}
	for _, want := range []string{"tip " + rot, "rotate_key " + keylog.Short(rot), "hard reason and last_good"} {
		if !strings.Contains(rr.Detail, want) {
			t.Fatalf("(a) refusal does not say %q: %s", want, rr.Detail)
		}
	}
	fk := view(w).ForeignKeyEvents(own)
	if len(fk) != 1 || fk[0].Tip != rot || len(fk[0].Events) != 1 || fk[0].Events[0].Kind != "rotate_key" {
		t.Fatalf("(a) foreign key events %+v", fk)
	}

	// Why: the refused soft merge, signed anyway, voids the revocation and lets the rotation count.
	rev := w.signMerge("REV", "A", "revoke_key", obj("reason", "superseded"), rot)
	res := w.store(nil)
	pr, _ := res.Statement(rot)
	pv, _ := res.Statement(rev)
	if !pr.Counts() || len(pv.After) == 0 {
		t.Fatalf("(a) the refused merge no longer harms: rotation counts=%v, revocation after=%v", pr.Counts(), pv.After)
	}

	// (b) hard reason with last_good = A2, merging nothing: the rotation is cut, the revocation is in force and
	// after no key event, A1 counts.
	w, a1, own, rot = build()
	rev = w.sign("REV", "A", "revoke_key", obj("reason", "key_compromise", "last_good", own))
	res = w.store(nil)
	pr, _ = res.Statement(rot)
	pv, _ = res.Statement(rev)
	pa, _ := res.Statement(a1)
	if pr.Counts() || len(pv.After) != 0 || !pa.Counts() {
		t.Fatalf("(b) rotation counts=%v doubted=%v; revocation after=%v; A1 counts=%v", pr.Counts(), pr.Doubted, pv.After, pa.Counts())
	}
	inForce := false
	for _, ev := range res.keys[w.signer("A")].Events {
		inForce = inForce || (ev.St.ID == rev && ev.InForce && ev.Hard())
	}
	if !inForce {
		t.Fatal("(b) the hard revocation is not in force")
	}

	// (c) control: the other tip is the owner's own authored, so the soft merge set names it and nothing is cut.
	w = newWorld(t)
	a1 = w.authored("A1", "A", "X", "licence", "CC0-1.0")
	own = w.authored("A2", "A", "Y", "licence", "CC0-1.0")
	w.forkAt("A", a1, 1)
	sib := w.authored("B2", "A", "Z", "licence", "CC0-1.0")
	w.forkAt("A", own, 2)
	merges, r = view(w).SoftRevokeMerges(own)
	if r != nil || len(merges) != 1 || merges[0] != sib {
		t.Fatalf("(c) soft merge set over the owner's own tips: %v, %v", merges, r)
	}
	rev = w.signMerge("REV", "A", "revoke_key", obj("reason", "superseded"), merges...)
	res = w.store(nil)
	if v := res.logs.Log(w.signer("A")).View(); len(v.Tips) != 1 || v.Tips[0] != rev || v.Forks[0].ClearedBy != rev {
		t.Fatalf("(c) fork not cleared by the revocation:\n%s", v.Render())
	}
	for _, id := range []string{a1, own, sib, rev} {
		if p, _ := res.Statement(id); !p.Counts() {
			t.Fatalf("(c) %s counts toward nothing: after=%v doubted=%v", keylog.Short(id), p.After, p.Doubted)
		}
	}

	// A tip at or above the new line's seq cannot be named in merges: refused, naming it. Extending A1 (seq 0)
	// leaves the tips A2 and B2 at seq 1, not below the new line's seq 1.
	w = newWorld(t)
	a1 = w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.authored("A2", "A", "Y", "licence", "CC0-1.0")
	w.forkAt("A", a1, 1)
	w.authored("B2", "A", "Z", "licence", "CC0-1.0")
	if _, r := view(w).SoftRevokeMerges(a1); r == nil || r.Reason != keylog.TipAboveNext {
		t.Fatalf("merge set below a higher tip: %v", r)
	}
}
