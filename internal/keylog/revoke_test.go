package keylog

import (
	"slices"
	"testing"
)

// TestSoftRevokeMergeSet: C-core-127c (covered with its counting outcomes by
// resolve.TestSoftRevokeRefusesForeignKeyEvent). The writer's soft-revocation merge set (storage note §4.2) at the log layer, in every
// delivery order. The other branch carries a revoke_key below its tip (not at it): the tip is refused, naming it
// and the event. A key event inside the extended line's own history (below the fork point, or on the owner's own
// branch) is never foreign. Control: two plain tips are both merged, sorted.
func TestSoftRevokeMergeSet(t *testing.T) {
	a, z := key("A"), key("Z")
	base := chain(a, 2)
	// Other branch: a revoke_key (hard, last_good = its prev) at seq 2, then a plain line on it at seq 3.
	evt := revoke(a, 2, base[1].id, "key_compromise")
	top := mk(a, 3, evt.id, 0xb3, "")
	// Owner's branch: a plain line at seq 2 and a rotate_key at seq 3 (the owner's own, inside its history).
	own := mk(a, 2, base[1].id, 0xa2, "")
	ownRot := rotate(a, 3, own.id, z)
	ownTop := mk(a, 4, ownRot.id, 0xa4, "")
	all := []line{base[0], base[1], evt, top, own, ownRot, ownTop}
	for _, order := range [][]int{{0, 1, 2, 3, 4, 5, 6}, {6, 5, 4, 3, 2, 1, 0}, {3, 6, 0, 2, 5, 1, 4}} {
		s := NewStore()
		for _, i := range order {
			deliver(t, s, a, all[i])
		}
		v := s.Log(a.Signer()).View()
		m, r := v.SoftRevokeMerges(ownTop.id)
		if r == nil || r.Reason != SoftMergeKeyEvent || m != nil {
			t.Fatalf("order %v: got %v, %v", order, m, r)
		}
		fk := v.ForeignKeyEvents(ownTop.id)
		if len(fk) != 1 || fk[0].Tip != top.id || len(fk[0].Events) != 1 || fk[0].Events[0].St.ID != evt.id {
			t.Fatalf("order %v: foreign %+v", order, fk)
		}
		// From the other side, the owner's rotation is the foreign event and the revoke_key is its own.
		if fk := v.ForeignKeyEvents(top.id); len(fk) != 1 || fk[0].Tip != ownTop.id || fk[0].Events[0].St.ID != ownRot.id {
			t.Fatalf("order %v: foreign from the other side %+v", order, fk)
		}
	}

	// Control: plain tips only (one of them on a branch whose base holds the owner's earlier rotation).
	b := key("B")
	bb := chain(b, 1)
	rot := rotate(b, 1, bb[0].id, z)
	x := mk(b, 2, rot.id, 0x12, "")
	y := mk(b, 2, rot.id, 0x22, "")
	w := mk(b, 2, rot.id, 0x32, "")
	s := NewStore()
	deliver(t, s, b, bb[0], rot, x, y, w)
	v := s.Log(b.Signer()).View()
	m, r := v.SoftRevokeMerges(x.id)
	want := []string{y.id, w.id}
	slices.Sort(want)
	if r != nil || !slices.Equal(m, want) {
		t.Fatalf("control: got %v, %v; want %v", m, r, want)
	}
	if _, r := v.SoftRevokeMerges(evt.id); r == nil {
		t.Fatal("a prev that is not a chained line was accepted")
	}
}
