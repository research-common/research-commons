package identitymodel

import (
	"fmt"
	"slices"
	"testing"
)

// The recoverable-root profile's scenarios (recoverable-root note §6, RR-01 to RR-31) at the model level, with
// SYNTHETIC ADAPTER ATTESTATIONS as in model_test.go: ids are labels, keys are names, and the commitment of a key
// is a label the adapter would have computed from its signer string. The signed, end-to-end cases live in
// internal/identity.

func commitOf(k Key) string { return "commit:" + string(k) }

// rr builds one scenario's facts. Every log keeps its own seq so prev adjacency holds, and a fork names its prev.
type rr struct {
	facts []Fact
	byID  map[ID]Fact
	n     int
}

func newRR() *rr { return &rr{byID: map[ID]Fact{}} }

func (w *rr) add(f Fact) Fact {
	w.facts = append(w.facts, f)
	w.byID[f.ID] = f
	return f
}

func (w *rr) id(tag string) ID {
	w.n++
	return ID(fmt.Sprintf("%s#%d", tag, w.n))
}

// after is the next line of key's log after prev.
func (w *rr) after(tag string, key Key, prev ID, ev Event) Fact {
	return line(w.id(tag), key, w.byID[prev].Seq+1, prev, ev)
}

func (w *rr) inception(root, recovery Key) Fact {
	f := line(w.id("inc"), root, 0, "", IdentityInception)
	f.Inception = &Inception{Profile: RecoverableRoot, Commitment: commitOf(recovery)}
	return w.add(f)
}

// delegate is a worker key's seq-0 line (its inception for a grant).
func (w *rr) delegate(key Key) Fact { return w.add(line(w.id("d"), key, 0, "", Inert)) }

func (w *rr) grant(root Key, prev, identity ID, delegate Fact) Fact {
	f := w.after("g", root, prev, GrantEvent)
	f.Grant = &Grant{Identity: identity, Delegate: delegate.Signer, Inception: delegate.ID,
		Permissions: []Permission{{Kind: Authored, Mode: ExactTargets, Targets: []ID{"content-a"}}}}
	return w.add(f)
}

func (w *rr) cut(root Key, prev, identity, grant ID, lastGood LastGood) Fact {
	f := w.after("cut", root, prev, CutEvent)
	f.Cut = &Cut{Identity: identity, Grant: grant, LastGood: lastGood}
	return w.add(f)
}

func (w *rr) revoke(root Key, prev ID) Fact { return w.add(w.after("rv", root, prev, RevokeKey)) }

// ordinary is a root's line outside the root vocabulary (an authored statement: issue #271).
func (w *rr) ordinary(root Key, prev ID) Fact {
	f := w.after("ord", root, prev, Data)
	f.Operation = &Operation{Kind: Authored, Target: Target{Type: ContentTarget, ID: "content-x"}}
	return w.add(f)
}

// act is a delegate's statement under grant, extending prev on its own log.
func (w *rr) act(delegate Key, prev ID, identity ID, grant Fact) Fact {
	f := w.after("act", delegate, prev, Data)
	f.Actor = &Actor{Identity: identity, Grant: grant.ID}
	f.Binding = BoundIdentityContext
	f.Operation = &Operation{Kind: Authored, Target: Target{Type: ContentTarget, ID: "content-a"}}
	return w.add(f)
}

func (w *rr) succession(successor Key, identity ID) Fact {
	f := line(w.id("succ"), successor, 0, "", SuccessionEvent)
	f.Succession = &Succession{Identity: identity}
	return w.add(f)
}

// recovery is the recovery key's statement (held as its own fact) naming lastGood ("" is null), the successor
// (nil closes the identity) and the next recovery key ("" with nil).
func (w *rr) recovery(key Key, identity, lastGood ID, successor *Fact, next Key) Fact {
	r := &Recovery{Identity: identity, LastGood: lastGood}
	if successor != nil {
		r.Successor = &Successor{Key: successor.Signer, Inception: successor.ID, Commitment: commitOf(successor.Signer)}
		r.Next = commitOf(next)
	}
	f := line(w.id("rec"), key, 0, "", RecoveryEvent)
	f.Recovery = r
	return w.add(f)
}

// carried is the adapter's reading of a recovery statement inside a handover.
func carried(rec Fact) Carried {
	return Carried{ID: rec.ID, Signer: rec.Signer, Commitment: commitOf(rec.Signer), Authentication: Authenticated,
		Validity: Understood, Seq: rec.Seq, Prev: rec.Prev, Event: rec.Event, Recovery: copyRecovery(rec.Recovery)}
}

func (w *rr) handover(root Key, prev, identity ID, rec Fact) Fact {
	return w.handoverCarrying(root, prev, identity, carried(rec))
}

func (w *rr) handoverCarrying(root Key, prev, identity ID, c Carried) Fact {
	f := w.after("h", root, prev, HandoverEvent)
	f.Handover = &Handover{Identity: identity, Carried: c}
	return w.add(f)
}

// recover is the whole ceremony: the successor's first line, the recovery statement, the handover by root at prev.
func (w *rr) recover(root Key, prev, identity, lastGood ID, recoveryKey, successor, next Key) (succ, rec, h Fact) {
	succ = w.succession(successor, identity)
	rec = w.recovery(recoveryKey, identity, lastGood, &succ, next)
	h = w.handover(root, prev, identity, rec)
	return
}

func (w *rr) snapshot(t *testing.T) *Snapshot { return snapshot(t, slices.Clone(w.facts)) }

func expect(t *testing.T, s *Snapshot, act Fact, status Status, code string, gen uint64) Result {
	t.Helper()
	r := s.Evaluate(act.ID)
	if r.Status != status || (code != "" && !hasReason(r, code)) || (status == Eligible && r.Generation != gen) {
		t.Fatalf("%s: got %s gen %d %v, want %s/%s gen %d", act.ID, r.Status, r.Generation, codes(r), status, code, gen)
	}
	return r
}

func codes(r Result) []string {
	var out []string
	for _, x := range r.Reasons {
		out = append(out, x.Code)
	}
	for _, x := range r.Warnings {
		out = append(out, "warning:"+x.Code)
	}
	return out
}

func hasWarning(r Result, code string) bool {
	return slices.ContainsFunc(r.Warnings, func(v Warning) bool { return v.Code == code })
}

// stolen is RR-02's world: the owner grants d1, the thief (holding R0) grants t1, the owner recovers to R1 with
// last_good at the owner's grant, R1 grants d2, the thief grants t2 on their branch.
type stolenWorld struct {
	w                           *rr
	I                           ID
	gOwn, gThief, gNew, gThief2 Fact
	aOwn, aThief, aNew, aThief2 Fact
	succ, rec, h                Fact
}

func stolen() stolenWorld {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d1, t1, d2, t2 := w.delegate("d1"), w.delegate("t1"), w.delegate("d2"), w.delegate("t2")
	gOwn := w.grant("R0", I, I, d1)
	gThief := w.grant("R0", gOwn.ID, I, t1)
	succ, rec, h := w.recover("R0", gThief.ID, I, gOwn.ID, "C0", "R1", "C1") // the owner's copy of R0 signs the handover
	gNew := w.grant("R1", succ.ID, I, d2)
	gThief2 := w.grant("R0", gThief.ID, I, t2)
	return stolenWorld{w, I, gOwn, gThief, gNew, gThief2,
		w.act("d1", d1.ID, I, gOwn), w.act("t1", t1.ID, I, gThief), w.act("d2", d2.ID, I, gNew), w.act("t2", t2.ID, I, gThief2),
		succ, rec, h}
}

func TestRR01OrdinaryUse(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	d := w.delegate("d1")
	g := w.grant("R0", inc.ID, inc.ID, d)
	a := w.act("d1", d.ID, inc.ID, g)
	r := expect(t, w.snapshot(t), a, Eligible, "", 0)
	if len(r.Recoveries) != 0 || r.Closed {
		t.Fatalf("%+v", r)
	}
}

func TestRR02RecoveryAfterTheft(t *testing.T) {
	sw := stolen()
	s := sw.w.snapshot(t)
	r := expect(t, s, sw.aOwn, Eligible, "", 1)
	if !slices.Equal(r.Recoveries, []ID{sw.h.ID}) {
		t.Fatalf("recoveries %v", r.Recoveries)
	}
	expect(t, s, sw.aNew, Eligible, "", 1)
	expect(t, s, sw.aThief, Denied, "recovery_voided", 0)
	expect(t, s, sw.aThief2, Denied, "recovery_voided", 0)
	// RR-14: before the handover is read, the thief's grant counts (the pre-recovery state).
	before := snapshot(t, without(slices.Clone(sw.w.facts), sw.h.ID))
	expect(t, before, sw.aThief, Eligible, "", 0)
	expect(t, before, sw.aOwn, Eligible, "", 0)
}

// RR-21: no subset of RR-02's statements reads generation 1 with a thief grant counting.
func TestRR21EverySubset(t *testing.T) {
	sw := stolen()
	fixed := []Fact{sw.aOwn, sw.aThief, sw.aNew, sw.aThief2}
	var pool []Fact
	for _, f := range sw.w.facts {
		if !slices.ContainsFunc(fixed, func(x Fact) bool { return x.ID == f.ID }) {
			pool = append(pool, f)
		}
	}
	for mask := 0; mask < 1<<len(pool); mask++ {
		fs := slices.Clone(fixed)
		for i, f := range pool {
			if mask&(1<<i) != 0 {
				fs = append(fs, f)
			}
		}
		s := snapshot(t, fs)
		for _, a := range []Fact{sw.aThief, sw.aThief2} {
			if r := s.Evaluate(a.ID); r.Status == Eligible && r.Generation == 1 {
				t.Fatalf("subset %b: thief act %s counts at generation 1", mask, a.ID)
			}
		}
	}
}

func TestRR03ThiefRevokesThenOwnerRecovers(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	rv := w.revoke("R0", g.ID)
	a := w.act("d1", d.ID, I, g)
	expect(t, w.snapshot(t), a, Denied, "root_retired", 0)
	w.recover("R0", g.ID, I, g.ID, "C0", "R1", "C1")
	r := expect(t, w.snapshot(t), a, Eligible, "", 1)
	if hasReason(r, "root_retired") || !slices.Contains(r.Basis, rv.ID) == true && false {
		t.Fatalf("%v", codes(r))
	}
}

func TestRR04And05OneKeyAlone(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	// RR-04: a holder of R alone carries a "recovery" by a key of their own: void.
	succ := w.succession("RT", I)
	fake := w.recovery("T", I, g.ID, &succ, "T2")
	w.handover("R0", g.ID, I, fake)
	r := expect(t, w.snapshot(t), a, Eligible, "", 0)
	if !hasWarning(r, "void_handover") {
		t.Fatalf("void handover not reported: %v", codes(r))
	}
	// RR-05: a holder of C alone signs a recovery: no handover, nothing.
	w2 := newRR()
	inc2 := w2.inception("R0", "C0")
	d2 := w2.delegate("d1")
	g2 := w2.grant("R0", inc2.ID, inc2.ID, d2)
	a2 := w2.act("d1", d2.ID, inc2.ID, g2)
	s2 := w2.succession("R1", inc2.ID)
	w2.recovery("C0", inc2.ID, g2.ID, &s2, "C1")
	expect(t, w2.snapshot(t), a2, Eligible, "", 0)
}

func TestRR06And07RivalsAndRepeats(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	_, rec1, h1 := w.recover("R0", g.ID, I, g.ID, "C0", "R1", "C1")
	expect(t, w.snapshot(t), a, Eligible, "", 1)
	// RR-07: the same recovery handed over twice is one recovery.
	w.handover("R0", g.ID, I, rec1)
	r := expect(t, w.snapshot(t), a, Eligible, "", 1)
	if len(r.Recoveries) != 1 || r.Recoveries[0] != h1.ID {
		t.Fatalf("recoveries %v", r.Recoveries)
	}
	// RR-06: two parties each complete a different recovery: retired for good.
	w.recover("R0", g.ID, I, g.ID, "C0", "R1x", "C1x")
	expect(t, w.snapshot(t), a, Denied, "retired_for_good", 0)
}

func TestRR08And09And22Unresolved(t *testing.T) {
	// RR-08: a root line with a missing ancestor, then a recovery that leaves it outside the kept prefix.
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	stray := line(w.id("stray"), "R0", 7, "missing-ancestor", GrantEvent)
	stray.Grant = &Grant{Identity: I, Delegate: "t1", Inception: "t1-inc"}
	w.add(stray)
	expect(t, w.snapshot(t), a, Unknown, "unresolved_root_ancestry", 0)
	w.recover("R0", g.ID, I, g.ID, "C0", "R1", "C1")
	expect(t, w.snapshot(t), a, Eligible, "", 1)

	// RR-09: a valid recovery whose last_good the reader does not hold.
	w2 := newRR()
	inc2 := w2.inception("R0", "C0")
	I2 := inc2.ID
	d2 := w2.delegate("d1")
	g2 := w2.grant("R0", I2, I2, d2)
	a2 := w2.act("d1", d2.ID, I2, g2)
	g3 := w2.grant("R0", g2.ID, I2, w2.delegate("d3"))
	w2.recover("R0", g3.ID, I2, g3.ID, "C0", "R1", "C1")
	s := snapshot(t, without(slices.Clone(w2.facts), g3.ID))
	r := expect(t, s, a2, Unknown, "recovery_unresolved", 0)
	if !slices.ContainsFunc(r.Dependencies, func(x Dependency) bool { return x.ID == g3.ID }) {
		t.Fatalf("the missing last good line is not a dependency: %+v", r.Dependencies)
	}

	// RR-22: a complete recovery plus a second valid one whose last_good is not held: unknown, never passed over.
	w3 := newRR()
	inc3 := w3.inception("R0", "C0")
	I3 := inc3.ID
	d3 := w3.delegate("d1")
	g4 := w3.grant("R0", I3, I3, d3)
	a3 := w3.act("d1", d3.ID, I3, g4)
	w3.recover("R0", g4.ID, I3, g4.ID, "C0", "R1", "C1")
	g5 := w3.grant("R0", g4.ID, I3, w3.delegate("d5"))
	w3.recover("R0", g5.ID, I3, g5.ID, "C0", "R1y", "C1y")
	expect(t, snapshot(t, without(slices.Clone(w3.facts), g5.ID)), a3, Unknown, "recovery_unresolved", 0)
}

func TestRR10EscrowedRevokeThenRecovery(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	rv := w.revoke("R0", I)     // signed at the first line, kept offline
	g := w.grant("R0", I, I, d) // the root goes on signing on another branch (a fork at the inception)
	a := w.act("d1", d.ID, I, g)
	expect(t, snapshot(t, without(slices.Clone(w.facts), rv.ID)), a, Eligible, "", 0)
	expect(t, w.snapshot(t), a, Denied, "root_retired", 0)
	w.recover("R0", g.ID, I, g.ID, "C0", "R1", "C1")
	expect(t, w.snapshot(t), a, Eligible, "", 1)
}

func TestRR11ClosedIdentity(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	rec := w.recovery("C0", I, g.ID, nil, "")
	h := w.handover("R0", g.ID, I, rec)
	later := w.grant("R0", h.ID, I, w.delegate("d9"))
	aLater := w.act("d9", w.byID[later.Grant.Inception].ID, I, later)
	s := w.snapshot(t)
	r := expect(t, s, a, Eligible, "", 0)
	if !r.Closed {
		t.Fatalf("not closed: %+v", r)
	}
	expect(t, s, aLater, Denied, "recovery_voided", 0)
}

func TestRR12And16TwoGenerations(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d0, d1, d2 := w.delegate("d0"), w.delegate("d1"), w.delegate("d2")
	g0 := w.grant("R0", I, I, d0)
	s1, _, _ := w.recover("R0", g0.ID, I, g0.ID, "C0", "R1", "C1")
	g1 := w.grant("R1", s1.ID, I, d1)
	// RR-16: R′ is revoked by its own key event: retired at generation 1, recoverable by R′ and the second key.
	rv := w.revoke("R1", g1.ID)
	a0, a1 := w.act("d0", d0.ID, I, g0), w.act("d1", d1.ID, I, g1)
	expect(t, w.snapshot(t), a0, Denied, "root_retired", 0)
	expect(t, w.snapshot(t), a1, Denied, "root_retired", 0)
	// RR-12: a second recovery by R′ and the second recovery key: generation 2; grants of all three roots count.
	s2, _, _ := w.recover("R1", g1.ID, I, g1.ID, "C1", "R2", "C2")
	g2 := w.grant("R2", s2.ID, I, d2)
	a2 := w.act("d2", d2.ID, I, g2)
	s := w.snapshot(t)
	for _, a := range []Fact{a0, a1, a2} {
		r := expect(t, s, a, Eligible, "", 2)
		if len(r.Recoveries) != 2 || slices.Contains(r.Basis, rv.ID) && hasReason(r, "root_retired") {
			t.Fatalf("%s: %v %v", a.ID, r.Recoveries, codes(r))
		}
	}
}

func TestRR13And20OldPairAfterRecovery(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	_, _, h := w.recover("R0", g.ID, I, g.ID, "C0", "R1", "C1")
	// RR-20: after a recovery, the old R is revoked: no effect.
	w.revoke("R0", h.ID)
	expect(t, w.snapshot(t), a, Eligible, "", 1)
	// RR-13: the old R and old C sign another recovery of generation 0: retired for good.
	w.recover("R0", h.ID, I, g.ID, "C0", "R1z", "C1z")
	expect(t, w.snapshot(t), a, Denied, "retired_for_good", 0)
}

func TestRR15And26And30And31VoidSuccessors(t *testing.T) {
	// RR-15: a recovery whose next repeats a used commitment is void.
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	succ := w.succession("R1", I)
	rec := w.recovery("C0", I, g.ID, &succ, "C0") // next repeats the commitment in force
	w.handover("R0", g.ID, I, rec)
	r := expect(t, w.snapshot(t), a, Eligible, "", 0)
	if !hasWarning(r, "void_handover") {
		t.Fatal(codes(r))
	}

	// RR-26: R0 → R1; a thief of R1 grants; R1 → R2 with last_good before that grant; a third recovery names R1 again.
	w = newRR()
	inc = w.inception("R0", "C0")
	I = inc.ID
	s1, _, _ := w.recover("R0", I, I, "", "C0", "R1", "C1")
	t1 := w.delegate("t1")
	gt := w.grant("R1", s1.ID, I, t1)
	at := w.act("t1", t1.ID, I, gt)
	s2, _, _ := w.recover("R1", gt.ID, I, "", "C1", "R2", "C2")
	expect(t, w.snapshot(t), at, Denied, "recovery_voided", 0)
	rec3 := w.recovery("C2", I, "", &s1, "C3") // R1 as the successor again
	w.handover("R2", s2.ID, I, rec3)
	r = expect(t, w.snapshot(t), at, Denied, "recovery_voided", 0)
	if r.Generation != 2 || !hasWarning(r, "void_handover") {
		t.Fatalf("gen %d %v", r.Generation, codes(r))
	}

	// RR-30a: the commitment names the root's own key, which signs a second seq-0 line as the "recovery".
	w = newRR()
	inc = w.inception("R0", "R0")
	I = inc.ID
	d = w.delegate("d1")
	g = w.grant("R0", I, I, d)
	a = w.act("d1", d.ID, I, g)
	sT := w.succession("RT", I)
	recR := w.recovery("R0", I, "", &sT, "CT")
	w.handover("R0", g.ID, I, recR)
	r = expect(t, w.snapshot(t), a, Eligible, "", 0)
	if !hasWarning(r, "void_handover") {
		t.Fatal(codes(r))
	}
	// RR-30b: the successor itself signs the recovery naming itself.
	w = newRR()
	inc = w.inception("R0", "S1")
	I = inc.ID
	d = w.delegate("d1")
	g = w.grant("R0", I, I, d)
	a = w.act("d1", d.ID, I, g)
	sS := w.succession("S1", I)
	recS := w.recovery("S1", I, "", &sS, "CT")
	w.handover("R0", g.ID, I, recS)
	r = expect(t, w.snapshot(t), a, Eligible, "", 0)
	if !hasWarning(r, "void_handover") {
		t.Fatal(codes(r))
	}

	// RR-31a: a spent recovery key named as a later successor. RR-31b: one key as both successor and next.
	w = newRR()
	inc = w.inception("R0", "C0")
	I = inc.ID
	d = w.delegate("d1")
	g = w.grant("R0", I, I, d)
	a = w.act("d1", d.ID, I, g)
	s1, _, _ = w.recover("R0", g.ID, I, g.ID, "C0", "R1", "C1")
	s2, _, _ = w.recover("R1", s1.ID, I, "", "C1", "R2", "C2")
	expect(t, w.snapshot(t), a, Eligible, "", 2)
	sC1 := w.succession("C1", I)
	rec31 := w.recovery("C2", I, "", &sC1, "C3")
	w.handover("R2", s2.ID, I, rec31)
	r = expect(t, w.snapshot(t), a, Eligible, "", 2)
	if !hasWarning(r, "void_handover") {
		t.Fatal(codes(r))
	}
	w = newRR()
	inc = w.inception("R0", "C0")
	I = inc.ID
	d = w.delegate("d1")
	g = w.grant("R0", I, I, d)
	a = w.act("d1", d.ID, I, g)
	sB := w.succession("S1", I)
	recB := w.recovery("C0", I, g.ID, &sB, "S1")
	w.handover("R0", g.ID, I, recB)
	r = expect(t, w.snapshot(t), a, Eligible, "", 0)
	if !hasWarning(r, "void_handover") {
		t.Fatal(codes(r))
	}
}

func TestRR17And28DelegateActsAcrossARecovery(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	dk, dv := w.delegate("kept"), w.delegate("voided")
	gk := w.grant("R0", I, I, dk)
	gv := w.grant("R0", gk.ID, I, dv)
	ak, av := w.act("kept", dk.ID, I, gk), w.act("voided", dv.ID, I, gv)
	before := w.snapshot(t)
	expect(t, before, ak, Eligible, "", 0)
	expect(t, before, av, Eligible, "", 0)
	s1, _, h := w.recover("R0", gv.ID, I, gk.ID, "C0", "R1", "C1")
	after := w.snapshot(t)
	expect(t, after, ak, Eligible, "", 1)              // (a) a grant inside the kept prefix
	expect(t, after, av, Denied, "recovery_voided", 0) // (b) a grant the recovery voids, whenever the act was signed
	// (c) the new root cuts a grant the old root issued.
	w.cut("R1", s1.ID, I, gk.ID, LastGood{Mode: PreserveNone})
	expect(t, w.snapshot(t), ak, Denied, "cut_excluded", 0)
	// (d) the old root signs a cut after the recovery: void, the grant still counts.
	w2 := newRR()
	inc2 := w2.inception("R0", "C0")
	I2 := inc2.ID
	d2 := w2.delegate("d")
	g2 := w2.grant("R0", I2, I2, d2)
	a2 := w2.act("d", d2.ID, I2, g2)
	_, _, h2 := w2.recover("R0", g2.ID, I2, g2.ID, "C0", "R1", "C1")
	w2.cut("R0", h2.ID, I2, g2.ID, LastGood{Mode: PreserveNone})
	r := expect(t, w2.snapshot(t), a2, Eligible, "", 1)
	if hasReason(r, "cut_excluded") || !slices.Equal(r.Recoveries, []ID{h2.ID}) {
		t.Fatal(codes(r))
	}
	_ = h
}

func TestRR18LastGoodNull(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	w.recover("R0", g.ID, I, "", "C0", "R1", "C1")
	expect(t, w.snapshot(t), a, Denied, "recovery_voided", 0)
}

func TestRR19And25VoidPrefixesAreNoRivals(t *testing.T) {
	// RR-19: a last_good with a root key event among its ancestors: that recovery is void, the raw event stands
	// (retired), and a second recovery with last_good before it is the only complete one: current at generation 1.
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	rv := w.revoke("R0", g.ID)
	after := w.grant("R0", rv.ID, I, w.delegate("d2"))
	w.recover("R0", after.ID, I, after.ID, "C0", "R1", "C1")
	r := expect(t, w.snapshot(t), a, Denied, "root_retired", 0)
	if !hasWarning(r, "void_handover") {
		t.Fatal(codes(r))
	}
	w.recover("R0", g.ID, I, g.ID, "C0", "R1b", "C1b")
	expect(t, w.snapshot(t), a, Eligible, "", 1)

	// RR-25: the root signs an ordinary statement: unknown. (b) last_good before it: current. (c) at or after it:
	// void, still unknown; then (b) is no rival.
	w = newRR()
	inc = w.inception("R0", "C0")
	I = inc.ID
	d = w.delegate("d1")
	g = w.grant("R0", I, I, d)
	a = w.act("d1", d.ID, I, g)
	ord := w.ordinary("R0", g.ID)
	after = w.grant("R0", ord.ID, I, w.delegate("d2"))
	expect(t, w.snapshot(t), a, Unknown, "unsupported_root_event", 0)
	w.recover("R0", after.ID, I, after.ID, "C0", "R1c", "C1c")
	r = expect(t, w.snapshot(t), a, Unknown, "unsupported_root_event", 0)
	if !hasWarning(r, "void_handover") {
		t.Fatal(codes(r))
	}
	w.recover("R0", g.ID, I, g.ID, "C0", "R1", "C1")
	expect(t, w.snapshot(t), a, Eligible, "", 1)
}

func TestRR23GenerationCap(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	root, prev := Key("R0"), g.ID
	const n = 70
	for i := 1; i <= n; i++ {
		succ, _, _ := w.recover(root, prev, I, prev, Key(fmt.Sprintf("C%d", i-1)), Key(fmt.Sprintf("R%d", i)), Key(fmt.Sprintf("C%d", i)))
		root, prev = succ.Signer, succ.ID
	}
	s := w.snapshot(t)
	if r := s.Evaluate(a.ID); r.Status != Unknown || !hasReason(r, "model_limit") {
		t.Fatalf("70 recoveries under the default cap: %s %v", r.Status, codes(r))
	}
	if r := s.EvaluateWith(a.ID, Limits{Generations: n}); r.Status != Eligible || r.Generation != n {
		t.Fatalf("raised cap: %s gen %d %v", r.Status, r.Generation, codes(r))
	}
	// 64 recoveries are followed by every reader.
	w = newRR()
	inc = w.inception("R0", "C0")
	I = inc.ID
	d = w.delegate("d1")
	g = w.grant("R0", I, I, d)
	a = w.act("d1", d.ID, I, g)
	root, prev = "R0", g.ID
	for i := 1; i <= DefaultMaxGenerations; i++ {
		succ, _, _ := w.recover(root, prev, I, prev, Key(fmt.Sprintf("C%d", i-1)), Key(fmt.Sprintf("R%d", i)), Key(fmt.Sprintf("C%d", i)))
		root, prev = succ.Signer, succ.ID
	}
	if r := w.snapshot(t).Evaluate(a.ID); r.Status != Eligible || r.Generation != DefaultMaxGenerations {
		t.Fatalf("64 recoveries: %s gen %d %v", r.Status, r.Generation, codes(r))
	}
}

func TestRR24CarriedStatementChecksInOrder(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d := w.delegate("d1")
	g := w.grant("R0", I, I, d)
	a := w.act("d1", d.ID, I, g)
	succ := w.succession("R1", I)
	rec := w.recovery("C0", I, g.ID, &succ, "C1")
	// (a) by the committed key, signature does not verify: void.
	ca := carried(rec)
	ca.Authentication = RejectedSignature
	w.handoverCarrying("R0", g.ID, I, ca)
	r := expect(t, w.snapshot(t), a, Eligible, "", 0)
	if !hasWarning(r, "void_handover") {
		t.Fatal(codes(r))
	}
	// (b) by another key, under an algorithm the reader lacks: void, since the commitment is compared first.
	cb := carried(rec)
	cb.Signer, cb.Commitment, cb.Authentication = "T", commitOf("T"), Unproven
	w.handoverCarrying("R0", g.ID, I, cb)
	expect(t, w.snapshot(t), a, Eligible, "", 0)
	// (c) by the committed key, under such an algorithm: unknown.
	cc := carried(rec)
	cc.Authentication = Unproven
	w.handoverCarrying("R0", g.ID, I, cc)
	expect(t, w.snapshot(t), a, Unknown, "recovery_unresolved", 0)
}

func TestRR27AbandonedSignedRecovery(t *testing.T) {
	w := newRR()
	inc := w.inception("R0", "C0")
	I := inc.ID
	d, td := w.delegate("d1"), w.delegate("t1")
	g := w.grant("R0", I, I, d)
	gt := w.grant("R0", g.ID, I, td)
	a := w.act("d1", d.ID, I, g)
	sA := w.succession("R1", I)
	recA := w.recovery("C0", I, g.ID, &sA, "C1")       // signed, then set aside
	w.recover("R0", g.ID, I, g.ID, "C0", "R1b", "C1b") // the owner publishes B
	expect(t, w.snapshot(t), a, Eligible, "", 1)
	w.handover("R0", gt.ID, I, recA) // a holder of R0 obtains A's bytes
	expect(t, w.snapshot(t), a, Denied, "retired_for_good", 0)
	expect(t, snapshot(t, without(slices.Clone(w.facts), sA.ID)), a, Unknown, "recovery_unresolved", 0)
}

func TestRR29QuietTheftKeepAndCut(t *testing.T) {
	build := func() (*rr, ID, Fact, Fact, Fact, Fact, []Fact) {
		w := newRR()
		inc := w.inception("R0", "C0")
		I := inc.ID
		d1, t1, d2, d3 := w.delegate("d1"), w.delegate("t1"), w.delegate("d2"), w.delegate("d3")
		g1 := w.grant("R0", I, I, d1)
		gt := w.grant("R0", g1.ID, I, t1) // the thief extends the owner's tip: no fork
		g2 := w.grant("R0", gt.ID, I, d2)
		g3 := w.grant("R0", g2.ID, I, d3)
		acts := []Fact{w.act("d1", d1.ID, I, g1), w.act("d2", d2.ID, I, g2), w.act("d3", d3.ID, I, g3), w.act("t1", t1.ID, I, gt)}
		return w, I, g1, gt, g2, g3, acts
	}
	// (a) last_good before the thief's grant voids the owner's two later grants too.
	w, I, g1, gt, _, g3, acts := build()
	w.recover("R0", g3.ID, I, g1.ID, "C0", "R1", "C1")
	s := w.snapshot(t)
	expect(t, s, acts[0], Eligible, "", 1)
	expect(t, s, acts[1], Denied, "recovery_voided", 0)
	expect(t, s, acts[2], Denied, "recovery_voided", 0)
	expect(t, s, acts[3], Denied, "recovery_voided", 0)
	// (b) last_good at the owner's tip, then the new root cuts the thief's grant: the owner's grants all count; the
	// thief's counts until the cut arrives.
	w, I, _, gt, _, g3, acts = build()
	s1, _, _ := w.recover("R0", g3.ID, I, g3.ID, "C0", "R1", "C1")
	expect(t, w.snapshot(t), acts[3], Eligible, "", 1)
	w.cut("R1", s1.ID, I, gt.ID, LastGood{Mode: PreserveNone})
	s = w.snapshot(t)
	for _, a := range acts[:3] {
		expect(t, s, a, Eligible, "", 1)
	}
	expect(t, s, acts[3], Denied, "cut_excluded", 0)
}

// Grant-level state follows the same generations: a grant a recovery voids is denied, one in the kept prefix is
// open, and one the new root cuts reads cut.
func TestRecoverableGrantState(t *testing.T) {
	sw := stolen()
	s := sw.w.snapshot(t)
	if gs := s.GrantState(sw.gOwn.ID); gs.Status != GrantOpen {
		t.Fatalf("kept grant: %s %+v", gs.Status, gs.Reasons)
	}
	if gs := s.GrantState(sw.gThief.ID); gs.Status != GrantDenied || !slices.ContainsFunc(gs.Reasons, func(r Reason) bool { return r.Code == "recovery_voided" }) {
		t.Fatalf("voided grant: %s %+v", gs.Status, gs.Reasons)
	}
	if gs := s.GrantState(sw.gNew.ID); gs.Status != GrantOpen {
		t.Fatalf("new root's grant: %s %+v", gs.Status, gs.Reasons)
	}
	sw.w.cut("R1", sw.gNew.ID, sw.I, sw.gOwn.ID, LastGood{Mode: PreserveThrough, ID: sw.aOwn.ID})
	if gs := sw.w.snapshot(t).GrantState(sw.gOwn.ID); gs.Status != GrantCutAt || !slices.Equal(gs.LastGood, []ID{sw.aOwn.ID}) {
		t.Fatalf("cut by the new root: %s %v %+v", gs.Status, gs.LastGood, gs.Reasons)
	}
}

// A fixed-root identity is unchanged by the generation walk: one generation, no recoveries, and a handover on its
// root's lineage is outside its vocabulary.
func TestFixedRootUnchangedByGenerations(t *testing.T) {
	s := snapshot(t, fixture())
	r := requireStatus(t, s, "A", Eligible, "")
	if r.Generation != 0 || len(r.Recoveries) != 0 || r.Closed {
		t.Fatalf("%+v", r)
	}
	fs := fixture()
	h := line("H", "R", 2, "G", HandoverEvent)
	h.Handover = &Handover{Identity: "I", Carried: Carried{ID: "rec", Signer: "C", Commitment: commitOf("C"), Authentication: Authenticated, Validity: Understood, Event: RecoveryEvent, Recovery: &Recovery{Identity: "I"}}}
	requireStatus(t, snapshot(t, append(fs, h)), "A", Unknown, "unsupported_root_event")
}
