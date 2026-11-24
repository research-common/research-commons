package identity_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/wire"
)

// The recoverable-root profile's conformance cases (recoverable-root note §10, C-id-46 to C-id-76: scenario handles
// RR-01 to RR-31), each built from signed lines through the production reader and the admission adapter. The
// model-level copies are internal/identitymodel/recovery_test.go; these are the signed, end-to-end ones.

// rw builds one scenario's signed statements on a world. Names are generated; the identity is "I".
type rw struct {
	*world
	n int
}

func newRW(t *testing.T) *rw { return &rw{world: newWorld(t)} }

func (w *rw) name(tag string) string {
	w.n++
	return fmt.Sprintf("%s#%d", tag, w.n)
}

// key makes a key for name if the world lacks it. Roots are EIP-191, everything else Ed25519, so both required
// algorithms sign on every path.
func (w *rw) key(name string) string {
	if _, ok := w.keys[name]; !ok {
		w.keys[name] = key("rr "+name, strings.HasPrefix(name, "R"))
	}
	return name
}

func (w *rw) inception(root, recovery string) string {
	w.key(root)
	w.key(recovery)
	return w.sign(stmt{name: "I", by: root, kind: "identity_inception", body: obj("profile", wire.RecoverableRootProfile, "recovery", commitments(w.world, recovery))})
}

// inceptionCommitting commits to a raw commitment (a key this test never holds, or one under a future algorithm).
func (w *rw) inceptionCommitting(root, commitment string) string {
	w.key(root)
	return w.sign(stmt{name: "I", by: root, kind: "identity_inception", body: obj("profile", wire.RecoverableRootProfile, "recovery",
		obj("commitments", []string{commitment}, "rule", obj("any_one", true)))})
}

// delegate is a worker's bare rc/1 first line.
func (w *rw) delegate(k string) string {
	w.key(k)
	return w.sign(stmt{name: k + ".0", by: k, rc: "rc/1", kind: "authored", body: authoredBody(9)})
}

func (w *rw) grant(root, prev, delegate string) string {
	n := w.name("G")
	w.sign(stmt{name: n, by: root, parent: prev, kind: "identity_grant", body: w.grantBody(delegate, authoredAny())})
	return n
}

// act is a delegate's statement under grant; prev "" starts after its first line.
func (w *rw) act(delegate, prev, grant string) string {
	if prev == "" {
		prev = delegate + ".0"
	}
	n := w.name("A")
	w.sign(stmt{name: n, by: delegate, parent: prev, kind: "authored", body: authoredBody(byte(w.n)), actor: [2]string{"I", grant}})
	return n
}

func (w *rw) cut(root, prev, grant, lastGood string) string {
	n := w.name("CUT")
	w.sign(stmt{name: n, by: root, parent: prev, kind: "identity_cut", body: cutBody(w.world, grant, lastGood)})
	return n
}

// revoke is the root's own raw revoke_key (rc/1, a soft reason: the terminal effect is the same).
func (w *rw) revoke(root, prev string) string {
	n := w.name("RV")
	w.sign(stmt{name: n, by: root, parent: prev, rc: "rc/1", kind: "revoke_key", body: obj("reason", "superseded")})
	return n
}

// ordinary is a root's statement outside its vocabulary (an authored, issue #271).
func (w *rw) ordinary(root, prev string) string {
	n := w.name("ORD")
	w.sign(stmt{name: n, by: root, parent: prev, kind: "authored", body: authoredBody(byte(w.n))})
	return n
}

func (w *rw) succession(successor string) string {
	w.key(successor)
	n := w.name("S")
	w.sign(stmt{name: n, by: successor, kind: "identity_succession", body: obj("identity", w.ids["I"])})
	return n
}

// recovery is C's statement: lastGood "" is null; succ "" closes the identity (then next is ignored).
func (w *rw) recovery(c, lastGood, succ, successorKey, next string) string {
	w.key(c)
	var lg any
	if lastGood != "" {
		lg = w.ids[lastGood]
	}
	var body *canon.Object
	if succ == "" {
		body = obj("identity", w.ids["I"], "last_good", lg, "successor", nil)
	} else {
		w.key(next)
		body = obj("identity", w.ids["I"], "last_good", lg, "successor", obj("key", w.signer(successorKey), "inception", w.ids[succ]), "next", commitments(w.world, next))
	}
	n := w.name("REC")
	w.sign(stmt{name: n, by: c, kind: "identity_recovery", body: body})
	return n
}

func (w *rw) handover(root, prev, rec string) string {
	return w.handoverCarrying(root, prev, w.statement(rec))
}

func (w *rw) handoverCarrying(root, prev string, carried *canon.Object) string {
	n := w.name("H")
	w.sign(stmt{name: n, by: root, parent: prev, kind: "identity_handover", body: obj("identity", w.ids["I"], "recovery", carried)})
	return n
}

// recover is the whole ceremony by root at prev: successor's first line, C's recovery, root's handover.
func (w *rw) recover(root, prev, lastGood, c, successor, next string) (succ, rec, h string) {
	succ = w.succession(successor)
	rec = w.recovery(c, lastGood, succ, successor, next)
	h = w.handover(root, prev, rec)
	return
}

func (w *rw) snap() *identity.Snapshot { return w.admit() }

func (w *rw) eligibleAt(s *identity.Snapshot, act string, gen uint64) identitymodel.Result {
	w.t.Helper()
	r := w.expect(s, act, identitymodel.Eligible, "")
	if r.Generation != gen {
		w.t.Fatalf("%s: generation %d, want %d", act, r.Generation, gen)
	}
	return r
}

func (w *rw) voidReported(r identitymodel.Result) {
	w.t.Helper()
	if !hasWarning(r, "void_handover") {
		w.t.Fatalf("void handover not reported: %+v", r.Warnings)
	}
}

// stolenRW is RR-02's world (recoverable_test.go draws it): the owner's grant, the thief's, the recovery to R1 at the
// owner's grant, R1's grant, the thief's second grant, and an act under each grant.
type stolenRW struct {
	*rw
	gOwn, gThief, gNew, gThief2 string
	aOwn, aThief, aNew, aThief2 string
	succ, rec, h                string
}

func stolenWorld(t *testing.T) stolenRW {
	w := newRW(t)
	i := w.inception("R0", "C0")
	for _, d := range []string{"d1", "t1", "d2", "t2"} {
		w.delegate(d)
	}
	gOwn := w.grant("R0", "I", "d1")
	gThief := w.grant("R0", gOwn, "t1")
	succ, rec, h := w.recover("R0", gThief, gOwn, "C0", "R1", "C1")
	gNew := w.grant("R1", succ, "d2")
	gThief2 := w.grant("R0", gThief, "t2")
	_ = i
	return stolenRW{w, gOwn, gThief, gNew, gThief2, w.act("d1", "", gOwn), w.act("t1", "", gThief), w.act("d2", "", gNew), w.act("t2", "", gThief2), succ, rec, h}
}

func TestRR01OrdinaryUse(t *testing.T) {
	conformance.Covers(t, "C-id-46")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	r := w.eligibleAt(w.snap(), a, 0)
	if len(r.Recoveries) != 0 || r.Closed {
		t.Fatalf("%+v", r)
	}
}

func TestRR02And14RecoveryAfterTheft(t *testing.T) {
	conformance.Covers(t, "C-id-47", "C-id-59")
	sw := stolenWorld(t)
	s := sw.snap()
	r := sw.eligibleAt(s, sw.aOwn, 1)
	if len(r.Recoveries) != 1 || string(r.Recoveries[0]) != sw.ids[sw.h] {
		t.Fatalf("recoveries %v", r.Recoveries)
	}
	sw.eligibleAt(s, sw.aNew, 1)
	sw.expect(s, sw.aThief, identitymodel.Denied, "recovery_voided")
	sw.expect(s, sw.aThief2, identitymodel.Denied, "recovery_voided")
	// RR-14: a reader that holds everything but the handover reads the pre-recovery state.
	before := sw.admit(without(sw.order, sw.h)...)
	sw.eligibleAt(before, sw.aThief, 0)
	sw.eligibleAt(before, sw.aOwn, 0)
}

func TestRR03ThiefRevokesThenOwnerRecovers(t *testing.T) {
	conformance.Covers(t, "C-id-48")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	w.revoke("R0", g)
	a := w.act("d1", "", g)
	w.expect(w.snap(), a, identitymodel.Denied, "root_retired")
	w.recover("R0", g, g, "C0", "R1", "C1")
	w.eligibleAt(w.snap(), a, 1)
}

func TestRR04And05OneKeyAlone(t *testing.T) {
	conformance.Covers(t, "C-id-49", "C-id-50")
	// RR-04: a holder of R alone hands over a "recovery" by a key of their own: void.
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	succ := w.succession("RT")
	fake := w.recovery("T", g, succ, "RT", "T2")
	w.handover("R0", g, fake)
	w.voidReported(w.eligibleAt(w.snap(), a, 0))
	// RR-05: a holder of C alone signs a recovery: no handover, nothing happens.
	w2 := newRW(t)
	w2.inception("R0", "C0")
	w2.delegate("d1")
	g2 := w2.grant("R0", "I", "d1")
	a2 := w2.act("d1", "", g2)
	s2 := w2.succession("R1")
	w2.recovery("C0", g2, s2, "R1", "C1")
	w2.eligibleAt(w2.snap(), a2, 0)
}

func TestRR06And07RivalsAndRepeats(t *testing.T) {
	conformance.Covers(t, "C-id-51", "C-id-52")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	_, rec1, h1 := w.recover("R0", g, g, "C0", "R1", "C1")
	w.eligibleAt(w.snap(), a, 1)
	// RR-07: the same recovery handed over twice is one recovery.
	w.handover("R0", g, rec1)
	if r := w.eligibleAt(w.snap(), a, 1); len(r.Recoveries) != 1 || string(r.Recoveries[0]) != w.ids[h1] {
		t.Fatalf("recoveries %v", r.Recoveries)
	}
	// RR-06: two parties each complete a different recovery: retired for good.
	w.recover("R0", g, g, "C0", "R1x", "C1x")
	w.expect(w.snap(), a, identitymodel.Denied, "retired_for_good")
}

func TestRR08MissingAncestorThenRecovery(t *testing.T) {
	conformance.Covers(t, "C-id-53")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	w.delegate("t1")
	gap := w.grant("R0", g, "t1")     // the line the reader will not hold
	stray := w.grant("R0", gap, "t1") // a root line whose ancestor is missing
	w.expect(w.admit(without(w.order, gap)...), a, identitymodel.Unknown, "unresolved_root_ancestry")
	w.recover("R0", g, g, "C0", "R1", "C1")
	w.eligibleAt(w.admit(without(w.order, gap)...), a, 1)
	_ = stray
}

func TestRR09And22UnresolvedRecoveries(t *testing.T) {
	conformance.Covers(t, "C-id-54", "C-id-67")
	// RR-09: a valid recovery whose last_good the reader does not hold.
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	w.delegate("d3")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	g3 := w.grant("R0", g, "d3")
	w.recover("R0", g3, g3, "C0", "R1", "C1")
	r := w.expect(w.admit(without(w.order, g3)...), a, identitymodel.Unknown, "recovery_unresolved")
	found := false
	for _, d := range r.Dependencies {
		found = found || string(d.ID) == w.ids[g3]
	}
	if !found {
		t.Fatalf("the missing last good line is not a dependency: %+v", r.Dependencies)
	}
	// RR-22: a complete recovery plus a second valid one whose last_good is not held: unknown, never passed over.
	w2 := newRW(t)
	w2.inception("R0", "C0")
	w2.delegate("d1")
	w2.delegate("d5")
	g4 := w2.grant("R0", "I", "d1")
	a2 := w2.act("d1", "", g4)
	w2.recover("R0", g4, g4, "C0", "R1", "C1")
	g5 := w2.grant("R0", g4, "d5")
	w2.recover("R0", g5, g5, "C0", "R1y", "C1y")
	w2.expect(w2.admit(without(w2.order, g5)...), a2, identitymodel.Unknown, "recovery_unresolved")
}

func TestRR10EscrowedRevokeThenRecovery(t *testing.T) {
	conformance.Covers(t, "C-id-55")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	rv := w.revoke("R0", "I")     // signed at the first line, kept offline
	g := w.grant("R0", "I", "d1") // the root goes on signing on another branch
	a := w.act("d1", "", g)
	w.eligibleAt(w.admit(without(w.order, rv)...), a, 0)
	w.expect(w.snap(), a, identitymodel.Denied, "root_retired")
	w.recover("R0", g, g, "C0", "R1", "C1")
	w.eligibleAt(w.snap(), a, 1)
}

func TestRR11ClosedIdentity(t *testing.T) {
	conformance.Covers(t, "C-id-56")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	w.delegate("d9")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	rec := w.recovery("C0", g, "", "", "")
	h := w.handover("R0", g, rec)
	later := w.grant("R0", h, "d9")
	aLater := w.act("d9", "", later)
	s := w.snap()
	if r := w.eligibleAt(s, a, 0); !r.Closed {
		t.Fatalf("not closed: %+v", r)
	}
	w.expect(s, aLater, identitymodel.Denied, "recovery_voided")
}

func TestRR12And16TwoGenerations(t *testing.T) {
	conformance.Covers(t, "C-id-57", "C-id-61")
	w := newRW(t)
	w.inception("R0", "C0")
	for _, d := range []string{"d0", "d1", "d2"} {
		w.delegate(d)
	}
	g0 := w.grant("R0", "I", "d0")
	s1, _, _ := w.recover("R0", g0, g0, "C0", "R1", "C1")
	g1 := w.grant("R1", s1, "d1")
	// RR-16: R′ is revoked by its own key event: retired at generation 1, recoverable by R′ and the second key.
	w.revoke("R1", g1)
	a0, a1 := w.act("d0", "", g0), w.act("d1", "", g1)
	w.expect(w.snap(), a0, identitymodel.Denied, "root_retired")
	w.expect(w.snap(), a1, identitymodel.Denied, "root_retired")
	// RR-12: a second recovery by R′ and the second recovery key: generation 2; grants of all three roots count.
	s2, _, _ := w.recover("R1", g1, g1, "C1", "R2", "C2")
	g2 := w.grant("R2", s2, "d2")
	a2 := w.act("d2", "", g2)
	s := w.snap()
	for _, a := range []string{a0, a1, a2} {
		if r := w.eligibleAt(s, a, 2); len(r.Recoveries) != 2 {
			t.Fatalf("%s: %v", a, r.Recoveries)
		}
	}
}

func TestRR13And20OldPairAfterRecovery(t *testing.T) {
	conformance.Covers(t, "C-id-58", "C-id-65")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	_, _, h := w.recover("R0", g, g, "C0", "R1", "C1")
	// RR-20: after a recovery, the old R is revoked: no effect.
	w.revoke("R0", h)
	w.eligibleAt(w.snap(), a, 1)
	// RR-13: the old R and the old C sign another recovery of generation 0: retired for good.
	w.recover("R0", h, g, "C0", "R1z", "C1z")
	w.expect(w.snap(), a, identitymodel.Denied, "retired_for_good")
}

func TestRR15NextRepeatsAUsedCommitment(t *testing.T) {
	conformance.Covers(t, "C-id-60")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	succ := w.succession("R1")
	rec := w.recovery("C0", g, succ, "R1", "C0") // next repeats the commitment in force
	w.handover("R0", g, rec)
	w.voidReported(w.eligibleAt(w.snap(), a, 0))
}

func TestRR17And28DelegateActsAcrossARecovery(t *testing.T) {
	conformance.Covers(t, "C-id-62")
	conformance.Partial(t, "C-id-73", "the approvals' counting at the identity layer; what a collection's view shows for an edition under a voided grant is the resource layer's (issue #285)")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("kept")
	w.delegate("voided")
	gk := w.grant("R0", "I", "kept")
	gv := w.grant("R0", gk, "voided")
	ak, av := w.act("kept", "", gk), w.act("voided", "", gv)
	before := w.snap()
	w.eligibleAt(before, ak, 0)
	w.eligibleAt(before, av, 0)
	s1, _, _ := w.recover("R0", gv, gk, "C0", "R1", "C1")
	after := w.snap()
	w.eligibleAt(after, ak, 1)                                   // (a) a grant inside the kept prefix counts before and after
	w.expect(after, av, identitymodel.Denied, "recovery_voided") // (b) a grant the recovery voids: counted before, not after
	// (c) the new root cuts a grant the old root issued.
	w.cut("R1", s1, gk, "")
	w.expect(w.snap(), ak, identitymodel.Denied, "cut_excluded")
	// (d) the old root signs a cut after the recovery: void, the grant still counts.
	w2 := newRW(t)
	w2.inception("R0", "C0")
	w2.delegate("d")
	g2 := w2.grant("R0", "I", "d")
	a2 := w2.act("d", "", g2)
	_, _, h2 := w2.recover("R0", g2, g2, "C0", "R1", "C1")
	w2.cut("R0", h2, g2, "")
	if r := w2.eligibleAt(w2.snap(), a2, 1); hasReason(r, "cut_excluded") {
		t.Fatal(r.Reasons)
	}
}

func TestRR18LastGoodNull(t *testing.T) {
	conformance.Covers(t, "C-id-63")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	w.recover("R0", g, "", "C0", "R1", "C1")
	w.expect(w.snap(), a, identitymodel.Denied, "recovery_voided")
}

func TestRR19And25VoidPrefixesAreNoRivals(t *testing.T) {
	conformance.Covers(t, "C-id-64", "C-id-70")
	// RR-19: a last_good with a root key event among its ancestors: void; the raw event stands; a second recovery
	// with a last_good before it is the only complete one.
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	w.delegate("d2")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	rv := w.revoke("R0", g)
	after := w.grant("R0", rv, "d2")
	w.recover("R0", after, after, "C0", "R1", "C1")
	w.voidReported(w.expect(w.snap(), a, identitymodel.Denied, "root_retired"))
	w.recover("R0", g, g, "C0", "R1b", "C1b")
	w.eligibleAt(w.snap(), a, 1)
	// RR-25: the root signs an ordinary statement: unknown. (b) last_good before it: current. (c) at or after it:
	// void, still unknown, and no rival to (b).
	w2 := newRW(t)
	w2.inception("R0", "C0")
	w2.delegate("d1")
	w2.delegate("d2")
	g2 := w2.grant("R0", "I", "d1")
	a2 := w2.act("d1", "", g2)
	ord := w2.ordinary("R0", g2)
	after2 := w2.grant("R0", ord, "d2")
	w2.expect(w2.snap(), a2, identitymodel.Unknown, "unsupported_root_event")
	w2.recover("R0", after2, after2, "C0", "R1c", "C1c")
	w2.voidReported(w2.expect(w2.snap(), a2, identitymodel.Unknown, "unsupported_root_event"))
	w2.recover("R0", g2, g2, "C0", "R1", "C1")
	w2.eligibleAt(w2.snap(), a2, 1)
}

// RR-21: no subset of RR-02's statements reads generation 1 with a thief grant counting. The delegates' first lines
// and the acts are held throughout; every subset of the identity's lines is tried.
func TestRR21EverySubset(t *testing.T) {
	conformance.Covers(t, "C-id-66")
	sw := stolenWorld(t)
	pool := []string{"I", sw.gOwn, sw.gThief, sw.succ, sw.rec, sw.h, sw.gThief2, sw.gNew}
	fixed := without(sw.order, pool...)
	for mask := 0; mask < 1<<len(pool); mask++ {
		names := append([]string{}, fixed...)
		for i, n := range pool {
			if mask&(1<<i) != 0 {
				names = append(names, n)
			}
		}
		s := sw.admit(names...)
		for _, a := range []string{sw.aThief, sw.aThief2} {
			if r := s.Evaluate(sw.ids[a]); r.Status == identitymodel.Eligible && r.Generation == 1 {
				t.Fatalf("subset %b: thief act %s counts at generation 1", mask, a)
			}
		}
	}
}

func TestRR23GenerationCap(t *testing.T) {
	conformance.Covers(t, "C-id-68")
	build := func(n int) (*rw, string) {
		w := newRW(t)
		w.inception("R0", "C0")
		w.delegate("d1")
		g := w.grant("R0", "I", "d1")
		a := w.act("d1", "", g)
		root, prev := "R0", g
		for i := 1; i <= n; i++ {
			succ, _, _ := w.recover(root, prev, prev, fmt.Sprintf("C%d", i-1), fmt.Sprintf("R%d", i), fmt.Sprintf("C%d", i))
			root, prev = fmt.Sprintf("R%d", i), succ
		}
		return w, a
	}
	w, a := build(identitymodel.DefaultMaxGenerations)
	w.eligibleAt(w.snap(), a, identitymodel.DefaultMaxGenerations) // 64 recoveries are followed by every reader
	w, a = build(identitymodel.DefaultMaxGenerations + 1)
	r := w.expect(w.snap(), a, identitymodel.Unknown, "model_limit")
	for _, x := range r.Reasons {
		if x.Code == "model_limit" && !strings.Contains(x.Detail, identitymodel.LimitGenerations) {
			t.Fatalf("the cap is not named: %s", x.Detail)
		}
	}
}

func TestRR24CarriedStatementChecksInOrder(t *testing.T) {
	conformance.Covers(t, "C-id-69")
	futureSigner := "mldsa65:" + strings.Repeat("ab", 32)
	// (c) by the committed key, under an algorithm the reader lacks: unknown. The inception commits to that key.
	w := newRW(t)
	w.inceptionCommitting("R0", wire.RecoveryCommitment(futureSigner))
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	succ := w.succession("R1")
	// a template recovery to rewrite under the future algorithm
	tmpl := w.recovery("C0", g, succ, "R1", "C1")
	future := withField(withField(withField(w.statement(tmpl), "alg", canon.String("mldsa-65")), "signer", canon.String(futureSigner)), "sig", canon.String("mldsa65:"+strings.Repeat("cd", 32)))
	w.handoverCarrying("R0", g, future)
	w.expect(w.snap(), a, identitymodel.Unknown, "recovery_unresolved")
	// (b) by another key, under such an algorithm: void, since the commitment is compared first.
	w2 := newRW(t)
	w2.inception("R0", "C0")
	w2.delegate("d1")
	g2 := w2.grant("R0", "I", "d1")
	a2 := w2.act("d1", "", g2)
	succ2 := w2.succession("R1")
	tmpl2 := w2.recovery("C0", g2, succ2, "R1", "C1")
	future2 := withField(withField(withField(w2.statement(tmpl2), "alg", canon.String("mldsa-65")), "signer", canon.String(futureSigner)), "sig", canon.String("mldsa65:"+strings.Repeat("cd", 32)))
	w2.handoverCarrying("R0", g2, future2)
	w2.voidReported(w2.eligibleAt(w2.snap(), a2, 0))
	// (a) by the committed key, with a signature that does not verify: void.
	tampered := w2.statement(tmpl2)
	tampered = withField(tampered, "body", withField(tampered.Members["body"].(*canon.Object), "note", canon.String("altered after signing")))
	w2.handoverCarrying("R0", g2, tampered)
	w2.voidReported(w2.eligibleAt(w2.snap(), a2, 0))
}

func TestRR26FormerRootAsSuccessor(t *testing.T) {
	conformance.Covers(t, "C-id-71")
	w := newRW(t)
	w.inception("R0", "C0")
	s1, _, _ := w.recover("R0", "I", "", "C0", "R1", "C1")
	w.delegate("t1")
	gt := w.grant("R1", s1, "t1") // a thief of R1 grants
	at := w.act("t1", "", gt)
	s2, _, _ := w.recover("R1", gt, "", "C1", "R2", "C2") // R1 → R2 with last_good before the thief's grant
	w.expect(w.snap(), at, identitymodel.Denied, "recovery_voided")
	rec3 := w.recovery("C2", "", s1, "R1", "C3") // names R1 as the successor again
	w.handover("R2", s2, rec3)
	r := w.expect(w.snap(), at, identitymodel.Denied, "recovery_voided")
	if r.Generation != 2 {
		t.Fatalf("generation %d", r.Generation)
	}
	w.voidReported(r)
}

func TestRR27AbandonedSignedRecovery(t *testing.T) {
	conformance.Covers(t, "C-id-72")
	w := newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	w.delegate("t1")
	g := w.grant("R0", "I", "d1")
	gt := w.grant("R0", g, "t1")
	a := w.act("d1", "", g)
	sA := w.succession("R1")
	recA := w.recovery("C0", g, sA, "R1", "C1") // signed, then set aside
	w.recover("R0", g, g, "C0", "R1b", "C1b")   // the owner publishes B
	w.eligibleAt(w.snap(), a, 1)
	w.handover("R0", gt, recA) // a holder of R0 obtains A's bytes
	w.expect(w.snap(), a, identitymodel.Denied, "retired_for_good")
	w.expect(w.admit(without(w.order, sA)...), a, identitymodel.Unknown, "recovery_unresolved")
}

func TestRR29QuietTheftKeepAndCut(t *testing.T) {
	conformance.Covers(t, "C-id-74")
	build := func() (*rw, string, string, string, []string) {
		w := newRW(t)
		w.inception("R0", "C0")
		for _, d := range []string{"d1", "t1", "d2", "d3"} {
			w.delegate(d)
		}
		g1 := w.grant("R0", "I", "d1")
		gt := w.grant("R0", g1, "t1") // the thief extends the owner's tip: no fork
		g2 := w.grant("R0", gt, "d2")
		g3 := w.grant("R0", g2, "d3")
		return w, g1, gt, g3, []string{w.act("d1", "", g1), w.act("d2", "", g2), w.act("d3", "", g3), w.act("t1", "", gt)}
	}
	// (a) last_good before the thief's grant voids the owner's two later grants too.
	w, g1, gt, g3, acts := build()
	w.recover("R0", g3, g1, "C0", "R1", "C1")
	s := w.snap()
	w.eligibleAt(s, acts[0], 1)
	for _, a := range acts[1:] {
		w.expect(s, a, identitymodel.Denied, "recovery_voided")
	}
	// (b) last_good at the owner's tip, then the new root cuts the thief's grant: the owner's grants all count;
	// the thief's counts until the cut arrives.
	w, _, gt, g3, acts = build()
	s1, _, _ := w.recover("R0", g3, g3, "C0", "R1", "C1")
	w.eligibleAt(w.snap(), acts[3], 1)
	w.cut("R1", s1, gt, "")
	s = w.snap()
	for _, a := range acts[:3] {
		w.eligibleAt(s, a, 1)
	}
	w.expect(s, acts[3], identitymodel.Denied, "cut_excluded")
}

func TestRR30And31TheRecoveryKeyIsNoRoot(t *testing.T) {
	conformance.Covers(t, "C-id-75", "C-id-76")
	// RR-30a: the commitment names the root's own key; the root signs a second seq-0 line as the "recovery".
	w := newRW(t)
	w.inception("R0", "R0")
	w.delegate("d1")
	g := w.grant("R0", "I", "d1")
	a := w.act("d1", "", g)
	sT := w.succession("RT")
	recR := w.recovery("R0", "", sT, "RT", "CT")
	w.handover("R0", g, recR)
	w.voidReported(w.eligibleAt(w.snap(), a, 0))
	// RR-30b: the successor itself signs the recovery naming itself.
	w = newRW(t)
	w.inception("R0", "S1")
	w.delegate("d1")
	g = w.grant("R0", "I", "d1")
	a = w.act("d1", "", g)
	sS := w.succession("S1")
	recS := w.recovery("S1", "", sS, "S1", "CT")
	w.handover("R0", g, recS)
	w.voidReported(w.eligibleAt(w.snap(), a, 0))
	// RR-31a: a spent recovery key named as a later successor.
	w = newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g = w.grant("R0", "I", "d1")
	a = w.act("d1", "", g)
	s1, _, _ := w.recover("R0", g, g, "C0", "R1", "C1")
	s2, _, _ := w.recover("R1", s1, "", "C1", "R2", "C2")
	w.eligibleAt(w.snap(), a, 2)
	sC1 := w.succession("C1")
	rec31 := w.recovery("C2", "", sC1, "C1", "C3")
	w.handover("R2", s2, rec31)
	w.voidReported(w.eligibleAt(w.snap(), a, 2))
	// RR-31b: one key named as both the successor and the next recovery key.
	w = newRW(t)
	w.inception("R0", "C0")
	w.delegate("d1")
	g = w.grant("R0", "I", "d1")
	a = w.act("d1", "", g)
	sB := w.succession("S1")
	recB := w.recovery("C0", g, sB, "S1", "S1")
	w.handover("R0", g, recB)
	w.voidReported(w.eligibleAt(w.snap(), a, 0))
}
