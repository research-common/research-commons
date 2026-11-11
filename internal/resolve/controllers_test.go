package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/wire"
)

// Typed controllers and effective-subject slots (fixed-root identity profile §2.1, §2.2, §5.2), over real signed
// rc/2 evidence: identity inceptions, grants and cuts signed by root keys, approvals and withdrawals signed by
// delegate keys, read by the candidate dual-major reader, with the real actor evaluator (identity.Actors) over the
// same bytes. Nothing builds a Placed or an evaluator answer by hand.

// ctrlWorld is a world with identity I (root key IR) whose grants name one resource exactly.
type ctrlWorld struct {
	*world
	I string
}

func newCtrlWorld(t *testing.T, workers ...string) *ctrlWorld {
	w := newWorld(t)
	for _, k := range workers {
		w.authored(k+"-0", k, k+"-zero") // each worker's seq-0 line: the delegate inception its grant pins
	}
	i := w.signRC2("I", "IR", "identity_inception", obj("profile", wire.FixedRootProfile), rc2MarkerOnly, [2]string{})
	return &ctrlWorld{world: w, I: i}
}

// grant signs a grant of I to worker for the given kinds over exactly resource.
func (w *ctrlWorld) grant(name, worker, resource string, kinds ...string) string {
	var perms canon.Array
	for _, k := range kinds {
		perms = append(perms, obj("kind", k, "targets", obj("resources", []string{resource})))
	}
	slices.SortFunc(perms, func(a, b canon.Value) int { return canon.CompareKeys(string(canon.Encode(a)), string(canon.Encode(b))) })
	return w.signRC2(name, "IR", "identity_grant", obj("identity", w.I,
		"delegate", obj("key", w.signer(worker), "inception", w.firstLine(worker)), "permissions", perms), rc2MarkerOnly, [2]string{})
}

// subjects is a typed controller set: "I" names the identity, any other name the key of that name.
func (w *ctrlWorld) subjects(names ...string) canon.Array {
	var out canon.Array
	for _, n := range names {
		if n == "I" {
			out = append(out, obj("identity", w.I))
		} else {
			out = append(out, obj("key", w.signer(n)))
		}
	}
	slices.SortFunc(out, func(a, b canon.Value) int { return canon.CompareKeys(string(canon.Encode(a)), string(canon.Encode(b))) })
	return out
}

func ruleOf(k int) *canon.Object {
	if k <= 1 {
		return obj("any_one", true)
	}
	return obj("k_of_n", obj("k", k))
}

// genesis2 signs an rc/2 genesis by key by (genesis is raw-key only).
func (w *ctrlWorld) genesis2(name, by string, k int, controllers ...string) string {
	return w.signRC2(name, by, "genesis", obj("type", "collection", "name", "typed", "controllers", w.subjects(controllers...),
		"rule", ruleOf(k)), rc2MarkerOnly, [2]string{})
}

// body2 is an rc/2 edition body (the marker added at signing).
func body2(resource string, preds []string, contents *canon.Object) *canon.Object {
	p := slices.Clone(preds)
	slices.Sort(p)
	return obj("resource", resource, "predecessors", p, "contents", contents)
}

// edID2 is the rc/2 edition id of a body as signed (with the marker): the v2 edition-body domain.
func edID2(b *canon.Object) string {
	st := &wire.Statement{RC: "rc/2", Body: withMember(b, wire.IdentityCrit, obj())}
	return EditionIDOf(st)
}

// approve signs an rc/2 approval of b by key by: raw (grant "") or for I under grant.
func (w *ctrlWorld) approve(name, by string, b *canon.Object, grant string) string {
	if grant == "" {
		return w.signRC2(name, by, "edition", b, rc2MarkerOnly, [2]string{})
	}
	return w.signRC2(name, by, "edition", b, rc2Actor, [2]string{w.I, grant})
}

// withdraw2 signs an rc/2 withdraw_approval of edition eid by key by for I under grant.
func (w *ctrlWorld) withdraw2(name, by, resource, eid, grant string) string {
	return w.signRC2(name, by, "withdraw_approval", obj("resource", resource, "edition", eid), rc2Actor, [2]string{w.I, grant})
}

// resolveCtrl resolves resource id over every line through the dual reader, with the real evaluator (or none),
// in sampled delivery orders; every order must give the same rendered view.
func (w *ctrlWorld) resolveCtrl(id string, withEvaluator bool, check func(*Resource)) {
	w.t.Helper()
	var opts []Option
	if withEvaluator {
		actors, err := identity.NewActors(w.lines)
		if err != nil {
			w.t.Fatal(err)
		}
		opts = append(opts, WithActorEligibility(actors))
	}
	first := ""
	for _, o := range append([][]int{nil}, sampleOrders(len(w.lines), 0xc7a1, 3)...) {
		in := w.lines
		if o != nil {
			in = make([][]byte, len(o))
			for i, j := range o {
				in[i] = w.lines[j]
			}
		}
		s := dualStore()
		if n := deliverAll(s, in); n != 0 {
			w.t.Fatalf("%d lines refused", n)
		}
		res, ok := New(s, opts...).Resource(id)
		if !ok {
			w.t.Fatalf("resource %s did not resolve", keylog.Short(id))
		}
		if first == "" {
			first = res.Render()
			check(res)
		} else if got := res.Render(); got != first {
			w.t.Fatalf("delivery order changed the view: %s", firstDiff(first, got))
		}
	}
}

func edState(t *testing.T, res *Resource, eid string, want EditionState, explain string) *Edition {
	t.Helper()
	for _, e := range res.Editions {
		if e.ID == eid {
			if e.State != want {
				t.Fatalf("edition %s: %s, want %s\n%s", keylog.Short(eid), e.State, want, res.Render())
			}
			if explain != "" && !strings.Contains(strings.Join(e.Explain, "\n"), explain) {
				t.Fatalf("edition %s: explain %q lacks %q\n%s", keylog.Short(eid), e.Explain, explain, res.Render())
			}
			return e
		}
	}
	t.Fatalf("no edition %s\n%s", keylog.Short(eid), res.Render())
	return nil
}

func approvalOf(t *testing.T, e *Edition, stmt string) Approval {
	t.Helper()
	for _, a := range e.Approvals {
		if a.Statement == stmt {
			return a
		}
	}
	t.Fatalf("no approval %s on %s", keylog.Short(stmt), keylog.Short(e.ID))
	return Approval{}
}

// C-id-24, C-id-25: approvals of one rc/2 body by different signers with different actors are one edition; two
// delegates of I fill I's one slot; a raw approval by a listed key fills that key's slot.
func TestTypedControllerSlotsSharedBody(t *testing.T) {
	conformance.Covers(t, "C-id-24")
	conformance.Covers(t, "C-id-25")
	w := newCtrlWorld(t, "K1", "K2")
	g := w.genesis2("G", "GK", 2, "I", "B")
	g1 := w.grant("G1", "K1", g, "edition")
	g2 := w.grant("G2", "K2", g, "edition")
	b := body2(g, []string{g}, obj("members", canon.Array{}))
	eid := edID2(b)
	a1 := w.approve("A1", "K1", b, g1)
	a2 := w.approve("A2", "K2", b, g2)
	w.resolveCtrl(g, true, func(res *Resource) {
		e := edState(t, res, eid, Pending, "1 of 2 approvals")
		if len(e.Approvals) != 2 || e.Major != 2 {
			t.Fatalf("one body, two approvals, v2 domain: %+v", e)
		}
		for _, a := range []string{a1, a2} {
			if x := approvalOf(t, e, a); !x.Counted || x.Subject.Identity != w.I || x.Subject.Key != "" {
				t.Fatalf("delegate approval %+v", x)
			}
		}
		if len(res.GenesisControllers) != 2 || res.GenesisK != 2 {
			t.Fatalf("typed genesis authority %+v k=%d", res.GenesisControllers, res.GenesisK)
		}
	})
	ab := w.approve("AB", "B", b, "")
	w.resolveCtrl(g, true, func(res *Resource) {
		e := edState(t, res, eid, Authorized, "2 approval(s)")
		if x := approvalOf(t, e, ab); !x.Counted || x.Subject.Key != w.signer("B") {
			t.Fatalf("raw approval %+v", x)
		}
		if res.Current != eid || res.VerifyExit() != 0 {
			t.Fatalf("current %s exit %d", res.Current, res.VerifyExit())
		}
	})
	// No evaluator (every production reader): the identity approvals fill nothing, with the hook-absent text,
	// and never count as their keys.
	w.resolveCtrl(g, false, func(res *Resource) {
		e := edState(t, res, eid, Pending, "1 of 2 approvals")
		for _, a := range []string{a1, a2} {
			if x := approvalOf(t, e, a); x.Counted || x.Doubted || x.Subject != (Controller{}) || !strings.Contains(x.Why, "identity profile not active") {
				t.Fatalf("identity approval without an evaluator %+v", x)
			}
		}
	})
}

// C-id-26: an identity approval with missing authority (a grant for another resource, or no `edition`) fills no
// slot, not even the key slot its signer holds; a root's raw signature never fills I's slot.
func TestTypedControllerSlotsNoFallback(t *testing.T) {
	conformance.Covers(t, "C-id-26")
	w := newCtrlWorld(t, "B", "K1")
	g := w.genesis2("G", "GK", 1, "I", "B")
	other := w.genesis2("OTHER", "GK", 1, "I")
	gb := w.grant("GB", "B", g, "withdraw_approval") // no `edition`
	gk := w.grant("GK1", "K1", other, "edition")     // another resource
	b := body2(g, []string{g}, obj("members", canon.Array{}))
	eid := edID2(b)
	ab := w.approve("AB", "B", b, gb)
	ak := w.approve("AK", "K1", b, gk)
	ar := w.approve("AR", "IR", b, "")
	w.resolveCtrl(g, true, func(res *Resource) {
		e := edState(t, res, eid, Unauthorized, "unauthorized under")
		if x := approvalOf(t, e, ab); x.Counted || x.Doubted || x.Subject.Key != "" || !strings.Contains(x.Why, "scope_excluded") {
			t.Fatalf("B's identity approval without `edition` %+v", x)
		}
		if x := approvalOf(t, e, ak); x.Counted || x.Doubted || !strings.Contains(x.Why, "scope_excluded") {
			t.Fatalf("K1's approval under another resource's grant %+v", x)
		}
		if x := approvalOf(t, e, ar); !x.Counted || x.Subject.Key != w.signer("IR") {
			t.Fatalf("root raw approval is key(IR)'s word %+v", x)
		}
	})
}

// C-id-27: one key's raw approval and its identity approval of the same body are two signatures for two subjects;
// neither fills both slots.
func TestTypedControllerSlotsRawAndIdentity(t *testing.T) {
	conformance.Covers(t, "C-id-27")
	w := newCtrlWorld(t, "B")
	g := w.genesis2("G", "GK", 2, "I", "B")
	gb := w.grant("GB", "B", g, "edition")
	b := body2(g, []string{g}, obj("members", canon.Array{}))
	eid := edID2(b)
	ai := w.approve("AI", "B", b, gb)
	w.resolveCtrl(g, true, func(res *Resource) {
		edState(t, res, eid, Pending, "1 of 2 approvals") // the identity approval fills I only
	})
	ar := w.approve("AR", "B", b, "")
	w.resolveCtrl(g, true, func(res *Resource) {
		e := edState(t, res, eid, Authorized, "2 approval(s)")
		if approvalOf(t, e, ai).Subject.Identity != w.I || approvalOf(t, e, ar).Subject.Key != w.signer("B") {
			t.Fatalf("two subjects expected\n%s", res.Render())
		}
	})
	// The raw approval alone fills B only.
	w2 := newCtrlWorld(t, "B")
	g2 := w2.genesis2("G", "GK", 2, "I", "B")
	b2 := body2(g2, []string{g2}, obj("members", canon.Array{}))
	w2.approve("AR", "B", b2, "")
	w2.resolveCtrl(g2, true, func(res *Resource) { edState(t, res, edID2(b2), Pending, "1 of 2 approvals") })
}

// C-id-28: an rc/2 controller change carries complete typed controllers and rule (the wire refuses partial,
// untyped and duplicate shapes: TestCandidateResourceKindsRead); it is authorized under its predecessor's rule and
// its successors under its own; an rc/1 key-only resource adopts typed controllers only through an edition its
// rc/1 controllers authorize; a merge of predecessors with different authority must declare both; and an rc/1 and
// an rc/2 approval of the same body bytes are two editions.
func TestTypedControllerChangesAndMerges(t *testing.T) {
	conformance.Covers(t, "C-id-28")
	w := newCtrlWorld(t, "K1")
	g := w.genesis("G", "A", 0, "A") // rc/1, key controller A
	gk := w.grant("GK1", "K1", g, "edition")
	adopt := body2(g, []string{g}, obj("members", canon.Array{}, "controllers", w.subjects("I"), "rule", ruleOf(1)))
	e1 := edID2(adopt)
	// K1 for I cannot adopt: I is not a controller of the rc/1 genesis
	w.approve("E1-by-I", "K1", adopt, gk)
	w.resolveCtrl(g, true, func(res *Resource) { edState(t, res, e1, Unauthorized, "unauthorized under") })
	w.approve("E1", "A", adopt, "") // A's raw rc/2 approval, under the rc/1 rule
	next := body2(g, []string{e1}, obj("members", canon.Array{}))
	e2 := edID2(next)
	w.approve("E2-by-A", "A", next, "") // A is no longer a controller
	w.resolveCtrl(g, true, func(res *Resource) {
		e := edState(t, res, e1, Authorized, "any one of {"+shortKey(w.signer("A")))
		if len(e.Controllers) != 1 || e.Controllers[0].Identity != w.I {
			t.Fatalf("adopted authority %+v", e.Controllers)
		}
		edState(t, res, e2, Unauthorized, "unauthorized under "+keylog.Short(e1)+": any one of {identity:")
	})
	w.approve("E2", "K1", next, gk)
	w.resolveCtrl(g, true, func(res *Resource) {
		edState(t, res, e2, Authorized, "authorized under "+keylog.Short(e1))
		if res.Current != e2 {
			t.Fatalf("current %s", res.Current)
		}
	})
	// A branch keeps key A (an rc/1 edition authorized under the genesis); a merge of it and E2 must declare both.
	side := w.edition("SIDE", "A", g, []string{g}, []string{"s"})
	merge := body2(g, []string{e2, w.ed(side)}, obj("members", canon.Array{}))
	w.approve("M-A", "A", merge, "")
	w.approve("M-I", "K1", merge, gk)
	w.resolveCtrl(g, true, func(res *Resource) {
		edState(t, res, edID2(merge), Invalid, "must declare both")
	})
	// rc/1 and rc/2 approvals of byte-identical bodies are two editions (the id domain is the major's).
	same := obj("resource", g, "predecessors", []string{g}, "contents", obj("members", canon.Array{}), wire.IdentityCrit, obj())
	v1 := w.sign("V1", "A", "edition", same)
	if EditionID(same) == edID2(obj("resource", g, "predecessors", []string{g}, "contents", obj("members", canon.Array{}))) {
		t.Fatal("rc/1 and rc/2 edition ids coincide")
	}
	w.resolveCtrl(g, true, func(res *Resource) {
		e := edState(t, res, w.ed(v1), Authorized, "")
		if e.Major != 1 || len(e.Approvals) != 1 {
			t.Fatalf("rc/1 approval of the same bytes joined an rc/2 edition: %+v", e)
		}
	})
}

// C-id-29: withdrawal is key-and-grant-local. One delegate cannot withdraw another's approval; a new grant does
// not let the same key cancel an approval made under another; the key's withdrawal under the same grant does.
func TestTypedControllerWithdrawalIsKeyAndGrantLocal(t *testing.T) {
	conformance.Covers(t, "C-id-29")
	w := newCtrlWorld(t, "K1", "K2")
	g := w.genesis2("G", "GK", 1, "I")
	g1 := w.grant("G1", "K1", g, "edition", "withdraw_approval")
	g2 := w.grant("G2", "K2", g, "edition", "withdraw_approval")
	g1b := w.grant("G1b", "K1", g, "edition", "withdraw_approval")
	b := body2(g, []string{g}, obj("members", canon.Array{}))
	eid := edID2(b)
	a1 := w.approve("A1", "K1", b, g1)
	w.withdraw2("W2", "K2", g, eid, g2) // K2 never approved: withdraws nothing of K1's
	w.withdraw2("W1b", "K1", g, eid, g1b)
	w.resolveCtrl(g, true, func(res *Resource) {
		e := edState(t, res, eid, Authorized, "")
		if x := approvalOf(t, e, a1); !x.Counted || x.Withdrawn != "" {
			t.Fatalf("another delegate or another grant withdrew K1's approval: %+v", x)
		}
	})
	w1 := w.withdraw2("W1", "K1", g, eid, g1)
	w.resolveCtrl(g, true, func(res *Resource) {
		e := edState(t, res, eid, Pending, "after withdrawal")
		if x := approvalOf(t, e, a1); x.Withdrawn != w1 {
			t.Fatalf("K1's withdrawal under its own grant: %+v", x)
		}
		if res.Current != g {
			t.Fatalf("current %s", res.Current)
		}
	})
	// Without an evaluator an identity withdrawal is no one's word: it takes nothing back (and the approval it
	// would have withdrawn never counted either).
	w.resolveCtrl(g, false, func(res *Resource) {
		e := edState(t, res, eid, Unauthorized, "")
		if approvalOf(t, e, a1).Withdrawn != "" {
			t.Fatal("an identity withdrawal applied without an evaluator")
		}
	})
}

// C-id-30: a cut that removes a required approval makes the edition and its dependants contested, never authorized
// and never silently unauthorized; so does unresolved identity state that would decide the slot.
func TestTypedControllerCutContests(t *testing.T) {
	conformance.Covers(t, "C-id-30")
	w := newCtrlWorld(t, "K1", "K2")
	g := w.genesis2("G", "GK", 1, "I")
	g1 := w.grant("G1", "K1", g, "edition")
	g2 := w.grant("G2", "K2", g, "edition")
	keep := w.head["K1"] // K1's seq-0 line: the cut's last_good
	b := body2(g, []string{g}, obj("members", canon.Array{}))
	eid := edID2(b)
	a1 := w.approve("A1", "K1", b, g1)
	nb := body2(g, []string{eid}, obj("members", canon.Array{}))
	nid := edID2(nb)
	w.approve("N", "K2", nb, g2)
	w.resolveCtrl(g, true, func(res *Resource) {
		edState(t, res, eid, Authorized, "")
		edState(t, res, nid, Authorized, "")
	})
	w.signRC2("CUT", "IR", "identity_cut", obj("identity", w.I, "grant", g1, "last_good", keep, "reason", "key_compromise"), rc2MarkerOnly, [2]string{})
	w.resolveCtrl(g, true, func(res *Resource) {
		e := edState(t, res, eid, Contested, "doubted")
		if x := approvalOf(t, e, a1); x.Counted || !x.Doubted || !strings.Contains(x.Why, "cut_excluded") {
			t.Fatalf("cut approval %+v", x)
		}
		edState(t, res, nid, Contested, "is contested")
		if res.VerifyExit() != 3 || len(res.Contested) != 2 {
			t.Fatalf("contested %v exit %d", res.Contested, res.VerifyExit())
		}
		// Today's reading (as for a key revocation's contested editions, C-core-143e): the authorized graph is
		// the genesis alone, so `current` names the genesis beside the contested list and verify exits 3.
		if res.Current != g || !strings.Contains(res.Render(), "contested: ") {
			t.Fatalf("current %s\n%s", res.Current, res.Render())
		}
	})
	// Unresolved identity state (an authenticated root-lineage event this reader does not understand): every act
	// for I reads unknown, and an edition that needs one is contested.
	u := newCtrlWorld(t, "K1")
	ug := u.genesis2("G", "GK", 1, "I")
	ug1 := u.grant("G1", "K1", ug, "edition")
	u.signRC2("FUTURE", "IR", "identity_future_event", obj("note", "x"), rc2MarkerOnly, [2]string{})
	ub := body2(ug, []string{ug}, obj("members", canon.Array{}))
	ua := u.approve("A1", "K1", ub, ug1)
	u.resolveCtrl(ug, true, func(res *Resource) {
		e := edState(t, res, edID2(ub), Contested, "not established")
		if x := approvalOf(t, e, ua); !x.Doubted {
			t.Fatalf("unknown eligibility not doubted %+v", x)
		}
		if res.VerifyExit() != 3 {
			t.Fatal("contested resource passed verify")
		}
	})
}
