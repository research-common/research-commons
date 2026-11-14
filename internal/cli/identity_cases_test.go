package cli

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/wire"
)

// Identity cases run through the commands: rc/2 lines signed by the test builders (identity_rc2_helpers_test.go),
// committed into a store, optionally carried by pull, and read by show, verify and explain. Each case builds the
// evidence the case names, holds only the part a reader would hold, and asserts what the command prints.

// actorView is what `show <id> --json` prints about one statement's actor claim.
type actorView struct {
	state, identity, grant, counted, reasons string
}

func actorOf(t *testing.T, w *world, id string) actorView {
	t.Helper()
	o := showJSON(t, w, id)
	str := func(v canon.Value) string { s, _ := v.(canon.String); return string(s) }
	reasons := ""
	if r := member(o, "actor", "reasons"); r != nil {
		reasons = string(canon.Encode(r))
	}
	return actorView{state: str(member(o, "actor", "state")), identity: str(member(o, "actor", "identity")),
		grant: str(member(o, "actor", "grant")), counted: str(o.Members["counted"]), reasons: reasons}
}

// holding commits the named statements of w (by w.ids name, in the order given) into a fresh store.
func holding(t *testing.T, w *world, names ...string) *world {
	t.Helper()
	lines, err := w.s.Statements()
	if err != nil {
		t.Fatal(err)
	}
	h := newWorld(t)
	for _, n := range names {
		id, ok := w.ids[n]
		if !ok || lines[id] == nil {
			t.Fatalf("no statement %q", n)
		}
		if _, err := h.s.Commit("publish", [][]byte{lines[id]}, nil); err != nil {
			t.Fatalf("%s: %v", n, err)
		}
	}
	return h
}

// readers returns the two ways a reader holds evidence: committed directly, and carried by pull into a fresh store.
func readers(h *world) map[string]*world {
	return map[string]*world{"held": h, "pulled": h.pullInto()}
}

// anyPerms is a grant's one `authored` permission over any content, with the amend mode.
func anyPerms(amend bool) canon.Array {
	return canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", amend)}
}

// TestIdentityCasesMissingEvidence: held evidence missing one of I, G, D or an ancestor, or a root event outside the
// closed vocabulary on I's lineage, reads `unknown` and counts toward nothing, through show on a direct store and a
// pulled one; the full set is the control (eligible, counted).
func TestIdentityCasesMissingEvidence(t *testing.T) {
	w := newWorld(t)
	w.worker("K1")
	_, a := w.identityOf("I", "IR", canon.Bool(true), "K1")
	grant := a["K1"][1]
	w.ids["G"] = grant
	a0 := w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
	a1 := w.signRC2("A1", "K1", "authored", licBody("Y", "MIT"), a["K1"])
	w.authored("RD", "IR", "Z") // an rc/1 authored on the root's own log after the grant: outside the closed vocabulary
	if v := actorOf(t, holding(t, w, "first:K1", "I", "G", "A0"), a0); v.state != "eligible" || v.counted != "counted" {
		t.Fatalf("control: %+v", v)
	}
	for _, c := range []struct {
		name  string
		held  []string
		act   string
		names string // what the printed reasons name
	}{
		{"no inception", []string{"first:K1", "G", "A0"}, a0, "identity inception"},
		{"no grant", []string{"first:K1", "I", "A0"}, a0, "grant"},
		{"no delegate inception", []string{"I", "G", "A0"}, a0, "delegate inception"},
		{"no ancestor", []string{"first:K1", "I", "G", "A1"}, a1, "statement ancestry"},
		{"unsupported root event", []string{"first:K1", "I", "G", "A0", "RD"}, a0, "unsupported_root_event"},
	} {
		for how, d := range readers(holding(t, w, c.held...)) {
			t.Run(c.name+"/"+how, func(t *testing.T) {
				v := actorOf(t, d, c.act)
				if v.state != "unknown" || v.counted != "not counted" || !strings.Contains(v.reasons, c.names) {
					t.Fatalf("%+v", v)
				}
			})
		}
	}
}

// rootAlt makes name a second log of root's key (a rival lineage: its seq 0 differs from the root's own).
func (w *world) rootAlt(name, root string) {
	w.keys[name] = w.key(root)
}

// TestIdentityCasesRivalLineage: a rival seq-0 inception by the root key, or a rival seq-0 line of the delegate's
// key, is a different lineage. A grant on the rival inception never authorizes a claim of I; a grant pinning the
// wrong delegate line (a head, or the key's rival seq 0) never authorizes the delegate; each reads `denied` naming
// the lineage, through a direct store and a pulled one. The rival identity's own grant stays eligible for the rival
// (it is another identity), and I's own acts are untouched.
func TestIdentityCasesRivalLineage(t *testing.T) {
	w := newWorld(t)
	w.worker("K1")
	w.worker("K2")
	w.worker("K3")
	i, a := w.identityOf("I", "IR", canon.Bool(true), "K1")
	w.ids["G1"] = a["K1"][1]
	w.rootAlt("IRx", "IR")
	j := w.signRC2("J", "IRx", "identity_inception", obj("profile", wire.FixedRootProfile, "n", 2), [2]string{})
	del := func(k string, inc string) *canon.Object { return obj("key", w.signer(k), "inception", inc) }

	// a grant on the rival inception, naming I (its prev chain does not reach I's inception)
	gr := w.signRC2("Grival", "IRx", "identity_grant", obj("identity", i, "delegate", del("K2", w.ids["first:K2"]), "permissions", anyPerms(true)), [2]string{})
	bRival := w.signRC2("B0", "K2", "authored", licBody("X", "MIT"), [2]string{i, gr})
	// the rival identity's own grant is good for the rival
	gj := w.signRC2("Gj", "IRx", "identity_grant", obj("identity", j, "delegate", del("K2", w.ids["first:K2"]), "permissions", anyPerms(true)), [2]string{})
	bJ := w.signRC2("B1", "K2", "authored", licBody("Y", "MIT"), [2]string{j, gj})
	// a grant by the root on I's own lineage, pinning the delegate's head instead of its inception
	a0 := w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
	gh := w.signRC2("Ghead", "IR", "identity_grant", obj("identity", i, "delegate", del("K3", a0), "permissions", anyPerms(true)), [2]string{})
	cHead := w.signRC2("C0", "K3", "authored", licBody("X", "MIT"), [2]string{i, gh})
	// a grant pinning the delegate key's rival seq 0 (a different line of the same key)
	w.rootAlt("K3x", "K3")
	r0 := w.signRC2("K3rival", "K3x", "authored", obj("content", canon.Value(content("rival-K3")), "type", "dataset"), [2]string{})
	gp := w.signRC2("Gpin", "IR", "identity_grant", obj("identity", i, "delegate", del("K3", r0), "permissions", anyPerms(true)), [2]string{})
	cPin := w.signRC2("C1", "K3", "authored", licBody("W", "MIT"), [2]string{i, gp})

	all := []string{"first:K1", "first:K2", "first:K3", "I", "G1", "J", "Grival", "Gj", "A0", "Ghead", "Gpin", "K3rival", "B0", "B1", "C0", "C1"}
	for how, d := range readers(holding(t, w, all...)) {
		t.Run(how, func(t *testing.T) {
			for _, c := range []struct{ name, act, code string }{
				{"grant on a rival inception naming I", bRival, "wrong_lineage: grant root ancestry"},
				{"grant pinning a head", cHead, "delegate_pin_not_inception"},
				{"grant pinning the key's rival seq 0", cPin, "wrong_lineage: statement ancestry"},
			} {
				v := actorOf(t, d, c.act)
				if v.state != "denied" || v.counted != "not counted" || v.identity != i || !strings.Contains(v.reasons, c.code) {
					t.Fatalf("%s: %+v", c.name, v)
				}
			}
			if v := actorOf(t, d, bJ); v.state != "eligible" || v.identity != j || v.counted != "counted" {
				t.Fatalf("the rival identity's own grant: %+v", v)
			}
			if v := actorOf(t, d, a0); v.state != "eligible" || v.identity != i || v.counted != "counted" {
				t.Fatalf("I's own act moved: %+v", v)
			}
		})
	}
}

// TestIdentityCasesWrongSignerIdentityGrant: an actor statement signed by a key other than the grant's delegate, a
// grant not signed by I's root, a grant whose delegate is the root (in a store of its own: the root's act is itself
// a line on the root's log), an actor naming a grant as its identity and an actor naming one identity with another's
// grant are each `denied` with the named reason through show, on a direct store and a pulled one, and count toward
// nothing. The same statement signed correctly is the control.
func TestIdentityCasesWrongSignerIdentityGrant(t *testing.T) {
	w := newWorld(t)
	for _, n := range []string{"K1", "K2", "S"} {
		w.worker(n)
	}
	i, a := w.identityOf("I", "IR", canon.Bool(true), "K1")
	w.ids["G1"] = a["K1"][1]
	ctrl := w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
	// a key other than the delegate signs under K1's grant
	wrongKey := w.signRC2("B0", "K2", "authored", licBody("X", "MIT"), a["K1"])
	// a stranger issues a grant naming I
	gs := w.signRC2("Gs", "S", "identity_grant", obj("identity", i, "delegate", obj("key", w.signer("K2"), "inception", w.ids["first:K2"]), "permissions", anyPerms(true)), [2]string{})
	byStranger := w.signRC2("B1", "K2", "authored", licBody("Y", "MIT"), [2]string{i, gs})
	// the grant named as the identity; another identity named with I's grant
	asIdentity := w.signRC2("B2", "K2", "authored", licBody("W", "MIT"), [2]string{a["K1"][1], a["K1"][1]})
	w.rootAlt("JR", "S")
	j := w.signRC2("J", "JR", "identity_inception", obj("profile", wire.FixedRootProfile, "n", 3), [2]string{})
	wrongI := w.signRC2("A1", "K1", "authored", licBody("V", "MIT"), [2]string{j, a["K1"][1]})

	all := []string{"first:K1", "first:K2", "first:S", "I", "G1", "Gs", "J", "A0", "B0", "B1", "B2", "A1"}
	for how, d := range readers(holding(t, w, all...)) {
		t.Run(how, func(t *testing.T) {
			if v := actorOf(t, d, ctrl); v.state != "eligible" || v.counted != "counted" {
				t.Fatalf("control: %+v", v)
			}
			for _, c := range []struct{ name, act, code string }{
				{"key other than the delegate", wrongKey, "wrong_delegate"},
				{"grant not signed by the root", byStranger, "wrong_signer"},
				{"grant named as the identity", asIdentity, "invalid_identity_inception"},
				{"another identity with I's grant", wrongI, "wrong_grant_identity"},
			} {
				v := actorOf(t, d, c.act)
				if v.state != "denied" || v.counted != "not counted" || !strings.Contains(v.reasons, c.code) {
					t.Fatalf("%s: %+v", c.name, v)
				}
			}
		})
	}
}

// TestIdentityCasesRootAsDelegate: a grant whose delegate is the root key itself never authorizes an act, whatever
// the act: `denied` root_is_delegate through show, direct and pulled.
func TestIdentityCasesRootAsDelegate(t *testing.T) {
	w := newWorld(t)
	i := w.signRC2("I", "IR", "identity_inception", obj("profile", wire.FixedRootProfile), [2]string{})
	w.ids["first:IR"] = i
	selfG := w.grantTo("Gself", "IR", i, "IR", obj("any_content", true), canon.Bool(true))
	w.ids["Gself"] = selfG[1]
	act := w.signRC2("R1", "IR", "authored", licBody("Z", "MIT"), selfG)
	for how, d := range readers(holding(t, w, "I", "Gself", "R1")) {
		t.Run(how, func(t *testing.T) {
			if v := actorOf(t, d, act); v.state != "denied" || v.counted != "not counted" || !strings.Contains(v.reasons, "root_is_delegate") {
				t.Fatalf("%+v", v)
			}
		})
	}
}
