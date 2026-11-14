package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
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
	conformance.Partial(t, "C-id-07", "through show on a direct and a pulled store: a missing inception, grant, delegate inception or ancestor, and an in-lineage root event outside the closed vocabulary, read unknown, not counted, never eligible; the printed reasons name the kind of what is missing (identity inception, grant, delegate inception, statement ancestry; unsupported_root_event), not its statement id, so `naming each missing or unsupported id` is not met")
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
// (it is another identity), and I's own acts are untouched. An act signed on a rival seq-0 line of the delegate's
// key, under a grant that pins the real inception, is on another lineage too.
func TestIdentityCasesRivalLineage(t *testing.T) {
	conformance.Covers(t, "C-id-03")
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

	// an act under K1's own, correct grant, but signed on a rival seq-0 line of K1's key (not the pinned inception)
	w.forkAt("K1x", "K1", "", 0)
	kRival := w.rawLine("K1rival", "K1x", "K1", "rc/2", "authored", "", nil, licBody("V", "MIT"), a["K1"])

	all := []string{"first:K1", "first:K2", "first:K3", "I", "G1", "J", "Grival", "Gj", "A0", "Ghead", "Gpin", "K3rival", "B0", "B1", "C0", "C1", "K1rival"}
	for how, d := range readers(holding(t, w, all...)) {
		t.Run(how, func(t *testing.T) {
			for _, c := range []struct{ name, act, code string }{
				{"act on the delegate key's rival seq-0 line", kRival, "wrong_lineage"},
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
// grant not signed by I's root, a grant whose delegate is the root (in a world of its own: the root's act is itself
// a line on the root's log), an actor naming a grant as its identity and an actor naming one identity with another's
// grant are each `denied` with the named reason through show, on a direct store and a pulled one, and count toward
// nothing. The same statement signed correctly is the control.
func TestIdentityCasesWrongSignerIdentityGrant(t *testing.T) {
	conformance.Covers(t, "C-id-05")
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

	// a grant whose delegate is the root key itself never authorizes an act, whatever the act
	rw := newWorld(t)
	ri := rw.signRC2("I", "IR", "identity_inception", obj("profile", wire.FixedRootProfile), [2]string{})
	rw.ids["first:IR"] = ri
	selfG := rw.grantTo("Gself", "IR", ri, "IR", obj("any_content", true), canon.Bool(true))
	rw.ids["Gself"] = selfG[1]
	bySelf := rw.signRC2("R1", "IR", "authored", licBody("Z", "MIT"), selfG)
	for how, d := range readers(holding(t, rw, "I", "Gself", "R1")) {
		t.Run("root is delegate/"+how, func(t *testing.T) {
			if v := actorOf(t, d, bySelf); v.state != "denied" || v.counted != "not counted" || !strings.Contains(v.reasons, "root_is_delegate") {
				t.Fatalf("%+v", v)
			}
		})
	}
}

// rawLine signs and commits one line of key keyName at an explicit position: log names the chain whose head and
// next seq it advances (two logs over one key make a fork), prev "" is a first line, merges are listed as given.
// rc is "rc/1" for a bare line or "rc/2" with actor (empty actor: a marker-only rc/2 line, as the root's own).
func (w *world) rawLine(name, log, keyName, rc, kind string, prev string, merges []string, body *canon.Object, actor [2]string) string {
	w.t.Helper()
	k := w.key(keyName)
	if _, ok := w.keys[log]; !ok {
		w.keys[log] = k
	}
	seq := w.seq[log]
	if prev == "" {
		prev = w.head[log]
	}
	var line []byte
	var id string
	if rc == "rc/2" {
		d := wire.Draft{RC: "rc/2", Kind: kind, Seq: seq, Prev: prev, Merges: merges, TS: fmt.Sprintf("2026-10-16T05:%02d:%02dZ", seq/60%60, seq%60),
			Crit: []string{wire.IdentityCrit}, Body: body}
		if _, ok := body.Get(wire.IdentityCrit); !ok {
			d.Body = withMember(body, wire.IdentityCrit, obj())
		}
		env := d.Envelope(k)
		if actor[0] != "" {
			env = withMember(env, wire.ActorField, obj("grant", actor[1], "identity", actor[0]))
		}
		ss := wire.PAE(wire.PayloadType(kind, 2), canon.Encode(env))
		line, id = canon.Encode(withMember(env, "sig", canon.String(k.Sign(ss)))), wire.ID(ss)
	} else {
		line, id = wire.Sign(wire.Draft{Kind: kind, Seq: seq, Prev: prev, Merges: merges, TS: fmt.Sprintf("2026-10-16T05:%02d:%02dZ", seq/60%60, seq%60), Body: body}, k)
	}
	if _, err := w.s.Commit("publish", [][]byte{line}, nil); err != nil {
		w.t.Fatalf("%s: %v", name, err)
	}
	w.ids[name] = id
	w.head[log], w.seq[log] = id, seq+1
	return id
}

// forkAt starts log as a second chain of key keyName whose next line follows prev at seq.
func (w *world) forkAt(log, keyName, prev string, seq int64) {
	w.keys[log] = w.key(keyName)
	w.head[log], w.seq[log] = prev, seq
}

// actorBytes is show's output for id with the evaluator's evidence digest and receipt removed: the answer about the
// statement itself, which another statement's evidence must not change.
func actorBytes(t *testing.T, w *world, id string) string {
	t.Helper()
	r := w.run("show", id, "--json")
	if r.code != ExitOK {
		t.Fatalf("show: %d %s", r.code, r.stdout)
	}
	s := r.stdout
	i := strings.Index(s, `"identity_evaluator"`)
	if i < 0 {
		t.Fatalf("no evaluator block: %s", s)
	}
	j := strings.Index(s[i:], "}") + i + 1
	return s[:i] + s[j:]
}

func nullCut(i, grant string) *canon.Object {
	return obj("identity", i, "grant", grant, "last_good", canon.Null{}, "reason", "key_compromise")
}

func cutAt(i, grant, lastGood string) *canon.Object {
	return obj("identity", i, "grant", grant, "last_good", lastGood, "reason", "key_compromise")
}

// TestIdentityCasesOneKeyTwoIdentities: key K holds grants from identity I and identity J. Each statement acts for
// exactly the actor it names (show), I's and J's answers do not change when the other identity's evidence is held
// or cut, an actor naming one identity with the other's grant is denied, and an act of I that names a claim of J as
// its amendment target applies to nothing (explain) and does not move J's claim. Through a direct and a pulled store.
func TestIdentityCasesOneKeyTwoIdentities(t *testing.T) {
	conformance.Covers(t, "C-id-06")
	w := newWorld(t)
	w.worker("K")
	i, a := w.identityOf("I", "IR", canon.Bool(true), "K")
	gI := a["K"][1]
	w.ids["GI"] = gI
	j := w.signRC2("J", "JR", "identity_inception", obj("profile", wire.FixedRootProfile), [2]string{})
	gJ := w.grantTo("J", "JR", j, "K", obj("any_content", true), canon.Bool(true))
	w.ids["GJ"] = gJ[1]
	aI := w.signRC2("AI", "K", "authored", licBody("X", "MIT"), a["K"])
	aJ := w.signRC2("AJ", "K", "authored", licBody("Y", "Apache-2.0"), gJ)
	cross := w.signRC2("AXI", "K", "authored", licBody("Z", "MIT"), [2]string{j, gI})
	// I's act amending J's claim on the same blob; J's claim is a different principal's
	jc := w.signRC2("JC", "K", "authored", licBody("W", "GPL-3.0"), gJ)
	amendJ := w.signRC2("IA", "K", "authored", amendingBody("W", "CC0-1.0", jc), a["K"])

	onlyI := []string{"first:K", "I", "GI", "AI"}
	withJ := append(slicesClone(onlyI), "J", "GJ", "AJ", "AXI", "JC", "IA")
	for how, d := range readers(holding(t, w, withJ...)) {
		t.Run(how, func(t *testing.T) {
			if v := actorOf(t, d, aI); v.state != "eligible" || v.identity != i || v.grant != gI {
				t.Fatalf("AI: %+v", v)
			}
			if v := actorOf(t, d, aJ); v.state != "eligible" || v.identity != j || v.grant != gJ[1] {
				t.Fatalf("AJ: %+v", v)
			}
			if v := actorOf(t, d, cross); v.state != "denied" || v.counted != "not counted" || !strings.Contains(v.reasons, "wrong_grant_identity") {
				t.Fatalf("J named with I's grant: %+v", v)
			}
			// J's claim is untouched by I's amendment naming it: explain says it amends nothing
			if ex := d.run("explain", dig("W")); !strings.Contains(ex.stdout, "amends nothing") {
				t.Fatalf("explain W:\n%s", ex.stdout)
			}
			if v := actorOf(t, d, amendJ); v.state != "eligible" || v.identity != i {
				t.Fatalf("the amending act is still I's own act: %+v", v)
			}
			if r := d.run("verify", dig("W"), "--json"); !strings.Contains(r.stdout, "GPL-3.0") {
				t.Fatalf("J's licence on W moved: %s", r.stdout)
			}
			// adding J's evidence leaves I's answer about AI byte-identical (evaluator digest aside)
			alone := actorBytes(t, holding(t, w, onlyI...), aI)
			if got := actorBytes(t, d, aI); got != alone {
				t.Fatalf("I's answer moved when J's evidence arrived:\n%s\nvs\n%s", alone, got)
			}
		})
	}
	// a null cut of J's grant: J's act is cut_excluded, I's acts by the same key are untouched; and the reverse
	w.signRC2("CJ", "JR", "identity_cut", nullCut(j, gJ[1]), [2]string{})
	d := w.pullInto()
	if v := actorOf(t, d, aJ); v.state != "denied" || !strings.Contains(v.reasons, "cut_excluded") {
		t.Fatalf("AJ after J's cut: %+v", v)
	}
	for _, id := range []string{aI, amendJ} {
		if v := actorOf(t, d, id); v.state != "eligible" || v.identity != i {
			t.Fatalf("I's act after J's cut: %+v", v)
		}
	}
	if got := actorBytes(t, d, aI); got != actorBytes(t, holding(t, w, onlyI...), aI) {
		t.Fatalf("J's cut moved I's answer")
	}
	w.signRC2("CI", "IR", "identity_cut", nullCut(i, gI), [2]string{})
	d = w.pullInto()
	if v := actorOf(t, d, aI); v.state != "denied" || !strings.Contains(v.reasons, "cut_excluded") {
		t.Fatalf("AI after I's cut: %+v", v)
	}
	// vice versa: with only I's cut held, J's act by the same key is untouched
	d = holding(t, w, append(slicesClone(withJ), "CI")...).pullInto()
	if v := actorOf(t, d, aJ); v.state != "eligible" || v.identity != j {
		t.Fatalf("AJ moved by I's cut: %+v", v)
	}
}

func slicesClone(s []string) []string { return append([]string(nil), s...) }

// TestIdentityCasesCutsThroughCommands: cuts read through show on a direct and a pulled store.
//
//   - C-id-11: a cut at L keeps exactly L's inclusive prev+merges closure: L and its ancestors stay eligible; its
//     descendants and a sibling fork of the delegate's log read `denied` (cut_excluded); another grant of the same
//     identity and a grant of another identity held by the same key are unaffected.
//   - C-id-16: a grant issued on a second fork of the root's log stands beside the first; a cut of the first grant
//     and a root line merging the forks never reopens it and never cuts the second.
//   - C-id-12: several cuts of one grant intersect (never newest, widest or union), a null cut excludes everything,
//     a later wider cut never reopens the grant, and the order the cuts are held in changes nothing.
//   - C-id-14: after the grant is cut to nothing, a new grant to the same key and inception cannot relabel the old
//     bytes: the act signed under the old grant stays denied under it, the act under the new grant is eligible,
//     and re-signing the same body under the new grant is a different statement id.
func TestIdentityCasesCutsThroughCommands(t *testing.T) {
	conformance.Covers(t, "C-id-11", "C-id-12", "C-id-14", "C-id-16")
	// --- C-id-11 ---
	w := newWorld(t)
	w.worker("K1")
	w.worker("K2")
	i, a := w.identityOf("I", "IR", canon.Bool(true), "K1", "K2")
	g1, g2 := a["K1"][1], a["K2"][1]
	w.ids["G1"], w.ids["G2"] = g1, g2
	l := w.signRC2("L", "K1", "authored", licBody("X", "MIT"), a["K1"])    // seq 1 (seq 0 is the worker's first line)
	l1 := w.signRC2("L1", "K1", "authored", licBody("X1", "MIT"), a["K1"]) // descendant
	l2 := w.signRC2("L2", "K1", "authored", licBody("X2", "MIT"), a["K1"]) // descendant
	w.forkAt("K1f", "K1", w.ids["first:K1"], 1)                            // a sibling of L: same parent, its own branch
	sib := w.rawLine("SIB", "K1f", "K1", "rc/2", "authored", "", nil, licBody("S", "MIT"), a["K1"])
	b1 := w.signRC2("B1", "K2", "authored", licBody("B", "MIT"), a["K2"]) // another grant of I, another key
	w.rootAlt("JR2", "JR")
	j := w.signRC2("J", "JR2", "identity_inception", obj("profile", wire.FixedRootProfile), [2]string{})
	gj := w.grantTo("J", "JR2", j, "K1", obj("any_content", true), canon.Bool(true))
	w.ids["GJ"] = gj[1]
	aj := w.signRC2("AJ", "K1", "authored", licBody("J1", "MIT"), gj) // J's act by K1, after L2 on K1's log
	rootHead, rootSeq := w.head["IR"], w.seq["IR"]
	w.signRC2("C", "IR", "identity_cut", cutAt(i, g1, l), [2]string{})
	all := []string{"first:K1", "first:K2", "I", "G1", "G2", "L", "L1", "L2", "SIB", "B1", "J", "GJ", "AJ", "C"}
	for how, d := range readers(holding(t, w, all...)) {
		t.Run("11/"+how, func(t *testing.T) {
			if v := actorOf(t, d, l); v.state != "eligible" || v.counted != "counted" {
				t.Fatalf("L: %+v", v)
			}
			for n, id := range map[string]string{"L1": l1, "L2": l2, "sibling": sib} {
				if v := actorOf(t, d, id); v.state != "denied" || v.counted != "not counted" || !strings.Contains(v.reasons, "cut_excluded") {
					t.Fatalf("%s: %+v", n, v)
				}
			}
			if v := actorOf(t, d, b1); v.state != "eligible" || v.counted != "counted" {
				t.Fatalf("another grant of I: %+v", v)
			}
			if v := actorOf(t, d, aj); v.state != "eligible" || v.identity != j {
				t.Fatalf("another identity's grant to the same key: %+v", v)
			}
		})
	}

	// the closure includes merges: a delegate line that merges the sibling fork is kept by a cut at it, with the
	// sibling, while a descendant of it is not
	w.forkAt("K1m", "K1", l2, 4)
	mg := w.rawLine("MG", "K1m", "K1", "rc/2", "authored", "", []string{sib}, licBody("M", "MIT"), a["K1"])
	after := w.rawLine("AFTER", "K1m", "K1", "rc/2", "authored", "", nil, licBody("M2", "MIT"), a["K1"])
	// the cut at the merge line sits on its own fork of the root's log; the cut at L is not held here, so the only
	// cut of G1 is the one at the merge line
	w.forkAt("IRm", "IR", rootHead, rootSeq)
	w.rawLine("C2", "IRm", "IR", "rc/2", "identity_cut", "", nil, cutAt(i, g1, mg), [2]string{})
	mergeHeld := []string{"first:K1", "first:K2", "I", "G1", "G2", "L", "L1", "L2", "SIB", "MG", "AFTER", "C2"}
	for how, d := range readers(holding(t, w, mergeHeld...)) {
		t.Run("11 merges/"+how, func(t *testing.T) {
			for n, id := range map[string]string{"L": l, "L1": l1, "L2": l2, "sibling": sib, "merge line": mg} {
				if v := actorOf(t, d, id); v.state != "eligible" || v.counted != "counted" {
					t.Fatalf("%s kept by the cut at the merge line: %+v", n, v)
				}
			}
			if v := actorOf(t, d, after); v.state != "denied" || !strings.Contains(v.reasons, "cut_excluded") {
				t.Fatalf("a descendant of the merge line: %+v", v)
			}
		})
	}

	// --- C-id-16 ---
	w = newWorld(t)
	w.worker("K1")
	w.worker("K2")
	i, a = w.identityOf("I", "IR", canon.Bool(true), "K1")
	g1 = a["K1"][1]
	w.ids["G1"] = g1
	// the second root fork: a second grant issued on a fork of the root's log at the inception (same key, prev = I)
	w.forkAt("IRf", "IR", i, 1)
	perms := canon.Array{obj("kind", "authored", "targets", obj("any_content", true), "amend", false)}
	gf := w.rawLine("GF", "IRf", "IR", "rc/2", "identity_grant", "", nil,
		obj("identity", i, "delegate", obj("key", w.signer("K2"), "inception", w.ids["first:K2"]), "permissions", perms), [2]string{})
	a1 := w.signRC2("A1", "K1", "authored", licBody("X", "MIT"), a["K1"])
	b1 = w.signRC2("BF", "K2", "authored", licBody("Y", "MIT"), [2]string{i, gf})
	cutHead := w.signRC2("C1", "IR", "identity_cut", nullCut(i, g1), [2]string{})
	m := w.rawLine("M", "IR", "IR", "rc/1", "describes", "", []string{gf}, obj("about", obj("statement", i), "note", "merge forks"), [2]string{})
	_ = cutHead
	all = []string{"first:K1", "first:K2", "I", "G1", "GF", "A1", "BF", "C1", "M"}
	for how, d := range readers(holding(t, w, all...)) {
		t.Run("16/"+how, func(t *testing.T) {
			if v := actorOf(t, d, b1); v.state != "eligible" || v.grant != gf || v.counted != "counted" {
				t.Fatalf("the grant on the second fork after the cut and the merge: %+v", v)
			}
			if v := actorOf(t, d, a1); v.state != "denied" || !strings.Contains(v.reasons, "cut_excluded") {
				t.Fatalf("the cut grant stays cut after the merge: %+v", v)
			}
			if r := d.run("show", m, "--json"); r.code != ExitOK {
				t.Fatalf("the merge line is not held: %d %s", r.code, r.stdout)
			}
		})
	}
	// the forks without the merge give the same answers
	d0 := holding(t, w, "first:K1", "first:K2", "I", "G1", "GF", "A1", "BF", "C1")
	if v := actorOf(t, d0, b1); v.state != "eligible" || v.grant != gf {
		t.Fatalf("the second fork before the merge: %+v", v)
	}
	if v := actorOf(t, d0, a1); v.state != "denied" {
		t.Fatalf("the cut grant before the merge: %+v", v)
	}

	// --- C-id-12 ---
	// Cuts of one grant, signed on the root's log in the order a case names (or each on its own fork of the root's
	// log, so no cut is the other's ancestor): the answer is the intersection whatever the order.
	cutsOf := func(forked bool, order ...string) (*world, [3]string) {
		w := newWorld(t)
		w.worker("K1")
		i, a := w.identityOf("I", "IR", canon.Bool(true), "K1")
		g := a["K1"][1]
		ps := [3]string{}
		for k, n := range []string{"P1", "P2", "P3"} {
			ps[k] = w.signRC2(n, "K1", "authored", licBody(fmt.Sprint("X", k), "MIT"), a["K1"])
		}
		root, rootSeq := w.head["IR"], w.seq["IR"]
		held := []string{"first:K1", "I", "P1", "P2", "P3"}
		w.ids["G1"] = g
		held = append(held, "G1")
		for k, c := range order {
			var body *canon.Object
			switch c {
			case "p1", "p2", "p3":
				body = cutAt(i, g, ps[c[1]-'1'])
			case "null":
				body = nullCut(i, g)
			}
			if forked {
				w.forkAt(fmt.Sprint("IRc", k), "IR", root, rootSeq)
				w.rawLine("C"+fmt.Sprint(k), fmt.Sprint("IRc", k), "IR", "rc/2", "identity_cut", "", nil, body, [2]string{})
			} else {
				w.signRC2("C"+fmt.Sprint(k), "IR", "identity_cut", body, [2]string{})
			}
			held = append(held, "C"+fmt.Sprint(k))
		}
		return holding(t, w, held...), ps
	}
	// every order of three cuts gives the intersection
	var orders [][]string
	var permute func(rest, done []string)
	permute = func(rest, done []string) {
		if len(rest) == 0 {
			orders = append(orders, done)
			return
		}
		for k := range rest {
			permute(append(slicesClone(rest[:k]), rest[k+1:]...), append(slicesClone(done), rest[k]))
		}
	}
	permute([]string{"p1", "p2", "p3"}, nil)
	for _, forked := range []bool{false, true} {
		for _, o := range orders {
			h, ps := cutsOf(forked, o...)
			for how, d := range readers(h) {
				t.Run(fmt.Sprint("12/forked=", forked, "/", o, "/", how), func(t *testing.T) {
					for k, want := range [3]string{"eligible", "denied", "denied"} {
						if v := actorOf(t, d, ps[k]); v.state != want {
							t.Fatalf("p%d: %+v, want %s", k+1, v, want)
						}
					}
				})
			}
		}
		for _, c := range []struct {
			name  string
			order []string
			want  [3]string
		}{
			{"one cut at p2", []string{"p2"}, [3]string{"eligible", "eligible", "denied"}},
			{"p2 then p1: the intersection", []string{"p2", "p1"}, [3]string{"eligible", "denied", "denied"}},
			{"p1 then p2: the same", []string{"p1", "p2"}, [3]string{"eligible", "denied", "denied"}},
			{"a later wider cut never reopens", []string{"p1", "p3"}, [3]string{"eligible", "denied", "denied"}},
			{"a wider cut first, then the narrow one", []string{"p3", "p1"}, [3]string{"eligible", "denied", "denied"}},
			{"the null cut excludes everything", []string{"null"}, [3]string{"denied", "denied", "denied"}},
			{"null among wider cuts: still everything", []string{"p3", "null", "p2"}, [3]string{"denied", "denied", "denied"}},
			{"a later wider cut after null never reopens", []string{"null", "p3"}, [3]string{"denied", "denied", "denied"}},
		} {
			h, ps := cutsOf(forked, c.order...)
			for how, d := range readers(h) {
				t.Run(fmt.Sprint("12/forked=", forked, "/", c.name, "/", how), func(t *testing.T) {
					for k, id := range ps {
						v := actorOf(t, d, id)
						if v.state != c.want[k] || (v.state == "denied" && (!strings.Contains(v.reasons, "cut_excluded") || v.counted != "not counted")) ||
							(v.state == "eligible" && v.counted != "counted") {
							t.Fatalf("p%d: %+v, want %s", k+1, v, c.want[k])
						}
					}
				})
			}
		}
	}

	// --- C-id-14 ---
	w = newWorld(t)
	w.worker("K1")
	i, a = w.identityOf("I", "IR", canon.Bool(true), "K1")
	g1 = a["K1"][1]
	w.ids["G1"] = g1
	old := w.signRC2("Old", "K1", "authored", licBody("X", "MIT"), a["K1"])
	w.signRC2("Cn", "IR", "identity_cut", nullCut(i, g1), [2]string{})
	a3 := w.grantTo("G3", "IR", i, "K1", obj("any_content", true), canon.Bool(true))
	w.ids["G3"] = a3[1]
	nw := w.signRC2("New", "K1", "authored", licBody("X2", "MIT"), a3)
	re := w.signRC2("Re", "K1", "authored", licBody("X", "MIT"), a3) // the old act's body, signed anew under G3
	if re == old {
		t.Fatal("re-signing under another grant produced the same id")
	}
	for how, d := range readers(holding(t, w, "first:K1", "I", "G1", "Old", "Cn", "G3", "New", "Re")) {
		t.Run("14/"+how, func(t *testing.T) {
			if v := actorOf(t, d, old); v.state != "denied" || v.grant != g1 || !strings.Contains(v.reasons, "cut_excluded") {
				t.Fatalf("the old act is judged under its own grant: %+v", v)
			}
			for _, id := range []string{nw, re} {
				if v := actorOf(t, d, id); v.state != "eligible" || v.grant != a3[1] || v.counted != "counted" {
					t.Fatalf("under the new grant: %+v", v)
				}
			}
		})
	}
}

// cutWorld is identity I with grants G1 (K1) and G2 (K2), K1's acts A1, A2 and K2's B1; the root's log is
// I, G1, G2 and then whatever cut a case signs. It returns the world and the ids.
func cutWorld(t *testing.T) (w *world, i string, ids map[string]string) {
	t.Helper()
	w = newWorld(t)
	w.worker("K1")
	w.worker("K2")
	i, a := w.identityOf("I", "IR", canon.Bool(true), "K1", "K2")
	w.ids["G1"], w.ids["G2"] = a["K1"][1], a["K2"][1]
	w.signRC2("A1", "K1", "authored", licBody("X", "MIT"), a["K1"])
	w.signRC2("A2", "K1", "authored", licBody("Y", "MIT"), a["K1"])
	w.signRC2("B1", "K2", "authored", licBody("B", "MIT"), a["K2"])
	return w, i, w.ids
}

// TestIdentityCasesCutEvidenceThroughCommands:
//   - C-id-08: a held root cut of G1 whose last_good, or the ancestry that places it, is missing makes G1's acts
//     `unknown` (never `eligible`, never `denied`), not counted; another grant is unaffected.
//   - C-id-13: an authenticated root cut that is malformed, or names G1 under the wrong identity, denies G1 (never
//     ignored, so the grant is not falsely passed); a cut whose grant cannot be read makes every grant of I unknown.
func TestIdentityCasesCutEvidenceThroughCommands(t *testing.T) {
	conformance.Covers(t, "C-id-13")
	conformance.Partial(t, "C-id-08", "through show on a direct and a pulled store: a held cut whose last_good, or the ancestry placing it, is missing makes the grant's act unknown (missing_evidence), not counted, another grant unaffected; `names L` and `the cut is listed as relevant` are not printed by any surface (the reasons name only the kind of what is missing, and show prints no relevant-cut list)")
	grant := func(w *world) string { return w.ids["G1"] }
	base := []string{"first:K1", "first:K2", "I", "G1", "G2", "A1", "A2", "B1"}

	// C-id-08: last_good is A1; the cut is held with A1 missing, and with A1's ancestor (the worker's first line) missing
	w, i, ids := cutWorld(t)
	w.signRC2("C", "IR", "identity_cut", cutAt(i, grant(w), ids["A1"]), [2]string{})
	for _, c := range []struct {
		name string
		held []string
	}{
		{"last_good not held", []string{"first:K1", "first:K2", "I", "G1", "G2", "A2", "B1", "C"}},
		{"ancestry of last_good not held", []string{"first:K2", "I", "G1", "G2", "A1", "A2", "B1", "C"}},
	} {
		for how, d := range readers(holding(t, w, c.held...)) {
			t.Run("08/"+c.name+"/"+how, func(t *testing.T) {
				for _, id := range []string{ids["A2"]} {
					v := actorOf(t, d, id)
					if v.state != "unknown" || v.counted != "not counted" || !strings.Contains(v.reasons, "missing_evidence") {
						t.Fatalf("%+v", v)
					}
				}
				if v := actorOf(t, d, ids["B1"]); v.state != "eligible" || v.counted != "counted" {
					t.Fatalf("another grant: %+v", v)
				}
			})
		}
	}
	// the control: with everything held the cut at A1 keeps A1 and denies A2
	d := holding(t, w, append(slicesClone(base), "C")...)
	if v := actorOf(t, d, ids["A1"]); v.state != "eligible" {
		t.Fatalf("control A1: %+v", v)
	}
	if v := actorOf(t, d, ids["A2"]); v.state != "denied" || !strings.Contains(v.reasons, "cut_excluded") {
		t.Fatalf("control A2: %+v", v)
	}

	// C-id-13
	for _, c := range []struct {
		name  string
		mod   func(b *canon.Object, w *world)
		grant string // the state of G1's acts and the reason fragment; "" = every grant unknown
		code  string
		state string
	}{
		{"reason not a token", func(b *canon.Object, w *world) { b.Members["reason"] = canon.String("Not A Token") }, "G1", "invalid_evidence", "denied"},
		{"last_good not an id", func(b *canon.Object, w *world) { b.Members["last_good"] = canon.String("not-an-id") }, "G1", "", "denied"},
		{"identity names another inception", func(b *canon.Object, w *world) {
			b.Members["identity"] = canon.String(strings.Repeat("ab", 32))
		}, "G1", "wrong_cut_identity", "denied"},
		{"grant unreadable", func(b *canon.Object, w *world) { b.Members["grant"] = canon.String("not-an-id") }, "", "unsupported_root_event", "unknown"},
	} {
		w, i, ids := cutWorld(t)
		b := cutAt(i, grant(w), ids["A1"])
		c.mod(b, w)
		w.signRC2("C", "IR", "identity_cut", b, [2]string{})
		for how, d := range readers(holding(t, w, append(slicesClone(base), "C")...)) {
			t.Run("13/"+c.name+"/"+how, func(t *testing.T) {
				for _, id := range []string{ids["A1"], ids["A2"]} {
					v := actorOf(t, d, id)
					if v.state == "eligible" || v.counted != "not counted" || (c.state != "" && v.state != c.state) || (c.code != "" && !strings.Contains(v.reasons, c.code)) {
						t.Fatalf("G1's act %s: %+v", id[:8], v)
					}
				}
				v := actorOf(t, d, ids["B1"])
				if c.grant == "" && (v.state != "unknown" || v.counted != "not counted" || !strings.Contains(v.reasons, c.code)) {
					t.Fatalf("a cut with an unreadable grant leaves G2 standing: %+v", v)
				}
				if c.grant != "" && (v.state != "eligible" || v.counted != "counted") {
					t.Fatalf("another grant moved: %+v", v)
				}
			})
		}
	}
}

// TestIdentityCasesKeysLost: C-id-18 through the commands. After the root's key file and the delegate's key file are
// both deleted, every answer about held public evidence is byte-identical (show, verify, explain: eligible acts
// counted, the cut act denied), on the store that held them and on a fresh store that pulls them; the writers that
// need a key refuse and leave the store byte-identical.
func TestIdentityCasesKeysLost(t *testing.T) {
	conformance.Covers(t, "C-id-18")
	for _, alg := range []string{wire.AlgEd25519, wire.AlgEIP191} {
		t.Run(alg, func(t *testing.T) {
			root, worker, ident, _, grant := idSetup(t, alg, `[{"kind":"authored","targets":{"any_content":true},"amend":false}]`)
			a1 := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("a1", "one"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant))
			a2 := firstID(t, worker.ok("publish", "--kind", "authored", "--content", worker.file("a2", "two"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant))
			root.pullFrom(worker)
			root.ok("identity", "cut", "--identity", ident, "--grant", grant, "--last-good", a1, "--reason", "key_compromise")
			worker.pullFrom(root)
			dg := string(member(jsonOf(t, worker.read("show", a1)), "body", "content", "digest").(canon.String))
			questions := [][]string{{"show", a1}, {"show", a2}, {"verify", dg}, {"explain", dg}}
			answers := func(h *idHome) []string {
				var out []string
				for _, q := range questions {
					r := h.read(q...)
					out = append(out, fmt.Sprint(r.code, "\n", r.stdout))
				}
				return out
			}
			before := answers(worker)
			if v := jsonOf(t, worker.read("show", a1)); member(v, "actor", "state") != canon.String("eligible") || v.Members["counted"] != canon.String("counted") {
				t.Fatalf("control a1: %s", canon.Encode(v))
			}
			if v := jsonOf(t, worker.read("show", a2)); member(v, "actor", "state") != canon.String("denied") || v.Members["counted"] != canon.String("not counted") {
				t.Fatalf("control a2: %s", canon.Encode(v))
			}
			// every private key is gone
			for _, k := range []string{root.key, worker.key} {
				if err := os.Remove(k); err != nil {
					t.Fatal(err)
				}
			}
			if after := answers(worker); !slices.Equal(before, after) {
				t.Fatalf("an answer moved when the keys were lost:\n%q\nvs\n%q", before, after)
			}
			fresh := newIDHome(t, alg)
			fresh.pullFrom(worker)
			if got := answers(fresh); !slices.Equal(before, got) {
				t.Fatalf("a fresh reader of the same evidence answers differently:\n%q\nvs\n%q", before, got)
			}
			// the writers that need a key refuse, writing nothing
			sb := storeBytes(t, worker.store)
			if r := worker.run("publish", "--kind", "authored", "--content", worker.file("a3", "three"), "--licence", "CC0-1.0", "--as", ident, "--grant", grant); r.code == ExitOK {
				t.Fatalf("publish without its key succeeded: %s", r.stdout)
			}
			if r := root.run("identity", "cut", "--identity", ident, "--grant", grant, "--last-good", a1, "--reason", "key_compromise"); r.code == ExitOK {
				t.Fatalf("a cut without the root key succeeded: %s", r.stdout)
			}
			if storeBytes(t, worker.store) != sb {
				t.Fatal("a refused writer changed the store")
			}
		})
	}
}

// receivedPolicyInjection: C-id-33's received-policy half through the commands. Statements that
// carry a policy document (the delegate's act under its grant, a stranger's line, the root key's line on a rival
// lineage that is not I's, a policy file placed in the package beside them) change no answer: the pull trust floor
// admits and refuses exactly what it did without them, and `explain` prints the same "none configured"
// reader-policy block. A root-key line on I's own lineage is a different matter, decided by the root-event
// vocabulary (an unsupported root event makes I unknown, C-id-07): it too installs no policy, which the bare
// line's refusal shows.
func receivedPolicyInjection(t *testing.T) {
	type outcome struct {
		verdicts [2]string // I's act, the bare line
		explain  string
	}
	run := func(inject string) outcome {
		w := newWorld(t)
		w.worker("K1")
		w.worker("S")
		i, a := w.identityOf("I", "IR", canon.Bool(true), "K1")
		act := w.signRC2("A0", "K1", "authored", licBody("X", "MIT"), a["K1"])
		bare := w.authored("S0", "S", "Y", "licence", "MIT")
		doc := `{"version":"reader-policy-v1","selections":[],"trust":[{"principal":{"key":"` + w.signer("S") + `"},"purposes":["admission"],"targets":{"any_content":true}}]}`
		carrying := func() *canon.Object { return withMember(licBody("P", "MIT"), "reader_policy", obj("doc", doc)) }
		switch inject {
		case "delegate":
			w.signRC2("P", "K1", "authored", carrying(), a["K1"])
		case "stranger":
			w.sign("P", "S", "authored", carrying())
		case "root rival lineage":
			w.rootAlt("IRx", "IR")
			w.rawLine("P", "IRx", "IR", "rc/1", "authored", "", nil, carrying(), [2]string{})
		case "root lineage":
			w.signRC2("P", "IR", "authored", carrying(), [2]string{})
			w.sign("note", "IR", "describes", obj("about", obj("statement", i), "note", doc))
		}
		pf := filepath.Join(t.TempDir(), "policy.json")
		os.WriteFile(pf, []byte(`{"version":"reader-policy-v1","selections":[],"trust":[{"principal":{"identity":"`+i+`"},"purposes":["admission"],"targets":{"any_content":true}}]}`), 0o644)
		pkg := t.TempDir()
		copyData(t, w.root, pkg)
		os.WriteFile(filepath.Join(pkg, "reader-policy.json"), []byte(readerPolicyDoc(w.signer("S"))), 0o644)
		dst := newWorld(t)
		rep := jsonOf(t, dst.run("pull", pkg, "--policy", pf, "--below-floor", "refuse", "--json"))
		var o outcome
		for k, x := range []struct{ signer, id string }{{w.signer("K1"), act}, {w.signer("S"), bare}} {
			o.verdicts[k] = "admitted"
			if row := objectRow(t, rep, stmtPath(x.signer, x.id)); row != nil {
				o.verdicts[k] = string(row.Members["verdict"].(canon.String))
			}
		}
		out := dst.run("explain", dig("X")).stdout
		i0 := strings.Index(out, "reader policy:")
		o.explain = out[i0 : i0+strings.Index(out[i0:], "\nevaluator:")]
		return o
	}
	ctrl := run("")
	if ctrl.verdicts[1] != "refused" || ctrl.verdicts[0] == "refused" || !strings.Contains(ctrl.explain, "none configured") {
		t.Fatalf("control: %+v", ctrl)
	}
	for _, inj := range []string{"delegate", "stranger", "root rival lineage"} {
		if got := run(inj); got != ctrl {
			t.Fatalf("%s: a received statement changed an answer:\n%+v\nvs\n%+v", inj, got, ctrl)
		}
	}
	if got := run("root lineage"); got.verdicts[1] != "refused" || got.explain != ctrl.explain {
		t.Fatalf("root lineage: a root-signed policy-shaped statement installed policy: %+v", got)
	}
}

// TestIdentityCasesConflictingSelectionsExit2: the preflight half of C-id-32 through every command that takes a
// reader policy: two selections for one (content, role), whether two pins, a pin and a follow, or two principals,
// are refused as a reader-policy problem with exit 2 before any work, by --policy and by the environment, and the
// store is byte-identical afterwards. The same policy with one selection is accepted (the control).
func TestIdentityCasesConflictingSelectionsExit2(t *testing.T) {
	conformance.Partial(t, "C-id-32", "production preflight: conflicting selections for one content and role are exit 2 before any work on every command that takes a policy, store untouched; not covered: a missing or ineligible pinned statement reading non-passing through a command, which currently ends in an internal error (state token not in the closed vocabulary) instead of a not-met answer")
	w := fixture(t)
	i := strings.Repeat("ab", 32)
	sub := `"subject":{"content":"` + dig("sole") + `","role":"authorship-declaration"}`
	pin := func(id string) string { return `{"statement":"` + id + `",` + sub + `}` }
	follow := func(p string) string { return `{"principal":` + p + `,` + sub + `}` }
	doc := func(sels ...string) string {
		return `{"version":"reader-policy-v1","selections":[` + strings.Join(sels, ",") + `],"trust":[]}`
	}
	dir := t.TempDir()
	write := func(name, d string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(d), 0o644)
		return p
	}
	// the control selects for a blob no statement is about, so it is accepted and nothing prints a selection
	// outcome (an unmet selection on a held blob is a separate finding: see the report)
	good := write("good.json", `{"version":"reader-policy-v1","selections":[{"statement":"`+i+`","subject":{"content":"`+dig("unheld")+`","role":"authorship-declaration"}}],"trust":[]}`)
	for _, c := range []struct{ name, doc string }{
		{"two pins", doc(pin(i), pin(strings.Repeat("cd", 32)))},
		{"a pin and a follow of a key", doc(follow(`{"key":"`+w.signer("K1")+`"}`), pin(i))},
		{"a pin and a follow of an identity", doc(follow(`{"identity":"`+i+`"}`), pin(i))},
		{"two principals", doc(follow(`{"identity":"`+i+`"}`), follow(`{"key":"`+w.signer("K1")+`"}`))},
	} {
		bad := write("bad.json", c.doc)
		before := snapshot(t, w.root)
		n := 0
		for _, cmd := range Commands() {
			if !cmd.ReaderPolicy {
				continue
			}
			args := strings.Fields(cmd.Name)
			if len(cmd.Args) > 0 && !cmd.Args[0].Optional {
				args = append(args, sweepArg(w, cmd))
			}
			n++
			if r := w.run(append(args, "--policy", bad, "--json")...); r.code != 2 || !strings.Contains(r.stdout, `"class":"reader policy"`) {
				t.Fatalf("%s: %v --policy: exit %d\n%s", c.name, args, r.code, r.stdout)
			}
			if r := runIn(w.root, map[string]string{PolicyEnv: bad}, append(args, "--json")...); r.code != 2 {
				t.Fatalf("%s: %v %s: exit %d", c.name, args, PolicyEnv, r.code)
			}
		}
		if n == 0 {
			t.Fatal("no command takes a reader policy")
		}
		if snapshot(t, w.root) != before {
			t.Fatalf("%s: a refused policy changed the store", c.name)
		}
	}
	if r := w.run("list", "--policy", good, "--json"); r.code != ExitOK {
		t.Fatalf("control: one selection refused: %d\n%s", r.code, r.stdout)
	}
}

// TestIdentityCasesPinVersusFollow: C-id-31 through verify with the real evaluator. I and J each hold a claim on
// one blob (licence MIT and Apache-2.0), made by one key under two grants, and I amends its own claim. An exact pin
// selects that statement only: pinning I's first claim reads MIT though I's current claim is CC0-1.0 (no successor
// is followed); pinning J's claim reads J's value (no alias between identities). Following I reads I's current
// claim (the amendment), following J reads J's; each by a direct and a pulled store. A bare statement of the same
// key, once held, is read only by pinning it: following I or J never reads it (GPL-3.0 appears under neither).
func TestIdentityCasesPinVersusFollow(t *testing.T) {
	conformance.Partial(t, "C-id-31", "through verify with the real evaluator: an exact pin selects that statement only (no successor, no alias between identities) and a principal selection of an identity follows its eligible current claim, direct and pulled; not covered: a pin on the amendment DAG of conflicting heads, and an unmet selection (ineligible pin, an identity with no eligible claim), which currently ends in an internal error instead of a not-met answer")
	w := newWorld(t)
	w.worker("K")
	i, a := w.identityOf("I", "IR", canon.Bool(true), "K")
	j := w.signRC2("J", "JR", "identity_inception", obj("profile", wire.FixedRootProfile), [2]string{})
	gJ := w.grantTo("J", "JR", j, "K", obj("any_content", true), canon.Bool(true))
	w.ids["GJ"] = gJ[1]
	w.ids["GI"] = a["K"][1]
	i0 := w.signRC2("I0", "K", "authored", licBody("X", "MIT"), a["K"])
	j0 := w.signRC2("J0", "K", "authored", licBody("X", "Apache-2.0"), gJ)
	i1 := w.signRC2("I1", "K", "authored", amendingBody("X", "CC0-1.0", i0), a["K"])
	bare := w.authored("B0", "K", "X", "licence", "GPL-3.0")
	sub := `"subject":{"content":"` + dig("X") + `","role":"authorship-declaration"}`
	selector := map[string]string{
		"pin I's first claim":     `{"statement":"` + i0 + `",` + sub + `}`,
		"pin I's amendment":       `{"statement":"` + i1 + `",` + sub + `}`,
		"pin J's claim":           `{"statement":"` + j0 + `",` + sub + `}`,
		"follow I":                `{"principal":{"identity":"` + i + `"},` + sub + `}`,
		"follow J":                `{"principal":{"identity":"` + j + `"},` + sub + `}`,
		"pin the key's bare line": `{"statement":"` + bare + `",` + sub + `}`,
	}
	want := map[string]string{
		"pin I's first claim": "MIT", "pin I's amendment": "CC0-1.0", "pin J's claim": "Apache-2.0",
		"follow I": "CC0-1.0", "follow J": "Apache-2.0", "pin the key's bare line": "GPL-3.0",
	}
	all := []string{"first:K", "I", "GI", "J", "GJ", "I0", "J0", "I1"}
	for how, d := range readers(holding(t, w, all...)) {
		d := d
		t.Run(how, func(t *testing.T) {
			for name, sel := range selector {
				pf := filepath.Join(t.TempDir(), "p.json")
				os.WriteFile(pf, []byte(`{"version":"reader-policy-v1","selections":[`+sel+`],"trust":[]}`), 0o644)
				o := jsonOf(t, d.run("verify", dig("X"), "--policy", pf, "--json"))
				lic, _ := member(o, "disclosures", "licence", "value").(canon.String)
				state := member(o, "disclosures", "licence", "state")
				if _, ok := want[name]; !ok || name == "pin the key's bare line" {
					continue // the bare line is not held here; an unmet selection is the report's finding, not asserted
				}
				if string(lic) != want[name] || state != canon.String("default") {
					t.Fatalf("%s: licence %v %v, want %s", name, state, lic, want[name])
				}
			}
		})
	}
	// with the bare line held too: pinning it reads GPL-3.0; following I or J never reads it
	h := holding(t, w, append(slicesClone(all), "B0")...)
	for name, sel := range selector {
		pf := filepath.Join(t.TempDir(), "p.json")
		os.WriteFile(pf, []byte(`{"version":"reader-policy-v1","selections":[`+sel+`],"trust":[]}`), 0o644)
		o := jsonOf(t, h.run("verify", dig("X"), "--policy", pf, "--json"))
		lic, _ := member(o, "disclosures", "licence", "value").(canon.String)
		if w, ok := want[name]; ok && (string(lic) != w || member(o, "disclosures", "licence", "state") != canon.String("default")) {
			t.Fatalf("bare line held, %s: %q, want %s", name, lic, w)
		}
	}
}

// trustPurposeAndTargets: the purpose and target boundary of C-id-33 through pull with the real
// evaluator. An `{identity: I}` entry for admission over any content admits I's grant-covered acts on every blob
// and refuses a stranger's line; narrowed to the contents of X it admits I's act on X and refuses I's act on Y (the
// same signer, the same grant: the target is judged, not the key); an entry for another purpose (attestation)
// creates no admission floor at all, so it never admits or refuses on the admission question.
func trustPurposeAndTargets(t *testing.T) {
	w := newWorld(t)
	w.worker("K1")
	w.worker("S")
	i, a := w.identityOf("I", "IR", canon.Bool(true), "K1")
	ax := w.signRC2("AX", "K1", "authored", licBody("X", "MIT"), a["K1"])
	ay := w.signRC2("AY", "K1", "authored", licBody("Y", "MIT"), a["K1"])
	sy := w.authored("SY", "S", "Y", "licence", "MIT")
	for _, c := range []struct {
		name, purposes, targets string
		want                    [3]string // AX, AY, SY
	}{
		{"admission, any content", `["admission"]`, `{"any_content":true}`, [3]string{"admitted and labelled", "admitted and labelled", "refused"}},
		{"admission, contents of X", `["admission"]`, `{"contents":["` + dig("X") + `"]}`, [3]string{"admitted and labelled", "refused", "refused"}},
		{"attestation only", `["attestation"]`, `{"any_content":true}`, [3]string{"admitted and labelled", "admitted and labelled", "admitted and labelled"}},
	} {
		tp := filepath.Join(t.TempDir(), "t.json")
		os.WriteFile(tp, []byte(`{"version":"reader-policy-v1","selections":[],"trust":[{"principal":{"identity":"`+i+`"},"purposes":`+c.purposes+`,"targets":`+c.targets+`}]}`), 0o644)
		pkg := t.TempDir()
		copyData(t, w.root, pkg)
		rep := jsonOf(t, newWorld(t).run("pull", pkg, "--policy", tp, "--below-floor", "refuse", "--json"))
		for k, x := range []struct{ s, id string }{{w.signer("K1"), ax}, {w.signer("K1"), ay}, {w.signer("S"), sy}} {
			row := objectRow(t, rep, stmtPath(x.s, x.id))
			if row == nil || row.Members["verdict"] != canon.String(c.want[k]) {
				t.Fatalf("%s, statement %d: %s, want %s", c.name, k, canon.Encode(row), c.want[k])
			}
		}
	}
}

// TestIdentityCasesTrustBoundaries: C-id-33 through the commands, both halves: trust applies only to the named
// purpose and targets, and no received statement (a delegate's, a stranger's, the root key's on a rival lineage or on
// I's own, or a policy file in the package) installs or changes local policy.
func TestIdentityCasesTrustBoundaries(t *testing.T) {
	conformance.Covers(t, "C-id-33")
	t.Run("purposes and targets", trustPurposeAndTargets)
	t.Run("received policy", receivedPolicyInjection)
}
