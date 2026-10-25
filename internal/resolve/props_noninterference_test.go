package resolve

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
)

// P-03 over resources, membership and observations/corroboration (the artifact view's version is
// TestNonInterferenceProperty). The scenario: for a reachable state S and a statement L from a key Q with no
// authority over X and no bearing on the reader's predicate for X, result_X(S+L) equals result_X(S).
//
// "No authority over X" is the same in every view: Q signs no statement of S, is not a controller of any
// authorized edition of the resource, and is not X's observer or author.
//
// "No bearing on the reader's predicate for X" is made precise per view, because what a reader's answer reads
// differs (spec finding PROPS-F2):
//
//	resource G          L does not name G (in `resource`, `about.resource`, `links[].resource`) and is not an
//	                    `edition`, `withdraw_approval` or key event of a controller. Statements that DO name G
//	                    but come from a non-controller (an edition, an approval of a pending body, a withdrawal)
//	                    are tested as a second class: the decision (current edition, tips, forks, contested,
//	                    exit, every edition's state and counted approvals) is unchanged while the explanation
//	                    shows the statement, attributed and not counted.
//	membership (G, m)   L does not name m (statement id, content digest or resource id), does not name G, and
//	                    does not enter the formation (is not listed by the current edition). A rival `authored`
//	                    on the digest of a content member DOES bear: the member's record is that blob's
//	                    single-party default (C-core-22). A `holds` does not: it adds a holder and no claim
//	                    (C-core-28). An annotation (`describes` with `links` to G) names m and G: decision
//	                    unchanged, explanation shows it as "an annotation, confers nothing".
//	observation O       L does not name O's statement id, O's bytes, or a referent O's class compares (same
//	                    chain id + block hash for exact-bytes; same endpoint + parameters for source), is not a
//	                    method-class observation of O's method edition, and is not a `corroborates` whose result
//	                    names O's bytes as comparison data. A `corroborates`, `refutes`, `retracts` or `describes`
//	                    naming O from Q bears on O's explanation (held and listed, never an input to the
//	                    status); only a counted corroborates moves the status.
//
// Each class has a control that DOES bear and must change the answer, so a harness that never reached the
// view cannot pass.

const outsider = "Q"

type addition struct {
	name string
	add  func(pw *propWorld)
}

// outside is the statements of Q that name nothing the base names.
func outsideAdditions() []addition {
	apiQ := obj("endpoint", "https://other.example/q", "parameters", obj("period", "q"), "response_digest", dig("resp:q"))
	chainQ := obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("c3", 32), "depth", 7)
	return []addition{
		{"holds an unrelated blob", func(pw *propWorld) { pw.sign("L", outsider, "holds", obj("content", contentOf("ZZ"))) }},
		{"describes an unrelated blob", func(pw *propWorld) {
			pw.sign("L", outsider, "describes", obj("about", obj("content", dig("ZZ")), "note", "n"))
		}},
		{"authors an unrelated blob", func(pw *propWorld) { pw.authored("L", outsider, "ZZ", "licence", "MIT") }},
		{"observes an unrelated blob (exact-bytes, another block)", func(pw *propWorld) {
			pw.observed("L", outsider, "ZZ", "exact-bytes", chainQ)
		}},
		{"observes an unrelated blob (source, another endpoint)", func(pw *propWorld) {
			pw.observed("L", outsider, "ZZ", "source", apiQ)
		}},
		{"observes an unrelated blob (phenomenon)", func(pw *propWorld) {
			pw.phenomenon("L", outsider, "ZZ", "instrument-q", "era-q")
		}},
		{"corroborates its own unrelated observation", func(pw *propWorld) {
			o := pw.observed("LO", outsider, "ZZ", "source", apiQ)
			pw.corroborates("L", outsider, o, strings.Repeat("ab", 32), "supports")
		}},
		{"anchors its own log", func(pw *propWorld) {
			pw.authored("LA", outsider, "ZZ")
			pw.anchor("L", outsider, "btc:101")
		}},
		{"rotates its own key", func(pw *propWorld) { pw.sign("L", outsider, "rotate_key", obj("successor", pw.signer("QZ"))) }},
		{"revokes its own key", func(pw *propWorld) {
			pw.authored("LA", outsider, "ZZ")
			pw.revoke("L", outsider, "key_compromise")
		}},
		{"withdraws an approval of a resource nobody holds", func(pw *propWorld) {
			pw.sign("L", outsider, "withdraw_approval", obj("resource", unheldID("g"), "edition", unheldID("e")))
		}},
	}
}

func withOutsider(t *testing.T, f fixture.Fixture, a addition) (*propWorld, [][]byte) {
	pw := concretize(t, f)
	base := len(pw.lines)
	a.add(pw)
	if len(pw.lines) == base {
		t.Fatalf("%s: added no statement", a.name)
	}
	return pw, pw.lines
}

// resourceDecision is every part of the resource view a reader acts on, without the explanation.
func resourceDecision(res *Resource) string {
	h, es := resourceParts(res)
	return h + strings.Join(es, "")
}

// resourceParts is the decision's header and one line per edition, by edition id.
func resourceParts(res *Resource) (string, []string) {
	var b strings.Builder
	fmt.Fprintf(&b, "current=%s tips=%v forks=%d contested=%v exit=%d noController=%v revoked=%v\n", res.Current, res.Tips, len(res.Forks), res.Contested,
		res.VerifyExit(), res.NoController, sortedKeys(res.RevokedControllers))
	// Approval.Counted means the line chains and its signer's key events let it count, not that the signer is a
	// controller (PROPS-F3), so approvals are not part of the decision: the edition's state is.
	var es []string
	for _, e := range res.Editions {
		es = append(es, fmt.Sprintf("%s %s after=%v controllers=%v k=%d\n", e.ID, e.State, e.Predecessors, e.Controllers, e.K))
	}
	return b.String(), es
}

// sameDecision compares two decisions where after may hold more editions than before (an outsider's edition is
// listed), every one of which must not be authorized: the editions that existed keep their line.
func sameDecision(before, after *Resource) string {
	bh, be := resourceParts(before)
	ah, ae := resourceParts(after)
	if bh != ah {
		return "header:\n" + firstDiff(bh, ah)
	}
	for _, l := range be {
		if !slices.Contains(ae, l) {
			return "an edition changed: " + l
		}
	}
	for _, l := range ae {
		if !slices.Contains(be, l) && strings.Contains(l, " authorized ") {
			return "an outsider's edition is authorized: " + l
		}
	}
	return ""
}

func TestPropertyNonInterferenceResources(t *testing.T) {
	conformance.Partial(t, "P-03", "resources, membership and observations here (and authorship in TestNonInterferenceProperty); the gates (pull, hub CI, push, pre-pin) are P-04's and are not built; tasks and the exchange view are built elsewhere")
	for _, a := range outsideAdditions() {
		t.Run(a.name, func(t *testing.T) {
			fixture.Check(t, propBaseSeed+3000, 12, fixture.Extended, func(f fixture.Fixture) string {
				before := concretize(t, f)
				r0 := New(storeOf(t, before.deliver(nil)), propOpts()...)
				res0, ok := r0.Resource(before.g)
				if !ok {
					return "base resource not resolved"
				}
				pw, _ := withOutsider(t, f, a)
				r1 := New(storeOf(t, pw.deliver(nil)), propOpts()...)
				res1, _ := r1.Resource(pw.g)
				if res0.Render() != res1.Render() || resourceDecision(res0) != resourceDecision(res1) {
					return "the resource answer changed:\n" + firstDiff(res0.Render(), res1.Render())
				}
				return ""
			})
		})
	}

	// statements that name the resource but come from a key with no authority over it
	t.Run("outsider edition and approvals name G and decide nothing", func(t *testing.T) {
		fixture.Check(t, propBaseSeed+3100, 12, fixture.Extended, func(f fixture.Fixture) string {
			pw := concretize(t, f)
			// a second resource that needs two of its controllers, with a pending edition by one of them
			g2 := pw.genesis("G2", "K1", 2, "K1", "K2") // keys outside the fixture, whose logs have no gap
			body := pw.editionBody(g2, []string{g2}, []string{"m"})
			pw.sign("E2A", "K1", "edition", body)
			read := func(pw *propWorld) (*Resource, *Resource) {
				r := New(storeOf(t, pw.deliver(nil)), propOpts()...)
				a, _ := r.Resource(pw.g)
				b, _ := r.Resource(g2)
				return a, b
			}
			b1, b2 := read(pw)
			for i, add := range []func(){
				func() { pw.sign("Q1", outsider, "edition", body) }, // approves the byte-identical pending body
				func() {
					pw.editionWith("Q2", outsider, g2, []string{g2}, "members", entries(Entry("content", dig("q"), "member")))
				},
				func() {
					pw.editionWith("Q3", outsider, pw.g, []string{pw.g}, "members", entries(Entry("content", dig("q"), "member")))
				},
				func() {
					pw.sign("Q4", outsider, "withdraw_approval", obj("resource", g2, "edition", pw.ed(pw.ids["E2A"])))
				},
				func() {
					pw.sign("Q5", outsider, "withdraw_approval", obj("resource", pw.g, "edition", pw.ed(pw.ids["E1"])))
				},
			} {
				add()
				a, b := read(pw)
				if d := sameDecision(b1, a); d != "" {
					return "an outsider's statement changed the decision on G: " + d
				}
				if d := sameDecision(b2, b); d != "" {
					return "an outsider's statement changed the decision on G2: " + d
				}
				// an outsider's edition is shown, attributed to it (a withdrawal of nobody's approval is not shown)
				if i < 3 && !strings.Contains(a.Render()+b.Render(), shortKey(pw.signer(outsider))) {
					return "the outsider's edition is not shown, attributed:\n" + a.Render() + b.Render()
				}
			}
			return ""
		})
	})

	// control: a controller's edition does change the resource
	t.Run("control: a controller's edition bears on the resource", func(t *testing.T) {
		pw := concretize(t, fixture.Gen(propBaseSeed, fixture.Extended))
		r := New(storeOf(t, pw.deliver(nil)), propOpts()...)
		res0, _ := r.Resource(pw.g)
		pw.editionWith("L", "C", pw.g, []string{pw.g}, "members", entries(Entry("content", dig("q"), "member")))
		res1, _ := New(storeOf(t, pw.deliver(nil)), propOpts()...).Resource(pw.g)
		if resourceDecision(res0) == resourceDecision(res1) {
			t.Fatal("a controller's edition changed nothing: the harness does not reach the resource view")
		}
	})
}

func TestPropertyNonInterferenceMembership(t *testing.T) {
	conformance.Partial(t, "P-03", "membership here; see TestPropertyNonInterferenceResources")
	mem := func(pw *propWorld) map[string]string {
		r := New(storeOf(t, pw.deliver(nil)), propOpts()...)
		out := map[string]string{}
		for _, k := range append(pw.members(r), pw.ids["M1"], pw.ids["O1"], dig("X")) {
			if m, ok := r.Membership(pw.g, k); ok {
				out[k] = m.Render()
			}
		}
		return out
	}
	decision := func(pw *propWorld) map[string]string {
		r := New(storeOf(t, pw.deliver(nil)), propOpts()...)
		out := map[string]string{}
		for _, k := range []string{pw.ids["M1"], pw.ids["O1"], dig("X")} {
			if m, ok := r.Membership(pw.g, k); ok {
				out[k] = fmt.Sprint(m.Listed, m.Endorsed, m.Outcome, m.Role, m.Edition)
			}
		}
		return out
	}
	same := func(a, b map[string]string) string {
		for k, v := range a {
			if b[k] != v {
				return k + ":\n" + firstDiff(v, b[k])
			}
		}
		return ""
	}
	for _, a := range outsideAdditions() {
		t.Run(a.name, func(t *testing.T) {
			fixture.Check(t, propBaseSeed+4000, 12, fixture.Extended, func(f fixture.Fixture) string {
				before := mem(concretize(t, f))
				pw, _ := withOutsider(t, f, a)
				if d := same(before, mem(pw)); d != "" {
					return "membership changed: " + d
				}
				return ""
			})
		})
	}
	t.Run("holds on a member's own blob adds a holder and no claim (C-core-28)", func(t *testing.T) {
		fixture.Check(t, propBaseSeed+4100, 12, fixture.Extended, func(f fixture.Fixture) string {
			before := mem(concretize(t, f))
			pw := concretize(t, f)
			pw.sign("L", outsider, "holds", obj("content", contentOf("X")))
			pw.sign("L2", outsider, "holds", obj("content", contentOf("M1")))
			if d := same(before, mem(pw)); d != "" {
				return "a holds changed membership: " + d
			}
			return ""
		})
	})
	t.Run("an annotation names the member and G: decision unchanged, explanation shows it", func(t *testing.T) {
		fixture.Check(t, propBaseSeed+4200, 12, fixture.Extended, func(f fixture.Fixture) string {
			before := decision(concretize(t, f))
			pw := concretize(t, f)
			pw.sign("L", outsider, "describes", obj("about", obj("statement", pw.ids["M1"]), "links", canon.Array{obj("resource", pw.g, "rel", "part-of")}, "note", "mine"))
			if d := same(before, decision(pw)); d != "" {
				return "an annotation changed a decision: " + d
			}
			r := New(storeOf(t, pw.deliver(nil)), propOpts()...)
			m, _ := r.Membership(pw.g, pw.ids["M1"])
			if !strings.Contains(m.Render(), "an annotation, confers nothing") {
				return "the annotation is not shown:\n" + m.Render()
			}
			return ""
		})
	})
	t.Run("control: a rival authored on a content member's digest bears (C-core-22)", func(t *testing.T) {
		pw := concretize(t, fixture.Gen(propBaseSeed, fixture.Extended))
		before := decision(pw)
		before2 := mem(pw)
		pw.authored("L", outsider, "X", "licence", "GPL-3.0-only")
		if same(before2, mem(pw)) == "" {
			t.Fatalf("a rival authored on the member's digest changed nothing: the harness does not reach membership (%v)", before)
		}
	})
}

func TestPropertyNonInterferenceObservations(t *testing.T) {
	conformance.Partial(t, "P-03", "observations/corroboration here; see TestPropertyNonInterferenceResources")
	obsAnswers := func(pw *propWorld) (full, status map[string]string) {
		r := New(storeOf(t, pw.deliver(nil)), propOpts()...)
		full, status = map[string]string{}, map[string]string{}
		for _, p := range r.byKind["observed"] {
			if o, ok := r.Observation(p.St.ID); ok {
				full[p.St.ID] = o.Render()
				c := o.Corroboration
				status[p.St.ID] = fmt.Sprint(c.Status(), c.Corroborated, c.Contradicted, c.Unchecked, o.ReferentStatus, o.Capture.Display, o.Class, o.Counts)
			}
		}
		return
	}
	// only the observations that exist before L are compared; L's own are new
	diff := func(a, b map[string]string) string {
		for k, v := range a {
			if b[k] != v {
				return keyShort(k) + ":\n" + firstDiff(v, b[k])
			}
		}
		return ""
	}
	for _, a := range outsideAdditions() {
		t.Run(a.name, func(t *testing.T) {
			fixture.Check(t, propBaseSeed+5000, 12, fixture.Extended, func(f fixture.Fixture) string {
				full, _ := obsAnswers(concretize(t, f))
				pw, _ := withOutsider(t, f, a)
				after, _ := obsAnswers(pw)
				if d := diff(full, after); d != "" {
					return "an observation's answer or explanation changed: " + d
				}
				return ""
			})
		})
	}
	// statements that name O from a key with no authority over it: the status and referent status are the
	// observer's and the evidence's, so they do not move; the explanation lists them as held, not an input
	t.Run("retracts, refutes and describes naming O change the explanation only", func(t *testing.T) {
		fixture.Check(t, propBaseSeed+5100, 12, fixture.Extended, func(f fixture.Fixture) string {
			pw := concretize(t, f)
			_, status := obsAnswers(pw)
			o1 := pw.ids["O1"]
			pw.sign("L1", outsider, "retracts", obj("of", o1))
			pw.sign("L2", outsider, "refutes", obj("of", o1, "evidence", dig("E")))
			pw.sign("L3", outsider, "describes", obj("about", obj("statement", o1), "note", "n"))
			full, after := obsAnswers(pw)
			if d := diff(status, after); d != "" {
				return "a statement with no authority moved a status: " + d
			}
			if !strings.Contains(full[o1], "(not an input to the status)") || !strings.Contains(full[o1], "names another key's statement: changes nothing") {
				return "the held statements are not listed as not inputs:\n" + full[o1]
			}
			return ""
		})
	})
	t.Run("control: a corroborates by Q moves the status", func(t *testing.T) {
		pw := concretize(t, fixture.Gen(propBaseSeed, fixture.Extended))
		_, before := obsAnswers(pw)
		pw.corroborates("L", outsider, pw.ids["O1"], pw.ids["RES"], "supports")
		_, after := obsAnswers(pw)
		if diff(before, after) == "" {
			t.Fatal("a counted corroboration changed nothing: the harness does not reach corroboration")
		}
	})
	t.Run("control: a same-referent capture by Q bears", func(t *testing.T) {
		pw := concretize(t, fixture.Gen(propBaseSeed, fixture.Extended))
		full, _ := obsAnswers(pw)
		pw.observed("L", outsider, "X", "exact-bytes", chainRef(9))
		after, _ := obsAnswers(pw)
		if diff(full, after) == "" {
			t.Fatal("a capture of the same referent changed nothing")
		}
	})
}
