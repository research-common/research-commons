package identity_test

// The published signed rc/2 vectors (docs/fixed-root-identity.signed-vectors.json), fed from their exact lines
// through the candidate reader, Admit and the actor evaluator, end to end, in both required algorithms. The
// vectors themselves check representation only; these tests check what the evaluator makes of them.

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/identitymodel"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// vchain is one algorithm's chain of the signed vectors: its positive lines by short name (the vector name
// without the chain prefix) in file order, and its negatives.
type vchain struct {
	name  string
	order []string
	pos   map[string]conformance.IdentityPositive
	neg   []conformance.IdentityNegative
}

func vectorChains(t *testing.T) []*vchain {
	t.Helper()
	v, err := conformance.LoadSignedIdentityVectors()
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]*vchain{}
	var out []*vchain
	for _, p := range v.Positive {
		c := by[p.Chain]
		if c == nil {
			c = &vchain{name: p.Chain, pos: map[string]conformance.IdentityPositive{}}
			by[p.Chain] = c
			out = append(out, c)
		}
		n := strings.TrimPrefix(p.Name, p.Chain+"-")
		c.order = append(c.order, n)
		c.pos[n] = p
	}
	for _, n := range v.Negative {
		by[n.Chain].neg = append(by[n.Chain].neg, n)
	}
	if len(out) != 2 {
		t.Fatalf("want the two required algorithms' chains, got %d", len(out))
	}
	for _, c := range out {
		for _, n := range []string{"worker-genesis", "inception", "grant", "authored", "authored-amends", "cut-last-good", "cut-null", "revoke-key"} {
			if _, ok := c.pos[n]; !ok {
				t.Fatalf("%s: no positive %q", c.name, n)
			}
		}
	}
	return out
}

func (c *vchain) lines(names ...string) [][]byte {
	var out [][]byte
	for _, n := range names {
		out = append(out, []byte(c.pos[n].Line))
	}
	return out
}

func (c *vchain) actors(t *testing.T, lines [][]byte) *identity.Actors {
	t.Helper()
	a, err := identity.NewActors(lines)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// st is the statement as the default (rc/1) reader holds the line: an rc/2 line is retained unverified with no
// actor. The evaluator answers from its own evidence by id.
func vst(t *testing.T, line string) *wire.Statement {
	t.Helper()
	st, err := wire.Read([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// TestSignedVectorsGrantCoveredActIsEligible: the published grant-covered rc/2 `authored` with x_actor_v1 is
// eligible for exactly the identity it names, with a basis naming I, G, D and the root lineage, in both
// algorithms; an `{identity: I}` corroboration entry trusts it through the evaluator, citing the evaluator; the
// worker's own bare rc/1 line is never I's.
func TestSignedVectorsGrantCoveredActIsEligible(t *testing.T) {
	conformance.Covers(t, "C-id-02")
	for _, c := range vectorChains(t) {
		t.Run(c.name, func(t *testing.T) {
			auth, inc, grant, gen := c.pos["authored"], c.pos["inception"], c.pos["grant"], c.pos["worker-genesis"]
			if auth.ActorIdentity != inc.ID || auth.ActorGrant != grant.ID {
				t.Fatalf("precondition: the vector's actor %s/%s", auth.ActorIdentity, auth.ActorGrant)
			}
			s, err := identity.Admit(c.lines("worker-genesis", "inception", "grant", "authored"))
			if err != nil {
				t.Fatal(err)
			}
			if len(s.Refused()) != 0 {
				t.Fatalf("refused %+v", s.Refused())
			}
			r := s.Evaluate(auth.ID)
			if r.Status != identitymodel.Eligible || len(r.Reasons) != 0 {
				t.Fatalf("model: %s %+v", r.Status, r.Reasons)
			}
			if string(r.Actor.Identity) != inc.ID || string(r.Grant) != grant.ID || string(r.DelegateInception) != gen.ID || string(r.RootLineage) != inc.ID {
				t.Fatalf("pins %+v", r)
			}
			for _, id := range []string{inc.ID, grant.ID, gen.ID, auth.ID} {
				if !slices.Contains(r.Basis, identitymodel.ID(id)) {
					t.Fatalf("basis lacks %s: %v", id[:12], r.Basis)
				}
			}
			a := s.Actors()
			id, state, why := a.Eligible(vst(t, auth.Line))
			if id != inc.ID || state != policy.ActorEligible {
				t.Fatalf("evaluator: (%s, %s) %v", id, state, why)
			}
			for _, n := range []string{"worker-genesis", "inception", "grant"} {
				if id, state, _ := a.Eligible(vst(t, c.pos[n].Line)); id != "" || state != policy.ActorDenied {
					t.Fatalf("%s acts for (%q, %s)", n, id, state)
				}
			}
			p, err := policy.Parse([]byte(`{"selections":[],"trust":[{"principal":{"identity":"` + inc.ID +
				`"},"purposes":["corroboration"],"targets":{"any_content":true}}],"version":"reader-policy-v1"}`))
			if err != nil {
				t.Fatal(err)
			}
			content := "sha256:" + strings.Repeat("1", 64)
			ans := p.TrustsStatement(vst(t, auth.Line), policy.PurposeCorroboration, content, a)
			if !ans.Trusted() || ans.Principal.Identity != inc.ID || ans.Evaluator != a.Evaluator() {
				t.Fatalf("trust: %s", ans)
			}
			if bare := p.TrustsStatement(vst(t, gen.Line), policy.PurposeCorroboration, content, a); bare.Trusted() {
				t.Fatalf("the worker's bare line is trusted as I's: %s", bare)
			}
		})
	}
}

// TestSignedVectorsNegativesNeverReachEligibility: every published negative is either refused at admission
// (never a fact, never asked about) or read without an actor (a bare-key statement for identity): none is ever
// eligible for an identity, and substituting it for the positive it was derived from leaves that act unheld,
// never eligible.
func TestSignedVectorsNegativesNeverReachEligibility(t *testing.T) {
	conformance.Partial(t, "C-id-37", "the published negatives (tamper, stripped actor, relabelled major, old preimage, non-canonical Ed25519) of both algorithms, end to end through the actor evaluator; marker-without-actor and unknown-critical-token shapes are checked at the reader and adapter, and no consumer reads this answer")
	for _, c := range vectorChains(t) {
		t.Run(c.name, func(t *testing.T) {
			full := c.lines(c.order...)
			for _, n := range c.neg {
				of := c.pos[strings.TrimPrefix(n.Of, c.name+"-")]
				var lines [][]byte
				for _, l := range full {
					if string(l) != of.Line {
						lines = append(lines, l)
					}
				}
				lines = append(lines, []byte(n.Delivered))
				s, err := identity.Admit(lines)
				if err != nil {
					t.Fatal(err)
				}
				a := s.Actors()
				if n.Result == "refused" {
					if len(s.Refused()) != 1 || s.Refused()[0].Index != len(lines)-1 {
						t.Fatalf("%s: refused %+v", n.Name, s.Refused())
					}
					if st, _ := s.Status(of.ID); st != "" {
						t.Fatalf("%s: the refused copy stands for %s", n.Name, of.Name)
					}
					if id, state, _ := a.Eligible(&wire.Statement{ID: of.ID, Signer: of.Signer}); id != "" || state == policy.ActorEligible {
						t.Fatalf("%s: (%q, %s) for the positive it replaced", n.Name, id, state)
					}
					continue
				}
				// read: rc/1 lines that carry or declare an identity extension are never upgraded
				st, err := wire.NewIdentityReader().Read([]byte(n.Delivered))
				if err != nil {
					t.Fatalf("%s: %v", n.Name, err)
				}
				if st.Actor != nil {
					t.Fatalf("%s: actor read", n.Name)
				}
				id, state, why := a.Eligible(st)
				if id != "" || state == policy.ActorEligible {
					t.Fatalf("%s: (%q, %s) %v", n.Name, id, state, why)
				}
			}
		})
	}
}

// TestSignedVectorsCutsAndRetirement: the published cut-at-last-good keeps exactly the act it names and denies
// the later amending act; the null cut denies both; the root's rc/1 revoke_key placed on I's lineage retires I
// for every act. Every answer stays bound to I (the denial is I's) in both algorithms.
func TestSignedVectorsCutsAndRetirement(t *testing.T) {
	conformance.Partial(t, "C-id-11", "the published cut at last_good, both algorithms, through the actor evaluator: the named act kept, its descendant excluded; siblings, merges and other grants are checked with synthetic keys at the adapter, and no consumer reads this answer")
	for _, c := range vectorChains(t) {
		t.Run(c.name, func(t *testing.T) {
			I := c.pos["inception"].ID
			auth, amends := vst(t, c.pos["authored"].Line), vst(t, c.pos["authored-amends"].Line)
			steps := []struct {
				upto            string
				authored, amend string
				code            string
			}{
				{"authored-amends", policy.ActorEligible, policy.ActorEligible, ""},
				{"cut-last-good", policy.ActorEligible, policy.ActorDenied, "cut_excluded"},
				{"cut-null", policy.ActorDenied, policy.ActorDenied, "cut_excluded"},
				{"revoke-key", policy.ActorDenied, policy.ActorDenied, "root_retired"},
			}
			for _, s := range steps {
				a := c.actors(t, c.lines(c.order[:slices.Index(c.order, s.upto)+1]...))
				for _, x := range []struct {
					st   *wire.Statement
					want string
				}{{auth, s.authored}, {amends, s.amend}} {
					id, state, why := a.Eligible(x.st)
					if id != I || state != x.want {
						t.Fatalf("up to %s, %s: (%q, %s), want %s; %v", s.upto, x.st.ID[:12], id, state, x.want, why)
					}
					if x.want == policy.ActorDenied && !slices.ContainsFunc(why, func(w string) bool { return strings.HasPrefix(w, s.code) }) {
						t.Fatalf("up to %s, %s: why %v lacks %s", s.upto, x.st.ID[:12], why, s.code)
					}
				}
			}
		})
	}
}

// TestRootTerminalEventPlacement: C-id-17's three outcomes through Admit and the actor evaluator. A valid rc/1
// revoke_key or rotate_key placed on I's lineage by its prev chain retires I (the published vectors, both
// algorithms, and synthetic keys with merges in TestReviewTerminalRootEventIgnoresAncestryDefects); the same
// event on a proved rival inception by the same root key has no effect on I; an event whose prev cannot be placed
// (its parent is not held) reads unknown, never retired and never eligible.
func TestRootTerminalEventPlacement(t *testing.T) {
	conformance.Covers(t, "C-id-17")
	for _, c := range vectorChains(t) {
		t.Run("vectors/"+c.name, func(t *testing.T) {
			a := c.actors(t, c.lines(c.order...))
			id, state, why := a.Eligible(vst(t, c.pos["authored"].Line))
			if id != c.pos["inception"].ID || state != policy.ActorDenied || !slices.Contains(why, "root_retired: terminal in-lineage root event; never follow a successor") {
				t.Fatalf("(%q, %s) %v", id, state, why)
			}
		})
	}
	for _, kind := range []string{"revoke_key", "rotate_key"} {
		body := func(w *world) *canon.Object {
			if kind == "rotate_key" {
				return obj("successor", w.signer("S"))
			}
			return obj("reason", "key_compromise")
		}
		t.Run("rival/"+kind, func(t *testing.T) {
			w := base(t)
			w.sign(stmt{name: "Irival", by: "R", kind: "identity_inception", body: obj("profile", "fixed-root-v1", "n", 2)})
			w.sign(stmt{name: "Rterm", by: "R", rc: "rc/1", parent: "Irival", kind: kind, body: body(w)})
			s := w.admit()
			if st, v := s.Status(w.ids["Rterm"]); st != wire.Valid || !v {
				t.Fatalf("precondition: %s/%v", st, v)
			}
			a := s.Actors()
			for _, n := range []string{"A1", "B1"} {
				why := w.eligible(a, n, w.ids["I"], policy.ActorEligible, "")
				if slices.ContainsFunc(why, func(x string) bool { return strings.HasPrefix(x, "root_retired") }) {
					t.Fatalf("%s: %v", n, why)
				}
			}
			// the rival lineage's own terminal event does retire the rival identity (the event is real)
			if r := s.Evaluate(w.ids["Rterm"]); r.Status == identitymodel.Eligible {
				t.Fatalf("a terminal key event reads eligible as an act: %+v", r)
			}
		})
		t.Run("merges/"+kind, func(t *testing.T) {
			w := base(t)
			w.sign(stmt{name: "Irival", by: "R", kind: "identity_inception", body: obj("profile", "fixed-root-v1", "n", 2)})
			w.sign(stmt{name: "Rterm", by: "R", rc: "rc/1", parent: "G2", merges: []string{"Irival"}, kind: kind, body: body(w)})
			a := w.admit().Actors()
			for _, n := range []string{"A1", "B1"} {
				w.eligible(a, n, w.ids["I"], policy.ActorDenied, "root_retired")
			}
		})
		t.Run("unplaceable/"+kind, func(t *testing.T) {
			w := base(t)
			w.sign(stmt{name: "Rmid", by: "R", rc: "rc/1", parent: "G2", kind: "describes", body: obj("about", obj("statement", w.ids["I"]), "note", "ops")})
			w.sign(stmt{name: "Rterm", by: "R", rc: "rc/1", parent: "Rmid", kind: kind, body: body(w)})
			s := w.admit(without(w.order, "Rmid")...)
			if st, v := s.Status(w.ids["Rterm"]); st != wire.Valid || !v {
				t.Fatalf("precondition: %s/%v", st, v)
			}
			a := s.Actors()
			for _, n := range []string{"A1", "B1"} {
				why := w.eligible(a, n, w.ids["I"], policy.ActorUnknown, "")
				if slices.ContainsFunc(why, func(x string) bool { return strings.HasPrefix(x, "root_retired") }) {
					t.Fatalf("%s: retired by an unplaceable event: %v", n, why)
				}
			}
			// delivering the missing parent places it: retired
			w.eligible(w.admit().Actors(), "A1", w.ids["I"], policy.ActorDenied, "root_retired")
		})
	}
}
