package resolve

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
	"github.com/research-common/research-commons/internal/wire"
)

// dualFallbackWorld: an rc/1 base (an observation O of X by C, a result R by A) and, by worker key K of identity I
// (root key IR), rc/2 acts with an actor (an authored on Y, a holds of Y, a corroborates of O, an observed of Z),
// and by worker key M the same kinds with the marker and no actor (an authored on V, a holds of V, a corroborates
// of O, an observed of U).
func dualFallbackWorld(t *testing.T) (*world, map[string]string) {
	w := newWorld(t)
	o := w.observed("O", "C", "X", "exact-bytes", chainRef(3))
	res := w.result("R", "A", "R", "W", "X")
	w.authored("K0", "K", "K0")   // K's seq-0 line: the delegate inception its grant names
	w.authored("MM0", "MM", "M0") // MM is secp256k1: both algorithms act on rc/2
	i, g := w.identityOf("I", "IR", "K")
	act := [2]string{i, g["K"]}
	cor := func(of string) *canon.Object {
		return obj("of", of, "result", res, "verdict", "supports", "model", "M", "cohort", obj("rule", "every station in R within 50 km"))
	}
	w.signRC2("K:authored", "K", "authored", obj("content", contentOf("Y"), "type", "dataset", "licence", "MIT"), rc2Actor, act)
	w.signRC2("K:holds", "K", "holds", obj("content", contentOf("Y")), rc2Actor, act)
	w.signRC2("K:corroborates", "K", "corroborates", cor(o), rc2Actor, act)
	w.signRC2("K:observed", "K", "observed", obj("content", contentOf("Z"), "class", "exact-bytes", "referent", chainRef(4),
		"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted")), rc2Actor, act)
	w.signRC2("M:authored", "MM", "authored", obj("content", contentOf("V"), "type", "dataset", "licence", "MIT"), rc2MarkerOnly, [2]string{})
	w.signRC2("M:holds", "MM", "holds", obj("content", contentOf("V")), rc2MarkerOnly, [2]string{})
	w.signRC2("M:corroborates", "MM", "corroborates", cor(o), rc2MarkerOnly, [2]string{})
	w.signRC2("M:observed", "MM", "observed", obj("content", contentOf("U"), "class", "exact-bytes", "referent", chainRef(5),
		"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted")), rc2MarkerOnly, [2]string{})
	return w, map[string]string{"I": i, "G": g["K"], "O": o}
}

// dualResolver builds a resolver over every world line through the candidate dual-major reader.
func dualResolver(t *testing.T, w *world, opts ...Option) *Resolver {
	t.Helper()
	s := dualStore()
	if n := deliverAll(s, w.lines); n != 0 {
		t.Fatalf("%d lines refused", n)
	}
	return New(s, opts...)
}

// TestDualNoKeyFallback: D-1108b-3 on every consumer that reads these kinds. Under the dual reader with no actor
// evaluator, an rc/2 act carrying an actor is never its key's evidence: no authorship claim, no holder, no counted
// corroboration, an observation that counts toward nothing, each with the hook-absent text; a marker-only rc/2
// act by another key counts as key(K) exactly as an rc/1 one would. With an evaluator that finds K eligible for I,
// the same acts count (the counting gate's identity path); under the unchanged reader none of the rc/2 lines is
// evaluable at all.
func TestDualNoKeyFallback(t *testing.T) {
	conformance.Partial(t, "C-id-36", "the resolver under the dual reader: an rc/2 actor line never counts as its key without an evaluator (authorship, holders, corroboration, observation), a marker-only rc/2 line counts as key(K); rc/2 resource/task kinds stay unsupported (TestDualViewsSurviveCandidateBytes)")
	w, ids := dualFallbackWorld(t)
	r := dualResolver(t, w)
	for _, n := range []string{"K:authored", "K:holds", "K:corroborates", "K:observed"} {
		p, ok := r.Statement(w.ids[n])
		if !ok || !p.EvidenceReady() || !p.IdentityContext() || p.BareKeyEligible() || p.Counts() {
			t.Fatalf("%s: %+v", n, p)
		}
		if why := notCountedWhy(p); !strings.HasPrefix(why, "unknown (identity profile not active)") || !strings.Contains(why, "never counted as its key") {
			t.Fatalf("%s: fallback text %q", n, why)
		}
	}
	for _, n := range []string{"M:authored", "M:holds", "M:corroborates", "M:observed"} {
		p, ok := r.Statement(w.ids[n])
		if !ok || p.IdentityContext() || !p.Counts() || p.St.RC != "rc/2" {
			t.Fatalf("marker-only %s should count as key(K): %+v", n, p)
		}
	}
	// authorship and holders
	y, v := r.Artifact(dig("Y")), r.Artifact(dig("V"))
	if y.State != NoClaim || len(y.Holders) != 0 || len(y.NotCounted) != 1 || !strings.Contains(y.Render(), "unknown (identity profile not active)") {
		t.Fatalf("actor authored/holds counted as key evidence:\n%s", y.Render())
	}
	if v.State != SoleAuthor || len(v.Holders) != 1 || v.Holders[0] != w.signer("MM") {
		t.Fatalf("marker-only authored/holds is key(K):\n%s", v.Render())
	}
	// corroboration
	o, _ := r.Observation(ids["O"])
	if e := evidenceOf(t, o, w.ids["K:corroborates"]); e.Counted || !strings.Contains(e.Cause, "unknown (identity profile not active)") {
		t.Fatalf("actor corroboration: %+v", e)
	}
	if e := evidenceOf(t, o, w.ids["M:corroborates"]); !e.Counted {
		t.Fatalf("marker-only corroboration: %+v", e)
	}
	if o.Corroboration.Corroborated != 1 {
		t.Fatalf("corroborated %d, want 1 (the marker-only key):\n%s", o.Corroboration.Corroborated, o.Render())
	}
	// observation
	z, _ := r.Observation(w.ids["K:observed"])
	if !strings.Contains(strings.Join(z.Explain, "\n"), "counts toward nothing: unknown (identity profile not active)") {
		t.Fatalf("actor observation:\n%s", z.Render())
	}
	if u, _ := r.Observation(w.ids["M:observed"]); strings.Contains(strings.Join(u.Explain, "\n"), "counts toward nothing") {
		t.Fatalf("marker-only observation:\n%s", u.Render())
	}

	// a test evaluator that finds K eligible for I: the corroboration counts through the identity path
	fake := &actorFake{rows: map[string]actorRow{}}
	for _, n := range []string{"K:authored", "K:holds", "K:corroborates", "K:observed"} {
		fake.rows[w.ids[n]] = actorRow{ids["I"], policy.ActorEligible}
	}
	o2, _ := dualResolver(t, w, WithActorEligibility(fake)).Observation(ids["O"])
	if e := evidenceOf(t, o2, w.ids["K:corroborates"]); !e.Counted || e.Cause != "" {
		t.Fatalf("eligible identity corroboration: %+v", e)
	}
	// ...and an evaluator that binds it to no identity: still never its key's
	fake.rows[w.ids["K:corroborates"]] = actorRow{"", policy.ActorDenied}
	o3, _ := dualResolver(t, w, WithActorEligibility(fake)).Observation(ids["O"])
	if e := evidenceOf(t, o3, w.ids["K:corroborates"]); e.Counted || !strings.Contains(e.Cause, "binds it to no identity") {
		t.Fatalf("unbound identity corroboration: %+v", e)
	}

	// the real candidate evaluator over the same signed lines
	actors, err := identity.NewActors(w.lines)
	if err != nil {
		t.Fatal(err)
	}
	if id, state, why := actors.Eligible(r.byID[w.ids["K:corroborates"]].St); id != ids["I"] || state != policy.ActorEligible {
		t.Fatalf("real evaluator on K's corroboration: %q %s %v", id, state, why)
	}
	o4, _ := dualResolver(t, w, WithActorEligibility(actors)).Observation(ids["O"])
	if e := evidenceOf(t, o4, w.ids["K:corroborates"]); !e.Counted {
		t.Fatalf("real evaluator: eligible identity corroboration not counted: %+v", e)
	}

	// the unchanged reader: every rc/2 line retained or placed unverified, never evaluable
	old := w.store(nil)
	for n, id := range w.ids {
		if p, ok := old.Statement(id); ok && p.St.RC == "rc/2" && (p.Evaluable || p.Counts() || p.IdentityContext()) {
			t.Fatalf("unchanged reader evaluated %s", n)
		}
	}
}

// everyView asks every public resolver view about every held statement id, every digest it names and every
// resource it could name, and renders the answers. A panic anywhere fails the caller.
func everyView(r *Resolver, digests []string) string {
	var b strings.Builder
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	for _, id := range ids {
		p := r.byID[id]
		fmt.Fprintf(&b, "%s %s %s evaluable=%v counts=%v identity=%v\n", keylog.Short(id), p.St.RC, p.St.Kind, p.Evaluable, p.Counts(), p.IdentityContext())
		if res, ok := r.Resource(id); ok {
			b.WriteString(res.Render())
			if m, ok := r.Membership(id, id); ok {
				b.WriteString(m.Render())
			}
			if s, ok := r.Series(id, ""); ok {
				b.WriteString(s.Render())
			}
			if _, rf := r.EndorseSeries(id, "", RequireDeclaredNotAfterComputed{}); rf != nil {
				b.WriteString("endorse: " + rf.Error() + "\n")
			}
			if a, err := r.Admit(id, res.Current, obj("statement", id, "role", "member")); err == nil {
				b.WriteString(a.Render())
			} else {
				b.WriteString("admit: " + err.Error() + "\n")
			}
			if pp, err := r.CheckIntendedFor(obj("content", contentOf("X"), "type", "dataset"), id, res.Current); err == nil {
				fmt.Fprintf(&b, "prepin %s %s %v %s %s\n", pp.Resource, pp.Edition, pp.Evals, pp.Outcome, canon.Encode(pp.Body))
			} else {
				b.WriteString("prepin: " + err.Error() + "\n")
			}
			if c, ok := r.Completeness(id, ""); ok {
				b.WriteString(c.Render())
			}
		}
		if t, ok := r.Task(id); ok {
			b.WriteString(t.Render())
		}
		if o, ok := r.Observation(id); ok {
			b.WriteString(o.Render())
		}
		if c, ok := r.CheckRecorded(id); ok {
			b.WriteString(c.Render())
		}
		if pr, ok := r.PreRegistration(id); ok {
			b.WriteString(pr.Display + "\n")
		}
		b.WriteString(r.Credit(p.St.Signer, &CreditRule{Name: "all"}).Render())
		if rep, err := r.Reputation(p.St.Signer, ReputationRule{Name: "all", From: "2026-01-01T00:00:00Z", To: "2027-01-01T00:00:00Z", Describe: "everything"}); err == nil {
			b.WriteString(rep.String() + "\n")
		}
		if p.St.Body == nil {
			continue
		}
		if pv := provenance(p.St.Body); pv != nil {
			if gr := r.Group(pv); gr != nil {
				fmt.Fprintf(&b, "group %s derivers=%v outputs=%v %v\n", gr.Token, gr.Derivers, gr.Outputs, gr.Explain)
			}
		}
	}
	for _, d := range digests {
		b.WriteString(r.Artifact(d).Render())
		code, why := r.Verify(d)
		fmt.Fprintf(&b, "verify %d %v\n", code, why)
		for _, o := range r.Observations(d) {
			b.WriteString(o.Render())
		}
	}
	return b.String()
}

// TestDualViewsSurviveCandidateBytes: the profile §2.4 integration blocker under the dual reader. Every signed
// identity vector line (both chains), and rc/2 resource and task kinds with identity controllers (genesis, edition,
// withdraw_approval, intent, submit, decide: verified and unsupported), authenticated-invalid rc/2 lines and a
// tampered one, are delivered with an rc/1 resource and observation corpus. Every view answers without a panic,
// with and without an evaluator, in sampled orders; no rc/2 kind the slice does not implement is evaluable, and no
// rc/2 actor line counts without an evaluator. The same bytes through the unchanged reader: every view answers,
// and every rc/2 line stays unverified, undecoded and unsupported (C-id-36).
func TestDualViewsSurviveCandidateBytes(t *testing.T) {
	conformance.Partial(t, "C-id-36", "every resolver view on the signed vectors + rc/2 resource/task/invalid lines under the dual reader without a panic, unimplemented rc/2 kinds non-passing; the unchanged reader's half is TestUnchangedReaderStackOnCandidateBytes")
	vec, err := conformance.LoadSignedIdentityVectors()
	if err != nil {
		t.Fatal(err)
	}
	w, ids := dualFallbackWorld(t)
	g := w.genesis("G", "A", 0, "A", "BB")
	w.edition("E1", "A", g, []string{g}, []string{"x"})
	act := [2]string{ids["I"], ids["G"]}
	// rc/2 kinds the slice reads unsupported, with identity controllers and actors
	gen := w.signRC2("rc2:genesis", "K", "genesis", obj("type", "collection", "name", "n", "controllers", canon.Array{obj("identity", ids["I"])},
		"rule", obj("any_one", true)), rc2MarkerOnly, [2]string{})
	w.signRC2("rc2:edition", "K", "edition", obj("resource", g, "predecessors", []string{g}, "contents", obj("members", canon.Array{})), rc2Actor, act)
	w.signRC2("rc2:edition-own", "K", "edition", obj("resource", gen, "predecessors", []string{gen}, "contents", obj("members", canon.Array{})), rc2Actor, act)
	w.signRC2("rc2:withdraw", "K", "withdraw_approval", obj("resource", g, "edition", w.ed(w.ids["E1"])), rc2Actor, act)
	w.signRC2("rc2:intent", "K", "intent", obj("task", g, "edition", w.ed(w.ids["E1"])), rc2Actor, act)
	w.signRC2("rc2:submit", "K", "submit", obj("task", g, "edition", w.ed(w.ids["E1"]), "result", dig("R")), rc2Actor, act)
	w.signRC2("rc2:decide", "K", "decide", obj("task", g, "edition", w.ed(w.ids["E1"]), "verdict", "accept", "submissions", []string{}), rc2Actor, act)
	// authenticated-invalid: a verified rc/2 authored whose body breaks the schema, and an actor on describes
	w.signRC2("rc2:bad-body", "K", "authored", obj("content", 7), rc2Actor, act)
	w.signRC2("rc2:describes-actor", "K", "describes", obj("about", obj("content", dig("X")), "note", "n"), rc2Actor, act)
	tampered, _ := w.rc2Line("K", "authored", obj("content", contentOf("X"), "type", "dataset"), rc2Actor, act)
	lines := append([][]byte{}, w.lines...)
	lines = append(lines, tamper(tampered))
	for _, x := range vec.Positive {
		lines = append(lines, []byte(x.Line))
	}
	for _, x := range vec.Negative {
		lines = append(lines, []byte(x.Delivered))
	}
	digests := []string{dig("X"), dig("Y"), dig("Z"), dig("V"), dig("U"), dig("R"), dig("x")}
	for i := byte(0); i < 16; i++ {
		digests = append(digests, "sha256:"+strings.Repeat(string("0123456789abcdef"[i]), 64))
	}
	actors, err := identity.NewActors(lines)
	if err != nil {
		t.Fatal(err)
	}
	// the unchanged reader on the same bytes: every view answers, and no rc/2 line is verified, evaluable or counted
	t.Run("unchanged reader", func(t *testing.T) {
		var first string
		for _, o := range append([][]int{nil}, sampleOrders(len(lines), 0xd0a2, 4)...) {
			in := lines
			if o != nil {
				in = make([][]byte, len(o))
				for i, j := range o {
					in[i] = lines[j]
				}
			}
			s := keylog.NewStore()
			deliverAll(s, in)
			r := New(s, WithActorEligibility(actors)) // an evaluator is never asked about an unverified line
			got := everyView(r, digests)
			if first == "" {
				first = got
			} else if got != first {
				t.Fatalf("order changed an answer: %s", firstDiff(first, got))
			}
			for _, p := range r.byID {
				if p.St.RC == "rc/2" && (p.St.Verified || p.Evaluable || p.Counts() || p.IdentityContext() || p.St.Body != nil) {
					t.Fatalf("unchanged reader read an rc/2 %s: %+v", p.St.Kind, p)
				}
			}
			for _, k := range s.Keys() {
				v := s.Log(k).View()
				for _, st := range v.Retained {
					if st.RC == "rc/2" && (st.Verified || st.Status != wire.Unsupported) {
						t.Fatalf("retained rc/2 line: %+v", st)
					}
				}
			}
		}
	})
	for _, tc := range []struct {
		name string
		opts []Option
	}{{"no evaluator", nil}, {"real evaluator", []Option{WithActorEligibility(actors)}}} {
		t.Run(tc.name, func(t *testing.T) {
			var first string
			for _, o := range append([][]int{nil}, sampleOrders(len(lines), 0xd0a1, 4)...) {
				in := lines
				if o != nil {
					in = make([][]byte, len(o))
					for i, j := range o {
						in[i] = lines[j]
					}
				}
				s := dualStore()
				if deliverAll(s, in) == 0 {
					t.Fatal("no line refused: the tampered line and the refused negatives did not reach the reader")
				}
				r := New(s, tc.opts...)
				got := everyView(r, digests)
				if first == "" {
					first = got
				} else if got != first {
					t.Fatalf("order changed an answer: %s", firstDiff(first, got))
				}
				for _, p := range r.byID {
					if p.St.RC != "rc/2" {
						continue
					}
					switch {
					case p.Evaluable && (p.St.Kind == "genesis" || p.St.Kind == "edition" || p.St.Kind == "withdraw_approval" ||
						p.St.Kind == "intent" || p.St.Kind == "submit" || p.St.Kind == "decide"):
						t.Fatalf("unimplemented rc/2 %s is evaluable", p.St.Kind)
					case tc.opts == nil && p.IdentityContext() && p.Counts():
						t.Fatalf("rc/2 actor %s counts without an evaluator", p.St.Kind)
					}
				}
				for n, want := range map[string]wire.Status{"rc2:genesis": wire.Unsupported, "rc2:edition": wire.Unsupported,
					"rc2:edition-own": wire.Unsupported, "rc2:withdraw": wire.Unsupported, "rc2:intent": wire.Unsupported,
					"rc2:submit": wire.Unsupported, "rc2:decide": wire.Unsupported, "rc2:bad-body": wire.Invalid,
					"rc2:describes-actor": wire.Invalid, "K:authored": wire.Valid} {
					p, ok := r.Statement(w.ids[n])
					if !ok || !p.St.Verified || p.St.Status != want || !p.Chained {
						t.Fatalf("fixture %s did not reach verified %s: %+v", n, want, p)
					}
				}
				if _, ok := r.Resource(gen); ok {
					t.Fatal("an rc/2 genesis resolved a resource")
				}
			}
		})
	}
}

// TestDualNoKeyFallbackSelection: D-1108b-3 on the reader's selections. With no evaluator, a `{key: K}` selection
// never follows K's rc/2 actor claim (it is I's or nobody's, never K's), an exact pin to that statement is not met
// (it counts toward nothing, with the hook-absent text), and an `{identity: I}` selection reads the hook-absent
// answer. A `{key: MM}` selection follows MM's marker-only rc/2 claim like any key claim.
func TestDualNoKeyFallbackSelection(t *testing.T) {
	conformance.Partial(t, "C-id-31", "under the dual reader with no evaluator: a key selection never follows the key's rc/2 actor claim, an exact pin to it is not met, an identity selection reads the hook-absent answer; a marker-only rc/2 claim is followed by key")
	w, _ := dualFallbackWorld(t)
	read := func(sel *canon.Object, x string) *Artifact {
		return dualResolver(t, w, WithPolicy(pol(t, []*canon.Object{sel}, nil))).Artifact(dig(x))
	}
	if a := read(keySel(dig("Y"), policy.RoleAuthorship, w.signer("K")), "Y"); a.Selection == nil || a.Selection.Met() {
		t.Fatalf("a key selection followed K's actor claim:\n%s", a.Render())
	}
	a := read(pinSel(dig("Y"), policy.RoleAuthorship, w.ids["K:authored"]), "Y")
	if a.Selection == nil || a.Selection.Met() || !strings.Contains(a.Selection.Why, "unknown (identity profile not active)") {
		t.Fatalf("an exact pin to K's actor claim: %+v\n%s", a.Selection, a.Render())
	}
	if a := read(identitySel(dig("Y"), policy.RoleAuthorship), "Y"); a.Selection == nil || a.Selection.State != SelIdentity {
		t.Fatalf("identity selection without an evaluator: %+v", a.Selection)
	}
	if a := read(keySel(dig("V"), policy.RoleAuthorship, w.signer("MM")), "V"); !a.Selection.Met() {
		t.Fatalf("a key selection did not follow MM's marker-only claim: %+v\n%s", a.Selection, a.Render())
	}
}
