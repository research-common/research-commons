package resolve

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/identity"
	"github.com/research-common/research-commons/internal/keylog"
)

// Gate R6: P-01 and P-03 over mixed rc/1 + rc/2 corpora under the candidate dual-major reader.
//
// The rc/2 generator is genRC2 (below). From a seed it signs, into a concretized property fixture, an identity I
// (root key IR, Ed25519) with grants to two workers, an Ed25519 key K and a secp256k1 key MM (both algorithms act
// on rc/2), then 3..10 rc/2 acts drawn from: authored / holds / observed / corroborates / refutes, each either with
// an actor naming I and the worker's grant, or with the marker only; an authenticated-invalid line (an actor on
// `describes`, a bad body); an rc/2 `edition` of the fixture's resource (verified, unsupported); an actor naming a
// grant this corpus does not hold (unbound); and a tampered line (bad signature: refused by the dual reader). Targets
// are the fixture's own blobs and statements, so rc/2 evidence lands on the same artifacts, observations and
// resource the rc/1 statements do.

// rc2World is a fixture with the generator's lines appended. tampered lines are delivered but never chained.
type rc2World struct {
	*propWorld
	tampered [][]byte
	acts     []string // generated statement names, in order
}

// genRC2 is the rc/2 generator. It never touches the fixture's own lines.
func genRC2(t *testing.T, pw *propWorld, seed uint64) *rc2World {
	t.Helper()
	r := rand.New(rand.NewPCG(seed, seed^0x5eed2))
	w := pw.world
	rw := &rc2World{propWorld: pw}
	w.authored("K:0", "K", "K0")
	w.authored("MM:0", "MM", "M0")
	i, g := w.identityOf("I", "IR", "K", "MM")
	res := w.ids["RES"]
	targets := pw.blobs
	var stmts []string // statement ids an act may name
	for _, n := range []string{"O1", "M1", "RES", "RES2"} {
		stmts = append(stmts, w.ids[n])
	}
	n := 3 + r.IntN(8)
	for j := 0; j < n; j++ {
		name := fmt.Sprintf("rc2:%d", j)
		k := []string{"K", "MM"}[r.IntN(2)]
		act, actor := rc2Actor, [2]string{i, g[k]}
		if r.IntN(3) == 0 {
			act = rc2MarkerOnly
		}
		x := targets[r.IntN(len(targets))]
		var kind string
		var body *canon.Object
		switch r.IntN(9) {
		case 0:
			kind, body = "authored", obj("content", contentOf(x), "type", "dataset", "licence", []string{"MIT", "CC0-1.0"}[r.IntN(2)])
		case 1:
			kind, body = "holds", obj("content", contentOf(x))
		case 2:
			kind, body = "observed", obj("content", contentOf(x), "class", "exact-bytes", "referent", chainRef(r.IntN(9)),
				"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted"))
		case 3:
			kind, body = "corroborates", obj("of", w.ids["O1"], "result", res, "verdict", []string{"supports", "contradicts"}[r.IntN(2)],
				"model", "M", "cohort", obj("rule", "every station in R within 50 km"))
		case 4:
			kind, body = "refutes", obj("of", stmts[r.IntN(len(stmts))], "evidence", dig("E"))
		case 5: // authenticated-invalid: describes never takes an actor
			kind, body, act = "describes", obj("about", obj("content", dig(x)), "note", "n"), rc2Actor
		case 6: // authenticated-invalid body
			kind, body = "authored", obj("content", 7)
		case 7: // verified, unsupported: rc/2 editions are not implemented by the slice
			kind, body = "edition", obj("resource", pw.g, "predecessors", []string{pw.g}, "contents", obj("members", entries(Entry("content", dig(x), "member"))))
		case 8: // an actor naming a grant this corpus does not hold: no evaluator can bind it
			kind, body, act, actor = "authored", obj("content", contentOf(x), "type", "dataset"), rc2Actor, [2]string{i, unheldID(name)}
		}
		if r.IntN(10) == 0 {
			line, _ := w.rc2Line(k, kind, body, act, actor)
			rw.tampered = append(rw.tampered, tamper(line))
			continue
		}
		w.signRC2(name, k, kind, body, act, actor)
		rw.acts = append(rw.acts, name)
	}
	return rw
}

// all is every line to deliver: the signed world plus the tampered lines.
func (rw *rc2World) all() [][]byte { return append(slices.Clone(rw.lines), rw.tampered...) }

// rc2Answers is every answer a resolver over lines gives (the property snapshot plus every other view), under the
// dual store; it fails when the refusals are not exactly the tampered lines.
func (rw *rc2World) rc2Answers(t *testing.T, lines [][]byte, opts ...Option) string {
	t.Helper()
	s := dualStore()
	tampered := 0
	for _, l := range lines {
		for _, x := range rw.tampered {
			if string(l) == string(x) {
				tampered++
			}
		}
	}
	if n := deliverAll(s, lines); n != tampered {
		t.Fatalf("%d lines refused, %d tampered", n, tampered)
	}
	r := New(s, append(propOpts(), opts...)...)
	var ds []string
	for _, x := range rw.blobs {
		ds = append(ds, dig(x))
	}
	return rw.snapshot(r, s) + everyView(r, ds)
}

// TestPropertyOrderInvarianceMixedMajors: P-01 over mixed rc/1 + rc/2 corpora (generator: genRC2) under the dual
// reader, with no evaluator, with the real candidate evaluator over the same lines, and with a test evaluator
// that answers every actor line "unknown": every answer of every view is identical in file order and in sampled
// delivery orders (duplicates included).
func TestPropertyOrderInvarianceMixedMajors(t *testing.T) {
	conformance.Partial(t, "P-01", "mixed rc/1 + rc/2 corpora (rc/2 generator genRC2: both algorithms, actor and marker-only, authenticated-invalid, unsupported editions, unbound actors, tampered) under the dual reader, every view, with no, the real and an all-unknown evaluator; orders sampled")
	fixture.Check(t, propBaseSeed+5000, 16, fixture.Extended, func(f fixture.Fixture) string {
		rw := genRC2(t, concretize(t, f), f.Seed)
		lines := rw.all()
		actors, err := identity.NewActors(lines)
		if err != nil {
			t.Fatal(err)
		}
		unknown := &actorFake{rows: map[string]actorRow{}}
		for _, n := range rw.acts {
			unknown.rows[rw.ids[n]] = actorRow{rw.ids["I"], "unknown"}
		}
		for _, ev := range []struct {
			name string
			opts []Option
		}{{"no evaluator", nil}, {"real evaluator", []Option{WithActorEligibility(actors)}}, {"unknown evaluator", []Option{WithActorEligibility(unknown)}}} {
			first := rw.rc2Answers(t, lines, ev.opts...)
			for _, o := range sampleOrders(len(lines), f.Seed, 3) {
				in := make([][]byte, 0, 2*len(o))
				for _, j := range o {
					in = append(in, lines[j])
				}
				if got := rw.rc2Answers(t, in, ev.opts...); got != first {
					return ev.name + ": order " + sprintOrder(o) + " changed an answer: " + firstDiff(first, got)
				}
			}
			dup := append(slices.Clone(lines), lines...)
			slices.Reverse(dup)
			if got := rw.rc2Answers(t, dup, ev.opts...); got != first {
				return ev.name + ": duplicated reverse delivery changed an answer: " + firstDiff(first, got)
			}
		}
		return ""
	})
}

// rc1Decision is the decision part of every view of the fixture's own (rc/1) subjects: per blob the authorship
// state, default claimants, each single-party field's state and default, holders and the verify exit; per base
// observation the corroboration status and counts (the resource is resourceSame's). Explanations are left out on purpose:
// a new statement naming a subject is listed, attributed and not counted (the exception P-03's rc/2 class names).
func rc1Decision(pw *propWorld, r *Resolver, obs []string) string {
	var b strings.Builder
	for _, x := range pw.blobs {
		a := r.Artifact(dig(x))
		var def []string
		if a.Default != nil {
			for _, c := range a.Default.Claims {
				def = append(def, c.Subject.ID)
			}
		}
		code, _ := r.Verify(dig(x))
		fmt.Fprintf(&b, "%s %s default=%v holders=%v verify=%d grade=%s\n", x, a.State, def, a.Holders, code, a.Grade)
		for _, f := range a.Fields {
			v, ok := f.Default()
			fmt.Fprintf(&b, "  %s %s %q %v\n", f.Name, f.State, v, ok)
		}
	}
	for _, id := range obs {
		if o, ok := r.Observation(id); ok {
			c := o.Corroboration
			fmt.Fprintf(&b, "%s %s +%d -%d unchecked=%v\n", keylog.Short(id), c.Status(), c.Corroborated, c.Contradicted, c.Unchecked)
		}
	}
	return b.String()
}

// resourceSame is the resource half of the decision, compared as the rc/1 P-03 compares it (sameDecision): the
// header and every existing edition unchanged, and a new edition, listed, never authorized.
func resourceSame(pw *propWorld, before, after *Resolver) string {
	a, aok := before.Resource(pw.g)
	b, bok := after.Resource(pw.g)
	if aok != bok {
		return "the resource resolves on one side only"
	}
	if !aok {
		return ""
	}
	return sameDecision(a, b)
}

// TestPropertyNonInterferenceMixedMajors: P-03 for rc/2 additions under the dual reader (generator: the outsider
// identity of rc2Outsider). An outsider identity J (root QR, worker QW: keys that sign nothing in the fixture)
// adds rc/2 acts carrying an actor for J. With no evaluator (D-1108b-3: never a key fallback) and with the real
// evaluator when the act's grant is not held (unbound), the decision on every rc/1 subject is unchanged, even
// for acts that name those subjects (an authored on a fixture blob, a holds, a corroborates of O1, a refutes, an
// rc/2 edition of G). The explanation lists such an act, attributed and not counted: that is the one difference
// the profile requires (it is shown, never counted as its key). An act on an unrelated blob changes no answer at
// all, explanation included. Controls: the same act signed marker-only (a key(K) statement) does change the
// authorship decision, and the real evaluator with a held grant makes the corroboration count.
func TestPropertyNonInterferenceMixedMajors(t *testing.T) {
	conformance.Partial(t, "P-03", "rc/2 additions under the dual reader (outsider identity generator rc2Outsider): decision unchanged with no evaluator and with unbound actors under the real evaluator; explanation unchanged off-subject; controls: marker-only and bound acts do bear")
	fixture.Check(t, propBaseSeed+6000, 12, fixture.Extended, func(f fixture.Fixture) string {
		base := concretize(t, f)
		obs := []string{base.ids["O1"]}
		for _, l := range base.labels {
			if base.kinds[l] == "observed" {
				obs = append(obs, base.ids[l])
			}
		}
		read := func(pw *propWorld, opts ...Option) (*Resolver, [][]byte) {
			s := dualStore()
			deliverAll(s, pw.lines)
			return New(s, append(propOpts(), opts...)...), pw.lines
		}
		r0, _ := read(base)
		d0, v0 := rc1Decision(base, r0, obs), offSubject(base, r0)
		for _, c := range rc2Outsider() {
			pw := concretize(t, f)
			j, grant := c.setup(pw)
			c.add(pw, [2]string{j, grant})
			for _, ev := range []string{"none", "real"} {
				var opts []Option
				if ev == "real" {
					actors, err := identity.NewActors(pw.lines)
					if err != nil {
						t.Fatal(err)
					}
					opts = []Option{WithActorEligibility(actors)}
				}
				r1, _ := read(pw, opts...)
				d1 := rc1Decision(pw, r1, obs)
				rs := resourceSame(base, r0, r1)
				switch {
				case c.bears && ev == "real":
					if d1 == d0 {
						return c.name + ": control did not bear on the decision under the real evaluator"
					}
				case c.marker:
					if d1 == d0 {
						return c.name + ": a marker-only (key) act changed nothing: the harness does not reach the view"
					}
				default:
					if rs != "" {
						return c.name + " (evaluator " + ev + "): the resource decision changed: " + rs
					}
					if d1 != d0 {
						return c.name + " (evaluator " + ev + "): the decision changed: " + firstDiff(d0, d1) + "\n" + d1
					}
					if c.offSubject {
						if v1 := offSubject(pw, r1); v1 != v0 {
							return c.name + " (evaluator " + ev + "): an off-subject act changed the explanation: " + firstDiff(v0, v1)
						}
					}
				}
			}
		}
		return ""
	})
}

// offSubject renders the fixture's subjects in full (explanations included).
func offSubject(pw *propWorld, r *Resolver) string {
	var b strings.Builder
	for _, x := range pw.blobs {
		b.WriteString(r.Artifact(dig(x)).Render())
	}
	if o, ok := r.Observation(pw.ids["O1"]); ok {
		b.WriteString(o.Render())
	}
	if res, ok := r.Resource(pw.g); ok {
		b.WriteString(res.Render())
	}
	return b.String()
}

type rc2Case struct {
	name string
	// setup incepts J and grants QW (bound) or returns an unheld grant (unbound)
	setup func(pw *propWorld) (string, string)
	add   func(pw *propWorld, actor [2]string)
	// offSubject: names nothing of the fixture; marker: signed marker-only (control); bears: the real evaluator
	// binds it and it must move a decision (control)
	offSubject, marker, bears bool
}

// rc2Outsider is P-03's rc/2 generator: an outsider identity J and its acts.
func rc2Outsider() []rc2Case {
	bound := func(pw *propWorld) (string, string) {
		pw.sign("QW:0", "QW", "holds", obj("content", contentOf("ZZ0")))
		j, g := pw.identityOf("J", "QR", "QW")
		return j, g["QW"]
	}
	unbound := func(pw *propWorld) (string, string) {
		pw.sign("QW:0", "QW", "holds", obj("content", contentOf("ZZ0")))
		j, _ := pw.identityOf("J", "QR")
		return j, unheldID("grant of J")
	}
	cor := func(pw *propWorld) *canon.Object {
		return obj("of", pw.ids["O1"], "result", pw.ids["RES"], "verdict", "supports", "model", "M", "cohort", obj("rule", "every station in R within 50 km"))
	}
	act := func(kind string, body func(pw *propWorld) *canon.Object, mode rc2Act) func(*propWorld, [2]string) {
		return func(pw *propWorld, a [2]string) { pw.signRC2("L", "QW", kind, body(pw), mode, a) }
	}
	authoredX := func(pw *propWorld) *canon.Object {
		return obj("content", contentOf("X"), "type", "dataset", "licence", "MIT")
	}
	return []rc2Case{
		{name: "J authors an unrelated blob", setup: bound, offSubject: true,
			add: act("authored", func(*propWorld) *canon.Object { return obj("content", contentOf("ZZ"), "type", "dataset") }, rc2Actor)},
		{name: "J holds an unrelated blob", setup: bound, offSubject: true,
			add: act("holds", func(*propWorld) *canon.Object { return obj("content", contentOf("ZZ")) }, rc2Actor)},
		{name: "J authors fixture blob X, no evaluator / unbound", setup: unbound, add: act("authored", authoredX, rc2Actor)},
		{name: "J holds fixture blob X, unbound", setup: unbound,
			add: act("holds", func(*propWorld) *canon.Object { return obj("content", contentOf("X")) }, rc2Actor)},
		{name: "J corroborates O1, unbound", setup: unbound, add: act("corroborates", cor, rc2Actor)},
		{name: "J refutes O1, unbound", setup: unbound,
			add: act("refutes", func(pw *propWorld) *canon.Object { return obj("of", pw.ids["O1"], "evidence", dig("E")) }, rc2Actor)},
		{name: "J approves an rc/2 edition of G (unsupported)", setup: bound,
			add: act("edition", func(pw *propWorld) *canon.Object {
				return obj("resource", pw.g, "predecessors", []string{pw.g}, "contents", obj("members", entries(Entry("content", dig("q"), "member"))))
			}, rc2Actor)},
		{name: "control: QW authors X marker-only (key(K))", setup: bound, marker: true, add: act("authored", authoredX, rc2MarkerOnly)},
		{name: "control: J corroborates O1 under a held grant", setup: bound, bears: true, add: act("corroborates", cor, rc2Actor)},
	}
}
