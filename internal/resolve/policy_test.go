package resolve

import (
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/policy"
)

// --- fixture language for policies --------------------------------------------------------------------------

// pol builds and parses a reader-policy-v1 from selection and trust entries (canonical JSON objects, in any
// order: pol sorts them).
func pol(t *testing.T, sels, trust []*canon.Object) *policy.Policy {
	t.Helper()
	enc := func(xs []*canon.Object) canon.Array {
		texts := make([]string, len(xs))
		for i, x := range xs {
			texts[i] = string(canon.Encode(x))
		}
		slices.SortFunc(texts, canon.CompareKeys)
		out := canon.Array{}
		for _, s := range texts {
			v, err := canon.Parse([]byte(s))
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, v)
		}
		return out
	}
	doc := obj("version", policy.Version, "selections", canon.Value(enc(sels)), "trust", canon.Value(enc(trust)))
	p, err := policy.Parse(canon.Encode(doc))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func pinSel(content, role, statement string) *canon.Object {
	return obj("subject", obj("content", content, "role", role), "statement", statement)
}

func keySel(content, role, key string) *canon.Object {
	return obj("subject", obj("content", content, "role", role), "principal", obj("key", key))
}

func identitySel(content, role string) *canon.Object {
	return obj("subject", obj("content", content, "role", role), "principal", obj("identity", strings.Repeat("ab", 32)))
}

func trustKey(key string, purposes []string, contents ...string) *canon.Object {
	tg := obj("any_content", true)
	if len(contents) > 0 {
		tg = obj("contents", contents)
	}
	return obj("principal", obj("key", key), "purposes", purposes, "targets", tg)
}

// --- defaults ------------------------------------------------------------------------------------------------

// TestNoPolicyIsToday: with no policy and with WithPolicy(nil) every view renders exactly as without the option
// (the existing tests run untouched, with no policy); an empty configured policy changes no grade, default or
// count of a fixture that needs no trust.
func TestNoPolicyIsToday(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	w.workflow("Q", "W", "bytes", "")
	base := w.store(nil).Artifact(dig("X")).Render()
	if got := w.store(nil, WithPolicy(nil)).Artifact(dig("X")).Render(); got != base {
		t.Fatalf("WithPolicy(nil) changed the view:\n%s\nvs\n%s", got, base)
	}
	empty := pol(t, nil, nil)
	a := w.store(nil, WithPolicy(empty)).Artifact(dig("X"))
	if a.Step.Tier != "T0" || a.Outcome() != w.store(nil).Artifact(dig("X")).Outcome() {
		t.Fatalf("an empty policy moved the answer: %s", a.Render())
	}
	has(t, a.Render(), "evaluated under reader policy "+empty.Digest)
	hw, x := hotReading(t)
	o, _ := hw.store(nil, WithPolicy(nil)).Observation(x)
	has(t, o.Render(), "your trust in these keys: not configured (every counted statement is counted)")
}

// --- workflow-declaration: the reader's pin of a workflow's mode (decision A7) -------------------------------

// TestWorkflowPinOverAgreement: W has two claimants that disagree (bytes vs protocol+K), so with no policy
// groups under W read no default replication (`unchecked`, A7). A reader that pins one declaration reads its
// mode and comparator; pinning the other reads the other's. Explain cites the policy and the selection. The
// pin recomputes the grade from the same runs: no run, comparison or statement is added.
func TestWorkflowPinOverAgreement(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "r~1", "BB": "r~2"})
	q := w.workflow("Q", "W", "protocol", "K")
	cmp := WithComparator(newFakeComparator("r~1", "r~2"))
	base := w.store(nil, cmp).Artifact(dig("r~1"))
	if base.Step.Why != UncheckedToken {
		t.Fatalf("control: %s\n%s", base.Step, base.Render())
	}

	pq := pol(t, []*canon.Object{pinSel(dig("W"), policy.RoleWorkflow, q)}, nil)
	everyOrderArtifact(t, w, "r~1", func(a *Artifact) {
		if a.Step.Tier != "T1" {
			t.Fatalf("pinned protocol: %s\n%s", a.Step, a.Render())
		}
		out := a.Render()
		has(t, out, "replication protocol (selected by the reader's policy ("+shortKey(w.signer("Q"))+" in "+keylog.Short(q)+"))")
		has(t, out, "reader policy sha256:"+shortDigest(pq.Digest)+" selects ")
		has(t, out, `"statement":"`+q+`"`)
		if len(a.Group.Runs) != len(base.Group.Runs) {
			t.Fatal("the pin changed the runs")
		}
	}, cmp, WithPolicy(pq))

	pa := pol(t, []*canon.Object{pinSel(dig("W"), policy.RoleWorkflow, w.ids["wf:W:WA"])}, nil)
	a := w.store(nil, cmp, WithPolicy(pa)).Artifact(dig("r~1"))
	if a.Step.Why != DivergedToken {
		t.Fatalf("pinned bytes: %s\n%s", a.Step, a.Render())
	}
	wantExit(t, a, 1, "diverged")

	// principal selection: follow Q's current claims
	pk := pol(t, []*canon.Object{keySel(dig("W"), policy.RoleWorkflow, w.signer("Q"))}, nil)
	if a := w.store(nil, cmp, WithPolicy(pk)).Artifact(dig("r~1")); a.Step.Tier != "T1" {
		t.Fatalf("principal Q: %s\n%s", a.Step, a.Render())
	}
}

// TestWorkflowPinIsExact: a pin names one statement. Pinning the author's first declaration after the author
// amended it reads the pinned (amended) declaration, never the amendment; principal selection follows the
// current one. A pin of a statement not held, of another blob, of a non-workflow `authored`, of a statement that
// counts toward nothing, or of an identity is unmet: `unchecked`, explain says why, nothing substituted.
func TestWorkflowPinIsExact(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	first := w.ids["wf:W:WA"]
	w.authored("WA2", "WA", "W", "type", "workflow", "replication", "protocol", "comparator", dig("K")) // WA amends its own declaration
	if a := w.store(nil).Artifact(dig("X")); a.Step.Why != IdenticalProto {
		t.Fatalf("control: %s", a.Step)
	}
	exact := w.store(nil, WithPolicy(pol(t, []*canon.Object{pinSel(dig("W"), policy.RoleWorkflow, first)}, nil))).Artifact(dig("X"))
	if exact.Step.Tier != "T0" {
		t.Fatalf("exact pin of the amended declaration: %s\n%s", exact.Step, exact.Render())
	}
	follow := w.store(nil, WithPolicy(pol(t, []*canon.Object{keySel(dig("W"), policy.RoleWorkflow, w.signer("WA"))}, nil))).Artifact(dig("X"))
	if follow.Step.Why != IdenticalProto {
		t.Fatalf("principal follows the current claim: %s\n%s", follow.Step, follow.Render())
	}

	other := w.authored("OT", "A", "OTHER", "type", "workflow", "replication", "bytes")
	notWf := w.authored("NW", "Q", "W", "type", "dataset", "replication", "bytes")
	for name, c := range map[string]struct {
		sel  *canon.Object
		want string
	}{
		"not held":     {pinSel(dig("W"), policy.RoleWorkflow, strings.Repeat("cd", 32)), SelMissing},
		"another blob": {pinSel(dig("W"), policy.RoleWorkflow, other), "about another blob"},
		"not workflow": {pinSel(dig("W"), policy.RoleWorkflow, notWf), "not a workflow declaration"},
		"identity":     {identitySel(dig("W"), policy.RoleWorkflow), SelIdentity},
		"no claim":     {keySel(dig("W"), policy.RoleWorkflow, w.signer("NOBODY")), SelNone},
	} {
		a := w.store(nil, WithPolicy(pol(t, []*canon.Object{c.sel}, nil))).Artifact(dig("X"))
		if a.Step.Why != UncheckedToken {
			t.Fatalf("%s: step %s\n%s", name, a.Step, a.Render())
		}
		has(t, a.Render(), c.want)
		has(t, a.Render(), "no default replication is read")
		wantExit(t, a, 3, "derivation: unchecked")
	}

	// a pinned statement that counts toward nothing (its key is revoked from before it) is ineligible
	w2 := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	good := w2.sign("QG", "Q", "holds", obj("content", contentOf("unrelated")))
	q := w2.workflow("Q", "W", "protocol", "K")
	w2.sign("RV", "Q", "revoke_key", obj("reason", "key_compromise", "last_good", good))
	if p := w2.store(nil).byID[q]; p == nil || p.Counts() {
		t.Fatal("fixture: the pinned statement still counts")
	}
	a := w2.store(nil, WithPolicy(pol(t, []*canon.Object{pinSel(dig("W"), policy.RoleWorkflow, q)}, nil))).Artifact(dig("X"))
	if a.Step.Why != UncheckedToken {
		t.Fatalf("revoked pin: %s\n%s", a.Step, a.Render())
	}
	has(t, a.Render(), SelIneligible)
}

// TestWorkflowPrincipalConflict: the followed key holds two current declarations on separate branches of its
// forked log that disagree: shown, never chosen by arrival, in every delivery order.
func TestWorkflowPrincipalConflict(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X", "BB": "X"})
	head, seq := w.head["WA"], w.seq["WA"]
	w.authored("F1", "WA", "W", "type", "workflow", "replication", "protocol", "comparator", dig("K"))
	w.forkAt("WA", head, seq)
	w.authored("F2", "WA", "W", "type", "workflow", "replication", "bytes", "comparator", dig("K2"))
	p := pol(t, []*canon.Object{keySel(dig("W"), policy.RoleWorkflow, w.signer("WA"))}, nil)
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		if a.Step.Why != UncheckedToken {
			t.Fatalf("step %s\n%s", a.Step, a.Render())
		}
		has(t, a.Render(), SelConflict)
	}, WithPolicy(p))
}

// --- authorship-declaration ----------------------------------------------------------------------------------

// TestAuthorshipSelection: two claimants with no verified bound: contested, no default (C-core-17 unchanged
// with no policy). A reader's pin of B's statement reads B's licence, with A's listed as a rival; authorship and
// grade are unchanged. A pin of a missing statement leaves every declared field without a default and verify
// names the unmet selection.
func TestAuthorshipSelection(t *testing.T) {
	w := newWorld(t)
	w.authored("A1", "A", "X", "licence", "CC0-1.0")
	b1 := w.authored("B1", "BB", "X", "licence", "MIT")
	base := w.store(nil).Artifact(dig("X"))
	wantAuthorship(t, base, ContestedAuthorship)
	wantField(t, base, "licence", FieldNoDefault, "")

	p := pol(t, []*canon.Object{pinSel(dig("X"), policy.RoleAuthorship, b1)}, nil)
	everyOrderArtifact(t, w, "X", func(a *Artifact) {
		wantAuthorship(t, a, ContestedAuthorship)
		wantField(t, a, "licence", FieldDefault, `"MIT"`)
		if f := a.Field("licence"); len(f.Rivals) != 1 || f.Rivals[0].Signer != w.signer("A") {
			t.Fatalf("rival not listed: %+v", f)
		}
		has(t, a.Render(), "reader policy sha256:"+shortDigest(p.Digest)+" selects")
	}, WithPolicy(p))

	miss := w.store(nil, WithPolicy(pol(t, []*canon.Object{pinSel(dig("X"), policy.RoleAuthorship, strings.Repeat("ef", 32))}, nil))).Artifact(dig("X"))
	wantField(t, miss, "licence", FieldSelectionUnmet, "")
	if code, why := miss.VerifyExit(); code != 3 || !slices.ContainsFunc(why, func(s string) bool { return strings.Contains(s, "reader's authorship selection") }) {
		t.Fatalf("verify %d %v", code, why)
	}

	// following a key whose current claims disagree on a field: contested, never the first to arrive
	w.authored("B2", "BB", "X", "licence", "Apache-2.0") // amends B1: B's current claim is B2 only
	f := w.store(nil, WithPolicy(pol(t, []*canon.Object{keySel(dig("X"), policy.RoleAuthorship, w.signer("BB"))}, nil))).Artifact(dig("X"))
	wantField(t, f, "licence", FieldDefault, `"Apache-2.0"`)
	exact := w.store(nil, WithPolicy(p)).Artifact(dig("X"))
	wantField(t, exact, "licence", FieldDefault, `"MIT"`) // the exact pin never moves to the amendment
}

// --- observation-declaration ---------------------------------------------------------------------------------

// TestObservationSelection: two observers of OBS, one contradicted. Without a policy a derived result rests on
// "1 contradicted"; selecting the other observation reads only it; an unmet selection says so and reads none.
func TestObservationSelection(t *testing.T) {
	w := newWorld(t)
	o1 := w.sign("O1", "O", "observed", obj("content", contentOf("OBS"), "class", "none-yet", "referent", obj(),
		"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted")))
	o2 := w.sign("O2", "P", "observed", obj("content", contentOf("OBS"), "class", "none-yet", "referent", obj(),
		"capture", obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted")))
	w.sign("CC", "C", "corroborates", obj("of", o1, "result", strings.Repeat("ab", 32), "verdict", "contradicts",
		"model", "bounds/1", "cohort", obj("rule", "climate record")))
	w.workflow("WA", "W", "bytes", "")
	w.authored("A1", "A", "X", "prov", []string{"W", "OBS"})
	has(t, w.store(nil).Artifact(dig("X")).Render(), "1 contradicted within statements you hold")

	p := pol(t, []*canon.Object{pinSel(dig("OBS"), policy.RoleObservation, o2)}, nil)
	a := w.store(nil, WithPolicy(p)).Artifact(dig("X"))
	hasNot(t, a.Render(), "contradicted")
	has(t, a.Render(), "evaluated under reader policy "+p.Digest)
	v, _ := w.store(nil, WithPolicy(p)).Observation(o1)
	has(t, v.Render(), "this statement is not the selected one")

	u := w.store(nil, WithPolicy(pol(t, []*canon.Object{pinSel(dig("OBS"), policy.RoleObservation, w.ids["A1"])}, nil))).Artifact(dig("X"))
	has(t, u.Render(), "reader's observation selection "+SelIneligible)
}

// --- trust ---------------------------------------------------------------------------------------------------

// TestCorroborationTrust: claims §5.3.2 "holds and trusts", once a policy is configured (identity note §6: no
// configured trust is not trusted). Trusting S1 and S2 for corroboration counts only them; trusting nobody
// counts nothing (unchecked) with every statement still listed and attributed; trust for another purpose or
// another content does not count. The reader's own re-check is never filtered.
func TestCorroborationTrust(t *testing.T) {
	w, x := hotReading(t)
	X := dig("X")
	sup := pol(t, nil, []*canon.Object{trustKey(w.signer("S1"), []string{"corroboration"}, X), trustKey(w.signer("S2"), []string{"corroboration"})})
	o := obsView(t, w, x, WithPolicy(sup))
	wantStatus(t, o, "corroborated 2 within statements you hold")
	out := o.Render()
	has(t, out, "your trust in these keys: reader policy sha256:"+shortDigest(sup.Digest)+" (2 trusted, 1 not trusted")
	has(t, out, "corroborates by "+shortKey(w.signer("C3"))+" in "+keylog.Short(w.ids["C3"])+": contradicts under M (not trusted for corroboration")
	hasNot(t, out, "not configured")

	none := pol(t, nil, nil)
	n := obsView(t, w, x, WithPolicy(none))
	wantStatus(t, n, "unchecked within statements you hold")
	for _, name := range []string{"S1", "S2", "C3"} {
		has(t, n.Render(), keylog.Short(w.ids[name]))
	}

	wrong := pol(t, nil, []*canon.Object{
		trustKey(w.signer("S1"), []string{"admission", "attestation"}),
		trustKey(w.signer("S2"), []string{"corroboration"}, dig("elsewhere")),
	})
	wantStatus(t, obsView(t, w, x, WithPolicy(wrong)), "unchecked within statements you hold")

	// the reader's own re-check (C-core-29's fixture) is the reader's computation, never filtered by trust
	w2 := newWorld(t)
	o1 := w2.observed("O1", "O1", "X", "exact-bytes", chainRef(3))
	rd := obsView(t, w2, o1, WithPolicy(none), WithReferentChecker(fakeReferents{o1: {Outcome: ReDifferent, Digest: dig("Y"), State: State{HasDepth: true, Depth: 12}}}))
	wantStatus(t, rd, "contradicted 1 (reader re-check) within statements you hold")
}

// TestRunAttestationTrust: A5 + A12. A runner's signed result and environment show the reader's attestation
// trust in the runner once a policy is configured; the grade never reads it.
func TestRunAttestationTrust(t *testing.T) {
	w := groupWorld(t, "bytes", "", map[string]string{"A": "X"})
	w.sign("BR", "BB", "reproduced", obj("of", w.ids["A1"], "result", "match", "content", contentOf("X"),
		"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
	base := w.store(nil).Artifact(dig("X"))
	has(t, base.Render(), "your trust in this key: not configured")
	yes := pol(t, nil, []*canon.Object{trustKey(w.signer("BB"), []string{"attestation"})})
	no := pol(t, nil, []*canon.Object{trustKey(w.signer("BB"), []string{"corroboration"})})
	ay := w.store(nil, WithPolicy(yes)).Artifact(dig("X"))
	an := w.store(nil, WithPolicy(no)).Artifact(dig("X"))
	has(t, ay.Render(), "your trust in this key: trusted for attestation of sha256:"+keylog.Short(strings.TrimPrefix(dig("X"), "sha256:"))[:5])
	has(t, an.Render(), "your trust in this key: not trusted for attestation")
	if ay.Step != base.Step || an.Step != base.Step || ay.Outcome() != an.Outcome() {
		t.Fatalf("trust moved a grade: %s %s %s", base.Step, ay.Step, an.Step)
	}
}

// --- P-11, P-08 ----------------------------------------------------------------------------------------------

// TestPolicyDifferenceExplained: P-11 over the resolver views built so far. Two readers with identical
// statements, policy and evaluator give identical answers; with one policy difference the differing answer's
// explanation cites the differing policy (its digest and the entry), never a validity difference: the set of
// statements each lists, and their verification, are identical. Covers a workflow pin (grade), an authorship pin
// (default) and a trust difference (corroboration status).
func TestPolicyDifferenceExplained(t *testing.T) {
	conformance.Partial(t, "P-11", "resolver views (grades, defaults, corroboration status); the CLI surfaces that print the policy digest need the CLI")
	conformance.Partial(t, "P-08", "a policy change between two runs is named by policy.Diff and cited in explain; statement, evaluator, time and execution-context causes and the CLI diff surface remain")
	w := groupWorld(t, "bytes", "", map[string]string{"A": "r~1", "BB": "r~2"})
	q := w.workflow("Q", "W", "protocol", "K")
	cmp := WithComparator(newFakeComparator("r~1", "r~2"))
	p1 := pol(t, []*canon.Object{pinSel(dig("W"), policy.RoleWorkflow, w.ids["wf:W:WA"])}, nil)
	p1b := pol(t, []*canon.Object{pinSel(dig("W"), policy.RoleWorkflow, w.ids["wf:W:WA"])}, nil)
	p2 := pol(t, []*canon.Object{pinSel(dig("W"), policy.RoleWorkflow, q)}, nil)

	r1 := w.store(nil, cmp, WithPolicy(p1)).Artifact(dig("r~1"))
	r1b := w.store(sampleOrders(len(w.lines), 7, 1)[0], cmp, WithPolicy(p1b)).Artifact(dig("r~1"))
	if r1.Render() != r1b.Render() {
		t.Fatal("identical statements, policy and evaluator gave different answers")
	}
	r2 := w.store(nil, cmp, WithPolicy(p2)).Artifact(dig("r~1"))
	if r1.Step == r2.Step {
		t.Fatalf("the policy difference did not move the grade: %s", r1.Step)
	}
	diff := policy.Diff(p1, p2)
	if len(diff) != 3 || !strings.Contains(diff[0], p1.Digest+" -> "+p2.Digest) || !strings.Contains(diff[2], q) {
		t.Fatalf("diff %q", diff)
	}
	for _, v := range []struct {
		a *Artifact
		p *policy.Policy
	}{{r1, p1}, {r2, p2}} {
		has(t, v.a.Render(), "reader policy sha256:"+shortDigest(v.p.Digest)+" selects")
		has(t, v.a.Render(), v.p.Selections[0].String())
	}
	// not a validity difference: the same runs (statements, signers, outputs) on both sides
	ids := func(a *Artifact) (out []string) {
		for _, run := range a.Group.Runs {
			out = append(out, run.Statement+run.Signer+run.Output)
		}
		return out
	}
	if !slices.Equal(ids(r1), ids(r2)) || !slices.Equal(r1.NotCounted, r2.NotCounted) {
		t.Fatal("the policy changed which statements count")
	}

	// a trust difference: one reader trusts C3 too
	hw, x := hotReading(t)
	t1 := pol(t, nil, []*canon.Object{trustKey(hw.signer("S1"), []string{"corroboration"}), trustKey(hw.signer("S2"), []string{"corroboration"})})
	t2 := pol(t, nil, []*canon.Object{trustKey(hw.signer("S1"), []string{"corroboration"}), trustKey(hw.signer("S2"), []string{"corroboration"}), trustKey(hw.signer("C3"), []string{"corroboration"})})
	o1, _ := hw.store(nil, WithPolicy(t1)).Observation(x)
	o2, _ := hw.store(nil, WithPolicy(t2)).Observation(x)
	wantStatus(t, o1, "corroborated 2 within statements you hold")
	wantStatus(t, o2, "corroborated 2 · contradicted 1 within statements you hold")
	has(t, o1.Render(), "not trusted for corroboration of sha256:"+shortDigest(dig("X"))[:5])
	has(t, o1.Render(), "under reader policy sha256:"+shortDigest(t1.Digest))
	if d := policy.Diff(t1, t2); len(d) != 2 || !strings.HasPrefix(d[1], "+ trust ") || !strings.Contains(d[1], hw.signer("C3")) {
		t.Fatalf("trust diff %q", d)
	}
}

// TestPolicyPermutationProperty: P-01 with a policy configured. Selections and trust are functions of the held
// set, so every delivery order gives one rendering.
func TestPolicyPermutationProperty(t *testing.T) {
	opts := []Option{WithTimeVerifier(newFakeBitcoin(100, 101)), WithComparator(newFakeComparator("X", "Y", "r~1", "r~2"))}
	for seed := uint64(1); seed <= 25; seed++ {
		w, blobs := genAuthorship(t, seed)
		var sels []*canon.Object
		var tr []*canon.Object
		sels = append(sels, keySel(dig("W"), policy.RoleWorkflow, w.signer("A")))
		for _, x := range blobs[:2] {
			sels = append(sels, keySel(dig(x), policy.RoleAuthorship, w.signer([]string{"A", "BB", "C"}[seed%3])))
		}
		tr = append(tr, trustKey(w.signer("BB"), []string{"attestation"}))
		p := pol(t, sels, tr)
		for _, x := range blobs {
			first := w.store(nil, append(opts, WithPolicy(p))...).Artifact(dig(x)).Render()
			for _, o := range sampleOrders(len(w.lines), seed, 8) {
				if got := w.store(o, append(opts, WithPolicy(p))...).Artifact(dig(x)).Render(); got != first {
					t.Fatalf("seed %d blob %s order %v:\n%s\nvs\n%s", seed, x, o, got, first)
				}
			}
		}
	}
}

// TestPolicyChangeNamesItsCause: C-core-06 (c). State S shows `contradicted 1` under a policy that trusts C3; a
// policy change that stops trusting C3 moves the result, the contradicting statement is still listed, and the
// change names its cause: the new policy digest, beside the statement it no longer counts.
func TestPolicyChangeNamesItsCause(t *testing.T) {
	conformance.Partial(t, "C-core-06", "(c) a reader policy change; (a) a corroboration and (b) a revocation moving the status, each naming its cause, need the explain diff surface")
	w, x := hotReading(t)
	all := []*canon.Object{trustKey(w.signer("S1"), []string{"corroboration"}), trustKey(w.signer("S2"), []string{"corroboration"}), trustKey(w.signer("C3"), []string{"corroboration"})}
	before := pol(t, nil, all)
	after := pol(t, nil, all[:2])
	s, _ := w.store(nil, WithPolicy(before)).Observation(x)
	n, _ := w.store(nil, WithPolicy(after)).Observation(x)
	if s.Corroboration.Contradicted != 1 || n.Corroboration.Contradicted != 0 {
		t.Fatalf("before %s, after %s", s.Corroboration.Status(), n.Corroboration.Status())
	}
	line := "corroborates by " + shortKey(w.signer("C3")) + " in " + keylog.Short(w.ids["C3"]) + ": contradicts under M (not trusted for corroboration"
	has(t, n.Render(), line)
	has(t, n.Render(), "under reader policy sha256:"+shortDigest(after.Digest)+") [not counted]")
	has(t, n.Render(), "evaluated under reader policy "+after.Digest)
}
