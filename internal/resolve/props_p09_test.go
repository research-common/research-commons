package resolve

import (
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/wire"
)

// P-09: unsupported, invalid or missing evidence never yields ok or pass (I4, §8, §13). Each row is one check
// the resolver delegates, a world where the check, configured and honest, yields the strong answer (the
// control; a row whose control does not reach it proves nothing), and the variants of the check that must not:
// missing (the reader configured none), unsupported (it does not know the format or rule), failing (it
// answers no) and lying (it answers yes with the unsupported marker, or about other bytes). For each variant
// the answer is read from the resolver, never from the check, and must be the weak token; for artifacts,
// Verify never exits 0.

type p09Row struct {
	name     string
	control  func(t *testing.T) (strong bool, what string)
	variants map[string]func(t *testing.T) (strong bool, what string)
}

// answerOf returns whether the answer is the strong one (one the reader may rest on) and a description.
type answer = func(t *testing.T) (bool, string)

// failingBitcoin verifies nothing and says why; unsupportedBitcoin verifies a format it was not asked about.
type failingBitcoin struct{}

func (failingBitcoin) Verify(a *wire.Statement) Bound {
	return Bound{Quality: NoBound, Anchor: a.ID, Why: "proof does not commit to the covered prefix"}
}

// optimisticBitcoin returns a Bitcoin-quality bound with no network or height: a verifier that claims quality
// and gives no position. The resolver must not rank on a bound it cannot place.
type optimisticBitcoin struct{}

func (optimisticBitcoin) Verify(a *wire.Statement) Bound {
	return Bound{Quality: Bitcoin, Anchor: a.ID}
}

// unknownComparator answers "unchecked" or "not comparable" for every pair; erroringComparator answers a token
// the resolver does not define.
type constComparator struct{ result string }

func (c constComparator) Compare(_, _, _ string) (string, string) { return c.result, "stub" }

// priorityWorld: two claimants of X (A anchored at 100, BB at 101); the control resolves a default author.
func priorityWorld(t *testing.T, opts ...Option) *Artifact {
	w := newWorld(t)
	w.authored("A0", "A", "X", "licence", "MIT")
	w.anchor("AA", "A", "btc:100")
	w.authored("B0", "BB", "X", "licence", "MIT")
	w.anchor("BA", "BB", "btc:101")
	return w.store(nil, opts...).Artifact(dig("X"))
}

func derivedWorld(t *testing.T, mode, comparator string, opts ...Option) (*Artifact, int) {
	w := newWorld(t)
	w.workflow("WA", "W", mode, comparator)
	w.authored("A1", "A", "r~1", "prov", []string{"W", "I"})
	w.authored("B1", "BB", "r~2", "prov", []string{"W", "I"})
	r := w.store(nil, opts...)
	code, _ := r.Verify(dig("r~1"))
	return r.Artifact(dig("r~1")), code
}

func TestPropertyUnverifiedEvidenceNeverPasses(t *testing.T) {
	conformance.Partial(t, "P-09", "every delegated check the resolver has (time verifier, comparator, replication declaration, attestation verifier, referent checker, finality rules, cohort rules, edition-rule dialect and domain, segment re-check, content reader) substituted by a missing, unsupported, failing or lying variant; the checks of later views (hub CI, pull, push, pre-pin as a gate, execution exit codes, the exchange's verifiers) are those views' and are not built here")

	t.Run("time verifier: priority needs a verified bound", func(t *testing.T) {
		good := priorityWorld(t, WithTimeVerifier(newFakeBitcoin(100, 101)))
		if good.State != Priority {
			t.Fatalf("control did not reach a default author: %s", good.Render())
		}
		for name, opt := range map[string]Option{
			"missing (default verifier)":        nil,
			"fails every proof":                 WithTimeVerifier(failingBitcoin{}),
			"claims Bitcoin quality, no height": WithTimeVerifier(optimisticBitcoin{}),
			"verifies only the earlier anchor":  WithTimeVerifier(newFakeBitcoin(100)),
			"verifies neither (other heights)":  WithTimeVerifier(newFakeBitcoin(7, 8)),
		} {
			var opts []Option
			if opt != nil {
				opts = append(opts, opt)
			}
			a := priorityWorld(t, opts...)
			switch name {
			case "verifies only the earlier anchor":
				// the earliest verified claim wins against an unverified rival (C-btc-01 (b)): the control for a
				// partial verifier, which must not make the unverified rival the default
				if a.State != Priority || a.Default.Claims[0].Signer == "" || !strings.Contains(a.Render(), "bound no anchor") && !strings.Contains(a.Render(), "local") {
					t.Fatalf("%s: %s", name, a.Render())
				}
				if !strings.Contains(a.Default.Bound.String(), "bitcoin") {
					t.Fatalf("%s: the default is not the verified claimant: %s", name, a.Render())
				}
			case "claims Bitcoin quality, no height":
				// a verified bound with no network and height places nothing: both claimants share it, same-block
				if a.State == Priority {
					t.Fatalf("%s: ranked on a bound with no position: %s", name, a.Render())
				}
			default:
				if a.State == Priority {
					t.Fatalf("%s: an unverified bound ordered claimants: %s", name, a.Render())
				}
				if a.Default != nil {
					t.Fatalf("%s: a default author without a verified bound: %s", name, a.Render())
				}
			}
		}
	})

	t.Run("comparator: a derivation step is checked only by a comparison that ran", func(t *testing.T) {
		ctl, code := derivedWorld(t, "protocol", "K", WithComparator(newFakeComparator("r~1", "r~2")))
		if ctl.Step.Tier != "T1" || code != 0 {
			t.Fatalf("control did not reach T1/exit 0: %s %d\n%s", ctl.Step, code, ctl.Render())
		}
		for name, opt := range map[string]Option{
			"missing (default runner)":         nil,
			"runner reports unchecked":         WithComparator(constComparator{"unchecked"}),
			"runner reports not comparable":    WithComparator(constComparator{"not comparable"}),
			"runner returns an unknown token":  WithComparator(constComparator{"ok"}),
			"runner returns the empty string":  WithComparator(constComparator{""}),
			"runner does not know the outputs": WithComparator(newFakeComparator("zz")),
		} {
			var opts []Option
			if opt != nil {
				opts = append(opts, opt)
			}
			a, code := derivedWorld(t, "protocol", "K", opts...)
			if a.Step.Tier != "" || code == 0 {
				t.Fatalf("%s: step %s exit %d\n%s", name, a.Step, code, a.Render())
			}
		}
		// the declaration, too: a missing or absent comparator name is not a pass (C-core-18a), nor an undeclared mode
		for _, c := range []struct{ mode, cmp string }{{"protocol", ""}, {"", ""}, {"none", ""}} {
			a, code := derivedWorld(t, c.mode, c.cmp, WithComparator(newFakeComparator("r~1", "r~2")))
			if a.Step.Tier != "" || code == 0 {
				t.Fatalf("mode %q comparator %q: step %s exit %d\n%s", c.mode, c.cmp, a.Step, code, a.Render())
			}
		}
	})

	t.Run("a verify exit of 0 needs every input statement to count", func(t *testing.T) {
		// the same T0 re-derivation, with one deriver's statement unsupported (a critical marker the reader
		// does not know), invalid-chained (detached) or absent: a group of one is never a re-derivation
		for _, variant := range []string{"unsupported", "detached", "absent"} {
			w := newWorld(t)
			w.workflow("WA", "W", "bytes", "")
			w.authored("A1", "A", "X", "prov", []string{"W", "I"})
			switch variant {
			case "unsupported":
				signCritical(w, "B1", "BB", "authored", obj("content", canon.Value(contentOf("X")), "type", "dataset",
					"provenance", obj("workflow", dig("W"), "inputs", []string{dig("I")})))
			case "detached":
				w.sign("gap", "BB", "describes", obj("about", obj("content", dig("gap")), "note", "withheld"))
				w.authored("B1", "BB", "X", "prov", []string{"W", "I"})
				w.lines = append(w.lines[:len(w.lines)-2], w.lines[len(w.lines)-1])
			}
			r := w.store(nil)
			a := r.Artifact(dig("X"))
			code, _ := r.Verify(dig("X"))
			if a.Grade.Tier == "T0" || a.Step.Tier == "T0" || code == 0 {
				t.Fatalf("%s: grade %s step %s exit %d\n%s", variant, a.Grade, a.Step, code, a.Render())
			}
		}
	})

	t.Run("attestation verifier: device-attested is verified only when the reader verifies it", func(t *testing.T) {
		w := newWorld(t)
		o1 := w.observed("O1", "O1", "X", "none-yet", obj(), "capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "device-attested", "attestation", obj("format", "x"))))
		ctl, _ := w.store(nil, WithAttestationVerifier(fakeAttest{true})).Observation(o1)
		if ctl.Capture.Verified != "device-attested" {
			t.Fatalf("control: %s", ctl.Capture.Verified)
		}
		for name, v := range map[string]AttestationVerifier{"missing": NoAttestationVerifier{}, "fails": fakeAttest{false}} {
			o, _ := w.store(nil, WithAttestationVerifier(v)).Observation(o1)
			if o.Capture.Verified == "device-attested" || o.Capture.Display != "device-attested (unverified)" {
				t.Fatalf("%s: %s / %s", name, o.Capture.Verified, o.Capture.Display)
			}
		}
		// witnessed with no witness statement, and anchored with no anchor, are not verified levels either
		w2 := newWorld(t)
		a := w2.observed("O1", "O1", "X", "none-yet", obj(), "capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "witnessed", "witnesses", []string{w2.signer("W1")})))
		b := w2.observed("O2", "O2", "Y", "none-yet", obj(), "evidence", "anchored-at-capture")
		for _, id := range []string{a, b} {
			o, _ := w2.store(nil).Observation(id)
			if o.Capture.Verified != "self-asserted" {
				t.Fatalf("an unwitnessed or unanchored capture reached %s: %s", o.Capture.Verified, o.Render())
			}
		}
	})

	t.Run("referent checker and finality rules: final needs a rule the reader evaluates", func(t *testing.T) {
		w := newWorld(t)
		depth := w.observed("D", "A", "X", "exact-bytes", chainRef(3), "finality", depthFinality("confirmations ≥ 6", 3))
		run := w.observed("R", "C", "S1", "source", apiRef("https://api.example/settle"), "finality", runFinality("RF"))
		status := func(id string, opts ...Option) *Observation {
			o, _ := w.store(nil, opts...).Observation(id)
			return o
		}
		// control: a rule the reader evaluates, a re-check that finds the bytes at depth 12
		if o := status(depth, WithReferentChecker(fakeReferents{depth: {Outcome: ReSame, State: State{HasDepth: true, Depth: 12}}})); o.ReferentStatus != RefFinal {
			t.Fatalf("control: %s", o.ReferentStatus)
		}
		// a rule nobody gave this reader a profile for is shown and left unchecked, even when the observer's
		// own state says the rule is met (settlement run RF): never final
		if o := status(run); o.ReferentStatus != RefRuleUnchecked {
			t.Fatalf("an unknown rule reached %q", o.ReferentStatus)
		}
		for name, c := range map[string]ReferentChecker{
			"missing":                                        NoReferentChecker{},
			"re-check unchecked":                             fakeReferents{depth: {Outcome: ReUnchecked, Why: "node offline"}},
			"re-check source unavailable":                    fakeReferents{depth: {Outcome: ReUnavailable, Why: "timeout"}},
			"re-check not canonical":                         fakeReferents{depth: {Outcome: ReNotCanonical, Why: "reorg"}},
			"re-check different bytes":                       fakeReferents{depth: {Outcome: ReDifferent}},
			"re-check names an unknown outcome":              fakeReferents{depth: {Outcome: "looks fine"}},
			"re-check same bytes at depth 2, below the rule": fakeReferents{depth: {Outcome: ReSame, State: State{HasDepth: true, Depth: 2}}},
			"re-check same bytes with no state":              fakeReferents{depth: {Outcome: ReSame}},
		} {
			o := status(depth, WithReferentChecker(c))
			if o.ReferentStatus == RefFinal {
				t.Fatalf("%s: reached final\n%s", name, o.Render())
			}
		}
		if o := status(depth, WithFinalityRules(unknownRules{})); o.ReferentStatus != RefRuleUnchecked {
			t.Fatalf("a finality evaluator that knows no rule reached %q", o.ReferentStatus)
		}
		// finding PROPS-F4: with no referent checker the observer's own asserted state is enough for `final`
		// when that state meets the rule (the observer is the only evidence), shown with the re-check
		// `unchecked`. The note says "an asserted finality state beside a re-check", never in place of one.
		self := w.observed("S", "OX", "X2", "exact-bytes", chainRef(9), "finality", depthFinality("confirmations ≥ 6", 9))
		if o := status(self); o.ReferentStatus == RefFinal {
			t.Skip("finding PROPS-F4: referent status final rests on the observer's asserted state alone; the re-check is unchecked")
		}
	})

	t.Run("corroboration: an unchecked evidence item is never counted", func(t *testing.T) {
		w := newWorld(t)
		x := w.observed("X", "OX", "X", "phenomenon", obj("instrument", "urn:DEN", "location", "geo:39.7,-105.0", "at", "2026-07-01T12:00:00Z"))
		w.workflow("WA", "W", "bytes", "")
		w.corroborates("S1", "S1", x, w.result("R1", "S1", "v1", "W", "X", "a"), "supports")
		ctl, _ := w.store(nil).Observation(x)
		if ctl.Corroboration.Corroborated != 1 {
			t.Fatalf("control: %s", ctl.Render())
		}
		for name, mk := range map[string]func(w *world, x string){
			"unsupported critical marker": func(w *world, x string) {
				signCritical(w, "U", "S2", "corroborates", obj("of", x, "result", strings.Repeat("ab", 32), "verdict", "supports", "model", "M"))
			},
			"statement of a revoked-before key": func(w *world, x string) {
				w.revoke("RV", "S2", "key_compromise")
				w.head["S2"], w.seq["S2"] = "", 0 // re-rooted revocation: a sibling branch, the line below is doubted
				w.corroborates("U", "S2", x, strings.Repeat("ab", 32), "supports")
			},
		} {
			w2 := newWorld(t)
			x2 := w2.observed("X", "OX", "X", "phenomenon", obj("instrument", "urn:DEN", "location", "geo:39.7,-105.0", "at", "2026-07-01T12:00:00Z"))
			mk(w2, x2)
			o, _ := w2.store(nil).Observation(x2)
			if o.Corroboration.Corroborated != 0 || !strings.HasPrefix(o.Corroboration.Status(), "unchecked") {
				t.Fatalf("%s: counted: %s", name, o.Render())
			}
		}
		// an observation whose referent lacks a field its class requires is admitted, never corroborated (C-core-30)
		w3 := newWorld(t)
		u := w3.observed("U", "OX", "X", "exact-bytes", obj("chain_id", "bip122:000000000019d6689c085ae165831e93"))
		w3.workflow("WA", "W", "bytes", "")
		w3.corroborates("S1", "S1", u, w3.result("R1", "S1", "v1", "W", "X", "a"), "supports")
		if o, _ := w3.store(nil).Observation(u); o.Corroboration.Corroborated != 0 || !o.Corroboration.Unchecked {
			t.Fatalf("an unpinned referent was corroborated: %s", o.Render())
		}
	})

	t.Run("edition rules: a rule that did not run is never ok, and neither is a membership resting on it", func(t *testing.T) {
		build := func(expr string) (*world, string, string) {
			w := newWorld(t)
			m := w.authored("M", "M", "m", "licence", "MIT")
			g := w.genesis("G", "A", 0, "A")
			w.editionWith("E1", "A", g, []string{g}, "members", entries(st(m)), "rules", rules(expr))
			return w, g, m
		}
		endorsed := func(w *world, g, m string, opts ...Option) (bool, Outcome, string) {
			mm, _ := w.store(nil, opts...).Membership(g, m)
			return mm.Endorsed, mm.Outcome, mm.Render()
		}
		w, g, m := build("IN licence MIT")
		if ok, out, r := endorsed(w, g, m, dialect); !ok || out != RuleOK {
			t.Fatalf("control: %s", r)
		}
		for name, c := range map[string]struct {
			expr string
			opts []Option
		}{
			"dialect not configured":       {"IN licence MIT", nil},
			"construct the dialect lacks":  {"KW nope", []Option{dialect}},
			"rule reads a field outside":   {"READ . type", []Option{dialect}},
			"rule reads another artifact":  {"LIAR " + strings.Repeat("ab", 32), []Option{dialect}},
			"field absent from the record": {"IN sampling.unit runs", []Option{dialect}},
			"content not held":             {"FORBID secret", []Option{dialect}},
		} {
			w, g, m := build(c.expr)
			ok, out, r := endorsed(w, g, m, c.opts...)
			if ok || out == RuleOK {
				t.Fatalf("%s: endorsed on a rule that did not run:\n%s", name, r)
			}
		}
		// an edition that declares a member schema no dialect defines endorses nothing on it
		w2 := newWorld(t)
		m2 := w2.authored("M", "M", "m", "licence", "MIT")
		g2 := w2.genesis("G", "A", 0, "A")
		w2.editionWith("E1", "A", g2, []string{g2}, "members", entries(st(m2)), "schema", dig("schema"))
		if mm, _ := w2.store(nil, dialect).Membership(g2, m2); mm.Endorsed || mm.Outcome == RuleOK {
			t.Fatalf("a member schema no dialect defines endorsed a member:\n%s", mm.Render())
		}
		// a dialect that returns a token the resolver does not define (a plugin bug) is unchecked
		if mm, _ := w.store(nil, WithDialect(badDialect{})).Membership(g, m); mm != nil && mm.Endorsed {
			t.Fatal("a dialect returning an undefined outcome endorsed")
		}
	})

	t.Run("pre-pin check: unchecked is recorded as unchecked, never ok", func(t *testing.T) {
		w := newWorld(t)
		g := w.genesis("G", "A", 0, "A")
		e1 := w.editionWith("E1", "A", g, []string{g}, "rules", rules("FORBID secret"))
		draft := obj("content", canon.Value(contentOf("c")), "type", "dataset")
		for name, opts := range map[string][]Option{
			"content not held":  {dialect, WithContent(tableContent{})},
			"no content reader": {dialect},
			"no dialect":        nil,
			"unscanned archive": {dialect, WithContent(tableContent{dig("c"): {{Name: "c", Unscanned: "encrypted"}}})},
		} {
			p, err := w.store(nil, opts...).CheckIntendedFor(draft, g, w.ed(e1))
			if err != nil {
				continue // a refusal is not ok either
			}
			if p.Outcome == RuleOK {
				t.Fatalf("%s: the pre-pin check recorded ok for a rule that could not finish", name)
			}
			if io, _ := p.Body.Get("intended_for"); str(io.(*canon.Object), "outcome") == "ok" {
				t.Fatalf("%s: the body to sign records ok", name)
			}
		}
	})

	t.Run("series: finality that was not re-checked is never a computed boundary", func(t *testing.T) {
		w, g, ids, f := seriesWorld(t)
		w.editionWith("E1", "A", g, []string{g}, "members", segs(ids...), "frozen_before", obj("date", "2025-03-01"))
		if s, _ := w.store(nil, WithSegments(f)).Series(g, ""); s.Comparison != "agrees" {
			t.Fatalf("control: %s", s.Line())
		}
		for name, opt := range map[string]Option{
			"default re-check (nothing re-checked)":              nil,
			"every segment unchecked":                            WithSegments(allSegments{SegmentState{Final: "unchecked", Why: "source offline", Rule: true, From: day("2025-01-01")}}),
			"segments with no rule":                              WithSegments(allSegments{SegmentState{Final: "final", From: day("2025-01-01")}}),
			"segments in no unit":                                WithSegments(allSegments{SegmentState{Final: "final", Rule: true}}),
			"segments report a state the reader does not define": WithSegments(allSegments{SegmentState{Final: "mostly", Rule: true, From: day("2025-01-01")}}),
		} {
			var opts []Option
			if opt != nil {
				opts = append(opts, opt)
			}
			s, _ := w.store(nil, opts...).Series(g, "")
			if s.Comparison == "agrees" || s.ComputedState == "computed" {
				t.Fatalf("%s: a boundary was computed from evidence that did not check: %s", name, s.Render())
			}
			if r := (RequireDeclaredNotAfterComputed{}).CheckSeries(s); r == nil {
				t.Fatalf("%s: the freeze policy endorsed an unverifiable freeze", name)
			}
		}
	})
}

// unknownRules is a finality evaluator that knows no rule.
type unknownRules struct{}

func (unknownRules) Evaluate(string, State) (bool, string, bool) { return false, "", false }
func (unknownRules) Compare(string, State, State) (int, bool)    { return 0, false }

// allSegments answers one state for every segment.
type allSegments struct{ s SegmentState }

func (a allSegments) Segment(*Member) SegmentState { return a.s }

// badDialect returns an outcome the resolver does not define.
type badDialect struct{}

func (badDialect) Name() string { return "rc-test/1" }
func (badDialect) Compile(string) (Rule, error) {
	return badRule{}, nil
}

type badRule struct{}

func (badRule) Eval(*Domain) (Outcome, string, []string) { return "pass", "", nil }

// TestPropertyUnverifiedGenerated: P-09 over generated worlds. For every fixture, resolving with every check
// missing (the default reader) never yields a grade of T0/T1 whose evidence is not in the held statements, and
// no Verify exit of 0 where the default reader cannot have run a comparison. A fixture whose derivation group
// has two outputs under a protocol workflow exits non-zero without a comparator.
func TestPropertyUnverifiedGenerated(t *testing.T) {
	conformance.Partial(t, "P-09", "generated worlds, default reader: no priority without a verified bound, no T1 and no exit 0 on a protocol group without a comparator, no endorsed member on an undeclared dialect; the substitutions of each check are in TestPropertyUnverifiedEvidenceNeverPasses")
	fixture.Check(t, propBaseSeed+6000, 40, fixture.Extended, func(f fixture.Fixture) string {
		pw := concretize(t, f)
		r := New(storeOf(t, pw.deliver(nil))) // no verifier, comparator, dialect or checker
		for _, x := range pw.blobs {
			a := r.Artifact(dig(x))
			code, _ := r.Verify(dig(x))
			if a.State == Priority {
				return "priority with no verified bound on " + x
			}
			if a.Step.Tier == "T1" || a.Grade.Tier == "T1" {
				return "a T1 grade with no comparator on " + x
			}
			if a.Group != nil && a.Group.Mode == "protocol" && len(a.Group.Outputs) > 1 && code == 0 {
				return "exit 0 for a protocol group with no comparator on " + x
			}
		}
		for _, p := range r.byKind["observed"] {
			o, ok := r.Observation(p.St.ID)
			if !ok {
				continue
			}
			if o.Capture.Verified == "device-attested" || o.Capture.Verified == "anchored-at-capture" {
				return "a verified capture level with no verifier"
			}
			if o.ReCheck.Outcome != ReUnchecked && o.Class != "none-yet" && o.Class != "phenomenon" && o.Class != "method" {
				return "a re-check outcome with no checker: " + o.ReCheck.Outcome
			}
		}
		res, _ := r.Resource(pw.g)
		for _, e := range res.Editions {
			if e.State != Authorized {
				continue
			}
			for _, x := range e.Members {
				key := ""
				if o, ok := x.(*canon.Object); ok {
					key = str(o, "statement") + str(o, "content")
				}
				if m, ok := r.Membership(pw.g, key); ok && m.Endorsed && len(m.Evals) > 0 {
					return "a member endorsed under rules whose dialect is not configured: " + m.Render()
				}
			}
		}
		return ""
	})
}
