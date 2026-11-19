package gate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/resolve"
)

// P-09 over the gates' delegated checks. Each check a gate consults (the edition-rule dialect and content reader
// behind intended_for, the series segment re-check behind the freeze policy, the completeness evaluator, the
// contested-authorship view) is replaced, one row at a time, by evidence that is missing, unsupported, failing or
// lying. Every row runs through all four gates over one fixture, and asserts the same thing: the gate never
// shows the check as passing. A row that must not pass is `unchecked`/`could not check`/refused, with the
// named outcome in the label or the typed member. Each family has a control row that does pass, so the
// assertion cannot hold vacuously.

// ----- shared builders ------------------------------------------------------------------------------------

type sweepDialect struct {
	name string
	eval func(d *resolve.Domain) (resolve.Outcome, string, []string)
	err  error
}

func (s sweepDialect) Name() string { return s.name }
func (s sweepDialect) Compile(string) (resolve.Rule, error) {
	if s.err != nil {
		return nil, s.err
	}
	return sweepRule(s.eval), nil
}

type sweepRule func(d *resolve.Domain) (resolve.Outcome, string, []string)

func (r sweepRule) Eval(d *resolve.Domain) (resolve.Outcome, string, []string) { return r(d) }

// emptyContent holds nothing; unscannedContent holds every blob but could not read it.
type emptyContent struct{}

func (emptyContent) Units(string) ([]resolve.ContentUnit, bool) { return nil, false }

type unscannedContent struct{}

func (unscannedContent) Units(d string) ([]resolve.ContentUnit, bool) {
	return []resolve.ContentUnit{{Name: d, Unscanned: "compression=xz"}}, true
}

// okEverything answers ok without reading anything; it is the lying dialect's body in several rows.
func okEverything(*resolve.Domain) (resolve.Outcome, string, []string) {
	return resolve.RuleOK, "", nil
}

// ----- 1. rule dialect, content reader, step budget: intended_for --------------------------------------------

// TestSweepRuleEvidenceNeverPasses: the receiver's re-application of a statement's intended_for. The statement
// is compliant and the publisher said ok. With every evidence substitution below, no gate computes `ok` for
// the named or the current edition: the report carries the typed outcome `unchecked`, the label says so, the
// statement is not endorsed. The control (a real dialect and a content reader) computes ok at all four gates, so
// the rows are not vacuous; a failing rule is refused at the pre-pin check and labelled `fail` elsewhere.
func TestSweepRuleEvidenceNeverPasses(t *testing.T) {
	w := newWorld(t)
	g := w.sign("C", "genesis", obj("type", "collection", "name", "readings", "controllers", []string{w.signer("C")}, "rule", obj("any_one", true)))
	e1 := edition(w, "C", g, []string{g}, "rules", canon.Array{obj("dialect", "rc-test/1", "expr", "FORBID secret")})
	e2 := edition(w, "C", g, []string{e1}, "rules", canon.Array{obj("dialect", "rc-test/1", "expr", "FORBID secret")}) // current differs from named
	held := w.held(g, e1, e2)
	okBlob := []byte(`{"reading":1}`)
	badBlob := []byte(`{"secret":"x"}`)
	content := contentTable{blobDigest(okBlob): okBlob, blobDigest(badBlob): badBlob}
	claim := func() canon.Value {
		return obj("resource", g, "edition", edID(w, e1), "edition_applied", edID(w, e1), "outcome", "ok")
	}
	compliant := w.authored("N", okBlob, "intended_for", claim())
	forged := w.authored("M", badBlob, "intended_for", claim())
	pkg := Package{Objects: []Object{w.object(compliant), w.object(forged)}}

	real := resolve.WithDialect(forbidDialect{})
	reads := func(opts ...resolve.Option) []resolve.Option { return opts }
	rows := []struct {
		name string
		opts []resolve.Option
	}{
		{"missing: nothing configured (the shipped reader)", nil},
		{"missing: dialect not registered", reads(resolve.WithContent(content))},
		{"missing: content reader absent", reads(real)},
		{"missing: content reader holds nothing", reads(real, resolve.WithContent(emptyContent{}))},
		{"unsupported: dialect refuses the construct", reads(resolve.WithDialect(sweepDialect{name: "rc-test/1", err: fmt.Errorf("no such construct")}), resolve.WithContent(content))},
		{"unsupported: content in a compression the scanner cannot read", reads(real, resolve.WithContent(unscannedContent{}))},
		{"lying: dialect answers a word outside the rule vocabulary", reads(resolve.WithDialect(sweepDialect{name: "rc-test/1", eval: func(*resolve.Domain) (resolve.Outcome, string, []string) {
			return resolve.Outcome("pass"), "", nil
		}}), resolve.WithContent(content))},
		{"lying: dialect says ok after reading outside its domain", reads(resolve.WithDialect(sweepDialect{name: "rc-test/1", eval: func(d *resolve.Domain) (resolve.Outcome, string, []string) {
			d.Get("https://example.invalid/oracle", "verdict")
			return resolve.RuleOK, "", nil
		}}), resolve.WithContent(content))},
		{"lying: dialect says ok over content it found unscanned", reads(resolve.WithDialect(sweepDialect{name: "rc-test/1", eval: func(d *resolve.Domain) (resolve.Outcome, string, []string) {
			d.Content("")
			return resolve.RuleOK, "", nil
		}}), resolve.WithContent(unscannedContent{}))},
		{"failing: step budget exhausted before the rule finishes", reads(resolve.WithDialect(sweepDialect{name: "rc-test/1", eval: func(d *resolve.Domain) (resolve.Outcome, string, []string) {
			for i := 0; i < 5; i++ {
				d.Get("", "type")
			}
			return resolve.RuleOK, "", nil
		}}), resolve.WithContent(content), resolve.WithRuleSteps(2))},
	}
	for _, row := range rows {
		for _, gname := range gates {
			pol := DefaultPolicy()
			pol.Resolver = row.opts
			rep := mustAdmit(t, gname, pkg, held, pol, Options{})
			r := get(t, rep, w.path(compliant))
			if r.Verdict != Admitted || r.IntendedFor == nil {
				t.Errorf("%s / %s: %s %v (want admitted with the re-application shown)", row.name, gname, r.Verdict, r.Refusal)
				continue
			}
			rec := r.IntendedFor
			if rec.Named != resolve.RuleUnchecked || (rec.CurrentEdition != "" && rec.Current != resolve.RuleUnchecked) || rec.Endorsed {
				t.Errorf("%s / %s: named %q current %q endorsed %v: a substituted check must read unchecked, never ok", row.name, gname, rec.Named, rec.Current, rec.Endorsed)
			}
			var lab string
			for _, l := range r.Labels {
				if l.Token == LabelIntendedFor {
					lab = l.Detail
				}
			}
			if !strings.Contains(lab, ": unchecked") || strings.Contains(lab, ": ok") || !strings.Contains(lab, "this receiver's computation") {
				t.Errorf("%s / %s: label %q", row.name, gname, lab)
			}
			if rep.Exit() != 0 && rep.Exit() != 3 {
				t.Errorf("%s / %s: exit %d", row.name, gname, rep.Exit())
			}
			// the forged statement is never admitted as passing either: no gate computes ok for it
			if fr := get(t, rep, w.path(forged)); fr.IntendedFor != nil && (fr.IntendedFor.Named == resolve.RuleOK || fr.IntendedFor.Current == resolve.RuleOK) {
				t.Errorf("%s / %s: forged statement computed ok", row.name, gname)
			}
		}
	}

	// control: the same fixture with the real dialect and content computes ok for the compliant statement and
	// fail for the forged one, at all four gates; the pre-pin check refuses the forged one, the others label it.
	for _, gname := range gates {
		pol := DefaultPolicy()
		pol.Resolver = reads(real, resolve.WithContent(content))
		rep := mustAdmit(t, gname, pkg, held, pol, Options{})
		if rec := get(t, rep, w.path(compliant)).IntendedFor; rec == nil || rec.Named != resolve.RuleOK || rec.Current != resolve.RuleOK {
			t.Fatalf("control %s: %+v", gname, rec)
		}
		fr := get(t, rep, w.path(forged))
		if fr.IntendedFor == nil || fr.IntendedFor.Named != resolve.RuleFail {
			t.Fatalf("control %s: forged %+v", gname, fr.IntendedFor)
		}
		if (gname == "pre-pin") != (fr.Verdict == Refused) {
			t.Fatalf("control %s: forged verdict %s", gname, fr.Verdict)
		}
	}
}

// ----- 2. series segment re-check: the freeze policy -----------------------------------------------------------

type segFn func(m *resolve.Member) resolve.SegmentState

func (f segFn) Segment(m *resolve.Member) resolve.SegmentState { return f(m) }

// TestSweepSegmentEvidenceNeverPasses: series.refuse_premature_freeze at each gate. The declaration is no later
// than the members' boundary in every row, so the only thing that can stop an endorsement is the evidence about
// the members. Missing, unsupported, malformed and as-captured evidence leave the edition could-not-check
// (undecided, exit 3); none admits it clean. The control (every segment re-checked final, declaration inside the
// boundary) is admitted with no label; a declaration past the boundary is refused.
func TestSweepSegmentEvidenceNeverPasses(t *testing.T) {
	// seriesFixture signs a fresh series, its three segments and one edition declaring frozen_before decl over
	// members (the three segments, or none); a fresh world each time, so every edition is the key's first line
	// after the genesis and nothing is detached.
	type fix struct {
		w      *world
		held   MemHeld
		ed     string
		segIDs []string
	}
	mk := func(decl *canon.Object, noMembers bool, more ...any) fix {
		w := newWorld(t)
		g := w.sign("C", "genesis", obj("type", "series", "name", "runs", "controllers", []string{w.signer("C")}, "rule", obj("any_one", true)))
		var ids []string
		segs := canon.Array{}
		for _, m := range []string{"01", "02", "03"} {
			id := w.sign("O", "observed", obj("content", contentOf([]byte("seg"+m)), "class", "none-yet", "referent", canon.Value(obj()),
				"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"))))
			ids = append(ids, id)
			segs = append(segs, obj("statement", id, "role", "segment"))
		}
		if noMembers {
			segs = canon.Array{}
		}
		kv := append([]any{"members", segs, "frozen_before", decl}, more...)
		ed := edition(w, "C", g, []string{g}, kv...)
		return fix{w, w.held(append([]string{g}, ids...)...), ed, ids}
	}
	day := func(m string) resolve.Boundary { return resolve.Boundary{Unit: "date", Date: "2025-" + m + "-01"} }
	state := func(i int, mut func(i int, s *resolve.SegmentState)) resolve.SegmentState {
		s := resolve.SegmentState{From: day([]string{"01", "02", "03"}[i]), To: day([]string{"02", "03", "04"}[i]), Rule: true, Final: "final"}
		if mut != nil {
			mut(i, &s)
		}
		return s
	}
	reader := func(f fix, mut func(i int, s *resolve.SegmentState)) segFn {
		idx := map[string]int{}
		for i, id := range f.segIDs {
			idx[id] = i
		}
		return func(m *resolve.Member) resolve.SegmentState { return state(idx[m.Key], mut) }
	}
	rows := []struct {
		name      string
		decl      *canon.Object
		noMembers bool
		mut       func(i int, s *resolve.SegmentState) // nil with !shipped: a clean re-check
		shipped   bool                                 // the shipped default reader: positions only, no finality re-check
	}{
		{name: "missing: no re-check configured (shipped default)", decl: obj("date", "2025-02-01"), shipped: true},
		{name: "missing: one segment unchecked", decl: obj("date", "2025-02-01"), mut: func(i int, s *resolve.SegmentState) {
			if i == 1 {
				s.Final, s.Why = "unchecked", "source unreachable"
			}
		}},
		{name: "missing: every segment unchecked", decl: obj("date", "2025-02-01"), mut: func(i int, s *resolve.SegmentState) { s.Final, s.Why = "unchecked", "no source" }},
		{name: "unsupported: a segment carries no finality rule", decl: obj("date", "2025-02-01"), mut: func(i int, s *resolve.SegmentState) {
			if i == 2 {
				s.Rule = false
			}
		}},
		{name: "unsupported: segment positions in different units", decl: obj("date", "2025-02-01"), mut: func(i int, s *resolve.SegmentState) {
			if i == 1 {
				s.From, s.To = resolve.Boundary{Unit: "run", Run: "R1"}, resolve.Boundary{}
			}
		}},
		{name: "lying: finality word outside the vocabulary", decl: obj("date", "2025-02-01"), mut: func(i int, s *resolve.SegmentState) { s.Final = "ok" }},
		{name: "lying: final with no position", decl: obj("date", "2025-02-01"), mut: func(i int, s *resolve.SegmentState) { s.From, s.To = resolve.Boundary{}, resolve.Boundary{} }},
		{name: "unsupported: declared in runs, computed in dates", decl: obj("run", "R1")},
		{name: "as captured: asserted states, never re-checked", decl: obj("date", "2025-02-01"), mut: func(i int, s *resolve.SegmentState) { s.AsCaptured = true }},
		{name: "as held: states read from held responses, still not a re-check", decl: obj("date", "2025-02-01"), mut: func(i int, s *resolve.SegmentState) { s.AsCaptured, s.Held = true, true }},
		{name: "missing: an edition with no segments", decl: obj("date", "2025-02-01"), noMembers: true},
	}
	for _, row := range rows {
		f := mk(row.decl, row.noMembers)
		for _, gname := range gates {
			pol := DefaultPolicy()
			pol.Freeze = resolve.RequireDeclaredNotAfterComputed{}
			if !row.shipped {
				pol.Resolver = []resolve.Option{resolve.WithSegments(reader(f, row.mut))}
			}
			rep := mustAdmit(t, gname, Package{Objects: []Object{f.w.object(f.ed)}}, f.held, pol, Options{})
			r := get(t, rep, f.w.path(f.ed))
			if r.Verdict != Undecided || rep.Exit() != 3 || !r.HasLabel(LabelSeriesUnknown) || r.Next == "" {
				t.Errorf("%s / %s: %s %v exit %d labels %v: a substituted segment check must leave the edition could-not-check", row.name, gname, r.Verdict, r.Refusal, rep.Exit(), r.Labels)
			}
		}
	}
	// control: a clean re-check admits a declaration inside the boundary with no could-not-check label, and
	// refuses one past it
	for _, gname := range gates {
		for _, c := range []struct {
			decl string
			want Verdict
		}{{"2025-02-01", Admitted}, {"2025-09-01", Refused}} {
			f := mk(obj("date", c.decl), false)
			pol := DefaultPolicy()
			pol.Freeze = resolve.RequireDeclaredNotAfterComputed{}
			pol.Resolver = []resolve.Option{resolve.WithSegments(reader(f, nil))}
			rep := mustAdmit(t, gname, Package{Objects: []Object{f.w.object(f.ed)}}, f.held, pol, Options{})
			r := get(t, rep, f.w.path(f.ed))
			if r.Verdict != c.want || r.HasLabel(LabelSeriesUnknown) {
				t.Fatalf("control %s %s: %s %v %v", gname, c.decl, r.Verdict, r.Refusal, r.Labels)
			}
		}
	}
}

// ----- 3. completeness evaluator ---------------------------------------------------------------------------

// TestSweepCompletenessEvidenceNeverPasses: selection.refuse_incomplete at each gate. A completeness claim whose
// check cannot run (the claim names no scope, a reading's source or position cannot be read, a position in
// another timescale, a source URI equal only up to normalisation) is undecided, never ok. The control claim over
// readable readings is ok and labelled; a claim that omits a held reading is refused.
func TestSweepCompletenessEvidenceNeverPasses(t *testing.T) {
	const station = "urn:example:station-7"
	scope := obj("class", "phenomenon", "source", station, "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-02-01T00:00:00Z"))
	reading := func(w *world, by, tag string, referent *canon.Object) string {
		return w.sign(by, "observed", obj("content", contentOf([]byte(tag)), "class", "phenomenon", "referent", canon.Value(referent),
			"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"))))
	}
	good := func(at string) *canon.Object {
		return obj("instrument", station, "location", "geo:39.74,-104.99", "at", at)
	}
	type fixture struct {
		w    *world
		g    string
		held MemHeld
		ids  []string
	}
	build := func(extra func(w *world) []string) fixture {
		w := newWorld(t)
		g := w.sign("C", "genesis", obj("type", "collection", "name", "january", "controllers", []string{w.signer("C")}, "rule", obj("any_one", true)))
		ids := []string{reading(w, "O", "jan-03", good("2026-01-03T12:00:00Z")), reading(w, "O", "jan-10", good("2026-01-10T12:00:00Z"))}
		if extra != nil {
			ids = append(ids, extra(w)...)
		}
		return fixture{w, g, w.held(append([]string{g}, ids...)...), ids}
	}
	members := func(ids ...string) canon.Array {
		var a canon.Array
		for _, id := range ids {
			a = append(a, resolve.Entry("statement", id, "member"))
		}
		return a
	}
	claim := func(f fixture, ids []string, sc canon.Value) string {
		kv := []any{"members", members(ids...), "selection", "completeness"}
		if sc != nil {
			kv = append(kv, "completeness", sc)
		}
		return edition(f.w, "C", f.g, []string{f.g}, kv...)
	}
	rows := []struct {
		name  string
		extra func(w *world) []string
		sc    canon.Value
	}{
		{"missing: the claim names no scope", nil, nil},
		{"unsupported: a reading whose referent names no source", func(w *world) []string {
			return []string{reading(w, "O", "nosrc", obj("location", "geo:1,1", "at", "2026-01-05T00:00:00Z"))}
		}, scope},
		{"missing: a reading with no position", func(w *world) []string {
			return []string{reading(w, "O", "nopos", obj("instrument", station, "location", "geo:1,1"))}
		}, scope},
		{"unsupported: a reading positioned in another timescale", func(w *world) []string {
			return []string{reading(w, "O", "tai", obj("instrument", station, "location", "geo:1,1", "at", "2026-01-05T00:00:37", "timescale", "TAI"))}
		}, scope},
		{"lying: a source equal only up to a trailing slash", func(w *world) []string {
			return []string{reading(w, "O", "loose", obj("instrument", station+"/", "location", "geo:1,1", "at", "2026-01-05T00:00:00Z"))}
		}, scope},
	}
	for _, row := range rows {
		f := build(row.extra)
		// the claim lists every reading but the unreadable one, so only the unreadable one can stop it
		listed := f.ids[:2]
		ed := claim(f, listed, row.sc)
		for _, gname := range gates {
			pol := DefaultPolicy()
			pol.RefuseIncomplete = true
			rep := mustAdmit(t, gname, Package{Objects: []Object{f.w.object(ed)}}, f.held, pol, Options{})
			r := get(t, rep, f.w.path(ed))
			if r.Verdict != Undecided || rep.Exit() != 3 || r.Next == "" || !r.HasLabel(LabelCompleteness) {
				t.Errorf("%s / %s: %s %v exit %d labels %v: an unreadable claim must be could-not-check", row.name, gname, r.Verdict, r.Refusal, rep.Exit(), r.Labels)
			}
			if c := r.Completeness; c != nil && c.Outcome == resolve.RuleOK {
				t.Errorf("%s / %s: completeness computed ok", row.name, gname)
			}
		}
	}
	f := build(nil)
	okEd := claim(f, f.ids, scope)
	partial := claim(f, f.ids[:1], scope)
	for _, gname := range gates {
		pol := DefaultPolicy()
		pol.RefuseIncomplete = true
		rep := mustAdmit(t, gname, Package{Objects: []Object{f.w.object(okEd), f.w.object(partial)}}, f.held, pol, Options{})
		if r := get(t, rep, f.w.path(okEd)); r.Verdict != Admitted || r.Completeness == nil || r.Completeness.Outcome != resolve.RuleOK {
			t.Fatalf("control %s: %s %v", gname, r.Verdict, r.Refusal)
		}
		if r := get(t, rep, f.w.path(partial)); r.Verdict != Refused || r.Refusal.Reason != HubRules+": selection.refuse_incomplete" {
			t.Fatalf("control %s: partial %s %v", gname, r.Verdict, r.Refusal)
		}
	}
}

// ----- 4. time verifier: contested authorship ---------------------------------------------------------------

// TestSweepTimeEvidenceNeverPasses: two keys author one blob, each with an anchors line whose proof no verifier
// at the gate has checked (the gates configure none). No gate reports a default author: the blob stays
// `contested` at each, because an unverified proof orders nothing.
func TestSweepTimeEvidenceNeverPasses(t *testing.T) {
	w := newWorld(t)
	blob := []byte("claimed twice")
	a := w.authored("A", blob)
	aa := w.sign("A", "anchors", obj("covered", a, "proof", blobDigest([]byte("proof a")), "proof_format", "ots-detached-v1"))
	b := w.authored("B", blob)
	ba := w.sign("B", "anchors", obj("covered", b, "proof", blobDigest([]byte("proof b")), "proof_format", "ots-detached-v1"))
	pkg := Package{Objects: []Object{w.object(a), w.object(aa), w.object(b), w.object(ba)}}
	for _, gname := range gates {
		rep := mustAdmit(t, gname, pkg, w.held(), DefaultPolicy(), Options{})
		for _, id := range []string{a, b} {
			r := get(t, rep, w.path(id))
			if r.Verdict != Admitted || !r.HasLabel(LabelContested) {
				t.Errorf("%s: %s: %s %v: two anchored claimants must read contested without a verified bound", gname, id[:8], r.Verdict, r.Labels)
			}
		}
	}
}
