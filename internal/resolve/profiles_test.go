package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
)

// settlementProfile is an ordered-label profile of a settlement source whose documents list timetable.
const timetable = "sha256:7474747474747474747474747474747474747474747474747474747474747474"

func settlementProfileBytes() []byte {
	return canon.Encode(obj("profile", SourceProfileTag, "source", "https://api.example/settlement", "dialect", DialectOrderedLabel,
		"labels", []string{"SF", "R1", "R2", "RF", "DF"}, "documents", []string{timetable}))
}

func mustProfile(t *testing.T, b []byte) *SourceProfile {
	t.Helper()
	p, err := ParseSourceProfile(b)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// TestSourceProfileOrderedLabel: C-core-104a. The ordered-label dialect under a chosen profile: a state is met
// at or after the rule's label in the profile's list; a label outside the list (the state's or the rule's) is
// not comparable, never ordered by spelling; a rule_source naming no chosen profile, or two, is unchecked with
// the reason; the profile resolves by its digest or by a document it lists. Control: a depth rule needs no
// profile.
func TestSourceProfileOrderedLabel(t *testing.T) {
	conformance.Covers(t, "C-core-104a")
	pb := settlementProfileBytes()
	p := mustProfile(t, pb)
	if p.Digest != sha(pb) || len(p.Labels) != 5 {
		t.Fatalf("%+v", p)
	}
	rules := NewProfileRules(p)
	run := func(l string) State { return State{Run: l} }
	type want struct {
		met  bool
		why  string // substring; "" = evaluated
		rule string
	}
	cases := map[string]struct {
		src, rule string
		s         State
		w         want
	}{
		"(a) before final, by digest": {p.Digest, "run >= RF", run("R2"), want{met: false}},
		"(a') at final":               {p.Digest, "run ≥ RF", run("RF"), want{met: true}},
		"(b) after final, by doc":     {timetable, "run >= RF", run("DF"), want{met: true}},
		"(c) state not in profile":    {p.Digest, "run >= RF", run("II"), want{why: `state "II" is not in source profile`}},
		"(c') spelled like a label":   {p.Digest, "run >= RF", run("RF "), want{why: "not comparable"}},
		"(d) no chosen profile":       {"https://elsewhere.example/policy", "run >= RF", run("RF"), want{why: "names no source profile this reader chose"}},
		"(d') no rule_source":         {"", "run >= RF", run("RF"), want{why: "cites no rule_source"}},
		"(e) rule label not in it":    {p.Digest, "run >= XF", run("DF"), want{why: `rule label "XF" is not in source profile`}},
		"another dialect":             {p.Digest, "epoch finalized", run("DF"), want{why: "neither finality dialect"}},
		"label rule, depth state":     {p.Digest, "run >= RF", State{HasDepth: true, Depth: 9}, want{why: "needs a run state"}},
		"control: depth, no profile":  {"", "confirmations >= 6", State{HasDepth: true, Depth: 7}, want{met: true}},
		"control: depth, unmet":       {"", "confirmations>=6", State{HasDepth: true, Depth: 5}, want{met: false}},
	}
	for name, c := range cases {
		met, _, why := rules.For(c.src).Check(c.rule, c.s)
		if c.w.why == "" && (why != "" || met != c.w.met) || c.w.why != "" && (!strings.Contains(why, c.w.why) || met) {
			t.Errorf("%s: met %v why %q, want %+v", name, met, why, c.w)
		}
	}
	// (f) two chosen profiles named by one rule_source: unchecked, neither picked, in either order of choice
	other := mustProfile(t, canon.Encode(obj("profile", SourceProfileTag, "source", "https://api.example/settlement", "dialect", DialectOrderedLabel,
		"labels", []string{"RF", "SF"}, "documents", []string{timetable})))
	for _, r := range []ProfileRules{NewProfileRules(p, other), NewProfileRules(other, p)} {
		if _, _, why := r.For(timetable).Check("run >= RF", run("DF")); !strings.Contains(why, "names 2 source profiles") || !strings.Contains(why, "none is picked") {
			t.Fatalf("(f): %q", why)
		}
	}
	// Compare: by index in the profile; a label outside it compares with nothing; two vintages of one label are
	// one state
	b := rules.For(p.Digest)
	if c, ok := b.Compare("run >= RF", run("R1"), run("RF")); !ok || c != -1 {
		t.Fatalf("R1 vs RF: %d %v", c, ok)
	}
	if c, ok := b.Compare("run >= RF", run("DF"), run("SF")); !ok || c != 1 {
		t.Fatalf("DF vs SF: %d %v", c, ok)
	}
	if c, ok := b.Compare("run >= RF", run("R2"), run("R2")); !ok || c != 0 {
		t.Fatalf("R2 vs R2: %d %v", c, ok)
	}
	if _, ok := b.Compare("run >= RF", run("R2"), run("II")); ok {
		t.Fatal("a label outside the profile was ordered")
	}
	// without a profile, a label rule orders nothing but equal labels (the wire-format note's default)
	nb := rules.For("")
	if _, ok := nb.Compare("run >= RF", run("R1"), run("RF")); ok {
		t.Fatal("ordered without a profile")
	}
	if c, ok := nb.Compare("run >= RF", run("RF"), run("RF")); !ok || c != 0 {
		t.Fatal("equal labels without a profile")
	}
	// As a plain FinalityRules (no rule_source): label rules unevaluated, depth rules as DepthRules
	if _, _, known := rules.Evaluate("run >= RF", run("DF")); known {
		t.Fatal("a label rule evaluated without a rule_source")
	}
	if met, final, known := rules.Evaluate("confirmations >= 6", State{HasDepth: true, Depth: 6}); !known || !met || final != "6" {
		t.Fatal("depth rule")
	}
}

// TestSourceProfileParse: a profile is canonical JSON with only the defined members, within their constraints;
// anything else is not a profile, and the error names why. The mutation of each negative reaches the parser
// (the positive control parses).
func TestSourceProfileParse(t *testing.T) {
	mustProfile(t, settlementProfileBytes())
	mustProfile(t, canon.Encode(obj("profile", SourceProfileTag, "source", "chain:bitcoin", "dialect", DialectIntegerDepth, "description", "six blocks")))
	enc := func(kv ...any) []byte { return canon.Encode(obj(kv...)) }
	base := []any{"profile", SourceProfileTag, "source", "s", "dialect", DialectOrderedLabel}
	cases := map[string]struct {
		b   []byte
		why string
	}{
		"not canonical":     {[]byte(`{"source":"s","profile":"rc-source-profile/1","dialect":"ordered-label","labels":["a"]}`), "canonical"},
		"whitespace":        {append(enc(append(base, "labels", []string{"a"})...), '\n'), "canonical"},
		"undefined member":  {enc(append(base, "labels", []string{"a"}, "tolerance", 1)...), `undefined member "tolerance"`},
		"wrong tag":         {enc("profile", "rc-source-profile/2", "source", "s", "dialect", DialectOrderedLabel, "labels", []string{"a"}), "profile is not"},
		"no tag":            {enc("source", "s", "dialect", DialectOrderedLabel, "labels", []string{"a"}), `missing required member "profile"`},
		"no source":         {enc("profile", SourceProfileTag, "dialect", DialectOrderedLabel, "labels", []string{"a"}), "source is missing"},
		"no dialect":        {enc("profile", SourceProfileTag, "source", "s", "labels", []string{"a"}), "dialect is missing"},
		"other dialect":     {enc("profile", SourceProfileTag, "source", "s", "dialect", "regex", "labels", []string{"a"}), "not one the format defines"},
		"no labels":         {enc(base...), "needs 1 to 4096 labels"},
		"repeated label":    {enc(append(base, "labels", []string{"a", "b", "a"})...), `labels[2] "a" repeats`},
		"empty label":       {enc(append(base, "labels", []string{"a", ""})...), "labels[1] is not a non-empty string"},
		"padded label":      {enc(append(base, "labels", []string{" a"})...), "surrounding whitespace"},
		"depth with labels": {enc("profile", SourceProfileTag, "source", "s", "dialect", DialectIntegerDepth, "labels", []string{"a"}), "carries no labels"},
		"repeated document": {enc(append(base, "labels", []string{"a"}, "documents", []string{"x", "x"})...), `documents[1] "x" repeats`},
		"not an object":     {[]byte(`[]`), "not an object"},
		"duplicate key":     {[]byte(`{"profile":"rc-source-profile/1","profile":"rc-source-profile/1"}`), "canonical JSON"},
		"labels not a list": {enc(append(base, "labels", "a")...), "labels is not a list"},
		"source not string": {enc("profile", SourceProfileTag, "source", 1, "dialect", DialectOrderedLabel, "labels", []string{"a"}), "source is not a string"},
	}
	for name, c := range cases {
		if _, err := ParseSourceProfile(c.b); err == nil || !strings.Contains(err.Error(), c.why) {
			t.Errorf("%s: %v, want %q", name, err, c.why)
		}
	}
	long := make([]string, MaxProfileLabels+1)
	for i := range long {
		long[i] = "L" + strconv.Itoa(i)
	}
	if _, err := ParseSourceProfile(enc(append(base, "labels", long)...)); err == nil || !strings.Contains(err.Error(), "4097") {
		t.Fatalf("over the label bound: %v", err)
	}
	if _, err := ParseSourceProfile(enc(append(base, "labels", long[:MaxProfileLabels])...)); err != nil {
		t.Fatalf("at the label bound: %v", err)
	}
}

// profileSegment signs a source-class segment for month m with rule `run >= RF` at state, citing src.
func (w *world) profileSegment(name, m, state, src string) string {
	ref := obj("endpoint", "https://api.example/settlement", "parameters", obj("period", m),
		"window", obj("from", m+"-01T00:00:00Z", "to", m+"-28T00:00:00Z"))
	f := []any{"rule", "run >= RF", "state_at_capture", obj("run", state)}
	if src != "" {
		f = append(f, "rule_source", src)
	}
	return w.observedRef(name, "O", m, "source", ref, "finality", obj(f...))
}

// TestSeriesBoundaryAsCaptured: the series view under ProfileSegments (claims-model note §8, "a boundary as
// captured"). Jan–Mar captured at or after RF, Apr–May before it: members final to 2025-04-01 as captured, not
// re-checked. A later declaration is flagged and says the members do not claim it; an earlier one agrees but
// the freeze policy still does not endorse it (their word is not a re-check). A segment whose state the
// profile cannot place, or that cites no chosen profile, leaves the boundary unchecked, naming why.
func TestSeriesBoundaryAsCaptured(t *testing.T) {
	w := newWorld(t)
	p := mustProfile(t, settlementProfileBytes())
	g := w.sign("G", "A", "genesis", obj("type", "series", "name", "settlements", "controllers", w.controllers("A"), "rule", obj("any_one", true)))
	var ids []string
	for i, st := range []string{"DF", "RF", "DF", "R2", "SF"} {
		m := "2025-0" + string(rune('1'+i))
		ids = append(ids, w.profileSegment("S"+m, m, st, p.Digest))
	}
	opt := WithSegments(ProfileSegments{Rules: NewProfileRules(p)})
	w.editionWith("E1", "A", g, []string{g}, "members", segs(ids...), "frozen_before", obj("date", "2025-06-01"))
	s, _ := w.store(nil, opt).Series(g, "")
	want := "frozen_before 2025-06-01 (declared) · members final to 2025-04-01 as captured, not re-checked (2 segments provisional) · FLAGGED: declared later than computed"
	if s.Line() != want || !s.AsCaptured || s.Comparison != "flagged" || !strings.Contains(s.Render(), "the members themselves do not claim") {
		t.Fatalf("%s\n%s", s.Line(), s.Render())
	}
	if _, rf := w.store(nil, opt).EndorseSeries(g, w.ed(w.ids["E1"]), RequireDeclaredNotAfterComputed{}); rf == nil || rf.Reason != PrematureFreeze {
		t.Fatalf("flagged: %v", rf)
	}
	// at or before: agrees, but not endorsed on the members' word
	w.editionWith("E2", "A", g, []string{w.ids["E1"]}, "members", segs(ids...), "frozen_before", obj("date", "2025-04-01"))
	s, rf := w.store(nil, opt).EndorseSeries(g, "", RequireDeclaredNotAfterComputed{})
	if s.Comparison != "agrees" || !s.AsCaptured || rf == nil || !strings.Contains(s.Render(), "not confirmed (I4)") {
		t.Fatalf("at: %s %v\n%s", s.Comparison, rf, s.Render())
	}
	// control: the same states from a re-check (not as captured) agree and are endorsed
	f := fakeSegments{}
	for i, id := range ids {
		fin := "final"
		if i >= 3 {
			fin = "provisional"
		}
		f[id] = SegmentState{From: day("2025-0" + string(rune('1'+i)) + "-01"), To: day("2025-0" + string(rune('1'+i)) + "-28"), Rule: true, Final: fin}
	}
	if s, rf := w.store(nil, WithSegments(f)).EndorseSeries(g, "", RequireDeclaredNotAfterComputed{}); s.Comparison != "agrees" || rf != nil || s.AsCaptured {
		t.Fatalf("re-checked control: %s %v", s.Comparison, rf)
	}
	// all final as captured: the end of the last segment
	w2 := newWorld(t)
	g2 := w2.sign("G", "A", "genesis", obj("type", "series", "name", "s", "controllers", w2.controllers("A"), "rule", obj("any_one", true)))
	a := w2.profileSegment("a", "2025-01", "RF", timetable)
	b := w2.profileSegment("b", "2025-02", "DF", timetable)
	w2.editionWith("E", "A", g2, []string{g2}, "members", segs(a, b), "frozen_before", obj("date", "2025-02-28"))
	if s, _ := w2.store(nil, opt).Series(g2, ""); s.Computed != day("2025-02-28") || s.Comparison != "agrees" || !s.AsCaptured {
		t.Fatalf("all final: %s", s.Line())
	}
	// C-core-104e: one segment's state is not in the profile: unchecked, naming it
	w3 := newWorld(t)
	g3 := w3.sign("G", "A", "genesis", obj("type", "series", "name", "s", "controllers", w3.controllers("A"), "rule", obj("any_one", true)))
	x := w3.profileSegment("x", "2025-01", "RF", p.Digest)
	y := w3.profileSegment("y", "2025-02", "II", p.Digest)
	z := w3.profileSegment("z", "2025-03", "RF", "https://elsewhere.example/timetable")
	w3.editionWith("E", "A", g3, []string{g3}, "members", segs(x, y, z), "frozen_before", obj("date", "2025-02-01"))
	s, rf = w3.store(nil, opt).EndorseSeries(g3, "", RequireDeclaredNotAfterComputed{})
	r := s.Render()
	if s.ComputedState != "unchecked" || s.Comparison != "unchecked" || rf == nil || !strings.Contains(r, `state "II" is not in source profile`) ||
		!strings.Contains(r, "names no source profile this reader chose") || s.NoRecheck() {
		t.Fatalf("unplaceable: %s\n%s", s.Line(), r)
	}
}

// TestProfileSegmentsWithoutProfilesIsRecordSegments: with no profile chosen, ProfileSegments evaluates depth
// rules only; a label rule is unchecked. Without WithSegments at all the view is the default reader's,
// unchanged by this file (C-core-101 – C-core-104 keep their exact wording).
func TestProfileSegmentsWithoutProfilesIsRecordSegments(t *testing.T) {
	w := newWorld(t)
	g := w.sign("G", "A", "genesis", obj("type", "series", "name", "s", "controllers", w.controllers("A"), "rule", obj("any_one", true)))
	a := w.profileSegment("a", "2025-01", "RF", timetable)
	w.editionWith("E", "A", g, []string{g}, "members", segs(a), "frozen_before", obj("date", "2025-01-01"))
	def, _ := w.store(nil).Series(g, "")
	none, _ := w.store(nil, WithSegments(ProfileSegments{})).Series(g, "")
	if def.ComputedState != "unchecked" || none.ComputedState != "unchecked" || !def.NoRecheck() || none.NoRecheck() ||
		!strings.Contains(none.Render(), "cites") && !strings.Contains(none.Render(), "names no source profile") {
		t.Fatalf("default %s / none %s\n%s", def.Line(), none.Line(), none.Render())
	}
}
