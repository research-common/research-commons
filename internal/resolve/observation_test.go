package resolve

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// --- fixture language for observations ---------------------------------------------------------------------

const blockH = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"

// observed signs an `observed` by key n for blob x. kv overrides or adds body fields; "at" sets capture.at,
// "evidence" the capture evidence level (default self-asserted), "capture" replaces the capture record.
func (w *world) observed(name, n, x, class string, ref *canon.Object, kv ...any) string {
	at, evidence := "2026-10-16T00:00:00Z", "self-asserted"
	var capture canon.Value
	var rest []any
	for i := 0; i < len(kv); i += 2 {
		switch kv[i] {
		case "at":
			at = kv[i+1].(string)
		case "evidence":
			evidence = kv[i+1].(string)
		case "capture":
			capture = kv[i+1].(canon.Value)
		default:
			rest = append(rest, kv[i], kv[i+1])
		}
	}
	if capture == nil {
		capture = obj("at", at, "evidence", evidence)
	}
	b := append([]any{"content", canon.Value(contentOf(x)), "class", class, "referent", canon.Value(ref), "capture", capture}, rest...)
	return w.sign(name, n, "observed", obj(b...))
}

func chainRef(depth int) *canon.Object {
	return obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", blockH, "depth", depth)
}

func apiRef(endpoint string) *canon.Object {
	return obj("endpoint", endpoint, "parameters", obj("period", "2026-09"), "response_digest", dig("resp:"+endpoint))
}

func depthFinality(rule string, depth int) *canon.Object {
	return obj("rule", rule, "state_at_capture", obj("depth", depth))
}

func runFinality(run string) *canon.Object {
	return obj("rule", "settlement run >= RF", "rule_source", "https://example.org/timetable", "state_at_capture", obj("run", run))
}

// corroborates signs a `corroborates` by key n of observation `of`, naming result (an authored statement id) with
// a verdict under model M. kv adds body fields; a "cohort" default is a rule.
func (w *world) corroborates(name, n, of, result, verdict string, kv ...any) string {
	b := []any{"of", of, "result", result, "verdict", verdict}
	set := map[any]bool{}
	for i := 0; i < len(kv); i += 2 {
		set[kv[i]] = true
	}
	if !set["model"] {
		b = append(b, "model", "M")
	}
	if !set["cohort"] {
		b = append(b, "cohort", canon.Value(obj("rule", "every station in R within 50 km")))
	}
	return w.sign(name, n, "corroborates", obj(append(b, kv...)...))
}

// result publishes a corroboration result: an authored by n for blob out under workflow wf on inputs.
func (w *world) result(name, n, out, wf string, inputs ...string) string {
	return w.authored(name, n, out, "type", "report", "prov", append([]string{wf}, inputs...))
}

// fakeReferents answers re-checks by statement id.
type fakeReferents map[string]ReCheck

func (f fakeReferents) Check(st *wire.Statement) ReCheck {
	if rc, ok := f[st.ID]; ok {
		return rc
	}
	return NoReferentChecker{}.Check(st)
}

// settlementRules understands "settlement run >= RF" over the runs SF < SF+1 < RF < RF+1, and depth rules.
type settlementRules struct{}

var runOrder = map[string]int64{"SF": 1, "SF+1": 2, "RF": 3, "RF+1": 4}

func (settlementRules) Evaluate(rule string, s State) (bool, string, bool) {
	if rule == "settlement run >= RF" {
		n, ok := runOrder[s.Run]
		return ok && n >= runOrder["RF"], "RF", ok
	}
	return DepthRules{}.Evaluate(rule, s)
}

func (settlementRules) Compare(rule string, a, b State) (int, bool) {
	if rule == "settlement run >= RF" {
		x, ok1 := runOrder[a.Run]
		y, ok2 := runOrder[b.Run]
		return cmpInt(x, y), ok1 && ok2
	}
	return DepthRules{}.Compare(rule, a, b)
}

type blobSet map[string]bool

func (b blobSet) Has(d string) bool { return b[d] }

type fakeAttest struct{ ok bool }

func (f fakeAttest) VerifyAttestation(*wire.Statement) (bool, string) {
	if f.ok {
		return true, ""
	}
	return false, "attestation bound to other bytes"
}

type fakeCohorts struct {
	members []string
	edition string
}

func (f fakeCohorts) Apply(string) ([]string, string, string, bool) {
	return f.members, f.edition, "", true
}

type fakeOrigins map[string][]string

func (f fakeOrigins) Origins(id string) []string { return f[id] }

// obsView resolves observation id under a sample of delivery orders and requires one rendering (I14).
func obsView(t *testing.T, w *world, id string, opts ...Option) *Observation {
	t.Helper()
	var first string
	var out *Observation
	for _, o := range append([][]int{nil}, sampleOrders(len(w.lines), uint64(len(w.lines))*31, 8)...) {
		v, ok := w.store(o, opts...).Observation(id)
		if !ok {
			t.Fatalf("observation %s not found", keylog.Short(id))
		}
		if r := v.Render(); first == "" {
			first, out = r, v
		} else if r != first {
			t.Fatalf("order %v changed the observation view:\n%s\nvs\n%s", o, r, first)
		}
	}
	return out
}

func wantStatus(t *testing.T, o *Observation, want string) {
	t.Helper()
	if got := o.Corroboration.Status(); got != want {
		t.Fatalf("status %q, want %q\n%s", got, want, o.Render())
	}
}

func wantRef(t *testing.T, o *Observation, want string) {
	t.Helper()
	if o.ReferentStatus != want {
		t.Fatalf("referent status %q, want %q\n%s", o.ReferentStatus, want, o.Render())
	}
}

// --- §5.3.1 classes and referents --------------------------------------------------------------------------

// TestReaderReCheckContradicts: C-core-29. The reader re-reads H and gets different bytes: the asserted class is
// shown as O1's word with a pointer, the status is computed from evidence and scoped, and the class is never
// rewritten.
func TestReaderReCheckContradicts(t *testing.T) {
	conformance.Covers(t, "C-core-29")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "exact-bytes", chainRef(3))
	o := obsView(t, w, o1, WithReferentChecker(fakeReferents{o1: {Outcome: ReDifferent, Digest: dig("Y"), State: State{HasDepth: true, Depth: 12}}}))
	wantStatus(t, o, "contradicted 1 (reader re-check) within statements you hold")
	if o.Class != "exact-bytes" {
		t.Fatalf("class rewritten: %s", o.Class)
	}
	has(t, o.Render(), "class exact-bytes (asserted by "+shortKey(w.signer("O1"))+" in "+keylog.Short(o1)+")")
	// control: no checker → unchecked, never a count
	wantStatus(t, obsView(t, w, o1), "unchecked within statements you hold")
}

// TestReferentPinsAndUnpinned: C-core-30 (resolver half; the admission half is the wire schema test). The control
// shows all three chain referent fields; with height in place of the hash, the referent is unpinned, no
// class-specific model is applied (a supporting corroboration is listed, not counted) and the status is unchecked.
func TestReferentPinsAndUnpinned(t *testing.T) {
	conformance.Covers(t, "C-core-30")
	w := newWorld(t)
	ctl := w.observed("O1", "O1", "X", "exact-bytes", chainRef(3))
	mut := w.observed("O2", "O2", "Y", "exact-bytes", obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "height", 860000, "depth", 3))
	w.workflow("WA", "W", "bytes", "")
	res := w.result("R", "C", "verdict", "W", "Y", "REF")
	w.corroborates("CS", "C", mut, res, "supports")
	re := fakeReferents{mut: {Outcome: ReSame}}
	c := obsView(t, w, ctl, WithReferentChecker(re))
	for _, f := range []string{"referent.chain_id", "referent.block_hash", "referent.depth"} {
		has(t, c.Render(), f+":")
	}
	m := obsView(t, w, mut, WithReferentChecker(re))
	wantRef(t, m, RefUnpinned)
	wantStatus(t, m, "unchecked within statements you hold")
	if m.Corroboration.Evidence[0].Counted || m.ReCheck.Outcome != ReUnchecked {
		t.Fatalf("a model was applied to an unpinned referent:\n%s", m.Render())
	}
	has(t, m.Render(), "referent.block_hash")
	has(t, m.Render(), "no class-specific agreement model applied")
}

// TestSourceAndPhenomenonReferents: C-core-31. Each pinned field shown as the observer's statement; a re-capture
// pinning a different endpoint is never agreement. The batch variant (locating the request log inside the
// content and naming the mutated request) needs the blob bytes, which the resolver does not read.
func TestSourceAndPhenomenonReferents(t *testing.T) {
	conformance.Partial(t, "C-core-31", "single-request and instrument referents shown, different endpoint never agreement; the batch variant (log located by hash inside the content, count checked, mutated request named, unmatched log hash unpinned) needs a reader of the content blob")
	w := newWorld(t)
	src := w.observed("S1", "O1", "X", "source", apiRef("https://api.example/settlements"), "finality", runFinality("SF"))
	// a final re-capture with identical bytes would corroborate (class migration), but it pins another endpoint
	w.observed("S2", "O2", "X", "source", apiRef("https://api.example/other"), "finality", runFinality("RF"), "at", "2026-10-17T00:00:00Z")
	ph := w.observed("P1", "O3", "T", "phenomenon", obj("instrument", "urn:station:DEN-1", "location", "geo:39.74,-104.99;u=10", "at", "2026-07-01T12:00:00Z"))
	s := obsView(t, w, src, WithFinalityRules(settlementRules{}))
	for _, f := range []string{"referent.endpoint", "referent.parameters", "referent.response_digest"} {
		has(t, s.Render(), f+":")
	}
	has(t, s.Render(), "(observer's statement)")
	wantStatus(t, s, "unchecked within statements you hold")
	// control: the same endpoint at RF does corroborate, so the endpoint is what stopped S2
	w.observed("S3", "O4", "X", "source", apiRef("https://api.example/settlements"), "finality", runFinality("RF"), "at", "2026-10-18T00:00:00Z")
	wantStatus(t, obsView(t, w, src, WithFinalityRules(settlementRules{})), "corroborated 1 within statements you hold")
	p := obsView(t, w, ph)
	for _, f := range []string{"referent.instrument", "referent.location", "referent.at"} {
		has(t, p.Render(), f+":")
	}
}

// TestMethodComparability: C-core-32. Every clause member shown; with the routing era omitted, comparability to
// the other method-class observation is unchecked and names the missing field, and a corroboration whose
// comparison data is that observation is never counted as supports.
func TestMethodComparability(t *testing.T) {
	conformance.Partial(t, "C-core-32", "omission detected against another observation of the same method edition; the note does not say which system members a method edition requires, so an omission with no comparison partner is not detectable (spec finding)")
	ed := strings.Repeat("e1", 32)
	ref := func(system *canon.Object) *canon.Object {
		return obj("method_edition", ed, "environment", obj("image_digest", dig("img"), "platform", "linux/amd64", "harness_commit", strings.Repeat("c", 40)),
			"system", system, "inputs", []string{dig("seeds")}, "window", obj("from", "2026-10-01T00:00:00Z", "to", "2026-10-02T00:00:00Z"))
	}
	w := newWorld(t)
	full := w.observed("M1", "O1", "B1", "method", ref(obj("model", "m-1", "provider", "p", "routing_era", "2026-q3")))
	part := w.observed("M2", "O2", "B2", "method", ref(obj("model", "m-1", "provider", "p")))
	w.workflow("WA", "W", "bytes", "")
	res := w.result("R", "C", "cmp", "W", "B1", "B2")
	w.corroborates("CS", "C", full, res, "supports")
	o := obsView(t, w, full)
	for _, f := range []string{"method_edition", "environment", "system", "inputs", "window"} {
		has(t, o.Render(), "referent."+f+":")
	}
	has(t, o.Render(), "comparability vs "+keylog.Short(part))
	has(t, o.Render(), "it does not pin system.routing_era")
	wantStatus(t, o, "unchecked within statements you hold")
	hasNot(t, o.Render(), "corroborated")
	// the decision is structured, keyed by the full statement id, and the display is rendered from it
	if len(o.Comparability) != 1 || o.Comparability[0].With != part || o.Comparability[0].Comparable ||
		!slices.Equal(o.Comparability[0].MissingThere, []string{"system.routing_era"}) {
		t.Fatalf("comparability: %+v", o.Comparability)
	}
	// control: with the routing era pinned on both, the two are comparable and the corroboration counts
	w2 := newWorld(t)
	f2 := w2.observed("M1", "O1", "B1", "method", ref(obj("model", "m-1", "provider", "p", "routing_era", "2026-q3")))
	p2 := w2.observed("M2", "O2", "B2", "method", ref(obj("model", "m-1", "provider", "p", "routing_era", "2026-q3")))
	w2.workflow("WA", "W", "bytes", "")
	res2 := w2.result("R", "C", "cmp", "W", "B1", "B2")
	w2.corroborates("CS", "C", f2, res2, "supports")
	o2 := obsView(t, w2, f2)
	if len(o2.Comparability) != 1 || o2.Comparability[0].With != p2 || !o2.Comparability[0].Comparable {
		t.Fatalf("control comparability: %+v", o2.Comparability)
	}
	has(t, o2.Render(), "same pinned clause members")
	wantStatus(t, o2, "corroborated 1 within statements you hold")
}

// TestForkDoesNotFalsify: C-core-33. H orphaned: referent status not canonical; O2's archival re-read still
// counts; no contradiction added; the derived result shows not canonical beside its grade.
func TestForkDoesNotFalsify(t *testing.T) {
	conformance.Covers(t, "C-core-33")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "exact-bytes", chainRef(3))
	o2 := w.observed("O2", "O2", "X", "exact-bytes", chainRef(900), "at", "2028-10-16T00:00:00Z")
	w.workflow("WA", "W", "bytes", "")
	w.authored("A1", "A", "OUT", "prov", []string{"W", "X"})
	w.authored("B1", "BB", "OUT", "prov", []string{"W", "X"})
	before := obsView(t, w, o1)
	orphan := WithReferentChecker(fakeReferents{o1: {Outcome: ReNotCanonical, Why: "H orphaned"}, o2: {Outcome: ReNotCanonical, Why: "H orphaned"}})
	o := obsView(t, w, o1, orphan)
	wantRef(t, o, RefNotCanonical)
	if before.Corroboration.Status() != o.Corroboration.Status() || o.Corroboration.Status() != "corroborated 1 within statements you hold" {
		t.Fatalf("status moved: %q -> %q\n%s", before.Corroboration.Status(), o.Corroboration.Status(), o.Render())
	}
	has(t, o.Render(), "nothing counts against the observer")
	hasNot(t, o.Render(), "contradicted")
	a := w.store(nil, orphan).Artifact(dig("OUT"))
	if a.Grade.Tier != "T0" {
		t.Fatalf("grade moved: %s", a.Grade)
	}
	has(t, a.Render(), "rests on 1 observation(s): 1 not canonical")
}

// TestSourceUnavailable: C-core-34. Two source captures corroborate each other; the endpoint goes away: referent
// status source unavailable, corroborated 1 persists, the reader's new attempt is inconclusive (source
// unavailable), never contradicts.
func TestSourceUnavailable(t *testing.T) {
	conformance.Covers(t, "C-core-34")
	w := newWorld(t)
	s1 := w.observed("S1", "O1", "X1", "source", apiRef("https://api.example/e"))
	s2 := w.observed("S2", "O2", "X2", "source", apiRef("https://api.example/e"), "at", "2026-10-16T00:04:00Z")
	w.workflow("WA", "W", "bytes", "")
	r1 := w.result("R1", "O2", "v1", "W", "X1", "X2")
	r2 := w.result("R2", "O1", "v2", "W", "X2", "X1")
	w.corroborates("C1", "O2", s1, r1, "supports")
	w.corroborates("C2", "O1", s2, r2, "supports")
	gone := WithReferentChecker(fakeReferents{s1: {Outcome: ReUnavailable, Why: "endpoint unreachable"}, s2: {Outcome: ReUnavailable, Why: "endpoint unreachable"}})
	for _, id := range []string{s1, s2} {
		wantStatus(t, obsView(t, w, id), "corroborated 1 within statements you hold")
		o := obsView(t, w, id, gone)
		wantRef(t, o, RefUnavailable)
		wantStatus(t, o, "corroborated 1 within statements you hold")
		has(t, o.Render(), "reader re-check by the reader: inconclusive under source (reader re-check) (source unavailable)")
		hasNot(t, o.Render(), "contradict")
	}
}

// TestOneClassPerStatement: C-core-36. Two observers, two classes, one blob: both admitted and listed with
// signers, each corroborated under its own class's model, no blob-level class.
func TestOneClassPerStatement(t *testing.T) {
	conformance.Covers(t, "C-core-36")
	w := newWorld(t)
	w.observed("O1", "O1", "X", "exact-bytes", chainRef(9))
	w.observed("O2", "O2", "X", "source", apiRef("https://api.example/e"))
	obs := w.store(nil).Observations(dig("X"))
	if len(obs) != 2 {
		t.Fatalf("%d observations", len(obs))
	}
	classes := map[string]string{}
	for _, o := range obs {
		classes[o.Signer] = o.Class
		has(t, o.Render(), "another class: each statement is corroborated under its own class's model")
		hasNot(t, o.Render(), "blob class")
	}
	if classes[w.signer("O1")] != "exact-bytes" || classes[w.signer("O2")] != "source" {
		t.Fatalf("classes %v", classes)
	}
	// each under its own model: O1 (exact-bytes, no finality rule) with a re-read; O2's model is source-class
	w.observed("O3", "O3", "X", "exact-bytes", chainRef(20), "at", "2026-10-17T00:00:00Z")
	for _, o := range w.store(nil).Observations(dig("X")) {
		switch o.Signer {
		case w.signer("O1"):
			wantStatus(t, o, "corroborated 1 within statements you hold")
			has(t, o.Render(), "under exact-bytes")
		case w.signer("O2"):
			wantStatus(t, o, "unchecked within statements you hold")
		}
	}
}

// TestReferentStatusByRule: C-core-37. (a) provisional, (b) final on the reader's re-check, (c) revised by a
// later capture before RF, (d) not canonical after a deep reorg; the earlier observation is never contradicted
// and the status history is in explain.
func TestReferentStatusByRule(t *testing.T) {
	conformance.Covers(t, "C-core-37")
	w := newWorld(t)
	a := w.observed("A", "O1", "X", "exact-bytes", chainRef(3), "finality", depthFinality("confirmations ≥ 6", 3))
	c := w.observed("C", "O2", "S1", "source", apiRef("https://api.example/settle"), "finality", runFinality("SF"))
	w.observed("C2", "O3", "S2", "source", apiRef("https://api.example/settle"), "finality", runFinality("SF+1"), "at", "2026-10-17T00:00:00Z")
	rules := WithFinalityRules(settlementRules{})

	wantRef(t, obsView(t, w, a, rules), "provisional (3; final at 6)")
	// a rule the reader has no source profile for is shown and left unchecked, never guessed
	wantRef(t, obsView(t, w, c), RefRuleUnchecked)
	has(t, obsView(t, w, c).Render(), "which this reader cannot evaluate")
	b := obsView(t, w, a, rules, WithReferentChecker(fakeReferents{a: {Outcome: ReSame, State: State{HasDepth: true, Depth: 12}}}))
	wantRef(t, b, RefFinal)
	has(t, b.Render(), "at capture: state 3")
	has(t, b.Render(), "reader re-check: state 12, identical bytes: final")
	rc := obsView(t, w, c, rules)
	wantRef(t, rc, RefRevised)
	has(t, rc.Render(), "stays true of what it pinned")
	d := obsView(t, w, a, rules, WithReferentChecker(fakeReferents{a: {Outcome: ReNotCanonical, Why: "deep reorg replaced the block"}}))
	wantRef(t, d, RefNotCanonical)
	for _, o := range []*Observation{rc, d} {
		hasNot(t, o.Render(), "contradicted")
		has(t, o.Render(), "at capture: state")
	}
}

// TestRuleProvenance: C-core-38. cited (document held) · cited (location only, unverified) · observer's
// convention; the held document is itself listed as a source-class observation.
func TestRuleProvenance(t *testing.T) {
	conformance.Covers(t, "C-core-38")
	w := newWorld(t)
	doc := dig("timetable.pdf")
	a := w.observed("A", "O1", "X1", "source", apiRef("https://api.example/a"), "finality", obj("rule", "settlement run >= RF", "rule_source", doc, "state_at_capture", obj("run", "SF")))
	b := w.observed("B", "O1", "X2", "source", apiRef("https://api.example/b"), "finality", runFinality("SF"))
	c := w.observed("C", "O1", "X3", "source", apiRef("https://api.example/c"), "finality", obj("rule", "settlement run >= RF", "state_at_capture", obj("run", "SF")))
	d := w.observed("D", "O2", "timetable.pdf", "source", apiRef("https://example.org/timetable.pdf"))
	held := WithBlobIndex(blobSet{doc: true})
	has(t, obsView(t, w, a, held).Render(), "cited (document held) "+doc)
	has(t, obsView(t, w, a, held).Render(), "rule document observed in "+keylog.Short(d))
	has(t, obsView(t, w, b, held).Render(), "cited (location only, unverified)")
	has(t, obsView(t, w, c, held).Render(), "observer's convention")
	has(t, obsView(t, w, a).Render(), "cited (document not held)")
}

// unorderedRules is settlementRules plus a run label "SF*" it can evaluate (unmet) but not order against any other
// state: two vintages of one run label.
type unorderedRules struct{ settlementRules }

func (u unorderedRules) Evaluate(rule string, s State) (bool, string, bool) {
	if s.Run == "SF*" {
		return false, "RF", true
	}
	return u.settlementRules.Evaluate(rule, s)
}

func (u unorderedRules) Compare(rule string, a, b State) (int, bool) {
	if a.Run == "SF*" || b.Run == "SF*" {
		return 0, a == b
	}
	return u.settlementRules.Compare(rule, a, b)
}

// TestUnorderedStatesNotComparable: C-core-39a. Two captures with different bytes at states the rule cannot order
// are `inconclusive (not comparable under the rule)`, never `referent revised` (which asserts an order).
func TestUnorderedStatesNotComparable(t *testing.T) {
	conformance.Covers(t, "C-core-39a")
	w := newWorld(t)
	x := w.observed("A", "O1", "S1", "source", apiRef("https://api.example/settle"), "finality", runFinality("SF"))
	y := w.observed("B", "O2", "S2", "source", apiRef("https://api.example/settle"), "finality", runFinality("SF*"), "at", "2026-10-17T00:00:00Z")
	for _, id := range []string{x, y} {
		o := obsView(t, w, id, WithFinalityRules(unorderedRules{}))
		wantStatus(t, o, "unchecked within statements you hold")
		has(t, o.Render(), "("+NotComparableUnderRule+")")
		hasNot(t, o.Render(), "referent revised")
	}
	// control: two ordered states give the revision token
	w2 := newWorld(t)
	a := w2.observed("A", "O1", "S1", "source", apiRef("https://api.example/settle"), "finality", runFinality("SF"))
	w2.observed("B", "O2", "S2", "source", apiRef("https://api.example/settle"), "finality", runFinality("SF+1"), "at", "2026-10-17T00:00:00Z")
	has(t, obsView(t, w2, a, WithFinalityRules(unorderedRules{})).Render(), "(referent revised)")
}

// TestRevisionIsNotContradiction: C-core-39 and C-core-40. Different bytes across states before RF are
// inconclusive (referent revised); at one state, or both past RF, they contradict, symmetrically.
func TestRevisionIsNotContradiction(t *testing.T) {
	conformance.Covers(t, "C-core-39", "C-core-40")
	rules := WithFinalityRules(settlementRules{})
	for _, tc := range []struct {
		a, b, want string
	}{
		{"SF", "SF+1", "unchecked within statements you hold"},
		{"SF", "SF", "contradicted 1 within statements you hold"},
		{"RF", "RF+1", "contradicted 1 within statements you hold"},
		{"SF", "RF", "unchecked within statements you hold"}, // one before finality, one past it: revised
	} {
		w := newWorld(t)
		x := w.observed("A", "O1", "S1", "source", apiRef("https://api.example/settle"), "finality", runFinality(tc.a))
		y := w.observed("B", "O2", "S2", "source", apiRef("https://api.example/settle"), "finality", runFinality(tc.b), "at", "2026-10-17T00:00:00Z")
		for _, id := range []string{x, y} {
			o := obsView(t, w, id, rules)
			wantStatus(t, o, tc.want)
			if tc.a == "SF" && tc.b != "SF" {
				has(t, o.Render(), "inconclusive under finality-aware (settlement run >= RF) (referent revised)")
			}
		}
	}
}

// TestClassMigrationByRule: C-core-41. A source-class referent under a finality rule: R1 before the rule holds is
// evaluated under the source-class model and shown so; R2 once it holds is an exact-bytes corroboration; the
// asserted class never changes.
func TestClassMigrationByRule(t *testing.T) {
	conformance.Covers(t, "C-core-41")
	rules := WithFinalityRules(settlementRules{})
	w := newWorld(t)
	s1 := w.observed("S1", "O1", "X", "source", apiRef("https://api.example/settle"), "finality", runFinality("SF"))
	w.observed("R1", "O2", "X", "source", apiRef("https://api.example/settle"), "finality", runFinality("SF+1"), "at", "2026-10-16T00:01:00Z")
	o := obsView(t, w, s1, rules)
	wantStatus(t, o, "unchecked within statements you hold")
	has(t, o.Render(), "re-capture by "+shortKey(w.signer("O2")))
	has(t, o.Render(), "source-class model")
	w.observed("R2", "O3", "X", "source", apiRef("https://api.example/settle"), "finality", runFinality("RF"), "at", "2026-10-18T00:00:00Z")
	o = obsView(t, w, s1, rules)
	wantStatus(t, o, "corroborated 1 within statements you hold")
	has(t, o.Render(), "class migration by rule")
	if o.Class != "source" {
		t.Fatalf("class changed: %s", o.Class)
	}
}

// TestExactBytesFinalityIsStatusOnly: C-core-41a. For an exact-bytes referent the finality rule drives the
// referent status only: a re-read at depth 4 under `confirmations >= 6` is an exact-bytes corroboration (the
// bytes at a block hash never change), while the referent stays provisional; different bytes at the same hash
// contradict at any depth and are never `revised`.
func TestExactBytesFinalityIsStatusOnly(t *testing.T) {
	conformance.Covers(t, "C-core-41a")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "exact-bytes", chainRef(3), "finality", depthFinality("confirmations >= 6", 3))
	w.observed("R1", "O2", "X", "exact-bytes", chainRef(4), "at", "2026-10-16T00:01:00Z")
	o := obsView(t, w, o1)
	wantStatus(t, o, "corroborated 1 within statements you hold")
	wantRef(t, o, "provisional (3; final at 6)")
	has(t, o.Render(), "re-read by "+shortKey(w.signer("O2")))
	hasNot(t, o.Render(), "source-class model")
	// different bytes at the same hash and a depth still under the rule: a contradiction, not a revision
	w.observed("D1", "O3", "Y", "exact-bytes", chainRef(4), "finality", depthFinality("confirmations >= 6", 4), "at", "2026-10-16T00:02:00Z")
	o = obsView(t, w, o1)
	wantStatus(t, o, "corroborated 1 · contradicted 1 within statements you hold")
	wantRef(t, o, "provisional (3; final at 6)")
	hasNot(t, o.Render(), "revised")
	// the reader's own re-check with different bytes at depth 4 contradicts too
	r := obsView(t, w, o1, WithReferentChecker(fakeReferents{o1: {Outcome: ReDifferent, Digest: dig("Z"), State: State{HasDepth: true, Depth: 4}}}))
	has(t, r.Render(), "reader re-check")
	if r.Corroboration.Contradicted != 2 {
		t.Fatalf("reader re-check with different bytes at depth 4: contradicted %d, want 2\n%s", r.Corroboration.Contradicted, r.Render())
	}
}

// TestIdenticalBytesPerClass: C-core-42. Identical bytes under the source class are a second publication.
func TestIdenticalBytesPerClass(t *testing.T) {
	conformance.Covers(t, "C-core-42")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "source", apiRef("https://api.example/e"))
	w.observed("O2", "O2", "X", "source", apiRef("https://api.example/e"), "at", "2026-10-16T00:00:30Z")
	o := obsView(t, w, o1)
	wantStatus(t, o, "unchecked within statements you hold")
	has(t, o.Render(), "second publication, not a corroboration")
}

// TestExactBytesReRead: C-core-43. O2's own re-read of H, minutes or two years later: corroborated 1 both times,
// explain cites O2's capture record, no recency condition.
func TestExactBytesReRead(t *testing.T) {
	conformance.Covers(t, "C-core-43")
	for _, at := range []string{"2026-10-16T00:05:00Z", "2028-10-16T00:00:00Z"} {
		w := newWorld(t)
		o1 := w.observed("O1", "O1", "X", "exact-bytes", chainRef(3))
		w.observed("O2", "O2", "X", "exact-bytes", chainRef(30), "at", at)
		o := obsView(t, w, o1)
		wantStatus(t, o, "corroborated 1 within statements you hold")
		has(t, o.Render(), `capture record (as signed): {"at":"`+at+`"`)
	}
	// a re-read at another block hash is another referent, and the observer's own re-read is its word again
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "exact-bytes", chainRef(3))
	w.observed("O2", "O2", "X", "exact-bytes", obj("chain_id", "bip122:000000000019d6689c085ae165831e93", "block_hash", strings.Repeat("b2", 32), "depth", 30), "at", "2026-10-19T00:00:00Z")
	w.observed("O3", "O1", "X", "exact-bytes", chainRef(40), "at", "2026-10-20T00:00:00Z")
	o := obsView(t, w, o1)
	wantStatus(t, o, "unchecked within statements you hold")
	has(t, o.Render(), "signed by the observer's own key: not counted")
}

// TestCopyIsNotCapture: C-core-44. holds only, or an observed whose capture record copies O1's byte for byte:
// neither counts; explain names the shared capture record.
func TestCopyIsNotCapture(t *testing.T) {
	conformance.Covers(t, "C-core-44")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "exact-bytes", chainRef(3))
	w.sign("H", "O2", "holds", obj("content", contentOf("X")))
	wantStatus(t, obsView(t, w, o1), "unchecked within statements you hold")
	w.observed("O2", "O2", "X", "exact-bytes", chainRef(3))
	o := obsView(t, w, o1)
	wantStatus(t, o, "unchecked within statements you hold")
	has(t, o.Render(), "shares its capture record byte for byte")
}

// --- §5.3.2 corroboration ----------------------------------------------------------------------------------

// TestCorroborationIsADerivation: C-core-45 (resolver half). The corroboration names its derived result; the
// result's grade (T0 here: a second run under a bytes workflow) is shown beside it.
func TestCorroborationIsADerivation(t *testing.T) {
	conformance.Partial(t, "C-core-45", "the corroboration carries its result's grade from the runs held; the reader's own re-run of the corroboration workflow needs the execution layer")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "phenomenon", obj("instrument", "urn:station:DEN-1", "location", "geo:39.74,-104.99", "at", "2026-07-01T12:00:00Z"))
	w.workflow("WA", "W", "bytes", "")
	res := w.result("R", "C", "verdict:contradicts", "W", "X", "REF")
	w.result("R2", "D", "verdict:contradicts", "W", "X", "REF")
	w.corroborates("CC", "C", o1, res, "contradicts")
	o := obsView(t, w, o1)
	has(t, o.Render(), "result "+keylog.Short(res)+", grade T0")
}

// TestReferenceDataCited: C-core-46. A climate-bounds reference is the only comparison data: contradicts, with
// the reference cited, before any neighbour.
func TestReferenceDataCited(t *testing.T) {
	conformance.Covers(t, "C-core-46")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "phenomenon", obj("instrument", "urn:station:DEN-1", "location", "geo:39.74,-104.99", "at", "2026-07-01T12:00:00Z"))
	w.workflow("WA", "W", "bytes", "")
	res := w.result("R", "C", "verdict", "W", "X", "climate-bounds")
	w.corroborates("CC", "C", o1, res, "contradicts", "model", "climate-bounds/1")
	o := obsView(t, w, o1)
	wantStatus(t, o, "contradicted 1 within statements you hold")
	has(t, o.Render(), "comparison data: "+shortDigest(dig("climate-bounds")))
}

// TestCohortRuleReapplied: C-core-47 and C-core-62. The rule re-applied to R yields five; inputs list four: the
// fifth is left out by inputs, the corroboration's output is unchanged, and the re-application is the reader's
// computation with the collection edition cited.
func TestCohortRuleReapplied(t *testing.T) {
	conformance.Covers(t, "C-core-47", "C-core-62")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "phenomenon", obj("instrument", "urn:station:DEN-1", "location", "geo:39.74,-104.99", "at", "2026-07-01T12:00:00Z"))
	w.workflow("WA", "W", "bytes", "")
	res := w.result("R", "C", "verdict", "W", "X", "s1", "s2", "s3", "s4")
	w.corroborates("CC", "C", o1, res, "contradicts")
	before := obsView(t, w, o1)
	o := obsView(t, w, o1, WithCohortRules(fakeCohorts{members: []string{dig("s1"), dig("s2"), dig("s3"), dig("s4"), dig("s5")}, edition: "R edition e7"}))
	has(t, o.Render(), "left out by inputs: "+shortDigest(dig("s5")))
	has(t, o.Render(), "reader re-applied the cohort rule to R edition e7: 5 member(s) (the reader's computation")
	if before.Corroboration.Status() != o.Corroboration.Status() {
		t.Fatal("re-applying the cohort rule moved the status")
	}
}

// TestHandPickedCohort: C-core-48. A hand-picked cohort is labelled; a corroboration declaring neither a rule nor
// hand-picked cannot be admitted: the wire schema makes `cohort` required with exactly one of the two.
func TestHandPickedCohort(t *testing.T) {
	conformance.Partial(t, "C-core-48", "hand-picked labelled; `cohort: undeclared` is unreachable because wire §5 requires cohort with exactly one of rule/hand_picked (spec finding)")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "phenomenon", obj("instrument", "urn:s", "location", "geo:1,2", "at", "2026-07-01T12:00:00Z"))
	w.workflow("WA", "W", "bytes", "")
	res := w.result("R", "C", "v", "W", "X", "a", "b", "c")
	w.corroborates("CC", "C", o1, res, "supports", "cohort", canon.Value(obj("hand_picked", true)))
	has(t, obsView(t, w, o1).Render(), "cohort: hand-picked")
	// neither: refused at the schema, so it reaches nothing (the mutation reaches the cohort rule: the only
	// difference from a valid body is the cohort member)
	line, _ := wire.Sign(wire.Draft{Kind: "corroborates", TS: "2026-10-16T00:00:00Z",
		Body: obj("of", o1, "result", res, "verdict", "supports", "model", "M", "cohort", obj())}, testKey("C"))
	_, err := wire.Read(line)
	if r, ok := err.(*refusal.Refusal); !ok || !strings.Contains(r.Error(), "cohort") {
		t.Fatalf("got %v, want a malformed refusal naming cohort", err)
	}
}

// TestSharedSourceAndIndependence: C-core-49 and C-core-50. Declared shared sources are grouped beside the count;
// independence is unknown whatever the keys.
func TestSharedSourceAndIndependence(t *testing.T) {
	conformance.Partial(t, "C-core-49", "counting unit pending identity decision (counts distinct signing keys, labelled); quorums requiring independence are the exchange profile")
	conformance.Covers(t, "C-core-50")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "phenomenon", obj("instrument", "urn:s", "location", "geo:1,2", "at", "2026-07-01T12:00:00Z"))
	w.workflow("WA", "W", "bytes", "")
	r1 := w.result("R1", "C1", "v1", "W", "X", "N1")
	r2 := w.result("R2", "C2", "v2", "W", "X", "N2")
	w.corroborates("K1", "C1", o1, r1, "supports", "shares", []string{"upstream feed F"})
	w.corroborates("K2", "C2", o1, r2, "supports", "shares", []string{"upstream feed F"})
	o := obsView(t, w, o1)
	wantStatus(t, o, "corroborated 2 within statements you hold")
	out := o.Render()
	has(t, out, `declared shared source "upstream feed F": corroborates `)
	if sh := o.Corroboration.Shared["upstream feed F"]; len(sh) != 2 {
		t.Fatalf("shared source groups %v", sh)
	}
	has(t, out, "independence: unknown")
	has(t, out, "counted as: "+UnitKeys)

	// C-core-50: no shares declared, distinct keys: independence still unknown, never 2
	w2 := newWorld(t)
	p := w2.observed("O1", "O1", "X", "phenomenon", obj("instrument", "urn:s", "location", "geo:1,2", "at", "2026-07-01T12:00:00Z"))
	w2.workflow("WA", "W", "bytes", "")
	w2.corroborates("K1", "C1", p, w2.result("R1", "C1", "v1", "W", "X", "N1"), "supports")
	w2.corroborates("K2", "C2", p, w2.result("R2", "C2", "v2", "W", "X", "N2"), "supports")
	o2 := obsView(t, w2, p)
	if o2.Corroboration.Independence != "unknown" {
		t.Fatalf("independence %q", o2.Corroboration.Independence)
	}
	has(t, o2.Render(), "distinct keys prove nothing about independence")
}

// TestDisagreementIsSymmetric: C-core-51. D contradicted by 2 under M; each neighbour contradicted by 1; nothing
// marked wrong, false or an outlier.
func TestDisagreementIsSymmetric(t *testing.T) {
	conformance.Partial(t, "C-core-51", "counting unit pending identity decision (D's 2 counts distinct signing keys, labelled)")
	w := newWorld(t)
	ph := func(name, n, x, inst string) string {
		return w.observed(name, n, x, "phenomenon", obj("instrument", inst, "location", "geo:39.7,-105.0", "at", "2026-07-01T12:00:00Z"))
	}
	d := ph("D", "OD", "D120", "urn:D")
	n1 := ph("N1", "ON1", "N1-85", "urn:N1")
	n2 := ph("N2", "ON2", "N2-85", "urn:N2")
	w.workflow("WA", "W", "bytes", "")
	w.corroborates("K1", "C1", d, w.result("R1", "C1", "v1", "W", "D120", "N1-85"), "contradicts")
	w.corroborates("K2", "C2", d, w.result("R2", "C2", "v2", "W", "D120", "N2-85"), "contradicts")
	od := obsView(t, w, d)
	if od.Corroboration.Contradicted != 2 || !strings.Contains(od.Render(), "contradicted by 2 under M") {
		t.Fatalf("%s", od.Render())
	}
	for _, id := range []string{n1, n2} {
		o := obsView(t, w, id)
		has(t, o.Render(), "contradicted by 1 under M")
		has(t, o.Render(), "neither side is marked wrong")
	}
	for _, id := range []string{d, n1, n2} {
		out := strings.ToLower(obsView(t, w, id).Render())
		for _, bad := range []string{"outlier", "false", "suppressed", " wrong:"} {
			hasNot(t, out, bad)
		}
	}
}

// --- §5.3.3 capture evidence -------------------------------------------------------------------------------

// TestDeviceAttestedUnverified: C-core-52. An attestation bound to other bytes and one with no verifier both
// display device-attested (unverified) and contribute no verified level.
func TestDeviceAttestedUnverified(t *testing.T) {
	conformance.Partial(t, "C-core-52", "display and verified level; \"no exit 0 rests on it\" needs an observation verify exit, which the note does not define yet")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "none-yet", obj(), "capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "device-attested", "attestation", obj("format", "x"))))
	for _, opt := range []Option{WithAttestationVerifier(fakeAttest{false}), WithAttestationVerifier(NoAttestationVerifier{})} {
		o := obsView(t, w, o1, opt)
		has(t, o.Render(), "evidence device-attested (unverified)")
		if o.Capture.Verified != "self-asserted" {
			t.Fatalf("verified level %s", o.Capture.Verified)
		}
	}
	if o := obsView(t, w, o1, WithAttestationVerifier(fakeAttest{true})); o.Capture.Display != "device-attested" {
		t.Fatalf("control: %s", o.Capture.Display)
	}
}

// TestAnchoredAtCapture: C-core-53. A local anchor displays (local, self-declared); a bitcoin-verified one
// displays the time (the block height that bounds it).
func TestAnchoredAtCapture(t *testing.T) {
	conformance.Covers(t, "C-core-53")
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "none-yet", obj(), "evidence", "anchored-at-capture")
	w.anchor("AA", "O1", "btc:812000")
	has(t, obsView(t, w, o1).Render(), "evidence anchored at capture (local, self-declared)")
	o := obsView(t, w, o1, WithTimeVerifier(newFakeBitcoin(812000)))
	has(t, o.Render(), "evidence anchored at capture (bitcoin mainnet height 812000")
	if o.Capture.Verified != "anchored-at-capture" {
		t.Fatalf("verified %s", o.Capture.Verified)
	}
}

// TestWitnessed: C-core-54. A witness counts only with its own observed statement.
func TestWitnessed(t *testing.T) {
	conformance.Covers(t, "C-core-54")
	capture := obj("at", "2026-10-16T00:00:00Z", "evidence", "witnessed", "witnesses", []string{testKey("O2").Signer()})
	// (b) named only, then a byte copy of O1's capture record (a co-signature in all but name)
	w := newWorld(t)
	o1 := w.observed("O1", "O1", "X", "none-yet", obj(), "capture", canon.Value(capture))
	o := obsView(t, w, o1)
	has(t, o.Render(), "evidence witnessed (0 own statements)")
	has(t, o.Render(), "named only, no own observed statement held (not counted)")
	w.observed("O2", "O2", "X", "none-yet", obj(), "capture", canon.Value(capture))
	has(t, obsView(t, w, o1).Render(), "evidence witnessed (0 own statements)")
	// (a) O2's own observed with its own capture record
	w2 := newWorld(t)
	p := w2.observed("O1", "O1", "X", "none-yet", obj(), "capture", canon.Value(capture))
	w2.observed("O2", "O2", "X", "none-yet", obj(), "at", "2026-10-16T00:00:01Z")
	has(t, obsView(t, w2, p).Render(), "evidence witnessed by 1")
}

// TestCaptureRoles: C-core-55. Signer, operator and instrument shown separately as declared; none inferred.
func TestCaptureRoles(t *testing.T) {
	conformance.Covers(t, "C-core-55")
	w := newWorld(t)
	o1 := w.observed("O1", "K1", "X", "none-yet", obj(), "capture", canon.Value(obj("at", "2026-10-16T00:00:00Z", "evidence", "self-asserted",
		"operator", "automated runner", "instrument", "sensor S")))
	bare := w.observed("O2", "K1", "Y", "none-yet", obj())
	out := obsView(t, w, o1).Render()
	has(t, out, "roles: signer "+shortKey(w.signer("K1"))+" (statement "+keylog.Short(o1)+`) · operator "automated runner" (declared) · instrument "sensor S" (declared)`)
	has(t, obsView(t, w, bare).Render(), "operator undeclared · instrument undeclared")
}

// --- §5.4 reputation ---------------------------------------------------------------------------------------

// TestReputationIsChosen: C-core-56. Two projections under different windows and rules each show rule, window
// and denominator; the package defines no rule of its own (fresh-install control: nothing ranks observers).
func TestReputationIsChosen(t *testing.T) {
	conformance.Partial(t, "C-core-56", "counting unit pending identity decision (a record is per signing key); install-tree scan covers this package only, the CLI tree does not exist yet")
	w := newWorld(t)
	x1 := w.observed("O1", "O", "X1", "exact-bytes", chainRef(3), "at", "2026-01-10T00:00:00Z")
	w.observed("O2", "O", "X2", "phenomenon", obj("instrument", "urn:s", "location", "geo:1,2", "at", "2026-06-01T00:00:00Z"), "at", "2026-06-01T00:00:00Z")
	w.observed("R1", "Q", "X1", "exact-bytes", chainRef(9), "at", "2026-01-11T00:00:00Z")
	r := w.store(nil)
	all, err := r.Reputation(w.signer("O"), ReputationRule{Name: "all evidence", From: "2026-01-01T00:00:00Z", To: "2027-01-01T00:00:00Z", Describe: "every counted item"})
	if err != nil {
		t.Fatal(err)
	}
	q1, _ := r.Reputation(w.signer("O"), ReputationRule{Name: "corroborations only", From: "2026-01-01T00:00:00Z", To: "2026-04-01T00:00:00Z",
		Describe: "corroborates statements only", Admit: func(e Evidence) bool { return e.Via == "corroborates" }})
	if all.Denominator != 2 || all.Corroborated != 1 || q1.Denominator != 1 || q1.Corroborated != 0 {
		t.Fatalf("%s\n%s", all, q1)
	}
	for _, p := range []*Reputation{all, q1} {
		s := p.String()
		has(t, s, "under rule \""+p.Rule+"\"")
		has(t, s, "window "+p.Window)
		has(t, s, "of "+string(rune('0'+p.Denominator))+" observation(s)")
	}
	_ = x1
	// no shipped rule: no non-test source file constructs a ReputationRule
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "ReputationRule{") {
			t.Fatalf("%s constructs a ReputationRule: the tool ships no reputation default (§5.4)", f)
		}
	}
}

// --- §6 scope and hubs -------------------------------------------------------------------------------------

// hotReading builds X and two supporting corroborations (by S1, S2) and one contradicting (by C3), returning the
// observation id and the line indices of each part.
func hotReading(t *testing.T) (*world, string) {
	w := newWorld(t)
	x := w.observed("X", "OX", "X", "phenomenon", obj("instrument", "urn:DEN", "location", "geo:39.7,-105.0", "at", "2026-07-01T12:00:00Z"))
	w.workflow("WA", "W", "bytes", "")
	w.corroborates("S1", "S1", x, w.result("R1", "S1", "v1", "W", "X", "a"), "supports")
	w.corroborates("S2", "S2", x, w.result("R2", "S2", "v2", "W", "X", "b"), "supports")
	w.corroborates("C3", "C3", x, w.result("R3", "C3", "v3", "W", "X", "c"), "contradicts")
	return w, x
}

// subset returns the line indices of w except those signed by the named keys.
func subset(w *world, drop ...string) []int {
	var out []int
	for i, line := range w.lines {
		st, _ := wire.Read(line)
		keep := true
		for _, d := range drop {
			keep = keep && st.Signer != w.signer(d)
		}
		if keep {
			out = append(out, i)
		}
	}
	return out
}

// TestScopedStatus: C-core-57, C-core-58, C-core-63 and C-core-01. Every status carries its scope; a hub's
// surface says "within this hub"; a reader following two hubs sees the contradiction attributed to the hub it
// came from; a hub holding only the original shows unchecked, never corroborated or uncontradicted; an omitted
// statement is absent, never reported as non-existent.
func TestScopedStatus(t *testing.T) {
	conformance.Partial(t, "C-core-57", "counting unit pending identity decision")
	conformance.Partial(t, "C-core-58", "counting unit pending identity decision")
	conformance.Covers(t, "C-core-63")
	conformance.Partial(t, "C-core-01", "counting unit pending identity decision; the relayer delivery itself needs pull")
	w, x := hotReading(t)
	hub := subset(w, "C3")
	hb, _ := w.store(hub, WithScope(ScopeHub)).Observation(x)
	wantStatus(t, hb, "corroborated 2 within this hub")

	origins := fakeOrigins{}
	for _, name := range []string{"S1", "S2", "X"} {
		origins[w.ids[name]] = []string{"hub Hb"}
	}
	origins[w.ids["C3"]] = []string{"hub H2"}
	all, _ := w.store(nil, WithOrigins(origins)).Observation(x)
	wantStatus(t, all, "corroborated 2 · contradicted 1 within statements you hold")
	has(t, all.Render(), "corroborates by "+shortKey(w.signer("C3"))+" in "+keylog.Short(w.ids["C3"])+": contradicts")
	has(t, all.Render(), "held via hub H2 (delivery metadata)")
	// delivery metadata never moves the status
	if plain, _ := w.store(nil).Observation(x); plain.Corroboration.Status() != all.Corroboration.Status() {
		t.Fatal("origins moved the status")
	}

	only, _ := w.store(subset(w, "S1", "S2", "C3"), WithScope(ScopeHub)).Observation(x)
	wantStatus(t, only, "unchecked within this hub")
	for _, bad := range []string{"corroborated", "uncontradicted"} {
		hasNot(t, only.Render(), bad)
	}
	// C-core-01: an omitted corroboration is absent, not reported as non-existent; no completeness claim
	part, _ := w.store(subset(w, "S2")).Observation(x)
	wantStatus(t, part, "corroborated 1 · contradicted 1 within statements you hold")
	for _, bad := range []string{"no other", "complete", "all corroborations", "none exist"} {
		hasNot(t, strings.ToLower(part.Render()), bad)
	}
}

// TestNoReferenceByDefault: C-core-61 (resolver half). With no reference collection chosen, re-applying a
// cohort rule is inconclusive with cause `no reference collection chosen`; the resolver ships none.
func TestNoReferenceByDefault(t *testing.T) {
	conformance.Partial(t, "C-core-61", "the resolver's re-application with no collection chosen; running a corroboration workflow and scanning the install tree need the CLI")
	w, x := hotReading(t)
	o, _ := w.store(nil).Observation(x)
	has(t, o.Render(), "reader re-application of the cohort rule: inconclusive (no reference collection chosen)")
}

// TestRetractedObservationShown: a retraction by the observer is displayed beside the observation; a third
// party's statements about it are attributed and inputs to nothing (I2, §13 "retraction is display").
func TestRetractedObservationShown(t *testing.T) {
	w, x := hotReading(t)
	w.sign("RT", "OX", "retracts", obj("of", x, "reason", "sensor fault"))
	w.sign("RF", "C3", "refutes", obj("of", x, "evidence", dig("bounds-report")))
	before, _ := w.store(subset(w, "OX")).Observation(x)
	_ = before
	o := obsView(t, w, x)
	has(t, o.Render(), "held retracts "+keylog.Short(w.ids["RT"])+" by "+shortKey(w.signer("OX"))+" (retracted by the observer)")
	has(t, o.Render(), "held refutes "+keylog.Short(w.ids["RF"])+" by "+shortKey(w.signer("C3"))+" evidence "+shortDigest(dig("bounds-report")))
	wantStatus(t, o, "corroborated 2 · contradicted 1 within statements you hold")
}

// TestRefutesAttributed: C-core-15. C's refutes and describes are displayed beside A's artifact, attributed to C
// with the statement id and the evidence artifact; never rendered as A's word or as an unsigned field.
func TestRefutesAttributed(t *testing.T) {
	conformance.Covers(t, "C-core-15")
	w := newWorld(t)
	a1 := w.authored("A1", "A", "X", "licence", "CC0-1.0")
	w.sign("CD", "C", "describes", obj("about", obj("content", dig("X")), "note", "looks off"))
	w.sign("CR", "C", "refutes", obj("of", a1, "evidence", dig("E")))
	a := w.store(nil).Artifact(dig("X"))
	out := a.Render()
	has(t, out, "held refutes "+keylog.Short(w.ids["CR"])+" by "+shortKey(w.signer("C"))+" of "+keylog.Short(a1)+" evidence "+shortDigest(dig("E")))
	has(t, out, "held describes "+keylog.Short(w.ids["CD"])+" by "+shortKey(w.signer("C")))
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "refutes") && !strings.Contains(line, shortKey(w.signer("C"))) {
			t.Fatalf("refutes line not attributed to C: %q", line)
		}
		if strings.Contains(line, "refutes") && strings.Contains(line, "by "+shortKey(w.signer("A"))) {
			t.Fatalf("refutes rendered as A's: %q", line)
		}
	}
	for _, f := range a.Fields {
		for _, s := range append(f.From, f.Rivals...) {
			if s.Signer == w.signer("C") {
				t.Fatalf("C's statement became a field value: %+v", f)
			}
		}
	}
}
