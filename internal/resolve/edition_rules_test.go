package resolve

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/refusal"
	"github.com/research-common/research-commons/internal/wire"
)

// --- a test rule dialect -----------------------------------------------------------------------------------
//
// The rule language is a profile (claims-model note §15) and no dialect note exists, so the package ships no
// dialect. testDialect is a stand-in that exercises the domain and the outcomes. Expressions:
//
//	sampling.n >= 30                  NUM: a number at a path compared with a constant
//	IN <path> <v1> <v2> ...           the value at path is one of the listed strings
//	ONE <path>                        the value is a single string (an era transition is written "a|b")
//	UNIQUE <path1>,<path2>            set-level: at most one member of the formation per tuple
//	FORBID <key>                      no content unit contains the key
//	SCHEMA <pattern>                  content parses (strict, depth-limited) and every string matches a
//	                                  backtracking pattern "(a+)+b" (a stand-in for a backtracking regex)
//	READ <ref> <path>                 reads a record ("." is the candidate) to test the domain boundary
//	LIAR <ref>                        reads ref outside the domain, then answers ok anyway
//	KW <word>                         a keyword this dialect does not support (compile error)
type testDialect struct{}

func (testDialect) Name() string { return "rc-test/1" }

func (testDialect) Compile(expr string) (Rule, error) {
	f := strings.Fields(expr)
	switch {
	case len(f) == 3 && f[1] == ">=":
		n, err := strconv.Atoi(f[2])
		if err != nil {
			return nil, err
		}
		return numRule{f[0], n}, nil
	case len(f) >= 3 && f[0] == "IN":
		return inRule{f[1], f[2:]}, nil
	case len(f) == 2 && f[0] == "ONE":
		return oneRule{f[1]}, nil
	case len(f) == 2 && f[0] == "UNIQUE":
		return uniqueRule{strings.Split(f[1], ",")}, nil
	case len(f) == 2 && f[0] == "FORBID":
		return forbidRule{f[1]}, nil
	case len(f) == 2 && f[0] == "SCHEMA":
		return schemaRule{}, nil
	case len(f) == 3 && f[0] == "READ":
		return readRule{strings.TrimPrefix(f[1], "."), f[2], false}, nil
	case len(f) == 2 && f[0] == "KW":
		return nil, fmt.Errorf("keyword %q", f[1])
	case len(f) == 2 && f[0] == "LIAR":
		return readRule{f[1], "licence", true}, nil
	}
	return nil, fmt.Errorf("keyword %q", f[0])
}

type numRule struct {
	path string
	min  int
}

func (r numRule) Eval(d *Domain) (Outcome, string, []string) {
	v, ok := d.Get("", r.path)
	if !ok {
		return RuleUnchecked, r.path + " not disclosed", nil
	}
	n, ok := v.(canon.Int)
	if !ok {
		return RuleUnchecked, r.path + " is not a number", nil
	}
	if int(n) >= r.min {
		return RuleOK, "", nil
	}
	return RuleFail, fmt.Sprintf("%s = %d < %d", r.path, n, r.min), nil
}

type inRule struct {
	path string
	vals []string
}

func (r inRule) Eval(d *Domain) (Outcome, string, []string) {
	v, ok := d.Get("", r.path)
	if !ok {
		return RuleUnchecked, r.path + " missing", nil
	}
	s, _ := v.(canon.String)
	if slices.Contains(r.vals, string(s)) {
		return RuleOK, "", nil
	}
	return RuleFail, fmt.Sprintf("%s = %q not in %v", r.path, s, r.vals), nil
}

type oneRule struct{ path string }

func (r oneRule) Eval(d *Domain) (Outcome, string, []string) {
	v, ok := d.Get("", r.path)
	if !ok {
		return RuleUnchecked, r.path + " missing", nil
	}
	if s, _ := v.(canon.String); strings.Contains(string(s), "|") {
		return RuleFail, r.path + " changes inside the window", nil
	}
	return RuleOK, "", nil
}

type uniqueRule struct{ paths []string }

func (r uniqueRule) tuple(d *Domain, ref string) (string, bool) {
	var parts []string
	for _, p := range r.paths {
		v, ok := d.Get(ref, p)
		if !ok {
			return "", false
		}
		s, _ := v.(canon.String)
		parts = append(parts, string(s))
	}
	return strings.Join(parts, "\x00"), true
}

func (r uniqueRule) Eval(d *Domain) (Outcome, string, []string) {
	mine, ok := r.tuple(d, "")
	if !ok {
		return RuleUnchecked, strings.Join(r.paths, ",") + " missing on the candidate", nil
	}
	conf := []string{d.Candidate()}
	for _, m := range d.Members() {
		if m == d.Candidate() {
			continue
		}
		if t, ok := r.tuple(d, m); ok && t == mine {
			conf = append(conf, m)
		}
	}
	if len(conf) > 1 {
		return RuleFail, "one member per (" + strings.Join(r.paths, ", ") + ")", conf
	}
	return RuleOK, "", nil
}

type forbidRule struct{ key string }

func (r forbidRule) Eval(d *Domain) (Outcome, string, []string) {
	units, ok := d.Content("")
	if !ok {
		return RuleUnchecked, "content not held", nil
	}
	for _, u := range units {
		if u.Data != nil && bytes.Contains(u.Data, []byte(`"`+r.key+`"`)) {
			return RuleFail, "forbidden key " + r.key + " in " + u.Name, nil
		}
	}
	return RuleOK, "", nil
}

type schemaRule struct{}

// backtrack is a naive backtracking match of "(a+)+b" against s: exponential on "aaaa…a" with no b, charging
// one step per attempt, as a backtracking regex engine would spend.
func backtrack(d *Domain, s string, i int) bool {
	if !d.Step() {
		return false
	}
	if i < len(s) && s[i] == 'b' {
		return i == len(s)-1
	}
	for j := i + 1; j <= len(s) && s[j-1] == 'a'; j++ {
		if backtrack(d, s, j) {
			return true
		}
	}
	return false
}

func (schemaRule) Eval(d *Domain) (Outcome, string, []string) {
	units, ok := d.Content("")
	if !ok {
		return RuleUnchecked, "content not held", nil
	}
	for _, u := range units {
		v, ok := d.ContentJSON(u)
		if !ok {
			return RuleUnchecked, "content of " + u.Name + " not parsed", nil
		}
		if s, isStr := v.(canon.String); isStr && !backtrack(d, string(s), 0) {
			return RuleFail, "does not match the member schema", nil
		}
	}
	return RuleOK, "", nil
}

type readRule struct {
	ref, path string
	liar      bool
}

func (r readRule) Eval(d *Domain) (Outcome, string, []string) {
	if _, ok := d.Get(r.ref, r.path); !ok && !r.liar {
		return RuleUnchecked, "", nil
	}
	return RuleOK, "", nil
}

// tableContent serves content units by digest.
type tableContent map[string][]ContentUnit

func (t tableContent) Units(d string) ([]ContentUnit, bool) {
	u, ok := t[d]
	return u, ok
}

// --- fixture helpers -----------------------------------------------------------------------------------------

func rule(expr string) canon.Value { return obj("dialect", "rc-test/1", "expr", expr) }

func rules(exprs ...string) canon.Value {
	a := canon.Array{}
	for _, e := range exprs {
		a = append(a, rule(e))
	}
	return a
}

// entries builds a members list from (by, key, role) triples.
func entries(es ...*canon.Object) canon.Array {
	a := canon.Array{}
	for _, e := range es {
		a = append(a, e)
	}
	return a
}

// editionOf signs an edition approval whose contents carry exactly the given fields.
func (w *world) editionWith(name, by, resource string, preds []string, kv ...any) string {
	var p []string
	for _, x := range preds {
		p = append(p, w.ed(x))
	}
	slices.Sort(p)
	return w.sign(name, by, "edition", obj("resource", resource, "predecessors", p, "contents", obj(kv...)))
}

// observedMethod signs a method-class observation of blob x with the given system map and harness commit.
func (w *world) observedMethod(name, n, x string, system map[string]string, harness string, kv ...any) string {
	sys := &canon.Object{Members: map[string]canon.Value{}}
	for k, v := range system {
		sys.Keys = append(sys.Keys, k)
		sys.Members[k] = canon.String(v)
	}
	slices.SortFunc(sys.Keys, canon.CompareKeys)
	ref := obj("method_edition", strings.Repeat("ab", 32),
		"environment", obj("image_digest", dig("img"), "platform", "linux/amd64", "harness_commit", harness),
		"system", canon.Value(sys), "window", obj("from", "2026-01-01T00:00:00Z", "to", "2026-01-02T00:00:00Z"))
	return w.observedRef(name, n, x, "method", ref, kv...)
}

func (w *world) observedRef(name, n, x, class string, ref *canon.Object, kv ...any) string {
	b := append([]any{"content", canon.Value(contentOf(x)), "class", class, "referent", canon.Value(ref),
		"capture", canon.Value(obj("at", "2026-01-02T00:00:00Z", "evidence", "self-asserted"))}, kv...)
	return w.sign(name, n, "observed", obj(b...))
}

// phenomenon signs a phenomenon observation of x by instrument; era "" leaves the era field out.
func (w *world) phenomenon(name, n, x, instrument, era string) string {
	kv := []any{"instrument", instrument, "location", "geo:39.74,-104.99", "at", "2026-01-01T00:00:00Z"}
	if era != "" {
		kv = append(kv, "era", era)
	}
	return w.observedRef(name, n, x, "phenomenon", obj(kv...))
}

func sampling(n int) canon.Value { return obj("n", n, "unit", "runs") }

func st(id string) *canon.Object { return Entry("statement", id, "member") }

var dialect = WithDialect(testDialect{})

func evalFor(t *testing.T, es []Eval, member string, rule int) Eval {
	t.Helper()
	for _, e := range es {
		if e.Member == member && e.Rule == rule {
			return e
		}
	}
	t.Fatalf("no evaluation of rule %d for %s in %v", rule, shortMember(member), es)
	return Eval{}
}

// --- cases ----------------------------------------------------------------------------------------------------

// TestPartOfConfersNothing: C-core-88. A non-controller signs a `describes` saying its artifact is part of R;
// R's editions never list it. The membership view excludes it, lists the claim only as that key's annotation,
// and applies none of R's rules (a rule that would pass is not evaluated at all).
func TestPartOfConfersNothing(t *testing.T) {
	conformance.Covers(t, "C-core-88")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	a := w.authored("Xa", "M", "X", "sampling", sampling(40))
	w.editionWith("E1", "A", g, []string{g}, "members", entries(Entry("content", dig("Y"), "member")), "rules", rules("sampling.n >= 30"))
	claim := w.sign("D", "M", "describes", obj("about", obj("content", dig("X")),
		"links", canon.Array{obj("resource", g, "rel", "part-of")}))
	r := w.store(nil, dialect)
	m, ok := r.Membership(g, dig("X"))
	if !ok {
		t.Fatal("no membership view")
	}
	if m.Listed || m.Endorsed || m.Evals != nil {
		t.Fatalf("the self-claim made X a member:\n%s", m.Render())
	}
	if len(m.Claims) != 1 || m.Claims[0].St.ID != claim || m.Claims[0].St.Signer != w.signer("M") {
		t.Fatalf("the self-claim is not listed as M's describes: %v", m.Claims)
	}
	has(t, m.Render(), "an annotation, confers nothing")
	has(t, m.Render(), "its rules are not applied")
	// the artifact's view lists the claim as M's describes, nothing more
	art := r.Artifact(dig("X"))
	if len(art.Held) != 1 || art.Held[0].St.ID != claim {
		t.Fatalf("the claim is not held beside the artifact: %v", art.Held)
	}
	_ = a
	// control: the same key listed by the controller is a member (the rule ran and passed)
	w2 := newWorld(t)
	w2.keys = w.keys
	g2 := w2.genesis("G", "A", 0, "A")
	xa := w2.authored("Xa", "M", "X", "sampling", sampling(40))
	w2.editionWith("E1", "A", g2, []string{g2}, "members", entries(st(xa)), "rules", rules("sampling.n >= 30"))
	m2, _ := w2.store(nil, dialect).Membership(g2, xa)
	if !m2.Endorsed || len(m2.Evals) != 1 {
		t.Fatalf("control: listed member not endorsed:\n%s", m2.Render())
	}
}

// TestStrictAndLax: C-core-89. X is listed by strict S (n ≥ 30) and lax L (no rules), with n = 10. In L it is
// endorsed; in S its membership fails, computed from S's rule only. L's pass never shows as satisfying S.
func TestStrictAndLax(t *testing.T) {
	conformance.Covers(t, "C-core-89")
	w := newWorld(t)
	x := w.authored("Xa", "M", "X", "sampling", sampling(10))
	s := w.genesis("S", "A", 0, "A")
	w.editionWith("ES", "A", s, []string{s}, "members", entries(st(x)), "rules", rules("sampling.n >= 30"))
	l := w.sign("L", "B", "genesis", obj("type", "collection", "name", "lax", "controllers", w.controllers("B"), "rule", obj("any_one", true)))
	w.editionWith("EL", "B", l, []string{l}, "members", entries(st(x)))
	r := w.store(nil, dialect)
	ms, _ := r.Membership(s, x)
	ml, _ := r.Membership(l, x)
	if !ml.Endorsed || ml.Outcome != RuleOK {
		t.Fatalf("lax: %s", ml.Render())
	}
	if ms.Endorsed || ms.Outcome != RuleFail || len(ms.Evals) != 1 || ms.Evals[0].Expr != "sampling.n >= 30" {
		t.Fatalf("strict: %s", ms.Render())
	}
	hasNot(t, ms.Render(), keyShort(l))
	// selection: neither edition declares one, so both show undeclared, never a bare curated (§6 (3))
	if ms.Selection != "undeclared" || ml.Selection != "undeclared" {
		t.Fatalf("selection %q %q", ms.Selection, ml.Selection)
	}
	has(t, ms.Render(), "selection: undeclared")
}

// TestSelectionDisclosure: C-core-59 (the resource half). Editions declaring curated, rule-based and
// completeness show those values; one declaring nothing shows `undeclared`; the rule-based one exposes its rules
// for re-application through the membership evaluation.
func TestSelectionDisclosure(t *testing.T) {
	conformance.Partial(t, "C-core-59", "selection shown on the membership view; beside a grade on every surface, and agreement models treating undeclared as curated, land with corroboration (§5.3.2)")
	w := newWorld(t)
	x := w.authored("Xa", "M", "X", "sampling", sampling(40))
	for _, sel := range []string{"curated", "rule-based", "completeness", ""} {
		g := w.sign("G"+sel, "A", "genesis", obj("type", "collection", "name", "c"+sel, "controllers", w.controllers("A"), "rule", obj("any_one", true)))
		kv := []any{"members", entries(st(x)), "rules", rules("sampling.n >= 30")}
		if sel != "" {
			kv = append(kv, "selection", sel)
		}
		w.editionWith("E"+sel, "A", g, []string{g}, kv...)
		m, _ := w.store(nil, dialect).Membership(g, x)
		want := sel
		if want == "" {
			want = "undeclared"
		}
		if m.Selection != want || !strings.Contains(m.Render(), "selection: "+want) {
			t.Fatalf("%q: %s", sel, m.Render())
		}
		if sel == "rule-based" && (len(m.Evals) != 1 || m.Evals[0].Expr != "sampling.n >= 30" || !m.Endorsed) {
			t.Fatalf("rule not exposed for re-application: %s", m.Render())
		}
	}
}

func keyShort(id string) string { return shortMember(id) }

// TestSamplingRule: C-core-90, C-core-91. Rule sampling.n ≥ 30; candidates n=40, n=10, no sampling. ok, fail,
// unchecked; only the first is endorsed. The failing candidate's artifact view and verify exit are byte-
// identical before and after the rule ran, and to a reader holding no collection at all.
func TestSamplingRule(t *testing.T) {
	conformance.Covers(t, "C-core-90", "C-core-91")
	w := newWorld(t)
	a := w.authored("Aa", "M", "XA", "sampling", sampling(40))
	b := w.authored("Ba", "M", "XB", "sampling", sampling(10))
	c := w.authored("Ca", "M", "XC")
	before := w.store(nil, dialect)
	beforeView := before.Artifact(dig("XB")).Render()
	beforeExit, _ := before.Artifact(dig("XB")).VerifyExit()
	g := w.genesis("G", "A", 0, "A")
	w.editionWith("E1", "A", g, []string{g}, "members", entries(st(a), st(b), st(c)), "rules", rules("sampling.n >= 30"))
	r := w.store(nil, dialect)
	want := map[string]Outcome{a: RuleOK, b: RuleFail, c: RuleUnchecked}
	for id, o := range want {
		m, _ := r.Membership(g, id)
		if m.Outcome != o || m.Endorsed != (o == RuleOK) {
			t.Fatalf("%s: want %s, endorsed %v:\n%s", shortMember(id), o, o == RuleOK, m.Render())
		}
		if m.Evals[0].Read[0] != "candidate:sampling.n" {
			t.Fatalf("the evaluator did not read the candidate's disclosure: %v", m.Evals[0].Read)
		}
	}
	// C-core-91: the artifact's own statements and verify exit are untouched by a failing membership
	after := r.Artifact(dig("XB"))
	if got := after.Render(); got != beforeView {
		t.Fatalf("artifact view changed:\n%s\nvs\n%s", got, beforeView)
	}
	if ex, _ := after.VerifyExit(); ex != beforeExit {
		t.Fatalf("verify exit %d, was %d", ex, beforeExit)
	}
	if p, _ := r.Statement(b); !p.Counts() {
		t.Fatal("the candidate's statement stopped counting")
	}
}

// TestUnsupportedRule: C-core-92. A rule in a dialect the reader does not support, and one using a keyword the
// supported dialect does not know: both are loaded, named in the evaluation, `unchecked`, never `ok`; the
// membership does not pass. Control: with no rule the same member is endorsed.
func TestUnsupportedRule(t *testing.T) {
	conformance.Covers(t, "C-core-92")
	w := newWorld(t)
	x := w.authored("Xa", "M", "X", "sampling", sampling(40))
	g := w.genesis("G", "A", 0, "A")
	w.editionWith("E1", "A", g, []string{g}, "members", entries(st(x)),
		"rules", canon.Array{obj("dialect", "cel/0.1", "expr", "x > 1"), rule("KW frobnicate")})
	m, _ := w.store(nil, dialect).Membership(g, x)
	if m.Endorsed || m.Outcome != RuleUnchecked || len(m.Evals) != 2 {
		t.Fatalf("%s", m.Render())
	}
	out := m.Render()
	has(t, out, `cel/0.1 "x > 1"`)
	has(t, out, "unsupported dialect cel/0.1")
	has(t, out, `unsupported construct: keyword "frobnicate"`)
	for _, e := range m.Evals {
		if e.Outcome == RuleOK {
			t.Fatal("an unsupported rule passed")
		}
	}
	// a member schema (contents.schema): loaded, named, unchecked; the member is not endorsed on it
	w.editionWith("E2", "A", g, []string{w.ids["E1"]}, "members", entries(st(x)), "schema", dig("schema"))
	m, _ = w.store(nil, dialect).Membership(g, x)
	if m.Endorsed || m.Outcome != RuleUnchecked || len(m.Evals) != 1 || m.Evals[0].Dialect != "member-schema" {
		t.Fatalf("member schema: %s", m.Render())
	}
	has(t, m.Render(), "no member-schema dialect configured")
	// no dialect configured at all: still unchecked, never ok
	m, _ = w.store(nil).Membership(g, x)
	if m.Outcome != RuleUnchecked || m.Endorsed {
		t.Fatalf("no dialect: %s", m.Render())
	}
}

// TestOutOfDomain: C-core-93. A rule that reads another artifact's statement, network data, or a field of the
// record no rule may read is `unchecked` with the reference named, and a dialect that answers `ok` after such a
// read is overruled. Control: a read of a member of the edition under formation is in the domain.
func TestOutOfDomain(t *testing.T) {
	conformance.Covers(t, "C-core-93")
	w := newWorld(t)
	x := w.authored("Xa", "M", "X", "licence", "CC0-1.0")
	other := w.authored("Oa", "N", "O", "licence", "MIT") // neither candidate nor member
	y := w.authored("Ya", "M", "Y", "licence", "MIT")
	g := w.genesis("G", "A", 0, "A")
	w.editionWith("E1", "A", g, []string{g}, "members", entries(st(x), st(y)),
		"rules", rules("READ "+other+" licence", "READ https://example.org/feed licence", "READ . type", "LIAR "+other, "READ "+y+" licence"))
	r := w.store(nil, dialect)
	m, _ := r.Membership(g, x)
	if m.Endorsed || m.Outcome != RuleUnchecked {
		t.Fatalf("%s", m.Render())
	}
	for i, want := range []string{other + ":licence", "https://example.org/feed:licence", "candidate:type (not a field a rule may read)", other + ":licence"} {
		e := evalFor(t, m.Evals, x, i)
		if e.Outcome != RuleUnchecked || !slices.Contains(e.Outside, want) || !strings.Contains(e.Why, want) {
			t.Fatalf("rule %d: %+v", i, e)
		}
	}
	// the liar answered ok; the outcome shown is unchecked
	if e := evalFor(t, m.Evals, x, 3); !strings.Contains(e.Why, "read outside the rule's domain") {
		t.Fatalf("liar not overruled: %+v", e)
	}
	// control: reading a member of the formation is in the domain
	if e := evalFor(t, m.Evals, x, 4); e.Outcome != RuleOK || len(e.Outside) != 0 {
		t.Fatalf("member read: %+v", e)
	}
}

// TestReferentRule: C-core-93a. Rule: routing era one value across the window, harness commit in {h1, h2}.
// (a) ok, (b) fail naming the field, (c) a referent with no routing_era: unchecked. The evaluation logs reads
// of the referent record.
func TestReferentRule(t *testing.T) {
	conformance.Covers(t, "C-core-93a")
	h1, h2, h3 := strings.Repeat("1", 40), strings.Repeat("2", 40), strings.Repeat("3", 40)
	w := newWorld(t)
	a := w.observedMethod("A", "M", "XA", map[string]string{"routing_era": "e7", "model": "m"}, h1)
	b := w.observedMethod("B", "M", "XB", map[string]string{"routing_era": "e7", "model": "m"}, h3)
	c := w.observedMethod("C", "M", "XC", map[string]string{"model": "m"}, h2)
	d := w.observedMethod("D", "M", "XD", map[string]string{"routing_era": "e7|e8", "model": "m"}, h2)
	g := w.genesis("G", "A", 0, "A")
	w.editionWith("E1", "A", g, []string{g}, "members", entries(st(a), st(b), st(c), st(d)),
		"rules", rules("ONE referent.system.routing_era", "IN referent.environment.harness_commit "+h1+" "+h2))
	r := w.store(nil, dialect)
	got := map[string]Outcome{}
	for _, id := range []string{a, b, c, d} {
		m, _ := r.Membership(g, id)
		got[id] = m.Outcome
	}
	if got[a] != RuleOK || got[b] != RuleFail || got[c] != RuleUnchecked || got[d] != RuleFail {
		t.Fatalf("outcomes a=%s b=%s c=%s d=%s", got[a], got[b], got[c], got[d])
	}
	m, _ := r.Membership(g, b)
	e := evalFor(t, m.Evals, b, 1)
	if !strings.Contains(e.Why, "referent.environment.harness_commit") {
		t.Fatalf("fail does not name the field: %+v", e)
	}
	ea := evalFor(t, m.Evals, b, 0)
	if !slices.Contains(ea.Read, "candidate:referent.system.routing_era") || !slices.Contains(e.Read, "candidate:referent.environment.harness_commit") {
		t.Fatalf("the evaluator did not log the referent reads: %v %v", ea.Read, e.Read)
	}
	mc, _ := r.Membership(g, c)
	if ec := evalFor(t, mc.Evals, c, 0); !slices.Contains(ec.Missing, "candidate:referent.system.routing_era") {
		t.Fatalf("missing era not named: %+v", ec)
	}
}

// TestSetLevelRule: C-core-93b. Rule: one member per (instrument, era). Base edition holds i1/e1. Candidates:
// (a) new instrument → ok; (b) a second i1/e1 → fail naming the existing member; (c) no era → unchecked;
// (d) two new i2/e1 proposed together → both fail, each naming both. Every candidate order and every delivery
// order gives the same answers; re-applying from the base edition after admission of (a) gives them again.
func TestSetLevelRule(t *testing.T) {
	conformance.Covers(t, "C-core-93b")
	w := newWorld(t)
	m0 := w.phenomenon("M0", "O", "X0", "i1", "e1")
	ca := w.phenomenon("Ca", "O", "XA", "i9", "e1")
	cb := w.phenomenon("Cb", "P", "XB", "i1", "e1")
	cc := w.phenomenon("Cc", "P", "XC", "i5", "")
	d1 := w.phenomenon("D1", "O", "XD1", "i2", "e1")
	d2 := w.phenomenon("D2", "P", "XD2", "i2", "e1")
	g := w.genesis("G", "A", 0, "A")
	e1 := w.editionWith("E1", "A", g, []string{g}, "members", entries(st(m0)), "rules", rules("UNIQUE referent.instrument,referent.era"))
	want := map[string]Outcome{ca: RuleOK, cb: RuleFail, cc: RuleUnchecked, d1: RuleFail, d2: RuleFail}
	conflicts := map[string][]string{cb: {cb, m0}, d1: {d1, d2}, d2: {d1, d2}}
	for _, k := range conflicts {
		slices.Sort(k)
	}
	cands := []*canon.Object{st(ca), st(cb), st(cc), st(d1), st(d2)}
	var first string
	for i, o := range append([][]int{nil}, sampleOrders(len(w.lines), 93, 12)...) {
		r := w.store(o, dialect)
		perm := slices.Clone(cands)
		pi := shuffle(len(perm), uint64(i)+1)
		for j := range perm {
			perm[j] = cands[pi[j]]
		}
		ad, err := r.Admit(g, w.ed(e1), perm...)
		if err != nil {
			t.Fatal(err)
		}
		for id, o := range want {
			if ad.Outcomes[id] != o {
				t.Fatalf("%s: %s, want %s\n%s", shortMember(id), ad.Outcomes[id], o, ad.Render())
			}
		}
		for id, c := range conflicts {
			if e := evalFor(t, ad.Evals, id, 0); !slices.Equal(e.Conflicts, c) {
				t.Fatalf("%s conflicts %v, want %v", shortMember(id), e.Conflicts, c)
			}
		}
		if out := ad.Render(); first == "" {
			first = out
		} else if out != first {
			t.Fatalf("order changed the answer:\n%s\nvs\n%s", out, first)
		}
	}
	// the controller admits (a); re-applying from the base edition gives the same answers
	w.editionWith("E2", "A", g, []string{e1}, "members", entries(st(m0), st(ca)), "rules", rules("UNIQUE referent.instrument,referent.era"))
	r := w.store(nil, dialect)
	ad, _ := r.Admit(g, w.ed(e1), cands...)
	for id, o := range want {
		if ad.Outcomes[id] != o {
			t.Fatalf("re-applied from base: %s %s, want %s", shortMember(id), ad.Outcomes[id], o)
		}
	}
	if m, _ := r.Membership(g, ca); !m.Endorsed {
		t.Fatalf("(a) admitted but not endorsed:\n%s", m.Render())
	}
}

// TestSetLevelProperty: C-core-93b as a property, P-01 for admissions. Seeded fixtures (internal/conformance/
// fixture) become phenomenon candidates: the blob names the instrument, the signer the era, and a `describes`
// a candidate with no era. For every fixture, admission answers are the same under every candidate order and
// delivery order, a fail names every member in conflict and nobody is admitted by order: two candidates with
// one tuple are never one ok and one fail.
func TestSetLevelProperty(t *testing.T) {
	opts := fixture.Default
	opts.MaxStatements = 7
	fixture.Check(t, 500, 60, opts, func(f fixture.Fixture) string {
		w := newWorld(t)
		g := w.genesis("G", "A", 0, "A")
		w.editionWith("E1", "A", g, []string{g}, "rules", rules("UNIQUE referent.instrument,referent.era"))
		var cands []*canon.Object
		tuple := map[string]string{}
		for i, s := range f.Statements {
			era := "e" + s.Signer
			if s.Kind == "describes" {
				era = ""
			}
			id := w.phenomenon(fmt.Sprint("C", i), s.Signer, fmt.Sprint(s.Blob, i), s.Blob, era)
			cands = append(cands, st(id))
			if era != "" {
				tuple[id] = s.Blob + "/" + era
			}
		}
		var first string
		for i, o := range append([][]int{nil}, sampleOrders(len(w.lines), f.Seed, 4)...) {
			pi := shuffle(len(cands), f.Seed+uint64(i))
			perm := make([]*canon.Object, len(cands))
			for j := range perm {
				perm[j] = cands[pi[j]]
			}
			ad, err := w.store(o, dialect).Admit(g, w.ed(w.ids["E1"]), perm...)
			if err != nil {
				return err.Error()
			}
			for a, ta := range tuple {
				for b, tb := range tuple {
					if a != b && ta == tb && ad.Outcomes[a] != ad.Outcomes[b] {
						return "same tuple admitted by order: " + ta
					}
				}
			}
			for _, e := range ad.Evals {
				if e.Outcome == RuleFail {
					for b, tb := range tuple {
						if tb == tuple[e.Member] && !slices.Contains(e.Conflicts, b) {
							return "a fail does not name every member in conflict"
						}
					}
				}
			}
			if out := ad.Render(); first == "" {
				first = out
			} else if out != first {
				return "order changed the answer"
			}
		}
		return ""
	})
}

// TestRuleLimits: C-core-94. The member schema has a catastrophic backtracking pattern, and a second member's
// content nests past the parser's depth limit; the evaluator reaches both (its reads are logged). Each
// evaluation terminates, is `unchecked`, and carries an operational refusal naming the limit and its scope
// (this rule, this member). The artifacts' views are untouched.
func TestRuleLimits(t *testing.T) {
	conformance.Partial(t, "C-core-94", "the step budget binds a dialect that charges Domain.Step (and every domain read); no member-schema dialect exists, and a dialect that computes without charging steps is bounded by nothing here (spec finding: the rule and schema note must fix a cost model)")
	w := newWorld(t)
	slow := w.authored("S", "M", "slow")
	deep := w.authored("D", "M", "deep")
	g := w.genesis("G", "A", 0, "A")
	w.editionWith("E1", "A", g, []string{g}, "members", entries(st(slow), st(deep)), "rules", rules("SCHEMA (a+)+b"))
	content := tableContent{
		dig("slow"): {{Name: "slow", Data: []byte(`"` + strings.Repeat("a", 40) + `"`)}},
		dig("deep"): {{Name: "deep", Data: []byte(strings.Repeat("[", 40) + strings.Repeat("]", 40))}},
	}
	before := w.store(nil).Artifact(dig("slow")).Render()
	r := w.store(nil, dialect, WithContent(content), WithRuleSteps(5000))
	for id, reason := range map[string]string{slow: RuleStepLimit, deep: refusal.DepthLimit} {
		m, _ := r.Membership(g, id)
		e := m.Evals[0]
		if e.Outcome != RuleUnchecked || m.Endorsed || e.Refusal == nil || e.Refusal.Class != refusal.Operational || e.Refusal.Reason != reason {
			t.Fatalf("%s: %+v", shortMember(id), e)
		}
		if !strings.Contains(e.Refusal.Detail, "scope rule 0 (rc-test/1), member "+shortMember(id)) {
			t.Fatalf("scope not named: %s", e.Refusal.Detail)
		}
		if !slices.Contains(e.Read, "candidate:content:"+map[string]string{slow: "slow", deep: "deep"}[id]) {
			t.Fatalf("the evaluator did not reach the schema: %v", e.Read)
		}
	}
	if m, _ := r.Membership(g, slow); !strings.Contains(m.Evals[0].Refusal.Detail, "rule step limit=5000") {
		t.Fatalf("limit value not named: %s", m.Evals[0].Refusal.Detail)
	}
	if got := r.Artifact(dig("slow")).Render(); got != before {
		t.Fatal("artifact view changed")
	}
	// control: a matching value inside the limit is ok
	w.authored("OK", "M", "fine")
	content[dig("fine")] = []ContentUnit{{Name: "fine", Data: []byte(`"aaab"`)}}
	w.editionWith("E2", "A", g, []string{w.ids["E1"]}, "members", entries(st(w.ids["OK"])), "rules", rules("SCHEMA (a+)+b"))
	if m, _ := w.store(nil, dialect, WithContent(content), WithRuleSteps(5000)).Membership(g, w.ids["OK"]); !m.Endorsed {
		t.Fatalf("control: %s", m.Render())
	}
}

// archive is the C-core-95 candidate: one scannable member, one in an unsupported compression that holds the key.
func archive() []ContentUnit {
	return []ContentUnit{{Name: "a.json", Data: []byte(`{"ok":1}`)}, {Name: "b.json.xz", Unscanned: "compression=xz unsupported"}}
}

// TestUnscannedArchive: C-core-95. Forbidden-key rule; the key hides in an archive member the reader cannot
// decompress. (a) As an edition rule: unchecked naming the member, never ok, not endorsed, no "clean". (b) As a
// pre-pin check: the draft passes with outcome `unchecked` recorded; re-applied by a reader (hub) it admits
// nothing.
func TestUnscannedArchive(t *testing.T) {
	conformance.Partial(t, "C-core-95", "the rule and pre-pin check at the resolver; the archive scanner is a stand-in ContentReader, and publish (pinning the bytes) is not built")
	w := newWorld(t)
	x := w.authored("X", "M", "arch")
	g := w.genesis("G", "A", 0, "A")
	e1 := w.editionWith("E1", "A", g, []string{g}, "members", entries(st(x)), "rules", rules("FORBID secret"))
	content := tableContent{dig("arch"): archive(), dig("arch2"): archive()}
	r := w.store(nil, dialect, WithContent(content))
	m, _ := r.Membership(g, x)
	e := m.Evals[0]
	if e.Outcome != RuleUnchecked || m.Endorsed || !strings.Contains(e.Why, "b.json.xz unscanned (compression=xz unsupported)") {
		t.Fatalf("(a) %s", m.Render())
	}
	hasNot(t, m.Render(), "clean")
	// (b) pre-pin
	draft := obj("content", canon.Value(contentOf("arch2")), "type", "dataset")
	p, err := r.CheckIntendedFor(draft, g, w.ed(e1))
	if err != nil || p.Outcome != RuleUnchecked {
		t.Fatalf("(b) %v %+v", err, p)
	}
	iv, _ := p.Body.Get("intended_for")
	if str(iv.(*canon.Object), "outcome") != "unchecked" {
		t.Fatal("outcome unchecked not recorded")
	}
	pub := w.sign("P", "M", "authored", p.Body)
	rec, _ := w.store(nil, dialect, WithContent(content)).CheckRecorded(pub)
	if rec.Named != RuleUnchecked || rec.Endorsed {
		t.Fatalf("re-applied: %s", rec.Render())
	}
}

// TestIntendedForNotHeld: C-core-95a. The named edition is not held: the check refuses under reader policy and
// names the edition to fetch; no body is returned, so nothing records `ok`. Control: after fetching it, the
// check runs and the body records its outcome.
func TestIntendedForNotHeld(t *testing.T) {
	conformance.Partial(t, "C-core-95a", "the pre-pin check at the resolver; publish (nothing pinned) is not built")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	e1 := w.editionWith("E1", "A", g, []string{g}, "rules", rules("FORBID secret"))
	content := tableContent{dig("c"): {{Name: "c", Data: []byte(`{"fine":1}`)}}}
	draft := obj("content", canon.Value(contentOf("c")), "type", "dataset")
	r := w.store([]int{0}, dialect, WithContent(content)) // genesis only
	p, err := r.CheckIntendedFor(draft, g, w.ed(e1))
	rf, _ := err.(*refusal.Refusal)
	if p != nil || rf == nil || rf.Class != refusal.Policy || rf.Reason != EditionNotHeld || !strings.Contains(rf.Detail, shortMember(w.ed(e1))) || !strings.Contains(rf.Detail, "fetch") {
		t.Fatalf("%v %v", p, err)
	}
	// the resource itself not held: the same refusal
	if _, err := w.store(nil, dialect).CheckIntendedFor(draft, strings.Repeat("cd", 32), w.ed(e1)); err.(*refusal.Refusal).Reason != EditionNotHeld {
		t.Fatal(err)
	}
	// control
	p, err = w.store(nil, dialect, WithContent(content)).CheckIntendedFor(draft, g, w.ed(e1))
	if err != nil || p.Outcome != RuleOK {
		t.Fatalf("control: %v %+v", err, p)
	}
}

// TestIntendedForFail: C-core-96. E2's rule forbids `secret`; the content has it. The check refuses with class
// reader policy, scope this statement, naming the edition, and returns no body to sign.
func TestIntendedForFail(t *testing.T) {
	conformance.Partial(t, "C-core-96", "the refusal at the resolver; publish (nothing pinned or appended) is not built")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	e1 := w.editionWith("E1", "A", g, []string{g})
	e2 := w.editionWith("E2", "A", g, []string{e1}, "rules", rules("FORBID secret"))
	content := tableContent{dig("c"): {{Name: "c", Data: []byte(`{"secret":"x"}`)}}}
	draft := obj("content", canon.Value(contentOf("c")), "type", "dataset")
	p, err := w.store(nil, dialect, WithContent(content)).CheckIntendedFor(draft, g, w.ed(e2))
	rf, _ := err.(*refusal.Refusal)
	if p != nil || rf == nil || rf.Class != refusal.Policy || rf.Reason != RuleFailed ||
		!strings.Contains(rf.Detail, "scope this statement") || !strings.Contains(rf.Detail, shortMember(w.ed(e2))) || !strings.Contains(rf.Detail, "forbidden key secret") {
		t.Fatalf("%v %v", p, err)
	}
}

// TestIntendedForOK: C-core-97. Compliant content: the signed body records intended_for.edition_applied = E2 and
// outcome ok, and is a valid statement.
func TestIntendedForOK(t *testing.T) {
	conformance.Covers(t, "C-core-97")
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	e1 := w.editionWith("E1", "A", g, []string{g})
	e2 := w.editionWith("E2", "A", g, []string{e1}, "rules", rules("FORBID secret"))
	content := tableContent{dig("c"): {{Name: "c", Data: []byte(`{"fine":1}`)}}}
	draft := obj("content", canon.Value(contentOf("c")), "type", "dataset", "licence", "CC0-1.0")
	p, err := w.store(nil, dialect, WithContent(content)).CheckIntendedFor(draft, g, w.ed(e2))
	if err != nil {
		t.Fatal(err)
	}
	id := w.sign("P", "M", "authored", p.Body)
	got, err := wire.Read(w.lines[len(w.lines)-1])
	if err != nil || got.ID != id || got.Status != wire.Valid {
		t.Fatalf("signed body: %v %v", err, got)
	}
	iv, _ := got.Body.Get("intended_for")
	io := iv.(*canon.Object)
	if str(io, "edition_applied") != w.ed(e2) || str(io, "edition") != w.ed(e2) || str(io, "resource") != g || str(io, "outcome") != "ok" {
		t.Fatalf("intended_for %s", canon.Encode(io))
	}
	if str(got.Body, "licence") != "CC0-1.0" {
		t.Fatal("the draft's own fields were not kept")
	}
}

// TestForgedIntendedFor: C-core-98, the resolver half (the hub gate half is hubcheck's TestForgedIntendedForAtHub, which
// declares the case). A statement records intended_for {R, E2} outcome ok over content E2's rule
// fails. R's current edition E3 lists it. The reader shows E2: fail and E3: fail side by side as its own
// computation, the publisher's ok only as its word, and does not endorse the membership.
func TestForgedIntendedFor(t *testing.T) {
	w := newWorld(t)
	g := w.genesis("G", "A", 0, "A")
	e1 := w.editionWith("E1", "A", g, []string{g})
	e2 := w.editionWith("E2", "A", g, []string{e1}, "rules", rules("FORBID secret"))
	forged := w.authored("F", "M", "c", "intended_for", obj("resource", g, "edition", w.ed(e2), "edition_applied", w.ed(e2), "outcome", "ok"))
	e3 := w.editionWith("E3", "A", g, []string{e2}, "members", entries(st(forged)), "rules", rules("FORBID secret", "FORBID password"))
	content := tableContent{dig("c"): {{Name: "c", Data: []byte(`{"secret":"x"}`)}}}
	rec, ok := w.store(nil, dialect, WithContent(content)).CheckRecorded(forged)
	if !ok {
		t.Fatal("no recorded view")
	}
	if rec.Named != RuleFail || rec.Current != RuleFail || rec.CurrentEdition != w.ed(e3) || rec.Endorsed || rec.PublisherSaid != "ok" {
		t.Fatalf("%s", rec.Render())
	}
	out := rec.Render()
	has(t, out, shortMember(w.ed(e2))+": fail (named edition; this reader's computation)")
	has(t, out, shortMember(w.ed(e3))+": fail (current edition; this reader's computation)")
	has(t, out, "says: ok (the publisher's word")
	has(t, out, "membership: not endorsed")
}

// TestBindingsAreToEditions: C-core-100. A collection edition endorses task T. T's id, the collection's id and
// T's current edition are unchanged; only a new collection edition exists.
func TestBindingsAreToEditions(t *testing.T) {
	conformance.Covers(t, "C-core-100")
	w := newWorld(t)
	task := w.sign("T", "B", "genesis", obj("type", "task", "name", "t", "controllers", w.controllers("B"), "rule", obj("any_one", true)))
	t1 := w.editionWith("T1", "B", task, []string{task}, "contract", obj("terms", "v1"))
	c := w.genesis("C", "A", 0, "A")
	c1 := w.editionWith("C1", "A", c, []string{c})
	r := w.store(nil)
	tb, _ := r.Resource(task)
	cb, _ := r.Resource(c)
	c2 := w.editionWith("C2", "A", c, []string{c1}, "members", entries(Entry("resource", task, "task")))
	r = w.store(nil)
	ta, _ := r.Resource(task)
	ca, _ := r.Resource(c)
	if ta.ID != task || ca.ID != c || tb.ID != ta.ID || cb.ID != ca.ID {
		t.Fatal("an id changed")
	}
	if ta.Current != w.ed(t1) || ta.Render() != tb.Render() {
		t.Fatalf("T's view changed:\n%s\nvs\n%s", ta.Render(), tb.Render())
	}
	if ca.Current != w.ed(c2) || len(ca.Editions) != len(cb.Editions)+1 {
		t.Fatalf("collection: %s", ca.Render())
	}
	m, _ := r.Membership(c, task)
	if !m.Endorsed || m.Role != "task" {
		t.Fatalf("%s", m.Render())
	}
}

// TestUnknownKindNoMembership: C-core-13 (membership half). A validly signed statement of an unregistered kind,
// signed even by the controller, that names the resource, a predecessor and a member list, changes no membership
// and no resource view: the diff before and after is empty.
func TestUnknownKindNoMembership(t *testing.T) {
	conformance.Partial(t, "C-core-13", "membership and the resource view unchanged by an unknown kind (here); defaults, grade and verify exit in TestNonInterference; corroboration lands with its view")
	w := newWorld(t)
	x := w.authored("Xa", "M", "X", "sampling", sampling(40))
	y := w.authored("Ya", "M", "Y", "sampling", sampling(40))
	g := w.genesis("G", "A", 0, "A")
	e1 := w.editionWith("E1", "A", g, []string{g}, "members", entries(st(x)), "rules", rules("sampling.n >= 30"))
	view := func(r *Resolver) string {
		res, _ := r.Resource(g)
		mx, _ := r.Membership(g, x)
		my, _ := r.Membership(g, y)
		return res.Render() + mx.Render() + my.Render()
	}
	before := view(w.store(nil, dialect))
	w.sign("U", "A", "endorses", obj("resource", g, "predecessors", []string{w.ed(e1)}, "contents", obj("members", entries(st(y)))))
	w.sign("U2", "M", "member_of", obj("resource", g, "member", y))
	if after := view(w.store(nil, dialect)); after != before {
		t.Fatalf("an unknown kind changed the view:\n%s\nvs\n%s", after, before)
	}
}
