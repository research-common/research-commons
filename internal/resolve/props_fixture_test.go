package resolve

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/keylog"
	"github.com/research-common/research-commons/internal/sig"
	"github.com/research-common/research-commons/internal/wire"
)

// This file is the property tests' fixture language over every resolver view: it turns an abstract fixture
// (internal/conformance/fixture) into signed statements, builds a resolver over any delivery of their lines,
// and renders every answer the resolver gives (snapshot). P-01, P-02, P-03, P-07, P-09 and P-12 are written
// against these two functions.

// propKeys maps the fixture's abstract signers to test keys. B and D are secp256k1 keys (even-length names), so
// equivalent signature encodings exist for them (wire §4); A and C are Ed25519.
var propKeys = map[string]string{"A": "A", "B": "BB", "C": "C", "D": "DD"}

// allMatch is a comparator that matches every pair of outputs it knows and diverges on nothing, so derivation
// groups reach T1 whenever the fixture re-derives.
type allMatch struct{}

func (allMatch) Compare(_, a, b string) (string, string) { return "match", "" }

// propWorld is a concretized fixture: the signed world plus the names a snapshot walks.
type propWorld struct {
	*world
	g      string            // the resource
	kinds  map[string]string // label -> kind
	blobs  []string
	labels []string // fixture statement labels in order
}

// propBaseLines is how many lines the base (resource, workflow, a result, a member, an observation) takes.
const propBase = "base"

func propOpts() []Option {
	return []Option{WithTimeVerifier(newFakeBitcoin(100, 101, 102)), WithComparator(allMatch{}), dialect,
		WithFinalityRules(settlementRules{})}
}

func unheldID(label string) string {
	h := sha256.Sum256([]byte("unheld " + label))
	return hex.EncodeToString(h[:])
}

// concretize signs a fixture. The base is always present: a resource G (controllers A, B and C, any one) with an
// edition E1 whose rules admit statements under two licences, a workflow W by A (replication from the seed), a
// result blob RES derived under W, a member statement M1 and an exact-bytes observation O1 of blob X.
func concretize(t *testing.T, f fixture.Fixture) *propWorld {
	t.Helper()
	w := newWorld(t)
	pw := &propWorld{world: w, kinds: map[string]string{}, blobs: []string{"RES", "RES2", "U", "V", "W", "X"}}
	w.workflow("A", "W", []string{"bytes", "protocol"}[f.Seed%2], "K")
	pw.g = w.genesis("G", "A", 0, "A", "BB", "C")
	m1 := w.authored("M1", "A", "M1", "licence", "CC0-1.0")
	o1 := w.observed("O1", "C", "X", "exact-bytes", chainRef(3), "finality", depthFinality("confirmations ≥ 6", 3))
	w.result("RES", "A", "RES", "W", "X")
	w.result("RES2", "BB", "RES2", "W", "X") // a second run of the same provenance: T1 under a matching comparator
	w.editionWith("E1", "A", pw.g, []string{pw.g}, "members", entries(st(m1), st(o1), Entry("content", dig("X"), "member")),
		"rules", rules("IN licence CC0-1.0 MIT"))
	pw.kinds["M1"], pw.kinds["O1"], pw.kinds["E1"] = "authored", "observed", "edition"

	target := func(s fixture.Statement) (string, bool) {
		if id, ok := w.ids[s.Of]; ok {
			return id, true
		}
		return unheldID(s.Of), false
	}
	prevHead, prevSeq := map[string]string{}, map[string]int64{}
	for i, s := range f.Statements {
		label := s.Label
		if label == "" {
			label = fmt.Sprint("s", i)
		}
		pw.labels = append(pw.labels, label)
		pw.kinds[label] = s.Kind
		k, x := propKeys[s.Signer], s.Blob
		// a same-key fork: every seventh statement chains after its signer's previous line instead of its head
		if s.Time%7 == 0 && prevSeq[k] > 0 && s.Kind != "edition" {
			w.head[k], w.seq[k] = prevHead[k], prevSeq[k]
		}
		prevHead[k], prevSeq[k] = w.head[k], w.seq[k]
		switch s.Kind {
		case "authored":
			kv := []any{"licence", s.Fields["licence"]}
			if s.Prov != nil {
				kv = append(kv, "prov", append([]string{s.Prov.Workflow}, s.Prov.Inputs...))
			}
			w.authored(label, k, x, kv...)
		case "holds":
			w.sign(label, k, "holds", obj("content", contentOf(x)))
		case "describes":
			w.sign(label, k, "describes", obj("about", obj("content", dig(x)), "note", "n"))
		case "observed":
			kv := []any{"licence", s.Fields["licence"]}
			var ref *canon.Object
			switch s.Fields["class"] {
			case "source":
				ref = apiRef("https://api.example/a")
				kv = append(kv, "finality", runFinality([]string{"SF", "RF"}[s.Time%2]))
			case "none-yet":
				ref = obj()
			default:
				ref = chainRef(s.Time % 9)
				if s.Time%3 == 0 {
					kv = append(kv, "finality", depthFinality("confirmations ≥ 6", s.Time%9))
				}
			}
			cls := s.Fields["class"]
			if cls == "" {
				cls = "none-yet"
				ref = obj()
			}
			w.observed(label, k, x, cls, ref, kv...)
		case "edition":
			preds, members := []string{pw.g}, entries(Entry("content", dig(x), "member"))
			if s.Time%4 == 0 {
				// a gap: the signer's previous line is never delivered, so this approval never chains (detached)
				w.sign("gap:"+label, k, "describes", obj("about", obj("content", dig("gap")), "note", "withheld"))
				w.lines = w.lines[:len(w.lines)-1]
			}
			if of, ok := w.ids[s.Of]; ok {
				switch pw.kinds[s.Of] {
				case "edition":
					preds = []string{of}
				case "authored", "observed":
					members = entries(st(of))
				}
			}
			w.editionWith(label, k, pw.g, preds, "members", members, "rules", rules("IN licence CC0-1.0 MIT"))
		case "corroborates":
			of, held := target(s)
			if !held || pw.kinds[s.Of] != "observed" {
				of = o1 // most targets in a random fixture are not observations; keep the kind exercised
			}
			result := w.ids["RES"]
			if s.Time%2 == 0 {
				result = strings.Repeat("ab", 32)
			}
			w.corroborates(label, k, of, result, s.Fields["verdict"])
		case "retracts":
			of, _ := target(s)
			w.sign(label, k, "retracts", obj("of", of))
		case "refutes":
			of, _ := target(s)
			w.sign(label, k, "refutes", obj("of", of, "evidence", dig("E")))
		case "anchors":
			if w.head[k] != "" {
				w.anchor(label, k, fmt.Sprint("btc:", 100+s.Time%3))
			}
		case "reproduced":
			if id, ok := w.ids[s.Of]; ok && w.by[id] != "" {
				w.sign(label, k, "reproduced", obj("of", id, "result", "match", "content", contentOf(x),
					"provenance", obj("workflow", dig("W"), "inputs", []string{dig("X")})))
			}
		}
	}
	return pw
}

// storeOf delivers lines, in the order and multiplicity given, into one fresh store.
func storeOf(t *testing.T, lines [][]byte) *keylog.Store {
	t.Helper()
	s := keylog.NewStore()
	for _, ln := range lines {
		st, err := wire.Read(ln)
		if err != nil {
			t.Fatalf("delivered line refused: %v", err)
		}
		if kept, err := s.Log(st.Signer).Add(ln); err != nil && kept == nil {
			t.Fatalf("delivered line refused by the log: %v", err)
		}
	}
	return s
}

func (pw *propWorld) deliver(order []int) [][]byte {
	if order == nil {
		order = make([]int, len(pw.lines))
		for i := range order {
			order[i] = i
		}
	}
	out := make([][]byte, len(order))
	for i, j := range order {
		out[i] = pw.lines[j]
	}
	return out
}

// reencodings is every delivered form of every line: the line itself and, for a secp256k1 signer, each
// equivalent signature encoding (wire §4).
func (pw *propWorld) reencodings(t *testing.T) [][]byte {
	t.Helper()
	var out [][]byte
	for _, ln := range pw.lines {
		out = append(out, ln)
		v, err := canon.Parse(ln)
		if err != nil {
			t.Fatal(err)
		}
		o := v.(*canon.Object)
		s := string(o.Members["sig"].(canon.String))
		if !strings.HasPrefix(s, "0x") {
			continue
		}
		raw, _ := hex.DecodeString(s[2:])
		for _, e := range sig.Equivalents(raw) {
			c, _ := canon.Parse(ln)
			c.(*canon.Object).Members["sig"] = canon.String("0x" + hex.EncodeToString(e))
			out = append(out, canon.Encode(c))
		}
	}
	return out
}

// snapshot renders every answer the resolver gives about the world: placed statements and key logs, every
// artifact (authorship, defaults, groups, grades, verify exit), every observation with its corroboration and
// referent status, the resource, its membership answers, the series, and each key's record.
func (pw *propWorld) snapshot(r *Resolver, s *keylog.Store) string {
	var b strings.Builder
	ids := make([]string, 0, len(r.byID))
	for id := range r.byID {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	b.WriteString("== statements\n")
	for _, id := range ids {
		p := r.byID[id]
		fmt.Fprintf(&b, "%s %s chained=%v evaluable=%v counts=%v after=%v doubted=%v\n", keylog.Short(id), p.St.Kind, p.Chained, p.Evaluable, p.Counts(), p.After, p.Doubted)
	}
	b.WriteString("== key logs\n")
	for _, k := range s.Keys() {
		b.WriteString(s.Log(k).View().Render())
	}
	b.WriteString("== artifacts\n")
	for _, x := range pw.blobs {
		a := r.Artifact(dig(x))
		code, why := r.Verify(dig(x))
		full, _ := a.VerifyExit()
		fmt.Fprintf(&b, "%s\nverify %d %v (full view %d)\nexplain %v\n", a.Render(), code, why, full, a.Explain)
		for _, o := range r.Observations(dig(x)) {
			b.WriteString(o.Render())
		}
	}
	b.WriteString("== observations\n")
	for _, p := range r.byKind["observed"] {
		if o, ok := r.Observation(p.St.ID); ok {
			fmt.Fprintf(&b, "%s status=%s ref=%s\n", keylog.Short(p.St.ID), o.Corroboration.Status(), o.ReferentStatus)
		}
	}
	b.WriteString("== resource\n")
	if res, ok := r.Resource(pw.g); ok {
		fmt.Fprintf(&b, "%s\nexit %d current=%s tips=%v\n", res.Render(), res.VerifyExit(), res.Current, res.Tips)
		for _, m := range pw.members(r) {
			if mm, ok := r.Membership(pw.g, m); ok {
				b.WriteString(mm.Render())
			}
		}
		if sr, ok := r.Series(pw.g, ""); ok {
			b.WriteString(sr.Render())
		}
	}
	b.WriteString("== reputation\n")
	for _, k := range sortedKeys(propKeys) {
		rep, err := r.Reputation(pw.signer(propKeys[k]), ReputationRule{Name: "all", From: "2026-01-01T00:00:00Z", To: "2027-01-01T00:00:00Z", Describe: "everything"})
		if err != nil {
			fmt.Fprintf(&b, "%s: %v\n", k, err)
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", k, rep)
	}
	return b.String()
}

// members lists every key an edition could name: each held `authored` or `observed` statement id, and each blob.
func (pw *propWorld) members(r *Resolver) []string {
	var out []string
	for _, k := range []string{"authored", "observed"} {
		for _, p := range r.byKind[k] {
			out = append(out, p.St.ID)
		}
	}
	for _, x := range pw.blobs {
		out = append(out, dig(x))
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// build resolves lines held in order, and returns the resolver, its store and the world's snapshot.
func (pw *propWorld) answers(t *testing.T, lines [][]byte, opts ...Option) string {
	t.Helper()
	s := storeOf(t, lines)
	return pw.snapshot(New(s, opts...), s)
}

func firstDiff(a, b string) string {
	x, y := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			return fmt.Sprintf("line %d:\n  %s\nvs\n  %s", i, x[i], y[i])
		}
	}
	return fmt.Sprintf("lengths differ: %d vs %d lines", len(x), len(y))
}

// idOf reads a line and returns the statement id it carries.
func idOf(_ *keylog.Store, line []byte) (string, error) {
	st, err := wire.Read(line)
	if err != nil {
		return "", err
	}
	return st.ID, nil
}
