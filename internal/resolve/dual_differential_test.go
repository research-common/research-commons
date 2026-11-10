package resolve

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/keylog"
)

// Gate R4 / C-id-01: an ordinary bare-key corpus reads identically with and without the dual-major reader. Three
// corpora, each checked on both stores in the same test run (no environment variable needed):
//
//	(a) the legacy characterization cases (identity_legacy_baseline): the golden snapshot under the dual store;
//	(b) the property fixtures of P-01 (propBaseSeed, propSeeds, fixture.Extended): every view's full snapshot
//	    (statements, key logs, artifacts, observations/corroboration, resource, membership, series, reputation)
//	    under both stores, byte for byte, in file order and sampled delivery orders;
//	(c) the wire-format vectors corpus delivered into a store: same refusals, same kept lines, same log views and
//	    the same resolver answers.
//
// The whole resolve suite can also be rerun under the dual store with RC_TEST_DUAL_READER=1 (dual_helpers_test.go),
// which covers every remaining resolver test's assertion; that rerun costs one more suite run (~100 s).

// TestDualDifferential: C-id-01 end to end. Every corpus below is resolved under the default store and the dual
// store, and every answer is compared: ids, statuses and refusals at the wire and key-log layers, and every
// resolver view (statements, key logs, artifacts and verify, observations and corroboration, resources,
// membership, series, completeness, recorded membership, pre-registration, credit, reputation, tasks).
func TestDualDifferential(t *testing.T) {
	conformance.Covers(t, "C-id-01")
	t.Run("legacy goldens", dualDifferentialLegacyGoldens)
	t.Run("property fixtures", dualDifferentialPropertyFixtures)
	t.Run("tasks", dualDifferentialTasks)
	t.Run("wire vectors", dualDifferentialWireVectors)
}

func dualDifferentialLegacyGoldens(t *testing.T) {
	for _, c := range identityLegacyCases(t) {
		t.Run(c.name, func(t *testing.T) {
			want, err := os.ReadFile(filepath.Join("testdata", "identity_legacy_baseline", c.name+".golden"))
			if err != nil {
				t.Fatal(err)
			}
			held := c.held
			if held == nil {
				for i := range c.w.lines {
					held = append(held, i)
				}
			}
			normalize := identityLegacyNormalizer(t, c.w)
			for _, s := range []*keylog.Store{keylog.NewStore(), dualStore()} {
				for _, i := range held {
					if n := deliverAll(s, [][]byte{c.w.lines[i]}); n != 0 {
						t.Fatalf("line %d refused", i)
					}
				}
				if got := normalize(identityLegacySnapshot(c, New(s))); got != string(want) {
					t.Fatalf("store %T differs from the golden:\n%s", s, firstDiff(string(want), got))
				}
			}
		})
	}
}

func dualDifferentialPropertyFixtures(t *testing.T) {
	fixture.Check(t, propBaseSeed, propSeeds, fixture.Extended, func(f fixture.Fixture) string {
		pw := concretize(t, f)
		for _, o := range append([][]int{nil}, sampleOrders(len(pw.lines), f.Seed, 2)...) {
			lines := pw.deliver(o)
			plain, dual := keylog.NewStore(), dualStore()
			if deliverAll(plain, lines) != deliverAll(dual, lines) {
				return "the stores refused a different number of lines"
			}
			ra, rb := New(plain, propOpts()...), New(dual, propOpts()...)
			var ds []string
			for _, x := range pw.blobs {
				ds = append(ds, dig(x))
			}
			// the property snapshot, plus every view it does not render (tasks, credit, completeness, recorded
			// membership, pre-registration) on every held id
			a := pw.snapshot(ra, plain) + everyView(ra, ds)
			b := pw.snapshot(rb, dual) + everyView(rb, ds)
			if a != b {
				return "order " + sprintOrder(o) + ": the dual reader changed an answer: " + firstDiff(a, b)
			}
		}
		return ""
	})
}

// dualDifferentialTasks: the task view (the property fixtures build no task): a task with a contract, two
// submissions, intents, a progress heartbeat, a decision citing both and a rival decision by a non-beneficiary,
// resolved under both stores with the provisional contract reader: the same task, readiness and decisions.
func dualDifferentialTasks(t *testing.T) {
	w := newWorld(t)
	g := w.task("G", "R")
	e := w.taskEdition("E", "R", g, []string{g}, w.contract("R", "quorum", quorum(2, "none")))
	w.life("I1", "A", "intent", g, e)
	w.life("P1", "A", "progress", g, e, "note", "half")
	s1 := w.submit("S1", "A", g, e, "X")
	s2 := w.submit("S2", "BB", g, e, "Y")
	w.decide("D", "R", g, e, "accept", []string{s1, s2})
	w.decide("DQ", "Q", g, e, "reject", []string{s1})
	for _, o := range append([][]int{nil}, sampleOrders(len(w.lines), 0x7a5c, 4)...) {
		var lines [][]byte
		if o == nil {
			lines = w.lines
		} else {
			for _, j := range o {
				lines = append(lines, w.lines[j])
			}
		}
		var out []string
		for _, s := range []*keylog.Store{keylog.NewStore(), dualStore()} {
			if n := deliverAll(s, lines); n != 0 {
				t.Fatalf("%d lines refused", n)
			}
			tk, ok := New(s, WithContractReader(ProvisionalContract{})).Task(g)
			if !ok {
				t.Fatal("task not resolved")
			}
			out = append(out, tk.Render())
		}
		if out[0] != out[1] {
			t.Fatalf("the dual reader changed the task view: %s", firstDiff(out[0], out[1]))
		}
		if !strings.Contains(out[0], "accept") {
			t.Fatalf("the fixture did not reach a decision:\n%s", out[0])
		}
	}
}

func dualDifferentialWireVectors(t *testing.T) {
	v, err := conformance.LoadVectors()
	if err != nil {
		t.Fatal(err)
	}
	var lines [][]byte
	for _, set := range [][]conformance.Vector{v.Positive, v.EdPositive, v.Negative, v.EdNegative} {
		for _, x := range set {
			switch {
			case x.Delivered != "":
				lines = append(lines, []byte(x.Delivered))
			case x.SignedString != "" && x.Sig != "":
				lines = append(lines, vectorLine(t, x.SignedString, x.Sig))
			}
		}
	}
	if len(lines) < 20 {
		t.Fatalf("only %d vector lines", len(lines))
	}
	render := func(s *keylog.Store) string {
		var b bytes.Buffer
		for _, k := range s.Keys() {
			b.WriteString(s.Log(k).View().Render())
		}
		r := New(s)
		var ds []string
		for _, p := range r.All() {
			b.WriteString(p.St.ID + " " + string(p.St.Status) + " " + p.St.Why + "\n")
			if d := contentDigest(p.St.Body); d != "" {
				ds = append(ds, d)
			}
		}
		b.WriteString(everyView(r, ds))
		return b.String()
	}
	for _, o := range append([][]int{nil}, sampleOrders(len(lines), 0xc1d01, 3)...) {
		in := lines
		if o != nil {
			in = make([][]byte, len(o))
			for i, j := range o {
				in[i] = lines[j]
			}
		}
		plain, dual := keylog.NewStore(), dualStore()
		for i, ln := range in {
			a, aerr := plain.Read(ln)
			b, berr := dual.Read(ln)
			if (aerr == nil) != (berr == nil) || (aerr != nil && aerr.Error() != berr.Error()) || (aerr == nil && (a.ID != b.ID || a.Status != b.Status || a.Why != b.Why)) {
				t.Fatalf("line %d reads differently: %v / %v", i, aerr, berr)
			}
			if aerr != nil {
				continue
			}
			ka, kaerr := plain.Log(a.Signer).Add(ln)
			kb, kberr := dual.Log(b.Signer).Add(ln)
			if (ka == nil) != (kb == nil) || (kaerr == nil) != (kberr == nil) {
				t.Fatalf("line %d delivered differently: %v / %v", i, kaerr, kberr)
			}
		}
		if a, b := render(plain), render(dual); a != b {
			t.Fatalf("the dual reader changed a view of the vectors corpus: %s", firstDiff(a, b))
		}
	}
}

// vectorLine is the delivered line of a signed string and a sig: the PAE body with sig added, re-encoded
// canonically (the wire package's lineFor, which is not exported to this package).
func vectorLine(t *testing.T, ss, sig string) []byte {
	t.Helper()
	parts := strings.SplitN(ss, " ", 5)
	if len(parts) != 5 || parts[0] != "DSSEv1" {
		t.Fatalf("not a PAE string: %.60q", ss)
	}
	v, err := canon.Parse([]byte(parts[4]))
	if err != nil {
		t.Fatalf("PAE body does not parse: %v", err)
	}
	o := v.(*canon.Object)
	o.Keys = append(o.Keys, "sig")
	o.Members["sig"] = canon.String(sig)
	return canon.Encode(o)
}
