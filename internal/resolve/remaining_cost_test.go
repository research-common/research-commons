package resolve

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/research-common/research-commons/internal/canon"
	"github.com/research-common/research-commons/internal/identity"
)

// Remaining read paths not covered by TestReadCostIsLinear. Fixtures use real signed lines;
// each closure checks that its intended answer was reached, not just that a call returned.
func remainingCostShapes() []costShape {
	return []costShape{
		{"membership annotations", func(t *testing.T, n int) func() {
			w := newWorld(t)
			g := w.genesis("g", "KEY", 0, "KEY")
			var ds []string
			for i := 0; i < n; i++ {
				x := fmt.Sprint(i)
				d := dig(x)
				ds = append(ds, d)
				w.sign(x, "KEY", "describes", obj("about", obj("content", d), "links", canon.Array{obj("resource", g, "rel", "part-of")}))
			}
			r := w.store(nil)
			return func() {
				for _, d := range ds {
					if got := r.partOfClaims(g, d); len(got) != 1 {
						t.Fatalf("claims=%d", len(got))
					}
				}
			}
		}},
		{"completeness scopes", func(t *testing.T, n int) func() {
			w := newWorld(t)
			var gs []string
			for i := 0; i < n; i++ {
				x := fmt.Sprint(i)
				source := "urn:station:" + x
				o := w.stationReading("o"+x, "OBS", x, source, "2026-01-15T00:00:00Z", "")
				g := w.genesis("g"+x, "KEY", 0, "KEY")
				w.editionWith("e"+x, "KEY", g, []string{g}, "members", entries(st(o)), "selection", "completeness", "completeness", completenessScope("source", source))
				gs = append(gs, g)
			}
			r := w.store(nil)
			return func() {
				for _, g := range gs {
					c, ok := r.Completeness(g, "")
					if !ok || c.Outcome != RuleOK || len(c.Listed) != 1 {
						t.Fatalf("completeness: %+v", c)
					}
				}
			}
		}},
		{"method editions on one resource", func(t *testing.T, n int) func() {
			w := newWorld(t)
			g := w.genesis("g", "KEY", 0, "KEY")
			prev := g
			var eds []string
			for i := 0; i < n; i++ {
				e := w.editionWith(fmt.Sprint(i), "KEY", g, []string{prev}, "system_keys", []string{"model"})
				prev = e
				eds = append(eds, w.ed(e))
			}
			base := w.store(nil)
			return func() {
				r := New(base.logs)
				for _, ed := range eds {
					d := r.methodDecl(ed)
					if !d.read() || len(d.Keys) != 1 {
						t.Fatalf("declaration %+v", d)
					}
				}
			}
		}},
		{"credit with settled submissions", func(t *testing.T, n int) func() {
			w := newWorld(t)
			g := w.task("g", "KEY")
			e := w.taskEdition("e", "KEY", g, []string{g}, w.contract("KEY"))
			for i := 0; i < n; i++ {
				x := fmt.Sprint(i)
				s := w.submit("s"+x, "OBS", g, e, x)
				w.decide("d"+x, "KEY", g, e, "accept", []string{s})
			}
			r := w.store(nil, WithContractReader(ProvisionalContract{}))
			return func() {
				c := r.Credit(w.signer("OBS"), &CreditRule{Name: "test"})
				for _, x := range c.Counts {
					if x.Name == "acceptance" {
						if x.N != n {
							t.Fatalf("acceptance=%d", x.N)
						}
						return
					}
				}
				t.Fatal("no acceptance")
			}
		}},
		{"identity run attestations", func(t *testing.T, n int) func() {
			w := newCtrlWorld(t, "KEY")
			var ds []string
			grant := w.signRC2("grant", "IR", "identity_grant", obj("identity", w.I, "delegate", obj("key", w.signer("KEY"), "inception", w.firstLine("KEY")), "permissions", canon.Array{obj("kind", "reproduced", "targets", obj("any_statement", true))}), rc2MarkerOnly, [2]string{})
			for i := 0; i < n; i++ {
				x := fmt.Sprint(i)
				a := w.authored("a"+x, "AUT", x, "prov", []string{"WF", "in-" + x})
				w.signRC2("r"+x, "KEY", "reproduced", obj("of", a, "result", "match", "content", contentOf(x), "provenance", obj("workflow", dig("WF"), "inputs", []string{dig("in-" + x)})), rc2Actor, [2]string{w.I, grant})
				ds = append(ds, dig(x))
			}
			actors, err := identity.NewActors(w.lines)
			if err != nil {
				t.Fatal(err)
			}
			p := pol(t, nil, []*canon.Object{obj("principal", obj("identity", w.I), "purposes", []string{"attestation"}, "targets", obj("any_content", true))})
			logs := dualStore()
			if refused := deliverAll(logs, w.lines); refused != 0 {
				t.Fatalf("%d refused", refused)
			}
			r := New(logs, WithActorEligibility(actors), WithPolicy(p))
			return func() {
				for _, d := range ds {
					a := r.Artifact(d)
					if !strings.Contains(a.Render(), "trusted for attestation") {
						t.Fatalf("identity attestation not reached: %s", a.Render())
					}
				}
			}
		}},
	}
}

// TestRemainingReadCostAudit reports slopes without pretending all are already linear. Set
// RC_REMAINING_COST to S; the second size is 8S. Fixture construction is excluded. Each measurement
// is best of three. The method-declaration closure includes a fresh resolver for each measurement.
func TestRemainingReadCostAudit(t *testing.T) {
	value := os.Getenv("RC_REMAINING_COST")
	if value == "" {
		t.Skip("set RC_REMAINING_COST")
	}
	n, err := strconv.Atoi(value)
	if err != nil || n < 1 {
		t.Fatal("positive size required")
	}
	for _, s := range remainingCostShapes() {
		t.Run(s.name, func(t *testing.T) {
			measure := func(n int) time.Duration {
				f := s.build(t, n)
				runtime.GC()
				var best time.Duration
				for i := 0; i < 3; i++ {
					start := time.Now()
					f()
					d := time.Since(start)
					if best == 0 || d < best {
						best = d
					}
				}
				return best
			}
			a, b := measure(n), measure(8*n)
			t.Logf("COST %s S=%d %s %s ratio=%.2f", s.name, n, a, b, float64(b)/float64(a))
		})
	}
}

// Each fixed path has a default cost guard, separate from the opt-in diagnostic audit.
func TestAdditionalReadCostsAreLinear(t *testing.T) {
	if testing.Short() {
		t.Skip("cost comparison")
	}
	for _, shape := range remainingCostShapes()[:3] {
		t.Run(shape.name, func(t *testing.T) { wantLinear(t, 8, shape.build(t, 64), shape.build(t, 512)) })
	}
}
