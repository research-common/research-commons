package gate

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
	"github.com/research-common/research-commons/internal/wire"
)

// gateOrders is the file order plus k seeded shuffles of n objects (every order up to five objects).
func gateOrders(n int, seed uint64, k int) [][]int {
	id := make([]int, n)
	for i := range id {
		id[i] = i
	}
	if n <= 5 {
		var out [][]int
		var rec func(int)
		rec = func(j int) {
			if j == n {
				out = append(out, slices.Clone(id))
				return
			}
			for i := j; i < n; i++ {
				id[j], id[i] = id[i], id[j]
				rec(j + 1)
				id[j], id[i] = id[i], id[j]
			}
		}
		rec(0)
		return out
	}
	out := [][]int{slices.Clone(id)}
	r := rand.New(rand.NewPCG(seed, 2))
	for range k {
		o := slices.Clone(id)
		r.Shuffle(n, func(i, j int) { o[i], o[j] = o[j], o[i] })
		out = append(out, o)
	}
	return out
}

func reorder(pkg Package, o []int) Package {
	out := Package{Tree: pkg.Tree}
	for _, i := range o {
		out.Objects = append(out.Objects, pkg.Objects[i])
	}
	return out
}

// gateAnswer is everything a gate answers about a package: the rendered report, every object's signature
// (verdict, class, reason, labels) and scope, and the exit.
func gateAnswer(rep *Report) string {
	s := rep.Render()
	for _, r := range rep.Results {
		s += fmt.Sprintf("%s %s %s\n", r.Path, signature(r), r.Scope)
	}
	return s + fmt.Sprintf("exit %d\n", rep.Exit())
}

// TestPropertyGateOrderInvariance: P-01 over the gates. For each gate (pull, hub check, push, pre-pin) the
// report on a package is the same in every delivery order of its objects: over generated fixtures (each object
// in its signer's directory, a hostile copy of another key's statement filed under A's, and the blobs), and
// over the cross-gate fixture's mix of admitted, labelled and refused objects under its held history and policy.
// Then transport order: the same statements delivered as a sequence of pulls, split and ordered by seed, each
// pull committing what it admits to the held set, end holding exactly the statements one pull of the whole set
// admits. The control: dropping one valid object changes the report, so the comparison sees the objects.
func TestPropertyGateOrderInvariance(t *testing.T) {
	conformance.Partial(t, "P-01", "the gates: pull, hub check, push and pre-pin over every object order (sampled past five objects) and pull over transport order; the resolver views and the exchange view are internal/resolve's, and internal/resolve.TestPropertyExchangeOrderInvariance covers the case")
	keys := map[string]wire.Key{"A": testKey("A"), "B": testKey("B"), "C": testKey("C")}
	fixture.Check(t, 1900, 40, fixture.Default, func(f fixture.Fixture) string {
		ids, lines, by := concretize(f, keys)
		var pkg Package
		for _, id := range ids {
			pkg.Objects = append(pkg.Objects, Object{Path: StatementPath(keys[by[id]].Signer(), id), Data: lines[id]})
			if by[id] != "A" {
				pkg.Objects = append(pkg.Objects, Object{Path: StatementPath(keys["A"].Signer(), id), Data: lines[id]})
			}
		}
		for _, s := range f.Statements {
			if s.Seq == 0 && s.Signer == "A" {
				pkg.Objects = append(pkg.Objects, blobObject([]byte(s.Blob)))
			}
		}
		for _, g := range gates {
			var first string
			for _, o := range gateOrders(len(pkg.Objects), f.Seed, 6) {
				rep, err := admitFn(g)(reorder(pkg, o), MemHeld{}, nil, Options{})
				if err != nil {
					return g + ": " + err.Error()
				}
				if got := gateAnswer(rep); first == "" {
					first = got
				} else if got != first {
					return fmt.Sprintf("%s: order %v changed the report", g, o)
				}
			}
		}
		// transport order: sequential pulls, each adding what it admits to the held set
		one, _ := Pull(pkg, MemHeld{}, nil, Options{})
		want := admittedIDs(one)
		r := rand.New(rand.NewPCG(f.Seed, 3))
		for range 4 {
			o := r.Perm(len(pkg.Objects))
			held := MemHeld{Lines: map[string][]byte{}, Blobs: map[string]bool{}}
			for i := 0; i < len(o); {
				n := 1 + r.IntN(3)
				part := reorder(pkg, o[i:min(i+n, len(o))])
				i += n
				rep, err := Pull(part, held, nil, Options{})
				if err != nil {
					return err.Error()
				}
				for _, x := range rep.Results {
					if x.Verdict == Admitted && x.Kind == KindStatement {
						held.Lines[x.ID] = x.st.Line()
					}
					if x.Verdict == Admitted && x.Kind == KindBlob {
						held.Blobs[x.ID] = true
					}
				}
			}
			if len(want) == 0 {
				return "one pull admitted no statement: the transport comparison is vacuous"
			}
			if got := sortedIDs(held.Lines); !slices.Equal(got, want) {
				return fmt.Sprintf("sequential pulls in order %v hold %d statements, one pull admits %d", o, len(got), len(want))
			}
		}
		return ""
	})

	// the cross-gate fixture: a mix of every verdict, under a held history and a policy
	cf := newCrossGateFixture(t)
	for _, g := range gates {
		var first string
		for _, o := range gateOrders(len(cf.pkg.Objects), 77, 12) {
			rep := mustAdmit(t, g, reorder(cf.pkg, o), cf.held, cf.pol, Options{})
			if got := gateAnswer(rep); first == "" {
				first = got
			} else if got != first {
				t.Fatalf("%s: order %v changed the cross-gate report:\n%s\nvs\n%s", g, o, got, first)
			}
		}
		// control: one object fewer is a different report
		less := Package{Objects: cf.pkg.Objects[1:]}
		if gateAnswer(mustAdmit(t, g, less, cf.held, cf.pol, Options{})) == first {
			t.Fatalf("%s: dropping an object changed nothing: the comparison does not see the objects", g)
		}
	}
}

// admittedIDs is the statement ids a report admitted, sorted.
func admittedIDs(rep *Report) []string {
	m := map[string][]byte{}
	for _, x := range rep.Results {
		if x.Verdict == Admitted && x.Kind == KindStatement {
			m[x.ID] = nil
		}
	}
	return sortedIDs(m)
}
