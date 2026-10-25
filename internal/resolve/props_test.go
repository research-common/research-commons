package resolve

import (
	"testing"

	"github.com/research-common/research-commons/internal/conformance"
	"github.com/research-common/research-commons/internal/conformance/fixture"
)

// propSeeds and propOrders fix the sampling: seeds base..base+propSeeds-1 of the generator, and for each fixture
// the file order plus propOrders seeded delivery orders (shuffle seed = fixture seed). A failure prints the seed
// and the shrunk fixture (fixture.Check).
const (
	propBaseSeed = 7000
	propSeeds    = 40
	propOrders   = 5
)

// TestPropertyOrderInvariance: P-01 over every view. Statements of every kind the resolver reads (authored,
// holds, describes, observed in three classes, editions with forks and chains, corroborates, retracts, refutes,
// anchors, reproduced) are generated from a seed over four keys, two of them secp256k1; every answer of every
// view (statements, key logs, artifacts, observations and corroboration, the resource, membership, series,
// reputation) is identical in the file order and in each sampled delivery order.
func TestPropertyOrderInvariance(t *testing.T) {
	conformance.Partial(t, "P-01", "all six views here (key logs, resources, artifacts, edition rules/membership/series, observations/corroboration, reputation) over a sample of delivery orders; the exchange view and the gates are built elsewhere; orders are sampled (propOrders per fixture), not exhaustive")
	fixture.Check(t, propBaseSeed, propSeeds, fixture.Extended, func(f fixture.Fixture) string {
		pw := concretize(t, f)
		first := pw.answers(t, pw.deliver(nil), propOpts()...)
		for _, o := range sampleOrders(len(pw.lines), f.Seed, propOrders) {
			if got := pw.answers(t, pw.deliver(o), propOpts()...); got != first {
				return "order " + sprintOrder(o) + " changed an answer: " + firstDiff(first, got)
			}
		}
		return ""
	})
}

// TestPropertyDuplicatesAndEncodings: P-02 over every view. Each line delivered twice, and once more in every
// equivalent signature encoding the writer could have produced (v as 0/1, high s), in a sampled order: every
// answer is the one of the single delivery, the resolver holds one statement per body.
func TestPropertyDuplicatesAndEncodings(t *testing.T) {
	conformance.Partial(t, "P-02", "all six views here, duplicate delivery and equivalent EIP-191 encodings; counts of submissions and credit are the exchange view's, not built; the Ed25519 encoding is unique (step 1) so only secp256k1 re-encodes")
	fixture.Check(t, propBaseSeed+1000, propSeeds, fixture.Extended, func(f fixture.Fixture) string {
		pw := concretize(t, f)
		once := pw.answers(t, pw.deliver(nil), propOpts()...)
		var many [][]byte
		for _, ln := range pw.reencodings(t) {
			many = append(many, ln, ln)
		}
		for _, o := range append([][]int{nil}, sampleOrders(len(many), f.Seed, 2)...) {
			lines := many
			if o != nil {
				lines = make([][]byte, len(o))
				for i, j := range o {
					lines[i] = many[j]
				}
			}
			s := storeOf(t, lines)
			r := New(s, propOpts()...)
			if len(r.byID) != len(storeResolver(t, pw).byID) {
				return "duplicates changed the number of statements held"
			}
			if got := pw.snapshot(r, s); got != once {
				return "duplicates or re-encodings changed an answer: " + firstDiff(once, got)
			}
		}
		return ""
	})
}

func storeResolver(t *testing.T, pw *propWorld) *Resolver {
	return New(storeOf(t, pw.deliver(nil)), propOpts()...)
}

func sprintOrder(o []int) string {
	s := "["
	for i, x := range o {
		if i > 0 {
			s += " "
		}
		s += string(rune('0'+x/10)) + string(rune('0'+x%10))
	}
	return s + "]"
}

// TestPropertyColdRecompute: P-07 at the resolver. A resolver keeps no state beyond its snapshot of the store,
// so building it again from the same store, and building it from a store rebuilt from the same lines, gives the
// answers byte for byte, including after the first resolver has answered everything (comparator and view
// caches inside the resolver must not leak into a fresh one).
func TestPropertyColdRecompute(t *testing.T) {
	conformance.Partial(t, "P-07", "resolver half: two resolvers over one store, and one over a rebuilt store, answer alike, every view; deleting the store-side caches and projections is the store layer's half")
	fixture.Check(t, propBaseSeed+2000, propSeeds, fixture.Extended, func(f fixture.Fixture) string {
		pw := concretize(t, f)
		s := storeOf(t, pw.deliver(nil))
		warm := New(s, propOpts()...)
		a := pw.snapshot(warm, s)
		if b := pw.snapshot(warm, s); b != a {
			return "the same resolver answered twice differently: " + firstDiff(a, b)
		}
		if b := pw.snapshot(New(s, propOpts()...), s); b != a {
			return "a second resolver over the same store answered differently: " + firstDiff(a, b)
		}
		if b := pw.answers(t, pw.deliver(nil), propOpts()...); b != a {
			return "a resolver over a rebuilt store answered differently: " + firstDiff(a, b)
		}
		return ""
	})
}
