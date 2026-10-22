package identitymodel

import (
	"fmt"
	"math/rand"
	"reflect"
	"slices"
	"testing"
)

// generatedDAG constructs ancestry SETS while generating a valid layered graph.
// This is the independent oracle: it never invokes chain/rootRelation, does not
// reconstruct a production keylog index, and has no arrival-order state machine.
// Cut expectations are literal intersections of these precomputed sets.
func generatedDAG(seed int64) ([]Fact, []ID, map[ID]map[ID]bool) {
	rng := rand.New(rand.NewSource(seed))
	fs := fixture()[:3]
	closures := map[ID]map[ID]bool{"D": {"D": true}}
	previous := []ID{"D"}
	all := []ID{"D"}
	var candidates []ID
	for seq := uint64(1); seq <= 6; seq++ {
		var layer []ID
		for branch := 0; branch < 1+rng.Intn(4); branch++ {
			id := ID(fmt.Sprintf("s-%d-%d", seq, branch))
			prev := previous[rng.Intn(len(previous))]
			f := data(id, seq, prev)
			f.Operation.Target.ID = ID(fmt.Sprintf("content-%d", rng.Intn(4)))
			if len(all) > 1 && rng.Intn(2) == 0 {
				m := all[rng.Intn(len(all))]
				if m != prev {
					f.Merges = []ID{m}
				}
			}
			set := map[ID]bool{id: true}
			for _, parent := range append([]ID{prev}, f.Merges...) {
				for ancestor := range closures[parent] {
					set[ancestor] = true
				}
			}
			closures[id] = set
			fs, layer, candidates = append(fs, f), append(layer, id), append(candidates, id)
		}
		all, previous = append(all, layer...), layer
	}
	mutate(fs, "G", func(f *Fact) { f.Grant.Permissions = []Permission{{Kind: Authored, Mode: AnyTarget}} })
	return fs, candidates, closures
}

func TestSeededCutsMatchIndependentSetOracleAndNeverWiden(t *testing.T) {
	for seed := int64(1); seed <= 60; seed++ {
		t.Run(fmt.Sprintf("seed-%d", seed), func(t *testing.T) {
			fs, candidates, closures := generatedDAG(seed)
			rng := rand.New(rand.NewSource(seed + 10000))
			allowed := map[ID]bool{}
			for _, id := range candidates {
				allowed[id] = true
			}
			for step := 0; step < 7; step++ {
				if step > 0 {
					last := candidates[rng.Intn(len(candidates))]
					if step == 6 && seed%2 == 0 {
						last = ""
					}
					fs = append(fs, cut(ID(fmt.Sprintf("cut-%d", step)), last))
					for id := range allowed {
						// Adding cuts leaves every prior fact fixed. The set oracle
						// simply removes every element outside the new closure.
						if !closures[last][id] {
							delete(allowed, id)
						}
					}
				}
				s := snapshot(t, fs)
				for _, id := range candidates {
					want := Denied
					if allowed[id] {
						want = Eligible
					}
					requireStatus(t, s, id, want, "")
				}
			}
			// An additional issuer-authenticated but unresolved cut never restores
			// a definite exclusion. Remaining passes become unknown, not broader.
			s := snapshot(t, append(fs, cut("missing-cut", "absent-last-good")))
			for _, id := range candidates {
				want := Denied
				if allowed[id] {
					want = Unknown
				}
				requireStatus(t, s, id, want, "missing_evidence")
			}
		})
	}
}

func TestSeededSetAndPermutationInvariance(t *testing.T) {
	for seed := int64(71); seed < 91; seed++ {
		fs, candidates, _ := generatedDAG(seed)
		fs = append(fs, cut("C", candidates[len(candidates)-1]), cut("gap-cut", "missing"))
		base := snapshot(t, fs)
		rng := rand.New(rand.NewSource(seed))
		for permutation := 0; permutation < 8; permutation++ {
			shuffled := slices.Clone(fs)
			rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
			shuffled = append(shuffled, copyFact(shuffled[rng.Intn(len(shuffled))]))
			s := snapshot(t, shuffled)
			if s.EvidenceDigest() != base.EvidenceDigest() {
				t.Fatalf("seed %d: arrival or duplicate changed evidence digest", seed)
			}
			for _, id := range candidates {
				if got, want := s.Evaluate(id), base.Evaluate(id); !reflect.DeepEqual(got, want) {
					t.Fatalf("seed %d permutation %d %s: result changed\ngot: %+v\nwant: %+v", seed, permutation, id, got, want)
				}
			}
		}
	}
}

func TestSeededScopeNarrowing(t *testing.T) {
	for seed := int64(101); seed <= 130; seed++ {
		fs, candidates, _ := generatedDAG(seed)
		wide := snapshot(t, fs)
		for _, id := range candidates {
			requireStatus(t, wide, id, Eligible, "")
		}
		mutate(fs, "G", func(f *Fact) {
			f.Grant.Permissions = []Permission{{Kind: Authored, Mode: ExactTargets, Targets: []ID{"content-0", "content-1"}}}
		})
		narrow := snapshot(t, fs)
		// This independent expected predicate is intentionally not scopeAllows.
		for _, f := range fs {
			if f.Event != Data {
				continue
			}
			want := Denied
			if f.Operation.Target.ID == "content-0" || f.Operation.Target.ID == "content-1" {
				want = Eligible
			}
			requireStatus(t, narrow, f.ID, want, "")
		}
		mutate(fs, "G", func(f *Fact) { f.Grant.Permissions[0].Targets = []ID{"content-0"} })
		narrower := snapshot(t, fs)
		for _, id := range candidates {
			if narrower.Evaluate(id).Status == Eligible && narrow.Evaluate(id).Status != Eligible {
				t.Fatalf("seed %d: narrowing widened %s", seed, id)
			}
		}
	}
}

func TestSeededForeignIdentityAndUnprovenNoiseNoninterference(t *testing.T) {
	for seed := int64(201); seed <= 220; seed++ {
		fs, candidates, _ := generatedDAG(seed)
		base := snapshot(t, fs)
		rng := rand.New(rand.NewSource(seed))
		for n := 0; n < 12; n++ {
			c := cut(ID(fmt.Sprintf("noise-%d", n)), "missing-noise-L")
			if rng.Intn(2) == 0 {
				c.Authentication = Unproven // Unverified signer claim R.
			} else {
				c.Signer = Key(fmt.Sprintf("foreign-root-%d", n)) // Authenticated stranger.
			}
			c.Prev = "missing-noise-ancestry"
			fs = append(fs, c)
		}
		noisy := snapshot(t, fs)
		for _, id := range candidates {
			got, want := noisy.Evaluate(id), base.Evaluate(id)
			// The global evidence-set digest intentionally records all held facts.
			got.EvidenceDigest = want.EvidenceDigest
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("seed %d %s: unproven/foreign facts affected authority: %+v", seed, id, got)
			}
		}
	}
}

func TestSetValuedFieldsAreOrderIndependent(t *testing.T) {
	fs := fixture()
	mutate(fs, "G", func(f *Fact) {
		f.Grant.Permissions = append(f.Grant.Permissions, Permission{Kind: Observed, Mode: AnyTarget})
	})
	mutate(fs, "M", func(f *Fact) { f.Merges = []ID{"X", "D"} })
	base := snapshot(t, fs)
	mutate(fs, "G", func(f *Fact) {
		slices.Reverse(f.Grant.Permissions[0].Targets)
		slices.Reverse(f.Grant.Permissions)
	})
	mutate(fs, "M", func(f *Fact) { slices.Reverse(f.Merges) })
	if got := snapshot(t, fs).Evaluate("M"); !reflect.DeepEqual(got, base.Evaluate("M")) {
		t.Fatalf("model set ordering changed result: %+v", got)
	}
}
